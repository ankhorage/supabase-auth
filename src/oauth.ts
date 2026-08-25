import type {
  AuthOAuthAdapter,
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthErrorCode,
  AuthOAuthErrorStage,
  AuthOAuthProviderId,
  AuthOAuthStartResult,
  AuthSession,
  CompleteOAuthAuthorizationInput,
  StartOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, isBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { readResponseBody } from './errors.js';
import { createOAuthAttemptId } from './oauthAttemptId.js';
import {
  getSupabaseOAuthProviderDefinition,
  isSupabaseOAuthProviderId,
  type SupabaseOAuthProviderId,
} from './oauthProviderDefinitions.js';
import { normalizeSupabaseSession } from './session.js';
import type {
  SupabaseAuthFetch,
  SupabaseAuthRandomBytes,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
  SupabaseOAuthLifecycleObserver,
  SupabaseOAuthProfileVerifier,
} from './types.js';

const ATTEMPT_VERSION = 4;
const DEFAULT_ATTEMPT_LIFETIME_MS = 10 * 60 * 1000;
const PKCE_RANDOM_BYTE_COUNT = 32;
const BASE64_URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const FORBIDDEN_QUERY_PARAMS = new Set([
  'code_challenge',
  'code_challenge_method',
  'provider',
  'redirect_to',
  'scopes',
  'skip_http_redirect',
]);
const CALLBACK_PARAMS = new Set(['code', 'error', 'error_code', 'error_description']);
const DANGEROUS_PROTOCOLS = new Set(['data:', 'file:', 'javascript:']);

interface CreateSupabaseOAuthAdapterInput {
  url: string;
  anonKey: string;
  fetch: SupabaseAuthFetch;
  storage: SupabaseAuthStorage;
  storageKey: string;
  providers: readonly SupabaseOAuthProviderId[];
  randomBytes?: SupabaseAuthRandomBytes;
  persistSession(session: AuthSession): Promise<void>;
  verifyProfile?: SupabaseOAuthProfileVerifier;
  onLifecycleEvent?: SupabaseOAuthLifecycleObserver;
  now?: () => number;
  attemptLifetimeMs?: number;
}

interface StoredOAuthAttempt {
  version: typeof ATTEMPT_VERSION;
  id: string;
  provider: SupabaseOAuthProviderId;
  redirectUri: string;
  status: 'pending' | 'completing' | 'completed';
  createdAt: number;
  expiresAt: number;
  callbackFingerprint?: string;
}

type StoredOAuthAttemptReadResult =
  | { type: 'missing' }
  | { type: 'invalid' }
  | { type: 'valid'; attempt: StoredOAuthAttempt };

export function createSupabaseOAuthAdapter(
  input: CreateSupabaseOAuthAdapterInput,
): AuthOAuthAdapter {
  const providers = [...new Set(input.providers)];
  if (providers.length === 0) {
    throw new TypeError('At least one enabled Supabase OAuth provider is required.');
  }

  const providerSet = new Set<SupabaseOAuthProviderId>(providers);
  const oauthStorageKey = `${input.storageKey}.oauth`;
  const attemptStorageKey = `${oauthStorageKey}.attempt`;
  const codeVerifierStorageKey = `${oauthStorageKey}.pkce-verifier`;
  const now = input.now ?? Date.now;
  const attemptLifetimeMs = normalizeAttemptLifetime(input.attemptLifetimeMs);
  let activeCompletion: Promise<void> | null = null;

  const capabilities = {
    providers: providers as [SupabaseOAuthProviderId, ...SupabaseOAuthProviderId[]],
  };

  return {
    capabilities,

    async startAuthorization(
      authorizationInput: StartOAuthAuthorizationInput,
    ): Promise<AuthOAuthStartResult> {
      const provider = resolveEnabledProvider(authorizationInput.provider, providerSet);
      if (!provider.ok) return provider.result;

      const redirectUri = normalizeRedirectUri(authorizationInput.redirectUri, provider.provider);
      if (!redirectUri.ok) return redirectUri.result;

      const queryParams = normalizeQueryParams(authorizationInput.queryParams, provider.provider);
      if (!queryParams.ok) return queryParams.result;

      let previousAttemptResult: StoredOAuthAttemptReadResult;
      try {
        previousAttemptResult = await readAttempt(input.storage, attemptStorageKey);
      } catch {
        return oauthStartError(
          'session_persistence_failed',
          'Unable to read the persisted OAuth authorization state.',
          provider.provider,
          true,
        );
      }

      if (previousAttemptResult.type === 'invalid') {
        await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
      }

      if (previousAttemptResult.type === 'valid') {
        const previousAttempt = previousAttemptResult.attempt;
        if (previousAttempt.status === 'completed' || isAttemptExpired(previousAttempt, now())) {
          await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
        } else {
          return oauthStartError(
            'authorization_failed',
            'An OAuth authorization attempt is already active.',
            provider.provider,
            true,
          );
        }
      }

      const definition = getSupabaseOAuthProviderDefinition(provider.provider);
      const requestedScopes = normalizeScopes(
        authorizationInput.scopes,
        definition?.defaultScopes ?? [],
      );

      try {
        const { challenge, verifier } = createPkcePair(input.randomBytes ?? randomBytes);
        const attemptId = createOAuthAttemptId();
        const createdAt = now();
        const attempt: StoredOAuthAttempt = {
          version: ATTEMPT_VERSION,
          id: attemptId,
          provider: provider.provider,
          redirectUri: redirectUri.value,
          status: 'pending',
          createdAt,
          expiresAt: createdAt + attemptLifetimeMs,
        };

        await input.storage.setItem(codeVerifierStorageKey, verifier);
        await writeAttempt(input.storage, attemptStorageKey, attempt);
        const authorizationUrl = createAuthorizationUrl({
          baseUrl: input.url,
          challenge,
          provider: provider.provider,
          queryParams: queryParams.value,
          redirectUri: redirectUri.value,
          scopes: requestedScopes,
        });

        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attemptId,
          provider: provider.provider,
          stage: 'start',
          status: 'started',
        });

        return {
          ok: true,
          data: {
            attemptId,
            provider: provider.provider,
            authorizationUrl,
            redirectUri: redirectUri.value,
          },
        };
      } catch {
        await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
        return oauthStartError(
          'session_persistence_failed',
          'Unable to initialize the OAuth PKCE authorization attempt.',
          provider.provider,
          true,
        );
      }
    },

    async completeAuthorization(
      completionInput: CompleteOAuthAuthorizationInput,
    ): Promise<AuthOAuthCompletionResult> {
      while (activeCompletion) await activeCompletion;
      let releaseCompletion: (() => void) | undefined;
      const completionLock = new Promise<void>((resolve) => {
        releaseCompletion = resolve;
      });
      activeCompletion = completionLock;

      try {
        let attemptResult: StoredOAuthAttemptReadResult;
        try {
          attemptResult = await readAttempt(input.storage, attemptStorageKey);
        } catch {
          await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
          return oauthCompletionError(
            'session_persistence_failed',
            'callback',
            'Unable to read the persisted OAuth authorization attempt.',
            undefined,
            true,
          );
        }

        if (attemptResult.type !== 'valid') {
          await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
          return oauthCompletionError(
            'authorization_attempt_not_found',
            'callback',
            'The OAuth authorization attempt was not found or is invalid.',
            undefined,
            true,
          );
        }

        const { attempt } = attemptResult;
        if (isAttemptExpired(attempt, now())) {
          await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
          return oauthCompletionError(
            'authorization_attempt_not_found',
            'callback',
            'The OAuth authorization attempt expired.',
            attempt.provider,
            true,
          );
        }

        if (attempt.id !== completionInput.attemptId) {
          return oauthCompletionError(
            'authorization_attempt_not_found',
            'callback',
            'The OAuth authorization attempt was not found.',
            attempt.provider,
            true,
          );
        }

        if (attempt.status !== 'pending') {
          return completeOAuthReplay(completionInput, attempt);
        }

        if (completionInput.response.type === 'cancelled') {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          await emitLifecycleEvent(input.onLifecycleEvent, {
            correlationId: attempt.id,
            provider: attempt.provider,
            stage: 'transport',
            status: 'cancelled',
          });
          return {
            ok: false,
            status: 'cancelled',
            provider: attempt.provider,
            reason: completionInput.response.reason,
          };
        }

        if (completionInput.response.type === 'error') {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'authorization_failed',
            'transport',
            'The OAuth authorization transport failed.',
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        const callback = parseCallback(completionInput.response.url, attempt);
        if (callback.type === 'error') {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          await emitOAuthError(input.onLifecycleEvent, attempt, callback.result);
          return callback.result;
        }
        if (callback.type === 'cancelled') {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          await emitLifecycleEvent(input.onLifecycleEvent, {
            correlationId: attempt.id,
            provider: attempt.provider,
            stage: 'callback',
            status: 'cancelled',
          });
          return {
            ok: false,
            status: 'cancelled',
            provider: attempt.provider,
            reason: 'provider_denied',
          };
        }

        const callbackFingerprint = fingerprintOAuthCallback(attempt.id, callback.code);

        try {
          await writeAttempt(input.storage, attemptStorageKey, {
            ...attempt,
            status: 'completing',
            callbackFingerprint,
          });
        } catch {
          await clearOAuthAttemptState(input.storage, attemptStorageKey, codeVerifierStorageKey);
          return oauthCompletionError(
            'session_persistence_failed',
            'callback',
            'Unable to lock the OAuth authorization callback for completion.',
            attempt.provider,
            true,
          );
        }

        let codeVerifier: string | null;
        try {
          codeVerifier = await input.storage.getItem(codeVerifierStorageKey);
        } catch {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'session_persistence_failed',
            'exchange',
            'The OAuth PKCE verifier could not be read.',
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        if (codeVerifier === null || codeVerifier.length === 0) {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'pkce_mismatch',
            'exchange',
            'The OAuth PKCE verifier is missing or invalid.',
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        let exchangeResponse: Response;
        try {
          exchangeResponse = await exchangeAuthorizationCode({
            anonKey: input.anonKey,
            baseUrl: input.url,
            code: callback.code,
            fetch: input.fetch,
            verifier: codeVerifier,
          });
        } catch {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'network_error',
            'exchange',
            'Unable to reach Supabase Auth while exchanging the OAuth code.',
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        const exchangeBody = await readResponseBody(exchangeResponse);
        if (!exchangeResponse.ok) {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result: AuthOAuthCompletionResult = {
            ok: false,
            status: 'error',
            error: mapSupabaseOAuthError(exchangeBody, 'exchange', attempt.provider),
          };
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        const session = normalizeSupabaseSession(exchangeBody);
        if (session === null) {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'provider_error',
            'session',
            'Supabase Auth returned an invalid OAuth session.',
            attempt.provider,
            false,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        try {
          await input.persistSession(session);
        } catch {
          await finalizeAttempt(input.storage, attemptStorageKey, codeVerifierStorageKey, attempt);
          const result = oauthCompletionError(
            'session_persistence_failed',
            'session',
            'The OAuth session could not be persisted.',
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        if (input.verifyProfile !== undefined) {
          let verification;
          try {
            verification = await input.verifyProfile({
              correlationId: attempt.id,
              provider: attempt.provider,
              session,
            });
          } catch {
            verification = {
              ok: false as const,
              message: 'The generated public profile could not be verified.',
            };
          }

          if (!verification.ok) {
            await finalizeAttempt(
              input.storage,
              attemptStorageKey,
              codeVerifierStorageKey,
              attempt,
            );
            const result = oauthCompletionError(
              'profile_creation_failed',
              'profile',
              verification.message,
              attempt.provider,
              true,
            );
            await emitOAuthError(input.onLifecycleEvent, attempt, result);
            return result;
          }

          await emitLifecycleEvent(input.onLifecycleEvent, {
            correlationId: attempt.id,
            provider: attempt.provider,
            stage: 'profile',
            status: 'profile_verified',
          });
        }

        await finalizeAttempt(
          input.storage,
          attemptStorageKey,
          codeVerifierStorageKey,
          attempt,
          callbackFingerprint,
        );
        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attempt.id,
          provider: attempt.provider,
          stage: 'session',
          status: 'authenticated',
        });
        return {
          ok: true,
          status: 'authenticated',
          provider: attempt.provider,
          session,
        };
      } finally {
        if (activeCompletion === completionLock) activeCompletion = null;
        releaseCompletion?.();
      }
    },
  };
}

function completeOAuthReplay(
  completionInput: CompleteOAuthAuthorizationInput,
  attempt: StoredOAuthAttempt,
): AuthOAuthCompletionResult {
  if (completionInput.response.type !== 'callback') {
    return invalidCallback(
      attempt.provider,
      'The OAuth response does not match the authorization callback being completed.',
    ).result;
  }

  const callback = parseCallback(completionInput.response.url, attempt);
  if (callback.type !== 'code') {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback does not match the completed authorization callback.',
    ).result;
  }

  const fingerprint = fingerprintOAuthCallback(attempt.id, callback.code);
  if (
    attempt.callbackFingerprint === undefined ||
    !constantTimeEqual(fingerprint, attempt.callbackFingerprint)
  ) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback does not match the completed authorization callback.',
    ).result;
  }

  return callbackAlreadyCompleted(attempt.provider);
}

function callbackAlreadyCompleted(provider: SupabaseOAuthProviderId): AuthOAuthCompletionResult {
  return oauthCompletionError(
    'callback_already_completed',
    'callback',
    'The OAuth authorization callback was already handled.',
    provider,
    false,
  );
}

async function emitOAuthError(
  observer: SupabaseOAuthLifecycleObserver | undefined,
  attempt: StoredOAuthAttempt,
  result: AuthOAuthCompletionResult,
): Promise<void> {
  if (result.ok || result.status !== 'error') return;
  await emitLifecycleEvent(observer, {
    correlationId: attempt.id,
    provider: attempt.provider,
    stage: result.error.stage,
    status: 'error',
    errorCode: result.error.code,
  });
}

async function emitLifecycleEvent(
  observer: SupabaseOAuthLifecycleObserver | undefined,
  event: SupabaseOAuthLifecycleEvent,
): Promise<void> {
  if (observer === undefined) return;
  try {
    await observer(event);
  } catch {
    // Observability must never change the authentication result.
  }
}

function resolveEnabledProvider(
  requestedProvider: AuthOAuthProviderId,
  providers: ReadonlySet<SupabaseOAuthProviderId>,
): { ok: true; provider: SupabaseOAuthProviderId } | { ok: false; result: AuthOAuthStartResult } {
  const provider = requestedProvider.trim();
  if (!isSupabaseOAuthProviderId(provider) || !providers.has(provider)) {
    return {
      ok: false,
      result: oauthStartError(
        'provider_disabled',
        `OAuth provider "${provider}" is not enabled for this adapter.`,
        requestedProvider,
        true,
      ),
    };
  }
  return { ok: true, provider };
}

function normalizeRedirectUri(
  rawRedirectUri: string,
  provider: SupabaseOAuthProviderId,
): { ok: true; value: string } | { ok: false; result: AuthOAuthStartResult } {
  const redirectUri = rawRedirectUri.trim();
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return {
      ok: false,
      result: oauthStartError(
        'invalid_redirect_uri',
        'OAuth redirect URI must be an absolute URL or application deep link.',
        provider,
        true,
      ),
    };
  }

  if (
    DANGEROUS_PROTOCOLS.has(url.protocol) ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    (url.protocol === 'http:' && !isLocalhost(url.hostname))
  ) {
    return {
      ok: false,
      result: oauthStartError(
        'invalid_redirect_uri',
        'OAuth redirect URI is not a permitted canonical callback URL.',
        provider,
        true,
      ),
    };
  }

  return { ok: true, value: url.toString() };
}

function normalizeQueryParams(
  queryParams: Readonly<Record<string, string>> | undefined,
  provider: SupabaseOAuthProviderId,
): { ok: true; value: Record<string, string> } | { ok: false; result: AuthOAuthStartResult } {
  const normalized: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(queryParams ?? {})) {
    const key = rawKey.trim();
    const value = rawValue.trim();
    if (key.length === 0 || FORBIDDEN_QUERY_PARAMS.has(key)) {
      return {
        ok: false,
        result: oauthStartError(
          'provider_misconfigured',
          `OAuth query parameter "${rawKey}" is reserved or invalid.`,
          provider,
          true,
        ),
      };
    }
    normalized[key] = value;
  }
  return { ok: true, value: normalized };
}

function normalizeScopes(
  scopes: readonly string[] | undefined,
  defaults: readonly string[],
): string[] {
  const requested = scopes === undefined || scopes.length === 0 ? defaults : scopes;
  return [...new Set(requested.map((scope) => scope.trim()).filter((scope) => scope.length > 0))];
}

function createPkcePair(generateRandomBytes: SupabaseAuthRandomBytes): {
  challenge: string;
  verifier: string;
} {
  const randomValue = generateRandomBytes(PKCE_RANDOM_BYTE_COUNT);
  if (!isBytes(randomValue) || randomValue.length !== PKCE_RANDOM_BYTE_COUNT) {
    throw new TypeError('OAuth random byte source returned an invalid value.');
  }
  const verifier = bytesToBase64Url(randomValue);
  const challenge = bytesToBase64Url(sha256(utf8ToBytes(verifier)));
  return { challenge, verifier };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let encoded = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    encoded += BASE64_URL_ALPHABET[first >> 2] ?? '';
    encoded += BASE64_URL_ALPHABET[((first & 0b11) << 4) | ((second ?? 0) >> 4)] ?? '';
    if (second !== undefined) {
      encoded += BASE64_URL_ALPHABET[((second & 0b1111) << 2) | ((third ?? 0) >> 6)] ?? '';
    }
    if (third !== undefined) encoded += BASE64_URL_ALPHABET[third & 0b11_1111] ?? '';
  }
  return encoded;
}

function createAuthorizationUrl(input: {
  baseUrl: string;
  challenge: string;
  provider: SupabaseOAuthProviderId;
  queryParams: Readonly<Record<string, string>>;
  redirectUri: string;
  scopes: readonly string[];
}): string {
  const url = new URL(`${input.baseUrl.replace(/\/+$/u, '')}/auth/v1/authorize`);
  url.searchParams.set('provider', input.provider);
  url.searchParams.set('redirect_to', input.redirectUri);
  if (input.scopes.length > 0) url.searchParams.set('scopes', input.scopes.join(' '));
  url.searchParams.set('code_challenge', input.challenge);
  url.searchParams.set('code_challenge_method', 's256');
  for (const [key, value] of Object.entries(input.queryParams)) url.searchParams.set(key, value);
  return url.toString();
}

function exchangeAuthorizationCode(input: {
  anonKey: string;
  baseUrl: string;
  code: string;
  fetch: SupabaseAuthFetch;
  verifier: string;
}): Promise<Response> {
  const url = `${input.baseUrl.replace(/\/+$/u, '')}/auth/v1/token?grant_type=pkce`;
  return input.fetch(url, {
    method: 'POST',
    headers: {
      apikey: input.anonKey,
      Authorization: `Bearer ${input.anonKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ auth_code: input.code, code_verifier: input.verifier }),
  });
}

function parseCallback(
  rawCallbackUrl: string,
  attempt: StoredOAuthAttempt,
):
  | { type: 'code'; code: string }
  | { type: 'cancelled' }
  | { type: 'error'; result: AuthOAuthCompletionResult } {
  let callbackUrl: URL;
  let redirectUri: URL;
  try {
    callbackUrl = new URL(rawCallbackUrl);
    redirectUri = new URL(attempt.redirectUri);
  } catch {
    return invalidCallback(attempt.provider, 'The OAuth callback URL is invalid.');
  }

  if (!sameCallbackLocation(callbackUrl, redirectUri) || callbackUrl.hash.length > 0) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback does not match the expected redirect URI.',
    );
  }

  for (const key of callbackUrl.searchParams.keys()) {
    if (!CALLBACK_PARAMS.has(key)) {
      return invalidCallback(
        attempt.provider,
        'The OAuth callback contains unexpected parameters.',
      );
    }
  }

  const codes = callbackUrl.searchParams.getAll('code');
  const errors = [
    ...callbackUrl.searchParams.getAll('error'),
    ...callbackUrl.searchParams.getAll('error_code'),
  ].filter((value) => value.length > 0);
  const errorDescriptions = callbackUrl.searchParams.getAll('error_description');

  if (errorDescriptions.length > 0 && errors.length === 0) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback contains an error description without an error.',
    );
  }

  if (codes.length > 0 && errors.length > 0) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback contains both a code and an error.',
    );
  }

  if (errors.length > 0) {
    if (errors.length === 1 && errors[0] === 'access_denied') return { type: 'cancelled' };
    return {
      type: 'error',
      result: oauthCompletionError(
        'authorization_failed',
        'callback',
        'The OAuth provider rejected the authorization request.',
        attempt.provider,
        true,
      ),
    };
  }

  const [code] = codes;
  if (codes.length !== 1 || code === undefined || code.trim().length === 0) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback does not contain one authorization code.',
    );
  }

  return { type: 'code', code };
}

function invalidCallback(
  provider: SupabaseOAuthProviderId,
  message: string,
): { type: 'error'; result: AuthOAuthCompletionResult } {
  return {
    type: 'error',
    result: oauthCompletionError('invalid_callback', 'callback', message, provider, true),
  };
}

function sameCallbackLocation(callbackUrl: URL, redirectUri: URL): boolean {
  return (
    callbackUrl.protocol === redirectUri.protocol &&
    callbackUrl.username === redirectUri.username &&
    callbackUrl.password === redirectUri.password &&
    callbackUrl.host === redirectUri.host &&
    callbackUrl.pathname === redirectUri.pathname
  );
}

function isLocalhost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

async function readAttempt(
  storage: SupabaseAuthStorage,
  key: string,
): Promise<StoredOAuthAttemptReadResult> {
  const stored = await storage.getItem(key);
  if (stored === null) return { type: 'missing' };
  try {
    const parsed: unknown = JSON.parse(stored);
    return isStoredAttempt(parsed) ? { type: 'valid', attempt: parsed } : { type: 'invalid' };
  } catch {
    return { type: 'invalid' };
  }
}

async function writeAttempt(
  storage: SupabaseAuthStorage,
  key: string,
  attempt: StoredOAuthAttempt,
): Promise<void> {
  await storage.setItem(key, JSON.stringify(attempt));
}

async function finalizeAttempt(
  storage: SupabaseAuthStorage,
  attemptKey: string,
  codeVerifierStorageKey: string,
  attempt: StoredOAuthAttempt,
  callbackFingerprint?: string,
): Promise<void> {
  try {
    await writeAttempt(storage, attemptKey, {
      ...attempt,
      status: 'completed',
      ...(callbackFingerprint === undefined ? {} : { callbackFingerprint }),
    });
  } catch {
    await safeRemove(storage, attemptKey);
  }
  await safeRemove(storage, codeVerifierStorageKey);
}

async function clearOAuthAttemptState(
  storage: SupabaseAuthStorage,
  attemptKey: string,
  codeVerifierStorageKey: string,
): Promise<void> {
  await safeRemove(storage, attemptKey);
  await safeRemove(storage, codeVerifierStorageKey);
}

function isAttemptExpired(attempt: StoredOAuthAttempt, now: number): boolean {
  return attempt.expiresAt <= now;
}

function fingerprintOAuthCallback(attemptId: string, code: string): string {
  return bytesToHex(sha256(utf8ToBytes(`${attemptId}\u0000${code}`)));
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function normalizeAttemptLifetime(value: number | undefined): number {
  const lifetime = value ?? DEFAULT_ATTEMPT_LIFETIME_MS;
  if (!Number.isSafeInteger(lifetime) || lifetime <= 0) {
    throw new TypeError('OAuth authorization attempt lifetime must be a positive safe integer.');
  }
  return lifetime;
}

async function safeRemove(storage: SupabaseAuthStorage, key: string): Promise<void> {
  try {
    await storage.removeItem(key);
  } catch {
    // Cleanup failure is intentionally not exposed with storage contents or secret values.
  }
}

function isStoredAttempt(value: unknown): value is StoredOAuthAttempt {
  if (!isRecord(value)) return false;
  return (
    value.version === ATTEMPT_VERSION &&
    typeof value.id === 'string' &&
    isSupabaseOAuthProviderId(typeof value.provider === 'string' ? value.provider : '') &&
    typeof value.redirectUri === 'string' &&
    (value.status === 'pending' || value.status === 'completing' || value.status === 'completed') &&
    typeof value.createdAt === 'number' &&
    Number.isSafeInteger(value.createdAt) &&
    value.createdAt >= 0 &&
    typeof value.expiresAt === 'number' &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > value.createdAt &&
    (value.callbackFingerprint === undefined ||
      ((value.status === 'completing' || value.status === 'completed') &&
        typeof value.callbackFingerprint === 'string' &&
        /^[0-9a-f]{64}$/u.test(value.callbackFingerprint)))
  );
}

function mapSupabaseOAuthError(
  error: unknown,
  stage: AuthOAuthErrorStage,
  provider: SupabaseOAuthProviderId,
): AuthOAuthError {
  const code = readString(error, 'code');
  const name = readString(error, 'name');
  const message = readString(error, 'message') ?? 'Supabase Auth returned an OAuth error.';
  const normalized = `${code ?? ''} ${name ?? ''} ${message}`.toLowerCase();

  if (
    normalized.includes('pkce_code_verifier_not_found') ||
    normalized.includes('bad_code_verifier')
  ) {
    return createOAuthError(
      'pkce_mismatch',
      'exchange',
      'The OAuth PKCE verifier is missing or invalid.',
      provider,
      true,
    );
  }
  if (
    normalized.includes('bad_oauth_state') ||
    normalized.includes('flow_state_not_found') ||
    normalized.includes('flow_state_expired')
  ) {
    return createOAuthError(
      'state_mismatch',
      stage,
      'The OAuth authorization state is missing, expired, or invalid.',
      provider,
      true,
    );
  }
  if (normalized.includes('bad_oauth_callback')) {
    return createOAuthError(
      'invalid_callback',
      'callback',
      'Supabase Auth rejected the OAuth callback.',
      provider,
      true,
    );
  }
  if (normalized.includes('provider_disabled')) {
    return createOAuthError(
      'provider_disabled',
      stage,
      'The OAuth provider is disabled in Supabase Auth.',
      provider,
      true,
    );
  }
  if (normalized.includes('oauth_provider_not_supported')) {
    return createOAuthError(
      'provider_misconfigured',
      stage,
      'The OAuth provider is not configured in Supabase Auth.',
      provider,
      true,
    );
  }
  if (normalized.includes('redirect')) {
    return createOAuthError(
      'invalid_redirect_uri',
      stage,
      'Supabase Auth rejected the OAuth redirect URI.',
      provider,
      true,
    );
  }
  if (
    normalized.includes('authretryablefetcherror') ||
    normalized.includes('fetch failed') ||
    normalized.includes('network')
  ) {
    return createOAuthError(
      'network_error',
      stage,
      'Unable to reach Supabase Auth during OAuth authorization.',
      provider,
      true,
    );
  }

  return createOAuthError(
    stage === 'start' ? 'authorization_failed' : 'code_exchange_failed',
    stage,
    stage === 'start'
      ? 'Supabase Auth could not start OAuth authorization.'
      : 'Supabase Auth could not exchange the OAuth authorization code.',
    provider,
    true,
  );
}

function oauthStartError(
  code: AuthOAuthErrorCode,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthStartResult {
  return {
    ok: false,
    error: createOAuthError(code, 'start', message, provider, recoverable),
  };
}

function oauthCompletionError(
  code: AuthOAuthErrorCode,
  stage: AuthOAuthErrorStage,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthCompletionResult {
  return {
    ok: false,
    status: 'error',
    error: createOAuthError(code, stage, message, provider, recoverable),
  };
}

function createOAuthError(
  code: AuthOAuthErrorCode,
  stage: AuthOAuthErrorStage,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthError {
  return provider === undefined
    ? { code, stage, message, recoverable }
    : { code, stage, message, provider, recoverable };
}

function readString(value: unknown, key: string): string | undefined {
  return isRecord(value) && typeof value[key] === 'string' ? value[key] : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
