import type { AuthOAuthStartResult, StartOAuthAuthorizationInput } from '@ankhorage/contracts/auth';
import { randomBytes } from '@noble/hashes/utils.js';

import { createOAuthAttemptId } from './oauthAttemptId.js';
import { oauthStartError } from './oauthErrors.js';
import { emitLifecycleEvent } from './oauthLifecycle.js';
import {
  getSupabaseOAuthProviderDefinition,
  type SupabaseOAuthProviderId,
} from './oauthProviderDefinitions.js';
import type { OAuthRuntimeContext, OAuthStartPreparation } from './oauthRuntime.js';
import {
  createAuthorizationUrl,
  createPkcePair,
  normalizeQueryParams,
  normalizeRedirectUri,
  normalizeScopes,
  resolveEnabledProvider,
} from './oauthStartSupport.js';
import {
  clearOAuthAttemptState,
  isAttemptExpired,
  readAttempt,
  writeAttempt,
} from './oauthStorage.js';
import { ATTEMPT_VERSION, type StoredOAuthAttempt } from './oauthTypes.js';

export async function startSupabaseOAuthAuthorization(
  context: OAuthRuntimeContext,
  input: StartOAuthAuthorizationInput,
): Promise<AuthOAuthStartResult> {
  const prepared = prepareStartInput(context, input);
  if (!prepared.ok) return prepared.result;
  const previousError = await clearPreviousAttempt(context, prepared.provider);
  if (previousError !== null) return previousError;
  return createAuthorizationAttempt(context, input, prepared);
}

function prepareStartInput(
  context: OAuthRuntimeContext,
  input: StartOAuthAuthorizationInput,
): OAuthStartPreparation {
  const provider = resolveEnabledProvider(input.provider, context.providerSet);
  if (!provider.ok) return provider;
  const redirectUri = normalizeRedirectUri(input.redirectUri, provider.provider);
  if (!redirectUri.ok) return redirectUri;
  const queryParams = normalizeQueryParams(input.queryParams, provider.provider);
  return queryParams.ok
    ? {
        ok: true,
        provider: provider.provider,
        redirectUri: redirectUri.value,
        queryParams: queryParams.value,
      }
    : queryParams;
}

async function clearPreviousAttempt(
  context: OAuthRuntimeContext,
  provider: SupabaseOAuthProviderId,
): Promise<AuthOAuthStartResult | null> {
  let previous;
  try {
    previous = await readAttempt(context.storage, context.attemptStorageKey);
  } catch {
    return oauthStartError(
      'session_persistence_failed',
      'Unable to read the persisted OAuth authorization state.',
      provider,
      true,
    );
  }
  if (previous.type === 'invalid') await clearAttempt(context);
  if (previous.type !== 'valid') return null;
  if (
    previous.attempt.status === 'completed' ||
    isAttemptExpired(previous.attempt, context.now())
  ) {
    await clearAttempt(context);
    return null;
  }
  return oauthStartError(
    'authorization_failed',
    'An OAuth authorization attempt is already active.',
    provider,
    true,
  );
}

async function createAuthorizationAttempt(
  context: OAuthRuntimeContext,
  input: StartOAuthAuthorizationInput,
  prepared: Extract<OAuthStartPreparation, { ok: true }>,
): Promise<AuthOAuthStartResult> {
  try {
    const { challenge, verifier } = createPkcePair(context.randomBytes ?? randomBytes);
    const attempt = createAttempt(context, prepared);
    await context.storage.setItem(context.codeVerifierStorageKey, verifier);
    await writeAttempt(context.storage, context.attemptStorageKey, attempt);
    await emitLifecycleEvent(context.onLifecycleEvent, {
      correlationId: attempt.id,
      provider: attempt.provider,
      stage: 'start',
      status: 'started',
    });
    return createStartResult(context, input, prepared, attempt, challenge);
  } catch {
    await clearAttempt(context);
    return oauthStartError(
      'session_persistence_failed',
      'Unable to initialize the OAuth PKCE authorization attempt.',
      prepared.provider,
      true,
    );
  }
}

function createAttempt(
  context: OAuthRuntimeContext,
  prepared: Extract<OAuthStartPreparation, { ok: true }>,
): StoredOAuthAttempt {
  const createdAt = context.now();
  return {
    version: ATTEMPT_VERSION,
    id: createOAuthAttemptId(),
    provider: prepared.provider,
    redirectUri: prepared.redirectUri,
    status: 'pending',
    createdAt,
    expiresAt: createdAt + context.attemptLifetimeMs,
  };
}

function createStartResult(
  context: OAuthRuntimeContext,
  input: StartOAuthAuthorizationInput,
  prepared: Extract<OAuthStartPreparation, { ok: true }>,
  attempt: StoredOAuthAttempt,
  challenge: string,
): AuthOAuthStartResult {
  const definition = getSupabaseOAuthProviderDefinition(prepared.provider);
  const scopes = normalizeScopes(input.scopes, definition?.defaultScopes ?? []);
  return {
    ok: true,
    data: {
      attemptId: attempt.id,
      provider: prepared.provider,
      authorizationUrl: createAuthorizationUrl({
        baseUrl: context.url,
        challenge,
        provider: prepared.provider,
        queryParams: prepared.queryParams,
        redirectUri: prepared.redirectUri,
        scopes,
      }),
      redirectUri: prepared.redirectUri,
    },
  };
}

async function clearAttempt(context: OAuthRuntimeContext): Promise<void> {
  await clearOAuthAttemptState(
    context.storage,
    context.attemptStorageKey,
    context.codeVerifierStorageKey,
  );
}
