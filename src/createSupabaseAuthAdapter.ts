import type {
  AuthAdapter,
  AuthAdapterError,
  AuthOAuthProviderId,
  AuthResult,
  AuthSession,
  AuthUser,
  PasswordResetInput,
  SignInInput,
  SignOutInput,
  SignUpInput,
  VerifyOtpInput,
} from '@ankhorage/contracts/auth';

import { createAuthError, mapNetworkError, mapSupabaseError, readResponseBody } from './errors.js';
import { createSupabaseOAuthAdapter } from './oauth.js';
import {
  isSupabaseOAuthProviderId,
  type SupabaseOAuthProviderId,
} from './oauthProviderDefinitions.js';
import {
  createSupabaseOAuthProfileVerifier,
  normalizeSupabaseAuthProfileVerificationConfig,
} from './profileVerification.js';
import {
  isAuthSessionExpired,
  normalizeSupabaseSession,
  normalizeSupabaseUser,
  parseStoredSession,
} from './session.js';
import type {
  SupabaseAuthConfig,
  SupabaseAuthFetch,
  SupabaseAuthProfileVerificationConfig,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleObserver,
  SupabaseOAuthProfileVerifier,
} from './types.js';

const DEFAULT_STORAGE_KEY = 'ankhorage.supabase-auth.session';

export function createSupabaseAuthAdapter(config: SupabaseAuthConfig): AuthAdapter {
  const normalizedConfig = validateConfig(config);
  let currentSession: AuthSession | null = null;
  let sessionLoaded = false;

  const request = async (
    path: string,
    options: {
      body?: Record<string, unknown>;
      accessToken?: string;
      redirectTo?: string;
    } = {},
  ): Promise<Response> => {
    const url = new URL(`${normalizedConfig.url}/auth/v1/${path}`);
    if (options.redirectTo !== undefined) url.searchParams.set('redirect_to', options.redirectTo);
    return normalizedConfig.fetch(url.toString(), {
      method: 'POST',
      headers: createHeaders(normalizedConfig.anonKey, options.accessToken),
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  };

  const persistSession = async (session: AuthSession | null): Promise<void> => {
    if (normalizedConfig.storage !== undefined) {
      if (session === null) {
        await normalizedConfig.storage.removeItem(normalizedConfig.storageKey);
      } else {
        await normalizedConfig.storage.setItem(
          normalizedConfig.storageKey,
          JSON.stringify(session),
        );
      }
    }
    currentSession = session;
    sessionLoaded = true;
  };

  const persistSessionSafely = async (
    session: AuthSession | null,
  ): Promise<AuthAdapterError | null> => {
    try {
      await persistSession(session);
      return null;
    } catch {
      return createAuthError(
        'session_persistence_failed',
        session === null
          ? 'The persisted auth session could not be cleared.'
          : 'The auth session could not be persisted.',
      );
    }
  };

  const readStoredSession = async (): Promise<AuthSession | null> => {
    if (sessionLoaded) return currentSession;
    sessionLoaded = true;
    if (normalizedConfig.storage === undefined) return null;

    const stored = await normalizedConfig.storage.getItem(normalizedConfig.storageKey);
    currentSession = parseStoredSession(stored);
    if (!isAuthSessionExpired(currentSession)) return currentSession;

    currentSession = null;
    await normalizedConfig.storage.removeItem(normalizedConfig.storageKey);
    return null;
  };

  const handleSessionResponse = async (
    response: Response,
    options: { clearExpiredSession?: boolean } = {},
  ): Promise<AuthResult<AuthSession>> => {
    const body = await readResponseBody(response);
    if (!response.ok) {
      const error = mapSupabaseError(response, body);
      if (options.clearExpiredSession === true && error.code === 'session_expired') {
        const persistenceError = await persistSessionSafely(null);
        if (persistenceError !== null) return { ok: false, error: persistenceError };
      }
      return { ok: false, error };
    }

    const session = normalizeSupabaseSession(body);
    if (session === null) {
      return {
        ok: false,
        error: createAuthError(
          'provider_error',
          'Supabase Auth returned an invalid session response.',
          body,
        ),
      };
    }

    const persistenceError = await persistSessionSafely(session);
    return persistenceError === null
      ? { ok: true, data: session }
      : { ok: false, error: persistenceError };
  };

  const oauthStorage = normalizedConfig.storage;
  const profileVerifier = createProfileVerifier(normalizedConfig);
  const oauth =
    normalizedConfig.oauthProviders.length === 0
      ? undefined
      : createSupabaseOAuthAdapter({
          url: normalizedConfig.url,
          anonKey: normalizedConfig.anonKey,
          fetch: normalizedConfig.fetch,
          storage: requireOAuthStorage(oauthStorage),
          storageKey: normalizedConfig.storageKey,
          providers: normalizedConfig.oauthProviders,
          persistSession: async (session) => {
            const error = await persistSessionSafely(session);
            if (error !== null) throw new Error(error.message);
          },
          ...(profileVerifier === undefined ? {} : { verifyProfile: profileVerifier }),
          ...(normalizedConfig.onOAuthLifecycleEvent === undefined
            ? {}
            : { onLifecycleEvent: normalizedConfig.onOAuthLifecycleEvent }),
        });

  return {
    capabilities: {
      signInIdentifiers: ['email', 'phone'],
      supportsSignUp: true,
      supportsPasswordReset: true,
      supportsOtp: true,
      supportsSessionRefresh: true,
    },
    ...(oauth === undefined ? {} : { oauth }),

    async signIn(input: SignInInput): Promise<AuthResult<AuthSession>> {
      const passwordError = validatePassword(input.password);
      if (passwordError !== null) return { ok: false, error: passwordError };
      const identifier = identifierBody(input.identifier);
      if (!identifier.ok) return { ok: false, error: identifier.error };
      try {
        const response = await request('token?grant_type=password', {
          body: { ...identifier.data, password: input.password },
        });
        return await handleSessionResponse(response);
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },

    async signUp(input: SignUpInput): Promise<AuthResult<AuthSession | AuthUser>> {
      const passwordError = validatePassword(input.password);
      if (passwordError !== null) return { ok: false, error: passwordError };
      const identifier = identifierBody(input.identifier);
      if (!identifier.ok) return { ok: false, error: identifier.error };
      try {
        const response = await request('signup', {
          body: {
            ...identifier.data,
            password: input.password,
            ...metadataBody(input.profile, input.metadata),
          },
          redirectTo: input.redirectTo,
        });
        const body = await readResponseBody(response);
        if (!response.ok) return { ok: false, error: mapSupabaseError(response, body) };
        const session = normalizeSupabaseSession(body);
        if (session !== null) {
          const persistenceError = await persistSessionSafely(session);
          return persistenceError === null
            ? { ok: true, data: session }
            : { ok: false, error: persistenceError };
        }
        const user = normalizeSupabaseUser(isRecord(body) && 'user' in body ? body.user : body);
        if (user !== null) return { ok: true, data: user };
        return {
          ok: false,
          error: createAuthError(
            'provider_error',
            'Supabase Auth returned an invalid sign-up response.',
            body,
          ),
        };
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },

    async signOut(input?: SignOutInput): Promise<AuthResult> {
      let providerError: AuthAdapterError | null = null;
      let session: AuthSession | null = null;

      try {
        session = await readStoredSession();
      } catch {
        providerError = createAuthError(
          'session_persistence_failed',
          'The persisted auth session could not be read before sign-out.',
        );
      }

      if (providerError === null && session?.accessToken !== undefined) {
        try {
          const response = await request('logout', {
            accessToken: session.accessToken,
            body: input?.allDevices === true ? { scope: 'global' } : undefined,
          });
          if (!response.ok) {
            const body = await readResponseBody(response);
            providerError = mapSupabaseError(response, body);
          }
        } catch (error) {
          providerError = mapNetworkError(error);
        }
      }

      const persistenceError = await persistSessionSafely(null);
      if (persistenceError !== null) return { ok: false, error: persistenceError };
      return providerError === null ? { ok: true } : { ok: false, error: providerError };
    },

    async getSession(): Promise<AuthResult<AuthSession | null>> {
      try {
        return { ok: true, data: await readStoredSession() };
      } catch {
        return {
          ok: false,
          error: createAuthError(
            'session_persistence_failed',
            'The persisted auth session could not be read.',
          ),
        };
      }
    },

    async refreshSession(): Promise<AuthResult<AuthSession | null>> {
      let session: AuthSession | null;
      try {
        session = await readStoredSession();
      } catch {
        return {
          ok: false,
          error: createAuthError(
            'session_persistence_failed',
            'The persisted auth session could not be read for refresh.',
          ),
        };
      }

      if (session?.refreshToken === undefined) {
        return {
          ok: false,
          error: createAuthError('missing_refresh_token', 'No refresh token is available.'),
        };
      }
      try {
        const response = await request('token?grant_type=refresh_token', {
          body: { refresh_token: session.refreshToken },
        });
        return await handleSessionResponse(response, { clearExpiredSession: true });
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },

    async requestPasswordReset(input: PasswordResetInput): Promise<AuthResult> {
      if (input.identifier.kind !== 'email') {
        return {
          ok: false,
          error: createAuthError(
            'unsupported_identifier',
            'Password reset supports email identifiers only.',
          ),
        };
      }
      const value = input.identifier.value.trim();
      if (value.length === 0) {
        return {
          ok: false,
          error: createAuthError('missing_identifier', 'An auth identifier is required.'),
        };
      }
      try {
        const response = await request('recover', {
          body: { email: value },
          redirectTo: input.redirectTo,
        });
        if (!response.ok) {
          const body = await readResponseBody(response);
          return { ok: false, error: mapSupabaseError(response, body) };
        }
        return { ok: true };
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },

    async verifyOtp(input: VerifyOtpInput): Promise<AuthResult<AuthSession>> {
      const token = input.token.trim();
      if (token.length === 0) {
        return {
          ok: false,
          error: createAuthError('validation_error', 'An OTP token is required.'),
        };
      }
      const identifier = identifierBody(input.identifier);
      if (!identifier.ok) return { ok: false, error: identifier.error };
      try {
        const response = await request('verify', {
          body: {
            ...identifier.data,
            token,
            type: input.identifier.kind === 'phone' ? 'sms' : 'email',
          },
          redirectTo: input.redirectTo,
        });
        return await handleSessionResponse(response);
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },
  };
}

function validateConfig(config: SupabaseAuthConfig): RequiredConfig {
  const url = config.url.trim();
  const anonKey = config.anonKey.trim();
  if (url.length === 0) throw new TypeError('Supabase Auth URL is required.');
  try {
    new URL(url);
  } catch {
    throw new TypeError('Supabase Auth URL must be a valid URL.');
  }
  if (anonKey.length === 0) throw new TypeError('Supabase anon key is required.');
  const fetchImplementation = config.fetch ?? globalThis.fetch;
  if (typeof fetchImplementation !== 'function')
    throw new TypeError('A fetch implementation is required to use Supabase Auth.');

  const oauthProviders: SupabaseOAuthProviderId[] = [];
  for (const rawProvider of config.oauthProviders ?? []) {
    const provider: AuthOAuthProviderId = rawProvider.trim();
    if (!isSupabaseOAuthProviderId(provider)) {
      throw new TypeError(
        `Supabase OAuth provider "${provider}" is not supported by the current provider registry.`,
      );
    }
    if (!oauthProviders.includes(provider)) oauthProviders.push(provider);
  }
  if (oauthProviders.length > 0 && config.storage === undefined) {
    throw new TypeError('Supabase OAuth PKCE requires persistent auth storage.');
  }
  if (config.profileVerification !== undefined && oauthProviders.length === 0) {
    throw new TypeError(
      'Supabase OAuth profile verification requires at least one OAuth provider.',
    );
  }

  const configuredStorageKey = config.storageKey?.trim();
  const profileVerification =
    config.profileVerification === undefined
      ? undefined
      : normalizeSupabaseAuthProfileVerificationConfig(config.profileVerification);

  return {
    url: url.replace(/\/+$/, ''),
    anonKey,
    fetch: fetchImplementation,
    storage: config.storage,
    storageKey:
      configuredStorageKey === undefined || configuredStorageKey.length === 0
        ? DEFAULT_STORAGE_KEY
        : configuredStorageKey,
    oauthProviders,
    profileVerification,
    onOAuthLifecycleEvent: config.onOAuthLifecycleEvent,
  };
}

function createProfileVerifier(config: RequiredConfig): SupabaseOAuthProfileVerifier | undefined {
  if (config.profileVerification === undefined) return undefined;
  return createSupabaseOAuthProfileVerifier({
    url: config.url,
    anonKey: config.anonKey,
    fetch: config.fetch,
    config: config.profileVerification,
  });
}

function requireOAuthStorage(
  storage: SupabaseAuthConfig['storage'],
): NonNullable<SupabaseAuthConfig['storage']> {
  if (storage === undefined) {
    throw new TypeError('Supabase OAuth PKCE requires persistent auth storage.');
  }
  return storage;
}

function validatePassword(password: string | undefined) {
  return password === undefined || password.length === 0
    ? createAuthError('missing_password', 'A password is required.')
    : null;
}

function identifierBody(identifier: SignInInput['identifier']): IdentifierResult {
  const value = identifier.value.trim();
  if (value.length === 0)
    return {
      ok: false,
      error: createAuthError('missing_identifier', 'An auth identifier is required.'),
    };
  if (identifier.kind === 'email') return { ok: true, data: { email: value } };
  if (identifier.kind === 'phone') return { ok: true, data: { phone: value } };
  return {
    ok: false,
    error: createAuthError(
      'unsupported_identifier',
      'Supabase Auth supports email and phone identifiers.',
    ),
  };
}

function metadataBody(
  profile: Record<string, unknown> | undefined,
  metadata: Record<string, unknown> | undefined,
): { data?: Record<string, unknown> } {
  const data = { ...(profile ?? {}), ...(metadata ?? {}) };
  return Object.keys(data).length > 0 ? { data } : {};
}

function createHeaders(anonKey: string, accessToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    apikey: anonKey,
    'Content-Type': 'application/json',
  };
  if (accessToken !== undefined) headers.Authorization = `Bearer ${accessToken}`;
  return headers;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface RequiredConfig {
  url: string;
  anonKey: string;
  fetch: SupabaseAuthFetch;
  storage?: SupabaseAuthStorage;
  storageKey: string;
  oauthProviders: SupabaseOAuthProviderId[];
  profileVerification?: SupabaseAuthProfileVerificationConfig;
  onOAuthLifecycleEvent?: SupabaseOAuthLifecycleObserver;
}

type IdentifierResult =
  | { ok: true; data: { email: string } | { phone: string } }
  | { ok: false; error: ReturnType<typeof createAuthError> };
