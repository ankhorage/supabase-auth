import type {
  AuthAdapter,
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
import { normalizeSupabaseSession, normalizeSupabaseUser, parseStoredSession } from './session.js';
import type { SupabaseAuthConfig } from './types.js';

const DEFAULT_STORAGE_KEY = 'ankhorage.supabase-auth.session';

export function createSupabaseAuthAdapter(config: SupabaseAuthConfig): AuthAdapter {
  const normalizedConfig = validateConfig(config);
  let currentSession: AuthSession | null = null;

  const request = async (
    path: string,
    options: {
      body?: Record<string, unknown>;
      accessToken?: string;
      redirectTo?: string;
    } = {},
  ): Promise<Response> => {
    const url = new URL(`${normalizedConfig.url}/auth/v1/${path}`);

    if (options.redirectTo !== undefined) {
      url.searchParams.set('redirect_to', options.redirectTo);
    }

    return normalizedConfig.fetch(url, {
      method: 'POST',
      headers: createHeaders(normalizedConfig.anonKey, options.accessToken),
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  };

  const persistSession = async (session: AuthSession | null): Promise<void> => {
    currentSession = session;

    if (normalizedConfig.storage === undefined) {
      return;
    }

    if (session === null) {
      await normalizedConfig.storage.removeItem(normalizedConfig.storageKey);
      return;
    }

    await normalizedConfig.storage.setItem(normalizedConfig.storageKey, JSON.stringify(session));
  };

  const readStoredSession = async (): Promise<AuthSession | null> => {
    if (currentSession !== null) {
      return currentSession;
    }

    if (normalizedConfig.storage === undefined) {
      return null;
    }

    const stored = await normalizedConfig.storage.getItem(normalizedConfig.storageKey);
    currentSession = parseStoredSession(stored);

    return currentSession;
  };

  const handleSessionResponse = async (response: Response): Promise<AuthResult<AuthSession>> => {
    const body = await readResponseBody(response);

    if (!response.ok) {
      return { ok: false, error: mapSupabaseError(response, body) };
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

    await persistSession(session);

    return { ok: true, data: session };
  };

  return {
    capabilities: {
      signInIdentifiers: ['email', 'phone'],
      supportsSignUp: true,
      supportsPasswordReset: true,
      supportsOtp: true,
      supportsSessionRefresh: true,
    },

    async signIn(input: SignInInput): Promise<AuthResult<AuthSession>> {
      const passwordError = validatePassword(input.password);

      if (passwordError !== null) {
        return { ok: false, error: passwordError };
      }

      const identifier = identifierBody(input.identifier);

      if (!identifier.ok) {
        return { ok: false, error: identifier.error };
      }

      try {
        const response = await request('token?grant_type=password', {
          body: {
            ...identifier.data,
            password: input.password,
          },
        });

        return await handleSessionResponse(response);
      } catch (error) {
        return { ok: false, error: mapNetworkError(error) };
      }
    },

    async signUp(input: SignUpInput): Promise<AuthResult<AuthSession | AuthUser>> {
      const passwordError = validatePassword(input.password);

      if (passwordError !== null) {
        return { ok: false, error: passwordError };
      }

      const identifier = identifierBody(input.identifier);

      if (!identifier.ok) {
        return { ok: false, error: identifier.error };
      }

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

        if (!response.ok) {
          return { ok: false, error: mapSupabaseError(response, body) };
        }

        const session = normalizeSupabaseSession(body);

        if (session !== null) {
          await persistSession(session);
          return { ok: true, data: session };
        }

        const user = normalizeSupabaseUser(isRecord(body) && 'user' in body ? body.user : body);

        if (user !== null) {
          return { ok: true, data: user };
        }

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
      const session = await readStoredSession();
      await persistSession(null);

      if (session?.accessToken === undefined) {
        return { ok: true };
      }

      try {
        const response = await request('logout', {
          accessToken: session.accessToken,
          body: input?.allDevices === true ? { scope: 'global' } : undefined,
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

    async getSession(): Promise<AuthResult<AuthSession | null>> {
      return { ok: true, data: await readStoredSession() };
    },

    async refreshSession(): Promise<AuthResult<AuthSession | null>> {
      const session = await readStoredSession();

      if (session?.refreshToken === undefined) {
        return {
          ok: false,
          error: createAuthError('missing_refresh_token', 'No refresh token is available.'),
        };
      }

      try {
        const response = await request('token?grant_type=refresh_token', {
          body: {
            refresh_token: session.refreshToken,
          },
        });

        return await handleSessionResponse(response);
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

      if (input.identifier.value.length === 0) {
        return {
          ok: false,
          error: createAuthError('missing_identifier', 'An auth identifier is required.'),
        };
      }

      try {
        const response = await request('recover', {
          body: {
            email: input.identifier.value,
          },
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
      if (input.token.length === 0) {
        return {
          ok: false,
          error: createAuthError('validation_error', 'An OTP token is required.'),
        };
      }

      const identifier = identifierBody(input.identifier);

      if (!identifier.ok) {
        return { ok: false, error: identifier.error };
      }

      try {
        const response = await request('verify', {
          body: {
            ...identifier.data,
            token: input.token,
            type: input.identifier.kind === 'phone' ? 'sms' : 'email',
            ...metadataBody(undefined, input.metadata),
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

  if (url.length === 0) {
    throw new TypeError('Supabase Auth URL is required.');
  }

  try {
    new URL(url);
  } catch {
    throw new TypeError('Supabase Auth URL must be a valid URL.');
  }

  if (anonKey.length === 0) {
    throw new TypeError('Supabase anon key is required.');
  }

  const fetchImplementation = config.fetch ?? globalThis.fetch;

  if (typeof fetchImplementation !== 'function') {
    throw new TypeError('A fetch implementation is required to use Supabase Auth.');
  }

  return {
    url: url.replace(/\/+$/, ''),
    anonKey,
    fetch: fetchImplementation,
    storage: config.storage,
    storageKey: config.storageKey ?? DEFAULT_STORAGE_KEY,
  };
}

function validatePassword(password: string | undefined) {
  if (password === undefined || password.length === 0) {
    return createAuthError('missing_password', 'A password is required.');
  }

  return null;
}

function identifierBody(identifier: SignInInput['identifier']): IdentifierResult {
  const value = identifier.value.trim();

  if (value.length === 0) {
    return {
      ok: false,
      error: createAuthError('missing_identifier', 'An auth identifier is required.'),
    };
  }

  if (identifier.kind === 'email') {
    return { ok: true, data: { email: value } };
  }

  if (identifier.kind === 'phone') {
    return { ok: true, data: { phone: value } };
  }

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
  const data = {
    ...(profile ?? {}),
    ...(metadata ?? {}),
  };

  return Object.keys(data).length > 0 ? { data } : {};
}

function createHeaders(anonKey: string, accessToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    apikey: anonKey,
    'Content-Type': 'application/json',
  };

  if (accessToken !== undefined) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  return headers;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

interface RequiredConfig {
  url: string;
  anonKey: string;
  fetch: typeof fetch;
  storage?: SupabaseAuthConfig['storage'];
  storageKey: string;
}

type IdentifierResult =
  | {
      ok: true;
      data: { email: string } | { phone: string };
    }
  | {
      ok: false;
      error: ReturnType<typeof createAuthError>;
    };
