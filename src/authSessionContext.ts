import type { AuthAdapterError, AuthResult, AuthSession } from '@ankhorage/contracts/auth';

import type { RequiredSupabaseAuthConfig } from './authConfiguration.js';
import { createAuthError, mapSupabaseError, readResponseBody } from './errors.js';
import { isAuthSessionExpired, normalizeSupabaseSession, parseStoredSession } from './session.js';

export interface AuthOperationContext {
  readonly config: RequiredSupabaseAuthConfig;
  readonly handleSessionResponse: (
    response: Response,
    options?: { readonly clearExpiredSession?: boolean },
  ) => Promise<AuthResult<AuthSession>>;
  readonly persistSessionSafely: (session: AuthSession | null) => Promise<AuthAdapterError | null>;
  readonly readStoredSession: () => Promise<AuthSession | null>;
  readonly request: (path: string, options?: AuthRequestOptions) => Promise<Response>;
}

interface AuthRequestOptions {
  readonly body?: Record<string, unknown>;
  readonly accessToken?: string;
  readonly redirectTo?: string;
}

export function createAuthOperationContext(
  config: RequiredSupabaseAuthConfig,
): AuthOperationContext {
  let currentSession: AuthSession | null = null;
  let sessionLoaded = false;
  const persistSession = async (session: AuthSession | null): Promise<void> => {
    if (config.storage !== undefined) {
      if (session === null) await config.storage.removeItem(config.storageKey);
      else await config.storage.setItem(config.storageKey, JSON.stringify(session));
    }
    currentSession = session;
    sessionLoaded = true;
  };
  const persistSessionSafely = createSafeSessionPersistence(persistSession);
  const readStoredSession = async (): Promise<AuthSession | null> => {
    if (sessionLoaded) return currentSession;
    sessionLoaded = true;
    if (config.storage === undefined) return null;
    currentSession = parseStoredSession(await config.storage.getItem(config.storageKey));
    if (!isAuthSessionExpired(currentSession)) return currentSession;
    currentSession = null;
    await config.storage.removeItem(config.storageKey);
    return null;
  };
  const request = createAuthRequest(config);
  return {
    config,
    request,
    persistSessionSafely,
    readStoredSession,
    handleSessionResponse: createSessionResponseHandler(persistSessionSafely),
  };
}

function createAuthRequest(config: RequiredSupabaseAuthConfig) {
  return async (path: string, options: AuthRequestOptions = {}): Promise<Response> => {
    const url = new URL(`${config.url}/auth/v1/${path}`);
    if (options.redirectTo !== undefined) url.searchParams.set('redirect_to', options.redirectTo);
    return config.fetch(url.toString(), {
      method: 'POST',
      headers: createHeaders(config.anonKey, options.accessToken),
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  };
}

function createSafeSessionPersistence(
  persistSession: (session: AuthSession | null) => Promise<void>,
) {
  return async (session: AuthSession | null): Promise<AuthAdapterError | null> => {
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
}

function createSessionResponseHandler(
  persistSessionSafely: AuthOperationContext['persistSessionSafely'],
): AuthOperationContext['handleSessionResponse'] {
  return async (response, options = {}) => {
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
        error: createAuthError('provider_error', 'Supabase returned an invalid session.', body),
      };
    }
    const persistenceError = await persistSessionSafely(session);
    return persistenceError === null
      ? { ok: true, data: session }
      : { ok: false, error: persistenceError };
  };
}

function createHeaders(anonKey: string, accessToken?: string): Record<string, string> {
  return {
    apikey: anonKey,
    'Content-Type': 'application/json',
    ...(accessToken === undefined ? {} : { Authorization: `Bearer ${accessToken}` }),
  };
}
