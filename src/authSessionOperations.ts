import type {
  AuthAdapter,
  AuthAdapterError,
  AuthResult,
  AuthSession,
} from '@ankhorage/contracts/auth';

import type { AuthOperationContext } from './authSessionContext.js';
import { createAuthError, mapNetworkError, mapSupabaseError, readResponseBody } from './errors.js';

export function createSignOutOperation(context: AuthOperationContext): AuthAdapter['signOut'] {
  return async (input): Promise<AuthResult> => {
    const providerError = await signOutProvider(context, input?.allDevices === true);
    const persistenceError = await context.persistSessionSafely(null);
    if (persistenceError !== null) return { ok: false, error: persistenceError };
    return providerError === null ? { ok: true } : { ok: false, error: providerError };
  };
}

export function createGetSessionOperation(
  context: AuthOperationContext,
): AuthAdapter['getSession'] {
  return async (): Promise<AuthResult<AuthSession | null>> => {
    try {
      return { ok: true, data: await context.readStoredSession() };
    } catch {
      return {
        ok: false,
        error: createAuthError(
          'session_persistence_failed',
          'The persisted auth session could not be read.',
        ),
      };
    }
  };
}

export function createRefreshSessionOperation(
  context: AuthOperationContext,
): AuthAdapter['refreshSession'] {
  return async (): Promise<AuthResult<AuthSession | null>> => {
    const session = await readRefreshSession(context);
    if (!session.ok) return session;
    if (session.data?.refreshToken === undefined) {
      return {
        ok: false,
        error: createAuthError('missing_refresh_token', 'No refresh token is available.'),
      };
    }
    try {
      const response = await context.request('token?grant_type=refresh_token', {
        body: { refresh_token: session.data.refreshToken },
      });
      return await context.handleSessionResponse(response, { clearExpiredSession: true });
    } catch (error) {
      return { ok: false, error: mapNetworkError(error) };
    }
  };
}

async function signOutProvider(
  context: AuthOperationContext,
  allDevices: boolean,
): Promise<AuthAdapterError | null> {
  let session: AuthSession | null;
  try {
    session = await context.readStoredSession();
  } catch {
    return createAuthError(
      'session_persistence_failed',
      'The persisted auth session could not be read before sign-out.',
    );
  }
  if (session?.accessToken === undefined) return null;
  try {
    const response = await context.request('logout', {
      accessToken: session.accessToken,
      body: allDevices ? { scope: 'global' } : undefined,
    });
    return response.ok ? null : mapSupabaseError(response, await readResponseBody(response));
  } catch (error) {
    return mapNetworkError(error);
  }
}

async function readRefreshSession(
  context: AuthOperationContext,
): Promise<AuthResult<AuthSession | null>> {
  try {
    return { ok: true, data: await context.readStoredSession() };
  } catch {
    return {
      ok: false,
      error: createAuthError(
        'session_persistence_failed',
        'The persisted auth session could not be read for refresh.',
      ),
    };
  }
}
