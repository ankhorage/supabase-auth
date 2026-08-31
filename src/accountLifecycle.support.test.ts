import type { AuthAdapter, AuthSession } from '@ankhorage/contracts/auth';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import type { SupabaseAuthStorage, SupabaseOAuthLifecycleEvent } from './types.js';

export const SESSION_STORAGE_KEY = 'ankhorage.supabase-auth.session';
export const ACCESS_TOKEN = 'sentinel-phase3-access-token-do-not-leak';
export const REFRESH_TOKEN = 'sentinel-phase3-refresh-token-do-not-leak';
export const CALLBACK_CODE = 'sentinel-phase3-callback-code-do-not-leak';

export function createStoredSession(): AuthSession {
  return {
    accessToken: 'stored-access-token',
    refreshToken: 'stored-refresh-token',
    user: { id: 'stored-user', email: 'stored@example.com' },
  };
}

export function createMemoryStorage(initial: Record<string, string> = {}): {
  storage: SupabaseAuthStorage;
  values: Map<string, string>;
} {
  const values = new Map(Object.entries(initial));
  return {
    values,
    storage: {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => {
        values.set(key, value);
      },
      removeItem: (key) => {
        values.delete(key);
      },
    },
  };
}

export function createOAuthFetch(input: {
  profileRows: readonly Record<string, unknown>[];
  calls?: string[];
}): typeof fetch {
  return Object.assign(
    (request: Parameters<typeof fetch>[0]) => {
      const url = request instanceof Request ? request.url : request.toString();
      input.calls?.push(url);
      if (url.includes('/auth/v1/token?grant_type=pkce'))
        return Promise.resolve(oauthSessionResponse());
      if (url.includes('/rest/v1/profiles?'))
        return Promise.resolve(jsonResponse(input.profileRows));
      throw new Error(`Unexpected OAuth lifecycle request: ${url}`);
    },
    { preconnect: globalThis.fetch.preconnect },
  );
}

export async function completeOAuth(adapter: AuthAdapter, provider: 'apple' | 'google') {
  const started = await adapter.oauth?.startAuthorization({
    provider,
    redirectUri: 'ankh-app://auth/callback',
  });
  if (started?.ok !== true) throw new Error('OAuth start failed.');
  const completed = await adapter.oauth?.completeAuthorization({
    attemptId: started.data.attemptId,
    response: { type: 'callback', url: `ankh-app://auth/callback?code=${CALLBACK_CODE}` },
  });
  return { started, completed };
}

export function createVerifiedProfileHarness() {
  const { storage, values } = createMemoryStorage();
  const events: SupabaseOAuthLifecycleEvent[] = [];
  const calls: string[] = [];
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    storage,
    oauthProviders: ['google'],
    profileVerification: {
      table: 'profiles',
      fields: ['email', 'displayName', 'avatarUrl'],
      maxAttempts: 1,
      retryDelayMs: 0,
    },
    onOAuthLifecycleEvent: (event) => {
      events.push(event);
    },
    fetch: createOAuthFetch({
      calls,
      profileRows: [
        {
          id: 'oauth-user',
          email: 'person@example.com',
          display_name: 'OAuth Person',
          avatar_url: 'https://example.com/oauth.png',
        },
      ],
    }),
  });
  return { adapter, calls, events, values };
}

function oauthSessionResponse(): Response {
  return jsonResponse({
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    expires_in: 3600,
    token_type: 'bearer',
    user: {
      id: 'oauth-user',
      email: 'person@example.com',
      app_metadata: {},
      user_metadata: {
        full_name: 'OAuth Person',
        avatar_url: 'https://example.com/oauth.png',
      },
      aud: 'authenticated',
    },
  });
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'content-type': 'application/json', ...init.headers },
  });
}
