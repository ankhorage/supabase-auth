import { readFileSync } from 'node:fs';

import type { AuthSession } from '@ankhorage/contracts/auth';
import { describe, expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import { normalizeSupabaseUser } from './session.js';
import type {
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
} from './types.js';

const SESSION_STORAGE_KEY = 'ankhorage.supabase-auth.session';
const ACCESS_TOKEN = 'sentinel-phase3-access-token-do-not-leak';
const REFRESH_TOKEN = 'sentinel-phase3-refresh-token-do-not-leak';
const CALLBACK_CODE = 'sentinel-phase3-callback-code-do-not-leak';

describe('complete OAuth account lifecycle', () => {
  it('normalizes Google and Apple provider metadata into the canonical AuthUser fields', () => {
    expect(
      normalizeSupabaseUser({
        id: 'google-user',
        email: 'google@example.com',
        user_metadata: {
          full_name: 'Google Person',
          avatar_url: 'https://example.com/google.png',
          preferred_username: 'google-person',
        },
      }),
    ).toMatchObject({
      id: 'google-user',
      email: 'google@example.com',
      displayName: 'Google Person',
      avatarUrl: 'https://example.com/google.png',
      username: 'google-person',
    });

    expect(
      normalizeSupabaseUser({
        id: 'apple-user',
        user_metadata: {
          email: 'apple@example.com',
          name: 'Apple Person',
          picture: 'https://example.com/apple.png',
        },
      }),
    ).toMatchObject({
      id: 'apple-user',
      email: 'apple@example.com',
      displayName: 'Apple Person',
      avatarUrl: 'https://example.com/apple.png',
    });
  });

  it('removes an expired persisted session before returning it', async () => {
    const { storage, values } = createMemoryStorage({
      [SESSION_STORAGE_KEY]: JSON.stringify({
        accessToken: 'expired-access-token',
        refreshToken: 'expired-refresh-token',
        expiresAt: Date.now() - 1_000,
        user: { id: 'expired-user' },
      }),
    });
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
    });

    expect(await adapter.getSession()).toEqual({ ok: true, data: null });
    expect(values.has(SESSION_STORAGE_KEY)).toBe(false);
  });

  it('clears an invalid refresh session and still clears local state after remote logout failure', async () => {
    const invalidRefresh = createMemoryStorage({
      [SESSION_STORAGE_KEY]: JSON.stringify(createStoredSession()),
    });
    const refreshAdapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage: invalidRefresh.storage,
      fetch: () =>
        Promise.resolve(
          jsonResponse(
            {
              error: 'invalid_grant',
              error_description: 'Invalid Refresh Token: Already Used',
            },
            { status: 400 },
          ),
        ),
    });

    expect(await refreshAdapter.refreshSession?.()).toMatchObject({
      ok: false,
      error: { code: 'session_expired' },
    });
    expect(invalidRefresh.values.has(SESSION_STORAGE_KEY)).toBe(false);

    const failedLogout = createMemoryStorage({
      [SESSION_STORAGE_KEY]: JSON.stringify(createStoredSession()),
    });
    const logoutAdapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage: failedLogout.storage,
      fetch: () => Promise.resolve(jsonResponse({ message: 'provider unavailable' }, { status: 503 })),
    });

    expect(await logoutAdapter.signOut()).toMatchObject({
      ok: false,
      error: { code: 'provider_error' },
    });
    expect(failedLogout.values.has(SESSION_STORAGE_KEY)).toBe(false);
    expect(await logoutAdapter.getSession()).toEqual({ ok: true, data: null });
  });

  it('verifies the generated profile and emits metadata-only correlated lifecycle events', async () => {
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
      onOAuthLifecycleEvent(event) {
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

    const started = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (started?.ok !== true) throw new Error('OAuth start failed.');

    const completed = await adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: `ankh-app://auth/callback?code=${CALLBACK_CODE}`,
      },
    });

    expect(completed).toMatchObject({
      ok: true,
      status: 'authenticated',
      provider: 'google',
      session: {
        accessToken: ACCESS_TOKEN,
        refreshToken: REFRESH_TOKEN,
        user: {
          id: 'oauth-user',
          email: 'person@example.com',
          displayName: 'OAuth Person',
          avatarUrl: 'https://example.com/oauth.png',
        },
      },
    });
    expect(calls.some((url) => url.includes('/auth/v1/token?grant_type=pkce'))).toBe(true);
    expect(calls.some((url) => url.includes('/rest/v1/profiles?'))).toBe(true);
    expect(events.map((event) => event.status)).toEqual([
      'started',
      'profile_verified',
      'authenticated',
    ]);
    expect(new Set(events.map((event) => event.correlationId))).toEqual(
      new Set([started.data.attemptId]),
    );

    const serializedEvents = JSON.stringify(events);
    expect(serializedEvents).not.toContain(ACCESS_TOKEN);
    expect(serializedEvents).not.toContain(REFRESH_TOKEN);
    expect(serializedEvents).not.toContain(CALLBACK_CODE);
    expect(serializedEvents).not.toContain('auth/callback');
    expect(values.get(SESSION_STORAGE_KEY)).toContain(ACCESS_TOKEN);
    expect([...values.keys()].some((key) => key.endsWith('-code-verifier'))).toBe(false);
    expect([...values.values()].join('\n')).not.toContain(CALLBACK_CODE);
  });

  it('returns a recoverable profile error while retaining the exchanged session for recovery', async () => {
    const { storage, values } = createMemoryStorage();
    const events: SupabaseOAuthLifecycleEvent[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['apple'],
      profileVerification: {
        table: 'profiles',
        maxAttempts: 1,
        retryDelayMs: 0,
      },
      onOAuthLifecycleEvent(event) {
        events.push(event);
      },
      fetch: createOAuthFetch({ profileRows: [] }),
    });

    const started = await adapter.oauth?.startAuthorization({
      provider: 'apple',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (started?.ok !== true) throw new Error('OAuth start failed.');

    const completed = await adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: `ankh-app://auth/callback?code=${CALLBACK_CODE}`,
      },
    });

    expect(completed).toMatchObject({
      ok: false,
      status: 'error',
      error: {
        code: 'profile_creation_failed',
        stage: 'profile',
        provider: 'apple',
        recoverable: true,
      },
    });
    expect(values.get(SESSION_STORAGE_KEY)).toContain(ACCESS_TOKEN);
    expect([...values.keys()].some((key) => key.endsWith('-code-verifier'))).toBe(false);
    expect(events.map((event) => event.status)).toEqual(['started', 'error']);
    expect(events[1]).toMatchObject({
      correlationId: started.data.attemptId,
      provider: 'apple',
      stage: 'profile',
      errorCode: 'profile_creation_failed',
    });
    expect(JSON.stringify({ completed, events })).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify({ completed, events })).not.toContain(CALLBACK_CODE);
  });

  it('documents one authoritative collision policy without custom account reassignment', () => {
    const policy = readFileSync(
      new URL('../docs/oauth-account-lifecycle.md', import.meta.url),
      'utf8',
    );

    expect(policy).toContain('same verified email');
    expect(policy).toContain('one Supabase user with multiple identities');
    expect(policy).toContain('Apple private relay');
    expect(policy).toContain('does not reassign an identity');
    expect(policy).toContain('Manual identity linking is outside Phase 3');
  });
});

function createStoredSession(): AuthSession {
  return {
    accessToken: 'stored-access-token',
    refreshToken: 'stored-refresh-token',
    user: { id: 'stored-user', email: 'stored@example.com' },
  };
}

function createMemoryStorage(initial: Record<string, string> = {}): {
  storage: SupabaseAuthStorage;
  values: Map<string, string>;
} {
  const values = new Map(Object.entries(initial));
  return {
    values,
    storage: {
      getItem(key) {
        return values.get(key) ?? null;
      },
      setItem(key, value) {
        values.set(key, value);
      },
      removeItem(key) {
        values.delete(key);
      },
    },
  };
}

function createOAuthFetch(input: {
  profileRows: readonly Record<string, unknown>[];
  calls?: string[];
}): typeof fetch {
  return (request) => {
    const url = request instanceof Request ? request.url : request.toString();
    input.calls?.push(url);

    if (url.includes('/auth/v1/token?grant_type=pkce')) {
      return Promise.resolve(
        jsonResponse({
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
        }),
      );
    }

    if (url.includes('/rest/v1/profiles?')) {
      return Promise.resolve(jsonResponse(input.profileRows));
    }

    throw new Error(`Unexpected OAuth lifecycle request: ${url}`);
  };
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...init.headers,
    },
  });
}
