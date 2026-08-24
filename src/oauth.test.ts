import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import type { SupabaseAuthStorage } from './types.js';

function createMemoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  const storage: SupabaseAuthStorage = {
    getItem(key) {
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      values.set(key, value);
    },
    removeItem(key) {
      values.delete(key);
    },
  };
  return { storage, values };
}

describe('canonical OAuth PKCE adapter', () => {
  it('requires persistent storage when OAuth is enabled', () => {
    expect(() =>
      createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
        oauthProviders: ['google'],
      }),
    ).toThrow('Supabase OAuth PKCE requires persistent auth storage.');
  });

  it('starts with the Supabase client PKCE flow and completes exactly once', async () => {
    const { storage, values } = createMemoryStorage();
    const calls: { url: string; body: unknown }[] = [];
    const fetcher: typeof fetch = (input, init) => {
      calls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body,
      });
      return new Response(
        JSON.stringify({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'user-1',
            email: 'person@example.com',
            app_metadata: {},
            user_metadata: {
              full_name: 'Person',
              avatar_url: 'https://example.com/avatar.png',
            },
            aud: 'authenticated',
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      fetch: fetcher,
      oauthProviders: ['google'],
    });

    const started = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
      scopes: ['openid', 'email'],
      queryParams: { prompt: 'select_account' },
    });
    expect(started?.ok).toBe(true);
    if (started?.ok !== true) throw new Error('OAuth start failed.');
    expect(started.data.authorizationUrl).toContain('/auth/v1/authorize?');
    expect(started.data.authorizationUrl).toContain('code_challenge=');
    expect(started.data.authorizationUrl).toContain('prompt=select_account');
    expect(calls).toHaveLength(0);

    const completed = await adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: 'ankh-app://auth/callback?code=opaque-code',
      },
    });
    expect(completed).toMatchObject({
      ok: true,
      status: 'authenticated',
      provider: 'google',
      session: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        user: {
          id: 'user-1',
          email: 'person@example.com',
        },
      },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toContain('/auth/v1/token?grant_type=pkce');
    expect(calls[0]?.body).toMatchObject({ auth_code: 'opaque-code' });

    const replay = await adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: 'ankh-app://auth/callback?code=opaque-code',
      },
    });
    expect(replay).toMatchObject({
      ok: false,
      status: 'error',
      error: { code: 'callback_already_completed' },
    });
    expect(calls).toHaveLength(1);

    for (const callbackUrl of [
      'ankh-app://auth/callback',
      'ankh-app://auth/callback?code=stale-code',
      'ankh-app://auth/callback?code=opaque-code&unexpected=value',
      'ankh-app://auth/callback?code=opaque-code&error_description=invalid',
    ]) {
      const unrelated = await adapter.oauth?.completeAuthorization({
        attemptId: started.data.attemptId,
        response: { type: 'callback', url: callbackUrl },
      });
      expect(unrelated).toMatchObject({
        ok: false,
        status: 'error',
        error: { code: 'invalid_callback' },
      });
    }
    expect(calls).toHaveLength(1);

    const persisted = values.get('ankhorage.supabase-auth.session') ?? '';
    expect(persisted).toContain('access-token');
    expect([...values.values()].join('\n')).not.toContain('opaque-code');
    expect(values.get('ankhorage.supabase-auth.session.oauth.attempt')).toMatch(
      /"callbackFingerprint":"[0-9a-f]{64}"/u,
    );
    expect([...values.keys()].some((key) => key.endsWith('-code-verifier'))).toBe(false);
  });

  it('correlates native callback replays when Web Crypto is unavailable', async () => {
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    if (!Reflect.deleteProperty(globalThis, 'crypto')) {
      throw new Error('The test runtime crypto global could not be removed.');
    }

    try {
      const { storage, values } = createMemoryStorage();
      let exchanges = 0;
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
        storage,
        oauthProviders: ['google'],
        fetch: () => {
          exchanges += 1;
          return Promise.resolve(
            new Response(
              JSON.stringify({
                access_token: 'native-access-token',
                refresh_token: 'native-refresh-token',
                expires_in: 3600,
                token_type: 'bearer',
                user: {
                  id: 'native-user',
                  email: 'native@example.com',
                  app_metadata: {},
                  user_metadata: {},
                  aud: 'authenticated',
                },
              }),
              { status: 200, headers: { 'content-type': 'application/json' } },
            ),
          );
        },
      });
      const started = await adapter.oauth?.startAuthorization({
        provider: 'google',
        redirectUri: 'ankh-app://auth/callback',
      });
      if (started?.ok !== true) throw new Error('OAuth start failed.');

      const callbackUrl = 'ankh-app://auth/callback?code=native-opaque-code';
      expect(
        await adapter.oauth?.completeAuthorization({
          attemptId: started.data.attemptId,
          response: { type: 'callback', url: callbackUrl },
        }),
      ).toMatchObject({ ok: true, status: 'authenticated' });
      expect(
        await adapter.oauth?.completeAuthorization({
          attemptId: started.data.attemptId,
          response: { type: 'callback', url: callbackUrl },
        }),
      ).toMatchObject({
        ok: false,
        status: 'error',
        error: { code: 'callback_already_completed' },
      });
      expect(
        await adapter.oauth?.completeAuthorization({
          attemptId: started.data.attemptId,
          response: {
            type: 'callback',
            url: 'ankh-app://auth/callback?code=unrelated-native-code',
          },
        }),
      ).toMatchObject({
        ok: false,
        status: 'error',
        error: { code: 'invalid_callback' },
      });
      expect(exchanges).toBe(1);
      expect(values.get('ankhorage.supabase-auth.session.oauth.attempt')).toMatch(
        /"callbackFingerprint":"[0-9a-f]{64}"/u,
      );
      expect([...values.values()].join('\n')).not.toContain('native-opaque-code');
    } finally {
      if (cryptoDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'crypto');
      } else {
        Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
      }
    }
  });

  it('exchanges OAuth codes with the active default global fetch after adapter creation', async () => {
    const originalFetch = globalThis.fetch;
    const { storage } = createMemoryStorage();
    const staleCalls: { url: string; body: unknown }[] = [];
    const activeCalls: { url: string; body: unknown }[] = [];
    const staleFetch: typeof fetch = (input, init) => {
      staleCalls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
      });
      return Promise.resolve(
        new Response(JSON.stringify({ message: 'stale OAuth fetch should not be used' }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        }),
      );
    };
    const activeFetch: typeof fetch = (input, init) => {
      activeCalls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
      });
      return Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: 'default-oauth-access-token',
            refresh_token: 'default-oauth-refresh-token',
            expires_in: 3600,
            token_type: 'bearer',
            user: {
              id: 'default-oauth-user',
              email: 'default-oauth@example.com',
              app_metadata: {},
              user_metadata: {},
              aud: 'authenticated',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    };

    globalThis.fetch = staleFetch;
    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
        storage,
        oauthProviders: ['google'],
      });
      const started = await adapter.oauth?.startAuthorization({
        provider: 'google',
        redirectUri: 'ankh-app://auth/callback',
      });
      expect(started?.ok).toBe(true);
      if (started?.ok !== true) throw new Error('OAuth start failed.');
      expect(staleCalls).toHaveLength(0);

      globalThis.fetch = activeFetch;
      const completed = await adapter.oauth?.completeAuthorization({
        attemptId: started.data.attemptId,
        response: {
          type: 'callback',
          url: 'ankh-app://auth/callback?code=active-oauth-code',
        },
      });

      expect(completed).toMatchObject({
        ok: true,
        status: 'authenticated',
        provider: 'google',
        session: {
          accessToken: 'default-oauth-access-token',
          refreshToken: 'default-oauth-refresh-token',
          user: {
            id: 'default-oauth-user',
            email: 'default-oauth@example.com',
          },
        },
      });
      expect(staleCalls).toHaveLength(0);
      expect(activeCalls).toHaveLength(1);
      expect(activeCalls[0]?.url).toContain('/auth/v1/token?grant_type=pkce');
      expect(activeCalls[0]?.body).toMatchObject({ auth_code: 'active-oauth-code' });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('rejects disabled providers and unsafe redirects', async () => {
    const { storage } = createMemoryStorage();
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
    });
    expect(
      await adapter.oauth?.startAuthorization({
        provider: 'apple',
        redirectUri: 'ankh-app://auth/callback',
      }),
    ).toMatchObject({ ok: false, error: { code: 'provider_disabled' } });
    expect(
      await adapter.oauth?.startAuthorization({
        provider: 'google',
        redirectUri: 'javascript:alert(1)',
      }),
    ).toMatchObject({ ok: false, error: { code: 'invalid_redirect_uri' } });
  });

  it('models browser and provider cancellation without exchanging a code', async () => {
    const { storage } = createMemoryStorage();
    let calls = 0;
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
      fetch: () => {
        calls += 1;
        return Promise.reject(new Error('unexpected'));
      },
    });
    const started = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (started?.ok !== true) throw new Error('OAuth start failed.');
    expect(
      await adapter.oauth?.completeAuthorization({
        attemptId: started.data.attemptId,
        response: { type: 'cancelled', reason: 'browser_dismissed' },
      }),
    ).toEqual({
      ok: false,
      status: 'cancelled',
      provider: 'google',
      reason: 'browser_dismissed',
    });
    expect(calls).toBe(0);

    const startedAgain = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (startedAgain?.ok !== true) throw new Error('OAuth restart failed.');
    expect(
      await adapter.oauth?.completeAuthorization({
        attemptId: startedAgain.data.attemptId,
        response: {
          type: 'callback',
          url: 'ankh-app://auth/callback?error=access_denied',
        },
      }),
    ).toEqual({
      ok: false,
      status: 'cancelled',
      provider: 'google',
      reason: 'provider_denied',
    });
    expect(calls).toBe(0);
  });

  it('uses only the Supabase client OAuth APIs and removes the manual legacy surface', () => {
    const adapterSource = readFileSync(
      new URL('./createSupabaseAuthAdapter.ts', import.meta.url),
      'utf8',
    );
    const oauthSource = readFileSync(new URL('./oauth.ts', import.meta.url), 'utf8');

    expect(adapterSource).not.toContain('/auth/v1/authorize');
    expect(adapterSource).not.toContain('signInWith' + 'OAuth');
    expect(adapterSource).not.toContain('completeOAuth' + 'SignIn');
    expect(adapterSource).not.toContain('supports' + 'OAuth');
    expect(oauthSource).toContain('client.auth.signInWithOAuth');
    expect(oauthSource).toContain('client.auth.exchangeCodeForSession');
  });
});
