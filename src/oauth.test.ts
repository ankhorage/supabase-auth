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

    const persisted = values.get('ankhorage.supabase-auth.session') ?? '';
    expect(persisted).toContain('access-token');
    expect([...values.values()].join('\n')).not.toContain('opaque-code');
    expect([...values.keys()].some((key) => key.endsWith('-code-verifier'))).toBe(false);
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
