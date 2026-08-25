import { readFileSync } from 'node:fs';

import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

  it('starts with one canonical S256 PKCE flow and completes exactly once', async () => {
    const { storage, values } = createMemoryStorage();
    const calls: { url: string; hasExpectedCode: boolean; hasVerifier: boolean }[] = [];
    const fetcher: typeof fetch = (input, init) => {
      const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      calls.push({
        url: input instanceof Request ? input.url : input.toString(),
        hasExpectedCode: isRecord(body) && body.auth_code === 'opaque-code',
        hasVerifier: isRecord(body) && typeof body.code_verifier === 'string',
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
    const authorizationUrl = new URL(started.data.authorizationUrl);
    expect(authorizationUrl.pathname).toBe('/auth/v1/authorize');
    expect(authorizationUrl.searchParams.getAll('code_challenge').length).toBe(1);
    expect(authorizationUrl.searchParams.getAll('code_challenge_method').length).toBe(1);
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('s256');
    expect(authorizationUrl.searchParams.get('prompt')).toBe('select_account');
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
    expect(calls[0]?.hasExpectedCode).toBe(true);
    expect(calls[0]?.hasVerifier).toBe(true);

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
    expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
  });

  it('serializes concurrent exact replay and mismatched callback completion', async () => {
    const { storage } = createMemoryStorage();
    let exchanges = 0;
    let releaseExchange: (() => void) | undefined;
    let reportExchangeStarted: (() => void) | undefined;
    const exchangeGate = new Promise<void>((resolve) => {
      releaseExchange = resolve;
    });
    const exchangeStarted = new Promise<void>((resolve) => {
      reportExchangeStarted = resolve;
    });
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
      async fetch() {
        exchanges += 1;
        reportExchangeStarted?.();
        await exchangeGate;
        return Response.json({
          access_token: 'concurrent-access-token',
          refresh_token: 'concurrent-refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'concurrent-user',
            email: 'concurrent@example.com',
            app_metadata: {},
            user_metadata: {},
            aud: 'authenticated',
          },
        });
      },
    });
    const started = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (started?.ok !== true) throw new Error('OAuth start failed.');

    const exactCallback = {
      attemptId: started.data.attemptId,
      response: {
        type: 'callback' as const,
        url: 'ankh-app://auth/callback?code=concurrent-code',
      },
    };
    const firstCompletion = adapter.oauth?.completeAuthorization(exactCallback);
    const exactReplay = adapter.oauth?.completeAuthorization(exactCallback);
    const mismatch = adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: 'ankh-app://auth/callback?code=concurrent-mismatch',
      },
    });

    await exchangeStarted;
    releaseExchange?.();
    expect(await firstCompletion).toMatchObject({ ok: true, status: 'authenticated' });
    expect(await exactReplay).toMatchObject({
      ok: false,
      status: 'error',
      error: { code: 'callback_already_completed' },
    });
    expect(await mismatch).toMatchObject({
      ok: false,
      status: 'error',
      error: { code: 'invalid_callback' },
    });
    expect(exchanges).toBe(1);
  });

  it('rejects a consumed callback after a newer authorization attempt starts', async () => {
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
          Response.json({
            access_token: `cross-attempt-access-${exchanges}`,
            refresh_token: `cross-attempt-refresh-${exchanges}`,
            expires_in: 3600,
            token_type: 'bearer',
            user: {
              id: 'cross-attempt-user',
              email: 'cross-attempt@example.com',
              app_metadata: {},
              user_metadata: {},
              aud: 'authenticated',
            },
          }),
        );
      },
    });
    const first = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (first?.ok !== true) throw new Error('First OAuth start failed.');
    const consumedCallback = 'ankh-app://auth/callback?code=already-consumed-code';
    expect(
      await adapter.oauth?.completeAuthorization({
        attemptId: first.data.attemptId,
        response: { type: 'callback', url: consumedCallback },
      }),
    ).toMatchObject({ ok: true, status: 'authenticated' });

    const second = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (second?.ok !== true) throw new Error('Second OAuth start failed.');
    const stale = await adapter.oauth?.completeAuthorization({
      attemptId: second.data.attemptId,
      response: { type: 'callback', url: consumedCallback },
    });

    expect(stale).toMatchObject({
      ok: false,
      status: 'error',
      error: { code: 'invalid_callback' },
    });
    expect(exchanges).toBe(1);
    expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
    expect([...values.values()].join('\n')).not.toContain('already-consumed-code');
    expect(values.get('ankhorage.supabase-auth.session.oauth.consumed-callbacks')).toMatch(
      /"fingerprint":"[0-9a-f]{64}"/u,
    );

    const third = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (third?.ok !== true) throw new Error('Third OAuth start failed.');
    expect(
      await adapter.oauth?.completeAuthorization({
        attemptId: third.data.attemptId,
        response: {
          type: 'callback',
          url: 'ankh-app://auth/callback?code=fresh-cross-attempt-code',
        },
      }),
    ).toMatchObject({ ok: true, status: 'authenticated' });
    expect(exchanges).toBe(2);
  });

  it('uses an injected CSPRNG for matching S256 and exchange values without global crypto', async () => {
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const originalCrypto = globalThis.crypto;
    let randomValueCalls = 0;
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    });

    try {
      const { storage, values } = createMemoryStorage();
      let exchanges = 0;
      let exchangeUsedMatchingVerifier = false;
      let authorizationChallenge: string | null = null;
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
        storage,
        oauthProviders: ['google'],
        oauthRandomBytes(length) {
          randomValueCalls += 1;
          return originalCrypto.getRandomValues(new Uint8Array(length));
        },
        fetch: (_input, init) => {
          exchanges += 1;
          const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
          const verifier = isRecord(body) ? body.code_verifier : undefined;
          if (typeof verifier === 'string' && authorizationChallenge !== null) {
            const expectedChallenge = Buffer.from(sha256(utf8ToBytes(verifier))).toString(
              'base64url',
            );
            exchangeUsedMatchingVerifier = expectedChallenge === authorizationChallenge;
          }
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
      const authorizationUrl = new URL(started.data.authorizationUrl);
      const challenges = authorizationUrl.searchParams.getAll('code_challenge');
      const methods = authorizationUrl.searchParams.getAll('code_challenge_method');
      authorizationChallenge = challenges[0] ?? null;
      expect(challenges.length).toBe(1);
      expect(methods.length).toBe(1);
      expect(methods[0]).toBe('s256');
      expect(authorizationChallenge !== null && authorizationChallenge.length > 0).toBe(true);
      expect(randomValueCalls > 0).toBe(true);

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
      expect(exchangeUsedMatchingVerifier).toBe(true);
      expect(values.get('ankhorage.supabase-auth.session.oauth.attempt')).toMatch(
        /"callbackFingerprint":"[0-9a-f]{64}"/u,
      );
      expect([...values.values()].join('\n')).not.toContain('native-opaque-code');
      expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
    } finally {
      if (cryptoDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'crypto');
      } else {
        Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
      }
    }
  });

  it('rejects an invalid injected random byte result without persisting PKCE state', async () => {
    const { storage, values } = createMemoryStorage();
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
      oauthRandomBytes: () => new Uint8Array(31),
    });

    expect(
      await adapter.oauth?.startAuthorization({
        provider: 'google',
        redirectUri: 'ankh-app://auth/callback',
      }),
    ).toMatchObject({
      ok: false,
      error: { code: 'session_persistence_failed' },
    });
    expect([...values.keys()].some((key) => key.includes('.oauth'))).toBe(false);
  });

  it('redacts every PKCE and OAuth value from terminal exchange errors', async () => {
    const { storage, values } = createMemoryStorage();
    let exchangedVerifier = '';
    const callbackCode = 'redaction-callback-value';
    const returnedToken = 'redaction-returned-value';
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
      fetch: (_input, init) => {
        const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
        const verifier = isRecord(body) ? body.code_verifier : undefined;
        if (typeof verifier === 'string') exchangedVerifier = verifier;
        return Promise.resolve(
          Response.json(
            {
              message: `${exchangedVerifier} ${callbackCode} ${returnedToken}`,
            },
            { status: 400 },
          ),
        );
      },
    });
    const started = await adapter.oauth?.startAuthorization({
      provider: 'google',
      redirectUri: 'ankh-app://auth/callback',
    });
    if (started?.ok !== true) throw new Error('OAuth start failed.');
    const challenge = new URL(started.data.authorizationUrl).searchParams.get('code_challenge');
    const completed = await adapter.oauth?.completeAuthorization({
      attemptId: started.data.attemptId,
      response: {
        type: 'callback',
        url: `ankh-app://auth/callback?code=${callbackCode}`,
      },
    });

    const serializedResult = JSON.stringify(completed);
    const sensitiveValues = [
      exchangedVerifier,
      challenge ?? '',
      started.data.authorizationUrl,
      callbackCode,
      returnedToken,
    ];
    expect(
      sensitiveValues.every((value) => value.length > 0 && !serializedResult.includes(value)),
    ).toBe(true);
    expect(completed?.ok === false && completed.status === 'error').toBe(true);
    expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
  });

  it('exchanges OAuth codes with the active default global fetch after adapter creation', async () => {
    const originalFetch = globalThis.fetch;
    const { storage } = createMemoryStorage();
    const staleCalls: { url: string }[] = [];
    const activeCalls: { url: string; hasExpectedCode: boolean; hasVerifier: boolean }[] = [];
    const staleFetch: typeof fetch = (input) => {
      staleCalls.push({
        url: input instanceof Request ? input.url : input.toString(),
      });
      return Promise.resolve(
        new Response(JSON.stringify({ message: 'stale OAuth fetch should not be used' }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        }),
      );
    };
    const activeFetch: typeof fetch = (input, init) => {
      const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      activeCalls.push({
        url: input instanceof Request ? input.url : input.toString(),
        hasExpectedCode: isRecord(body) && body.auth_code === 'active-oauth-code',
        hasVerifier: isRecord(body) && typeof body.code_verifier === 'string',
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
      expect(activeCalls[0]?.hasExpectedCode).toBe(true);
      expect(activeCalls[0]?.hasVerifier).toBe(true);
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

  it('uses only public Supabase HTTP contracts without private auth-js coupling', () => {
    const adapterSource = readFileSync(
      new URL('./createSupabaseAuthAdapter.ts', import.meta.url),
      'utf8',
    );
    const oauthSource = readFileSync(new URL('./oauth.ts', import.meta.url), 'utf8');

    expect(adapterSource).not.toContain('signInWith' + 'OAuth');
    expect(adapterSource).not.toContain('completeOAuth' + 'SignIn');
    expect(adapterSource).not.toContain('supports' + 'OAuth');
    expect(oauthSource).not.toContain('@supabase/auth-js');
    expect(oauthSource).not.toContain('@supabase/supabase-js');
    expect(oauthSource).not.toContain('crypto.subtle');
    expect(oauthSource).not.toContain('Math.random');
    expect(oauthSource).not.toContain('oauth-code-verifier');
    expect(oauthSource).toContain('/auth/v1/authorize');
    expect(oauthSource).toContain('/auth/v1/token?grant_type=pkce');
    expect(oauthSource).toContain('createPkcePair(input.randomBytes ?? randomBytes)');
  });
});
