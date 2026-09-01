import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import {
  completeOAuthCode,
  createCanonicalOAuthHarness,
  createConcurrentOAuthHarness,
  createMemoryStorage,
  expectReplayProtection,
  oauthSessionResponse,
  startCanonicalOAuth,
  startGoogleOAuth,
  testFetch,
} from './oauth.support.test.js';

it('requires persistent storage when OAuth is enabled', () => {
  expect(() =>
    createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      oauthProviders: ['google'],
    }),
  ).toThrow('Supabase OAuth PKCE requires persistent auth storage.');
});

it('starts with one canonical S256 PKCE flow', async () => {
  const { adapter, calls } = createCanonicalOAuthHarness();
  const started = await startCanonicalOAuth(adapter);
  const authorizationUrl = new URL(started.authorizationUrl);
  expect(authorizationUrl.pathname).toBe('/auth/v1/authorize');
  expect(authorizationUrl.searchParams.getAll('code_challenge')).toHaveLength(1);
  expect(authorizationUrl.searchParams.getAll('code_challenge_method')).toEqual(['s256']);
  expect(authorizationUrl.searchParams.get('prompt')).toBe('select_account');
  expect(calls).toHaveLength(0);

  const completed = await completeOAuthCode(adapter, started.attemptId, 'opaque-code');
  expect(completed).toMatchObject({
    ok: true,
    status: 'authenticated',
    provider: 'google',
    session: {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      user: { id: 'user-1', email: 'person@example.com' },
    },
  });
  expect(calls).toHaveLength(1);
  expect(calls.at(0)?.hasExpectedCode).toBe(true);
  expect(calls.at(0)?.hasVerifier).toBe(true);
});

it('completes an OAuth callback exactly once', async () => {
  const { adapter, calls } = createCanonicalOAuthHarness();
  const started = await startCanonicalOAuth(adapter);
  await completeOAuthCode(adapter, started.attemptId, 'opaque-code');
  await expectReplayProtection(adapter, started.attemptId, 'opaque-code');
  for (const callbackUrl of [
    'ankh-app://auth/callback',
    'ankh-app://auth/callback?code=opaque-code&unexpected=value',
    'ankh-app://auth/callback?code=opaque-code&error_description=invalid',
  ]) {
    expect(
      await adapter.oauth?.completeAuthorization({
        attemptId: started.attemptId,
        response: { type: 'callback', url: callbackUrl },
      }),
    ).toMatchObject({ ok: false, error: { code: 'invalid_callback' } });
  }
  expect(calls).toHaveLength(1);
});

it('persists only the session and callback fingerprint after completion', async () => {
  const { adapter, values } = createCanonicalOAuthHarness();
  const started = await startCanonicalOAuth(adapter);
  await completeOAuthCode(adapter, started.attemptId, 'opaque-code');
  expect(values.get('ankhorage.supabase-auth.session')).toContain('access-token');
  expect([...values.values()].join('\n')).not.toContain('opaque-code');
  expect(values.get('ankhorage.supabase-auth.session.oauth.attempt')).toMatch(
    /"callbackFingerprint":"[0-9a-f]{64}"/u,
  );
  expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
});

it('serializes concurrent exact replay and mismatched callback completion', async () => {
  const { adapter, exchangeStarted, releaseExchange, exchangeCount } =
    createConcurrentOAuthHarness();
  const started = await startGoogleOAuth(adapter);

  const exactCallback = {
    attemptId: started.attemptId,
    response: {
      type: 'callback' as const,
      url: 'ankh-app://auth/callback?code=concurrent-code',
    },
  };
  const firstCompletion = adapter.oauth?.completeAuthorization(exactCallback);
  const exactReplay = adapter.oauth?.completeAuthorization(exactCallback);
  const mismatch = adapter.oauth?.completeAuthorization({
    attemptId: started.attemptId,
    response: {
      type: 'callback',
      url: 'ankh-app://auth/callback?code=concurrent-mismatch',
    },
  });

  await exchangeStarted;
  releaseExchange();
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
  expect(exchangeCount()).toBe(1);
});

it('rejects a consumed callback after a newer authorization attempt starts', async () => {
  const { storage, values } = createMemoryStorage();
  let exchanges = 0;
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    storage,
    oauthProviders: ['google'],
    fetch: testFetch(() => {
      exchanges += 1;
      return oauthSessionResponse({
        accessToken: `cross-attempt-access-${exchanges}`,
        refreshToken: `cross-attempt-refresh-${exchanges}`,
        userId: 'cross-attempt-user',
        email: 'cross-attempt@example.com',
      });
    }),
  });
  const first = await startGoogleOAuth(adapter);
  const consumedCallback = 'ankh-app://auth/callback?code=already-consumed-code';
  expect(await completeOAuthCode(adapter, first.attemptId, 'already-consumed-code')).toMatchObject({
    ok: true,
    status: 'authenticated',
  });

  const second = await startGoogleOAuth(adapter);
  const stale = await adapter.oauth?.completeAuthorization({
    attemptId: second.attemptId,
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

  const third = await startGoogleOAuth(adapter);
  expect(
    await completeOAuthCode(adapter, third.attemptId, 'fresh-cross-attempt-code'),
  ).toMatchObject({
    ok: true,
    status: 'authenticated',
  });
  expect(exchanges).toBe(2);
});
