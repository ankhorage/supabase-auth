import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import {
  completeOAuthCode,
  createActiveGlobalFetchHarness,
  createInjectedCryptoHarness,
  createMemoryStorage,
  expectReplayProtection,
  isRecord,
  startGoogleOAuth,
  testFetch,
} from './oauth.support.test.js';

it('uses an injected CSPRNG for matching S256 and exchange values without global crypto', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
  try {
    const { storage, values } = createMemoryStorage();
    const harness = createInjectedCryptoHarness(storage, originalCrypto);
    const started = await startGoogleOAuth(harness.adapter);
    const authorizationUrl = new URL(started.authorizationUrl);
    const challenges = authorizationUrl.searchParams.getAll('code_challenge');
    expect(challenges).toHaveLength(1);
    expect(authorizationUrl.searchParams.getAll('code_challenge_method')).toEqual(['s256']);
    const challenge = challenges.at(0);
    if (challenge === undefined) throw new Error('PKCE challenge is missing.');
    harness.setChallenge(challenge);

    expect(
      await completeOAuthCode(harness.adapter, started.attemptId, 'native-opaque-code'),
    ).toMatchObject({ ok: true, status: 'authenticated' });
    await expectReplayProtection(harness.adapter, started.attemptId, 'native-opaque-code');
    expect(harness.stats()).toEqual({ exchanges: 1, matchingVerifier: true, randomValueCalls: 1 });
    expect([...values.values()].join('\n')).not.toContain('native-opaque-code');
    expect([...values.keys()].some((key) => key.endsWith('.pkce-verifier'))).toBe(false);
  } finally {
    if (descriptor === undefined) Reflect.deleteProperty(globalThis, 'crypto');
    else Object.defineProperty(globalThis, 'crypto', descriptor);
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
    fetch: testFetch((_input, init) => {
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
    }),
  });
  const started = await startGoogleOAuth(adapter);
  const challenge = new URL(started.authorizationUrl).searchParams.get('code_challenge');
  const completed = await completeOAuthCode(adapter, started.attemptId, callbackCode);

  const serializedResult = JSON.stringify(completed);
  const sensitiveValues = [
    exchangedVerifier,
    challenge ?? '',
    started.authorizationUrl,
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
  const harness = createActiveGlobalFetchHarness();
  globalThis.fetch = harness.staleFetch;
  try {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      oauthProviders: ['google'],
    });
    const started = await startGoogleOAuth(adapter);
    expect(harness.staleCalls).toHaveLength(0);
    globalThis.fetch = harness.activeFetch;
    const completed = await completeOAuthCode(adapter, started.attemptId, 'active-oauth-code');
    expect(completed).toMatchObject({
      ok: true,
      status: 'authenticated',
      session: {
        accessToken: 'default-oauth-access-token',
        user: { id: 'default-oauth-user' },
      },
    });
    expect(harness.staleCalls).toHaveLength(0);
    expect(harness.activeCalls).toHaveLength(1);
    expect(harness.activeCalls.at(0)).toMatchObject({
      hasExpectedCode: true,
      hasVerifier: true,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
