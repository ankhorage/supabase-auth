import type { AuthAdapter } from '@ankhorage/contracts/auth';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { expect } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import type { SupabaseAuthStorage } from './types.js';

export interface CanonicalOAuthCall {
  readonly url: string;
  readonly hasExpectedCode: boolean;
  readonly hasVerifier: boolean;
}

export function createMemoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  const storage: SupabaseAuthStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
    removeItem: (key) => {
      values.delete(key);
    },
  };
  return { storage, values };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function testFetch(
  handler: (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ) => Promise<Response> | Response,
): typeof fetch {
  return Object.assign(
    async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) =>
      handler(input, init),
    { preconnect: globalThis.fetch.preconnect },
  );
}

export function oauthSessionResponse(input: {
  accessToken: string;
  refreshToken: string;
  userId: string;
  email: string;
}): Response {
  return Response.json({
    access_token: input.accessToken,
    refresh_token: input.refreshToken,
    expires_in: 3600,
    token_type: 'bearer',
    user: {
      id: input.userId,
      email: input.email,
      app_metadata: {},
      user_metadata: {},
      aud: 'authenticated',
    },
  });
}

export async function startGoogleOAuth(adapter: AuthAdapter) {
  const started = await adapter.oauth?.startAuthorization({
    provider: 'google',
    redirectUri: 'ankh-app://auth/callback',
  });
  if (started?.ok !== true) throw new Error('OAuth start failed.');
  return started.data;
}

export async function completeOAuthCode(adapter: AuthAdapter, attemptId: string, code: string) {
  return adapter.oauth?.completeAuthorization({
    attemptId,
    response: { type: 'callback', url: `ankh-app://auth/callback?code=${code}` },
  });
}

export async function expectReplayProtection(
  adapter: AuthAdapter,
  attemptId: string,
  code: string,
): Promise<void> {
  expect(await completeOAuthCode(adapter, attemptId, code)).toMatchObject({
    ok: false,
    status: 'error',
    error: { code: 'callback_already_completed' },
  });
  expect(await completeOAuthCode(adapter, attemptId, `${code}-unrelated`)).toMatchObject({
    ok: false,
    status: 'error',
    error: { code: 'invalid_callback' },
  });
}

export function createCanonicalOAuthHarness() {
  const { storage, values } = createMemoryStorage();
  const calls: CanonicalOAuthCall[] = [];
  const fetch = testFetch((input, init) => {
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    calls.push({
      url: input instanceof Request ? input.url : input.toString(),
      hasExpectedCode: isRecord(body) && body.auth_code === 'opaque-code',
      hasVerifier: isRecord(body) && typeof body.code_verifier === 'string',
    });
    return oauthSessionResponse({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      userId: 'user-1',
      email: 'person@example.com',
    });
  });
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    storage,
    fetch,
    oauthProviders: ['google'],
  });
  return { adapter, calls, values };
}

export async function startCanonicalOAuth(adapter: AuthAdapter) {
  const started = await adapter.oauth?.startAuthorization({
    provider: 'google',
    redirectUri: 'ankh-app://auth/callback',
    scopes: ['openid', 'email'],
    queryParams: { prompt: 'select_account' },
  });
  if (started?.ok !== true) throw new Error('OAuth start failed.');
  return started.data;
}

export function createConcurrentOAuthHarness() {
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
    fetch: testFetch(async () => {
      exchanges += 1;
      reportExchangeStarted?.();
      await exchangeGate;
      return oauthSessionResponse({
        accessToken: 'concurrent-access-token',
        refreshToken: 'concurrent-refresh-token',
        userId: 'concurrent-user',
        email: 'concurrent@example.com',
      });
    }),
  });
  return {
    adapter,
    exchangeStarted,
    releaseExchange: () => {
      releaseExchange?.();
    },
    exchangeCount: () => exchanges,
  };
}

export function createInjectedCryptoHarness(storage: SupabaseAuthStorage, originalCrypto: Crypto) {
  let exchanges = 0;
  let authorizationChallenge: string | null = null;
  let matchingVerifier = false;
  let randomValueCalls = 0;
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    storage,
    oauthProviders: ['google'],
    oauthRandomBytes(length) {
      randomValueCalls += 1;
      return originalCrypto.getRandomValues(new Uint8Array(length));
    },
    fetch: testFetch((_input, init) => {
      exchanges += 1;
      const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      const verifier = isRecord(body) ? body.code_verifier : undefined;
      if (typeof verifier === 'string' && authorizationChallenge !== null) {
        const expected = Buffer.from(sha256(utf8ToBytes(verifier))).toString('base64url');
        matchingVerifier = expected === authorizationChallenge;
      }
      return oauthSessionResponse({
        accessToken: 'native-access-token',
        refreshToken: 'native-refresh-token',
        userId: 'native-user',
        email: 'native@example.com',
      });
    }),
  });
  return {
    adapter,
    setChallenge: (value: string) => {
      authorizationChallenge = value;
    },
    stats: () => ({ exchanges, matchingVerifier, randomValueCalls }),
  };
}

export function createActiveGlobalFetchHarness() {
  const staleCalls: string[] = [];
  const activeCalls: CanonicalOAuthCall[] = [];
  const staleFetch = testFetch((input) => {
    staleCalls.push(input instanceof Request ? input.url : input.toString());
    return Response.json({ message: 'stale OAuth fetch should not be used' }, { status: 503 });
  });
  const activeFetch = testFetch((input, init) => {
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    activeCalls.push({
      url: input instanceof Request ? input.url : input.toString(),
      hasExpectedCode: isRecord(body) && body.auth_code === 'active-oauth-code',
      hasVerifier: isRecord(body) && typeof body.code_verifier === 'string',
    });
    return oauthSessionResponse({
      accessToken: 'default-oauth-access-token',
      refreshToken: 'default-oauth-refresh-token',
      userId: 'default-oauth-user',
      email: 'default-oauth@example.com',
    });
  });
  return { activeCalls, activeFetch, staleCalls, staleFetch };
}
