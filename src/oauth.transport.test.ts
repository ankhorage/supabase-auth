import { readFileSync } from 'node:fs';

import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import { createMemoryStorage, startGoogleOAuth, testFetch } from './oauth.support.test.js';

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
    fetch: testFetch(() => {
      calls += 1;
      return Promise.reject(new Error('unexpected'));
    }),
  });
  const started = await startGoogleOAuth(adapter);
  expect(
    await adapter.oauth?.completeAuthorization({
      attemptId: started.attemptId,
      response: { type: 'cancelled', reason: 'browser_dismissed' },
    }),
  ).toEqual({
    ok: false,
    status: 'cancelled',
    provider: 'google',
    reason: 'browser_dismissed',
  });
  expect(calls).toBe(0);

  const startedAgain = await startGoogleOAuth(adapter);
  expect(
    await adapter.oauth?.completeAuthorization({
      attemptId: startedAgain.attemptId,
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
  const oauthSource = ['oauth.ts', 'oauthStart.ts', 'oauthComplete.ts', 'oauthStartSupport.ts']
    .map((sourceFile) => readFileSync(new URL(`./${sourceFile}`, import.meta.url), 'utf8'))
    .join('\n');

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
  expect(oauthSource).toContain('createPkcePair(context.randomBytes ?? randomBytes)');
});
