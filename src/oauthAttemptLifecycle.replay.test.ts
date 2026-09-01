import { expect, it } from 'bun:test';

import { createSupabaseOAuthAdapter } from './oauth.js';
import {
  ATTEMPT_KEY,
  CODE_VERIFIER_KEY,
  createHarness,
  createMemoryStorage,
  readAttempt,
  REDIRECT_URI,
  startAuthorization,
  STORAGE_KEY,
} from './oauthAttemptLifecycle.support.test.js';

it('does not clear a different valid attempt for a mismatched callback id', async () => {
  const { adapter, values } = createHarness({ now: 50_000 });
  await startAuthorization(adapter);
  const attemptBefore = values.get(ATTEMPT_KEY);
  const verifierBefore = values.get(CODE_VERIFIER_KEY);

  const completed = await adapter.completeAuthorization.call(adapter, {
    attemptId: 'different-attempt',
    response: {
      type: 'callback',
      url: `${REDIRECT_URI}?code=must-not-be-exchanged`,
    },
  });

  expect(completed).toMatchObject({
    ok: false,
    status: 'error',
    error: { code: 'authorization_attempt_not_found' },
  });
  expect(values.get(ATTEMPT_KEY)).toBe(attemptBefore);
  expect(values.get(CODE_VERIFIER_KEY)).toBe(verifierBefore);
});

it('finalizes cancellation, removes the verifier, and permits immediate restart', async () => {
  const { adapter, values, lifecycleEvents } = createHarness({ now: 60_000 });
  const started = await startAuthorization(adapter);

  const cancelled = await adapter.completeAuthorization.call(adapter, {
    attemptId: started.attemptId,
    response: { type: 'cancelled', reason: 'browser_dismissed' },
  });

  expect(cancelled).toEqual({
    ok: false,
    status: 'cancelled',
    provider: 'google',
    reason: 'browser_dismissed',
  });
  expect(readAttempt(values)).toMatchObject({
    id: started.attemptId,
    status: 'completed',
  });
  expect(values.has(CODE_VERIFIER_KEY)).toBe(false);
  expect(JSON.stringify(lifecycleEvents)).not.toContain(REDIRECT_URI);

  const restarted = await startAuthorization(adapter);
  expect(restarted.attemptId).not.toBe(started.attemptId);
  expect(readAttempt(values)).toMatchObject({
    id: restarted.attemptId,
    status: 'pending',
  });
});

it('rejects invalid internal attempt lifetimes', () => {
  const { storage } = createMemoryStorage();

  expect(() =>
    createSupabaseOAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: () => Promise.reject(new Error('Unexpected OAuth network request.')),
      storage,
      storageKey: STORAGE_KEY,
      providers: ['google'],
      persistSession: () => Promise.resolve(),
      attemptLifetimeMs: 0,
    }),
  ).toThrow('OAuth authorization attempt lifetime must be a positive safe integer.');
});
