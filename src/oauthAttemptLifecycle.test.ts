import { expect, it } from 'bun:test';

import {
  ATTEMPT_KEY,
  CODE_VERIFIER_KEY,
  createHarness,
  readAttempt,
  REDIRECT_URI,
  startAuthorization,
  TERMINAL_ERROR_CASES,
} from './oauthAttemptLifecycle.support.test.js';

it('persists deterministic creation and expiry timestamps', async () => {
  const { adapter, values } = createHarness({ now: 10_000, attemptLifetimeMs: 2_500 });

  const started = await startAuthorization(adapter);

  expect(readAttempt(values)).toEqual({
    version: 4,
    id: started.attemptId,
    provider: 'google',
    redirectUri: REDIRECT_URI,
    status: 'pending',
    createdAt: 10_000,
    expiresAt: 12_500,
  });
});

it('keeps an unexpired active attempt recoverably locked', async () => {
  const { adapter, setNow } = createHarness({ now: 10_000, attemptLifetimeMs: 5_000 });
  await startAuthorization(adapter);
  setNow(14_999);

  const duplicate = await adapter.startAuthorization.call(adapter, {
    provider: 'google',
    redirectUri: REDIRECT_URI,
  });

  expect(duplicate).toMatchObject({
    ok: false,
    error: {
      code: 'authorization_failed',
      recoverable: true,
      message: 'An OAuth authorization attempt is already active.',
    },
  });
});

it('replaces expired pending and completing attempts', async () => {
  for (const status of ['pending', 'completing'] as const) {
    const { adapter, values } = createHarness({
      now: 20_000,
      initial: {
        [ATTEMPT_KEY]: JSON.stringify({
          version: 4,
          id: `expired-${status}`,
          provider: 'google',
          redirectUri: REDIRECT_URI,
          status,
          createdAt: 10_000,
          expiresAt: 20_000,
        }),
        [CODE_VERIFIER_KEY]: 'stale-verifier',
      },
    });

    const restarted = await startAuthorization(adapter);
    const persisted = readAttempt(values);

    expect(restarted.attemptId).not.toBe(`expired-${status}`);
    expect(persisted).toMatchObject({
      version: 4,
      id: restarted.attemptId,
      status: 'pending',
      createdAt: 20_000,
      expiresAt: 25_000,
    });
    expect(values.get(CODE_VERIFIER_KEY)).not.toBe('stale-verifier');
  }
});

it('self-cleans unknown-version and corrupted attempt state before restart', async () => {
  for (const persistedAttempt of [
    JSON.stringify({
      version: 1,
      id: 'legacy-attempt',
      provider: 'google',
      redirectUri: REDIRECT_URI,
      status: 'pending',
    }),
    '{not-json',
  ]) {
    const { adapter, values } = createHarness({
      now: 30_000,
      initial: {
        [ATTEMPT_KEY]: persistedAttempt,
        [CODE_VERIFIER_KEY]: 'stale-verifier',
      },
    });

    const restarted = await startAuthorization(adapter);

    expect(readAttempt(values)).toMatchObject({
      version: 4,
      id: restarted.attemptId,
      status: 'pending',
      createdAt: 30_000,
      expiresAt: 35_000,
    });
    expect(values.get(CODE_VERIFIER_KEY)).not.toBe('stale-verifier');
  }
});

it('cleans an expired attempt and PKCE verifier during callback completion', async () => {
  const { adapter, values, setNow } = createHarness({
    now: 40_000,
    attemptLifetimeMs: 1_000,
  });
  const started = await startAuthorization(adapter);
  setNow(41_000);

  const completed = await adapter.completeAuthorization.call(adapter, {
    attemptId: started.attemptId,
    response: {
      type: 'callback',
      url: `${REDIRECT_URI}?code=must-not-be-exchanged`,
    },
  });

  expect(completed).toMatchObject({
    ok: false,
    status: 'error',
    error: {
      code: 'authorization_attempt_not_found',
      recoverable: true,
    },
  });
  expect(values.has(ATTEMPT_KEY)).toBe(false);
  expect(values.has(CODE_VERIFIER_KEY)).toBe(false);
});

it('removes the verifier on every terminal OAuth error path', async () => {
  for (const terminalCase of TERMINAL_ERROR_CASES) {
    const { adapter, values } = createHarness({
      ...(terminalCase.fetch === undefined ? {} : { fetch: terminalCase.fetch }),
      ...(terminalCase.persistSession === undefined
        ? {}
        : { persistSession: terminalCase.persistSession }),
    });
    const started = await startAuthorization(adapter);
    const completed = await adapter.completeAuthorization.call(
      adapter,
      terminalCase.input(started.attemptId),
    );

    expect(completed.ok).toBe(false);
    expect(values.has(CODE_VERIFIER_KEY)).toBe(false);
    expect(readAttempt(values).status).toBe('completed');
  }
});
