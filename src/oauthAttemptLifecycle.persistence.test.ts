import { expect, it } from 'bun:test';

import { createSupabaseOAuthAdapter } from './oauth.js';
import {
  ATTEMPT_KEY,
  CODE_VERIFIER_KEY,
  CONSUMED_CALLBACK_RETENTION_MS,
  CONSUMED_CALLBACKS_KEY,
  createHarness,
  createMemoryStorage,
  readAttempt,
  readConsumedCallbacks,
  REDIRECT_URI,
  startAuthorization,
  STORAGE_KEY,
  validExchangeResponse,
} from './oauthAttemptLifecycle.support.test.js';
import type { SupabaseAuthStorage } from './types.js';

it('clears PKCE state when the callback lock cannot be persisted', async () => {
  const { storage: memoryStorage, values } = createMemoryStorage();
  let attemptWrites = 0;
  let exchanges = 0;
  const storage: SupabaseAuthStorage = {
    getItem: (key) => memoryStorage.getItem(key),
    setItem(key, value) {
      if (key === ATTEMPT_KEY) {
        attemptWrites += 1;
        if (attemptWrites === 2) throw new Error('Synthetic callback lock failure.');
      }
      return memoryStorage.setItem(key, value);
    },
    removeItem: (key) => memoryStorage.removeItem(key),
  };
  const adapter = createSupabaseOAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    fetch: () => {
      exchanges += 1;
      return Promise.reject(new Error('Unexpected OAuth network request.'));
    },
    storage,
    storageKey: STORAGE_KEY,
    providers: ['google'],
    persistSession: () => Promise.resolve(),
  });
  const started = await startAuthorization(adapter);

  const completed = await adapter.completeAuthorization.call(adapter, {
    attemptId: started.attemptId,
    response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
  });

  expect(completed).toMatchObject({
    ok: false,
    status: 'error',
    error: { code: 'session_persistence_failed' },
  });
  expect(exchanges).toBe(0);
  expect(values.has(ATTEMPT_KEY)).toBe(false);
  expect(values.has(CODE_VERIFIER_KEY)).toBe(false);
});

it('fails closed when the consumed callback ledger cannot be read, parsed, or reserved', async () => {
  for (const failure of ['read', 'invalid', 'write'] as const) {
    const { storage: memoryStorage, values } = createMemoryStorage(
      failure === 'invalid' ? { [CONSUMED_CALLBACKS_KEY]: '{invalid-json' } : {},
    );
    let exchanges = 0;
    const storage: SupabaseAuthStorage = {
      getItem(key) {
        if (failure === 'read' && key === CONSUMED_CALLBACKS_KEY) {
          throw new Error('Synthetic consumed callback ledger read failure.');
        }
        return memoryStorage.getItem(key);
      },
      setItem(key, value) {
        if (failure === 'write' && key === CONSUMED_CALLBACKS_KEY) {
          throw new Error('Synthetic consumed callback ledger write failure.');
        }
        return memoryStorage.setItem(key, value);
      },
      removeItem: (key) => memoryStorage.removeItem(key),
    };
    const adapter = createSupabaseOAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: () => {
        exchanges += 1;
        return Promise.resolve(validExchangeResponse());
      },
      storage,
      storageKey: STORAGE_KEY,
      providers: ['google'],
      persistSession: () => Promise.resolve(),
    });
    const started = await startAuthorization(adapter);

    const completed = await adapter.completeAuthorization.call(adapter, {
      attemptId: started.attemptId,
      response: { type: 'callback', url: `${REDIRECT_URI}?code=fail-closed-${failure}` },
    });

    expect(completed).toMatchObject({
      ok: false,
      status: 'error',
      error: { code: 'session_persistence_failed' },
    });
    expect(exchanges).toBe(0);
    expect(values.has(CODE_VERIFIER_KEY)).toBe(false);
    expect(readAttempt(values).status).toBe('completed');
    expect(JSON.stringify(completed)).not.toContain(`fail-closed-${failure}`);
  }
});

it('expires consumed callback fingerprints after 24 hours', async () => {
  let exchanges = 0;
  const { adapter, values, setNow } = createHarness({
    now: 10_000,
    fetch: () => Promise.resolve(validExchangeResponse(++exchanges)),
  });
  const first = await startAuthorization(adapter);
  expect(
    await adapter.completeAuthorization.call(adapter, {
      attemptId: first.attemptId,
      response: { type: 'callback', url: `${REDIRECT_URI}?code=expiring-ledger-code` },
    }),
  ).toMatchObject({ ok: true, status: 'authenticated' });
  const initialLedger = readConsumedCallbacks(values);
  expect(initialLedger).toHaveLength(1);
  expect(initialLedger[0]).toMatchObject({
    expiresAt: 10_000 + CONSUMED_CALLBACK_RETENTION_MS,
  });

  setNow(10_000 + CONSUMED_CALLBACK_RETENTION_MS);
  const second = await startAuthorization(adapter);
  expect(
    await adapter.completeAuthorization.call(adapter, {
      attemptId: second.attemptId,
      response: { type: 'callback', url: `${REDIRECT_URI}?code=fresh-after-retention` },
    }),
  ).toMatchObject({ ok: true, status: 'authenticated' });

  const prunedLedger = readConsumedCallbacks(values);
  expect(prunedLedger).toHaveLength(1);
  expect(prunedLedger).not.toEqual(initialLedger);
  expect(values.get(CONSUMED_CALLBACKS_KEY)).not.toContain('expiring-ledger-code');
  expect(values.get(CONSUMED_CALLBACKS_KEY)).not.toContain('fresh-after-retention');
  expect(exchanges).toBe(2);
});

it('retains at most 32 valid consumed callback fingerprints', async () => {
  let exchanges = 0;
  const { adapter, values } = createHarness({
    fetch: () => Promise.resolve(validExchangeResponse(++exchanges)),
  });

  for (let index = 0; index < 40; index += 1) {
    const started = await startAuthorization(adapter);
    expect(
      await adapter.completeAuthorization.call(adapter, {
        attemptId: started.attemptId,
        response: { type: 'callback', url: `${REDIRECT_URI}?code=bounded-${index}` },
      }),
    ).toMatchObject({ ok: true, status: 'authenticated' });
  }

  const callbacks = readConsumedCallbacks(values);
  expect(callbacks).toHaveLength(32);
  expect(new Set(callbacks.map((entry) => JSON.stringify(entry))).size).toBe(32);
  expect(values.get(CONSUMED_CALLBACKS_KEY)).not.toContain('bounded-');
  expect(exchanges).toBe(40);
});
