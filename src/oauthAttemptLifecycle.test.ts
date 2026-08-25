import type { AuthOAuthAdapter, CompleteOAuthAuthorizationInput } from '@ankhorage/contracts/auth';
import { describe, expect, it } from 'bun:test';

import { createSupabaseOAuthAdapter } from './oauth.js';
import type {
  SupabaseAuthFetch,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
} from './types.js';

const STORAGE_KEY = 'ankhorage.supabase-auth.session';
const ATTEMPT_KEY = `${STORAGE_KEY}.oauth.attempt`;
const CODE_VERIFIER_KEY = `${STORAGE_KEY}.oauth.pkce-verifier`;
const CONSUMED_CALLBACKS_KEY = `${STORAGE_KEY}.oauth.consumed-callbacks`;
const REDIRECT_URI = 'ankh-app://auth/callback';
const CONSUMED_CALLBACK_RETENTION_MS = 24 * 60 * 60 * 1000;

function createMemoryStorage(initial: Readonly<Record<string, string>> = {}) {
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

function createHarness(
  options: {
    readonly now?: number;
    readonly attemptLifetimeMs?: number;
    readonly initial?: Readonly<Record<string, string>>;
    readonly fetch?: SupabaseAuthFetch;
    readonly persistSession?: () => Promise<void>;
  } = {},
) {
  let currentTime = options.now ?? 1_000;
  const { storage, values } = createMemoryStorage(options.initial);
  const lifecycleEvents: SupabaseOAuthLifecycleEvent[] = [];
  const adapter = createSupabaseOAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    fetch: options.fetch ?? (() => Promise.reject(new Error('Unexpected OAuth network request.'))),
    storage,
    storageKey: STORAGE_KEY,
    providers: ['google'],
    persistSession: options.persistSession ?? (() => Promise.resolve()),
    onLifecycleEvent(event) {
      lifecycleEvents.push(event);
    },
    now: () => currentTime,
    attemptLifetimeMs: options.attemptLifetimeMs ?? 5_000,
  });

  return {
    adapter,
    values,
    lifecycleEvents,
    setNow: (value: number) => {
      currentTime = value;
    },
  };
}

async function startAuthorization(adapter: AuthOAuthAdapter) {
  const result = await adapter.startAuthorization.call(adapter, {
    provider: 'google',
    redirectUri: REDIRECT_URI,
  });
  if (!result.ok) throw new Error(`OAuth start failed: ${result.error.code}`);
  return result.data;
}

function readAttempt(values: ReadonlyMap<string, string>): Record<string, unknown> {
  const raw = values.get(ATTEMPT_KEY);
  if (raw === undefined) throw new Error('Persisted OAuth attempt is missing.');
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) {
    throw new Error('Persisted OAuth attempt is invalid.');
  }
  return parsed;
}

function readConsumedCallbacks(values: ReadonlyMap<string, string>): readonly unknown[] {
  const raw = values.get(CONSUMED_CALLBACKS_KEY);
  if (raw === undefined) throw new Error('Persisted consumed callback ledger is missing.');
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed.callbacks)) {
    throw new Error('Persisted consumed callback ledger is invalid.');
  }
  return parsed.callbacks;
}

function validExchangeResponse(index = 1): Response {
  return Response.json({
    access_token: `lifecycle-access-${index}`,
    refresh_token: `lifecycle-refresh-${index}`,
    expires_in: 3600,
    token_type: 'bearer',
    user: {
      id: `lifecycle-user-${index}`,
      email: `lifecycle-${index}@example.com`,
      app_metadata: {},
      user_metadata: {},
      aud: 'authenticated',
    },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

describe('expiring OAuth attempt lifecycle', () => {
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
    const validExchangeResponse = () =>
      Response.json({
        access_token: 'terminal-access-value',
        refresh_token: 'terminal-refresh-value',
        expires_in: 3600,
        token_type: 'bearer',
        user: {
          id: 'terminal-user',
          email: 'terminal@example.com',
          app_metadata: {},
          user_metadata: {},
          aud: 'authenticated',
        },
      });
    const cases: readonly {
      readonly input: (attemptId: string) => CompleteOAuthAuthorizationInput;
      readonly fetch?: SupabaseAuthFetch;
      readonly persistSession?: () => Promise<void>;
    }[] = [
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'error', reason: 'transport_failed' },
        }),
      },
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'callback', url: `${REDIRECT_URI}?unexpected=value` },
        }),
      },
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
        }),
        fetch: () => Promise.reject(new Error('Synthetic network failure.')),
      },
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
        }),
        fetch: () => Promise.resolve(Response.json({ code: 'bad_code_verifier' }, { status: 400 })),
      },
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
        }),
        fetch: () => Promise.resolve(Response.json({ user: null })),
      },
      {
        input: (attemptId) => ({
          attemptId,
          response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
        }),
        fetch: () => Promise.resolve(validExchangeResponse()),
        persistSession: () => Promise.reject(new Error('Synthetic persistence failure.')),
      },
    ];

    for (const terminalCase of cases) {
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
});
