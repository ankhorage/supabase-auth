import type { AuthOAuthAdapter } from '@ankhorage/contracts/auth';
import { describe, expect, it } from 'bun:test';

import { createSupabaseOAuthAdapter } from './oauth.js';
import type { SupabaseAuthStorage, SupabaseOAuthLifecycleEvent } from './types.js';

const STORAGE_KEY = 'ankhorage.supabase-auth.session';
const ATTEMPT_KEY = `${STORAGE_KEY}.oauth.attempt`;
const CODE_VERIFIER_KEY = `${STORAGE_KEY}.oauth-code-verifier`;
const REDIRECT_URI = 'ankh-app://auth/callback';

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
  } = {},
) {
  let currentTime = options.now ?? 1_000;
  const { storage, values } = createMemoryStorage(options.initial);
  const lifecycleEvents: SupabaseOAuthLifecycleEvent[] = [];
  const adapter = createSupabaseOAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
    fetch: () => Promise.reject(new Error('Unexpected OAuth network request.')),
    storage,
    storageKey: STORAGE_KEY,
    providers: ['google'],
    persistSession: () => Promise.resolve(),
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

describe('expiring OAuth attempt lifecycle', () => {
  it('persists deterministic creation and expiry timestamps', async () => {
    const { adapter, values } = createHarness({ now: 10_000, attemptLifetimeMs: 2_500 });

    const started = await startAuthorization(adapter);

    expect(readAttempt(values)).toEqual({
      version: 3,
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
            version: 3,
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
        version: 3,
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
        version: 3,
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
