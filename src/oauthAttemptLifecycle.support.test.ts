import type { AuthOAuthAdapter, CompleteOAuthAuthorizationInput } from '@ankhorage/contracts/auth';

import { createSupabaseOAuthAdapter } from './oauth.js';
import type {
  SupabaseAuthFetch,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
} from './types.js';

export const STORAGE_KEY = 'ankhorage.supabase-auth.session';
export const ATTEMPT_KEY = `${STORAGE_KEY}.oauth.attempt`;
export const CODE_VERIFIER_KEY = `${STORAGE_KEY}.oauth.pkce-verifier`;
export const CONSUMED_CALLBACKS_KEY = `${STORAGE_KEY}.oauth.consumed-callbacks`;
export const REDIRECT_URI = 'ankh-app://auth/callback';
export const CONSUMED_CALLBACK_RETENTION_MS = 24 * 60 * 60 * 1000;

export function createMemoryStorage(initial: Readonly<Record<string, string>> = {}) {
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

export function createHarness(
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
    fetch:
      options.fetch ??
      Object.assign(() => Promise.reject(new Error('Unexpected OAuth network request.')), {
        preconnect: globalThis.fetch.preconnect,
      }),
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

export async function startAuthorization(adapter: AuthOAuthAdapter) {
  const result = await adapter.startAuthorization.call(adapter, {
    provider: 'google',
    redirectUri: REDIRECT_URI,
  });
  if (!result.ok) throw new Error(`OAuth start failed: ${result.error.code}`);
  return result.data;
}

export function readAttempt(values: ReadonlyMap<string, string>): Record<string, unknown> {
  const raw = values.get(ATTEMPT_KEY);
  if (raw === undefined) throw new Error('Persisted OAuth attempt is missing.');
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) {
    throw new Error('Persisted OAuth attempt is invalid.');
  }
  return parsed;
}

export function readConsumedCallbacks(values: ReadonlyMap<string, string>): readonly unknown[] {
  const raw = values.get(CONSUMED_CALLBACKS_KEY);
  if (raw === undefined) throw new Error('Persisted consumed callback ledger is missing.');
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed.callbacks)) {
    throw new Error('Persisted consumed callback ledger is invalid.');
  }
  return parsed.callbacks;
}

export function validExchangeResponse(index = 1): Response {
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

export const TERMINAL_ERROR_CASES: readonly {
  readonly input: (attemptId: string) => CompleteOAuthAuthorizationInput;
  readonly fetch?: SupabaseAuthFetch;
  readonly persistSession?: () => Promise<void>;
}[] = [
  {
    input: (attemptId) => ({
      attemptId,
      response: {
        type: 'error',
        error: { code: 'transport_failed', message: 'Synthetic transport failure.' },
      },
    }),
  },
  {
    input: (attemptId) => ({
      attemptId,
      response: { type: 'callback', url: `${REDIRECT_URI}?unexpected=value` },
    }),
  },
  {
    input: callbackInput,
    fetch: testFetch(() => Promise.reject(new Error('Synthetic network failure.'))),
  },
  {
    input: callbackInput,
    fetch: testFetch(() =>
      Promise.resolve(Response.json({ code: 'bad_code_verifier' }, { status: 400 })),
    ),
  },
  { input: callbackInput, fetch: testFetch(() => Promise.resolve(Response.json({ user: null }))) },
  {
    input: callbackInput,
    fetch: testFetch(() => Promise.resolve(validExchangeResponse())),
    persistSession: () => Promise.reject(new Error('Synthetic persistence failure.')),
  },
];

function callbackInput(attemptId: string): CompleteOAuthAuthorizationInput {
  return {
    attemptId,
    response: { type: 'callback', url: `${REDIRECT_URI}?code=terminal-code` },
  };
}

function testFetch(handler: () => Promise<Response>): SupabaseAuthFetch {
  return Object.assign(handler, { preconnect: globalThis.fetch.preconnect });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
