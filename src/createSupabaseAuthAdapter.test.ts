import type { AuthAdapter } from '@ankhorage/contracts/auth';
import { describe, expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import type { SupabaseAuthStorage } from './types.js';

describe('createSupabaseAuthAdapter', () => {
  it('validates required config', () => {
    expect(() => createSupabaseAuthAdapter({ url: '', anonKey: 'anon', fetch })).toThrow(
      'Supabase Auth URL is required.',
    );
    expect(() =>
      createSupabaseAuthAdapter({ url: 'https://example.supabase.co', anonKey: '', fetch }),
    ).toThrow('Supabase anon key is required.');
    expect(() =>
      createSupabaseAuthAdapter({
        url: 'not a url',
        anonKey: 'anon',
        fetch,
      }),
    ).toThrow('Supabase Auth URL must be a valid URL.');
  });

  it('returns an AuthAdapter-compatible object', () => {
    const adapter: AuthAdapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch([
        jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'user-1',
            email: 'user@example.com',
          },
        }),
      ]),
    });

    expect(adapter.capabilities?.supportsSessionRefresh).toBe(true);
  });

  it('normalizes a successful email and password sign-in response', async () => {
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co/',
      anonKey: 'anon',
      fetch: createFetch(
        [
          jsonResponse({
            access_token: 'access-token',
            refresh_token: 'refresh-token',
            expires_in: 3600,
            token_type: 'bearer',
            user: {
              id: 'user-1',
              email: 'user@example.com',
              user_metadata: {
                plan: 'pro',
              },
            },
          }),
        ],
        calls,
      ),
    });

    const result = await adapter.signIn({
      identifier: { kind: 'email', value: 'user@example.com' },
      password: 'password',
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        tokenType: 'bearer',
        user: {
          id: 'user-1',
          email: 'user@example.com',
          metadata: {
            plan: 'pro',
          },
        },
      },
    });
    expect(calls[0]?.url).toBe('https://example.supabase.co/auth/v1/token?grant_type=password');
    expect(calls[0]?.body).toEqual({
      email: 'user@example.com',
      password: 'password',
    });
  });

  it('normalizes failed sign-in provider errors', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch([
        jsonResponse(
          {
            error: 'invalid_grant',
            error_description: 'Invalid login credentials',
          },
          { status: 400 },
        ),
      ]),
    });

    const result = await adapter.signIn({
      identifier: { kind: 'email', value: 'user@example.com' },
      password: 'wrong-password',
    });

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'invalid_credentials',
        message: 'Invalid credentials.',
        cause: {
          status: 400,
          body: {
            error: 'invalid_grant',
            error_description: 'Invalid login credentials',
          },
        },
      },
    });
  });

  it('normalizes a sign-up response with a session', async () => {
    const supabaseExpiresAtSeconds = 1_800_000_000;
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch(
        [
          jsonResponse({
            access_token: 'new-access-token',
            refresh_token: 'new-refresh-token',
            expires_at: supabaseExpiresAtSeconds,
            user: {
              id: 'user-2',
              email: 'new@example.com',
            },
          }),
        ],
        calls,
      ),
    });

    const result = await adapter.signUp({
      identifier: { kind: 'email', value: 'new@example.com' },
      password: 'password',
      profile: { displayName: 'New User' },
      metadata: { source: 'test' },
      redirectTo: 'https://app.example.com/welcome',
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt: supabaseExpiresAtSeconds * 1000,
        user: {
          id: 'user-2',
          email: 'new@example.com',
        },
      },
    });
    expect(calls[0]?.url).toBe(
      'https://example.supabase.co/auth/v1/signup?redirect_to=https%3A%2F%2Fapp.example.com%2Fwelcome',
    );
    expect(calls[0]?.body).toEqual({
      email: 'new@example.com',
      password: 'password',
      data: {
        displayName: 'New User',
        source: 'test',
      },
    });
  });

  it('normalizes a sign-up response with a user only', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch([
        jsonResponse({
          user: {
            id: 'user-3',
            email: 'confirm@example.com',
          },
        }),
      ]),
    });

    const result = await adapter.signUp({
      identifier: { kind: 'email', value: 'confirm@example.com' },
      password: 'password',
    });

    expect(result).toEqual({
      ok: true,
      data: {
        id: 'user-3',
        email: 'confirm@example.com',
      },
    });
  });

  it('requests an email password reset', async () => {
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch([jsonResponse({})], calls),
    });

    const result = await adapter.requestPasswordReset?.({
      identifier: { kind: 'email', value: 'user@example.com' },
      redirectTo: 'https://app.example.com/reset',
    });

    expect(result).toEqual({ ok: true });
    expect(calls[0]?.url).toBe(
      'https://example.supabase.co/auth/v1/recover?redirect_to=https%3A%2F%2Fapp.example.com%2Freset',
    );
    expect(calls[0]?.body).toEqual({
      email: 'user@example.com',
    });
  });

  it('verifies an email OTP and persists the session', async () => {
    const storage = createMemoryStorage();
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      fetch: createFetch(
        [
          jsonResponse({
            access_token: 'otp-access-token',
            refresh_token: 'otp-refresh-token',
            user: {
              id: 'user-4',
              email: 'otp@example.com',
            },
          }),
        ],
        calls,
      ),
    });

    const result = await adapter.verifyOtp?.({
      identifier: { kind: 'email', value: 'otp@example.com' },
      token: '123456',
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        accessToken: 'otp-access-token',
        refreshToken: 'otp-refresh-token',
      },
    });
    expect(calls[0]?.body).toEqual({
      email: 'otp@example.com',
      token: '123456',
      type: 'email',
    });
    expect(await storage.getItem('ankhorage.supabase-auth.session')).toContain('otp-access-token');
  });

  it('refreshes a stored session', async () => {
    const storage = createMemoryStorage({
      'ankhorage.supabase-auth.session': JSON.stringify({
        accessToken: 'old-access-token',
        refreshToken: 'old-refresh-token',
        user: { id: 'user-5', email: 'refresh@example.com' },
      }),
    });
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      fetch: createFetch(
        [
          jsonResponse({
            access_token: 'new-access-token',
            refresh_token: 'new-refresh-token',
            user: {
              id: 'user-5',
              email: 'refresh@example.com',
            },
          }),
        ],
        calls,
      ),
    });

    const result = await adapter.refreshSession?.();

    expect(result).toMatchObject({
      ok: true,
      data: {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      },
    });
    expect(calls[0]?.body).toEqual({
      refresh_token: 'old-refresh-token',
    });
    expect(await storage.getItem('ankhorage.supabase-auth.session')).toContain('new-access-token');
  });

  it('returns a missing refresh token error', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      fetch: createFetch([]),
    });

    const result = await adapter.refreshSession?.();

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'missing_refresh_token',
        message: 'No refresh token is available.',
      },
    });
  });

  it('reads and removes storage-backed sessions', async () => {
    const storage = createMemoryStorage({
      'ankhorage.supabase-auth.session': JSON.stringify({
        accessToken: 'stored-access-token',
        refreshToken: 'stored-refresh-token',
        user: { id: 'user-6', email: 'stored@example.com' },
      }),
    });
    const calls: FetchCall[] = [];
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon',
      storage,
      fetch: createFetch([jsonResponse({})], calls),
    });

    const storedSession = await adapter.getSession();
    expect(storedSession).toEqual({
      ok: true,
      data: {
        accessToken: 'stored-access-token',
        refreshToken: 'stored-refresh-token',
        user: { id: 'user-6', email: 'stored@example.com' },
      },
    });
    const signOutResult = await adapter.signOut();
    expect(signOutResult).toEqual({ ok: true });
    const clearedSession = await adapter.getSession();
    expect(clearedSession).toEqual({
      ok: true,
      data: null,
    });
    expect(await storage.getItem('ankhorage.supabase-auth.session')).toBeNull();
    expect(calls[0]?.url).toBe('https://example.supabase.co/auth/v1/logout');
    expect(calls[0]?.headers.authorization).toBe('Bearer stored-access-token');
  });
});

interface FetchCall {
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

function createFetch(responses: Response[], calls: FetchCall[] = []): typeof fetch {
  return (input, init) => {
    const headers = new Headers(init?.headers);
    calls.push({
      url: input instanceof Request ? input.url : input.toString(),
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
      headers: Object.fromEntries(headers.entries()),
    });

    const response = responses.shift();

    if (response === undefined) {
      throw new Error('Unexpected fetch call.');
    }

    return Promise.resolve(response);
  };
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...init.headers,
    },
  });
}

function createMemoryStorage(initialValues: Record<string, string> = {}): SupabaseAuthStorage {
  const values = new Map(Object.entries(initialValues));

  return {
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
}
