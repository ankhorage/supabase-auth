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

  it('uses the default global fetch for email and password sign-in', async () => {
    const originalFetch = globalThis.fetch;
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetch(
      [
        jsonResponse({
          access_token: 'default-access-token',
          refresh_token: 'default-refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'default-user',
            email: 'default@example.com',
          },
        }),
      ],
      calls,
    );

    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co/',
        anonKey: 'anon',
      });

      const result = await adapter.signIn({
        identifier: { kind: 'email', value: 'default@example.com' },
        password: 'password',
      });

      expect(result).toMatchObject({
        ok: true,
        data: {
          accessToken: 'default-access-token',
          refreshToken: 'default-refresh-token',
          user: {
            id: 'default-user',
            email: 'default@example.com',
          },
        },
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe('https://example.supabase.co/auth/v1/token?grant_type=password');
      expect(calls[0]?.headers.apikey).toBe('anon');
      expect(calls[0]?.headers['content-type']).toBe('application/json');
      expect(calls[0]?.body).toEqual({
        email: 'default@example.com',
        password: 'password',
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('calls the default global fetch with the global receiver', async () => {
    const originalFetch = globalThis.fetch;
    const calls: FetchCall[] = [];
    let globalReceiverCalls = 0;
    const receiverSensitiveFetch: typeof fetch = function (
      this: unknown,
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ) {
      if (this !== globalThis) throw new TypeError('incorrect fetch receiver');
      globalReceiverCalls += 1;

      const headers = new Headers(init?.headers);
      calls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
        headers: Object.fromEntries(headers.entries()),
      });

      return Promise.resolve(
        jsonResponse({
          access_token: 'receiver-access-token',
          refresh_token: 'receiver-refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'receiver-user',
            email: 'receiver@example.com',
          },
        }),
      );
    };
    globalThis.fetch = receiverSensitiveFetch;

    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
      });

      const result = await adapter.signIn({
        identifier: { kind: 'email', value: 'receiver@example.com' },
        password: 'password',
      });

      expect(result).toMatchObject({
        ok: true,
        data: {
          accessToken: 'receiver-access-token',
          refreshToken: 'receiver-refresh-token',
          user: {
            id: 'receiver-user',
            email: 'receiver@example.com',
          },
        },
      });
      expect(globalReceiverCalls).toBe(1);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe('https://example.supabase.co/auth/v1/token?grant_type=password');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('uses the default global fetch for email and password sign-up', async () => {
    const originalFetch = globalThis.fetch;
    const calls: FetchCall[] = [];
    globalThis.fetch = createFetch(
      [
        jsonResponse({
          access_token: 'signup-default-access-token',
          refresh_token: 'signup-default-refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'signup-default-user',
            email: 'signup-default@example.com',
          },
        }),
      ],
      calls,
    );

    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
      });

      const result = await adapter.signUp({
        identifier: { kind: 'email', value: 'signup-default@example.com' },
        password: 'password',
        profile: { displayName: 'Default User' },
      });

      expect(result).toMatchObject({
        ok: true,
        data: {
          accessToken: 'signup-default-access-token',
          refreshToken: 'signup-default-refresh-token',
          user: {
            id: 'signup-default-user',
            email: 'signup-default@example.com',
          },
        },
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe('https://example.supabase.co/auth/v1/signup');
      expect(calls[0]?.headers.apikey).toBe('anon');
      expect(calls[0]?.headers['content-type']).toBe('application/json');
      expect(calls[0]?.body).toEqual({
        email: 'signup-default@example.com',
        password: 'password',
        data: { displayName: 'Default User' },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('uses the active runtime global fetch after default adapter creation', async () => {
    const originalFetch = globalThis.fetch;
    const staleCalls: FetchCall[] = [];
    const activeCalls: FetchCall[] = [];
    globalThis.fetch = createFetch(
      [jsonResponse({ message: 'stale fetch should not be used' }, { status: 503 })],
      staleCalls,
    );

    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
      });

      globalThis.fetch = createFetch(
        [
          jsonResponse({
            access_token: 'active-access-token',
            refresh_token: 'active-refresh-token',
            expires_in: 3600,
            token_type: 'bearer',
            user: {
              id: 'active-user',
              email: 'active@example.com',
            },
          }),
        ],
        activeCalls,
      );

      const result = await adapter.signIn({
        identifier: { kind: 'email', value: 'active@example.com' },
        password: 'password',
      });

      expect(result).toMatchObject({
        ok: true,
        data: {
          accessToken: 'active-access-token',
          refreshToken: 'active-refresh-token',
          user: {
            id: 'active-user',
            email: 'active@example.com',
          },
        },
      });
      expect(staleCalls).toHaveLength(0);
      expect(activeCalls).toHaveLength(1);
      expect(activeCalls[0]?.url).toBe(
        'https://example.supabase.co/auth/v1/token?grant_type=password',
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('keeps an explicit custom fetch stable when the global fetch changes', async () => {
    const originalFetch = globalThis.fetch;
    const customCalls: FetchCall[] = [];
    const globalCalls: FetchCall[] = [];
    const customFetch = createFetch(
      [
        jsonResponse({
          access_token: 'custom-access-token',
          refresh_token: 'custom-refresh-token',
          expires_in: 3600,
          token_type: 'bearer',
          user: {
            id: 'custom-user',
            email: 'custom@example.com',
          },
        }),
      ],
      customCalls,
    );

    try {
      const adapter = createSupabaseAuthAdapter({
        url: 'https://example.supabase.co',
        anonKey: 'anon',
        fetch: customFetch,
      });
      globalThis.fetch = createFetch(
        [jsonResponse({ message: 'global fetch should not be used' }, { status: 503 })],
        globalCalls,
      );

      const result = await adapter.signIn({
        identifier: { kind: 'email', value: 'custom@example.com' },
        password: 'password',
      });

      expect(result).toMatchObject({
        ok: true,
        data: {
          accessToken: 'custom-access-token',
          refreshToken: 'custom-refresh-token',
        },
      });
      expect(customCalls).toHaveLength(1);
      expect(globalCalls).toHaveLength(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
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
