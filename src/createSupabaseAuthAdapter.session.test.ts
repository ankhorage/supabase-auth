import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import {
  createFetch,
  createMemoryStorage,
  type FetchCall,
  jsonResponse,
} from './createSupabaseAuthAdapter.support.test.js';

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
