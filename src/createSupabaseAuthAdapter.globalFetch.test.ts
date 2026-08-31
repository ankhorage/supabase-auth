import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import {
  authSessionResponse,
  createFetch,
  type FetchCall,
  jsonResponse,
} from './createSupabaseAuthAdapter.support.test.js';

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
        authSessionResponse({
          accessToken: 'active-access-token',
          refreshToken: 'active-refresh-token',
          userId: 'active-user',
          email: 'active@example.com',
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
        authSessionResponse({
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          userId: 'user-2',
          email: 'new@example.com',
          expiresAt: supabaseExpiresAtSeconds,
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
