import type { AuthAdapter } from '@ankhorage/contracts/auth';
import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
import {
  authSessionResponse,
  createFetch,
  type FetchCall,
  jsonResponse,
  receiverSensitiveFetch,
} from './createSupabaseAuthAdapter.support.test.js';

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
  globalThis.fetch = receiverSensitiveFetch(calls, () => {
    globalReceiverCalls += 1;
  });

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
      authSessionResponse({
        accessToken: 'signup-default-access-token',
        refreshToken: 'signup-default-refresh-token',
        userId: 'signup-default-user',
        email: 'signup-default@example.com',
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
