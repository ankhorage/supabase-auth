import { expect, it } from 'bun:test';

import {
  normalizeSupabaseAuthProfileVerificationConfig,
  verifySupabaseOAuthProfile,
} from './profileVerification.js';

const SESSION = {
  accessToken: 'sentinel-phase3-access-token-do-not-leak',
  refreshToken: 'sentinel-phase3-refresh-token-do-not-leak',
  user: {
    id: 'user-1',
    email: 'person@example.com',
    displayName: 'Person Example',
    avatarUrl: 'https://example.com/avatar.png',
  },
};

it('normalizes one safe app-owned profile verification model', () => {
  expect(
    normalizeSupabaseAuthProfileVerificationConfig({
      table: ' profiles ',
      fields: ['email', 'displayName', 'email'],
      maxAttempts: 3,
      retryDelayMs: 0,
    }),
  ).toEqual({
    table: 'profiles',
    fields: ['email', 'displayName'],
    maxAttempts: 3,
    retryDelayMs: 0,
  });

  expect(() => normalizeSupabaseAuthProfileVerificationConfig({ table: 'users' })).toThrow(
    'not public.users',
  );
  expect(() => normalizeSupabaseAuthProfileVerificationConfig({ table: 'Profile-Rows' })).toThrow(
    'snake_case',
  );
  expect(() =>
    normalizeSupabaseAuthProfileVerificationConfig({
      table: 'profiles',
      fields: ['privateKey' as never],
    }),
  ).toThrow('Unsupported Supabase profile verification field');
});

it('retries trigger visibility and verifies exactly one matching profile row', async () => {
  const calls: { url: string; headers: Headers }[] = [];
  const responses = [
    jsonResponse([]),
    jsonResponse([
      {
        id: 'user-1',
        email: 'person@example.com',
        display_name: 'Person Example',
        avatar_url: 'https://example.com/avatar.png',
      },
    ]),
  ];

  const result = await verifySupabaseOAuthProfile({
    url: 'https://example.supabase.co/',
    anonKey: 'anon-key',
    fetch: createFetch(responses, calls),
    config: {
      table: 'profiles',
      fields: ['email', 'displayName', 'avatarUrl'],
      maxAttempts: 2,
      retryDelayMs: 0,
    },
    session: SESSION,
  });

  expect(result).toEqual({ ok: true });
  expect(calls).toHaveLength(2);
  expect(calls[0]?.url).toContain('/rest/v1/profiles?');
  expect(calls[0]?.url).toContain('id=eq.user-1');
  expect(calls[0]?.url).toContain('limit=2');
  expect(calls[0]?.headers.get('apikey')).toBe('anon-key');
  expect(calls[0]?.headers.get('authorization')).toBe(
    'Bearer sentinel-phase3-access-token-do-not-leak',
  );
});

it('returns safe failures for missing, duplicate, and mismatched profile rows', async () => {
  const missing = await verifySupabaseOAuthProfile({
    url: 'https://example.supabase.co',
    anonKey: 'anon-key',
    fetch: createFetch([jsonResponse([])]),
    config: { table: 'profiles', maxAttempts: 1, retryDelayMs: 0 },
    session: SESSION,
  });
  const duplicate = await verifySupabaseOAuthProfile({
    url: 'https://example.supabase.co',
    anonKey: 'anon-key',
    fetch: createFetch([jsonResponse([{ id: 'user-1' }, { id: 'user-1' }])]),
    config: { table: 'profiles', maxAttempts: 1, retryDelayMs: 0 },
    session: SESSION,
  });
  const mismatch = await verifySupabaseOAuthProfile({
    url: 'https://example.supabase.co',
    anonKey: 'anon-key',
    fetch: createFetch([
      jsonResponse([
        {
          id: 'user-1',
          email: 'different@example.com',
          display_name: 'Person Example',
          avatar_url: 'https://example.com/avatar.png',
        },
      ]),
    ]),
    config: { table: 'profiles', maxAttempts: 1, retryDelayMs: 0 },
    session: SESSION,
  });

  expect(missing).toEqual({
    ok: false,
    message: 'The auth identity exists but its generated public profile row was not found.',
  });
  expect(duplicate).toEqual({
    ok: false,
    message: 'The generated public profile lookup returned more than one row.',
  });
  expect(mismatch).toEqual({
    ok: false,
    message: 'The generated public profile field "email" does not match provider metadata.',
  });

  const serialized = JSON.stringify({ missing, duplicate, mismatch });
  expect(serialized).not.toContain('sentinel-phase3-access-token-do-not-leak');
  expect(serialized).not.toContain('sentinel-phase3-refresh-token-do-not-leak');
});

function createFetch(
  responses: Response[],
  calls: { url: string; headers: Headers }[] = [],
): typeof fetch {
  return (input, init) => {
    calls.push({
      url: input instanceof Request ? input.url : input.toString(),
      headers: new Headers(init?.headers),
    });
    const response = responses.shift();
    if (response === undefined) throw new Error('Unexpected profile verification request.');
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
