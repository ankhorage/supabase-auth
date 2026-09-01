import { expect, test } from 'bun:test';

import {
  getSupabaseOAuthProviderDefinition,
  materializeSupabaseOAuthEnvironment,
  SUPABASE_OAUTH_PROVIDER_DEFINITIONS,
  validateSupabaseOAuthSecretPayload,
} from './oauthProviderDefinitions.js';

test('defines Google and Apple from one registry', () => {
  expect(Object.keys(SUPABASE_OAUTH_PROVIDER_DEFINITIONS)).toEqual(['google', 'apple']);
  expect(getSupabaseOAuthProviderDefinition('google')?.secretFields).toEqual([
    { name: 'clientId', label: 'Client ID', secret: false },
    { name: 'clientSecret', label: 'Client secret', secret: true },
  ]);
});

test('validates required secret fields without echoing values', () => {
  const result = validateSupabaseOAuthSecretPayload('google', {
    clientId: 'google-client-id',
    clientSecret: '',
  });

  expect(result).toEqual({
    ok: false,
    error: {
      code: 'invalid_payload',
      message: 'OAuth credentials for "google" are missing required fields: clientSecret.',
    },
  });
  expect(JSON.stringify(result)).not.toContain('google-client-id');
});

test('materializes official GoTrue Google environment names', () => {
  expect(
    materializeSupabaseOAuthEnvironment({
      provider: 'google',
      payload: {
        clientId: 'google-client-id',
        clientSecret: 'sentinel-google-secret',
      },
      redirectUri: 'http://localhost:9999/callback',
    }),
  ).toEqual({
    ok: true,
    data: {
      GOTRUE_EXTERNAL_GOOGLE_ENABLED: 'true',
      GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID: 'google-client-id',
      GOTRUE_EXTERNAL_GOOGLE_SECRET: 'sentinel-google-secret',
      GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI: 'http://localhost:9999/callback',
    },
  });
});

test('materializes official GoTrue Apple environment names', () => {
  expect(
    materializeSupabaseOAuthEnvironment({
      provider: 'apple',
      payload: {
        clientId: 'apple-client-id',
        clientSecret: 'sentinel-apple-secret',
      },
      redirectUri: 'http://localhost:9999/callback',
    }),
  ).toEqual({
    ok: true,
    data: {
      GOTRUE_EXTERNAL_APPLE_ENABLED: 'true',
      GOTRUE_EXTERNAL_APPLE_CLIENT_ID: 'apple-client-id',
      GOTRUE_EXTERNAL_APPLE_SECRET: 'sentinel-apple-secret',
      GOTRUE_EXTERNAL_APPLE_REDIRECT_URI: 'http://localhost:9999/callback',
    },
  });
});

test('rejects providers outside the current Supabase registry', () => {
  const result = materializeSupabaseOAuthEnvironment({
    provider: 'github',
    payload: { clientId: 'id', clientSecret: 'secret' },
    redirectUri: 'http://localhost:9999/callback',
  });

  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error.code).toBe('invalid_config');
});
