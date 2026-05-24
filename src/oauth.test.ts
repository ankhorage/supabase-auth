import { describe, expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';

describe('Supabase OAuth sign-in', () => {
  it('exposes OAuth capabilities from configured providers', () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon-key',
      oauthProviders: ['google', 'github', 'google', ''],
    });

    expect(adapter.capabilities?.supportsOAuth).toBe(true);
    expect(adapter.capabilities?.oauthProviders).toEqual(['google', 'github']);
  });

  it('creates a provider-neutral OAuth redirect result', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co/',
      anonKey: 'anon-key',
      oauthProviders: ['google'],
    });

    const result = await adapter.signInWithOAuth?.({
      provider: 'google',
      redirectTo: 'ankhorage://auth/callback',
      scopes: ['openid', 'email', 'profile'],
      queryParams: {
        prompt: 'select_account',
      },
    });

    expect(result?.ok).toBe(true);

    if (result?.ok !== true || result.data === undefined) {
      throw new Error('Expected OAuth redirect result.');
    }

    const url = new URL(result.data.url);

    expect(result.data.provider).toBe('google');
    expect(url.origin).toBe('https://example.supabase.co');
    expect(url.pathname).toBe('/auth/v1/authorize');
    expect(url.searchParams.get('provider')).toBe('google');
    expect(url.searchParams.get('redirect_to')).toBe('ankhorage://auth/callback');
    expect(url.searchParams.get('scopes')).toBe('openid email profile');
    expect(url.searchParams.get('prompt')).toBe('select_account');
  });

  it('rejects OAuth providers that are not configured', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon-key',
      oauthProviders: ['github'],
    });

    const result = await adapter.signInWithOAuth?.({
      provider: 'google',
      redirectTo: 'ankhorage://auth/callback',
    });

    expect(result?.ok).toBe(false);

    if (result?.ok !== false) {
      throw new Error('Expected OAuth provider validation error.');
    }

    expect(result.error.code).toBe('unsupported_oauth_provider');
  });

  it('does not allow query params to override reserved OAuth parameters', async () => {
    const adapter = createSupabaseAuthAdapter({
      url: 'https://example.supabase.co',
      anonKey: 'anon-key',
      oauthProviders: ['google'],
    });

    const result = await adapter.signInWithOAuth?.({
      provider: 'google',
      redirectTo: 'ankhorage://auth/callback',
      scopes: ['openid'],
      queryParams: {
        provider: 'github',
        redirect_to: 'https://evil.example.com',
        scopes: 'admin',
        prompt: 'consent',
      },
    });

    expect(result?.ok).toBe(true);

    if (result?.ok !== true || result.data === undefined) {
      throw new Error('Expected OAuth redirect result.');
    }

    const url = new URL(result.data.url);

    expect(url.searchParams.get('provider')).toBe('google');
    expect(url.searchParams.get('redirect_to')).toBe('ankhorage://auth/callback');
    expect(url.searchParams.get('scopes')).toBe('openid');
    expect(url.searchParams.get('prompt')).toBe('consent');
  });
});
