import type { AuthOAuthProviderId } from '@ankhorage/contracts/auth';

import {
  isSupabaseOAuthProviderId,
  type SupabaseOAuthProviderId,
} from './oauthProviderDefinitions.js';
import { normalizeSupabaseAuthProfileVerificationConfig } from './profileVerification.js';
import type {
  SupabaseAuthConfig,
  SupabaseAuthFetch,
  SupabaseAuthProfileVerificationConfig,
  SupabaseAuthRandomBytes,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleObserver,
} from './types.js';

const DEFAULT_STORAGE_KEY = 'ankhorage.supabase-auth.session';

export interface RequiredSupabaseAuthConfig {
  readonly url: string;
  readonly anonKey: string;
  readonly fetch: SupabaseAuthFetch;
  readonly storage?: SupabaseAuthStorage;
  readonly storageKey: string;
  readonly oauthProviders: SupabaseOAuthProviderId[];
  readonly oauthRandomBytes?: SupabaseAuthRandomBytes;
  readonly profileVerification?: SupabaseAuthProfileVerificationConfig;
  readonly onOAuthLifecycleEvent?: SupabaseOAuthLifecycleObserver;
}

export function validateSupabaseAuthConfig(config: SupabaseAuthConfig): RequiredSupabaseAuthConfig {
  const url = normalizeUrl(config.url);
  const anonKey = config.anonKey.trim();
  if (anonKey.length === 0) throw new TypeError('Supabase anon key is required.');
  const oauthProviders = normalizeOAuthProviders(config);
  validateOAuthConfiguration(config, oauthProviders);
  const configuredStorageKey = config.storageKey?.trim();
  return {
    url,
    anonKey,
    fetch: requireFetch(config.fetch),
    storage: config.storage,
    storageKey:
      configuredStorageKey === undefined || configuredStorageKey.length === 0
        ? DEFAULT_STORAGE_KEY
        : configuredStorageKey,
    oauthProviders,
    oauthRandomBytes: config.oauthRandomBytes,
    profileVerification:
      config.profileVerification === undefined
        ? undefined
        : normalizeSupabaseAuthProfileVerificationConfig(config.profileVerification),
    onOAuthLifecycleEvent: config.onOAuthLifecycleEvent,
  };
}

function normalizeUrl(rawUrl: string): string {
  const url = rawUrl.trim();
  if (url.length === 0) throw new TypeError('Supabase Auth URL is required.');
  try {
    new URL(url);
  } catch {
    throw new TypeError('Supabase Auth URL must be a valid URL.');
  }
  return url.replace(/\/+$/u, '');
}

function normalizeOAuthProviders(config: SupabaseAuthConfig): SupabaseOAuthProviderId[] {
  const providers: SupabaseOAuthProviderId[] = [];
  for (const rawProvider of config.oauthProviders ?? []) {
    const provider: AuthOAuthProviderId = rawProvider.trim();
    if (!isSupabaseOAuthProviderId(provider)) {
      throw new TypeError(`Supabase OAuth provider "${provider}" is not supported.`);
    }
    if (!providers.includes(provider)) providers.push(provider);
  }
  return providers;
}

function validateOAuthConfiguration(
  config: SupabaseAuthConfig,
  providers: readonly SupabaseOAuthProviderId[],
): void {
  if (providers.length > 0 && config.storage === undefined) {
    throw new TypeError('Supabase OAuth PKCE requires persistent auth storage.');
  }
  if (config.profileVerification !== undefined && providers.length === 0) {
    throw new TypeError('Supabase OAuth profile verification requires an OAuth provider.');
  }
}

function requireFetch(fetchImplementation = createDefaultFetch()): SupabaseAuthFetch {
  if (typeof fetchImplementation !== 'function') {
    throw new TypeError('A fetch implementation is required to use Supabase Auth.');
  }
  return fetchImplementation;
}

function createDefaultFetch(): SupabaseAuthFetch {
  return Object.assign(
    (input: Parameters<SupabaseAuthFetch>[0], init?: Parameters<SupabaseAuthFetch>[1]) =>
      globalThis.fetch(input, init),
    {
      preconnect(
        url: Parameters<SupabaseAuthFetch['preconnect']>[0],
        options?: Parameters<SupabaseAuthFetch['preconnect']>[1],
      ): ReturnType<SupabaseAuthFetch['preconnect']> {
        return globalThis.fetch.preconnect(url, options);
      },
    },
  );
}
