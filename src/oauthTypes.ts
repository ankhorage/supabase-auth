import type { AuthSession } from '@ankhorage/contracts/auth';

import type { SupabaseOAuthProviderId } from './oauthProviderDefinitions.js';
import type {
  SupabaseAuthFetch,
  SupabaseAuthRandomBytes,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleObserver,
  SupabaseOAuthProfileVerifier,
} from './types.js';

export const ATTEMPT_VERSION = 4;
export const DEFAULT_ATTEMPT_LIFETIME_MS = 10 * 60 * 1000;
export const CONSUMED_CALLBACKS_VERSION = 1;
export const CONSUMED_CALLBACK_RETENTION_MS = 24 * 60 * 60 * 1000;
export const MAX_CONSUMED_CALLBACKS = 32;

export interface CreateSupabaseOAuthAdapterInput {
  url: string;
  anonKey: string;
  fetch: SupabaseAuthFetch;
  storage: SupabaseAuthStorage;
  storageKey: string;
  providers: readonly SupabaseOAuthProviderId[];
  randomBytes?: SupabaseAuthRandomBytes;
  persistSession(session: AuthSession): Promise<void>;
  verifyProfile?: SupabaseOAuthProfileVerifier;
  onLifecycleEvent?: SupabaseOAuthLifecycleObserver;
  now?: () => number;
  attemptLifetimeMs?: number;
}

export interface StoredOAuthAttempt {
  version: typeof ATTEMPT_VERSION;
  id: string;
  provider: SupabaseOAuthProviderId;
  redirectUri: string;
  status: 'pending' | 'completing' | 'completed';
  createdAt: number;
  expiresAt: number;
  callbackFingerprint?: string;
}

export interface StoredConsumedOAuthCallback {
  fingerprint: string;
  expiresAt: number;
}

export interface StoredConsumedOAuthCallbacks {
  version: typeof CONSUMED_CALLBACKS_VERSION;
  callbacks: readonly StoredConsumedOAuthCallback[];
}

export type StoredOAuthAttemptReadResult =
  { type: 'missing' } | { type: 'invalid' } | { type: 'valid'; attempt: StoredOAuthAttempt };
