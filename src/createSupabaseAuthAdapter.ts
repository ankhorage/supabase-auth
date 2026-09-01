import type { AuthAdapter, AuthSession } from '@ankhorage/contracts/auth';

import {
  type RequiredSupabaseAuthConfig,
  validateSupabaseAuthConfig,
} from './authConfiguration.js';
import {
  createPasswordResetOperation,
  createSignInOperation,
  createSignUpOperation,
  createVerifyOtpOperation,
} from './authPasswordOperations.js';
import { type AuthOperationContext, createAuthOperationContext } from './authSessionContext.js';
import {
  createGetSessionOperation,
  createRefreshSessionOperation,
  createSignOutOperation,
} from './authSessionOperations.js';
import { createSupabaseOAuthAdapter } from './oauth.js';
import { createSupabaseOAuthProfileVerifier } from './profileVerification.js';
import type { SupabaseAuthConfig, SupabaseOAuthProfileVerifier } from './types.js';

export function createSupabaseAuthAdapter(config: SupabaseAuthConfig): AuthAdapter {
  const normalizedConfig = validateSupabaseAuthConfig(config);
  const context = createAuthOperationContext(normalizedConfig);
  const oauth = createOAuthAdapter(context);
  return {
    capabilities: {
      signInIdentifiers: ['email', 'phone'],
      supportsSignUp: true,
      supportsPasswordReset: true,
      supportsOtp: true,
      supportsSessionRefresh: true,
    },
    ...(oauth === undefined ? {} : { oauth }),
    signIn: createSignInOperation(context),
    signUp: createSignUpOperation(context),
    signOut: createSignOutOperation(context),
    getSession: createGetSessionOperation(context),
    refreshSession: createRefreshSessionOperation(context),
    requestPasswordReset: createPasswordResetOperation(context),
    verifyOtp: createVerifyOtpOperation(context),
  };
}

function createOAuthAdapter(context: AuthOperationContext) {
  const { config } = context;
  if (config.oauthProviders.length === 0) return undefined;
  const profileVerifier = createProfileVerifier(config);
  return createSupabaseOAuthAdapter({
    url: config.url,
    anonKey: config.anonKey,
    fetch: config.fetch,
    storage: requireOAuthStorage(config),
    storageKey: config.storageKey,
    providers: config.oauthProviders,
    randomBytes: config.oauthRandomBytes,
    persistSession: createOAuthSessionPersistence(context),
    ...(profileVerifier === undefined ? {} : { verifyProfile: profileVerifier }),
    ...(config.onOAuthLifecycleEvent === undefined
      ? {}
      : { onLifecycleEvent: config.onOAuthLifecycleEvent }),
  });
}

function createOAuthSessionPersistence(context: AuthOperationContext) {
  return async (session: AuthSession): Promise<void> => {
    const error = await context.persistSessionSafely(session);
    if (error !== null) throw new Error(error.message);
  };
}

function createProfileVerifier(
  config: RequiredSupabaseAuthConfig,
): SupabaseOAuthProfileVerifier | undefined {
  if (config.profileVerification === undefined) return undefined;
  return createSupabaseOAuthProfileVerifier({
    url: config.url,
    anonKey: config.anonKey,
    fetch: config.fetch,
    config: config.profileVerification,
  });
}

function requireOAuthStorage(config: RequiredSupabaseAuthConfig) {
  if (config.storage === undefined) {
    throw new TypeError('Supabase OAuth PKCE requires persistent auth storage.');
  }
  return config.storage;
}
