export { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';
export type {
  SupabaseOAuthProviderDefinition,
  SupabaseOAuthProviderId,
  SupabaseOAuthRuntimeEnvironmentDefinition,
  SupabaseOAuthSecretFieldDefinition,
  SupabaseOAuthSecretPayload,
} from './oauthProviderDefinitions.js';
export {
  getSupabaseOAuthProviderDefinition,
  isSupabaseOAuthProviderId,
  materializeSupabaseOAuthEnvironment,
  SUPABASE_OAUTH_PROVIDER_DEFINITIONS,
  SUPABASE_OAUTH_PROVIDER_IDS,
  validateSupabaseOAuthSecretPayload,
} from './oauthProviderDefinitions.js';
export {
  resolveSupabaseOAuthSetupPlan,
  SUPABASE_OAUTH_SETUP_CAPABILITIES,
} from './oauthSetupRequirements.js';
export {
  createSupabaseOAuthProfileVerifier,
  normalizeSupabaseAuthProfileVerificationConfig,
  verifySupabaseOAuthProfile,
} from './profileVerification.js';
export type {
  SupabaseAuthConfig,
  SupabaseAuthErrorCode,
  SupabaseAuthProfileField,
  SupabaseAuthProfileVerificationConfig,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
  SupabaseOAuthLifecycleObserver,
  SupabaseOAuthLifecycleStatus,
  SupabaseOAuthProfileVerificationInput,
  SupabaseOAuthProfileVerificationResult,
  SupabaseOAuthProfileVerifier,
  SupabaseProviderErrorCause,
} from './types.js';
export { SUPABASE_AUTH_PROFILE_FIELDS } from './types.js';
