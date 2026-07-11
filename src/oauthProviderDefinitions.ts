import type { AuthOAuthProviderId } from '@ankhorage/contracts/auth';
import type { SecretPayload, SecretStoreResult } from '@ankhorage/contracts/secrets';

export const SUPABASE_OAUTH_PROVIDER_IDS = ['google', 'apple'] as const;
export type SupabaseOAuthProviderId = (typeof SUPABASE_OAUTH_PROVIDER_IDS)[number];

export interface SupabaseOAuthSecretFieldDefinition {
  name: 'clientId' | 'clientSecret';
  label: string;
  secret: boolean;
}

export interface SupabaseOAuthRuntimeEnvironmentDefinition {
  enabled: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface SupabaseOAuthProviderDefinition {
  id: SupabaseOAuthProviderId;
  label: string;
  defaultScopes: readonly string[];
  secretFields: readonly SupabaseOAuthSecretFieldDefinition[];
  runtimeEnvironment: SupabaseOAuthRuntimeEnvironmentDefinition;
}

const SHARED_SECRET_FIELDS = [
  { name: 'clientId', label: 'Client ID', secret: false },
  { name: 'clientSecret', label: 'Client secret', secret: true },
] as const satisfies readonly SupabaseOAuthSecretFieldDefinition[];

export const SUPABASE_OAUTH_PROVIDER_DEFINITIONS = {
  google: {
    id: 'google',
    label: 'Google',
    defaultScopes: ['openid', 'email', 'profile'],
    secretFields: SHARED_SECRET_FIELDS,
    runtimeEnvironment: {
      enabled: 'GOTRUE_EXTERNAL_GOOGLE_ENABLED',
      clientId: 'GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID',
      clientSecret: 'GOTRUE_EXTERNAL_GOOGLE_SECRET',
      redirectUri: 'GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI',
    },
  },
  apple: {
    id: 'apple',
    label: 'Apple',
    defaultScopes: ['name', 'email'],
    secretFields: SHARED_SECRET_FIELDS,
    runtimeEnvironment: {
      enabled: 'GOTRUE_EXTERNAL_APPLE_ENABLED',
      clientId: 'GOTRUE_EXTERNAL_APPLE_CLIENT_ID',
      clientSecret: 'GOTRUE_EXTERNAL_APPLE_SECRET',
      redirectUri: 'GOTRUE_EXTERNAL_APPLE_REDIRECT_URI',
    },
  },
} as const satisfies Record<SupabaseOAuthProviderId, SupabaseOAuthProviderDefinition>;

export function isSupabaseOAuthProviderId(
  provider: AuthOAuthProviderId,
): provider is SupabaseOAuthProviderId {
  return (SUPABASE_OAUTH_PROVIDER_IDS as readonly string[]).includes(provider);
}

export function getSupabaseOAuthProviderDefinition(
  provider: AuthOAuthProviderId,
): SupabaseOAuthProviderDefinition | null {
  return isSupabaseOAuthProviderId(provider)
    ? SUPABASE_OAUTH_PROVIDER_DEFINITIONS[provider]
    : null;
}

export function validateSupabaseOAuthSecretPayload(
  provider: AuthOAuthProviderId,
  payload: SecretPayload,
): SecretStoreResult<SecretPayload> {
  const definition = getSupabaseOAuthProviderDefinition(provider);
  if (definition === null) {
    return {
      ok: false,
      error: {
        code: 'invalid_config',
        message: `Supabase OAuth provider "${provider}" is not supported by the current provider registry.`,
      },
    };
  }

  const missingFields = definition.secretFields
    .map((field) => field.name)
    .filter((field) => typeof payload[field] !== 'string' || payload[field].trim().length === 0);

  if (missingFields.length > 0) {
    return {
      ok: false,
      error: {
        code: 'invalid_payload',
        message: `OAuth credentials for "${provider}" are missing required fields: ${missingFields.join(', ')}.`,
      },
    };
  }

  return { ok: true, data: payload };
}

export function materializeSupabaseOAuthEnvironment(input: {
  provider: AuthOAuthProviderId;
  payload: SecretPayload;
  redirectUri: string;
}): SecretStoreResult<Readonly<Record<string, string>>> {
  const definition = getSupabaseOAuthProviderDefinition(input.provider);
  if (definition === null) {
    return {
      ok: false,
      error: {
        code: 'invalid_config',
        message: `Supabase OAuth provider "${input.provider}" is not supported by the current provider registry.`,
      },
    };
  }

  const payloadResult = validateSupabaseOAuthSecretPayload(input.provider, input.payload);
  if (!payloadResult.ok) return payloadResult;

  const redirectUri = input.redirectUri.trim();
  if (redirectUri.length === 0) {
    return {
      ok: false,
      error: {
        code: 'invalid_config',
        message: `OAuth provider "${input.provider}" requires a redirect URI.`,
      },
    };
  }

  return {
    ok: true,
    data: {
      [definition.runtimeEnvironment.enabled]: 'true',
      [definition.runtimeEnvironment.clientId]: payloadResult.data.clientId,
      [definition.runtimeEnvironment.clientSecret]: payloadResult.data.clientSecret,
      [definition.runtimeEnvironment.redirectUri]: redirectUri,
    },
  };
}
