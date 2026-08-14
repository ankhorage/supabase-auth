import {
  AUTH_OAUTH_SETUP_FIELD_PERSISTENCE_KINDS,
  AUTH_OAUTH_SETUP_FIELD_SENSITIVITIES,
  type AuthOAuthProviderId,
  type AuthOAuthSetupCapabilities,
  type AuthOAuthSetupPlan,
  type AuthOAuthSetupRequirement,
  type AuthOAuthTransportId,
} from '@ankhorage/contracts/auth';

import {
  getSupabaseOAuthProviderDefinition,
  SUPABASE_OAUTH_PROVIDER_IDS,
} from './oauthProviderDefinitions.js';

export const SUPABASE_OAUTH_SETUP_CAPABILITIES = {
  providers: SUPABASE_OAUTH_PROVIDER_IDS,
  transports: ['brokeredRedirect'],
} as const satisfies AuthOAuthSetupCapabilities;

export function resolveSupabaseOAuthSetupPlan(input: {
  readonly provider: AuthOAuthProviderId;
  readonly transport: AuthOAuthTransportId;
  readonly environment: AuthOAuthSetupPlan['environment'];
  readonly targets: AuthOAuthSetupPlan['targets'];
}): AuthOAuthSetupPlan | null {
  if (input.transport !== 'brokeredRedirect') return null;

  const definition = getSupabaseOAuthProviderDefinition(input.provider);
  if (definition === null) return null;

  const targets = [...new Set(input.targets)];
  const requirements: AuthOAuthSetupRequirement[] = definition.secretFields.map((field) => ({
    kind: 'field',
    key: field.name,
    label: field.label,
    required: true,
    sensitivity: AUTH_OAUTH_SETUP_FIELD_SENSITIVITIES[field.secret ? 1 : 0],
    persistence: AUTH_OAUTH_SETUP_FIELD_PERSISTENCE_KINDS[0],
  }));

  requirements.push({
    kind: 'callback',
    role: 'provider',
    label: 'Provider callback URI',
    required: true,
  });

  for (const target of targets) {
    requirements.push({
      kind: 'callback',
      role: 'app',
      target,
      label: `${target} app callback`,
      required: true,
    });
  }

  return { ...input, targets, requirements };
}
