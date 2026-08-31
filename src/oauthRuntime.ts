import type { AuthOAuthStartResult } from '@ankhorage/contracts/auth';

import type { SupabaseOAuthProviderId } from './oauthProviderDefinitions.js';
import { normalizeAttemptLifetime } from './oauthStorage.js';
import type { CreateSupabaseOAuthAdapterInput } from './oauthTypes.js';

export interface OAuthRuntimeContext extends CreateSupabaseOAuthAdapterInput {
  readonly providers: [SupabaseOAuthProviderId, ...SupabaseOAuthProviderId[]];
  readonly providerSet: ReadonlySet<SupabaseOAuthProviderId>;
  readonly attemptStorageKey: string;
  readonly consumedCallbacksStorageKey: string;
  readonly codeVerifierStorageKey: string;
  readonly now: () => number;
  readonly attemptLifetimeMs: number;
}

export function createOAuthRuntimeContext(
  input: CreateSupabaseOAuthAdapterInput,
): OAuthRuntimeContext {
  const providers = [...new Set(input.providers)];
  if (providers.length === 0) {
    throw new TypeError('At least one enabled Supabase OAuth provider is required.');
  }
  const [firstProvider, ...remainingProviders] = providers;
  if (firstProvider === undefined) throw new TypeError('An OAuth provider is required.');
  const oauthStorageKey = `${input.storageKey}.oauth`;
  return {
    ...input,
    providers: [firstProvider, ...remainingProviders],
    providerSet: new Set(providers),
    attemptStorageKey: `${oauthStorageKey}.attempt`,
    consumedCallbacksStorageKey: `${oauthStorageKey}.consumed-callbacks`,
    codeVerifierStorageKey: `${oauthStorageKey}.pkce-verifier`,
    now: input.now ?? Date.now,
    attemptLifetimeMs: normalizeAttemptLifetime(input.attemptLifetimeMs),
  };
}

export type OAuthStartPreparation =
  | {
      readonly ok: true;
      readonly provider: SupabaseOAuthProviderId;
      readonly redirectUri: string;
      readonly queryParams: Readonly<Record<string, string>>;
    }
  | { readonly ok: false; readonly result: AuthOAuthStartResult };
