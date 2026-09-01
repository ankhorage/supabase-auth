import type {
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthErrorCode,
  AuthOAuthErrorStage,
  AuthOAuthProviderId,
  AuthOAuthStartResult,
} from '@ankhorage/contracts/auth';

import type { SupabaseOAuthProviderId } from './oauthProviderDefinitions.js';

interface OAuthErrorRule {
  readonly matches: (normalized: string) => boolean;
  readonly code: AuthOAuthErrorCode;
  readonly stage?: AuthOAuthErrorStage;
  readonly message: string;
}

const OAUTH_ERROR_RULES: readonly OAuthErrorRule[] = [
  {
    matches: includesAny('pkce_code_verifier_not_found', 'bad_code_verifier'),
    code: 'pkce_mismatch',
    stage: 'exchange',
    message: 'The OAuth PKCE verifier is missing or invalid.',
  },
  {
    matches: includesAny('bad_oauth_state', 'flow_state_not_found', 'flow_state_expired'),
    code: 'state_mismatch',
    message: 'The OAuth authorization state is missing, expired, or invalid.',
  },
  {
    matches: includesAny('bad_oauth_callback'),
    code: 'invalid_callback',
    stage: 'callback',
    message: 'Supabase Auth rejected the OAuth callback.',
  },
  {
    matches: includesAny('provider_disabled'),
    code: 'provider_disabled',
    message: 'The OAuth provider is disabled in Supabase Auth.',
  },
  {
    matches: includesAny('oauth_provider_not_supported'),
    code: 'provider_misconfigured',
    message: 'The OAuth provider is not configured in Supabase Auth.',
  },
  {
    matches: includesAny('redirect'),
    code: 'invalid_redirect_uri',
    message: 'Supabase Auth rejected the OAuth redirect URI.',
  },
  {
    matches: includesAny('authretryablefetcherror', 'fetch failed', 'network'),
    code: 'network_error',
    message: 'Unable to reach Supabase Auth during OAuth authorization.',
  },
];

/*** Maps safe Supabase error metadata to the canonical OAuth error contract. */
export function mapSupabaseOAuthError(
  error: unknown,
  stage: AuthOAuthErrorStage,
  provider: SupabaseOAuthProviderId,
): AuthOAuthError {
  const normalized = normalizeOAuthErrorText(error);
  const rule = OAUTH_ERROR_RULES.find((candidate) => candidate.matches(normalized));
  if (rule !== undefined) {
    return createOAuthError(rule.code, rule.stage ?? stage, rule.message, provider, true);
  }
  return createOAuthError(
    stage === 'start' ? 'authorization_failed' : 'code_exchange_failed',
    stage,
    stage === 'start'
      ? 'Supabase Auth could not start OAuth authorization.'
      : 'Supabase Auth could not exchange the OAuth authorization code.',
    provider,
    true,
  );
}

/*** Creates a failed OAuth start result. */
export function oauthStartError(
  code: AuthOAuthErrorCode,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthStartResult {
  return { ok: false, error: createOAuthError(code, 'start', message, provider, recoverable) };
}

/*** Creates a failed OAuth completion result. */
export function oauthCompletionError(
  code: AuthOAuthErrorCode,
  stage: AuthOAuthErrorStage,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthCompletionResult {
  return {
    ok: false,
    status: 'error',
    error: createOAuthError(code, stage, message, provider, recoverable),
  };
}

/*** Creates a canonical OAuth error without exposing provider secrets. */
function createOAuthError(
  code: AuthOAuthErrorCode,
  stage: AuthOAuthErrorStage,
  message: string,
  provider: AuthOAuthProviderId | undefined,
  recoverable: boolean,
): AuthOAuthError {
  return provider === undefined
    ? { code, stage, message, recoverable }
    : { code, stage, message, provider, recoverable };
}

function normalizeOAuthErrorText(value: unknown): string {
  const code = readString(value, 'code');
  const name = readString(value, 'name');
  const message = readString(value, 'message') ?? 'Supabase Auth returned an OAuth error.';
  return `${code ?? ''} ${name ?? ''} ${message}`.toLowerCase();
}

function includesAny(...needles: readonly string[]): (value: string) => boolean {
  return (value) => needles.some((needle) => value.includes(needle));
}

function readString(value: unknown, key: string): string | undefined {
  if (!isRecord(value)) return undefined;
  const candidate: unknown = Reflect.get(value, key);
  return typeof candidate === 'string' ? candidate : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
