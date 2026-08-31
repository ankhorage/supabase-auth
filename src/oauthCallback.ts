import type {
  AuthOAuthCompletionResult,
  CompleteOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import { oauthCompletionError } from './oauthErrors.js';
import type { SupabaseOAuthProviderId } from './oauthProviderDefinitions.js';
import { constantTimeEqual, fingerprintOAuthCallback } from './oauthStorage.js';
import type { StoredOAuthAttempt } from './oauthTypes.js';

const CALLBACK_PARAMS = new Set(['code', 'error', 'error_code', 'error_description']);

type ParsedCallback =
  | { type: 'code'; code: string }
  | { type: 'cancelled' }
  | { type: 'error'; result: AuthOAuthCompletionResult };

/*** Validates an OAuth replay against the callback fingerprint stored for its attempt. */
export function completeOAuthReplay(
  input: CompleteOAuthAuthorizationInput,
  attempt: StoredOAuthAttempt,
): AuthOAuthCompletionResult {
  if (input.response.type !== 'callback') return replayMismatch(attempt.provider, 'response');
  const callback = parseCallback(input.response.url, attempt);
  if (callback.type !== 'code') return replayMismatch(attempt.provider, 'callback');
  const fingerprint = fingerprintOAuthCallback(attempt.id, callback.code);
  if (
    attempt.callbackFingerprint === undefined ||
    !constantTimeEqual(fingerprint, attempt.callbackFingerprint)
  ) {
    return replayMismatch(attempt.provider, 'callback');
  }
  return oauthCompletionError(
    'callback_already_completed',
    'callback',
    'The OAuth authorization callback was already handled.',
    attempt.provider,
    false,
  );
}

/*** Parses and validates the provider callback against the stored redirect URI. */
export function parseCallback(rawCallbackUrl: string, attempt: StoredOAuthAttempt): ParsedCallback {
  const locations = parseCallbackLocations(rawCallbackUrl, attempt.redirectUri);
  if (locations === null)
    return invalidCallback(attempt.provider, 'The OAuth callback URL is invalid.');
  if (
    !sameCallbackLocation(locations.callback, locations.redirect) ||
    locations.callback.hash.length > 0
  ) {
    return invalidCallback(
      attempt.provider,
      'The OAuth callback does not match the expected redirect URI.',
    );
  }
  const unexpected = [...locations.callback.searchParams.keys()].find(
    (key) => !CALLBACK_PARAMS.has(key),
  );
  if (unexpected !== undefined)
    return invalidCallback(attempt.provider, 'The OAuth callback contains unexpected parameters.');
  return classifyCallback(locations.callback.searchParams, attempt.provider);
}

/*** Creates a safe invalid-callback completion result. */
export function invalidCallback(
  provider: SupabaseOAuthProviderId,
  message: string,
): { type: 'error'; result: AuthOAuthCompletionResult } {
  return {
    type: 'error',
    result: oauthCompletionError('invalid_callback', 'callback', message, provider, true),
  };
}

function classifyCallback(
  parameters: URLSearchParams,
  provider: SupabaseOAuthProviderId,
): ParsedCallback {
  const codes = parameters.getAll('code');
  const errors = [...parameters.getAll('error'), ...parameters.getAll('error_code')].filter(
    (value) => value.length > 0,
  );
  if (parameters.getAll('error_description').length > 0 && errors.length === 0) {
    return invalidCallback(
      provider,
      'The OAuth callback contains an error description without an error.',
    );
  }
  if (codes.length > 0 && errors.length > 0) {
    return invalidCallback(provider, 'The OAuth callback contains both a code and an error.');
  }
  if (errors.length > 0) return classifyProviderError(errors, provider);
  const code = codes.at(0);
  return codes.length === 1 && code !== undefined && code.trim().length > 0
    ? { type: 'code', code }
    : invalidCallback(provider, 'The OAuth callback does not contain one authorization code.');
}

function classifyProviderError(
  errors: readonly string[],
  provider: SupabaseOAuthProviderId,
): ParsedCallback {
  if (errors.length === 1 && errors.at(0) === 'access_denied') return { type: 'cancelled' };
  return {
    type: 'error',
    result: oauthCompletionError(
      'authorization_failed',
      'callback',
      'The OAuth provider rejected the authorization request.',
      provider,
      true,
    ),
  };
}

function parseCallbackLocations(
  rawCallbackUrl: string,
  rawRedirectUri: string,
): { callback: URL; redirect: URL } | null {
  try {
    return { callback: new URL(rawCallbackUrl), redirect: new URL(rawRedirectUri) };
  } catch {
    return null;
  }
}

function sameCallbackLocation(callback: URL, redirect: URL): boolean {
  return (
    callback.protocol === redirect.protocol &&
    callback.username === redirect.username &&
    callback.password === redirect.password &&
    callback.host === redirect.host &&
    callback.pathname === redirect.pathname
  );
}

function replayMismatch(
  provider: SupabaseOAuthProviderId,
  subject: 'response' | 'callback',
): AuthOAuthCompletionResult {
  return invalidCallback(
    provider,
    `The OAuth ${subject} does not match the completed authorization callback.`,
  ).result;
}
