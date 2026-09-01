import type { AuthAdapterError } from '@ankhorage/contracts/auth';

import type { SupabaseAuthErrorCode, SupabaseProviderErrorCause } from './types.js';

export function createAuthError(
  code: SupabaseAuthErrorCode,
  message: string,
  cause?: unknown,
): AuthAdapterError {
  return cause === undefined ? { code, message } : { code, message, cause };
}

export function mapNetworkError(cause: unknown): AuthAdapterError {
  return createAuthError('network_error', 'Unable to reach Supabase Auth.', cause);
}

export function mapSupabaseError(response: Response, body: unknown): AuthAdapterError {
  const message = extractErrorMessage(body) ?? response.statusText;
  const normalizedMessage = message.toLowerCase();
  const cause: SupabaseProviderErrorCause = {
    status: response.status,
    body,
  };

  if (isExpiredAccessSession(response.status, normalizedMessage)) {
    return createAuthError('session_expired', 'The auth session expired.', cause);
  }

  if (isInvalidCredentialMessage(normalizedMessage)) {
    return createAuthError('invalid_credentials', 'Invalid credentials.', cause);
  }

  if (isExpiredRefreshSession(normalizedMessage)) {
    return createAuthError('session_expired', 'The auth session expired.', cause);
  }

  if (response.status === 400 || response.status === 422) {
    return createAuthError(
      'validation_error',
      message || 'Supabase rejected the auth request.',
      cause,
    );
  }

  return createAuthError('provider_error', message || 'Supabase Auth returned an error.', cause);
}

function isExpiredAccessSession(status: number, message: string): boolean {
  return status === 401 && includesAny(message, 'jwt', 'session', 'token');
}

function isInvalidCredentialMessage(message: string): boolean {
  return includesAny(
    message,
    'invalid login credentials',
    'invalid credentials',
    'invalid_credentials',
    'invalid_grant',
  );
}

function isExpiredRefreshSession(message: string): boolean {
  return (
    includesAny(message, 'refresh token', 'refresh_token') &&
    includesAny(message, 'invalid', 'expired', 'not found', 'not_found')
  );
}

function includesAny(value: string, ...needles: readonly string[]): boolean {
  return needles.some((needle) => value.includes(needle));
}

export async function readResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? '';

  if (contentType.includes('application/json')) {
    try {
      return await response.json();
    } catch (error) {
      return {
        message: 'Unable to parse Supabase Auth JSON response.',
        cause: error,
      };
    }
  }

  try {
    return await response.text();
  } catch (error) {
    return {
      message: 'Unable to read Supabase Auth response.',
      cause: error,
    };
  }
}

function extractErrorMessage(body: unknown): string | undefined {
  if (typeof body === 'string') {
    return body;
  }

  if (!isRecord(body)) {
    return undefined;
  }

  const candidates = [
    body.message,
    body.msg,
    body.error_description,
    body.error,
    body.error_code,
    body.code,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) {
      return candidate;
    }
  }

  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
