import type {
  AuthAdapter,
  AuthResult,
  AuthSession,
  AuthUser,
  PasswordResetInput,
  SignInInput,
  SignUpInput,
  VerifyOtpInput,
} from '@ankhorage/contracts/auth';

import type { AuthOperationContext } from './authSessionContext.js';
import { createAuthError, mapNetworkError, mapSupabaseError, readResponseBody } from './errors.js';
import { normalizeSupabaseSession, normalizeSupabaseUser } from './session.js';

export function createSignInOperation(context: AuthOperationContext): AuthAdapter['signIn'] {
  return async (input: SignInInput): Promise<AuthResult<AuthSession>> => {
    const credentials = passwordCredentials(input.identifier, input.password);
    if (!credentials.ok) return credentials;
    try {
      const response = await context.request('token?grant_type=password', {
        body: credentials.data,
      });
      return await context.handleSessionResponse(response);
    } catch (error) {
      return { ok: false, error: mapNetworkError(error) };
    }
  };
}

export function createSignUpOperation(context: AuthOperationContext): AuthAdapter['signUp'] {
  return async (input: SignUpInput): Promise<AuthResult<AuthSession | AuthUser>> => {
    const credentials = passwordCredentials(input.identifier, input.password);
    if (!credentials.ok) return credentials;
    try {
      const response = await context.request('signup', {
        body: { ...credentials.data, ...metadataBody(input.profile, input.metadata) },
        redirectTo: input.redirectTo,
      });
      return await handleSignUpResponse(context, response);
    } catch (error) {
      return { ok: false, error: mapNetworkError(error) };
    }
  };
}

export function createPasswordResetOperation(
  context: AuthOperationContext,
): AuthAdapter['requestPasswordReset'] {
  return async (input: PasswordResetInput): Promise<AuthResult> => {
    const email = passwordResetEmail(input);
    if (!email.ok) return email;
    try {
      const response = await context.request('recover', {
        body: { email: email.data },
        redirectTo: input.redirectTo,
      });
      if (response.ok) return { ok: true };
      return { ok: false, error: mapSupabaseError(response, await readResponseBody(response)) };
    } catch (error) {
      return { ok: false, error: mapNetworkError(error) };
    }
  };
}

export function createVerifyOtpOperation(context: AuthOperationContext): AuthAdapter['verifyOtp'] {
  return async (input: VerifyOtpInput): Promise<AuthResult<AuthSession>> => {
    const body = otpBody(input);
    if (!body.ok) return body;
    try {
      const response = await context.request('verify', {
        body: body.data,
        redirectTo: input.redirectTo,
      });
      return await context.handleSessionResponse(response);
    } catch (error) {
      return { ok: false, error: mapNetworkError(error) };
    }
  };
}

async function handleSignUpResponse(
  context: AuthOperationContext,
  response: Response,
): Promise<AuthResult<AuthSession | AuthUser>> {
  const body = await readResponseBody(response);
  if (!response.ok) return { ok: false, error: mapSupabaseError(response, body) };
  const session = normalizeSupabaseSession(body);
  if (session !== null) {
    const error = await context.persistSessionSafely(session);
    return error === null ? { ok: true, data: session } : { ok: false, error };
  }
  const user = normalizeSupabaseUser(isRecord(body) && 'user' in body ? body.user : body);
  return user === null
    ? {
        ok: false,
        error: createAuthError('provider_error', 'Supabase returned an invalid sign-up.', body),
      }
    : { ok: true, data: user };
}

function passwordCredentials(identifier: SignInInput['identifier'], password: string | undefined) {
  const passwordError = validatePassword(password);
  if (passwordError !== null) return { ok: false as const, error: passwordError };
  const body = identifierBody(identifier);
  return body.ok ? { ok: true as const, data: { ...body.data, password } } : body;
}

function passwordResetEmail(input: PasswordResetInput) {
  if (input.identifier.kind !== 'email') {
    return {
      ok: false as const,
      error: createAuthError('unsupported_identifier', 'Password reset supports email only.'),
    };
  }
  const value = input.identifier.value.trim();
  return value.length === 0
    ? {
        ok: false as const,
        error: createAuthError('missing_identifier', 'An auth identifier is required.'),
      }
    : { ok: true as const, data: value };
}

function otpBody(input: VerifyOtpInput) {
  const token = input.token.trim();
  if (token.length === 0) {
    return {
      ok: false as const,
      error: createAuthError('validation_error', 'An OTP token is required.'),
    };
  }
  const identifier = identifierBody(input.identifier);
  return identifier.ok
    ? {
        ok: true as const,
        data: {
          ...identifier.data,
          token,
          type: input.identifier.kind === 'phone' ? 'sms' : 'email',
        },
      }
    : identifier;
}

function validatePassword(password: string | undefined) {
  return password === undefined || password.length === 0
    ? createAuthError('missing_password', 'A password is required.')
    : null;
}

function identifierBody(identifier: SignInInput['identifier']) {
  const value = identifier.value.trim();
  if (value.length === 0) {
    return {
      ok: false as const,
      error: createAuthError('missing_identifier', 'An auth identifier is required.'),
    };
  }
  if (identifier.kind === 'email') return { ok: true as const, data: { email: value } };
  if (identifier.kind === 'phone') return { ok: true as const, data: { phone: value } };
  return {
    ok: false as const,
    error: createAuthError('unsupported_identifier', 'Supabase supports email and phone.'),
  };
}

function metadataBody(
  profile: Record<string, unknown> | undefined,
  metadata: Record<string, unknown> | undefined,
): { readonly data?: Record<string, unknown> } {
  const data = { ...(profile ?? {}), ...(metadata ?? {}) };
  return Object.keys(data).length > 0 ? { data } : {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
