import type { AuthOAuthCompletionResult, AuthSession } from '@ankhorage/contracts/auth';

import { readResponseBody } from './errors.js';
import { failOAuthAttempt } from './oauthCompletionState.js';
import { mapSupabaseOAuthError, oauthCompletionError } from './oauthErrors.js';
import { emitLifecycleEvent } from './oauthLifecycle.js';
import type { OAuthRuntimeContext } from './oauthRuntime.js';
import { exchangeAuthorizationCode } from './oauthStartSupport.js';
import type { StoredOAuthAttempt } from './oauthTypes.js';
import { normalizeSupabaseSession } from './session.js';

type SessionResult =
  { ok: true; data: AuthSession } | { ok: false; result: AuthOAuthCompletionResult };

/*** Exchanges an OAuth code, persists its session, and verifies the generated profile. */
export async function exchangeAndPersistOAuthSession(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  code: string,
): Promise<SessionResult> {
  const verifier = await readVerifier(context, attempt);
  if (!verifier.ok) return verifier;
  const exchanged = await exchangeSession(context, attempt, code, verifier.data);
  if (!exchanged.ok) return exchanged;
  const persisted = await persistSession(context, attempt, exchanged.data);
  if (!persisted.ok) return persisted;
  const verified = await verifyProfile(context, attempt, exchanged.data);
  return verified.ok ? exchanged : verified;
}

async function exchangeSession(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  code: string,
  verifier: string,
): Promise<SessionResult> {
  let response: Response;
  try {
    response = await exchangeAuthorizationCode({
      anonKey: context.anonKey,
      baseUrl: context.url,
      code,
      fetch: context.fetch,
      verifier,
    });
  } catch {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'network_error',
        'exchange',
        'Unable to exchange the OAuth code.',
        attempt.provider,
        true,
      ),
    );
  }
  return normalizeExchangeResponse(context, attempt, response);
}

async function normalizeExchangeResponse(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  response: Response,
): Promise<SessionResult> {
  const body = await readResponseBody(response);
  if (!response.ok) {
    return failOAuthAttempt(context, attempt, {
      ok: false,
      status: 'error',
      error: mapSupabaseOAuthError(body, 'exchange', attempt.provider),
    });
  }
  const session = normalizeSupabaseSession(body);
  return session === null
    ? failOAuthAttempt(
        context,
        attempt,
        oauthCompletionError(
          'provider_error',
          'session',
          'Supabase returned an invalid OAuth session.',
          attempt.provider,
          false,
        ),
      )
    : { ok: true, data: session };
}

async function readVerifier(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
): Promise<{ ok: true; data: string } | { ok: false; result: AuthOAuthCompletionResult }> {
  let verifier: string | null;
  try {
    verifier = await context.storage.getItem(context.codeVerifierStorageKey);
  } catch {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'session_persistence_failed',
        'exchange',
        'The OAuth verifier could not be read.',
        attempt.provider,
        true,
      ),
    );
  }
  return verifier === null || verifier.length === 0
    ? failOAuthAttempt(
        context,
        attempt,
        oauthCompletionError(
          'pkce_mismatch',
          'exchange',
          'The OAuth verifier is missing.',
          attempt.provider,
          true,
        ),
      )
    : { ok: true, data: verifier };
}

async function persistSession(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  session: AuthSession,
): Promise<{ ok: true } | { ok: false; result: AuthOAuthCompletionResult }> {
  try {
    await context.persistSession(session);
    return { ok: true };
  } catch {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'session_persistence_failed',
        'session',
        'The OAuth session could not be persisted.',
        attempt.provider,
        true,
      ),
    );
  }
}

async function verifyProfile(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  session: AuthSession,
): Promise<{ ok: true } | { ok: false; result: AuthOAuthCompletionResult }> {
  if (context.verifyProfile === undefined) return { ok: true };
  let verification;
  try {
    verification = await context.verifyProfile({
      correlationId: attempt.id,
      provider: attempt.provider,
      session,
    });
  } catch {
    verification = {
      ok: false as const,
      message: 'The generated public profile could not be verified.',
    };
  }
  if (!verification.ok) {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'profile_creation_failed',
        'profile',
        verification.message,
        attempt.provider,
        true,
      ),
    );
  }
  await emitLifecycleEvent(context.onLifecycleEvent, {
    correlationId: attempt.id,
    provider: attempt.provider,
    stage: 'profile',
    status: 'profile_verified',
  });
  return { ok: true };
}
