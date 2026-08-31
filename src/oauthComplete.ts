import type {
  AuthOAuthCancellationReason,
  AuthOAuthCompletionResult,
  CompleteOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import { completeOAuthReplay, invalidCallback, parseCallback } from './oauthCallback.js';
import {
  clearOAuthAttempt,
  failOAuthAttempt,
  finalizeOAuthAttemptState,
} from './oauthCompletionState.js';
import { oauthCompletionError } from './oauthErrors.js';
import { exchangeAndPersistOAuthSession } from './oauthExchange.js';
import { emitLifecycleEvent } from './oauthLifecycle.js';
import type { OAuthRuntimeContext } from './oauthRuntime.js';
import {
  constantTimeEqual,
  fingerprintConsumedOAuthCallback,
  fingerprintOAuthCallback,
  isAttemptExpired,
  readAttempt,
  readConsumedCallbacks,
  writeAttempt,
  writeConsumedCallbacks,
} from './oauthStorage.js';
import {
  CONSUMED_CALLBACK_RETENTION_MS,
  type StoredConsumedOAuthCallback,
  type StoredOAuthAttempt,
} from './oauthTypes.js';

type LoadedAttempt =
  | { readonly ok: true; readonly attempt: StoredOAuthAttempt }
  | { readonly ok: false; readonly result: AuthOAuthCompletionResult };
type ParsedCompletion =
  | { readonly ok: true; readonly code: string }
  | { readonly ok: false; readonly result: AuthOAuthCompletionResult };
type ReservedCallback =
  | { readonly ok: true; readonly callbackFingerprint: string }
  | { readonly ok: false; readonly result: AuthOAuthCompletionResult };

/*** Completes one Supabase OAuth authorization attempt. */
export async function completeSupabaseOAuthAuthorization(
  context: OAuthRuntimeContext,
  input: CompleteOAuthAuthorizationInput,
): Promise<AuthOAuthCompletionResult> {
  const loaded = await loadAttempt(context, input);
  if (!loaded.ok) return loaded.result;
  const { attempt } = loaded;
  if (attempt.status !== 'pending') return completeOAuthReplay(input, attempt);
  const parsed = await parseCompletion(context, attempt, input);
  if (!parsed.ok) return parsed.result;
  const reserved = await reserveCallback(context, attempt, parsed.code);
  if (!reserved.ok) return reserved.result;
  const session = await exchangeAndPersistOAuthSession(context, attempt, parsed.code);
  if (!session.ok) return session.result;
  await finalizeOAuthAttemptState(context, attempt, reserved.callbackFingerprint);
  return { ok: true, status: 'authenticated', provider: attempt.provider, session: session.data };
}

async function loadAttempt(
  context: OAuthRuntimeContext,
  input: CompleteOAuthAuthorizationInput,
): Promise<LoadedAttempt> {
  let stored;
  try {
    stored = await readAttempt(context.storage, context.attemptStorageKey);
  } catch {
    await clearOAuthAttempt(context);
    return completionFailure('session_persistence_failed', 'Unable to read the OAuth attempt.');
  }
  if (stored.type !== 'valid') {
    await clearOAuthAttempt(context);
    return completionFailure('authorization_attempt_not_found', 'The OAuth attempt is invalid.');
  }
  const { attempt } = stored;
  if (isAttemptExpired(attempt, context.now())) {
    await clearOAuthAttempt(context);
    return completionFailure(
      'authorization_attempt_not_found',
      'The OAuth attempt expired.',
      attempt,
    );
  }
  return attempt.id === input.attemptId
    ? { ok: true, attempt }
    : completionFailure(
        'authorization_attempt_not_found',
        'The OAuth attempt was not found.',
        attempt,
      );
}

async function parseCompletion(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  input: CompleteOAuthAuthorizationInput,
): Promise<ParsedCompletion> {
  if (input.response.type === 'cancelled') {
    return completeCancellation(context, attempt, 'transport', input.response.reason);
  }
  if (input.response.type === 'error') {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'authorization_failed',
        'transport',
        'The OAuth transport failed.',
        attempt.provider,
        true,
      ),
    );
  }
  const callback = parseCallback(input.response.url, attempt);
  if (callback.type === 'code') return { ok: true, code: callback.code };
  if (callback.type === 'error') return failOAuthAttempt(context, attempt, callback.result);
  return completeCancellation(context, attempt, 'callback', 'provider_denied');
}

async function completeCancellation(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  stage: 'transport' | 'callback',
  reason: AuthOAuthCancellationReason,
): Promise<ParsedCompletion> {
  await finalizeOAuthAttemptState(context, attempt);
  await emitLifecycleEvent(context.onLifecycleEvent, {
    correlationId: attempt.id,
    provider: attempt.provider,
    stage,
    status: 'cancelled',
  });
  return {
    ok: false,
    result: { ok: false, status: 'cancelled', provider: attempt.provider, reason },
  };
}

async function reserveCallback(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  code: string,
): Promise<ReservedCallback> {
  const callbackFingerprint = fingerprintOAuthCallback(attempt.id, code);
  const consumedFingerprint = fingerprintConsumedOAuthCallback(attempt.redirectUri, code);
  let callbacks: readonly StoredConsumedOAuthCallback[];
  try {
    callbacks = await readConsumedCallbacks(
      context.storage,
      context.consumedCallbacksStorageKey,
      context.now(),
    );
  } catch {
    return failOAuthAttempt(
      context,
      attempt,
      oauthCompletionError(
        'session_persistence_failed',
        'callback',
        'Unable to read consumed OAuth callbacks.',
        attempt.provider,
        true,
      ),
    );
  }
  if (callbacks.some((entry) => constantTimeEqual(entry.fingerprint, consumedFingerprint))) {
    return failOAuthAttempt(
      context,
      attempt,
      invalidCallback(attempt.provider, 'The OAuth callback was already consumed.').result,
    );
  }
  return writeCallbackReservation(
    context,
    attempt,
    callbacks,
    consumedFingerprint,
    callbackFingerprint,
  );
}

async function writeCallbackReservation(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  callbacks: readonly StoredConsumedOAuthCallback[],
  consumedFingerprint: string,
  callbackFingerprint: string,
): Promise<ReservedCallback> {
  const ledgerWritten = await writeCallbackLedger(context, attempt, callbacks, consumedFingerprint);
  if (!ledgerWritten.ok) return ledgerWritten;
  try {
    await writeAttempt(context.storage, context.attemptStorageKey, {
      ...attempt,
      status: 'completing',
      callbackFingerprint,
    });
    return { ok: true, callbackFingerprint };
  } catch {
    await clearOAuthAttempt(context);
    return reservationFailure(attempt, 'Unable to reserve the OAuth callback.');
  }
}

async function writeCallbackLedger(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  callbacks: readonly StoredConsumedOAuthCallback[],
  fingerprint: string,
): Promise<{ ok: true } | { ok: false; result: AuthOAuthCompletionResult }> {
  try {
    await writeConsumedCallbacks(context.storage, context.consumedCallbacksStorageKey, [
      ...callbacks,
      { fingerprint, expiresAt: context.now() + CONSUMED_CALLBACK_RETENTION_MS },
    ]);
    return { ok: true };
  } catch {
    return failOAuthAttempt(
      context,
      attempt,
      reservationFailure(attempt, 'Unable to reserve the OAuth callback.').result,
    );
  }
}

function reservationFailure(
  attempt: StoredOAuthAttempt,
  message: string,
): { ok: false; result: AuthOAuthCompletionResult } {
  return {
    ok: false,
    result: oauthCompletionError(
      'session_persistence_failed',
      'callback',
      message,
      attempt.provider,
      true,
    ),
  };
}

function completionFailure(
  code: 'authorization_attempt_not_found' | 'session_persistence_failed',
  message: string,
  attempt?: StoredOAuthAttempt,
): LoadedAttempt {
  return {
    ok: false,
    result: oauthCompletionError(code, 'callback', message, attempt?.provider, true),
  };
}
