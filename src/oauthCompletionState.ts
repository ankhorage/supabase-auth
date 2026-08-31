import type { AuthOAuthCompletionResult } from '@ankhorage/contracts/auth';

import { emitLifecycleEvent, emitOAuthError } from './oauthLifecycle.js';
import type { OAuthRuntimeContext } from './oauthRuntime.js';
import { clearOAuthAttemptState, finalizeAttempt } from './oauthStorage.js';
import type { StoredOAuthAttempt } from './oauthTypes.js';

/*** Finalizes a failed OAuth attempt, emits safe lifecycle metadata, and returns its result. */
export async function failOAuthAttempt(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  result: AuthOAuthCompletionResult,
): Promise<{ ok: false; result: AuthOAuthCompletionResult }> {
  await finalizeOAuthAttemptState(context, attempt);
  await emitOAuthError(context.onLifecycleEvent, attempt, result);
  return { ok: false, result };
}

/*** Marks an OAuth attempt completed and emits authentication success when applicable. */
export async function finalizeOAuthAttemptState(
  context: OAuthRuntimeContext,
  attempt: StoredOAuthAttempt,
  callbackFingerprint?: string,
): Promise<void> {
  await finalizeAttempt(
    context.storage,
    context.attemptStorageKey,
    context.codeVerifierStorageKey,
    attempt,
    callbackFingerprint,
  );
  if (callbackFingerprint === undefined) return;
  await emitLifecycleEvent(context.onLifecycleEvent, {
    correlationId: attempt.id,
    provider: attempt.provider,
    stage: 'session',
    status: 'authenticated',
  });
}

/*** Clears the active attempt and its PKCE verifier. */
export async function clearOAuthAttempt(context: OAuthRuntimeContext): Promise<void> {
  await clearOAuthAttemptState(
    context.storage,
    context.attemptStorageKey,
    context.codeVerifierStorageKey,
  );
}
