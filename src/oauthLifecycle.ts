import type { AuthOAuthCompletionResult } from '@ankhorage/contracts/auth';

import type { StoredOAuthAttempt } from './oauthTypes.js';
import type { SupabaseOAuthLifecycleEvent, SupabaseOAuthLifecycleObserver } from './types.js';

/*** Emits a redacted OAuth failure event for the supplied attempt. */
export async function emitOAuthError(
  observer: SupabaseOAuthLifecycleObserver | undefined,
  attempt: StoredOAuthAttempt,
  result: AuthOAuthCompletionResult,
): Promise<void> {
  if (result.ok || result.status !== 'error') return;
  await emitLifecycleEvent(observer, {
    correlationId: attempt.id,
    provider: attempt.provider,
    stage: result.error.stage,
    status: 'error',
    errorCode: result.error.code,
  });
}

/*** Notifies the optional lifecycle observer without changing authentication behavior. */
export async function emitLifecycleEvent(
  observer: SupabaseOAuthLifecycleObserver | undefined,
  event: SupabaseOAuthLifecycleEvent,
): Promise<void> {
  if (observer === undefined) return;
  try {
    await observer(event);
  } catch {
    // Observability must never change the authentication result.
  }
}
