import type {
  AuthOAuthAdapter,
  AuthOAuthCompletionResult,
  CompleteOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import { completeSupabaseOAuthAuthorization } from './oauthComplete.js';
import { createOAuthRuntimeContext } from './oauthRuntime.js';
import { startSupabaseOAuthAuthorization } from './oauthStart.js';
import type { CreateSupabaseOAuthAdapterInput } from './oauthTypes.js';

/*** Creates the Supabase OAuth adapter around isolated start and completion operations. */
export function createSupabaseOAuthAdapter(
  input: CreateSupabaseOAuthAdapterInput,
): AuthOAuthAdapter {
  const context = createOAuthRuntimeContext(input);
  const completeAuthorization = createCompletionRunner(context);
  return {
    capabilities: { providers: context.providers },
    startAuthorization: (authorizationInput) =>
      startSupabaseOAuthAuthorization(context, authorizationInput),
    completeAuthorization,
  };
}

/*** Serializes completion attempts so the same callback cannot be consumed concurrently. */
function createCompletionRunner(
  context: ReturnType<typeof createOAuthRuntimeContext>,
): (input: CompleteOAuthAuthorizationInput) => Promise<AuthOAuthCompletionResult> {
  let activeCompletion: Promise<void> | null = null;
  return async (input) => {
    while (activeCompletion !== null) await activeCompletion;
    let releaseCompletion: (() => void) | undefined;
    const completionLock = new Promise<void>((resolve) => {
      releaseCompletion = resolve;
    });
    activeCompletion = completionLock;
    try {
      return await completeSupabaseOAuthAuthorization(context, input);
    } finally {
      if (activeCompletion === completionLock) activeCompletion = null;
      releaseCompletion?.();
    }
  };
}
