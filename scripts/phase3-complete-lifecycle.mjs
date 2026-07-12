import { readFile, writeFile } from 'node:fs/promises';

function replaceExactly(source, search, replacement, label) {
  const count = source.split(search).length - 1;
  if (count !== 1) {
    throw new Error(`${label}: expected one match, found ${count}`);
  }
  return source.replace(search, replacement);
}

const adapterPath = 'src/createSupabaseAuthAdapter.ts';
let adapter = await readFile(adapterPath, 'utf8');
adapter = replaceExactly(
  adapter,
  `  const persistSession = async (session: AuthSession | null): Promise<void> => {
    currentSession = session;
    sessionLoaded = true;
    if (normalizedConfig.storage === undefined) return;
    if (session === null) {
      await normalizedConfig.storage.removeItem(normalizedConfig.storageKey);
      return;
    }
    await normalizedConfig.storage.setItem(normalizedConfig.storageKey, JSON.stringify(session));
  };`,
  `  const persistSession = async (session: AuthSession | null): Promise<void> => {
    if (normalizedConfig.storage !== undefined) {
      if (session === null) {
        await normalizedConfig.storage.removeItem(normalizedConfig.storageKey);
      } else {
        await normalizedConfig.storage.setItem(normalizedConfig.storageKey, JSON.stringify(session));
      }
    }
    currentSession = session;
    sessionLoaded = true;
  };`,
  'persist session ordering',
);
await writeFile(adapterPath, adapter);

const oauthPath = 'src/oauth.ts';
let oauth = await readFile(oauthPath, 'utf8');
oauth = replaceExactly(
  oauth,
  `import type { SupabaseAuthFetch, SupabaseAuthStorage } from './types.js';`,
  `import type {
  SupabaseAuthFetch,
  SupabaseAuthStorage,
  SupabaseOAuthLifecycleEvent,
  SupabaseOAuthLifecycleObserver,
  SupabaseOAuthProfileVerifier,
} from './types.js';`,
  'OAuth type imports',
);
oauth = replaceExactly(
  oauth,
  `  providers: readonly SupabaseOAuthProviderId[];
  persistSession(session: AuthSession): Promise<void>;
}`,
  `  providers: readonly SupabaseOAuthProviderId[];
  persistSession(session: AuthSession): Promise<void>;
  verifyProfile?: SupabaseOAuthProfileVerifier;
  onLifecycleEvent?: SupabaseOAuthLifecycleObserver;
}`,
  'OAuth adapter input',
);
oauth = replaceExactly(
  oauth,
  `        try {
          await writeAttempt(input.storage, attemptStorageKey, attempt);
        } catch {
          await safeRemove(input.storage, codeVerifierStorageKey);
          return oauthStartError(
            'session_persistence_failed',
            'Unable to persist the OAuth authorization attempt.',
            provider.provider,
            true,
          );
        }

        return {`,
  `        try {
          await writeAttempt(input.storage, attemptStorageKey, attempt);
        } catch {
          await safeRemove(input.storage, codeVerifierStorageKey);
          return oauthStartError(
            'session_persistence_failed',
            'Unable to persist the OAuth authorization attempt.',
            provider.provider,
            true,
          );
        }

        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attemptId,
          provider: provider.provider,
          stage: 'start',
          status: 'started',
        });

        return {`,
  'OAuth started event',
);
oauth = replaceExactly(
  oauth,
  `      if (completionInput.response.type === 'cancelled') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        return {
          ok: false,
          status: 'cancelled',
          provider: attempt.provider,
          reason: completionInput.response.reason,
        };
      }`,
  `      if (completionInput.response.type === 'cancelled') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attempt.id,
          provider: attempt.provider,
          stage: 'transport',
          status: 'cancelled',
        });
        return {
          ok: false,
          status: 'cancelled',
          provider: attempt.provider,
          reason: completionInput.response.reason,
        };
      }`,
  'transport cancellation lifecycle',
);
oauth = replaceExactly(
  oauth,
  `      if (completionInput.response.type === 'error') {
        return oauthCompletionError(
          'authorization_failed',
          'transport',
          'The OAuth authorization transport failed.',
          attempt.provider,
          true,
        );
      }`,
  `      if (completionInput.response.type === 'error') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        const result = oauthCompletionError(
          'authorization_failed',
          'transport',
          'The OAuth authorization transport failed.',
          attempt.provider,
          true,
        );
        await emitOAuthError(input.onLifecycleEvent, attempt, result);
        return result;
      }`,
  'transport error cleanup',
);
oauth = replaceExactly(
  oauth,
  `      const callback = parseCallback(completionInput.response.url, attempt);
      if (callback.type === 'error') return callback.result;`,
  `      const callback = parseCallback(completionInput.response.url, attempt);
      if (callback.type === 'error') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        await emitOAuthError(input.onLifecycleEvent, attempt, callback.result);
        return callback.result;
      }`,
  'callback error cleanup',
);
oauth = replaceExactly(
  oauth,
  `      if (callback.type === 'cancelled') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        return {
          ok: false,
          status: 'cancelled',
          provider: attempt.provider,
          reason: 'provider_denied',
        };
      }`,
  `      if (callback.type === 'cancelled') {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attempt.id,
          provider: attempt.provider,
          stage: 'callback',
          status: 'cancelled',
        });
        return {
          ok: false,
          status: 'cancelled',
          provider: attempt.provider,
          reason: 'provider_denied',
        };
      }`,
  'provider cancellation lifecycle',
);
oauth = replaceExactly(
  oauth,
  `      } catch {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        return oauthCompletionError(
          'network_error',
          'exchange',
          'Unable to reach Supabase Auth while exchanging the OAuth code.',
          attempt.provider,
          true,
        );
      }`,
  `      } catch {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        const result = oauthCompletionError(
          'network_error',
          'exchange',
          'Unable to reach Supabase Auth while exchanging the OAuth code.',
          attempt.provider,
          true,
        );
        await emitOAuthError(input.onLifecycleEvent, attempt, result);
        return result;
      }`,
  'exchange network cleanup',
);
oauth = replaceExactly(
  oauth,
  `      if (exchange.error !== null) {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        return {
          ok: false,
          status: 'error',
          error: mapSupabaseOAuthError(exchange.error, 'exchange', attempt.provider),
        };
      }`,
  `      if (exchange.error !== null) {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        const result: AuthOAuthCompletionResult = {
          ok: false,
          status: 'error',
          error: mapSupabaseOAuthError(exchange.error, 'exchange', attempt.provider),
        };
        await emitOAuthError(input.onLifecycleEvent, attempt, result);
        return result;
      }`,
  'exchange provider cleanup',
);
oauth = replaceExactly(
  oauth,
  `      if (session === null) {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        return oauthCompletionError(
          'provider_error',
          'session',
          'Supabase Auth returned an invalid OAuth session.',
          attempt.provider,
          false,
        );
      }`,
  `      if (session === null) {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        const result = oauthCompletionError(
          'provider_error',
          'session',
          'Supabase Auth returned an invalid OAuth session.',
          attempt.provider,
          false,
        );
        await emitOAuthError(input.onLifecycleEvent, attempt, result);
        return result;
      }`,
  'invalid session cleanup',
);
oauth = replaceExactly(
  oauth,
  `      } catch {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        return oauthCompletionError(
          'session_persistence_failed',
          'session',
          'The OAuth session could not be persisted.',
          attempt.provider,
          true,
        );
      }

      await completeAttempt(input.storage, attemptStorageKey, attempt);
      return {
        ok: true,
        status: 'authenticated',
        provider: attempt.provider,
        session,
      };`,
  `      } catch {
        await completeAttempt(input.storage, attemptStorageKey, attempt);
        await safeRemove(input.storage, codeVerifierStorageKey);
        const result = oauthCompletionError(
          'session_persistence_failed',
          'session',
          'The OAuth session could not be persisted.',
          attempt.provider,
          true,
        );
        await emitOAuthError(input.onLifecycleEvent, attempt, result);
        return result;
      }

      if (input.verifyProfile !== undefined) {
        let verification;
        try {
          verification = await input.verifyProfile({
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
          await completeAttempt(input.storage, attemptStorageKey, attempt);
          await safeRemove(input.storage, codeVerifierStorageKey);
          const result = oauthCompletionError(
            'profile_creation_failed',
            'profile',
            verification.message,
            attempt.provider,
            true,
          );
          await emitOAuthError(input.onLifecycleEvent, attempt, result);
          return result;
        }

        await emitLifecycleEvent(input.onLifecycleEvent, {
          correlationId: attempt.id,
          provider: attempt.provider,
          stage: 'profile',
          status: 'profile_verified',
        });
      }

      await completeAttempt(input.storage, attemptStorageKey, attempt);
      await safeRemove(input.storage, codeVerifierStorageKey);
      await emitLifecycleEvent(input.onLifecycleEvent, {
        correlationId: attempt.id,
        provider: attempt.provider,
        stage: 'session',
        status: 'authenticated',
      });
      return {
        ok: true,
        status: 'authenticated',
        provider: attempt.provider,
        session,
      };`,
  'profile verification and authenticated lifecycle',
);
oauth = replaceExactly(
  oauth,
  `function createPkceOnlyStorage(`,
  `async function emitOAuthError(
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

async function emitLifecycleEvent(
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

function createPkceOnlyStorage(`,
  'lifecycle helpers',
);
await writeFile(oauthPath, oauth);
