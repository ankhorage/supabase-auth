import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

import { isSupabaseOAuthProviderId } from './oauthProviderDefinitions.js';
import {
  ATTEMPT_VERSION,
  CONSUMED_CALLBACKS_VERSION,
  DEFAULT_ATTEMPT_LIFETIME_MS,
  MAX_CONSUMED_CALLBACKS,
  type StoredConsumedOAuthCallback,
  type StoredConsumedOAuthCallbacks,
  type StoredOAuthAttempt,
  type StoredOAuthAttemptReadResult,
} from './oauthTypes.js';
import type { SupabaseAuthStorage } from './types.js';

/*** Reads and validates the persisted OAuth authorization attempt. */
export async function readAttempt(
  storage: SupabaseAuthStorage,
  key: string,
): Promise<StoredOAuthAttemptReadResult> {
  const stored = await storage.getItem(key);
  if (stored === null) return { type: 'missing' };
  try {
    const parsed: unknown = JSON.parse(stored);
    return isStoredAttempt(parsed) ? { type: 'valid', attempt: parsed } : { type: 'invalid' };
  } catch {
    return { type: 'invalid' };
  }
}

/*** Persists the current OAuth authorization attempt. */
export async function writeAttempt(
  storage: SupabaseAuthStorage,
  key: string,
  attempt: StoredOAuthAttempt,
): Promise<void> {
  await storage.setItem(key, JSON.stringify(attempt));
}

/*** Finalizes an OAuth attempt and removes its one-use PKCE verifier. */
export async function finalizeAttempt(
  storage: SupabaseAuthStorage,
  attemptKey: string,
  verifierKey: string,
  attempt: StoredOAuthAttempt,
  callbackFingerprint?: string,
): Promise<void> {
  try {
    await writeAttempt(storage, attemptKey, {
      ...attempt,
      status: 'completed',
      ...(callbackFingerprint === undefined ? {} : { callbackFingerprint }),
    });
  } catch {
    await safeRemove(storage, attemptKey);
  }
  await safeRemove(storage, verifierKey);
}

/*** Removes all persisted state for the active OAuth attempt. */
export async function clearOAuthAttemptState(
  storage: SupabaseAuthStorage,
  attemptKey: string,
  verifierKey: string,
): Promise<void> {
  await safeRemove(storage, attemptKey);
  await safeRemove(storage, verifierKey);
}

/*** Reports whether an OAuth attempt has reached its expiry time. */
export function isAttemptExpired(attempt: StoredOAuthAttempt, now: number): boolean {
  return attempt.expiresAt <= now;
}

/*** Fingerprints one callback for exact replay detection within its attempt. */
export function fingerprintOAuthCallback(attemptId: string, code: string): string {
  return digest(`${attemptId}\u0000${code}`);
}

/*** Fingerprints one callback across attempts sharing the same redirect URI. */
export function fingerprintConsumedOAuthCallback(redirectUri: string, code: string): string {
  return digest(`${redirectUri}\u0000${code}`);
}

/*** Reads valid, unexpired callback fingerprints from persistent storage. */
export async function readConsumedCallbacks(
  storage: SupabaseAuthStorage,
  key: string,
  currentTime: number,
): Promise<readonly StoredConsumedOAuthCallback[]> {
  const stored = await storage.getItem(key);
  if (stored === null) return [];
  const parsed: unknown = JSON.parse(stored);
  if (!isStoredConsumedOAuthCallbacks(parsed)) {
    throw new TypeError('Persisted consumed OAuth callback state is invalid.');
  }
  return parsed.callbacks.filter((entry) => entry.expiresAt > currentTime);
}

/*** Persists the bounded callback replay-protection ledger. */
export async function writeConsumedCallbacks(
  storage: SupabaseAuthStorage,
  key: string,
  callbacks: readonly StoredConsumedOAuthCallback[],
): Promise<void> {
  const state: StoredConsumedOAuthCallbacks = {
    version: CONSUMED_CALLBACKS_VERSION,
    callbacks: callbacks.slice(-MAX_CONSUMED_CALLBACKS),
  };
  await storage.setItem(key, JSON.stringify(state));
}

/*** Compares equal-length callback fingerprints without data-dependent early exit. */
export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

/*** Normalizes the configured OAuth attempt lifetime. */
export function normalizeAttemptLifetime(value: number | undefined): number {
  const lifetime = value ?? DEFAULT_ATTEMPT_LIFETIME_MS;
  if (!Number.isSafeInteger(lifetime) || lifetime <= 0) {
    throw new TypeError('OAuth authorization attempt lifetime must be a positive safe integer.');
  }
  return lifetime;
}

function isStoredAttempt(value: unknown): value is StoredOAuthAttempt {
  if (!isRecord(value)) return false;
  return (
    hasAttemptIdentity(value) && hasAttemptTimeline(value) && hasValidCallbackFingerprint(value)
  );
}

function hasAttemptIdentity(value: Record<string, unknown>): boolean {
  return (
    value.version === ATTEMPT_VERSION &&
    typeof value.id === 'string' &&
    isSupabaseOAuthProviderId(typeof value.provider === 'string' ? value.provider : '') &&
    typeof value.redirectUri === 'string' &&
    (value.status === 'pending' || value.status === 'completing' || value.status === 'completed')
  );
}

function hasAttemptTimeline(value: Record<string, unknown>): boolean {
  return (
    typeof value.createdAt === 'number' &&
    Number.isSafeInteger(value.createdAt) &&
    value.createdAt >= 0 &&
    typeof value.expiresAt === 'number' &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > value.createdAt
  );
}

function hasValidCallbackFingerprint(value: Record<string, unknown>): boolean {
  if (value.callbackFingerprint === undefined) return true;
  return (
    (value.status === 'completing' || value.status === 'completed') &&
    typeof value.callbackFingerprint === 'string' &&
    /^[0-9a-f]{64}$/u.test(value.callbackFingerprint)
  );
}

function isStoredConsumedOAuthCallbacks(value: unknown): value is StoredConsumedOAuthCallbacks {
  return (
    isRecord(value) &&
    value.version === CONSUMED_CALLBACKS_VERSION &&
    Array.isArray(value.callbacks) &&
    value.callbacks.length <= MAX_CONSUMED_CALLBACKS &&
    value.callbacks.every(isStoredConsumedOAuthCallback)
  );
}

function isStoredConsumedOAuthCallback(value: unknown): value is StoredConsumedOAuthCallback {
  return (
    isRecord(value) &&
    typeof value.fingerprint === 'string' &&
    /^[0-9a-f]{64}$/u.test(value.fingerprint) &&
    typeof value.expiresAt === 'number' &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > 0
  );
}

async function safeRemove(storage: SupabaseAuthStorage, key: string): Promise<void> {
  try {
    await storage.removeItem(key);
  } catch {
    // Cleanup failure is intentionally not exposed with storage contents or secret values.
  }
}

function digest(value: string): string {
  return bytesToHex(sha256(utf8ToBytes(value)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
