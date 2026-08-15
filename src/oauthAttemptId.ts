const SECURE_RANDOM_BYTE_COUNT = 16;
const FALLBACK_RANDOM_CHUNK_COUNT = 4;
const RANDOM_CHUNK_RANGE = 0x1_0000_0000;

let fallbackSequence = 0;

interface OAuthAttemptIdRuntime {
  readonly randomUuid?: () => string;
  readonly fillRandomBytes?: (bytes: Uint8Array) => void;
  readonly now: () => number;
  readonly random: () => number;
}

export function createOAuthAttemptId(
  runtime: OAuthAttemptIdRuntime = resolveOAuthAttemptIdRuntime(),
): string {
  if (runtime.randomUuid !== undefined) return runtime.randomUuid();

  if (runtime.fillRandomBytes !== undefined) {
    const bytes = new Uint8Array(SECURE_RANDOM_BYTE_COUNT);
    runtime.fillRandomBytes(bytes);
    const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `oauth-${value}`;
  }

  fallbackSequence = (fallbackSequence + 1) % Number.MAX_SAFE_INTEGER;
  const randomPart = Array.from({ length: FALLBACK_RANDOM_CHUNK_COUNT }, () =>
    createFallbackRandomChunk(runtime.random),
  ).join('');
  return `oauth-${runtime.now().toString(36)}-${fallbackSequence.toString(36)}-${randomPart}`;
}

function resolveOAuthAttemptIdRuntime(): OAuthAttemptIdRuntime {
  const crypto = globalThis.crypto;
  return {
    ...(typeof crypto?.randomUUID === 'function'
      ? { randomUuid: () => crypto.randomUUID() }
      : {}),
    ...(typeof crypto?.getRandomValues === 'function'
      ? { fillRandomBytes: (bytes: Uint8Array) => void crypto.getRandomValues(bytes) }
      : {}),
    now: Date.now,
    random: Math.random,
  };
}

function createFallbackRandomChunk(random: () => number): string {
  return Math.floor(random() * RANDOM_CHUNK_RANGE)
    .toString(36)
    .padStart(7, '0');
}
