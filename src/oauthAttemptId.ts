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
  const cryptoValue: unknown = Reflect.get(globalThis, 'crypto');
  if (typeof cryptoValue !== 'object' || cryptoValue === null) {
    return { now: Date.now, random: Math.random };
  }

  const randomUuidValue: unknown = Reflect.get(cryptoValue, 'randomUUID');
  const randomValuesValue: unknown = Reflect.get(cryptoValue, 'getRandomValues');
  const randomUuid =
    typeof randomUuidValue === 'function'
      ? () => {
          const value: unknown = Reflect.apply(randomUuidValue, cryptoValue, []);
          if (typeof value !== 'string') throw new TypeError('crypto.randomUUID() must return a string.');
          return value;
        }
      : undefined;
  const fillRandomBytes =
    typeof randomValuesValue === 'function'
      ? (bytes: Uint8Array) => {
          Reflect.apply(randomValuesValue, cryptoValue, [bytes]);
        }
      : undefined;

  return {
    ...(randomUuid === undefined ? {} : { randomUuid }),
    ...(fillRandomBytes === undefined ? {} : { fillRandomBytes }),
    now: Date.now,
    random: Math.random,
  };
}

function createFallbackRandomChunk(random: () => number): string {
  return Math.floor(random() * RANDOM_CHUNK_RANGE)
    .toString(36)
    .padStart(7, '0');
}
