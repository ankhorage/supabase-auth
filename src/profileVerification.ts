import type { AuthSession } from '@ankhorage/contracts/auth';

import type {
  SupabaseAuthFetch,
  SupabaseAuthProfileField,
  SupabaseAuthProfileVerificationConfig,
  SupabaseOAuthProfileVerificationResult,
  SupabaseOAuthProfileVerifier,
} from './types.js';
import { SUPABASE_AUTH_PROFILE_FIELDS } from './types.js';

const DEFAULT_PROFILE_FIELDS = ['email', 'displayName', 'avatarUrl'] as const;
const DEFAULT_MAX_ATTEMPTS = 4;
const DEFAULT_RETRY_DELAY_MS = 75;
const PROFILE_COLUMN_BY_FIELD = {
  email: 'email',
  displayName: 'display_name',
  avatarUrl: 'avatar_url',
  username: 'username',
  phone: 'phone',
} as const satisfies Record<SupabaseAuthProfileField, string>;

interface NormalizedSupabaseAuthProfileVerificationConfig {
  table: string;
  fields: SupabaseAuthProfileField[];
  maxAttempts: number;
  retryDelayMs: number;
}

export function createSupabaseOAuthProfileVerifier(input: {
  url: string;
  anonKey: string;
  fetch: SupabaseAuthFetch;
  config: SupabaseAuthProfileVerificationConfig;
}): SupabaseOAuthProfileVerifier {
  const config = normalizeSupabaseAuthProfileVerificationConfig(input.config);
  const url = input.url.replace(/\/+$/, '');

  return async ({ session }) =>
    verifySupabaseOAuthProfile({
      url,
      anonKey: input.anonKey,
      fetch: input.fetch,
      config,
      session,
    });
}

export async function verifySupabaseOAuthProfile(input: {
  url: string;
  anonKey: string;
  fetch: SupabaseAuthFetch;
  config: SupabaseAuthProfileVerificationConfig;
  session: AuthSession;
}): Promise<SupabaseOAuthProfileVerificationResult> {
  const config = normalizeSupabaseAuthProfileVerificationConfig(input.config);
  const endpoint = createProfileEndpoint(input.url, config, input.session.user.id);

  for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
    let response: Response;
    try {
      response = await input.fetch(endpoint, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          apikey: input.anonKey,
          Authorization: `Bearer ${input.session.accessToken}`,
        },
      });
    } catch {
      if (attempt < config.maxAttempts) {
        await delay(config.retryDelayMs);
        continue;
      }
      return {
        ok: false,
        message: 'Unable to reach the generated Supabase profile endpoint.',
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        message: `Supabase profile verification failed with HTTP ${response.status}.`,
      };
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return {
        ok: false,
        message: 'Supabase profile verification returned invalid JSON.',
      };
    }

    if (!Array.isArray(body)) {
      return {
        ok: false,
        message: 'Supabase profile verification returned an invalid row collection.',
      };
    }

    if (body.length === 0) {
      if (attempt < config.maxAttempts) {
        await delay(config.retryDelayMs);
        continue;
      }
      return {
        ok: false,
        message: 'The auth identity exists but its generated public profile row was not found.',
      };
    }

    if (body.length !== 1) {
      return {
        ok: false,
        message: 'The generated public profile lookup returned more than one row.',
      };
    }

    return validateProfileRow(body[0], input.session, config.fields);
  }

  return {
    ok: false,
    message: 'The generated public profile row could not be verified.',
  };
}

export function normalizeSupabaseAuthProfileVerificationConfig(
  config: SupabaseAuthProfileVerificationConfig,
): NormalizedSupabaseAuthProfileVerificationConfig {
  const table = config.table.trim();
  if (table === 'users') {
    throw new TypeError(
      'Supabase profile verification must target an app-owned table such as "profiles", not public.users.',
    );
  }
  if (!/^[a-z_][a-z0-9_]*$/u.test(table)) {
    throw new TypeError(
      'Supabase profile verification table must use snake_case letters, numbers, and underscores.',
    );
  }

  const fields = uniqueProfileFields(config.fields ?? DEFAULT_PROFILE_FIELDS);
  const maxAttempts = normalizeIntegerOption(
    config.maxAttempts,
    DEFAULT_MAX_ATTEMPTS,
    1,
    20,
    'maxAttempts',
  );
  const retryDelayMs = normalizeIntegerOption(
    config.retryDelayMs,
    DEFAULT_RETRY_DELAY_MS,
    0,
    5_000,
    'retryDelayMs',
  );

  return { table, fields, maxAttempts, retryDelayMs };
}

function createProfileEndpoint(
  baseUrl: string,
  config: NormalizedSupabaseAuthProfileVerificationConfig,
  userId: string,
): string {
  const url = new URL(`${baseUrl.replace(/\/+$/, '')}/rest/v1/${config.table}`);
  const columns = ['id', ...config.fields.map((field) => PROFILE_COLUMN_BY_FIELD[field])];
  url.searchParams.set('id', `eq.${userId}`);
  url.searchParams.set('select', [...new Set(columns)].join(','));
  url.searchParams.set('limit', '2');
  return url.toString();
}

function validateProfileRow(
  value: unknown,
  session: AuthSession,
  fields: readonly SupabaseAuthProfileField[],
): SupabaseOAuthProfileVerificationResult {
  if (!isRecord(value) || value.id !== session.user.id) {
    return {
      ok: false,
      message: 'The generated public profile row does not match the authenticated identity.',
    };
  }

  for (const field of fields) {
    const expected = getExpectedProfileValue(session, field);
    if (expected === undefined) continue;
    if (value[PROFILE_COLUMN_BY_FIELD[field]] !== expected) {
      return {
        ok: false,
        message: `The generated public profile field "${field}" does not match provider metadata.`,
      };
    }
  }

  return { ok: true };
}

function getExpectedProfileValue(
  session: AuthSession,
  field: SupabaseAuthProfileField,
): string | undefined {
  switch (field) {
    case 'email':
      return session.user.email;
    case 'displayName':
      return session.user.displayName;
    case 'avatarUrl':
      return session.user.avatarUrl;
    case 'username':
      return session.user.username;
    case 'phone':
      return session.user.phone;
  }
}

function uniqueProfileFields(
  fields: readonly SupabaseAuthProfileField[],
): SupabaseAuthProfileField[] {
  const supported = new Set<string>(SUPABASE_AUTH_PROFILE_FIELDS);
  const normalized: SupabaseAuthProfileField[] = [];

  for (const field of fields) {
    if (!supported.has(field)) {
      throw new TypeError(`Unsupported Supabase profile verification field "${field}".`);
    }
    if (!normalized.includes(field)) normalized.push(field);
  }

  return normalized;
}

function normalizeIntegerOption(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new TypeError(
      `Supabase profile verification ${name} must be an integer between ${minimum} and ${maximum}.`,
    );
  }
  return resolved;
}

async function delay(milliseconds: number): Promise<void> {
  if (milliseconds === 0) return;
  await new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
