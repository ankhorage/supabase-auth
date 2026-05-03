import type { AuthSession, AuthUser } from '@ankhorage/contracts/auth';

export interface SupabaseAuthUser {
  id?: unknown;
  email?: unknown;
  phone?: unknown;
  user_metadata?: unknown;
  app_metadata?: unknown;
  raw_user_meta_data?: unknown;
  raw_app_meta_data?: unknown;
}

export interface SupabaseAuthSessionResponse {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_at?: unknown;
  expires_in?: unknown;
  token_type?: unknown;
  user?: unknown;
}

export function normalizeSupabaseSession(body: unknown, now = Date.now()): AuthSession | null {
  if (!isRecord(body)) {
    return null;
  }

  const accessToken = stringValue(body.access_token);
  const user = normalizeSupabaseUser(body.user);

  if (accessToken === undefined || user === null) {
    return null;
  }

  const session: AuthSession = {
    accessToken,
    user,
  };
  const refreshToken = stringValue(body.refresh_token);
  const tokenType = stringValue(body.token_type);
  const expiresAt = normalizeExpiresAt(body.expires_at, body.expires_in, now);

  if (refreshToken !== undefined) {
    session.refreshToken = refreshToken;
  }

  if (tokenType !== undefined) {
    session.tokenType = tokenType;
  }

  if (expiresAt !== undefined) {
    session.expiresAt = expiresAt;
  }

  return session;
}

export function normalizeSupabaseUser(body: unknown): AuthUser | null {
  if (!isRecord(body)) {
    return null;
  }

  const id = stringValue(body.id);

  if (id === undefined) {
    return null;
  }

  const user: AuthUser = { id };
  const email = stringValue(body.email);
  const phone = stringValue(body.phone);
  const metadata = mergeMetadata(
    body.user_metadata,
    body.raw_user_meta_data,
    body.app_metadata,
    body.raw_app_meta_data,
  );

  if (email !== undefined) {
    user.email = email;
  }

  if (phone !== undefined) {
    user.phone = phone;
  }

  if (metadata !== undefined) {
    user.metadata = metadata;
  }

  return user;
}

export function parseStoredSession(value: string | null): AuthSession | null {
  if (value === null) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(value);

    if (!isAuthSession(parsed)) {
      return null;
    }

    return {
      ...parsed,
      ...(parsed.expiresAt !== undefined
        ? { expiresAt: normalizeStoredExpiresAt(parsed.expiresAt) }
        : {}),
    };
  } catch {
    return null;
  }
}

function normalizeStoredExpiresAt(value: number): number {
  return value < 10_000_000_000 ? value * 1000 : value;
}

function normalizeExpiresAt(
  expiresAt: unknown,
  expiresIn: unknown,
  now: number,
): number | undefined {
  const directExpiresAt = numberValue(expiresAt);

  if (directExpiresAt !== undefined) {
    return directExpiresAt < 10_000_000_000 ? directExpiresAt * 1000 : directExpiresAt;
  }

  const ttl = numberValue(expiresIn);

  if (ttl === undefined) {
    return undefined;
  }

  return now + ttl * 1000;
}

function mergeMetadata(...values: unknown[]): Record<string, unknown> | undefined {
  const metadata: Record<string, unknown> = {};

  for (const value of values) {
    if (isRecord(value)) {
      Object.assign(metadata, value);
    }
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

function isAuthSession(value: unknown): value is AuthSession {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.accessToken === 'string' &&
    isRecord(value.user) &&
    typeof value.user.id === 'string'
  );
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);

    return Number.isFinite(parsed) ? parsed : undefined;
  }

  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
