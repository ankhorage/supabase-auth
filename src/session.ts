import type { AuthSession, AuthUser } from '@ankhorage/contracts/auth';
import type { Session as SupabaseSession } from '@supabase/supabase-js';

export function normalizeSupabaseSession(body: unknown, now = Date.now()): AuthSession | null {
  if (!isRecord(body)) return null;
  const accessToken = stringValue(body.access_token);
  const user = normalizeSupabaseUser(body.user);
  if (accessToken === undefined || user === null) return null;
  const session: AuthSession = { accessToken, user };
  const refreshToken = stringValue(body.refresh_token);
  const tokenType = stringValue(body.token_type);
  const expiresAt = normalizeExpiresAt(body.expires_at, body.expires_in, now);
  if (refreshToken !== undefined) session.refreshToken = refreshToken;
  if (tokenType !== undefined) session.tokenType = tokenType;
  if (expiresAt !== undefined) session.expiresAt = expiresAt;
  return session;
}

export function normalizeSupabaseClientSession(session: SupabaseSession): AuthSession | null {
  return normalizeSupabaseSession({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    expires_in: session.expires_in,
    token_type: session.token_type,
    user: session.user,
  });
}

export function normalizeSupabaseUser(body: unknown): AuthUser | null {
  if (!isRecord(body)) return null;
  const id = stringValue(body.id);
  if (id === undefined) return null;

  const metadata = mergeMetadata(
    body.user_metadata,
    body.raw_user_meta_data,
    body.app_metadata,
    body.raw_app_meta_data,
  );
  const user: AuthUser = { id };
  const email = stringValue(body.email) ?? metadataString(metadata, ['email']);
  const phone = stringValue(body.phone) ?? metadataString(metadata, ['phone']);
  const username = metadataString(metadata, ['username', 'user_name', 'preferred_username']);
  const displayName = metadataString(metadata, [
    'displayName',
    'display_name',
    'full_name',
    'name',
  ]);
  const avatarUrl = metadataString(metadata, ['avatarUrl', 'avatar_url', 'picture']);

  if (email !== undefined) user.email = email;
  if (phone !== undefined) user.phone = phone;
  if (username !== undefined) user.username = username;
  if (displayName !== undefined) user.displayName = displayName;
  if (avatarUrl !== undefined) user.avatarUrl = avatarUrl;
  if (metadata !== undefined) user.metadata = metadata;
  return user;
}

export function parseStoredSession(value: string | null): AuthSession | null {
  if (value === null) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isAuthSession(parsed)) return null;
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

export function isAuthSessionExpired(
  session: AuthSession | null | undefined,
  now = Date.now(),
): boolean {
  const expiresAt = session?.expiresAt;
  return typeof expiresAt === 'number' && Number.isFinite(expiresAt) && expiresAt <= now;
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
  if (directExpiresAt !== undefined)
    return directExpiresAt < 10_000_000_000 ? directExpiresAt * 1000 : directExpiresAt;
  const ttl = numberValue(expiresIn);
  return ttl === undefined ? undefined : now + ttl * 1000;
}

function mergeMetadata(...values: unknown[]): Record<string, unknown> | undefined {
  const metadata: Record<string, unknown> = {};
  for (const value of values) if (isRecord(value)) Object.assign(metadata, value);
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

function metadataString(
  metadata: Record<string, unknown> | undefined,
  keys: readonly string[],
): string | undefined {
  if (metadata === undefined) return undefined;
  for (const key of keys) {
    const value = stringValue(metadata[key]);
    if (value !== undefined) return value;
  }
  return undefined;
}

function isAuthSession(value: unknown): value is AuthSession {
  if (!isRecord(value) || stringValue(value.accessToken) === undefined) return false;
  if (!isRecord(value.user) || stringValue(value.user.id) === undefined) return false;
  return (
    value.expiresAt === undefined ||
    (typeof value.expiresAt === 'number' && Number.isFinite(value.expiresAt))
  );
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
