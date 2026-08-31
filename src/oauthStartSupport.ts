import type { AuthOAuthProviderId, AuthOAuthStartResult } from '@ankhorage/contracts/auth';
import { sha256 } from '@noble/hashes/sha2.js';
import { isBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { oauthStartError } from './oauthErrors.js';
import {
  isSupabaseOAuthProviderId,
  type SupabaseOAuthProviderId,
} from './oauthProviderDefinitions.js';
import type { SupabaseAuthFetch, SupabaseAuthRandomBytes } from './types.js';

const PKCE_RANDOM_BYTE_COUNT = 32;
const BASE64_URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const FORBIDDEN_QUERY_PARAMS = new Set([
  'code_challenge',
  'code_challenge_method',
  'provider',
  'redirect_to',
  'scopes',
  'skip_http_redirect',
]);
const DANGEROUS_PROTOCOLS = new Set(['data:', 'file:', 'javascript:']);

/*** Resolves an OAuth provider against the adapter's enabled provider set. */
export function resolveEnabledProvider(
  requestedProvider: AuthOAuthProviderId,
  providers: ReadonlySet<SupabaseOAuthProviderId>,
): { ok: true; provider: SupabaseOAuthProviderId } | { ok: false; result: AuthOAuthStartResult } {
  const provider = requestedProvider.trim();
  if (!isSupabaseOAuthProviderId(provider) || !providers.has(provider)) {
    return {
      ok: false,
      result: oauthStartError(
        'provider_disabled',
        `OAuth provider "${provider}" is not enabled for this adapter.`,
        requestedProvider,
        true,
      ),
    };
  }
  return { ok: true, provider };
}

/*** Normalizes and validates a canonical OAuth callback URI. */
export function normalizeRedirectUri(
  rawRedirectUri: string,
  provider: SupabaseOAuthProviderId,
): { ok: true; value: string } | { ok: false; result: AuthOAuthStartResult } {
  const url = parseAbsoluteUrl(rawRedirectUri.trim());
  if (url === null) {
    return invalidRedirect(
      provider,
      'OAuth redirect URI must be an absolute URL or application deep link.',
    );
  }
  if (!isPermittedRedirect(url)) {
    return invalidRedirect(
      provider,
      'OAuth redirect URI is not a permitted canonical callback URL.',
    );
  }
  return { ok: true, value: url.toString() };
}

/*** Normalizes provider query parameters while rejecting reserved OAuth fields. */
export function normalizeQueryParams(
  queryParams: Readonly<Record<string, string>> | undefined,
  provider: SupabaseOAuthProviderId,
): { ok: true; value: Record<string, string> } | { ok: false; result: AuthOAuthStartResult } {
  const entries = Object.entries(queryParams ?? {}).map(
    ([key, value]) => [key.trim(), value.trim()] as const,
  );
  const invalid = entries.find(([key]) => key.length === 0 || FORBIDDEN_QUERY_PARAMS.has(key));
  if (invalid !== undefined) {
    return {
      ok: false,
      result: oauthStartError(
        'provider_misconfigured',
        `OAuth query parameter "${invalid[0]}" is reserved or invalid.`,
        provider,
        true,
      ),
    };
  }
  return { ok: true, value: Object.fromEntries(entries) };
}

/*** Returns unique non-empty OAuth scopes in request order. */
export function normalizeScopes(
  scopes: readonly string[] | undefined,
  defaults: readonly string[],
): string[] {
  const requested = scopes === undefined || scopes.length === 0 ? defaults : scopes;
  return [...new Set(requested.map((scope) => scope.trim()).filter(Boolean))];
}

/*** Creates a PKCE verifier and its S256 challenge from an injected secure byte source. */
export function createPkcePair(generateRandomBytes: SupabaseAuthRandomBytes): {
  challenge: string;
  verifier: string;
} {
  const randomValue = generateRandomBytes(PKCE_RANDOM_BYTE_COUNT);
  if (!isBytes(randomValue) || randomValue.length !== PKCE_RANDOM_BYTE_COUNT) {
    throw new TypeError('OAuth random byte source returned an invalid value.');
  }
  const verifier = bytesToBase64Url(randomValue);
  return { challenge: bytesToBase64Url(sha256(utf8ToBytes(verifier))), verifier };
}

/*** Creates the public Supabase PKCE authorization URL. */
export function createAuthorizationUrl(input: {
  baseUrl: string;
  challenge: string;
  provider: SupabaseOAuthProviderId;
  queryParams: Readonly<Record<string, string>>;
  redirectUri: string;
  scopes: readonly string[];
}): string {
  const url = new URL(`${input.baseUrl.replace(/\/+$/u, '')}/auth/v1/authorize`);
  const parameters = [
    ['provider', input.provider],
    ['redirect_to', input.redirectUri],
    ['code_challenge', input.challenge],
    ['code_challenge_method', 's256'],
    ...Object.entries(input.queryParams),
  ] as const;
  if (input.scopes.length > 0) url.searchParams.set('scopes', input.scopes.join(' '));
  for (const [key, value] of parameters) url.searchParams.set(key, value);
  return url.toString();
}

/*** Exchanges a Supabase PKCE authorization code through the public HTTP contract. */
export function exchangeAuthorizationCode(input: {
  anonKey: string;
  baseUrl: string;
  code: string;
  fetch: SupabaseAuthFetch;
  verifier: string;
}): Promise<Response> {
  return input.fetch(`${input.baseUrl.replace(/\/+$/u, '')}/auth/v1/token?grant_type=pkce`, {
    method: 'POST',
    headers: {
      apikey: input.anonKey,
      Authorization: `Bearer ${input.anonKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ auth_code: input.code, code_verifier: input.verifier }),
  });
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let encoded = '';
  for (let index = 0; index < bytes.length; index += 3)
    encoded += encodeBase64Triplet(bytes, index);
  return encoded;
}

function encodeBase64Triplet(bytes: Uint8Array, index: number): string {
  const first = bytes.at(index) ?? 0;
  const second = bytes.at(index + 1);
  const third = bytes.at(index + 2);
  const encoded = [
    BASE64_URL_ALPHABET.at(first >> 2) ?? '',
    BASE64_URL_ALPHABET.at(((first & 0b11) << 4) | ((second ?? 0) >> 4)) ?? '',
    second === undefined
      ? ''
      : (BASE64_URL_ALPHABET.at(((second & 0b1111) << 2) | ((third ?? 0) >> 6)) ?? ''),
    third === undefined ? '' : (BASE64_URL_ALPHABET.at(third & 0b11_1111) ?? ''),
  ];
  return encoded.join('');
}

function parseAbsoluteUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isPermittedRedirect(url: URL): boolean {
  return (
    !DANGEROUS_PROTOCOLS.has(url.protocol) &&
    url.username.length === 0 &&
    url.password.length === 0 &&
    url.search.length === 0 &&
    url.hash.length === 0 &&
    (url.protocol !== 'http:' || isLocalhost(url.hostname))
  );
}

function invalidRedirect(provider: SupabaseOAuthProviderId, message: string) {
  return {
    ok: false as const,
    result: oauthStartError('invalid_redirect_uri', message, provider, true),
  };
}

function isLocalhost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}
