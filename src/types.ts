export interface SupabaseAuthStorage {
  getItem(key: string): string | Promise<string | null> | null;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export interface SupabaseAuthConfig {
  url: string;
  anonKey: string;
  fetch?: typeof fetch;
  storage?: SupabaseAuthStorage;
  storageKey?: string;
}

export type SupabaseAuthErrorCode =
  | 'invalid_credentials'
  | 'missing_identifier'
  | 'missing_password'
  | 'missing_refresh_token'
  | 'network_error'
  | 'provider_error'
  | 'session_expired'
  | 'unsupported_identifier'
  | 'validation_error';

export interface SupabaseProviderErrorCause {
  status?: number;
  body?: unknown;
}
