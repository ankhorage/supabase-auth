# Public API

## createSupabaseAuthAdapter

Kind: `function`
Module: `src/createSupabaseAuthAdapter.ts`
Source: `src/createSupabaseAuthAdapter.ts:42:1`

### Signatures

- `(config: SupabaseAuthConfig) => AuthAdapter`
  - config: `SupabaseAuthConfig`
  - returns: `AuthAdapter`

## createSupabaseOAuthProfileVerifier

Kind: `function`
Module: `src/profileVerification.ts`
Source: `src/profileVerification.ts:30:1`

### Signatures

- `(input: { url: string; anonKey: string; fetch: SupabaseAuthFetch; config: SupabaseAuthProfileVerificationConfig; }) => SupabaseOAuthProfileVerifier`
  - input: `{ url: string; anonKey: string; fetch: SupabaseAuthFetch; config: SupabaseAuthProfileVerificationConfig; }`
  - returns: `SupabaseOAuthProfileVerifier`

## getSupabaseOAuthProviderDefinition

Kind: `function`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:71:1`

### Signatures

- `(provider: AuthOAuthProviderId) => SupabaseOAuthProviderDefinition | null`
  - provider: `AuthOAuthProviderId`
  - returns: `SupabaseOAuthProviderDefinition | null`

## isSupabaseOAuthProviderId

Kind: `function`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:65:1`

### Signatures

- `(provider: AuthOAuthProviderId) => boolean`
  - provider: `AuthOAuthProviderId`
  - returns: `boolean`

## materializeSupabaseOAuthEnvironment

Kind: `function`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:122:1`

### Signatures

- `(input: { provider: AuthOAuthProviderId; payload: SecretPayload; redirectUri: string; }) => SecretStoreResult<Readonly<Record<string, string>>>`
  - input: `{ provider: AuthOAuthProviderId; payload: SecretPayload; redirectUri: string; }`
  - returns: `SecretStoreResult<Readonly<Record<string, string>>>`

## normalizeSupabaseAuthProfileVerificationConfig

Kind: `function`
Module: `src/profileVerification.ts`
Source: `src/profileVerification.ts:132:1`

### Signatures

- `(config: SupabaseAuthProfileVerificationConfig) => NormalizedSupabaseAuthProfileVerificationConfig`
  - config: `SupabaseAuthProfileVerificationConfig`
  - returns: `NormalizedSupabaseAuthProfileVerificationConfig`

## SUPABASE_AUTH_PROFILE_FIELDS

Kind: `value`
Module: `src/types.ts`
Source: `src/types.ts:16:14`

## SUPABASE_OAUTH_PROVIDER_DEFINITIONS

Kind: `value`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:38:14`

## SUPABASE_OAUTH_PROVIDER_IDS

Kind: `value`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:4:14`

## SupabaseAuthConfig

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:71:1`

### Members

| Name                  | Kind     | Type                                                 | Required | Description |
| --------------------- | -------- | ---------------------------------------------------- | -------- | ----------- |
| anonKey               | property | `string`                                             | yes      |             |
| fetch                 | property | `typeof fetch \| undefined`                          | no       |             |
| oauthProviders        | property | `readonly AuthOAuthProviderId[] \| undefined`        | no       |             |
| onOAuthLifecycleEvent | property | `SupabaseOAuthLifecycleObserver \| undefined`        | no       |             |
| profileVerification   | property | `SupabaseAuthProfileVerificationConfig \| undefined` | no       |             |
| storage               | property | `SupabaseAuthStorage \| undefined`                   | no       |             |
| storageKey            | property | `string \| undefined`                                | no       |             |
| url                   | property | `string`                                             | yes      |             |

## SupabaseAuthErrorCode

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:82:1`

## SupabaseAuthProfileField

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:23:1`

## SupabaseAuthProfileVerificationConfig

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:25:1`

### Members

| Name         | Kind     | Type                                                                                         | Required | Description |
| ------------ | -------- | -------------------------------------------------------------------------------------------- | -------- | ----------- |
| fields       | property | `readonly ("email" \| "displayName" \| "avatarUrl" \| "username" \| "phone")[] \| undefined` | no       |             |
| maxAttempts  | property | `number \| undefined`                                                                        | no       |             |
| retryDelayMs | property | `number \| undefined`                                                                        | no       |             |
| table        | property | `string`                                                                                     | yes      |             |

## SupabaseAuthStorage

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:10:1`

### Members

| Name       | Kind   | Type                                                         | Required | Description |
| ---------- | ------ | ------------------------------------------------------------ | -------- | ----------- |
| getItem    | method | `(key: string) => string \| Promise<string \| null> \| null` | yes      |             |
| removeItem | method | `(key: string) => void \| Promise<void>`                     | yes      |             |
| setItem    | method | `(key: string, value: string) => void \| Promise<void>`      | yes      |             |

## SupabaseOAuthLifecycleEvent

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:55:1`

### Members

| Name          | Kind     | Type                                                                                                                                                                                                                                                                                                                                                                                                      | Required | Description |
| ------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------- |
| correlationId | property | `string`                                                                                                                                                                                                                                                                                                                                                                                                  | yes      |             |
| errorCode     | property | `"oauth_unavailable" \| "provider_disabled" \| "provider_misconfigured" \| "invalid_redirect_uri" \| "authorization_failed" \| "authorization_attempt_not_found" \| "invalid_callback" \| "state_mismatch" \| "pkce_mismatch" \| "callback_already_completed" \| "code_exchange_failed" \| "network_error" \| "session_persistence_failed" \| "profile_creation_failed" \| "provider_error" \| undefined` | no       |             |
| provider      | property | `AuthOAuthProviderId`                                                                                                                                                                                                                                                                                                                                                                                     | yes      |             |
| stage         | property | `"start" \| "transport" \| "callback" \| "exchange" \| "session" \| "profile"`                                                                                                                                                                                                                                                                                                                            | yes      |             |
| status        | property | `SupabaseOAuthLifecycleStatus`                                                                                                                                                                                                                                                                                                                                                                            | yes      |             |

## SupabaseOAuthLifecycleObserver

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:67:1`

## SupabaseOAuthLifecycleStatus

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:48:1`

## SupabaseOAuthProfileVerificationInput

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:36:1`

### Members

| Name          | Kind     | Type                  | Required | Description |
| ------------- | -------- | --------------------- | -------- | ----------- |
| correlationId | property | `string`              | yes      |             |
| provider      | property | `AuthOAuthProviderId` | yes      |             |
| session       | property | `AuthSession`         | yes      |             |

## SupabaseOAuthProfileVerificationResult

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:42:1`

## SupabaseOAuthProfileVerifier

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:44:1`

## SupabaseOAuthProviderDefinition

Kind: `type`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:25:1`

### Members

| Name               | Kind     | Type                                            | Required | Description |
| ------------------ | -------- | ----------------------------------------------- | -------- | ----------- |
| defaultScopes      | property | `readonly string[]`                             | yes      |             |
| id                 | property | `"google" \| "apple"`                           | yes      |             |
| label              | property | `string`                                        | yes      |             |
| runtimeEnvironment | property | `SupabaseOAuthRuntimeEnvironmentDefinition`     | yes      |             |
| secretFields       | property | `readonly SupabaseOAuthSecretFieldDefinition[]` | yes      |             |

## SupabaseOAuthProviderId

Kind: `unknown`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:5:1`

## SupabaseOAuthRuntimeEnvironmentDefinition

Kind: `type`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:18:1`

### Members

| Name         | Kind     | Type     | Required | Description |
| ------------ | -------- | -------- | -------- | ----------- |
| clientId     | property | `string` | yes      |             |
| clientSecret | property | `string` | yes      |             |
| enabled      | property | `string` | yes      |             |
| redirectUri  | property | `string` | yes      |             |

## SupabaseOAuthSecretFieldDefinition

Kind: `type`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:12:1`

### Members

| Name   | Kind     | Type                           | Required | Description |
| ------ | -------- | ------------------------------ | -------- | ----------- |
| label  | property | `string`                       | yes      |             |
| name   | property | `"clientId" \| "clientSecret"` | yes      |             |
| secret | property | `boolean`                      | yes      |             |

## SupabaseOAuthSecretPayload

Kind: `unknown`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:7:1`

## SupabaseProviderErrorCause

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:94:1`

### Members

| Name   | Kind     | Type                  | Required | Description |
| ------ | -------- | --------------------- | -------- | ----------- |
| body   | property | `unknown`             | no       |             |
| status | property | `number \| undefined` | no       |             |

## validateSupabaseOAuthSecretPayload

Kind: `function`
Module: `src/oauthProviderDefinitions.ts`
Source: `src/oauthProviderDefinitions.ts:77:1`

### Signatures

- `(provider: AuthOAuthProviderId, payload: Readonly<Record<string, string>>) => SecretStoreResult<SupabaseOAuthSecretPayload>`
  - payload: `Readonly<Record<string, string>>`
  - provider: `AuthOAuthProviderId`
  - returns: `SecretStoreResult<SupabaseOAuthSecretPayload>`

## verifySupabaseOAuthProfile

Kind: `function`
Module: `src/profileVerification.ts`
Source: `src/profileVerification.ts:49:1`

### Signatures

- `(input: { url: string; anonKey: string; fetch: SupabaseAuthFetch; config: SupabaseAuthProfileVerificationConfig; session: AuthSession; }) => Promise<SupabaseOAuthProfileVerificationResult>`
  - input: `{ url: string; anonKey: string; fetch: SupabaseAuthFetch; config: SupabaseAuthProfileVerificationConfig; session: AuthSession; }`
  - returns: `Promise<SupabaseOAuthProfileVerificationResult>`
