# Public API

## createSupabaseAuthAdapter

Kind: `function`
Module: `src/createSupabaseAuthAdapter.ts`
Source: `src/createSupabaseAuthAdapter.ts:25:1`

### Signatures

- `(config: SupabaseAuthConfig) => AuthAdapter`
  - config: `SupabaseAuthConfig`
  - returns: `AuthAdapter`

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
Source: `src/types.ts:11:1`

### Members

| Name           | Kind     | Type                                          | Required | Description |
| -------------- | -------- | --------------------------------------------- | -------- | ----------- |
| anonKey        | property | `string`                                      | yes      |             |
| fetch          | property | `typeof fetch \| undefined`                   | no       |             |
| oauthProviders | property | `readonly AuthOAuthProviderId[] \| undefined` | no       |             |
| storage        | property | `SupabaseAuthStorage \| undefined`            | no       |             |
| storageKey     | property | `string \| undefined`                         | no       |             |
| url            | property | `string`                                      | yes      |             |

## SupabaseAuthErrorCode

Kind: `unknown`
Module: `src/types.ts`
Source: `src/types.ts:20:1`

## SupabaseAuthStorage

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:5:1`

### Members

| Name       | Kind   | Type                                                         | Required | Description |
| ---------- | ------ | ------------------------------------------------------------ | -------- | ----------- |
| getItem    | method | `(key: string) => string \| Promise<string \| null> \| null` | yes      |             |
| removeItem | method | `(key: string) => void \| Promise<void>`                     | yes      |             |
| setItem    | method | `(key: string, value: string) => void \| Promise<void>`      | yes      |             |

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
Source: `src/types.ts:31:1`

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
