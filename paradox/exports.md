# Public API

## createSupabaseAuthAdapter

Kind: `function`
Module: `src/createSupabaseAuthAdapter.ts`
Source: `src/createSupabaseAuthAdapter.ts:21:1`

### Signatures

- `(config: SupabaseAuthConfig) => AuthAdapter`
  - config: `SupabaseAuthConfig`
  - returns: `AuthAdapter`

## SupabaseAuthConfig

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:11:1`

### Members

| Name           | Kind     | Type                                 | Required | Description |
| -------------- | -------- | ------------------------------------ | -------- | ----------- |
| anonKey        | property | `string`                             | yes      |             |
| fetch          | property | `SupabaseAuthFetch \| undefined`     | no       |             |
| oauthProviders | property | `AuthOAuthProviderId[] \| undefined` | no       |             |
| storage        | property | `SupabaseAuthStorage \| undefined`   | no       |             |
| storageKey     | property | `string \| undefined`                | no       |             |
| url            | property | `string`                             | yes      |             |

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

## SupabaseProviderErrorCause

Kind: `type`
Module: `src/types.ts`
Source: `src/types.ts:32:1`

### Members

| Name   | Kind     | Type                  | Required | Description |
| ------ | -------- | --------------------- | -------- | ----------- |
| body   | property | `unknown`             | no       |             |
| status | property | `number \| undefined` | no       |             |
