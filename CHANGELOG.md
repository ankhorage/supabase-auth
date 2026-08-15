# @ankhorage/supabase-auth

## 1.2.1

### Patch Changes

- 4585160: Allow brokered OAuth attempts to initialize in native runtimes where browser WebCrypto globals are unavailable.

## 1.2.0

### Minor Changes

- 7a2e61a: Add target- and environment-aware OAuth setup requirement planning for supported Supabase providers.

## 1.1.2

### Patch Changes

- f64d67b: Add bounded, self-healing OAuth attempt persistence with explicit creation and expiry timestamps, stale/corrupt state recovery, and deterministic terminal PKCE cleanup.

## 1.1.1

### Patch Changes

- 5d60f85: Restore the default Supabase Auth fetch boundary so generated apps use the active runtime
  global fetch implementation.

## 1.1.0

### Minor Changes

- 45e6069: Complete the OAuth account lifecycle with canonical Google and Apple metadata normalization, expired-session cleanup, local sign-out hardening, optional generated-profile verification, metadata-only lifecycle observation, complete PKCE cleanup, and the documented identity-collision policy.

## 1.0.0

### Major Changes

- 19649d8: Replace the manual URL-only OAuth adapter with the canonical Supabase client PKCE start and callback-completion runtime, including persistent authorization attempts, exactly-once code exchange, typed failures, and canonical session persistence.

## 0.4.0

### Minor Changes

- 2df2791: Add one canonical Google/Apple provider-definition registry with required secret fields, validation, and official GoTrue runtime environment materialization for Studio and Infra consumers.

## 0.3.0

### Minor Changes

- 33b1599: Add OAuth2 provider allow-list configuration and redirect sign-in support.

## 0.2.8

### Patch Changes

- 2e0a908: Update packages

## 0.2.7

### Patch Changes

- 94e7373: Update package

## 0.2.6

### Patch Changes

- 76bb461: Add the standard package tooling baseline script and workflow files.

## 0.2.5

### Patch Changes

- 17d1a6f: update @ankhorage/contracts

## 0.2.4

### Patch Changes

- c57fc06: fix test: normalize supabase session expiry
- 4ec9cc6: Normalize Supabase session expiration timestamps to JavaScript milliseconds.

## 0.2.3

### Patch Changes

- Bind the default fetch implementation safely for browser and Expo web runtimes.

## 0.2.2

### Patch Changes

- a7640ed: Pass Supabase Auth request URLs to fetch as strings and improve React Native fetch compatibility.

## 0.2.1

### Patch Changes

- ea7cc93: trigger release

## 0.2.0

### Minor Changes

- ad5867f: Add a standalone Supabase auth adapter implementing the shared auth contracts.

### Patch Changes

- adb2a44: fix package.json for npm & add changeset config
