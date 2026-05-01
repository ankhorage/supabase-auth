# @ankhorage/supabase-auth

Supabase auth adapter implementing shared TypeScript auth contracts.

This package is standalone. It does not depend on generated apps, app
manifests, routing, React, React Native, Expo Router, ZORA, the Ankhorage CLI,
or runtime packages.

## Install

```bash
bun add @ankhorage/supabase-auth @ankhorage/contracts
```

```bash
npm install @ankhorage/supabase-auth @ankhorage/contracts
```

## Basic Usage

```ts
import { createSupabaseAuthAdapter } from '@ankhorage/supabase-auth';
import type { AuthAdapter } from '@ankhorage/contracts/auth';

const authAdapter: AuthAdapter = createSupabaseAuthAdapter({
  url: process.env.SUPABASE_URL ?? '',
  anonKey: process.env.SUPABASE_ANON_KEY ?? '',
});
```

## Config

```ts
interface SupabaseAuthConfig {
  url: string;
  anonKey: string;
  fetch?: typeof fetch;
  storage?: SupabaseAuthStorage;
  storageKey?: string;
}
```

The adapter uses Supabase Auth REST endpoints directly. It uses the global
`fetch` implementation by default, or a provided `fetch` override. It never
uses browser-only storage APIs directly. Pass a `storage` implementation when
you want sessions persisted outside the adapter instance.

## Sign In

```ts
const result = await authAdapter.signIn({
  identifier: { kind: 'email', value: 'user@example.com' },
  password: 'correct-horse-battery-staple',
});

if (result.ok) {
  console.log(result.data.accessToken);
} else {
  console.error(result.error.code);
}
```

## Sign Up

```ts
const result = await authAdapter.signUp({
  identifier: { kind: 'email', value: 'user@example.com' },
  password: 'correct-horse-battery-staple',
  profile: {
    displayName: 'User Example',
  },
});
```

## Sessions

```ts
const session = await authAdapter.getSession();

if (session.ok && session.data !== null) {
  console.log(session.data.user.id);
}
```

The returned adapter implements `AuthAdapter` from
`@ankhorage/contracts/auth`. Supabase provider responses and errors are
normalized into the shared contract shape.
