# OAuth account lifecycle

This document defines the authoritative Phase 3 account and identity policy for
`@ankhorage/supabase-auth`.

## Identity ownership

Supabase Auth is the sole authority for OAuth identity ownership. The adapter accepts the user and
identity relationship returned by Supabase and does not implement a parallel account-merging layer.

For providers that return the same verified email, Supabase automatic identity linking may produce
one Supabase user with multiple identities. The adapter preserves the returned Supabase user ID and
normalizes provider metadata onto the shared `AuthUser`; it does not reassign an identity, rewrite
identity ownership, or move profile rows between users.

Apple private relay can provide an address that differs from the address returned by another provider.
Because automatic linking depends on the provider email matching an existing verified email, a relay
address can result in a separate Supabase user. The adapter must not guess that two different addresses
belong to the same person.

Manual identity linking is outside Phase 3. It requires an authenticated, explicit user action and a
separate product flow. It must never be performed implicitly during sign-in, callback completion,
profile verification, or session restoration.

Reference: [Supabase Identity Linking](https://supabase.com/docs/guides/auth/auth-identity-linking).

## OAuth completion invariant

A successful OAuth callback has the following ordered lifecycle:

1. Supabase exchanges the authorization code through the PKCE verifier.
2. The returned Supabase session is normalized and persisted.
3. When profile verification is configured, the adapter verifies exactly one app-owned profile row for
   the authenticated Supabase user ID.
4. The callback is marked completed and all PKCE verifier material is removed.
5. The caller receives the canonical authenticated result.

When the Supabase identity exists but the configured profile invariant fails, completion returns
`profile_creation_failed`. The identity and persisted session are not silently reassigned or replaced.
The caller may surface recovery guidance or retry profile verification after infrastructure recovery.

## Session lifecycle

- Stored sessions are parsed defensively. Invalid or expired stored sessions are removed before they
  are returned to the application.
- An invalid or expired refresh token clears the local session before returning `session_expired`.
- Sign-out always clears local session state, even when the remote Supabase logout request fails. The
  remote error is still returned so the caller can report degraded global sign-out.
- OAuth callback completion is exactly once. A completed, cancelled, or failed attempt cannot exchange
  the same authorization code again.

## Collision policy

The authoritative collision policy is:

- Same provider identity: use the Supabase user already owning that identity.
- Different provider with the same verified email: rely on Supabase automatic linking and accept the
  resulting one Supabase user with multiple identities.
- Different or private-relay email: accept the Supabase result as a distinct user unless a future,
  explicit manual-linking flow links it.
- Existing password and OAuth methods with the same verified email: rely on Supabase identity behavior;
  the adapter does not create a second account-matching database or custom reassignment rule.
- Ambiguous ownership: fail safely and require explicit account recovery. Never choose a target user by
  display name, unverified metadata, provider label, or profile similarity.

## Observability and privacy

OAuth lifecycle events may contain only:

- correlation ID;
- provider ID;
- lifecycle stage;
- status;
- typed error code when applicable.

They must never contain callback URLs, authorization codes, PKCE verifiers, access tokens, refresh
tokens, serialized sessions, provider credentials, private keys, service-role keys, or profile rows.
Observer failures must not change the authentication result.
