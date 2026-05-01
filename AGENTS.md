# Ankhorage Agent Guide

This repository is a strict TypeScript Bun package for a standalone Supabase auth adapter.

The package must remain usable outside Ankhorage-generated apps. It should implement shared auth contracts while staying independent from UI, routing, CLI, runtime, orchestrator, and generated app logic.

All coding agents must follow the rules below.

## Non-negotiables

- Do not introduce `any`, `as any`, `unknown as any`, or broad casts to silence errors.
- Do not add `@ts-ignore` / `@ts-expect-error` unless explicitly requested.
- Do not add `eslint-disable` or weaken lint rules/config to “make it pass”.
- Do not weaken tsconfig strictness or change module resolution settings.
- Do not perform large refactors unless explicitly requested.
- Do not add UI, routing, generated app, CLI, runtime, or orchestrator dependencies.
- Do not hardcode browser-only APIs such as `localStorage` without an injectable abstraction.
- Do not perform real network calls in tests.
- If you cannot proceed without violating rules: STOP and propose 2–3 options with tradeoffs.

## Required verification

Before concluding any task, run from repo root:

- `bun run build`
- `bun run lint:fix`
- `bun run test`

For release or packaging-related work, also run:

- `npm pack --dry-run`

If any command fails: STOP and report the failure + the minimal fix.

## Package responsibility

This package owns Supabase auth behavior:

- `signIn`
- `signUp`
- `signOut`
- `getSession`
- `refreshSession`
- `requestPasswordReset`
- `verifyOtp`
- Supabase auth error mapping
- Supabase session normalization
- provider-specific config validation

This package does not own:

- UI
- forms
- routing
- generated routes
- generated layouts
- app manifest interpretation
- session screens
- CLI file generation
- runtime orchestration
- deployment orchestration

## Dependency boundaries

Allowed dependency direction:

- The package may import shared types from `@ankhorage/contracts/auth`.
- The package may use platform-standard APIs such as `fetch` through config injection or safe defaults.

Forbidden dependencies:

- `@ankhorage/cli`
- `@ankhorage/runtime`
- `@ankhorage/zora`
- `@ankhorage/orchestrator`
- app manifests
- generated app code
- Expo Router
- React
- React Native

If a feature appears to require one of these dependencies, STOP and propose a boundary-safe alternative.

## Public API expectations

The package should expose a small public API centered around:

```ts
import { createSupabaseAuthAdapter } from '@ankhorage/supabase-auth';

const authAdapter = createSupabaseAuthAdapter({
  url: process.env.SUPABASE_URL,
  anonKey: process.env.SUPABASE_ANON_KEY,
});

## Public API expectations

The returned object must satisfy the shared `AuthAdapter` contract from `@ankhorage/contracts/auth`.

Public APIs should use consistent terminology:

- `signIn`
- `signUp`
- `signOut`
- `getSession`
- `refreshSession`
- `requestPasswordReset`
- `verifyOtp`

Do not introduce new public APIs named with alternative auth action terminology.

## Implementation rules

- Prefer small, focused modules.
- Keep Supabase response normalization isolated.
- Keep Supabase error normalization isolated.
- Return provider-neutral contract results.
- Do not expose raw Supabase response shapes as the primary API.
- Do not throw for expected provider/auth failures. Return normalized error results.
- Attach raw provider details only where the shared contract safely allows it, such as `cause`.
- Keep storage injectable.
- Keep fetch injectable for tests and non-standard runtimes.
- Do not introduce large dependencies unless explicitly approved.

## Testing rules

- Use mocked `fetch`.
- Do not call real Supabase services in tests.
- Test provider response normalization.
- Test error normalization.
- Test missing config validation.
- Test missing identifier/password/refresh-token cases.
- Test storage read/write/remove behavior if storage support exists.
- Tests must be deterministic and runnable offline.

## Repo boundaries

- Build outputs must go to `dist/`.
- Never write build artifacts into `src/`.
- Keep source files under `src/`.
- Keep tests close to the code they verify unless the repository already has another convention.
- Keep README examples standalone and provider-focused.
- Do not describe this package as generated-app, CLI, runtime, or UI-specific.

## Mandatory workflow

1. Plan first: list the exact files you will touch and why.
2. Keep changes micro-scoped: small PR-sized steps, one concern at a time.
3. Do not edit files during planning.
4. Apply changes only after the plan has been approved.
5. After edits: show `git diff --stat` and briefly explain changes.
6. Rollback rule: if a step goes sideways, revert to the last checkpoint instead of trial-and-error edits.
7. If a completed task changes the published package, create or update a `.changeset/*.md` file before committing that work.
8. Repo-doc/tooling-only changes do not need a changeset unless they affect package release behavior.
9. After verification, commit the completed unit of work unless the user explicitly says not to.

## Current initiative

We are creating `@ankhorage/supabase-auth` as a standalone MIT package.

The package should implement the released auth contracts from `@ankhorage/contracts/auth` and provide a clean Supabase auth adapter for use in any TypeScript app.

High-level goals:

- standalone package
- strict TypeScript
- provider-neutral contract results
- no UI or routing assumptions
- mocked tests only
- npm trusted-publishing-ready metadata
- small public API
- clean README and examples

## Tool-specific notes

### Codex

- Do not edit files during planning.
- Output a plan first.
- Wait for approval before applying changes.
- Add or update the relevant `.changeset/*.md` file before committing package changes.
- Commit completed, verified work unless the user explicitly asks you not to.

### Gemini CLI / gemini-kit

- Always run a plan step before execution.
- Execute work in micro-plans.
- Checkpoint with git before risky execution steps.
- Add or update the relevant `.changeset/*.md` file before committing package changes.
- Commit completed, verified work unless the user explicitly asks you not to.
```
