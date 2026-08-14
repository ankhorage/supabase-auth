import type { AppDeployTargetId } from '@ankhorage/contracts/deploy';
import { describe, expect, it } from 'bun:test';

import {
  resolveSupabaseOAuthSetupPlan,
  SUPABASE_OAUTH_SETUP_CAPABILITIES,
} from './oauthSetupRequirements.js';

const TARGETS: readonly (readonly AppDeployTargetId[])[] = [
  ['web'],
  ['android'],
  ['ios'],
  ['web', 'android'],
  ['web', 'ios'],
  ['android', 'ios'],
  ['web', 'android', 'ios'],
];

describe('Supabase OAuth setup planning', () => {
  for (const environment of ['local', 'preview', 'production'] as const) {
    for (const targets of TARGETS) {
      it(`${environment} ${targets.join('+')}`, () => {
        const plan = resolveSupabaseOAuthSetupPlan({
          provider: 'google',
          transport: 'brokeredRedirect',
          environment,
          targets,
        });
        expect(plan).not.toBeNull();
        if (plan === null) return;

        const fields = plan.requirements.filter((item) => item.kind === 'field');
        const callbacks = plan.requirements.filter((item) => item.kind === 'callback');
        expect(fields).toHaveLength(2);
        expect(fields.every((field) => field.target === undefined)).toBe(true);
        expect(callbacks.filter((item) => item.role === 'provider')).toHaveLength(1);
        expect(callbacks.filter((item) => item.role === 'app').map((item) => item.target)).toEqual(
          targets,
        );
      });
    }
  }

  it('supports the current brokered providers only', () => {
    expect(SUPABASE_OAUTH_SETUP_CAPABILITIES).toEqual({
      providers: ['google', 'apple'],
      transports: ['brokeredRedirect'],
    });
    expect(
      resolveSupabaseOAuthSetupPlan({
        provider: 'custom-sso',
        transport: 'brokeredRedirect',
        environment: 'local',
        targets: ['web'],
      }),
    ).toBeNull();
    expect(
      resolveSupabaseOAuthSetupPlan({
        provider: 'google',
        transport: 'nativeIdToken',
        environment: 'local',
        targets: ['ios'],
      }),
    ).toBeNull();
  });

  it('deduplicates enabled targets without reordering them', () => {
    expect(
      resolveSupabaseOAuthSetupPlan({
        provider: 'apple',
        transport: 'brokeredRedirect',
        environment: 'preview',
        targets: ['ios', 'web', 'ios'],
      })?.targets,
    ).toEqual(['ios', 'web']);
  });
});
