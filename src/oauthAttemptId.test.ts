import { describe, expect, it } from 'bun:test';

import { createOAuthAttemptId } from './oauthAttemptId.js';

describe('OAuth attempt ids', () => {
  it('prefers crypto.randomUUID when available', () => {
    const id = createOAuthAttemptId({
      randomUuid: () => '00000000-0000-4000-8000-000000000001',
      fillRandomBytes: () => {
        throw new Error('random bytes should not be used');
      },
      now: () => 1,
      random: () => 0,
    });

    expect(id).toBe('00000000-0000-4000-8000-000000000001');
  });

  it('uses secure random bytes when randomUUID is unavailable', () => {
    const id = createOAuthAttemptId({
      fillRandomBytes(bytes) {
        for (let index = 0; index < bytes.length; index += 1) bytes[index] = index;
      },
      now: () => 1,
      random: () => 0,
    });

    expect(id).toBe('oauth-000102030405060708090a0b0c0d0e0f');
  });

  it('creates distinct correlation ids when crypto is unavailable', () => {
    let randomValue = 0;
    const runtime = {
      now: () => 123_456,
      random: () => {
        randomValue = (randomValue + 0.125) % 1;
        return randomValue;
      },
    };

    const first = createOAuthAttemptId(runtime);
    const second = createOAuthAttemptId(runtime);

    expect(first.startsWith('oauth-')).toBe(true);
    expect(second.startsWith('oauth-')).toBe(true);
    expect(second).not.toBe(first);
  });
});
