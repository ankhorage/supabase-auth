export interface FetchCall {
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

export function createFetch(responses: Response[], calls: FetchCall[] = []): typeof fetch {
  return Object.assign(
    (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      const headers = new Headers(init?.headers);
      calls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
        headers: Object.fromEntries(headers.entries()),
      });

      const response = responses.shift();

      if (response === undefined) {
        throw new Error('Unexpected fetch call.');
      }

      return Promise.resolve(response);
    },
    { preconnect: globalThis.fetch.preconnect },
  );
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...init.headers,
    },
  });
}

export function authSessionResponse(input: {
  accessToken: string;
  refreshToken: string;
  userId: string;
  email: string;
  expiresAt?: number;
}): Response {
  return jsonResponse({
    access_token: input.accessToken,
    refresh_token: input.refreshToken,
    ...(input.expiresAt === undefined
      ? { expires_in: 3600, token_type: 'bearer' }
      : { expires_at: input.expiresAt }),
    user: { id: input.userId, email: input.email },
  });
}

export function receiverSensitiveFetch(calls: FetchCall[], onCall: () => void): typeof fetch {
  return Object.assign(
    function (
      this: unknown,
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ) {
      if (this !== globalThis) throw new TypeError('incorrect fetch receiver');
      onCall();
      const headers = new Headers(init?.headers);
      calls.push({
        url: input instanceof Request ? input.url : input.toString(),
        body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body,
        headers: Object.fromEntries(headers.entries()),
      });
      return Promise.resolve(
        authSessionResponse({
          accessToken: 'receiver-access-token',
          refreshToken: 'receiver-refresh-token',
          userId: 'receiver-user',
          email: 'receiver@example.com',
        }),
      );
    },
    { preconnect: globalThis.fetch.preconnect },
  );
}

export function createMemoryStorage(
  initialValues: Record<string, string> = {},
): SupabaseAuthStorage {
  const values = new Map(Object.entries(initialValues));

  return {
    getItem(key) {
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      values.set(key, value);
    },
    removeItem(key) {
      values.delete(key);
    },
  };
}
import type { SupabaseAuthStorage } from './types.js';
