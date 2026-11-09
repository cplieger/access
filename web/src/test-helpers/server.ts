import { createFetch } from "@cplieger/reactive/fetch";
import { createAuthClient } from "../client.js";
import type { AuthClient } from "../client.js";

const PREFIX = "/api/auth";
const OIDC_PREFIX = "/api/auth/oidc";

export interface Answer {
  readonly status: number;
  readonly body?: unknown;
}

interface Sent {
  /** "POST /api/auth/login/passkey/begin": the method and the path with its query. */
  readonly route: string;
  readonly headers: Headers;
  readonly body: unknown;
}

export interface FakeServer {
  readonly client: AuthClient;
  /** Every request the client sent, in order, answered or not. */
  readonly sent: Sent[];
}

/** An error body as accesshttp writes it. */
export function refusal(status: number, code: string, reason?: string): Answer {
  return { status, body: { code, error: code, ...(reason === undefined ? {} : { reason }) } };
}

/**
 * A real client on a real FetchInstance whose network answers each "METHOD /path" key (query
 * excluded) from answers; a list answers its nth call with its nth entry, then its last. A
 * request with no answer rejects the fetch, so it surfaces as the client's network failure
 * and stays in sent for the test to see.
 */
export function fakeServer(
  answers: Readonly<Record<string, Answer | readonly Answer[]>>,
): FakeServer {
  const sent: Sent[] = [];
  const calls = new Map<string, number>();
  const fetchFn = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(href, "https://app.example");
    const method = init?.method ?? "GET";
    const raw = init?.body;
    sent.push({
      route: `${method} ${url.pathname}${url.search}`,
      headers: new Headers(init?.headers),
      body: typeof raw === "string" ? (JSON.parse(raw) as unknown) : raw,
    });
    const key = `${method} ${url.pathname}`;
    if (!Object.hasOwn(answers, key)) {
      return Promise.reject(new TypeError(`no answer for ${key}`));
    }
    const n = calls.get(key) ?? 0;
    calls.set(key, n + 1);
    const given = answers[key];
    const a = Array.isArray(given) ? (given[n] ?? given.at(-1)) : (given as Answer | undefined);
    if (a === undefined) {
      return Promise.reject(new TypeError(`no answer for ${key}`));
    }
    return Promise.resolve(
      a.body === undefined
        ? new Response(null, { status: a.status })
        : new Response(JSON.stringify(a.body), {
            status: a.status,
            headers: { "Content-Type": "application/json" },
          }),
    );
  };
  const client = createAuthClient({
    fetch: createFetch({ fetchFn }),
    prefix: PREFIX,
    oidcPrefix: OIDC_PREFIX,
  });
  return { client, sent };
}
