// The CR-04 proof: /authorize must say what it is authorizing, before the
// owner types anything into it.
//
// Every case here fails against the pre-fix handler, which is what makes them
// worth having. Pre-fix the page was a fixed title, a fixed sentence, and a
// password field: the client was looked up only *after* the secret had been
// accepted, and its name was used only as grant metadata. With open dynamic
// client registration at /oauth/register, an attacker registers a client with
// their own redirect URI and a familiar-looking name, sends the owner an
// /authorize link on the correct origin over TLS, and every signal the owner
// can see is legitimate. The authorization code is then delivered to the
// attacker and nothing in the flow is abnormal from the library's perspective.
//
// Two test shapes, deliberately:
//
//   Real registration. Cases that assert what the owner *sees* drive a real
//   OAuth provider through POST /oauth/register and then GET /authorize. The
//   client is a genuinely registered one, its name and redirect URI travel the
//   same path they do in production, and nothing about the identity on the page
//   is supplied by the test. This was tried first and works inside the workers
//   pool, so the stubbed-provider fallback the plan allowed was not needed for
//   these.
//
//   Since Phase 11 that entry is test/fixtures/worker-with-login-proof.ts
//   rather than src/index.ts. It composes the very same provider options and
//   substitutes exactly one thing, the login proof, because the positive
//   control below completes the whole ceremony and D-09 forbids any automated
//   login to a real Apple ID. Nothing in this file asserts anything about the
//   proof; every case here is about what the page NAMES.
//
//   Note on the redirect URIs below: they are not arbitrary. Since window 8 the
//   handler carries an origin allowlist, so every URI in this file has to sit on
//   an allowed origin or the case would be answered 403 before reaching the
//   behaviour it was written to prove. The allowlist itself is proved in
//   test/authorize-redirect-allowlist.test.ts, deliberately not here — this file
//   proves the consent screen NAMES the destination, which is a different claim
//   from refusing one.
//
//   Stubbed provider. Cases about *ordering* — that an unresolvable client is
//   refused, and that an over-cap source is refused without the provider being
//   consulted at all — cannot be observed from the outside of a real provider,
//   because "was lookupClient called?" is not a property of any response. Those
//   drive `loginHandler.fetch` directly with a recording stub. The handler
//   takes its env as a parameter, so this needs no real namespace and no
//   registered client.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  FAILURE_FLOOR_MS,
  createLoginHandler,
  loginHandler,
} from "../src/auth/login-handler";
import { CREDENTIAL_FAILURE_BODY } from "../src/auth/login-page";
import type { Env } from "../src/env";
import { ImapAuthError } from "../src/errors";
import { entryEnv } from "./fixtures/bound-secrets";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  UNLISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The password field's input name. Its absence is how "no form" is asserted. */
const SECRET_FIELD = `name="app_password"`;

/** Drive the real provider, over the injected proof, through its real fetch. */
async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Register a real client through the real registration endpoint. */
async function register(
  redirectUri: string,
  clientName?: string,
): Promise<string> {
  const response = await call(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ...(clientName === undefined ? {} : { client_name: clientName }),
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
  );

  expect(response.status).toBeLessThan(300);
  const body = (await response.json()) as { client_id: string };
  expect(typeof body.client_id).toBe("string");
  return body.client_id;
}

function authorizeQuery(clientId: string, redirectUri: string): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    state: "xyz",
  }).toString();
}

/**
 * The rendered client name and destination, read out of the page.
 *
 * Reading the marked elements rather than searching the whole body is what
 * makes the origin-only case meaningful: `toContain` would be satisfied by an
 * origin that happened to be a prefix of a displayed full URI.
 */
function clientFrom(body: string): string | null {
  return /<strong class="client">([^<]*)<\/strong>/.exec(body)?.[1] ?? null;
}

function destinationFrom(body: string): string | null {
  return /<code class="dest">([^<]*)<\/code>/.exec(body)?.[1] ?? null;
}

/**
 * A KV stub: no real namespace, and every key it is asked about is recorded.
 *
 * `value` is a function of the key rather than a constant, because the cases
 * that matter are exactly the ones where two keys must behave differently —
 * one source over the cap while another is not.
 */
function recordingKv(
  options: {
    value?: (key: string) => string | null;
    putRejects?: boolean;
  } = {},
) {
  const gets: string[] = [];
  const puts: string[] = [];
  return {
    gets,
    puts,
    kv: {
      async get(key: string) {
        gets.push(key);
        return options.value?.(key) ?? null;
      },
      async put(key: string) {
        puts.push(key);
        if (options.putRejects) {
          // What same-key write throttling looks like from the handler's side.
          throw new Error("KV PUT throttled");
        }
      },
    },
  };
}

/**
 * An env whose provider records what the handler asked it for.
 *
 * `lookupClient` returning a fixed record rather than a real one is the point:
 * these cases are about *whether and when* it is consulted, not about what a
 * registered client looks like — the real-registration cases above cover that.
 */
function stubEnv(options: {
  parseAuthRequest?: () => Promise<unknown>;
  client?: { clientId: string; clientName?: string } | null;
  kv?: unknown;
  calls?: string[];
  limiterKeys?: string[];
  floodRefused?: boolean;
}): Env {
  const calls = options.calls ?? [];
  return {
    OAUTH_KV: options.kv ?? recordingKv().kv,
    // The source-connection limiter, stubbed. `limiterKeys` records what it was
    // asked about, which is where the per-source keying this file has always
    // asserted now lives: the key used to be built into a store key and is now
    // built into this call.
    LOGIN_IP_LIMITER: {
      async limit({ key }: { key: string }) {
        options.limiterKeys?.push(key);
        return { success: options.floodRefused !== true };
      },
    },
    // The per-target limiter, stubbed open. No case in this file is about it.
    LOGIN_ID_LIMITER: {
      async limit() {
        return { success: true };
      },
    },
    // Without this the allow-list gate answers 503 above the method dispatch
    // and not one case in this file reaches the behaviour it was written for.
    ALLOWED_APPLE_IDS_SEED: JSON.stringify([LISTED_APPLE_ID]),
    // The store half, answering "nobody is in here". A case in this file is
    // never about the store, so it says nothing about it — and a binding that
    // said something would make every case in the file quietly depend on it.
    ALLOW_LIST_KV: { get: async () => null },
    OAUTH_PROVIDER: {
      parseAuthRequest:
        options.parseAuthRequest ??
        (async () => {
          calls.push("parseAuthRequest");
          return {
            responseType: "code",
            clientId: "stub-client",
            // On an allowed origin because the allowlist refuses anything else
            // ahead of the ordering these cases exist to observe.
            redirectUri: "https://claude.ai/cb",
            scope: ["mcp"],
            state: "",
          };
        }),
      lookupClient: async () => {
        calls.push("lookupClient");
        return options.client === undefined
          ? { clientId: "stub-client", clientName: "Stub Client" }
          : options.client;
      },
    },
  } as unknown as Env;
}

/**
 * A POST carrying credentials. The FIRST argument is now the Apple ID.
 *
 * That is the mechanical shape of the switch in this file: the form used to
 * carry one shared secret and now carries an address and a password, and under
 * the new rule it is the ADDRESS that decides whether a refusal happens at all.
 * A case that wants a refusal posts `UNLISTED_APPLE_ID`, which is turned away
 * by the allow-list check before a principal is built or the proof is called;
 * a case that wants the ceremony to complete posts `LISTED_APPLE_ID`.
 *
 * The password is the same fake every time, because no case in this file is
 * about the password.
 */
function post(appleId: string, query: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
    }).toString(),
  });
}

describe("the consent screen names what it is authorizing", () => {
  it("shows the registered client's name and the origin it will send you to", async () => {
    // The whole finding in one case. Distinguishes from pre-fix, where the page
    // contained neither value and the owner had no way to tell an attacker's
    // client from their own.
    // On an allowed origin: the allowlist would otherwise refuse this before
    // the page it is asserting on could be rendered.
    const redirectUri = "https://claude.ai/callback";
    const clientId = await register(redirectUri, "Claude Desktop");

    const response = await call(
      new Request(`${ORIGIN}/authorize?${authorizeQuery(clientId, redirectUri)}`),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(clientFrom(body)).toBe("Claude Desktop");
    expect(destinationFrom(body)).toBe("https://claude.ai");
    expect(body).toContain(SECRET_FIELD);
  });

  it("shows the client id when the client registered no name", async () => {
    // Never a blank space where an identity should be: an unnamed client is
    // still identified, by the only identifier it has.
    // Allowlist-constrained origin; the anonymity under test is the absent
    // client_name, which is unrelated to where the code would be delivered.
    const redirectUri = "https://claude.ai/anonymous-cb";
    const clientId = await register(redirectUri);

    const response = await call(
      new Request(`${ORIGIN}/authorize?${authorizeQuery(clientId, redirectUri)}`),
    );

    expect(clientFrom(await response.text())).toBe(clientId);
  });

  it("escapes a client name carrying HTML control characters", async () => {
    // The displayed name is attacker-chosen: it arrives through unauthenticated
    // dynamic client registration. If it were interpolated raw it could rewrite
    // the warning sentence it sits next to, which would turn the mitigation
    // into a second attack surface.
    // The hostile NAME is what this case is about, and it is unchanged. Only
    // the URI moved, onto the loopback arm of the allowlist — which is the
    // honest shape for this case anyway: a loopback callback is precisely the
    // one an attacker CAN still register, so the escaping this asserts is doing
    // its work on a page the owner can really be shown.
    const redirectUri = "http://localhost:8976/cb";
    const clientId = await register(redirectUri, `Ev<il>"Client'`);

    const response = await call(
      new Request(`${ORIGIN}/authorize?${authorizeQuery(clientId, redirectUri)}`),
    );
    const body = await response.text();

    expect(clientFrom(body)).toBe("Ev&lt;il&gt;&quot;Client&#39;");
    expect(body).not.toContain("Ev<il>");
    expect(body).not.toContain('"Client\'');
  });

  it("shows the destination as an origin, never the full path", async () => {
    // A long attacker-chosen path would otherwise push the origin out of view —
    // the origin is the only part of the URI that says who receives the code.
    // The long path is the point and is unchanged; only the host moved onto an
    // allowed origin, so the expected destination moves with it.
    const redirectUri = "https://claude.ai/callback/a/very/long/path?x=1";
    const clientId = await register(redirectUri, "Pathy Client");

    const response = await call(
      new Request(`${ORIGIN}/authorize?${authorizeQuery(clientId, redirectUri)}`),
    );
    const body = await response.text();

    expect(destinationFrom(body)).toBe("https://claude.ai");
    expect(body).not.toContain("/callback/a/very/long/path");
  });

  it("refuses a GET whose client the provider cannot resolve", async () => {
    // The form must not exist for a client that cannot be named. Distinguishes
    // from pre-fix, which rendered the form without ever consulting the
    // provider about who was asking.
    const response = await loginHandler.fetch(
      new Request(`${ORIGIN}/authorize?response_type=code&client_id=ghost`),
      stubEnv({ client: null }),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).not.toContain(SECRET_FIELD);
  });

  it("still authorizes and still redirects to the registered URI", async () => {
    // The positive control. Without it every case above is satisfied by a
    // handler that refuses everything.
    // The positive control keeps its shape and moves onto the OBSERVED remote
    // callback — the exact URI read off the live registration store.
    const redirectUri = "https://claude.ai/api/mcp/auth_callback";
    const clientId = await register(redirectUri, "Legit Client");
    const query = authorizeQuery(clientId, redirectUri);

    const response = await call(post(LISTED_APPLE_ID, query, { "cf-connecting-ip": "203.0.113.7" }));

    expect(response.status).toBe(302);
    expect(response.headers.get("location") ?? "").toContain(`${redirectUri}?code=`);
  });
});

describe("a second attempt is no less informed than the first", () => {
  it("still names the client on the 401 re-render after a wrong secret", async () => {
    const response = await loginHandler.fetch(
      post(UNLISTED_APPLE_ID, "response_type=code&client_id=stub-client"),
      stubEnv({}),
    );
    const body = await response.text();

    expect(response.status).toBe(401);
    // Asserted against the value the page actually serves. Since plan 11-02
    // there is ONE body for every failure on the credential path, and it is a
    // constant precisely so an assertion cannot drift from it.
    expect(body).toContain(CREDENTIAL_FAILURE_BODY[0]);
    expect(clientFrom(body)).toBe("Stub Client");
  });
});

describe("resolution sits below the cap check and above the comparison", () => {
  it("answers an unresolvable request with its own 400, not the 401 form", async () => {
    // A deliberate status change on an unauthenticated path, pinned here so a
    // later reader cannot mistake it for a regression. Pre-fix this request —
    // malformed oauth_request AND a wrong secret — reached the comparison first
    // and came back as the 401 form. Resolution now runs first, so the request
    // is answered by its own malformedness. That discloses nothing about the
    // submitted secret: the 400 is a function purely of well-formedness, which
    // the sender already knows.
    const { AuthorizationError } = await import("@cloudflare/workers-oauth-provider");
    const response = await loginHandler.fetch(
      post(UNLISTED_APPLE_ID, "not-a-valid-authorization-request"),
      stubEnv({
        parseAuthRequest: async () => {
          throw new AuthorizationError("invalid_request", {
            description: "Missing response_type",
          });
        },
      }),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).not.toContain(SECRET_FIELD);
  });

  it("refuses a flooding source without consulting the provider at all", async () => {
    // The flood brake must stay above the lookup: otherwise an unauthenticated
    // flood buys a provider round trip per request, precisely when the limiter
    // is trying to make requests cheap.
    const calls: string[] = [];
    const response = await loginHandler.fetch(
      post(UNLISTED_APPLE_ID, "response_type=code&client_id=stub-client"),
      stubEnv({ calls, floodRefused: true }),
    );

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBeTruthy();
    expect(calls).not.toContain("lookupClient");
    expect(calls).not.toContain("parseAuthRequest");
  });
});

/**
 * The same handler with the failure floor injected small.
 *
 * The two blocks below are about the counter's KEY and about the counter's
 * WRITE, and about nothing else — but every case in them drives a failing
 * path, which since Phase 11 sleeps whatever is left of a three-second floor.
 * Two of them make two calls each, so at the production figure they exceed the
 * default test timeout while proving nothing extra. The one case that IS about
 * the floor keeps the production handler, which is what stops this injection
 * hiding a default that had quietly changed.
 *
 * The proof THROWS rather than counting. No case here posts a listed address,
 * so reaching it at all would mean the allow-list check had stopped running —
 * and a throw says that loudly instead of passing quietly.
 */
const fastLogin = createLoginHandler(async () => {
  throw new Error("the login proof must not be reached by these cases");
}, 120);

describe("one party's failures are not everyone's", () => {
  const QUERY = "response_type=code&client_id=stub-client";

  // WHAT MOVED HERE IN PLAN 11-05, because these three cases read as if they
  // had been rewritten for no reason otherwise.
  //
  // The per-source count used to be a store key carrying a time bucket and the
  // connecting address, and these cases asserted on the KEYS that store was
  // asked about. The count is now a platform rate-limit binding, so the same
  // property — one party's failures are their own — lives in the KEY THAT
  // BINDING IS ASKED ABOUT. The assertion moved from one recorder to another;
  // the claim did not change.
  //
  // What DID change is that a refusal no longer writes to the store at all. The
  // store counter is now keyed by the address being tried rather than by who is
  // trying, and it is bumped only when Apple has actually turned a password
  // down. Every case here posts an address that is not on the list, so none of
  // them should reach it — which is why two of them assert the store was never
  // touched, a claim these cases could not have made before.

  it("counts two different sources against two different keys", async () => {
    // WR-02. Pre-fix the key was the time bucket and nothing else, so ten
    // failed POSTs from anyone who knew the hostname put the owner's own
    // /authorize POST behind a 429 with a five-minute retry-after — for the
    // price of ten HTTP requests, sustainable indefinitely.
    const limiterKeys: string[] = [];
    const kv = recordingKv();

    await fastLogin.fetch(
      post(UNLISTED_APPLE_ID, QUERY, { "cf-connecting-ip": "203.0.113.1" }),
      stubEnv({ kv: kv.kv, limiterKeys }),
    );
    await fastLogin.fetch(
      post(UNLISTED_APPLE_ID, QUERY, { "cf-connecting-ip": "198.51.100.2" }),
      stubEnv({ kv: kv.kv, limiterKeys }),
    );

    expect(limiterKeys).toHaveLength(2);
    expect(new Set(limiterKeys).size).toBe(2);
    // An unlisted address is refused before either per-target layer, so the
    // store is never consulted and never written.
    expect(kv.gets).toHaveLength(0);
    expect(kv.puts).toHaveLength(0);
  });

  it("still counts a request that arrives with no address header", async () => {
    // An absent header must not disable the limiter — otherwise the cheapest
    // way past the counter is to send one fewer header.
    const limiterKeys: string[] = [];

    const response = await fastLogin.fetch(
      post(UNLISTED_APPLE_ID, QUERY),
      stubEnv({ limiterKeys }),
    );

    expect(response.status).toBe(401);
    expect(limiterKeys).toHaveLength(1);
    expect(limiterKeys[0]!.length).toBeGreaterThan(0);
  });

  it("caps one source without capping another", async () => {
    // Two envs rather than one, because the binding's verdict is now a property
    // of the binding and not of a value read back out of a store. The pair is
    // still what makes the case mean something: a refusal with no second
    // request beside it would be satisfied by a limiter that refused everybody.
    const capped = await fastLogin.fetch(
      post(UNLISTED_APPLE_ID, QUERY, { "cf-connecting-ip": "203.0.113.9" }),
      stubEnv({ floodRefused: true }),
    );
    const other = await fastLogin.fetch(
      post(UNLISTED_APPLE_ID, QUERY, { "cf-connecting-ip": "198.51.100.9" }),
      stubEnv({}),
    );

    expect(capped.status).toBe(429);
    // Sixty, not the three hundred the store bucket used to advertise: the
    // binding's window is sixty seconds and this header carries the real one.
    expect(capped.headers.get("retry-after")).toBe("60");
    expect(other.status).toBe(401);
  });
});

describe("the counter's write cannot change the response", () => {
  it("still answers 401 when the counter's write rejects", async () => {
    // WR-01. The store throttles writes to the same key, so a burst makes the
    // write reject; pre-fix that rejection was unhandled and turned a 401 into
    // a 500 for identical input — an observable oracle distinguishing a burst
    // from a quiet request.
    //
    // This case now has to reach the write, and the write moved: it happens
    // only after Apple has turned a password down. So the address is a LISTED
    // one and the proof rejects with the type the handler reads as a credential
    // refusal — which is what a real wrong password looks like from here. That
    // is also why this case builds its own handler instead of taking the shared
    // one above, whose proof throws to prove it was never reached.
    const kv = recordingKv({ putRejects: true });
    const reachesApple = createLoginHandler(async () => {
      throw new ImapAuthError();
    }, 120);

    const response = await reachesApple.fetch(
      post(LISTED_APPLE_ID, "response_type=code&client_id=stub-client", {
        "cf-connecting-ip": "203.0.113.55",
      }),
      stubEnv({ kv: kv.kv }),
    );

    expect(kv.puts).toHaveLength(1);
    expect(response.status).toBe(401);
    expect(await response.text()).toContain(CREDENTIAL_FAILURE_BODY[0]);
  });

  it(
    "pays a delay a human does not notice and a parallel guesser is not slowed by",
    async () => {
      // The delay is the limiter that does not depend on a durable counter
      // succeeding, which is why its value is asserted rather than assumed.
      //
      // Phase 11 turned it from a fixed penalty into a FLOOR measured from the
      // handler's entry, and this is the one case in this file that still
      // drives the production handler with no floor injected — so the figure
      // below is the deployed one. It is compared against the exported
      // constant rather than a number typed here: a retyped figure would go
      // stale the day spike S6 resizes the floor, and it would go stale
      // silently, in the direction that keeps the case green.
      const started = Date.now();
      await loginHandler.fetch(
        post(UNLISTED_APPLE_ID, "response_type=code&client_id=stub-client", {
          "cf-connecting-ip": "203.0.113.56",
        }),
        stubEnv({}),
      );

      expect(Date.now() - started).toBeGreaterThanOrEqual(FAILURE_FLOOR_MS);
    },
    10_000,
  );
});
