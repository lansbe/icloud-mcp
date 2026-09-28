// A login lasts until someone revokes it (LIFE-01, LIFE-02, LIFE-03).
//
// **What this file proves that its neighbours do not.** Every other authorize
// suite stops at the 302. This one carries on: it redeems the code at the token
// endpoint, refreshes, and then reads the records the provider actually wrote.
// That is the only place the two lifetimes are visible. A test that stopped at
// the redirect would pass identically with both expiries back in place, because
// nothing about a 302 says how long the grant behind it lives.
//
// It is also the first file in this repository to perform a code exchange or a
// refresh at all. Later plans in this phase copy the helpers below rather than
// importing them, which is this repo's habit for test helpers.
//
// Three groups:
//
//   LIFE-01. Both lifetime keys are present and undefined, and one real
//   sign-in leaves a client record and a grant with no expiry. Plus the
//   CONTROL: the same flow with both keys deleted from a copy of the options
//   writes both records WITH an expiry. That control is the whole reason the
//   two undefined assertions mean anything — an absent key and an explicitly
//   undefined one do not behave the same, and the control is what can tell
//   them apart.
//
//   LIFE-02. A registration whose redirect addresses are not all on the origin
//   allowlist is refused before anything is stored, by the same predicate the
//   authorize page uses.
//
//   LIFE-03. Several Claude apps signed in as one Apple ID all stay signed in,
//   including one app that signs in twice.
//
// ---------------------------------------------------------------------------
// **Four hygiene rules, each with its reason. Do not undo them.**
//
// 1. EVERY sign-in runs against a SPREAD COPY of `entryEnv()` whose
//    `LOGIN_IP_LIMITER` and `LOGIN_ID_LIMITER` are allow-all stubs. The pool's
//    real per-target binding refuses a fourth sign-in per address per minute,
//    its windows are aligned to the wall clock, and nothing clears them between
//    files or between runs. This file signs the one listed address in many
//    times, so a real binding here would spend windows that the next case, the
//    next file, or the next run then has to live with.
//
// 2. NEVER write onto the shared environment object. The `env-assignment` scan
//    rule refuses it, and the reason the rule exists is that the object is
//    shared by every test in a file and every request in an isolate — a write
//    onto it leaks into every case beside this one. Overrides go on a copy.
//
// 3. Check keys by the grant id THIS case minted, never by a total. Sibling
//    test files read and write the same namespaces at the same time, so any
//    assertion on how many grants, tokens or clients the store holds is an
//    assertion about what the rest of the suite happened to be doing.
//
// 4. CLEAN UP. Grants and client records no longer expire, so nothing sweeps
//    them any more. Each case deletes the `grant:` key and every `token:` key
//    for every grant it minted, plus the client records it registered, in a
//    `finally`.
// ---------------------------------------------------------------------------
//
// **No real Apple ID is ever authenticated (D-09).** Every sign-in below goes
// through `test/fixtures/worker-with-login-proof.ts`, whose proof is a counter.
// The address is under the reserved `.invalid` domain and the password is
// plainly fake.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type {
  ClientRegistrationCallbackOptions,
  ClientRegistrationCallbackResult,
} from "@cloudflare/workers-oauth-provider";
import {
  MAX_CLIENT_NAME_LENGTH,
  MAX_REDIRECT_URIS,
  MAX_REDIRECT_URI_LENGTH,
  MAX_REGISTRATION_BYTES,
  REGISTRATION_REFUSED_DESCRIPTION,
  createLoginHandler,
  refuseUnlistedRedirects,
} from "../src/auth/login-handler";
import { AUTONOMY_CLIENT_NAME } from "../src/agent/autonomy-client";
import { oauthProviderOptions } from "../src/auth/oauth";
import type { Env } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { userIdOf } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/**
 * The PKCE verifier this file redeems codes with.
 *
 * The challenge below is its real SHA-256, base64url-encoded, and the pair was
 * COMPUTED rather than copied. That matters: the challenge the older authorize
 * suites send is a different string, and it pairs with no verifier anybody
 * holds. It never mattered there, because no test in this repository redeemed a
 * code until this one — the provider only checks the pair at the exchange.
 *
 * Recompute either value with:
 *
 *   printf '<verifier>' | openssl dgst -sha256 -binary \
 *     | openssl base64 | tr '+/' '-_' | tr -d '='
 *
 * A mismatched pair is a 400 `invalid_grant` at the token endpoint, "Invalid
 * PKCE code_verifier", which is exactly what a copied-and-assumed pair produced
 * here first time.
 */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";

/** `BASE64URL(SHA256(ASCII(CODE_VERIFIER)))`, computed. See above. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

/** One day, in the seconds a KV `expiration` is reported in. */
const DAY_SECONDS = 86400;

/** A Worker entry: the fixture by default, a locally built provider otherwise. */
type WorkerEntry = {
  fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response>;
};

/**
 * A rate-limit binding stub that always lets the request through.
 *
 * Hygiene rule 1. The shape is copied from `test/authorize-login.test.ts`: it
 * takes `{ key }` and reads nothing else, because `{ key }` is all the shipped
 * options type accepts. It touches nothing, which is the point.
 */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/**
 * The pool's environment with both limiters replaced, as a COPY.
 *
 * A spread, never a write onto the object `entryEnv()` hands back — hygiene
 * rule 2. Extra overrides are spread last so a case can also swap the store.
 */
function allowAllEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
    ...overrides,
  } as unknown as Env;
}

/** Drive a Worker entry through its real fetch, on a real execution context. */
async function callWorker(
  request: Request,
  env: Env,
  entry: WorkerEntry = worker,
): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await entry.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** A registration request carrying exactly the metadata it is handed. */
function registerRequest(metadata: Record<string, unknown>): Request {
  return new Request(`${ORIGIN}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(metadata),
  });
}

/** The metadata a public client registers with, which is how Claude registers. */
function publicClientMetadata(
  clientName: string,
  redirectUri: string,
): Record<string, unknown> {
  return {
    client_name: clientName,
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}

/** Register a real public client through the real registration endpoint. */
async function register(
  env: Env,
  clientName: string,
  redirectUri: string,
  entry: WorkerEntry = worker,
): Promise<string> {
  const response = await callWorker(
    registerRequest(publicClientMetadata(clientName, redirectUri)),
    env,
    entry,
  );

  expect(response.status).toBeLessThan(300);
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

/** An authorization query the real provider parses and re-validates. */
function authorizeQuery(
  clientId: string,
  redirectUri: string,
  state: string,
): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    state,
  }).toString();
}

/** A sign-in POST at the real Worker, from a named source connection. */
function postFrom(source: string, appleId: string, query: string): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": source,
    },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
    }).toString(),
  });
}

/**
 * A source key this invocation owns and nothing else in the repository uses.
 *
 * Not an address shape, and it does not need to be: the binding keys on the
 * string it is handed and never parses it. Minting a fresh one per sign-in is
 * belt and braces beside the allow-all stubs — it means a case still spends
 * nobody else's window if someone later removes a stub.
 */
function freshSource(): string {
  return `test-source-${crypto.randomUUID()}`;
}

/** Sign the listed address in, and hand back the authorization code. */
async function signIn(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string,
  entry: WorkerEntry = worker,
): Promise<string> {
  const response = await callWorker(
    postFrom(
      freshSource(),
      LISTED_APPLE_ID,
      authorizeQuery(clientId, redirectUri, state),
    ),
    env,
    entry,
  );

  expect(response.status).toBe(302);
  const location = response.headers.get("location");
  expect(location).not.toBeNull();
  const code = new URL(location as string).searchParams.get("code");
  expect(code).not.toBeNull();
  return code as string;
}

/** Redeem an authorization code at the real token endpoint. */
async function exchangeCode(
  env: Env,
  clientId: string,
  redirectUri: string,
  code: string,
  entry: WorkerEntry = worker,
): Promise<{ accessToken: string; refreshToken: string }> {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    }),
    env,
    entry,
  );

  // The body is read FIRST and named in the assertion, because a 400 here is
  // otherwise a bare status with no clue which of the exchange's six inputs the
  // provider disliked.
  const text = await response.text();
  expect(`${response.status} ${text}`).toBe(`200 ${text}`);
  const body = JSON.parse(text) as {
    access_token: string;
    refresh_token: string;
  };
  expect(typeof body.access_token).toBe("string");
  expect(typeof body.refresh_token).toBe("string");
  return { accessToken: body.access_token, refreshToken: body.refresh_token };
}

/** Refresh a login at the real token endpoint. The response, not an assertion. */
async function refreshWith(
  env: Env,
  clientId: string,
  refreshToken: string,
  entry: WorkerEntry = worker,
): Promise<Response> {
  return callWorker(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
      }).toString(),
    }),
    env,
    entry,
  );
}

/**
 * The grant id inside a token this library issued.
 *
 * Both token kinds have the shape `userId:grantId:secret`, so the middle
 * segment is the grant. Read from the token rather than from a listing, because
 * a listing is shared with every sibling file (hygiene rule 3).
 */
function grantIdOf(token: string): string {
  const segments = token.split(":");
  expect(segments).toHaveLength(3);
  return segments[1] as string;
}

/** Every key listed under a prefix, with the expiry the store reports. */
async function keysUnder(
  prefix: string,
): Promise<Array<{ name: string; expiration?: number }>> {
  const listed = await entryEnv().OAUTH_KV.list({ prefix });
  return listed.keys;
}

/**
 * Delete a grant and every access token under it (hygiene rule 4).
 *
 * Serial, one delete at a time. Nothing here needs to be fast, and a fan-out
 * over a store is the shape two scan rules exist to refuse elsewhere.
 */
async function forgetGrant(userId: string, grantId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const key of await keysUnder(`token:${userId}:${grantId}:`)) {
    await kv.delete(key.name);
  }
  await kv.delete(`grant:${userId}:${grantId}`);
}

/** Delete a client record this file registered (hygiene rule 4). */
async function forgetClient(clientId: string): Promise<void> {
  await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
}

/**
 * The pool's store, wrapped so every key it is asked to WRITE is recorded.
 *
 * It delegates all four methods the library uses and changes nothing about what
 * is stored — the point is to see a write that does not happen. A refusal at
 * registration leaves no key behind, so there is nothing for a listing to fail
 * to find, and "no key exists" is true of a store the request never reached at
 * all. The wrapper can tell those apart; a listing cannot.
 */
function recordingKv(puts: string[]): Record<string, unknown> {
  const store = entryEnv().OAUTH_KV as unknown as {
    get(key: string, options?: unknown): Promise<unknown>;
    put(key: string, value: unknown, options?: unknown): Promise<void>;
    delete(key: string): Promise<void>;
    list(options?: unknown): Promise<unknown>;
  };

  return {
    get(key: string, options?: unknown) {
      return store.get(key, options);
    },
    put(key: string, value: unknown, options?: unknown) {
      puts.push(key);
      return store.put(key, value, options);
    },
    delete(key: string) {
      return store.delete(key);
    },
    list(options?: unknown) {
      return store.list(options);
    },
  };
}

/** The listed address's user id, derived by the real function. Never hashed here. */
async function listedUserId(): Promise<string> {
  const userId = await userIdOf(LISTED_APPLE_ID);
  expect(userId).not.toBeNull();
  return userId as string;
}

const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

describe("LIFE-01: a login lasts until someone revokes it", () => {
  // Titled so `-t "LIFE-01"` matches. A name filter that matches nothing passes
  // SILENTLY, which would leave the requirement looking covered while measuring
  // nothing, so 12-VALIDATION.md's command and this title move together.

  it("both lifetime keys are present, and both are undefined", () => {
    // PRESENCE, not absence, and the distinction is the whole assertion. The
    // library spreads our options over its defaults, so an own key holding
    // `undefined` replaces the default while an ABSENT key keeps it — 30 days
    // for a refresh token, 90 for a client record. Deleting either line is the
    // forced logout coming back with nothing failing on the way out.
    expect(Object.hasOwn(oauthProviderOptions, "refreshTokenTTL")).toBe(true);
    expect(Object.hasOwn(oauthProviderOptions, "clientRegistrationTTL")).toBe(
      true,
    );
    expect(oauthProviderOptions.refreshTokenTTL).toBeUndefined();
    expect(oauthProviderOptions.clientRegistrationTTL).toBeUndefined();

    // Access tokens still expire in an hour. Only the two lifetimes that end a
    // LOGIN moved; the short-lived credential the client re-mints is unchanged.
    expect(oauthProviderOptions.accessTokenTTL).toBe(3600);
  });

  it("a real sign-in leaves a client record and a grant with no expiry, and refresh still works", async () => {
    const env = allowAllEnv();
    const userId = await listedUserId();
    const clientId = await register(
      env,
      "LIFE-01 web client",
      CLAUDE_WEB_REDIRECT,
    );
    let grantId: string | null = null;

    try {
      const code = await signIn(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        "life-01-lifetimes",
      );
      const { accessToken, refreshToken } = await exchangeCode(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        code,
      );
      grantId = grantIdOf(accessToken);

      const clientKeys = await keysUnder(`client:${clientId}`);
      expect(clientKeys).toHaveLength(1);
      expect(clientKeys[0]?.expiration).toBeUndefined();

      const grantKeys = await keysUnder(`grant:${userId}:${grantId}`);
      expect(grantKeys).toHaveLength(1);
      expect(grantKeys[0]?.expiration).toBeUndefined();

      // THE NON-VACUITY CHECK. Without it, both assertions above are satisfied
      // by a listing that never reports an expiry at all — a store binding that
      // dropped the field, or a pool that stopped surfacing it, would read as a
      // pass. The access token is written with a one-hour expiry by the same
      // call, through the same binding, so its key is the positive control.
      const tokenKeys = await keysUnder(`token:${userId}:${grantId}:`);
      expect(tokenKeys.length).toBeGreaterThan(0);
      expect(tokenKeys.some((key) => key.expiration !== undefined)).toBe(true);

      // Spike S2's failure, from the other side: with the client record gone
      // this answers 401 `invalid_client` even though the grant is fine. Both
      // records are kept now, so it answers 200.
      const refreshed = await refreshWith(env, clientId, refreshToken);
      expect(refreshed.status).toBe(200);
      const refreshedBody = (await refreshed.json()) as {
        access_token?: unknown;
      };
      expect(typeof refreshedBody.access_token).toBe("string");

      // A refresh does not rewrite the grant's expiry either way — it is fixed
      // at the code exchange — so this is the check that a rotation did not
      // quietly reintroduce one.
      const grantAfterRefresh = await keysUnder(`grant:${userId}:${grantId}`);
      expect(grantAfterRefresh).toHaveLength(1);
      expect(grantAfterRefresh[0]?.expiration).toBeUndefined();
    } finally {
      if (grantId !== null) await forgetGrant(userId, grantId);
      await forgetClient(clientId);
    }
  });

  it("the control: with both keys absent, the same flow writes both with an expiry", async () => {
    // WHY THIS CASE EXISTS. CONTEXT.md originally said a deleted key and an
    // explicitly-undefined one behave identically. They do not, and the
    // correction of 2026-09-21 is what this case holds: absent keeps the
    // library's 30-day and 90-day defaults, explicit `undefined` means never.
    // Without this case the two assertions above are consistent with a library
    // that ignores both keys, and the "tidy-up" that deletes the two lines
    // would leave the whole suite green while restoring the forced logout.
    const options: OAuthProviderOptions<Env> = {
      ...oauthProviderOptions,
      // The proof, injected as always (D-09). It does nothing and resolves.
      defaultHandler: createLoginHandler(async () => {}),
    };
    // Deleted from the COPY. Never from the imported object, which every other
    // case in this file and the real Worker both read.
    delete options.refreshTokenTTL;
    delete options.clientRegistrationTTL;

    const control = new OAuthProvider<Env>(options);
    const entry: WorkerEntry = {
      fetch(request, env, ctx) {
        return control.fetch(request, env, ctx);
      },
    };

    const env = allowAllEnv();
    const userId = await listedUserId();
    const before = Math.floor(Date.now() / 1000);
    const clientId = await register(
      env,
      "LIFE-01 control client",
      CLAUDE_WEB_REDIRECT,
      entry,
    );
    let grantId: string | null = null;

    try {
      const code = await signIn(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        "life-01-control",
        entry,
      );
      const { accessToken } = await exchangeCode(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        code,
        entry,
      );
      grantId = grantIdOf(accessToken);

      // 90 days by default. Asserted loosely at 80, because the exact default
      // is the library's to change and this case is about there being an expiry
      // at all rather than about its value.
      const clientKeys = await keysUnder(`client:${clientId}`);
      expect(clientKeys).toHaveLength(1);
      expect(clientKeys[0]?.expiration).toBeGreaterThan(
        before + 80 * DAY_SECONDS,
      );

      // 30 days by default, bounded on both sides so the case cannot be
      // satisfied by the 90-day value landing on the wrong record.
      const grantKeys = await keysUnder(`grant:${userId}:${grantId}`);
      expect(grantKeys).toHaveLength(1);
      expect(grantKeys[0]?.expiration).toBeGreaterThan(
        before + 25 * DAY_SECONDS,
      );
      expect(grantKeys[0]?.expiration).toBeLessThan(before + 31 * DAY_SECONDS);
    } finally {
      if (grantId !== null) await forgetGrant(userId, grantId);
      await forgetClient(clientId);
    }
  });
});

/**
 * Registration callback options carrying exactly the metadata handed in.
 *
 * The request is built from a fixed benign body rather than from the metadata,
 * and that is load-bearing for one row: a metadata object whose `redirect_uris`
 * getter throws cannot be serialized, so building the request from it would
 * throw in the test helper instead of in the predicate under test.
 *
 * The predicate reads no part of the request. It is present because the
 * library's own options type carries it.
 */
function registrationOptions(
  clientMetadata: Record<string, unknown>,
): ClientRegistrationCallbackOptions {
  return {
    clientMetadata,
    request: new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
  };
}

/** What every refusal must be, byte for byte, carrying nothing from the input. */
const REGISTRATION_REFUSAL: ClientRegistrationCallbackResult = {
  description: REGISTRATION_REFUSED_DESCRIPTION,
};

/** Drive the predicate over one redirect list. */
function judge(
  uris: unknown,
): ClientRegistrationCallbackResult | undefined | void {
  return refuseUnlistedRedirects(
    registrationOptions({
      client_name: "a client",
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
    }),
  );
}

describe("LIFE-02: a registration off the allowlist is refused at the door", () => {
  // Titled so `-t "LIFE-02"` matches. Same reason the LIFE-01 title is pinned:
  // a name filter that matches nothing passes silently.
  //
  // The table below drives the predicate DIRECTLY, in the style of
  // `test/authorize-redirect-allowlist.test.ts`. That is both cheaper and far
  // more exhaustive than routing every shape through the endpoint; the endpoint
  // cases further down are what prove the predicate is wired to anything.

  it("allows every redirect shape the allowlist already admits", () => {
    // The exact entry, and the shape all 16 live Claude web registrations hold.
    expect(judge(["https://claude.ai/api/mcp/auth_callback"])).toBeUndefined();
    // Claude Code. A local client binds an ephemeral port and re-binds a
    // different one next session, so the port is deliberately unpinned.
    expect(judge(["http://localhost:51877/callback"])).toBeUndefined();
    // Hermes. The IPv4 literal form of the same carve-out.
    expect(judge(["http://127.0.0.1:8976/callback"])).toBeUndefined();
    // The bracketed IPv6 form, which is how URL.origin renders ::1.
    expect(judge(["http://[::1]:8976/cb"])).toBeUndefined();
  });

  it("refuses every shape the allowlist does not admit", () => {
    // Suffix: a substring test would admit this. Matching is equality on the
    // whole origin, which is why it does not.
    expect(judge(["https://claude.ai.evil.example/cb"])).toEqual(
      REGISTRATION_REFUSAL,
    );
    // Scheme downgrade. Cleartext is admitted for loopback and nowhere else.
    expect(judge(["http://claude.ai/cb"])).toEqual(REGISTRATION_REFUSAL);
    // TLS loopback was never observed, so the rule stays the observed shape.
    expect(judge(["https://localhost/cb"])).toEqual(REGISTRATION_REFUSAL);
  });

  it("refuses a mixed list: EVERY address must pass, not merely one", () => {
    // Why `every` and not `some`. A client can only ever authorize to an
    // address it registered, so a mixed list buys it nothing it could use — and
    // now that client records never expire, the junk half would be stored
    // forever. The allowed entry is first, so a predicate that stopped at the
    // first pass would go green here.
    expect(
      judge([
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.ai.evil.example/cb",
      ]),
    ).toEqual(REGISTRATION_REFUSAL);
  });

  it("refuses malformed metadata rather than reading past it", () => {
    // `clientMetadata` is the RAW JSON body, not the library's validated form,
    // so each of these is a shape a stranger can actually post.
    expect(judge([])).toEqual(REGISTRATION_REFUSAL);
    expect(
      refuseUnlistedRedirects(
        registrationOptions({ client_name: "no redirects at all" }),
      ),
    ).toEqual(REGISTRATION_REFUSAL);
    expect(judge("https://claude.ai/api/mcp/auth_callback")).toEqual(
      REGISTRATION_REFUSAL,
    );
    expect(judge(["https://claude.ai/api/mcp/auth_callback", 7])).toEqual(
      REGISTRATION_REFUSAL,
    );
  });

  it("caps client_name, because a client record is now stored forever", () => {
    // CR-01's cheap half. Registration is unauthenticated by the OAuth spec and
    // accepts a body up to 1 MiB; the library puts no length cap on this field
    // and a client record no longer expires. So without a bound one accepted
    // registration parks most of a megabyte, permanently, in the very namespace
    // that holds the grants and the tokens. The redirect gate does not help: its
    // loopback half admits any port, so passing it costs a stranger nothing.
    const good = "https://claude.ai/api/mcp/auth_callback";
    const nameOf = (
      client_name: unknown,
    ): ClientRegistrationCallbackResult | undefined | void =>
      refuseUnlistedRedirects(
        registrationOptions({
          client_name,
          redirect_uris: [good],
          token_endpoint_auth_method: "none",
        }),
      );

    // Compared against the exported bound, not a second copy of the number.
    expect(nameOf("n".repeat(MAX_CLIENT_NAME_LENGTH))).toBeUndefined();
    expect(nameOf("n".repeat(MAX_CLIENT_NAME_LENGTH + 1))).toEqual(
      REGISTRATION_REFUSAL,
    );

    // Absent is fine — the field is optional in the spec and the consent screen
    // already has a fallback for it.
    expect(nameOf(undefined)).toBeUndefined();
    expect(nameOf(null)).toBeUndefined();

    // Present but not a string is REFUSED rather than ignored. This callback
    // decides whether to store the body, and a field it cannot measure is one it
    // cannot vouch for.
    expect(nameOf(7)).toEqual(REGISTRATION_REFUSAL);
    expect(nameOf({ toString: () => "short" })).toEqual(REGISTRATION_REFUSAL);
  });

  it("refuses a registration named as the autonomy client, in any letter case and with any surrounding spaces (Phase 27, D-23)", () => {
    // The owner's grant listing shows a grant's client name, and only the fixed
    // autonomy id may carry this one. The name is compared trimmed and
    // case-folded, so a registrant cannot pass with a capital or a space.
    const good = "https://claude.ai/api/mcp/auth_callback";
    const nameOf = (client_name: unknown) =>
      refuseUnlistedRedirects(
        registrationOptions({
          client_name,
          redirect_uris: [good],
          token_endpoint_auth_method: "none",
        }),
      );

    for (const posing of [
      AUTONOMY_CLIENT_NAME,
      AUTONOMY_CLIENT_NAME.toUpperCase(),
      AUTONOMY_CLIENT_NAME.toLowerCase(),
      `  ${AUTONOMY_CLIENT_NAME}  `,
      `\t${AUTONOMY_CLIENT_NAME}\n`,
    ]) {
      expect(nameOf(posing), JSON.stringify(posing)).toEqual(REGISTRATION_REFUSAL);
    }

    // Near names are ordinary names. The rule is equality, not a prefix match.
    expect(nameOf(`${AUTONOMY_CLIENT_NAME} 2`)).toBeUndefined();
    expect(nameOf("iCloud MCP")).toBeUndefined();
    expect(nameOf("a client")).toBeUndefined();
  });

  it("refuses the autonomy client's name at the real registration endpoint, and stores nothing", async () => {
    const puts: string[] = [];
    const env = allowAllEnv({ OAUTH_KV: recordingKv(puts) });
    const response = await callWorker(
      registerRequest({
        client_name: ` ${AUTONOMY_CLIENT_NAME.toUpperCase()} `,
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
      env,
    );
    expect(response.status).toBe(400);
    const body = (await response.json()) as { error_description?: unknown };
    expect(body.error_description).toBe(REGISTRATION_REFUSED_DESCRIPTION);
    expect(puts.filter((key) => key.startsWith("client:"))).toEqual([]);
  });

  it("caps the redirect addresses too, which the origin gate does not", () => {
    // WR-01, iteration 2. The gate above reduces each URI to its ORIGIN and
    // discards the path, so `https://claude.ai/<most of a megabyte>` passed it
    // and the library only checks the scheme and control characters. The whole
    // string lands in the permanent record.
    const good = "https://claude.ai/api/mcp/auth_callback";
    const padding = MAX_REDIRECT_URI_LENGTH - "https://claude.ai/".length;

    // The reduction itself, pinned, so the reason for this bound is not left as
    // a claim in a comment. A 200-character path is invisible to the gate.
    expect(new URL(`https://claude.ai/${"a".repeat(200)}`).origin).toBe(
      "https://claude.ai",
    );

    // Exactly at the bound passes; one over is refused. Compared against the
    // exported constant rather than a second copy of the number.
    expect(judge([`https://claude.ai/${"a".repeat(padding)}`])).toBeUndefined();
    expect(
      judge([`https://claude.ai/${"a".repeat(padding + 1)}`]),
    ).toEqual(REGISTRATION_REFUSAL);

    // And the COUNT. Every live record held exactly one address; a long list
    // buys a real client nothing it could use, because it can only authorize to
    // an address it registered.
    expect(
      judge(Array.from({ length: MAX_REDIRECT_URIS }, () => good)),
    ).toBeUndefined();
    expect(
      judge(Array.from({ length: MAX_REDIRECT_URIS + 1 }, () => good)),
    ).toEqual(REGISTRATION_REFUSAL);
  });

  it("caps the WHOLE body, so a field this gate never heard of is bounded too", () => {
    // WR-01's backstop, and the only one of the four bounds that a field nobody
    // thought of cannot walk around. Each row below is a real stored field the
    // named caps miss entirely.
    const good = "https://claude.ai/api/mcp/auth_callback";
    const base = {
      client_name: "a client",
      redirect_uris: [good],
      token_endpoint_auth_method: "none",
    };
    const bodyOf = (
      extra: Record<string, unknown>,
    ): ClientRegistrationCallbackResult | undefined | void =>
      refuseUnlistedRedirects(registrationOptions({ ...base, ...extra }));

    // A real registration is nowhere near the ceiling.
    expect(JSON.stringify(base).length).toBeLessThan(MAX_REGISTRATION_BYTES / 4);
    expect(bodyOf({})).toBeUndefined();

    // `contacts` — any number of strings of any length, stored verbatim by the
    // library at `oauth-provider.js:2586`. Neither the name cap nor the URI cap
    // sees it.
    expect(
      bodyOf({ contacts: ["someone@example.invalid"] }),
      "a real contacts array was refused",
    ).toBeUndefined();
    expect(
      bodyOf({
        contacts: Array.from({ length: 400 }, () => "x".repeat(200)),
      }),
    ).toEqual(REGISTRATION_REFUSAL);

    // The i18n keys — every key matching `client_name#…` is accepted and stored,
    // with no cap on how many there are. Each VALUE here is under
    // MAX_CLIENT_NAME_LENGTH, so only the whole-body bound can refuse this.
    const i18n: Record<string, unknown> = {};
    for (let index = 0; index < 200; index += 1) {
      i18n[`client_name#lang${index}`] = "n".repeat(MAX_CLIENT_NAME_LENGTH);
    }
    expect(bodyOf(i18n)).toEqual(REGISTRATION_REFUSAL);
    // One of them is a real client being polite, and is not refused.
    expect(
      bodyOf({ "client_name#fr": "un client" }),
      "a single translated name was refused",
    ).toBeUndefined();
  });

  it("refuses a non-object argument rather than throwing past its own claim", () => {
    // IN-03. The parameter used to be destructured in the signature, which runs
    // BEFORE the try — so a non-object argument threw straight past the
    // never-throw claim. What held the claim up was the library's own wrapper,
    // not this function. Now it is this function.
    for (const argument of [null, undefined, 7, "a string"]) {
      let outcome: ClientRegistrationCallbackResult | undefined | void;
      expect(() => {
        outcome = refuseUnlistedRedirects(
          argument as unknown as ClientRegistrationCallbackOptions,
        );
      }, `threw on ${String(argument)}`).not.toThrow();
      expect(outcome).toEqual(REGISTRATION_REFUSAL);
    }
  });

  it("refuses a metadata object whose getter throws, and does not throw itself", () => {
    // A throw in this callback is a 500 whose description is the ERROR'S OWN
    // MESSAGE — text a stranger wrote, served back out. That is why the whole
    // body sits in a try/catch and the caught value is never read.
    const hostile: Record<string, unknown> = {};
    Object.defineProperty(hostile, "redirect_uris", {
      enumerable: true,
      get() {
        throw new Error("a message a stranger chose");
      },
    });

    let outcome: ClientRegistrationCallbackResult | undefined | void;
    expect(() => {
      outcome = refuseUnlistedRedirects(registrationOptions(hostile));
    }).not.toThrow();
    expect(outcome).toEqual(REGISTRATION_REFUSAL);
  });

  // -------------------------------------------------------------------------
  // Through the REAL registration endpoint. The table above proves the rule;
  // these prove it is wired to the endpoint, and that a refusal happens BEFORE
  // anything is written.
  // -------------------------------------------------------------------------

  it("registers all three client shapes seen in production", async () => {
    const env = allowAllEnv();
    const registered: string[] = [];

    try {
      // Claude on the web: confidential, 16 of the 21 live records.
      const web = await callWorker(
        registerRequest({
          client_name: "Claude",
          redirect_uris: [CLAUDE_WEB_REDIRECT],
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        }),
        env,
      );
      expect(web.status).toBeLessThan(300);
      const webBody = (await web.json()) as {
        client_id: string;
        client_secret_expires_at?: unknown;
      };
      registered.push(webBody.client_id);

      // LIFE-01 reaching the SECRET too. RFC 7591 reads zero as "never", and
      // the library serves zero precisely because the client lifetime is unset.
      // A number here instead would mean the 90-day clock came back.
      expect(webBody.client_secret_expires_at).toBe(0);

      // Claude Code and Hermes: public, loopback, ephemeral ports.
      registered.push(
        await register(env, "Claude Code (icloud-mcp)", "http://localhost:51877/callback"),
      );
      registered.push(
        await register(env, "Hermes Agent", "http://127.0.0.1:8976/callback"),
      );
    } finally {
      for (const clientId of registered) await forgetClient(clientId);
    }
  });

  it("refuses an off-list registration with a 400 and stores nothing", async () => {
    const puts: string[] = [];
    const env = allowAllEnv({ OAUTH_KV: recordingKv(puts) });

    const response = await callWorker(
      registerRequest({
        client_name: "a client this server will not send a code to",
        redirect_uris: ["https://claude.ai.evil.example/cb"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
      env,
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as {
      error?: unknown;
      error_description?: unknown;
    };
    expect(body.error).toBe("invalid_client_metadata");
    // Compared against the EXPORT, not a second copy of the sentence. And the
    // served value carries nothing from the request that was refused.
    expect(body.error_description).toBe(REGISTRATION_REFUSED_DESCRIPTION);
    expect(body.error_description).not.toContain("evil.example");

    // NOTHING WAS STORED. The refusal runs before the library's write, so no
    // client record exists to clean up — and there is no key to delete, which
    // is why this is observed through a recording wrapper rather than by
    // listing the store (hygiene rule 3: a listing is shared).
    expect(puts.filter((key) => key.startsWith("client:"))).toEqual([]);
  });

  it("the positive control: an allowed registration records exactly one client write", async () => {
    // Without this, the assertion above is satisfied by a wrapper that records
    // nothing at all — a delegating `put` that forgot to push, or a library that
    // writes client records through some other method. Same wrapper shape, same
    // endpoint, one character of difference in the redirect address.
    const puts: string[] = [];
    const env = allowAllEnv({ OAUTH_KV: recordingKv(puts) });
    let clientId: string | null = null;

    try {
      clientId = await register(env, "LIFE-02 control client", CLAUDE_WEB_REDIRECT);
      expect(puts.filter((key) => key.startsWith("client:"))).toEqual([
        `client:${clientId}`,
      ]);
    } finally {
      if (clientId !== null) await forgetClient(clientId);
    }
  });
});

/**
 * A well-formed 2026-07-28 `tools/list`, carrying a bearer token.
 *
 * Copied from `test/door.test.ts`, with the authorization header added. It calls
 * no tool, so it opens no socket to Apple — what it proves is that the door
 * still serves the grant behind the token.
 */
function toolsList(accessToken: string): Request {
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: DEPLOYED_HOSTNAME,
      "Mcp-Method": "tools/list",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/**
 * The JSON-RPC message in a response body, on either lane.
 *
 * Copied from `test/door.test.ts`. The modern lane answers with a JSON body;
 * an event stream carries the message after `data:`. Null when it holds neither.
 */
function rpcMessageIn(bodyText: string): Record<string, unknown> | null {
  const trimmed = bodyText.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  return null;
}

/** Assert an access token still gets served a tool list at `/mcp`. */
async function expectStillServed(
  env: Env,
  accessToken: string,
): Promise<void> {
  const response = await callWorker(toolsList(accessToken), env);
  expect(response.status).toBe(200);
  const message = rpcMessageIn(await response.text());
  expect(message).not.toBeNull();
  const result = (message as { result?: { tools?: unknown } }).result;
  expect(Array.isArray(result?.tools)).toBe(true);
  expect((result?.tools as unknown[]).length).toBeGreaterThan(0);
}

describe("LIFE-03: several Claude apps signed in as one Apple ID", () => {
  // Titled so `-t "LIFE-03"` matches, for the same reason the two titles above
  // are pinned.
  //
  // `test/authorize-login.test.ts` already pins `revokeExistingGrants: false` on
  // a STUB recorder — it proves the argument is passed. These two prove what
  // that argument BUYS, through the real provider and the real store: the grants
  // coexist, and the older app is still served afterwards. The failure they
  // guard against is the one a family member reports as "it keeps signing me
  // out", and it happened for real on 2026-09-21.

  it("two different Claude apps stay signed in as one Apple ID", async () => {
    const env = allowAllEnv();
    const userId = await listedUserId();
    const secondRedirect = "http://localhost:51877/callback";

    const firstClient = await register(env, "Claude", CLAUDE_WEB_REDIRECT);
    const secondClient = await register(
      env,
      "Claude Code (icloud-mcp)",
      secondRedirect,
    );
    let firstGrant: string | null = null;
    let secondGrant: string | null = null;

    try {
      const firstCode = await signIn(
        env,
        firstClient,
        CLAUDE_WEB_REDIRECT,
        "life-03-first",
      );
      const first = await exchangeCode(
        env,
        firstClient,
        CLAUDE_WEB_REDIRECT,
        firstCode,
      );
      firstGrant = grantIdOf(first.accessToken);

      const secondCode = await signIn(
        env,
        secondClient,
        secondRedirect,
        "life-03-second",
      );
      const second = await exchangeCode(
        env,
        secondClient,
        secondRedirect,
        secondCode,
      );
      secondGrant = grantIdOf(second.accessToken);

      // Two distinct grants, found by the ids THESE sign-ins minted rather than
      // by counting what the shared store holds (hygiene rule 3).
      expect(firstGrant).not.toBe(secondGrant);
      expect(await keysUnder(`grant:${userId}:${firstGrant}`)).toHaveLength(1);
      expect(await keysUnder(`grant:${userId}:${secondGrant}`)).toHaveLength(1);

      // Both refreshes work AFTER the second sign-in. The first is the one that
      // matters: under the revoking default it is the grant that loses.
      const firstRefresh = await refreshWith(
        env,
        firstClient,
        first.refreshToken,
      );
      expect(firstRefresh.status).toBe(200);
      const secondRefresh = await refreshWith(
        env,
        secondClient,
        second.refreshToken,
      );
      expect(secondRefresh.status).toBe(200);

      // And the first app's ACCESS token still serves. This is the half a
      // refresh cannot show: the store is eventually consistent, so a revoked
      // grant kept serving for about sixty seconds on 2026-09-21 before the
      // delete caught up. A served tool list is the door's own answer.
      await expectStillServed(env, first.accessToken);
    } finally {
      if (firstGrant !== null) await forgetGrant(userId, firstGrant);
      if (secondGrant !== null) await forgetGrant(userId, secondGrant);
      await forgetClient(firstClient);
      await forgetClient(secondClient);
    }
  });

  it("one app signing in twice keeps both grants", async () => {
    // WHY THIS CASE EXISTS BESIDE THE ONE ABOVE. The library revokes earlier
    // grants for the same user id AND the same client id. Two different apps
    // register two different client ids, so they coexist even under the revoking
    // default — the case above would pass with the lockout fully restored. This
    // is the case that can see it.
    //
    // It is also the shape a real Claude client actually produces: it submits
    // the sign-in form TWICE, about 1.4 seconds apart, and both submissions
    // succeed (commit 3043361). One client, two authorizations, two codes, two
    // exchanges.
    const env = allowAllEnv();
    const userId = await listedUserId();
    const clientId = await register(env, "Claude", CLAUDE_WEB_REDIRECT);
    let firstGrant: string | null = null;
    let secondGrant: string | null = null;

    try {
      const firstCode = await signIn(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        "life-03-twice-a",
      );
      const first = await exchangeCode(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        firstCode,
      );
      firstGrant = grantIdOf(first.accessToken);

      const secondCode = await signIn(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        "life-03-twice-b",
      );
      const second = await exchangeCode(
        env,
        clientId,
        CLAUDE_WEB_REDIRECT,
        secondCode,
      );
      secondGrant = grantIdOf(second.accessToken);

      expect(firstGrant).not.toBe(secondGrant);
      expect(await keysUnder(`grant:${userId}:${firstGrant}`)).toHaveLength(1);
      expect(await keysUnder(`grant:${userId}:${secondGrant}`)).toHaveLength(1);

      // The FIRST of the two, on both paths. That is the one the default kills.
      await expectStillServed(env, first.accessToken);
      const firstRefresh = await refreshWith(env, clientId, first.refreshToken);
      expect(firstRefresh.status).toBe(200);
    } finally {
      if (firstGrant !== null) await forgetGrant(userId, firstGrant);
      if (secondGrant !== null) await forgetGrant(userId, secondGrant);
      await forgetClient(clientId);
    }
  });
});
