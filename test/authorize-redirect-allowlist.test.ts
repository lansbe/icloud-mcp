// The window-8 proof: /authorize must REFUSE a redirect origin it does not
// recognise, not merely display it.
//
// What this distinguishes from is `test/authorize-consent.test.ts`, and the
// distinction is the whole point of this file. That suite proves the consent
// screen NAMES the destination — it makes an attacker-registered redirect
// visible to the owner. Visibility is not refusal. With open dynamic client
// registration at /oauth/register, an attacker registers a client with a
// familiar name and their own redirect URI, sends the owner an /authorize link
// on the correct origin over TLS, and every signal on the page is legitimate;
// the mitigation there depends entirely on the owner reading carefully. The
// allowlist closes the class outright, before the form is ever rendered.
//
// The legitimate origins were OBSERVED on 2026-08-14 by enumerating the live
// registration store, never guessed. That measurement is why this exists now
// and did not exist in Phase 1: narrowing against a guess would have locked the
// owner out of their own server, which is worse than the outcome prevented.
//
// Three test shapes, following the conventions this project already set:
//
//   The predicate, driven directly. `isAllowedRedirectOrigin` is exported so a
//   table of bypass shapes can be driven straight at it — cheaper and far more
//   exhaustive than routing every candidate through the handler. It proves the
//   RULE. It does not prove the rule is wired to anything, which is why the
//   handler-level cases below exist too.
//
//   Stubbed provider. Anything about ORDERING — that the refusal beats the
//   client lookup, and beats the credential check even when the credential is
//   one that works — cannot be observed from outside a real provider. Those
//   drive `loginHandler.fetch` directly with a recording stub.
//
//   Real registration. The lockout controls — the cases that would catch this
//   change locking the OWNER out — register a genuinely observed callback
//   through the real registration endpoint and complete the whole ceremony.
//   Without them every case here is satisfied by a handler that refuses
//   everything.
//
//   Since Phase 11 those end-to-end cases go through
//   test/fixtures/worker-with-login-proof.ts rather than src/index.ts. The
//   ceremony now ends in a real IMAP login, and D-09 forbids any automated
//   login to a real Apple ID, so the fixture composes the very same provider
//   options and substitutes exactly one thing: the proof. The registration, the
//   provider, the allowlist check and the redirect are all the production ones.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  isAllowedRedirectOrigin,
  loginHandler,
  refusedRedirectBody,
} from "../src/auth/login-handler";
import type { Env, LoginGateSecret } from "../src/env";
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

/** The observed Claude Desktop callback — read off the live registration store. */
const OBSERVED_REMOTE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

/**
 * A loopback callback on a port that is deliberately NOT the observed 3118.
 *
 * The whole point of the loopback entry being a class: a local client binds an
 * ephemeral port and re-binds a different one next session, so a rule pinned to
 * the port seen on any given day breaks the very next authorization.
 */
const OTHER_PORT_LOOPBACK_CALLBACK = "http://localhost:51877/callback";

/** Drive the production entry — the real provider — through its real fetch. */
async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/**
 * Register a real client through the real registration endpoint.
 *
 * Returns the raw response alongside the id so a caller can MEASURE whether a
 * given redirect shape is accepted rather than assuming it. `expectOk` is off
 * for the loopback probe for exactly that reason.
 */
async function registerRaw(
  redirectUri: string,
  clientName?: string,
): Promise<Response> {
  return call(
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
}

async function register(
  redirectUri: string,
  clientName?: string,
): Promise<string> {
  const response = await registerRaw(redirectUri, clientName);
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
 * The rendered destination, read out of the marked element.
 *
 * Reading the element rather than searching the whole body is what makes the
 * origin-only assertion meaningful: `toContain` would be satisfied by an origin
 * that happened to be a prefix of a displayed full URI.
 */
function destinationFrom(body: string): string | null {
  return /<code class="dest">([^<]*)<\/code>/.exec(body)?.[1] ?? null;
}

/** A KV stub: no real namespace, nothing over the cap. */
function quietKv() {
  return {
    async get() {
      return null;
    },
    async put() {
      /* nothing here asserts on the counter; the refusal must not touch it. */
    },
  };
}

/** A rate-limit binding that lets everything through. Takes only a key. */
function openLimiter() {
  return {
    async limit() {
      return { success: true };
    },
  };
}

/**
 * An env whose provider records what the handler reached.
 *
 * `completeAuthorization` is recorded rather than omitted on purpose: "the
 * refusal beat the comparison" is only really proved by the ceremony NOT being
 * completed, and a stub that simply lacked the method would fail by throwing,
 * which is a different assertion wearing the same green.
 */
function stubEnv(options: {
  redirectUri?: string;
  parseAuthRequest?: () => Promise<unknown>;
  calls?: string[];
}): Env & LoginGateSecret {
  const calls = options.calls ?? [];
  return {
    OAUTH_KV: quietKv(),
    // Both sign-in limiters, stubbed open. No case here is about a limiter, and
    // the real bindings are counters the pool persists to disk with no reset
    // between tests or between runs — so a case that touched one would spend a
    // window the next run has to live with.
    LOGIN_IP_LIMITER: openLimiter(),
    LOGIN_ID_LIMITER: openLimiter(),
    // Without this the allow-list gate answers 503 above the method dispatch
    // and not one case in this file reaches the refusal it was written for.
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
            redirectUri: options.redirectUri ?? "https://attacker.example/cb",
            scope: ["mcp"],
            state: "",
          };
        }),
      lookupClient: async () => {
        calls.push("lookupClient");
        return { clientId: "stub-client", clientName: "Stub Client" };
      },
      completeAuthorization: async () => {
        calls.push("completeAuthorization");
        return { redirectTo: "https://attacker.example/cb?code=leaked" };
      },
    },
  } as unknown as Env & LoginGateSecret;
}

function get(query: string): Request {
  return new Request(`${ORIGIN}/authorize?${query}`);
}

/**
 * A POST carrying credentials. The FIRST argument is now the Apple ID.
 *
 * That is the mechanical shape of the switch in this file. `LISTED_APPLE_ID` is
 * a credential that WOULD complete the ceremony, which is what makes the
 * "refuses a POST carrying a credential that works" case below mean anything;
 * `UNLISTED_APPLE_ID` is one that would not. Neither reaches Apple: the
 * redirect refusal sits above the credential path entirely, and the end-to-end
 * cases go through the injected proof.
 */
function post(
  appleId: string,
  query: string,
  headers: Record<string, string> = {},
): Request {
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

const STUB_QUERY = "response_type=code&client_id=stub-client";

describe("the allowlist predicate", () => {
  it("admits the observed origins and the loopback class", () => {
    // The exact entry, matched by equality on the derived origin.
    expect(isAllowedRedirectOrigin("https://claude.ai")).toBe(true);
    // Any port, because a local client re-binds an ephemeral one each session.
    expect(isAllowedRedirectOrigin("http://localhost:51877")).toBe(true);
    // No port at all is still loopback.
    expect(isAllowedRedirectOrigin("http://localhost")).toBe(true);
    // The IPv4 literal form.
    expect(isAllowedRedirectOrigin("http://127.0.0.1:8976")).toBe(true);
    // The bracketed IPv6 form, which is how URL.origin renders ::1.
    expect(isAllowedRedirectOrigin("http://[::1]:8976")).toBe(true);
  });

  it("refuses every shape that would slip past a looser rule", () => {
    // Suffix: a substring test would admit this, which is why matching is
    // equality on the whole origin.
    expect(isAllowedRedirectOrigin("https://claude.ai.evil.example")).toBe(false);
    // Scheme downgrade: cleartext is admitted for loopback and nowhere else.
    expect(isAllowedRedirectOrigin("http://claude.ai")).toBe(false);
    // Added port: URL.origin carries the port, so this is a different string.
    expect(isAllowedRedirectOrigin("https://claude.ai:8443")).toBe(false);
    // Loopback-prefixed public host: exactly what an UNANCHORED loopback
    // expression would admit, and it resolves to an attacker's server.
    expect(isAllowedRedirectOrigin("http://localhost.evil.example")).toBe(false);
    // The same bypass against the IPv4 form.
    expect(isAllowedRedirectOrigin("http://127.0.0.1.evil.example")).toBe(false);
    // Nothing unrelated is admitted by accident.
    expect(isAllowedRedirectOrigin("https://unrelated.example")).toBe(false);
    // Fails closed: an origin that could not be derived is not permitted.
    expect(isAllowedRedirectOrigin(null)).toBe(false);
  });
});

describe("a disallowed destination is refused on BOTH verbs", () => {
  // A check on one verb only is a hole. The GET renders the form and the POST
  // issues the code, so a GET-only check refuses nothing that matters and a
  // POST-only check invites the owner to type their secret into a page that
  // was already doomed. This pair is what holds the second call site in place.

  it("refuses a GET locally, with no form and no redirect", async () => {
    const calls: string[] = [];
    const response = await loginHandler.fetch(get(STUB_QUERY), stubEnv({ calls }));
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    // Never a redirect: sending the browser to an origin just refused would be
    // the CVE-class bug this whole check exists to prevent, with an extra step.
    expect(response.headers.get("location")).toBeNull();
    expect(body).not.toContain(SECRET_FIELD);
    // Asserted against the value the handler serves, not a retyped copy.
    expect(body).toBe(refusedRedirectBody("https://attacker.example"));
    // Refused before the client lookup: a doomed request buys no store round
    // trip, the same argument the resolution ordering already makes.
    expect(calls).not.toContain("lookupClient");
  });

  it("refuses a POST carrying a credential that works", async () => {
    // The case that matters most. A credential that would complete the ceremony
    // must not purchase a code for a destination this server will not send to,
    // so the check sits ABOVE the credential path rather than after it. The
    // address posted here is the listed one, which is what makes that claim
    // non-vacuous: it is refused despite being a credential this server accepts.
    const calls: string[] = [];
    const response = await loginHandler.fetch(
      post(LISTED_APPLE_ID, STUB_QUERY, { "cf-connecting-ip": "203.0.113.21" }),
      stubEnv({ calls }),
    );

    expect(response.status).toBe(403);
    expect(response.status).not.toBe(302);
    expect(response.headers.get("location")).toBeNull();
    expect(calls).not.toContain("completeAuthorization");
    expect(calls).not.toContain("lookupClient");
  });

  it("answers a POST with an UNLISTED address 403 rather than the 401 form", async () => {
    // Deliberate, and pinned here so a later reader cannot read it as a
    // regression: the refusal is above the credential path, so the destination
    // is what answers, not the address. This discloses nothing — the answer is
    // a pure function of the requester's own redirect URI, which they chose —
    // and it is precisely why list membership cannot be read off this status.
    const response = await loginHandler.fetch(
      post(UNLISTED_APPLE_ID, STUB_QUERY, {
        "cf-connecting-ip": "203.0.113.22",
      }),
      stubEnv({}),
    );

    expect(response.status).toBe(403);
    expect(response.status).not.toBe(401);
    expect(await response.text()).not.toContain(SECRET_FIELD);
  });
});

describe("the refusal says enough and no more", () => {
  it("names the origin and never the attacker's path", async () => {
    // The body echoes attacker-influenced content, so it echoes only the part
    // that identifies the recipient. A long chosen path would push the origin
    // out of view — the same reasoning the consent screen's display follows.
    const response = await loginHandler.fetch(
      get(STUB_QUERY),
      stubEnv({
        redirectUri:
          "https://attacker.example/callback/a/very/long/path?harvest=code",
      }),
    );
    const body = await response.text();

    expect(body).toBe(refusedRedirectBody("https://attacker.example"));
    expect(body).not.toContain("/callback/a/very/long/path");
    expect(body).not.toContain("harvest=code");
  });

  it("tells a locked-out owner how to recover", async () => {
    // Convention 4 forbids logging anywhere under src/, so this body is the
    // only diagnostic channel that exists — and the only party a refusal can
    // lock out is the owner, who has nothing else to read.
    const body = refusedRedirectBody("https://claude.example");

    expect(body).toContain("https://claude.example");
    expect(body).toContain("ALLOWED_REDIRECT_ORIGINS");
    expect(body).toContain("src/auth/login-handler.ts");
    // A wrong allowlist blocks a NEW authorization only; issued tokens keep
    // refreshing through the token endpoint. An owner reading this in a panic
    // needs to know the server is not down.
    expect(body).toContain("Existing authorizations are unaffected");
  });
});

describe("the check fails closed", () => {
  it("refuses a redirect URI that is not a URL at all", async () => {
    const response = await loginHandler.fetch(
      get(STUB_QUERY),
      stubEnv({ redirectUri: "not a url at all" }),
    );

    expect(response.status).toBe(403);
    // Rendered as the unreadable-destination sentence rather than echoed raw.
    expect(await response.text()).toBe(
      refusedRedirectBody("an address this server could not read"),
    );
  });

  it("refuses a custom-scheme callback with no host", async () => {
    // URL.origin is the literal string "null" for a non-special scheme. It is
    // refused by not matching the allowlist, never by a special case.
    const response = await loginHandler.fetch(
      get(STUB_QUERY),
      stubEnv({ redirectUri: "com.example.app:/oauth/callback" }),
    );

    expect(response.status).toBe(403);
  });

  it("refuses a custom-scheme callback that does have a host", async () => {
    const response = await loginHandler.fetch(
      get(STUB_QUERY),
      stubEnv({ redirectUri: "com.example.app://callback/done" }),
    );

    expect(response.status).toBe(403);
  });
});

describe("the observed origins still authorize end to end", () => {
  // The lockout controls. These are the cases that catch this change locking
  // the owner out of their own server, and they are the reason the allowlist
  // was deferred until the origins had actually been observed.

  it("completes the whole ceremony for the observed remote callback", async () => {
    const clientId = await register(OBSERVED_REMOTE_CALLBACK, "Claude");
    const query = authorizeQuery(clientId, OBSERVED_REMOTE_CALLBACK);

    const form = await call(new Request(`${ORIGIN}/authorize?${query}`));
    const body = await form.text();

    expect(form.status).toBe(200);
    expect(destinationFrom(body)).toBe("https://claude.ai");
    expect(body).toContain(SECRET_FIELD);

    const authorized = await call(
      post(LISTED_APPLE_ID, query, { "cf-connecting-ip": "203.0.113.31" }),
    );

    expect(authorized.status).toBe(302);
    expect(authorized.headers.get("location") ?? "").toContain(
      `${OBSERVED_REMOTE_CALLBACK}?code=`,
    );
  });

  it("completes the ceremony for a loopback callback on a DIFFERENT port", async () => {
    // Proves the loopback rule is a class rather than the port observed today.
    // Pinning today's port would break the next session — reproducing exactly
    // the lockout this deferral was protecting against.
    const clientId = await register(
      OTHER_PORT_LOOPBACK_CALLBACK,
      "Claude Code (icloud-mcp)",
    );
    const query = authorizeQuery(clientId, OTHER_PORT_LOOPBACK_CALLBACK);

    const form = await call(new Request(`${ORIGIN}/authorize?${query}`));
    const body = await form.text();

    expect(form.status).toBe(200);
    expect(destinationFrom(body)).toBe("http://localhost:51877");

    const authorized = await call(
      post(LISTED_APPLE_ID, query, { "cf-connecting-ip": "203.0.113.32" }),
    );

    expect(authorized.status).toBe(302);
    expect(authorized.headers.get("location") ?? "").toContain(
      `${OTHER_PORT_LOOPBACK_CALLBACK}?code=`,
    );
  });
});
