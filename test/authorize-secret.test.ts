// The CR-01 proof: /authorize must never authorize while it has no configured
// secret.
//
// Every case in this file fails against the pre-fix implementation, which is
// the only thing that makes them worth having — a criterion that passed before
// and after the change would verify nothing. Pre-fix there was no
// `isConfiguredSecret` and no exported body constant, so the predicate cases
// could not even be written; and the two cases that matter most (an absent
// binding, an empty binding) did not merely return a different status, they
// minted a live authorization code.
//
// The mechanism, for a reader who has not opened REVIEW.md:
// `TextEncoder.prototype.encode` is declared `encode(optional USVString input
// = "")`. An unset Workers Secret binding is `undefined` at runtime, which
// resolves to the WebIDL default `""` rather than throwing or stringifying to
// `"undefined"`. Both sides of the comparison became the SHA-256 digest of the
// empty string, `timingSafeEqual` returned true, and a POST carrying `secret=`
// completed the ceremony against an endpoint that reaches real personal mail.
// Pre-fix that POST reached `parseAuthRequest` on an empty rebuilt query and
// answered 400 with an `AuthorizationError` body — never 503.
//
// The 503 body is asserted against the constant the handler itself serves, not
// a re-typed copy, so a reworded sentence cannot pass silently.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  UNCONFIGURED_BODY,
  isConfiguredSecret,
  loginHandler,
} from "../src/auth/login-handler";
import type { Env, LoginGateSecret } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The value the workers pool binds AUTH_SECRET to (see vitest.config.ts). */
const BOUND_SECRET = "test-secret-not-real";

/**
 * An env carrying only what the refusal path can reach.
 *
 * The guard returns before `OAUTH_PROVIDER` is touched, so leaving it out is
 * not a shortcut — it is a second, structural assertion that the refusal never
 * reaches the provider. A case that needs the provider passes its own stub.
 */
function envWithSecret(
  secret: string | undefined,
  provider?: unknown,
): Env & LoginGateSecret {
  return {
    OAUTH_KV: env.OAUTH_KV,
    OAUTH_PROVIDER: provider,
    AUTH_SECRET: secret,
  } as unknown as Env & LoginGateSecret;
}

/**
 * The smallest provider a wrong-secret POST now reaches.
 *
 * Plan 01-11 moved client resolution above the secret comparison, so the
 * failure re-render can name the client it is refusing (CR-04). A POST that
 * expects the 401 form therefore has to carry a provider that resolves —
 * before that change the comparison was reached first and the provider was
 * never consulted on this path. Nothing here is asserted against; it exists so
 * the cases below still exercise the refusal they were written for.
 */
function resolvingProvider() {
  return {
    parseAuthRequest: async () => ({
      responseType: "code",
      clientId: "abc",
      // On an allowed origin since window 8: the handler's redirect-origin
      // allowlist would otherwise refuse these requests with a 403 before they
      // reached the CR-01 refusal each case was written to exercise.
      redirectUri: "https://claude.ai/cb",
      scope: [],
      state: "",
    }),
    lookupClient: async () => ({ clientId: "abc", clientName: "Test Client" }),
  };
}

function authorizeGet(): Request {
  return new Request(`${ORIGIN}/authorize?response_type=code&client_id=abc`);
}

function authorizePost(secret: string, query = "response_type=code&client_id=abc"): Request {
  const body = new URLSearchParams({ secret, oauth_request: query });
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
}

describe("isConfiguredSecret", () => {
  it("accepts only a non-empty string", () => {
    // Distinguishes from pre-fix, where the predicate did not exist at all and
    // an absent binding was indistinguishable from an empty one at the
    // comparison.
    expect(isConfiguredSecret(undefined)).toBe(false);
    expect(isConfiguredSecret(null)).toBe(false);
    expect(isConfiguredSecret("")).toBe(false);
    expect(isConfiguredSecret("x")).toBe(true);
    expect(isConfiguredSecret(BOUND_SECRET)).toBe(true);
  });
});

describe("an unconfigured deployment refuses to authorize", () => {
  it("refuses a POST with an empty submitted value when the binding is absent", async () => {
    // The exploit, exactly as reported. Distinguishes from pre-fix, where this
    // request passed the comparison and answered 400 from `parseAuthRequest`
    // on its way to issuing a code.
    const response = await loginHandler.fetch(
      authorizePost(""),
      envWithSecret(undefined),
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
  });

  it("refuses a POST when the binding is present but empty", async () => {
    // An empty binding is as dangerous as an absent one: it is the value the
    // absent one decays to. Distinguishes from pre-fix, where both digested to
    // the same 32 bytes and matched.
    const response = await loginHandler.fetch(
      authorizePost(""),
      envWithSecret(""),
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
  });

  it("refuses a GET rather than serving the login form", async () => {
    // The guard sits above method dispatch, so a GET never reaches the form.
    // Distinguishes from pre-fix, which rendered the form (200, text/html) and
    // invited a submission that would have succeeded.
    const response = await loginHandler.fetch(
      authorizeGet(),
      envWithSecret(undefined),
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("still 404s every path other than /authorize", async () => {
    // The gate belongs inside the /authorize branch only. If it had been
    // placed above the pathname check, this would answer 503 and
    // `defaultHandler` would become a second reachable surface — the exact
    // shape REVIEW.md checked and cleared.
    const response = await loginHandler.fetch(
      new Request(`${ORIGIN}/anything-else`),
      envWithSecret(undefined),
    );

    expect(response.status).toBe(404);
  });
});

describe("a configured deployment behaves exactly as before", () => {
  it("still answers a wrong value with 401 and the form", async () => {
    const response = await loginHandler.fetch(
      authorizePost("definitely-not-the-secret"),
      envWithSecret(BOUND_SECRET, resolvingProvider()),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toContain("That value was not accepted.");
  });

  it("lets the correct value past the guard and into the provider", async () => {
    // The positive control, without which every case above is satisfied by a
    // guard that refuses everything. The stub stops the ceremony one step past
    // the comparison: `parseAuthRequest` records that it was reached, and an
    // unknown client ends the request at 400 rather than issuing a code.
    let parseAuthRequestReached = false;
    const provider = {
      parseAuthRequest: async () => {
        parseAuthRequestReached = true;
        // `redirectUri` was missing here, and only the cast to Env hid that
        // from the compiler — `AuthRequest.redirectUri` is typed non-optional,
        // so a real parse always supplies it and this stub was simply wrong.
        // It matters now as well as being wrong then: since window 8 an absent
        // value derives no origin, fails the allowlist closed, and would answer
        // 403 before reaching the client lookup this case asserts on.
        return {
          clientId: "test-client",
          redirectUri: "https://claude.ai/cb",
          scope: [],
        };
      },
      lookupClient: async () => null,
    };

    const response = await loginHandler.fetch(
      authorizePost(BOUND_SECRET),
      envWithSecret(BOUND_SECRET, provider),
    );

    expect(parseAuthRequestReached).toBe(true);
    expect(response.status).not.toBe(503);
    expect(response.status).toBe(400);
  });
});

describe("no refusal discloses the binding", () => {
  it("never names the secret binding in any response body", async () => {
    const bodies = await Promise.all([
      loginHandler
        .fetch(authorizeGet(), envWithSecret(undefined))
        .then((r) => r.text()),
      loginHandler
        .fetch(authorizePost(""), envWithSecret(undefined))
        .then((r) => r.text()),
      loginHandler
        .fetch(authorizePost(""), envWithSecret(""))
        .then((r) => r.text()),
      loginHandler
        .fetch(
          authorizePost("wrong"),
          envWithSecret(BOUND_SECRET, resolvingProvider()),
        )
        .then((r) => r.text()),
    ]);

    for (const body of bodies) {
      expect(body).not.toContain("AUTH_SECRET");
    }
  });
});
