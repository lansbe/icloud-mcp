// The /authorize surface: one password field checked against a Workers
// Secret (D-01).
//
// The full OAuth 2.1 ceremony still happens around this — dynamic client
// registration, PKCE-protected code exchange, refresh rotation, revocation —
// all owned by the provider. Only the identity step is minimal, because this
// is a single-user server against one Apple ID and the goal is gating the
// endpoint, not building an identity system.
//
// The submitted secret is compared and nothing else: never echoed, never
// reflected into the rendered page, never logged, never included in an error.
// It is NOT, however, the only untrusted input in the flow. The redirect URI
// is attacker-chosen too — client registration is unauthenticated by spec —
// and it decides where the authorization code is delivered. That is why the
// page names the client and the destination before it asks for anything
// (CR-04). The consent screen is now the second of two controls in front of
// that URI, not the sole one: an origin allowlist refuses the class outright
// before the form is ever rendered. The screen still earns its place, because
// the allowlist's loopback entry is a CLASS rather than an exact value — an
// attacker can register a client whose callback is a loopback address on some
// port, and that passes the allowlist. The code would then be delivered to a
// listener on the owner's OWN machine, which is small residual risk but not
// zero, and the screen is what surfaces it: the owner sees a loopback address
// on the page when they expected the remote origin.
//
// ---------------------------------------------------------------------------
// One thing this file deliberately does NOT do. It is tracked, it was neither
// dropped nor half-implemented, and anyone tempted to add it should read the
// reason first — the omission is the decision.
//
// The failure counter is not atomic, and is not made atomic here.
// `get` -> compare -> `put` is a read-modify-write over an
// eventually-consistent store, so concurrent attempts all read the same
// value and the cap does not engage under parallel load. That is real and
// it remains. It is accepted because the counter is a tripwire, not the
// defence: the defence is a high-entropy secret compared in constant time,
// against which two hundred parallel guesses a round is nothing. Both fixes
// that would close it properly — a Durable Object, or a platform
// rate-limit binding — are new platform surface in a phase that
// deliberately took neither. Per-source keying (WR-02, above) already
// removed the harm that made this urgent: a stranger's failures no longer
// lock the owner out. What remains is that the cap UNDER-COUNTS a parallel
// attacker, not that the owner is denied service.
//
// A second omission stood here until 2026-08-14, and it was closed rather than
// quietly erased: this file used to record that it carried no allowlist of
// permitted redirect origins. What blocked that allowlist was never its cost —
// it was one constant then and it is one constant now. It was that the
// legitimate origin set was genuinely unobserved, and narrowing against a
// guess locks the owner out of their own server, which is worse than the
// outcome being prevented. Enumerating the live registration store on
// 2026-08-14 produced the real values and cleared the blocker. The observed
// set, the reasoning behind the matching rule, and the recovery for a wrong
// value now all live at ALLOWED_REDIRECT_ORIGINS below.
// ---------------------------------------------------------------------------

import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import type { ClientInfo } from "@cloudflare/workers-oauth-provider";
import { isConfiguredSecret } from "../configured-secret";
import type { Env, LoginGateSecret } from "../env";

/** The only scope this server issues. */
const SUPPORTED_SCOPES = ["mcp"];

/**
 * Fixed penalty on a failed attempt, before any response is written.
 *
 * One second, not the quarter second this started at, because the asymmetry
 * runs entirely one way: a human typing a password does not notice a second,
 * and a parallel guesser is not slowed by a quarter second either way — 200
 * concurrent guesses pay the delay in parallel, so the round costs whatever
 * one request costs. The only party a short delay was gentle to was the one it
 * was aimed at.
 *
 * This is also the limiter that does not depend on a durable counter
 * succeeding, which is why the counter's write is allowed to fail below and
 * this is not.
 */
const FAILURE_DELAY_MS = 1000;

/** Width of the brute-force counter's time bucket. */
const BUCKET_SECONDS = 300;

/** Failed attempts tolerated within one bucket before the form stops trying. */
const MAX_FAILURES_PER_BUCKET = 10;

/**
 * The exact origins this server will deliver an authorization code to.
 *
 * These values were OBSERVED, not guessed. On 2026-08-14 the live registration
 * store was enumerated and the legitimate redirect shapes read off the clients
 * that actually hold grants; everything else in there was a throwaway
 * verification registration. That measurement is the whole reason this
 * allowlist exists now and did not exist before — narrowing against a guess
 * was the risk that kept it deferred.
 *
 * Matching is EXACT EQUALITY on the origin derived by `originOf`, never a
 * substring test. That single choice is what makes three separate bypasses
 * fail without any of them being enumerated as a negative: a host that merely
 * ends with an allowed one is a different string, a cleartext scheme is a
 * different string, and `URL.origin` carries the port so an added port is a
 * different string too.
 *
 * The `.com` sibling of the entry below is deliberately ABSENT. It was
 * considered and declined, not missed: it was not observed, and pre-adding an
 * unobserved origin is the mirror image of the error this deferral existed to
 * avoid — widening against a guess instead of narrowing against one.
 *
 * If this value is ever wrong, the recovery is small and worth knowing before
 * panicking. This is a source constant, not stored state, so nothing saved has
 * to be edited or deleted. A wrong entry blocks only a NEW authorization: the
 * gate is on `/authorize` alone, while token refresh is served by the provider
 * at the token endpoint and never reaches this handler, so an already-issued
 * token keeps working. The fix is to read the refused origin out of the
 * refusal body this server just served, add it here, and deploy.
 */
const ALLOWED_REDIRECT_ORIGINS: readonly string[] = ["https://claude.ai"];

/**
 * The one origin CLASS admitted alongside the exact entries above: loopback.
 *
 * The port is optional and deliberately unpinned. A local client binds an
 * ephemeral port and re-binds a different one next session, so pinning the
 * value observed on any given day breaks the very next authorization —
 * reproducing exactly the lockout this work was deferred to avoid. This is the
 * standard OAuth native-app carve-out and not laxness invented here: RFC 8252
 * section 7.3 states that a loopback redirect's port is assigned at runtime and
 * that the authorization server MUST allow any port.
 *
 * This is also the only place the cleartext scheme is permitted, and it is safe
 * precisely because a loopback address is unreachable from anywhere but the
 * owner's own machine. Traffic on that interface never leaves the host, so
 * there is no transport to expose; an attacker positioned to receive on it
 * already has the machine.
 *
 * The TLS form of loopback is deliberately NOT admitted. It was not observed,
 * and this rule stays the observed shape plus the RFC's carve-out.
 *
 * Anchored at both ends on purpose. Without the anchors a public host that
 * merely BEGINS with a loopback name would be admitted, which is the bypass
 * `test/authorize-redirect-allowlist.test.ts` pins with its own named cases.
 */
const LOOPBACK_REDIRECT_ORIGIN =
  /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/;

/**
 * The entire body served when this deployment has no configured secret.
 *
 * Exported so the test asserts against the value the handler actually serves
 * rather than a second copy of the sentence that could drift from it. It is a
 * fixed constant: it names no binding, interpolates nothing, and never varies.
 */
export const UNCONFIGURED_BODY =
  "This server is not configured to issue authorizations.";

/**
 * The entire body served for any path this server does not have.
 *
 * Exported for the same reason `UNCONFIGURED_BODY` is: so the test asserts
 * against the value the handler actually serves rather than a second copy of
 * the sentence that could drift from it. Unlike that constant this one varies —
 * with the request's own origin — so it is a function rather than a string, and
 * the origin is a parameter rather than a hostname read from anywhere else.
 *
 * Naming the endpoint here discloses nothing new. The
 * `/.well-known/oauth-protected-resource/mcp` document already publishes
 * `resource: <origin>/mcp` to any unauthenticated caller — `test/auth-ordering.test.ts`
 * asserts exactly that — so the URL is already public and a 404 that repeats it
 * gives a stranger nothing they could not fetch with one request. Recorded here
 * because a bare 404 looks like the more cautious choice and is not: it is the
 * same disclosure posture with the legitimate user removed from it.
 *
 * The origin is taken from the caller rather than pinned to a constant, and the
 * pinned alternative was specifically declined. Importing the deployed hostname
 * from the MCP module would make this module depend on that one for a display
 * string, and would go silently stale the day the hostname changes; the
 * reflected value is one the sender supplied in their own Host header, so it
 * tells them nothing, and it is served as plain text with no redirect and no
 * markup interpretation anywhere.
 *
 * The response body is the only channel available for saying any of this:
 * Convention 4 forbids logging on this path, exactly as it does on the
 * unconfigured-deployment path below, so a self-describing response is what
 * stands in for a diagnostic nobody can read.
 */
export function notFoundBody(origin: string): string {
  return `This path does not exist on this server.

The MCP endpoint is ${origin}/mcp

Point your MCP client at that full URL, including the /mcp path. Authorization is served from ${origin} itself, so a client configured with the bare origin can complete the entire authorization ceremony successfully and still be unable to open a session.`;
}

/**
 * The configured-secret predicate, re-exported unchanged from where it now
 * lives.
 *
 * This is a compatibility surface and nothing else — no wrapper, no second
 * implementation. The definition now lives in the root module
 * `src/configured-secret.ts`. The five source importers (`src/confirm.ts`,
 * `src/staging/presign.ts`, `src/mail/credentials.ts`, `src/dav/transport.ts`
 * and `src/dav/discovery.ts`) and `test/authorize-secret.test.ts` resolve the
 * name from this module, and keeping them unedited is the evidence that the
 * move was mechanical. This handler also calls the function itself, which is
 * why it holds an import above as well as this statement.
 */
export { isConfiguredSecret };

/**
 * The counter's key: the time bucket AND the connecting client's address.
 *
 * The bucket alone used to be the whole key, which made every failure
 * everyone's failure. Ten failed POSTs a bucket — from anyone who knew the
 * hostname, at a cost of ten HTTP requests, sustainable indefinitely — put
 * every subsequent /authorize POST behind a 429 with a five-minute
 * retry-after, the owner's own included. The MCP endpoint then stops being
 * usable the moment the current access token expires, and no secret is ever
 * guessed: the denial is the whole attack (WR-02).
 *
 * The fallback literal is load-bearing. A request arriving without the header
 * must still be counted, or the cheapest way past the counter would be to send
 * one fewer header.
 */
function failureKey(request: Request): string {
  const bucket = Math.floor(Date.now() / 1000 / BUCKET_SECONDS);
  const source = request.headers.get("cf-connecting-ip") ?? "unknown-source";
  return `authorize-failures:${bucket}:${source}`;
}

/**
 * Who is asking, and where authorizing will send the browser.
 *
 * Both values originate outside this server: the name arrives through
 * unauthenticated dynamic client registration, and the redirect URI is the one
 * the code will be delivered to. They are display-only — nothing branches on
 * either — and both are escaped at the interpolation.
 */
interface ClientIdentity {
  /** The registered name, or the client id when the client registered none. */
  name: string;
  /** The full redirect URI. Only its origin is ever displayed. */
  redirectUri: string;
}

/** The body served when the provider cannot resolve the requesting client. */
function unknownClientResponse(): Response {
  return new Response("Unknown OAuth client", { status: 400 });
}

function identityOf(client: ClientInfo, redirectUri: string): ClientIdentity {
  // Falling back to the id rather than to a placeholder: a client that
  // registered no name is still identified, and a blank space where an
  // identity should be is exactly what CR-04 is about.
  return { name: client.clientName ?? client.clientId, redirectUri };
}

/**
 * The destination, reduced to an origin — the ONE derivation, shared.
 *
 * The path and query are deliberately dropped. A long attacker-chosen path
 * would push the origin — the only part that says who receives the code — out
 * of view on a narrow screen, which would leave the identity technically
 * present and practically invisible.
 *
 * Null means only that `new URL()` could not read the value. Callers decide
 * what to do with that: the page renders a sentence saying so, and the
 * allowlist check treats it as not-allowed, so an unreadable destination fails
 * closed rather than falling through some parsing accident into permitted.
 */
function originOf(redirectUri: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return null;
  }

  // `origin` is the literal string "null" for a non-special scheme, which is
  // the shape a native client's custom-scheme callback has. Scheme and host
  // are still bounded, and still not the path.
  if (parsed.origin && parsed.origin !== "null") return parsed.origin;
  return parsed.host ? `${parsed.protocol}//${parsed.host}` : parsed.protocol;
}

/**
 * The destination as the consent screen shows it.
 *
 * The reduction itself lives in `originOf`, and the sharing is the point
 * rather than a tidiness: the allowlist check evaluates the value this
 * function displays. Were the two to derive the origin separately, the page
 * could name an origin the check never looked at — a mitigation that lies
 * about what it mitigated.
 */
function displayDestination(redirectUri: string): string {
  // Showing the raw string instead would reintroduce the very
  // push-the-origin-out-of-view problem origin-only display exists to stop.
  return originOf(redirectUri) ?? "an address this server could not read";
}

/**
 * Whether a derived origin is one this server will send a code to.
 *
 * Null is false, which is the fail-closed edge: a redirect URI this server
 * cannot parse is refused rather than admitted.
 *
 * Exported so a test can drive a table of shapes straight at the predicate.
 * That is both cheaper and far more exhaustive than routing every bypass
 * candidate through the handler; the handler-level cases still exist, and are
 * what prove the predicate is actually wired to anything.
 */
export function isAllowedRedirectOrigin(origin: string | null): boolean {
  if (origin === null) return false;
  return (
    ALLOWED_REDIRECT_ORIGINS.includes(origin) ||
    LOOPBACK_REDIRECT_ORIGIN.test(origin)
  );
}

/**
 * The entire body served when a redirect origin is refused.
 *
 * Exported for the reason `notFoundBody` is: so the test asserts the value the
 * handler actually serves rather than a second copy of the sentence, which
 * could drift from it. It is a function rather than a constant because the
 * value varies — with the destination that was refused.
 *
 * It takes an ALREADY-REDUCED destination, never the raw URI, and both
 * consequences are the point: the attacker's chosen path never reaches this
 * body, and an unparseable URI arrives pre-rendered as a sentence rather than
 * needing a second null branch here.
 *
 * The body carries the recovery in full because there is nowhere else to put
 * it. Convention 4 forbids logging anywhere under src/, so the response is the
 * only diagnostic channel that exists, and the only party a refusal can lock
 * out is the owner — who has nothing else to read. Naming the source file to
 * an unauthenticated caller is the same disclosure posture `notFoundBody`
 * already takes and the same reasoning: a stranger cannot edit that file, and
 * withholding it helps only against the party it cannot hurt.
 */
export function refusedRedirectBody(destination: string): string {
  return `This server is not permitted to send an authorization code to that destination.

Refused destination: ${destination}

Existing authorizations are unaffected. This check gates /authorize only — token refresh is served by the OAuth token endpoint and never reaches it — so a client that already holds a token keeps working. Nothing has been revoked and the server is not down.

If that destination is genuinely yours, add its origin to ALLOWED_REDIRECT_ORIGINS in src/auth/login-handler.ts and deploy. The allowlist is a source constant rather than stored state, so nothing saved has to be edited or deleted to recover.`;
}

/**
 * Refuse a destination outside the allowlist — or null to carry on.
 *
 * Rendered LOCALLY, and never as a redirect. This file already states the rule
 * this obeys one function down: redirecting an unvalidated URI is what
 * CVE-class bugs in this problem space are made of. Redirecting to an origin
 * that was just refused would be that bug with an extra step, so nothing here
 * constructs a URL from the redirect URI, sets a Location header, or calls
 * `Response.redirect`.
 *
 * 403 rather than 400, because 400 is already this file's answer for a
 * MALFORMED request. A refused origin is well-formed and understood, and
 * declined by policy. The distinction costs nothing and lets a test tell the
 * two apart — which matters, because a regression that silently turned the
 * allowlist off would otherwise hide behind a status this file returns for
 * three other reasons.
 *
 * Placement is load-bearing at all three of its edges. BELOW the POST cap
 * check, so an over-cap source still gets its 429 without the provider being
 * consulted. ABOVE `lookupClient`, so a doomed request does not buy a store
 * round trip — the same argument the resolution comment below already makes
 * about free amplification. ABOVE the secret comparison, so a CORRECT secret
 * cannot purchase a code for a destination this server will not send to. That
 * last edge discloses nothing: the answer is a pure function of the
 * requester's own redirect URI.
 *
 * The failure counter is deliberately not touched here. It counts guesses at
 * the secret, and a refused destination is not one.
 */
function refusedRedirectResponse(redirectUri: string): Response | null {
  if (isAllowedRedirectOrigin(originOf(redirectUri))) return null;

  return new Response(refusedRedirectBody(displayDestination(redirectUri)), {
    status: 403,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Compare a submitted value against the configured secret in constant time.
 *
 * Both sides are SHA-256 digested first and the two 32-byte digests compared.
 * Digesting first is not decoration: the runtime's comparison throws on
 * inputs of unequal length, and a throw that only happens for the wrong
 * length is itself an oracle for the secret's length. Digests are always 32
 * bytes, so the comparison is reached unconditionally.
 *
 * A plain `===` here would be a timing oracle, and no comparison loop is
 * hand-rolled anywhere in this repository — all cryptography is the
 * runtime's or the OAuth library's.
 *
 * A missing or empty configured value is refused rather than compared: it is
 * not a secret, and digesting it would make the empty submission match (CR-01).
 * That short-circuit reads only a server-side configuration fact, never a
 * property of the submitted value, so it adds no timing signal an attacker can
 * influence.
 */
async function secretMatches(
  submitted: string,
  expected: string | undefined,
): Promise<boolean> {
  if (!isConfiguredSecret(expected)) return false;

  const encoder = new TextEncoder();
  const submittedDigest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(submitted),
  );
  const expectedDigest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(expected),
  );
  return crypto.subtle.timingSafeEqual(submittedDigest, expectedDigest);
}

function renderForm(
  query: string,
  failed: boolean,
  identity: ClientIdentity,
): Response {
  const notice = failed
    ? '<p class="err">That value was not accepted.</p>'
    : "";

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iCloud MCP — authorize</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0;
         min-height: 100dvh; display: grid; place-items: center; }
  main { width: min(22rem, 90vw); }
  h1 { font-size: 1.125rem; margin: 0 0 .25rem; }
  p { margin: 0 0 1.25rem; opacity: .7; font-size: .875rem; }
  .err { color: #b3261e; opacity: 1; }
  .who { opacity: 1; }
  .client { overflow-wrap: anywhere; }
  .dest { overflow-wrap: anywhere; }
  label { display: block; font-size: .8125rem; margin-bottom: .375rem; }
  input { width: 100%; box-sizing: border-box; padding: .625rem .75rem;
          font: inherit; border: 1px solid currentColor; border-radius: .5rem;
          background: transparent; color: inherit; }
  button { width: 100%; margin-top: .75rem; padding: .625rem;
           font: inherit; border: 0; border-radius: .5rem; cursor: pointer; }
</style>
</head>
<body>
<main>
  <h1>Authorize iCloud MCP</h1>
  <p>This endpoint reaches real personal mail.</p>
  <p class="who"><strong class="client">${escapeHtml(identity.name)}</strong>
     is asking for that access. Authorizing sends you to
     <code class="dest">${escapeHtml(displayDestination(identity.redirectUri))}</code>.
     If you do not recognise both, do not continue.</p>
  ${notice}
  <form method="post" action="/authorize">
    <input type="hidden" name="oauth_request" value="${escapeHtml(query)}">
    <label for="secret">Access secret</label>
    <input id="secret" name="secret" type="password" autocomplete="off"
           autofocus required>
    <button type="submit">Authorize</button>
  </form>
</main>
</body>
</html>`,
    {
      status: failed ? 401 : 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    },
  );
}

function authorizationErrorResponse(error: AuthorizationError): Response {
  // An unknown client or an unregistered redirect URI must be rendered
  // locally — redirecting an unvalidated URI is what CVE-class bugs in this
  // problem space are made of.
  if (!error.redirectUri) {
    return new Response(error.description, { status: 400 });
  }

  const redirect = new URL(error.redirectUri);
  redirect.searchParams.set("error", error.code);
  redirect.searchParams.set("error_description", error.description);
  if (error.state) redirect.searchParams.set("state", error.state);
  if (error.issuer) redirect.searchParams.set("iss", error.issuer);
  return Response.redirect(redirect.toString(), 302);
}

/**
 * The provider's `defaultHandler`: everything that is not an API request.
 *
 * Only `/authorize` is ours. The token, registration, and metadata endpoints
 * are implemented by the provider itself and never reach this handler.
 */
export const loginHandler = {
  async fetch(
    request: Request,
    env: Env & LoginGateSecret,
  ): Promise<Response> {
    const url = new URL(request.url);

    // Still a 404 — the path genuinely does not exist — but one that says where
    // the client should have gone. The condition is left exactly as it was:
    // every non-/authorize path gets this, with no special case for the bare
    // origin, because "the client was pointed somewhere wrong" is the whole
    // failure class and the bare origin is only its most common member.
    if (url.pathname !== "/authorize") {
      return new Response(notFoundBody(url.origin), {
        status: 404,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    // Fail closed before method dispatch, so neither verb can reach the form
    // or the comparison while this deployment has nothing to compare against
    // (CR-01). 503 rather than 401 is deliberate: 401 would tell the owner
    // they mistyped a value that is in fact absent, sending them hunting for a
    // typo instead of a missing binding, and the distinction gives nothing
    // exploitable to a party who cannot authenticate either way. It has to be
    // the status code carrying that signal — Convention 4 forbids logging on
    // this path, so a self-describing response is the only channel left.
    if (!isConfiguredSecret(env.AUTH_SECRET)) {
      return new Response(UNCONFIGURED_BODY, {
        status: 503,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    if (request.method === "GET") {
      let oauthRequest;
      try {
        oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      } catch (error) {
        if (!(error instanceof AuthorizationError)) throw error;
        return authorizationErrorResponse(error);
      }

      // Refuse a destination outside the allowlist before anything else is
      // spent on this request. `parseAuthRequest` has already confirmed the URI
      // is one this client actually registered, so what happens here is a
      // NARROWING of what may be registered-and-used — not a replacement for
      // that validation.
      const refusedGet = refusedRedirectResponse(oauthRequest.redirectUri);
      if (refusedGet) return refusedGet;

      // Resolve who is asking BEFORE rendering, not after the secret has been
      // accepted (CR-04). A client the provider cannot resolve cannot be
      // named, and a form that cannot say what it is authorizing is worse than
      // no form: it invites a submission the owner has no way to evaluate.
      const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
      if (!client) return unknownClientResponse();

      // The raw query is round-tripped rather than the parsed object, so the
      // POST re-runs the provider's own client, redirect-URI, response-type
      // and PKCE validation against it. A tampered hidden field is then
      // rejected by the library rather than trusted by this handler.
      return renderForm(
        url.search.replace(/^\?/, ""),
        false,
        identityOf(client, oauthRequest.redirectUri),
      );
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { allow: "GET, POST" },
      });
    }

    const form = await request.formData();
    const submitted = String(form.get("secret") ?? "");
    const query = String(form.get("oauth_request") ?? "");

    // Brute-force mitigation, deliberately kept this small: a coarse
    // time-bucketed counter in the KV namespace that already exists, and a
    // fixed delay. Not a rate-limiting subsystem.
    const key = failureKey(request);
    const failures = Number((await env.OAUTH_KV.get(key)) ?? "0");
    if (failures >= MAX_FAILURES_PER_BUCKET) {
      await new Promise((resolve) => setTimeout(resolve, FAILURE_DELAY_MS));
      return new Response("Too many attempts. Try again shortly.", {
        status: 429,
        headers: { "retry-after": String(BUCKET_SECONDS) },
      });
    }

    // Resolution sits BELOW the cap check and ABOVE the comparison, and both
    // edges are deliberate.
    //
    // Below the cap check, because an over-cap source must not buy a provider
    // round trip per request — that is free amplification precisely when the
    // limiter is trying to make requests cheap.
    //
    // Above the comparison, because the failure re-render has to carry the
    // same identity the first render did; a second attempt should be no less
    // informed than the first.
    const rebuilt = new Request(`${url.origin}/authorize?${query}`);
    let oauthRequest;
    try {
      oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(rebuilt);
    } catch (error) {
      if (!(error instanceof AuthorizationError)) throw error;
      // Deliberate status change on an unauthenticated path, and not an
      // accident: a request whose oauth_request cannot be resolved used to
      // reach the comparison first and, with a wrong secret, came back as the
      // 401 form. It now comes back as this local 400 instead. There is no
      // identity to render and no comparison worth running, and the 400
      // discloses nothing new — it is a function purely of the request's own
      // well-formedness, which its sender already knows, and it says nothing
      // about whether the submitted secret was right, wrong, or absent. It is
      // rendered locally rather than redirected, exactly as before.
      return authorizationErrorResponse(error);
    }

    // Same check as the GET path, and the second call site is the whole point:
    // a check on one verb only is a hole, because the POST is what actually
    // issues the code. It sits above the comparison as well as above the
    // lookup, so a correct secret buys nothing for a refused destination.
    const refusedPost = refusedRedirectResponse(oauthRequest.redirectUri);
    if (refusedPost) return refusedPost;

    const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
    if (!client) return unknownClientResponse();

    const identity = identityOf(client, oauthRequest.redirectUri);

    if (!(await secretMatches(submitted, env.AUTH_SECRET))) {
      try {
        await env.OAUTH_KV.put(key, String(failures + 1), {
          expirationTtl: BUCKET_SECONDS * 2,
        });
      } catch {
        // The store throttles writes to the same key, so a burst makes this
        // write reject. Unhandled, that rejection turned a 401 into a 500 for
        // identical input — an observable oracle telling an attacker their
        // burst landed, which is precisely the signal a brute-force counter
        // should not hand out (WR-01). Swallowed deliberately and swallowed
        // silently: Convention 4 forbids logging anywhere under src/, and
        // there is nothing here worth a response field either. The fixed
        // delay below is the limiter that does not depend on this write
        // succeeding.
      }
      await new Promise((resolve) => setTimeout(resolve, FAILURE_DELAY_MS));
      return renderForm(query, true, identity);
    }

    // Grant what was asked for, narrowed to what this server supports. A
    // client that asks for nothing gets the one scope that exists, because a
    // single-user single-scope server has nothing meaningful to withhold.
    const requested = oauthRequest.scope.filter((scope) =>
      SUPPORTED_SCOPES.includes(scope),
    );
    const granted = requested.length > 0 ? requested : [...SUPPORTED_SCOPES];

    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthRequest,
      userId: "owner",
      metadata: { clientName: client.clientName },
      scope: granted,
      props: { userId: "owner" },
    });

    return Response.redirect(redirectTo, 302);
  },
};
