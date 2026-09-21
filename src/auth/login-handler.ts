// The /authorize surface: a person signs in with their OWN Apple ID and app-
// specific password, and the credentials go into the grant's encrypted props.
//
// **Phase 11 replaced what this file asks for.** It used to ask for one shared
// secret and compare it against a Workers Secret (D-01), which is how a
// single-user server against one Apple ID identified its one user. The server
// now has N users, and identity moved out of the environment and into the
// grant. So the form asks for an Apple ID and an app-specific password, the
// address is checked against an allow list before anything else is spent on it,
// one IMAP login proves the pair, and `completeAuthorization` stores both in
// props that only this server can decrypt. `src/principal.ts` is where they
// come back out.
//
// **This file renders nothing.** Every byte the reader sees is built by
// `src/auth/login-page.ts`, which owns the approved design contract, the copy
// and the security headers; this file decides WHICH response happens and in
// what order, and calls into the page for the one that has a body worth
// designing. That split is a locked decision rather than a tidiness: this file
// was already 32 KB before the phase added a credential form and three limiter
// layers to it.
//
// The full OAuth 2.1 ceremony still happens around this — dynamic client
// registration, PKCE-protected code exchange, refresh rotation, revocation —
// all owned by the provider. Only the identity step is ours.
//
// **The submitted credentials are spent and nothing else**: never echoed, never
// reflected into the rendered page, never logged, never included in an error,
// and never put in any store but the grant's own props. No object holding the
// password is constructed here — `principalFromProps` builds the one principal
// and keeps the password in its own holder, and this file never asks for it
// back. The password reader is not imported here and must never be.
//
// The credentials are NOT, however, the only untrusted input in the flow. The
// redirect URI
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
// it remains for now.
//
// **This omission is being RETIRED rather than defended, and it is worth
// knowing which.** It was accepted while the thing behind the form was a
// high-entropy shared secret compared in constant time, against which two
// hundred parallel guesses a round is nothing. That argument left with the
// secret. What sits behind the form now is a person's real Apple app-
// specific password, and the cost of a guess is no longer this server's
// alone: attempts land at Apple, whose own lockout threshold is unpublished
// and must be assumed small.
//
// So the counter is being REPLACED, not made atomic. Plan 11-05 is where,
// and it takes one of the two fixes this paragraph used to say the phase
// had declined: a platform rate-limit binding, alongside a per-Apple-ID
// counter keyed by the hashed address rather than by the connecting
// source. A Durable Object was compared and declined for v2.0 on deploy
// risk; 11-CONTEXT.md records that comparison in full so a later phase
// does not have to re-derive it.
//
// Until that lands, what remains is unchanged: per-source keying (WR-02,
// above) means a stranger's failures do not lock the owner out, and the cap
// UNDER-COUNTS a parallel attacker rather than denying service.
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
import { ImapConnectError, ImapThrottleError } from "../errors";
import type { SessionGate } from "../mail/service";
import { createSessionGate, withMailSession } from "../mail/service";
import type { Principal } from "../principal";
import { normaliseAppleId, principalFromProps, userIdOf } from "../principal";
import type { AllowList } from "./allow-list";
import { isAllowed, parseAllowList } from "./allow-list";
import { RESPONSE_HEADERS, SOURCE_REFUSAL_BODY, renderForm } from "./login-page";

/** The only scope this server issues. */
const SUPPORTED_SCOPES = ["mcp"];

/** The version every props object this server writes carries. */
const PROPS_VERSION = 1;

/**
 * The form field carrying the Apple ID.
 *
 * Exported so `src/auth/login-page.ts` writes the very name this file reads.
 * Two spellings of a field name are two rules, and the failure is silent: the
 * form renders, the person types, and the submitted value arrives under a name
 * nothing looks for, which reaches the reader as the generic failure body.
 */
export const APPLE_ID_FIELD = "apple_id";

/** The form field carrying the app-specific password. Exported for the same reason. */
export const APP_PASSWORD_FIELD = "app_password";

/**
 * The shortest a submitted value may be, once dashes are stripped.
 *
 * This bound exists to refuse a FRAGMENT: a paste that caught half the value,
 * a couple of characters typed into the wrong box, a value that was cut short
 * by a copy that ended early. Eight is well under the one length anyone here
 * has ever seen from Apple, so it refuses nothing plausible.
 */
const MIN_CANONICAL_APP_PASSWORD = 8;

/**
 * The longest a submitted value may be, once dashes are stripped.
 *
 * This bound exists for an entirely different reason from the one above, and
 * the pair is deliberately not one rule with two ends. It refuses a
 * PASSPHRASE — a sentence, a paragraph, a whole paste of something that was
 * never a credential. Sixty-four is four times the one observed length, so an
 * Apple grammar with twice the groups, or twice the characters per group,
 * still passes.
 *
 * Neither bound tries to tell an app-specific password from a real Apple ID
 * password. It cannot be done by length — Apple's account password is eight or
 * more characters and can be sixteen too — and pretending otherwise is exactly
 * the over-tight rule the locked decision refuses.
 */
const MAX_CANONICAL_APP_PASSWORD = 64;

/**
 * The submitted app-specific password, reduced to the one form this server
 * uses.
 *
 * **One function, one place, and the direction is a decision rather than a
 * detail.** It strips the separators Apple displays and trims the ends, and
 * what it returns is BOTH what goes to Apple and what goes into the grant's
 * props. That is the point: the value the login proves and the value every
 * later request replays are the same bytes by construction, so they cannot
 * drift apart.
 *
 * Whitespace is trimmed at the ends only. Anything left in the middle is not
 * repaired here — `couldBeAppPassword` refuses it, because a value with a space
 * inside is far more likely to be a sentence than a credential, and silently
 * removing it would send a guess to Apple on the person's behalf.
 *
 * **The direction is gated on spike S5**, which is a manual check on the
 * owner's own account: no automated job in this repository may authenticate
 * against a real Apple ID, so nothing here can settle whether iCloud wants the
 * dashed form or the dashless one. Plan 11-07 runs S5 before the single deploy.
 * If it shows iCloud wants the dashes, the inversion is THIS FUNCTION and
 * nothing else — the caller, the props and the wire all follow whatever it
 * answers. The person typing may use either form either way.
 */
function canonicalAppPassword(submitted: string): string {
  return submitted.trim().replaceAll("-", "");
}

/**
 * Could this be an app-specific password at all? (LOGIN-03)
 *
 * It takes the ALREADY-CANONICAL value, never the raw one, and that is the same
 * habit `refusedRedirectBody` follows in taking an already-reduced destination:
 * the check and the thing that gets used are then provably the same value,
 * rather than two derivations that could disagree.
 *
 * **This check is LOOSE on purpose, and this is the rule a later session will
 * be most tempted to tighten.** The argument, written here because a planning
 * file is not where the tempted reader will be looking:
 *
 * - **Apple publishes no format.** Its own support page for app-specific
 *   passwords covers creating, managing and revoking them and says nothing
 *   about length, character set or grouping. The four-groups-of-four shape is
 *   training knowledge plus exactly one observed sample — the owner's own.
 * - **The question it answers is "is this clearly not an app-specific
 *   password", never "is this exactly the grammar I remember".** A strict rule
 *   that is wrong refuses a legitimate family member behind a failure message
 *   that deliberately will not say why, and they have no way to learn the
 *   reason.
 * - **The requirement is still satisfied.** A clearly-wrong value is refused
 *   before any socket opens, because this function does no I/O and sits above
 *   the one proof call site.
 * - **The cost accepted:** a typo inside the band costs one attempt at Apple
 *   and one tick of the per-target counter, instead of being caught locally.
 * - **Do not tighten this into the observed grammar to catch more typos.** That
 *   reverses a decision made on 2026-09-20 with the silent-failure cost in
 *   view. Refusing more is safe for a user id, where a refusal is a fresh start;
 *   it is not safe here, where a refusal is a person locked out of a page that
 *   will not tell them why.
 *
 * Exactly three classes are refused and there is no fourth: an empty value; a
 * value still carrying white space once the dashes are gone; and a length
 * outside the band the two constants above describe.
 *
 * **It does not duplicate `isUsablePassword`**, which lives in
 * `src/principal.ts` and refuses a whitespace-only value and any control
 * character. That one runs SECOND, inside the principal constructor, and it is
 * the deeper of the two: it guards every construction site, including the
 * props read at the door on a later request, where no form was ever submitted.
 * This one runs FIRST because it is the only one of the two that can refuse
 * before a principal is built at all — which is what makes "nothing was opened
 * to Apple" true of the shape refusal rather than merely likely.
 */
function couldBeAppPassword(canonical: string): boolean {
  if (canonical.length === 0) return false;
  if (/\s/.test(canonical)) return false;
  return (
    canonical.length >= MIN_CANONICAL_APP_PASSWORD &&
    canonical.length <= MAX_CANONICAL_APP_PASSWORD
  );
}

/**
 * What it takes to prove a credential pair is real: one login, at Apple.
 *
 * Resolves to nothing on success and REJECTS on failure, so the caller branches
 * on the error's type and never on a returned flag. There is no value here to
 * carry a credential out on: the principal goes in, the session spends it, and
 * what comes back is either nothing or a throw built with no argument.
 *
 * It exists as a type so the one call can be INJECTED. D-09 forbids any
 * automated login to a real Apple ID — no test, CI job, pre-commit hook or
 * post-deploy check ever authenticates against one — so the tests that drive
 * this whole path substitute a counting stub here. That substitution is also
 * what makes "an unlisted address opened zero sockets" an assertion a test can
 * actually make, rather than an inference from a status code.
 */
export type LoginProof = (
  principal: Principal,
  gate: SessionGate,
) => Promise<void>;

/**
 * The production proof: open one session, authenticate, close it.
 *
 * `withMailSession` is named literally at this one call site, and that is
 * deliberate rather than incidental. The `concurrent-session` scan rule matches
 * a concurrency combinator within a bounded distance of that exact name, so
 * naming it here puts this call under the existing rule with no alternation to
 * extend — and a rule whose entry points are enumerated by name is invisible to
 * every other assertion in the suite for a name it does not list.
 *
 * A fresh gate per call, from `createSessionGate()`. The gate is a closure over
 * one local boolean, so two sign-ins get two gates because they get two
 * construction sites, with no bookkeeping to reason about.
 *
 * `null` for the mailbox and `null` for the expected validity, together. That
 * skips the mailbox open and its validity gate entirely: this is
 * authenticated-state-only work, and opening a mailbox would be a second round
 * trip that proves nothing the login did not already prove.
 *
 * The callback does nothing and returns nothing. Reaching it at all IS the
 * proof — the session only exists once the server answered the login with OK.
 *
 * `oneAttemptPerGuess` is the login-path option plan 11-03 added, and THIS is
 * the one call site that passes it. A wrong password costs Apple two attempts
 * by default, because the session falls back to a second mechanism when the
 * first is refused; on this path that fallback buys nothing — the caller
 * already treats both refusals as the same answer — and it doubles what Apple
 * sees per guess against an account whose lockout threshold Apple does not
 * publish. The tools keep both mechanisms: a tool call is not a guess.
 *
 * **No second session helper.** Convention 3 permits exactly one orchestrator
 * and this calls it. Nothing here opens a socket, holds one, or fans out.
 */
async function proveWithApple(
  principal: Principal,
  gate: SessionGate,
): Promise<void> {
  await withMailSession(principal, gate, null, null, async () => {}, {
    oneAttemptPerGuess: true,
  });
}

/**
 * How long a failed sign-in takes, at minimum, measured from the handler's
 * entry.
 *
 * A FLOOR rather than the fixed penalty this replaces, and the difference is
 * the whole of what it buys. A fixed delay added to whatever the work already
 * cost leaves the work's own duration visible: an allow-list refusal returns
 * almost instantly plus the delay, a real login returns after a round trip to
 * Apple plus the delay, and a stopwatch sorts listed addresses from unlisted
 * ones by the gap. A floor measured from entry makes every failing answer take
 * the same wall-clock no matter which branch produced it.
 *
 * Three seconds, not the one it replaces, and the asymmetry argument carries
 * forward unchanged: a person typing a password does not notice three seconds,
 * and a parallel guesser is not slowed by a shorter one either way — two
 * hundred concurrent guesses pay the delay in parallel, so the round costs
 * whatever one request costs. The only party a short delay was ever gentle to
 * was the one it was aimed at.
 *
 * **The figure is sized by spike S6 in plan 11-07**, which measures a real IMAP
 * login from the deployed Worker. If a real login turns out to exceed this, the
 * leftover leak is accepted IN WRITING rather than the floor being raised
 * indefinitely: a floor that chases the slowest observed login grows without
 * bound and makes the page unusable to defend against a stopwatch nobody has
 * been observed holding.
 *
 * Exported so a test asserts the production default against the value the
 * handler actually sleeps rather than a retyped number, and so the injected
 * floor below has something to default to.
 *
 * This is also the limiter that does not depend on a durable counter
 * succeeding, which is why the counter's write is allowed to fail below and
 * this is not.
 */
export const FAILURE_FLOOR_MS = 3000;

/**
 * Sleep whatever is left of the floor, counted from ONE timestamp.
 *
 * **The arithmetic looks wrong without the runtime fact beside it.** In this
 * runtime the clock returns the time of the last input or output and does not
 * advance during code execution. On the shape-refusal path there is no I/O at
 * all between the handler's entry and the refusal, so the elapsed time reads as
 * exactly zero and this sleeps the whole floor. That is the correct answer for
 * a path that did no work, and it is the direction the arithmetic fails in:
 * safe, not leaky.
 *
 * The remainder is computed from `started` at each failing return and is NEVER
 * accumulated per step. A running total would drift with every branch that
 * forgot to add to it, and the branch that forgot would be the fast one — the
 * refusal — which is precisely the one the floor exists to slow down.
 *
 * The sleep idiom is the one this file already used twice before the floor
 * replaced them.
 */
async function holdFloor(started: number, floorMs: number): Promise<void> {
  const remaining = Math.max(0, floorMs - (Date.now() - started));
  await new Promise((resolve) => setTimeout(resolve, remaining));
}

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
 *
 * Exported as a type so the page module can take one without rebuilding the
 * shape. It is built here, by `identityOf`, because resolving who is asking is
 * flow control; displaying it is not.
 */
export interface ClientIdentity {
  /** The registered name, or the client id when the client registered none. */
  name: string;
  /** The full redirect URI. Only its origin is ever displayed. */
  redirectUri: string;
}

/**
 * The body served when the provider cannot resolve the requesting client.
 *
 * The wording, the status and the plain-text shape are unchanged: this is an
 * owner diagnostic with carefully argued text, and restyling it is scope this
 * phase did not ask for. What it gains is the header set, which it did not
 * carry before.
 */
function unknownClientResponse(): Response {
  return new Response("Unknown OAuth client", {
    status: 400,
    headers: { ...RESPONSE_HEADERS },
  });
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
 *
 * Exported, but only so the sharing below can cross a module boundary. There is
 * exactly one derivation of a destination origin under `src/auth/`, and a
 * second one anywhere would let the allowlist check and the consent line
 * disagree about what they are talking about.
 */
export function originOf(redirectUri: string): string | null {
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
 *
 * Exported for the page module to call. It stays HERE rather than moving with
 * the rendering, because the value it answers is the one
 * `refusedRedirectResponse` decides on two functions down, and the sharing is
 * the entire point of the function existing.
 */
export function displayDestination(redirectUri: string): string {
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
      ...RESPONSE_HEADERS,
      "content-type": "text/plain; charset=utf-8",
    },
  });
}

function authorizationErrorResponse(error: AuthorizationError): Response {
  // An unknown client or an unregistered redirect URI must be rendered
  // locally — redirecting an unvalidated URI is what CVE-class bugs in this
  // problem space are made of.
  if (!error.redirectUri) {
    return new Response(error.description, {
      status: 400,
      headers: { ...RESPONSE_HEADERS },
    });
  }

  const redirect = new URL(error.redirectUri);
  redirect.searchParams.set("error", error.code);
  redirect.searchParams.set("error_description", error.description);
  if (error.state) redirect.searchParams.set("state", error.state);
  if (error.issuer) redirect.searchParams.set("iss", error.issuer);

  // Constructed explicitly rather than through the static redirect helper, and
  // for one reason: that helper builds a response this code cannot put a header
  // on, and this phase's requirement is that EVERY response carries the four.
  // The location header is set by hand and the body is empty, which is what the
  // helper produces anyway — a caller reading `location` off this response sees
  // the identical value.
  return new Response(null, {
    status: 302,
    headers: { ...RESPONSE_HEADERS, location: redirect.toString() },
  });
}

/**
 * Build the provider's `defaultHandler`: everything that is not an API request.
 *
 * Only `/authorize` is ours. The token, registration, and metadata endpoints
 * are implemented by the provider itself and never reach this handler.
 *
 * `proof` is the one injection seam, and it defaults to the production one, so
 * production calls this factory with no argument at all — the same shape
 * `createMcpApiHandler(extraTools)` already has one tree over. A test hands in
 * a counting stub instead, which is how D-09 is kept (no automated login to a
 * real Apple ID, ever) and how "zero sockets were opened for that request"
 * becomes something a test can assert rather than infer.
 *
 * `floorMs` is the second seam, and it has the same default-to-the-exported-
 * value property the mail session options already have: production passes
 * nothing and behaves exactly as the constant says. A test can then exercise
 * every failure path for a few milliseconds each instead of three seconds each,
 * while one case still drives the default and asserts the real figure.
 */
export function createLoginHandler(
  proof: LoginProof = proveWithApple,
  floorMs: number = FAILURE_FLOOR_MS,
): {
  fetch(request: Request, env: Env & LoginGateSecret): Promise<Response>;
} {
  return {
    async fetch(
      request: Request,
      env: Env & LoginGateSecret,
    ): Promise<Response> {
      // The floor's clock starts HERE, as the first statement of the request
      // handler, before the pathname is read and before any branch exists to
      // be timed. Anything taken later would start the clock after some of the
      // work, and the amount of work already done is exactly what the floor is
      // hiding.
      const started = Date.now();
      return handleAuthorize(request, env, proof, floorMs, started);
    },
  };
}

/**
 * The production handler, built from the factory above with no argument.
 *
 * Kept as a named export because `src/auth/oauth.ts` wires this exact value as
 * the provider's `defaultHandler`, and several tests drive it directly.
 */
export const loginHandler = createLoginHandler();

/**
 * One `/authorize` request, from the pathname check to the redirect.
 *
 * A plain function rather than a method so the factory above is the only thing
 * that closes over `proof`, and so the whole flow reads top to bottom in one
 * place. The environment parameter keeps its current type: the login gate's own
 * secret is no longer read anywhere in this file, but `test/env-narrowing.test.ts`
 * and `test/authorize-not-found.test.ts` both spell that type, and Phase 13
 * (CUT-01) removes the binding, the interface and every mention of it together
 * rather than leaving a half-removed name behind.
 */
async function handleAuthorize(
  request: Request,
  env: Env & LoginGateSecret,
  proof: LoginProof,
  floorMs: number,
  started: number,
): Promise<Response> {
  {
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
          ...RESPONSE_HEADERS,
          "content-type": "text/plain; charset=utf-8",
        },
      });
    }

    // The allow list is read ONCE, here, and the verdict is carried down. Gate
    // first: an unconfigured deployment has nothing to protect, so nothing is
    // spent on the request before this — not a parse, not a store round trip,
    // and certainly not a socket to Apple.
    //
    // Fail closed above method dispatch, so neither verb can reach the form
    // while this deployment cannot say who may sign in. A list that is missing,
    // empty, malformed, or holding one unusable entry all mean NOBODY, so all
    // of them answer here.
    //
    // 503 rather than 401 is deliberate, and it matters more now than it did
    // under the shared secret: 401 would tell the owner they mistyped their own
    // Apple password, sending them to Apple to make a new one, when what is
    // actually wrong is a binding on this server. The distinction gives nothing
    // exploitable to a party who cannot authenticate either way. It has to be
    // the status code carrying that signal — Convention 4 forbids logging on
    // this path, so a self-describing response is the only channel left. The
    // body is `UNCONFIGURED_BODY` unchanged, byte for byte: it names no binding
    // and interpolates nothing, so it is as true of an absent allow list as it
    // was of an absent secret.
    const allowed = parseAllowList(env.ALLOWED_APPLE_IDS);
    if (allowed.kind === "nobody") {
      return new Response(UNCONFIGURED_BODY, {
        status: 503,
        headers: {
          ...RESPONSE_HEADERS,
          "content-type": "text/plain; charset=utf-8",
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
        null,
        identityOf(client, oauthRequest.redirectUri),
      );
    }

    if (request.method !== "POST") {
      // One of the two sites that carried no caching header at all before this
      // phase. The spread goes first and the site's own header follows, so a
      // site can never silently drop one of the four.
      return new Response("Method not allowed", {
        status: 405,
        headers: { ...RESPONSE_HEADERS, allow: "GET, POST" },
      });
    }

    const form = await request.formData();
    const submittedAppleId = String(form.get(APPLE_ID_FIELD) ?? "");
    const submittedPassword = String(form.get(APP_PASSWORD_FIELD) ?? "");
    const query = String(form.get("oauth_request") ?? "");

    // Brute-force mitigation, deliberately kept this small: a coarse
    // time-bucketed counter in the KV namespace that already exists, and a
    // fixed delay. Not a rate-limiting subsystem.
    const key = failureKey(request);
    const failures = Number((await env.OAUTH_KV.get(key)) ?? "0");
    if (failures >= MAX_FAILURES_PER_BUCKET) {
      // The floor applies HERE too, and that is decided rather than incidental.
      // A floor applied only after the allow-list check would let a stopwatch
      // sort listed addresses from unlisted ones, which is the exact leak the
      // floor exists to close, and a refusal that returned early would be the
      // fastest answer this surface has.
      //
      // The cost is real and is recorded so the next reader does not optimise
      // it away: during a flood this holds N requests open for the floor each,
      // consuming concurrent-request capacity precisely when the limiter is
      // trying to make requests cheap. It is wall-clock rather than processor
      // time, this runtime bills processor time, and the code this replaces
      // already slept before the very same refusal — so it is a change of
      // degree and not of kind.
      await holdFloor(started, floorMs);
      // The other site that carried no caching header. The body is the same
      // sentence it has always been, now named where the rest of this surface's
      // copy lives.
      return new Response(SOURCE_REFUSAL_BODY, {
        status: 429,
        headers: {
          ...RESPONSE_HEADERS,
          "retry-after": String(BUCKET_SECONDS),
        },
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

    /**
     * The ONE place a credential-path response is built. Count it, wait the
     * floor, re-render.
     *
     * One helper for every refusal on this path, because they are the SAME
     * answer. A stopwatch, a status code and a body must not sort the causes
     * apart, and the cheapest way to hold all three true is for there to be one
     * place the answer is written.
     *
     * **The mapping, in full.** The last column describes the per-Apple-ID
     * hourly counter plan 11-05 introduces; the counter this helper bumps today
     * is the per-SOURCE one above, which every caller bumps alike.
     *
     * | Cause                               | Error class        | Renders     | Status | Bumps the per-Apple-ID hourly counter (11-05) |
     * |-------------------------------------|--------------------|-------------|--------|-----------------------------------------------|
     * | Badly-shaped app password           | — (Apple untouched)| the string  | 401    | No                                            |
     * | Address not on the list             | — (Apple untouched)| the string  | 401    | No                                            |
     * | Address unparseable or empty        | —                  | the string  | 401    | No                                            |
     * | Per-Apple-ID burst trip (layer 2)   | —                  | the string  | 401    | No                                            |
     * | Per-Apple-ID hourly cap (layer 3)   | —                  | the string  | 401    | No                                            |
     * | Wrong password                      | `ImapAuthError`    | the string  | 401    | Yes                                           |
     * | Apple refusing on availability      | `ImapThrottleError`| the throttle| 401    | No                                            |
     * | Connect, TLS or read failure        | `ImapConnectError` | the throttle| 401    | No                                            |
     *
     * **The last row is decided here, and research left it open.** The throttle
     * wording — Apple is not answering right now, wait a few minutes — is
     * LITERALLY TRUE of a connect failure. The single failure string tells the
     * reader to check the address and the password, which is false on that path
     * and sends a family member hunting for a typo that does not exist. It
     * leaks no more than the throttle message already does, because a connect
     * failure can only happen after the allow-list check has passed.
     *
     * The branch reads the error's TYPE and never a caught value's text. The
     * mail tree classifies from the parsed reply, response codes before prose
     * hints, and this handler consumes that classification rather than
     * repeating it.
     *
     * The source-connection refusal is NOT built here. It is keyed by the
     * connecting source rather than by the address being tried, so it carries
     * no information about who is on the list, and it is answered above — before
     * any credential check exists to leak anything.
     */
    async function refuseCredential(
      failure: "credentials" | "throttled" = "credentials",
    ): Promise<Response> {
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
        // there is nothing here worth a response field either. The floor
        // below is the limiter that does not depend on this write succeeding.
      }
      await holdFloor(started, floorMs);

      // Where the single failure string is built: a per-target limiter trip
      // renders this string and never a source-connection refusal status. A
      // refusal status that only ever appears for a listed address is a
      // membership oracle, which is exactly what success criterion 3 forbids.
      //
      // Where the throttle message is built: criterion 3 binds this server's
      // own limiter, not Apple's reply. The throttle message does reveal that
      // the address passed the allow list, and that is accepted, because it can
      // only be built after Apple has already answered — which already means
      // the address was listed.
      return renderForm(query, failure, identity);
    }

    // The shape check sits ABOVE the allow-list check, and the placement is
    // argued rather than assumed, the way the redirect refusal argues its own
    // three edges.
    //
    // It is the cheapest refusal in the chain: a pure function of ONE submitted
    // field that consults no configuration, reads no stored state and does no
    // I/O. Neither this nor the allow-list check can open a socket, so the
    // ordering is a question of cost and not of safety — and because every
    // refusal below answers with the same body at the same status under the
    // same floor, the order is not observable from outside either.
    //
    // The canonical form is derived ONCE, here, and carried down to both the
    // principal and the props. Deriving it twice is how the value Apple is told
    // and the value the grant stores come to disagree.
    const appPassword = canonicalAppPassword(submittedPassword);
    if (!couldBeAppPassword(appPassword)) return refuseCredential();

    // The allow-list check sits ABOVE every use of the credentials, and that
    // placement is the whole of GATE-02: an address that is not on the list
    // must never reach Apple, so no principal is built and no session is opened
    // for one. The folded address is what gets compared and what gets stored,
    // so the comparison and the grant cannot disagree about who this is.
    const appleId = normaliseAppleId(submittedAppleId);
    if (!isAllowed(allowed, appleId)) return refuseCredential();

    try {
      // `principalFromProps` is the ONE constructor, and it refuses before any
      // socket exists: an unusable password — empty, whitespace-only, or
      // carrying a control character — throws here (D-19). What it is handed is
      // the CANONICAL form derived above, which is the same value the props
      // below carry, so the login this proves and every later request replay
      // the identical bytes.
      const principal = await principalFromProps({
        v: PROPS_VERSION,
        appleId,
        appPassword,
      });

      // One login, at Apple. This is the only place in the whole flow that
      // talks to Apple, and it is reached only for an address already on the
      // list carrying a password already judged usable.
      await proof(principal, createSessionGate());
    } catch (error) {
      // NEVER read the caught value's TEXT. The type is all that is consulted,
      // and `instanceof` is the whole of the test — no `.message`, no `.stack`,
      // no prose hint re-derived here. The mail tree already decided a throttle
      // from a credential refusal by reading the parsed tagged reply, response
      // codes before prose hints, and this handler consumes that decision
      // rather than making a second one that could disagree with it.
      //
      // Anything that is not one of these two named types falls through to the
      // single failure string, which is the silent answer. Failing toward the
      // silent one is deliberate: no live refusal has ever been observed from
      // iCloud, so every code the classifier matches is taken from the
      // specification rather than from evidence.
      const throttled =
        error instanceof ImapThrottleError || error instanceof ImapConnectError;
      return refuseCredential(throttled ? "throttled" : "credentials");
    }

    // The session is already closed. `withMailSession` runs teardown and
    // releases its gate in its own `finally` BEFORE it returns, so reaching
    // this line means the socket is gone. The trap this avoids is completing
    // the ceremony inside the session callback, which would hold a connection
    // open against iCloud's low, undocumented per-account ceiling while a store
    // write and a redirect were built.

    // Grant what was asked for, narrowed to what this server supports. A
    // client that asks for nothing gets the one scope that exists, because a
    // single-user single-scope server has nothing meaningful to withhold.
    const requested = oauthRequest.scope.filter((scope) =>
      SUPPORTED_SCOPES.includes(scope),
    );
    const granted = requested.length > 0 ? requested : [...SUPPORTED_SCOPES];

    // The user id is DERIVED from the address, never invented and never read
    // back off anything. It is the same folded string the allow-list check just
    // accepted, so the id that names this person's stored objects and the
    // address in their grant cannot disagree.
    //
    // It cannot be null here: the folding already answered a string, and
    // `userIdOf` refuses exactly what the folding refuses. The check is kept
    // anyway rather than asserted away, because a null would otherwise become
    // the literal string "null" in a key name.
    const userId = await userIdOf(appleId);
    if (userId === null) return refuseCredential();

    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthRequest,
      userId,
      // Only the client's name, and nothing else. Metadata is not encrypted
      // the way props are, so nothing about the person goes in it — not the
      // address, not the id derived from it.
      metadata: { clientName: client.clientName },
      scope: granted,
      // Exactly the three keys `principalFromProps` accepts, and no fourth. It
      // derives the user id from the address every time, so a props object
      // carrying one of its own is refused for having an extra key.
      props: {
        v: PROPS_VERSION,
        appleId,
        appPassword,
      },
      // `revokeExistingGrants` is left at its default, which is TRUE. A second
      // sign-in from the same client therefore replaces the first rather than
      // adding to it. That is the dead-password recovery path and not a bug:
      // when someone revokes their app-specific password at Apple, signing in
      // again with a fresh one is what fixes it, and the stale grant holding
      // the dead password goes away in the same step. Phase 12 owns the rest of
      // the grant lifetime (LIFE-01 through LIFE-06).
    });

    // Constructed explicitly rather than through the static redirect helper,
    // and this is the site where that matters most: this location header
    // carries the authorization code, so a cached copy of this redirect is a
    // cached copy of a credential-equivalent. The helper builds a response
    // nothing can put a caching header on. A caller reading `location` off this
    // response sees the same value the helper would have set.
    return new Response(null, {
      status: 302,
      headers: { ...RESPONSE_HEADERS, location: redirectTo },
    });
  }
}
