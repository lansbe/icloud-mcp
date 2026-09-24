// THE ONLY MODULE IN THIS REPOSITORY THAT MAY ISSUE A DAV REQUEST.
//
// This is the structural half of DAV-01, and it is the exact analog of
// `src/mail/socket.ts` one protocol over: every tsdav call in `src/dav/` passes
// `fetch: davFetch`, and tsdav resolves that as `fetchOverride ?? fetch`, so the
// function built here replaces the global entirely for DAV traffic. The
// detective half is the source scan run from the test suite and the pre-commit
// hook. The preventive half is the Conventions section of ./.claude/CLAUDE.md,
// which carries the full rationale for the request-budget rule this module
// enforces.
//
// Five obligations land on this one seam and no other seam can serve any of
// them. tsdav does not throw on a non-2xx — it returns a response object with
// `ok: false` — and where it does throw, it throws a bare `Error` whose message
// embeds a server URL, so error classification has to happen here, by status
// number, before tsdav sees the response. tsdav sets no redirect policy, so the
// manual policy has to be forced here. tsdav fans out internally over
// collections, so the serialisation gate has to live here. The credential has
// to be attached here, per call, so that no caller ever holds one. And tsdav
// hardcodes method strings this runtime refuses to build a request from, so the
// sendability check has to happen here too — Phase 14 shipped a probe whose
// `MKCALENDAR` threw before any byte left the Worker and was reported as a
// failed connection to iCloud, which is a wrong answer of the worst shape:
// plausible, specific, and about a server that was never contacted.
//
// Nothing in this module goes near a socket, and nothing in it may name a
// transport mode or a port: the DAV protocols run over ordinary HTTPS. The
// banned transport tokens are described in prose in ./.claude/CLAUDE.md rather
// than spelled here, because the scan reads this file too.
//
// This module contains no logging calls of any kind and must never acquire any.

import { isConfiguredSecret } from "../auth/login-handler";
import { reportRefusal } from "../password-pause";
import { passwordOf } from "../principal";
import type { Principal } from "../principal";
import {
  DavAuthError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavThrottleError,
  DavUnsendableError,
} from "./errors";

const ENCODER = new TextEncoder();

/**
 * The characters that cannot appear inside an HTTP header value.
 *
 * The same three `src/mail/credentials.ts` refuses, and refused for the same
 * class of reason: CR and LF terminate a header line early and inject a second
 * one, and NUL is rejected outright by every conformant HTTP implementation.
 * The ordinary way a value acquires one is mundane, which is why this is not
 * theoretical — a secret provisioned from a file carries the file's trailing
 * newline.
 *
 * Refusing beats escaping here for the same reason it does there: escaping
 * would send a value the server rejects, and the user would be told the
 * app-specific password was wrong when only its encoding was.
 */
const ILLEGAL_IN_HEADER_VALUE = /[\r\n\u0000]/;

/**
 * Refuse a binding that was never provisioned.
 *
 * An assertion signature rather than a boolean predicate, for the reason
 * `src/mail/credentials.ts` records: `src/env.ts` types the secret bindings as
 * absent-or-string, and a predicate returning plain `boolean` would not narrow
 * at the call site, leaving the choice between a failing typecheck and a
 * forbidden cast.
 *
 * **The check is BEHAVIOURAL, not compiler-driven, and must not be removed on
 * the grounds that the typecheck passes without it.** The values land in a
 * template literal, and a template literal accepts an absent binding silently —
 * it stringifies to the nine characters spelling "undefined". Without this, an
 * unprovisioned binding is base64-encoded and sent to Apple as a literal
 * placeholder username. A green typecheck is not evidence the check is
 * redundant.
 *
 * `isConfiguredSecret` is reused rather than restated: one definition of what a
 * usable configured secret looks like, shared with the `/authorize` path that
 * first needed it (CR-01).
 *
 * **Since Phase 9 this is the SECOND layer.** The two values now come from a
 * signed-in principal, and the principal module refuses an absent or blank
 * value when it builds one. A principal's type is only a claim at runtime,
 * though, so the check stays: it costs one comparison and it is the last thing
 * standing between a hand-made object and a placeholder username sent to Apple.
 */
function assertProvisioned(value: string | undefined): asserts value is string {
  if (!isConfiguredSecret(value)) throw new DavAuthError();
}

/** Refuse a value carrying a character that is illegal in a header value. */
function assertNoIllegalCharacters(value: string): void {
  if (ILLEGAL_IN_HEADER_VALUE.test(value)) throw new DavAuthError();
}

/**
 * Base64 over raw bytes.
 *
 * Takes bytes, not a string, so the caller is forced to decide the encoding
 * before reaching here. Handing a JavaScript string straight to the runtime's
 * base64 primitive encodes UTF-16 code units, which is wrong for every
 * non-ASCII byte.
 *
 * THAT IS NO LONGER A LIVE CONCERN, AND THE HELPER STAYS ANYWAY (code review
 * IN-06). This docstring used to call a non-ASCII Apple ID a live concern. It
 * is not one now: since Phase 8 the user-id function refuses any address
 * holding a character outside printable ASCII, and since Phase 9 every DAV
 * header here is built from a principal, so no such address can reach this
 * function. This is the second layer, not the only one. It stays because
 * handing a string to the base64 primitive is wrong in a way no green test
 * would show — the mistake produces a header that encodes cleanly and means
 * something else — and because the layer in front of it is one decision away
 * from being relaxed.
 *
 * **Copied from `src/mail/credentials.ts` rather than imported from it, with
 * its rationale carried across.** That module's helper is private and stays
 * private: exporting it would mean editing the shipped credential path — the
 * one path this project most needs to keep working — for a cosmetic dedupe,
 * which buys nothing and risks a regression. ARCHITECTURE Q1's zero-import
 * boundary between `src/mail/` and `src/dav/` rules out the import in any case.
 */
function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}

/**
 * Build the Basic authorization header for one DAV request.
 *
 * **This diverges from `src/mail/credentials.ts` and the divergence is written
 * down rather than left for a reader to infer.** Both exports of that module
 * consume the password and return nothing, so no object holding it is ever
 * constructed — there is nothing to log, serialize, or attach to an error. This
 * function returns a string, which is a weaker property, and D-55 requires it:
 * tsdav's standalone functions take `headers` per call.
 *
 * The honest claim, with its limit stated: the password is not recoverable by
 * any code path in this repository, because nothing here decodes a Basic header
 * back. That guarantee rests on nothing ever adding such a decoder, where
 * `credentials.ts`'s rests on there being nothing to decode. `credentials.ts`'s
 * own header warns that one convenience of exactly this shape would undo the
 * whole pattern; this is that convenience, taken deliberately and bounded to
 * one function whose result is consumed immediately by the fetch below.
 *
 * Deliberately NOT tsdav's own `getBasicAuthHeaders()`. That helper opens by
 * logging the username, which names the Apple ID — a violation of
 * ./.claude/CLAUDE.md §4 that this project cannot see, because the scan does not
 * walk `node_modules/`.
 *
 * **It takes the signed-in principal, not the environment (Phase 9, D-11).**
 * The login address comes off the principal. The password comes from the
 * principal module's password reader and from nowhere else. That reader answers
 * only the very object a constructor built, so a spread copy, a clone or a
 * hand-made look-alike is refused here before any header exists (D-16). This
 * file is one of exactly two that may call it. The other is the mail tree's
 * credential writer.
 *
 * The reader refuses with the mail tree's auth error. That is mapped to the DAV
 * auth error right here, without binding the caught value, so everything this
 * module raises stays inside the DAV error vocabulary.
 */
export function davAuthHeader(principal: Principal): string {
  const appleId = principal.appleId;
  let password: string;
  try {
    password = passwordOf(principal);
  } catch {
    // Never read the caught value. A refusal is a refusal.
    throw new DavAuthError();
  }
  assertProvisioned(appleId);
  assertProvisioned(password);
  assertNoIllegalCharacters(appleId);
  assertNoIllegalCharacters(password);

  return `Basic ${base64(ENCODER.encode(`${appleId}:${password}`))}`;
}

/**
 * The shape every DAV caller passes to tsdav as its `fetch` parameter.
 *
 * Exactly `typeof globalThis.fetch`, so it is a drop-in for tsdav's
 * `fetch?: typeof fetch` parameter with no adapter and no cast at any call site.
 */
export type DavFetch = typeof globalThis.fetch;

/**
 * Translate an HTTP status number into one of the four typed DAV errors.
 *
 * This is where D-60's enumerated failure list becomes executable, and each
 * branch carries D-60's reasoning rather than a label.
 *
 * **401 and 403 are never retried.** A wrong app-specific password would
 * otherwise mean a second full authentication attempt against Apple on every
 * single tool call — two services times two attempts, forever — and that cadence
 * is exactly what gets an account locked out of Mail.app on the user's own
 * devices. The cost of over-asking here falls on the user, not on this server.
 *
 * **429 and 503 are never retried.** A server that has just said it is
 * throttling is the last thing to send a second request to. That claim is now
 * proven rather than stated: `test/dav-transport.test.ts` drives each of the
 * two statuses through this function all the way to the fixed wait sentence in
 * `SAFE_MESSAGES`, and pins the outbound request count at one, so a retry
 * inserted anywhere between the status number and the caller's string turns
 * that case red. A pointer rather than a count, because a number written in
 * prose beside the code it counts has a silent expiry date — `davToErrorCategory`'s
 * own docstring records exactly that happening to it.
 *
 * **400, 404, 410 and any 3xx are re-discovery eligible.** All four are what a
 * stale cached shard host looks like from the outside. 3xx is on the list only
 * because the manual redirect policy below makes it observable at all — under
 * the follow policy a redirect from a stale host is transparently followed and
 * the client sees a 200. 400 is on the list deliberately: an empty-bodied 400
 * on PROPFIND is the documented iCloud failure mode, and it has a history of
 * firing account-wide.
 *
 * **415 and 501 are NOT re-discovery eligible, and that pairing earns its own
 * sentence.** Those two statuses say "this server does not offer this report" —
 * a statement about a missing CAPABILITY rather than about a resource or a
 * stale host. Re-discovery would not help, so it must not be attempted, and
 * plan 03-08's contacts fallback needs exactly this signal to tell a refused
 * server-side filter apart from a failed network.
 *
 * **412 is NOT re-discovery eligible either, for a third distinct reason.**
 * 415 and 501 answer a question about the server's capabilities; 412 answers
 * one about the RESOURCE'S CURRENT STATE — the etag the write named is no
 * longer the etag the resource has. Re-resolving the host produces the
 * identical answer at the cost of a real PROPFIND and a second write, which is
 * why the class it raises deliberately carries no `rediscoverable` field to get
 * wrong. This is the branch that makes CALW-05 executable: without it a raced
 * write falls through to `DavConnectError`, is reported as a transient
 * connection fault, and the model is told the one thing that can never work —
 * retry once.
 *
 * Everything else non-2xx is a transport fault this layer cannot classify.
 */
function throwForStatus(status: number): void {
  if (status >= 200 && status < 300) return;
  if (status === 401 || status === 403) throw new DavAuthError();
  if (status === 429 || status === 503) throw new DavThrottleError();
  if (status === 415 || status === 501) throw new DavNotFoundError(false);
  if (status === 412) throw new DavStaleResourceError();
  if (status === 400 || status === 404 || status === 410) {
    throw new DavNotFoundError(true);
  }
  if (status >= 300 && status < 400) throw new DavNotFoundError(true);
  throw new DavConnectError();
}

/**
 * A URL that can never resolve, used only to build a request and throw it away.
 *
 * `.invalid` is reserved by RFC 2606 precisely so that it cannot be registered,
 * and nothing is ever fetched from it: the request below is constructed and
 * discarded in the same expression. The host is required because a `Request`
 * needs one, not because anything is addressed.
 */
const SENDABILITY_PROBE_URL = "https://method-check.invalid/";

/**
 * Refuse a method this runtime cannot express, BEFORE attempting to send it.
 *
 * **This is a behavioural check against the platform, not a restatement of
 * it, and that distinction is the whole design.** An allow-list of method
 * names written here would be a second copy of workerd's own list, agreeing
 * with it today and drifting silently the day either side changes. So the
 * question is put to the runtime itself: build a `Request` carrying this
 * method against a host that cannot exist, and see whether the constructor
 * accepts it. The construction IS the check; the object is discarded.
 *
 * **It exists because of a measured failure.** Phase 14's collection write
 * probe sent `MKCALENDAR`, which workerd refuses while accepting `PROPFIND`,
 * `PROPPATCH`, `REPORT`, `MKCOL` and every other method this project uses. The
 * refusal is a `TypeError` raised before any I/O — which landed in the `catch`
 * around the fetch below, became a `DavConnectError`, and was reported as a
 * transient connection fault against a server that had never seen the request.
 * The tool that produced that report exists to write down what iCloud does, so
 * the wrong answer was on its way into a verdict.
 *
 * **It runs here rather than at the call sites, and that is the point.** Every
 * method string in this repository is a compile-time constant at its call
 * site, so a check up there would be one assertion per site and a new blind
 * spot per site added. This seam is the only place every DAV request passes
 * through, which is the same argument the credential, the redirect policy and
 * the serialisation gate already rest on.
 *
 * `undefined` is permitted and checked as nothing: the fetch below then sends
 * `GET`, which no runtime refuses.
 *
 * The caught value is never read — only the fact that construction failed.
 */
function assertSendableMethod(method: string | undefined): void {
  if (method === undefined) return;
  try {
    // Constructed and discarded. See the docstring: this is the check.
    new Request(SENDABILITY_PROBE_URL, { method });
  } catch {
    // Never read the caught value — ./.claude/CLAUDE.md §4.
    throw new DavUnsendableError();
  }
}

/**
 * Build the one outbound DAV function for ONE request.
 *
 * Constructed per request inside `createServerFactory`, never at module scope.
 * **The distinction from `createSessionGate` matters and is stated here because
 * a reader arriving from `src/mail/service.ts` would otherwise read a
 * per-instance chain as the known-wrong choice.** That gate REFUSES a second
 * acquisition, so it must be per-invocation or it would falsely refuse a
 * legitimate second request that happened to land in the same isolate. This one
 * QUEUES rather than refuses — and building it per request is what keeps one
 * caller's queue from growing behind another caller's in the same isolate,
 * where a module-level chain would serialise unrelated requests against each
 * other and turn an isolate into a single-file line.
 *
 * **Why it queues at all.** ./.claude/CLAUDE.md §3 records the budget: production
 * allows six simultaneous connections per Worker invocation, and that budget
 * counts KV reads and outbound requests too — the OAuth provider has already
 * spent one before any DAV code runs. iCloud's own per-account ceiling is
 * lower, undocumented, and deliberately unmeasured, because exhausting it does
 * not fail politely: it locks the user out of their own mail in Mail.app on
 * their own devices. tsdav fans out internally over collections in
 * `fetchCalendars` and `fetchAddressBooks`, and the source scan cannot see
 * inside `node_modules/` — so this gate is what makes that fan-out serial
 * without forking the library.
 *
 * **It takes a PROMISE of the signed-in principal, and stays synchronous
 * (Phase 9, D-09, D-27).** The server factory builds this function and must not
 * await anything: a rejection there would become a 500 with no challenge. So
 * the promise is awaited at the top of `run` instead, which is already async
 * and already behind the queue, so request order does not change.
 *
 * That await has a `try` of its own, and it sits OUTSIDE the `try` around the
 * fetch on purpose. A promise that rejects means the Worker's two mail secrets
 * are unset or unusable. Inside the fetch's `try` that would be reported as a
 * connection fault, and a connection fault invites a retry that can never work.
 * Out here it is the DAV auth error, and no request is sent.
 *
 * Whatever the promise resolves to is handed on as it is. It is never spread
 * and never cloned, because the password reader answers only that one object.
 */
export function createDavFetch(principal: Promise<Principal>): DavFetch {
  // Per-instance, and therefore per request. See the docstring above for why
  // module scope would be wrong here for the opposite reason it is wrong for
  // the session gate.
  let inFlight: Promise<unknown> = Promise.resolve();

  const davFetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const run = async (): Promise<Response> => {
      // Who this request acts for. Its own `try`, outside the one around the
      // fetch below: see the docstring for why a refusal here must not read as
      // a connection fault.
      let actor: Principal;
      try {
        actor = await principal;
      } catch {
        // Never read the caught value.
        throw new DavAuthError();
      }

      // Can this runtime express the request at all? Its own statement,
      // outside the `try` around the fetch below, for the same reason the
      // principal's await is: a refusal here means nothing was sent and no
      // retry can ever succeed, and reporting that as a connection fault tells
      // the reader the one thing that can never work. See the docstring above
      // for the measured failure this was added for.
      //
      // BEFORE the credential is built, deliberately. A request that cannot be
      // sent has no business causing a password to be read.
      assertSendableMethod(init?.method);

      // Built per call, and merged rather than assigned, so no caller ever
      // holds a header carrying the credential.
      const headers = new Headers(init?.headers);
      headers.set("authorization", davAuthHeader(actor));

      let response: Response;
      try {
        response = await fetch(input, {
          ...init,
          headers,
          // Last, so no caller-supplied init can override it. D-60's 3xx clause
          // is unreachable without this, and it is also what stops the Basic
          // credential being forwarded to a redirect target — Cloudflare
          // documents the follow policy as forwarding all headers to the
          // destination even across hostnames.
          redirect: "manual",
        });
      } catch {
        // Never read the caught value. A transport failure carries no status,
        // and the value itself can carry anything at all.
        throw new DavConnectError();
      }

      // LIFE-04, and it sits HERE rather than inside `throwForStatus` because
      // that function maps 401 and 403 together. A 403 can be a write to a
      // read-only shared calendar, which is not a dead password — pausing on it
      // would lock a working account out of its own mail tools.
      //
      // That iCloud answers 401 and not 403 for a bad password is research
      // assumption A1 rather than a measurement. If it ever answers 403,
      // calendar-only use with a dead password would simply not pause, and every
      // call still fails fast. The refusal above, where the principal itself
      // rejected, is deliberately left alone: that is THIS SERVER refusing, not
      // Apple. Only a door-armed principal reports.
      if (response.status === 401) await reportRefusal(actor);

      throwForStatus(response.status);
      return response;
    };

    // `then(run, run)` rather than `finally`: the next request must run whether
    // its predecessor resolved or rejected, and a rejected chain that is never
    // reset would wedge every later call in this request.
    const result = inFlight.then(run, run);
    inFlight = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }) as DavFetch;

  return davFetch;
}
