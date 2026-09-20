// THE ONLY MODULE IN THIS REPOSITORY THAT MAY NAME AN iCLOUD DAV HOSTNAME.
//
// DAV-02 and DAV-03. The two constants below are the *entry* hostnames, and
// they are passed to exactly one function — `createAccount`'s `serverUrl` — for
// exactly one purpose: to ask iCloud where this account actually lives. The
// answer is a sharded `pXX-` host that differs per account AND per service, and
// no constant anywhere in this codebase may stand in for it. The ROADMAP note
// states the rule; PITFALLS #9 records Apple breaking working clients
// account-wide when a client assumed otherwise.
//
// Every later DAV call takes a `DAVAccount` reconstructed from this module's
// cache, via `davAccountFor` below, so no other module needs — or gets — a
// hostname literal at all.
//
// This module contains no logging calls of any kind and must never acquire any.

import { createAccount } from "tsdav";
import type { DAVAccount } from "tsdav";
import type { Env } from "../env";
import type { Principal } from "../principal";
import {
  DavAuthError,
  DavConnectError,
  DavNotFoundError,
  DavThrottleError,
} from "./errors";
import type { DavFetch } from "./transport";

/** The CalDAV discovery entry point. Passed only as `createAccount.serverUrl`. */
const CALDAV_SERVER_URL = "https://caldav.icloud.com";

/** The CardDAV discovery entry point. Passed only as `createAccount.serverUrl`. */
const CARDDAV_SERVER_URL = "https://contacts.icloud.com";

const SERVER_URL: Record<DavService, string> = {
  caldav: CALDAV_SERVER_URL,
  carddav: CARDDAV_SERVER_URL,
};

/** The two DAV services this project speaks. */
export type DavService = "caldav" | "carddav";

/** Every service this module can resolve, in a fixed order. Sequential use only. */
export const DAV_SERVICES: readonly DavService[] = ["caldav", "carddav"];

/** What one resolved service looks like, plus where the answer came from. */
export interface ResolvedDavAccount {
  rootUrl: string;
  principalUrl: string;
  homeUrl: string;
  /** True when no outbound request was made to produce this. */
  cacheHit: boolean;
}

/** The three URLs, as stored. `cacheHit` is a property of the read, not the value. */
type CachedDiscovery = Pick<
  ResolvedDavAccount,
  "rootUrl" | "principalUrl" | "homeUrl"
>;

/**
 * How long a resolved discovery triple stays usable (D-59).
 *
 * Twenty-four hours: the shorter end of the range this kind of value is usually
 * cached for. The cost of the short end is two extra PROPFINDs a day, which is
 * nothing. What it buys is a tight bound on worst-case staleness even if the
 * re-discovery failure path turns out to have a gap — where a week or a month
 * would let a bug in that path hide for weeks before anyone noticed.
 *
 * KV's minimum `expirationTtl` is 60 seconds, so this value is comfortably
 * valid. After expiry a read behaves exactly as if the key had never existed,
 * which is the behaviour the re-discovery path wants: an expiry and a miss need
 * not be told apart, and nothing in this phase depends on telling them apart.
 */
export const DISCOVERY_TTL_SECONDS = 86400;

/**
 * The key namespace, versioned.
 *
 * The `v1` buys the same hedge `TOKEN_VERSION` buys in `src/mail/ids.ts`: a
 * future change to the stored shape becomes detectable rather than silently
 * misread as the current one.
 */
const DAV_CACHE_KEY_PREFIX = "dav:v1";

const ENCODER = new TextEncoder();

function hex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The Apple ID this request acts for, off the signed-in principal.
 *
 * The address is returned exactly as the principal carries it, with no trim and
 * no case change, because the key below hashes it as given.
 *
 * Until Phase 9 this function read the two mail secrets and refused when either
 * was absent. That check is not gone, it moved: a principal cannot be built
 * without both, so by the time one exists both are known good. The rest of that
 * argument now sits on `davCacheKey` below, where the identity it is about is
 * actually used (code review IN-02).
 */
function requireAppleId(principal: Principal): string {
  return principal.appleId;
}

/**
 * The KV key for one `{appleId, service}` pair (DAV-03).
 *
 * `dav:v1:<sha256hex(appleId)>:<service>`. The Apple ID is hashed, and the
 * reason is NOT secrecy — KV is not world-readable, and anything that can read
 * this namespace can already read its values. It is that a key NAME is exactly
 * the sort of value that ends up somewhere nobody audited: a metrics label, an
 * error string, a `wrangler kv key list` transcript pasted into a conversation.
 * ./.claude/CLAUDE.md §4's discipline is that the Apple ID does not travel, and a
 * hash travels harmlessly.
 *
 * **Two keys, one per service — not one object holding both.** D-61 deletes
 * both entries on `refresh: true` regardless, so the "atomic pair" argument for
 * a single object never pays. Two keys let a CalDAV entry survive a CardDAV
 * re-discovery, and they make DAV-03's `{appleId, service}` key literal rather
 * than encoded inside a value.
 *
 * **THE IDENTITY KEYED HERE IS THE SAME ONE THE DAV FETCH LOGS IN WITH (D-13).**
 * The cache key and the DAV login moved to the principal together, in one plan,
 * and that is why. A key read from one identity and a login from another would
 * let the home-set check compare a caller's target against somebody else's
 * home. The hash is over the Apple ID exactly as the principal carries it, so
 * the owner's key did not move when this changed. Nothing in this module
 * retains the address.
 *
 * **An unset secret answers before any request is built.** It shows up as a
 * promise of the principal that rejects. Each DAV tool callback awaits that
 * promise as the first line of its `try`, and the DAV fetch awaits it at the
 * top of every request, so `auth_failed` arrives ahead of the network on both
 * paths — the cache-hit path, where no request is ever built, included.
 */
async function davCacheKey(appleId: string, service: DavService): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", ENCODER.encode(appleId));
  return `${DAV_CACHE_KEY_PREFIX}:${hex(digest)}:${service}`;
}

/**
 * Rebuild the `DAVAccount` every later tsdav call takes.
 *
 * This exists so that `serverUrl` — the one field carrying a hostname literal —
 * is produced here rather than at each call site. The alternative is every
 * calendar and contacts module importing a host constant, which is the exact
 * spread this module's header exists to prevent.
 *
 * **`credentials` is never populated.** The type marks it optional, and leaving
 * it unset is what makes D-55's claim structurally true rather than merely
 * intended: with the standalone functions, no object holding the password is
 * ever constructed at all.
 */
export function davAccountFor(
  service: DavService,
  resolved: Pick<ResolvedDavAccount, "rootUrl" | "principalUrl" | "homeUrl">,
): DAVAccount {
  return {
    accountType: service,
    serverUrl: SERVER_URL[service],
    rootUrl: resolved.rootUrl,
    principalUrl: resolved.principalUrl,
    homeUrl: resolved.homeUrl,
  };
}

/**
 * Run tsdav's three-stage chain, and let nothing untyped out of it.
 *
 * **This wrapper is the difference between a typed refusal and a bare `Error`,
 * and the case it exists for is not hypothetical.** When a PROPFIND comes back
 * as a perfectly well-formed 207 that simply carries no `current-user-principal`
 * href — or no home-set href — tsdav does not return an empty string, which
 * would be the worse outcome; it throws its own `Error("cannot find
 * principalUrl")`. That error is untyped, so `davToErrorCategory` would fall
 * through to `connection_failed` and tell the user to check their network about
 * a server that answered promptly and correctly. `not_found` is the honest
 * category, and the plan's own must-have names it.
 *
 * A `Dav*` error passes through UNCHANGED, and that ordering is the whole
 * design. Those were classified at the fetch boundary by status number, which
 * is strictly better information than anything recoverable here — flattening a
 * 401 into `not_found` would put an auth failure onto the re-discovery path
 * D-60 exists to keep it off.
 *
 * `rediscoverable: false`, deliberately. This failure happened DURING discovery,
 * so re-running discovery is precisely the thing that just failed; retrying it
 * would spend a second request to reach the same answer.
 *
 * The caught value is never read — not its message, not its stack, not its
 * name. tsdav's messages embed the resolved server URL verbatim, and the
 * discovery layer exists so that value never travels.
 */
async function discoverAccount(
  davFetch: DavFetch,
  service: DavService,
): Promise<DAVAccount> {
  try {
    return await createAccount({
      account: { serverUrl: SERVER_URL[service], accountType: service },
      headers: {},
      fetch: davFetch,
    });
  } catch (err) {
    if (
      err instanceof DavAuthError ||
      err instanceof DavThrottleError ||
      err instanceof DavNotFoundError ||
      err instanceof DavConnectError
    ) {
      throw err;
    }
    throw new DavNotFoundError(false);
  }
}

/**
 * Resolve one service's root, principal and home URLs (DAV-02, DAV-03).
 *
 * On a cache hit this issues **zero** outbound requests — no PROPFIND, no
 * well-known probe, nothing. That is the entire point of D-55's standalone-
 * function API: `createAccount` is the only call that needs a `serverUrl`, and
 * everything after it takes the three URLs directly.
 *
 * On a miss it runs tsdav's three-stage chain and stores the result. **Neither
 * of `createAccount`'s two eager-load flags is ever passed**, and they are
 * described here rather than spelled, on `src/mail/socket.ts`'s own precedent:
 * a future scan rule bans those two token names under `src/dav/`, so a comment
 * naming them would fail the very check it was explaining. Both default to
 * false, and either one turns discovery into a fan-out over every collection —
 * one of them additionally fetching every object inside each — which is a
 * connection-budget failure and a response-size failure in a single flag. The
 * call below passes exactly four keys, so neither is expressible without an
 * edit that shows up in a diff.
 *
 * An absent or empty URL on the result throws rather than caching. An empty
 * string used as a later request target resolves against nothing and produces a
 * failure whose cause is invisible; a typed refusal at the point of knowledge
 * is the cheaper failure by a wide margin.
 */
export async function resolveDavAccount(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  service: DavService,
): Promise<ResolvedDavAccount> {
  const key = await davCacheKey(requireAppleId(principal), service);

  const cached = await env.DAV_CACHE.get<CachedDiscovery>(key, "json");
  if (
    cached &&
    cached.rootUrl &&
    cached.principalUrl &&
    cached.homeUrl
  ) {
    return { ...cached, cacheHit: true };
  }

  const account = await discoverAccount(davFetch, service);

  const { rootUrl, principalUrl, homeUrl } = account;
  if (!rootUrl || !principalUrl || !homeUrl) {
    // A PROPFIND that carried no `current-user-principal` href, or no home-set
    // href, reaches here. Refusing is what stops an empty string becoming a
    // request target one layer up.
    throw new DavNotFoundError(false);
  }

  const value: CachedDiscovery = { rootUrl, principalUrl, homeUrl };
  try {
    await env.DAV_CACHE.put(key, JSON.stringify(value), {
      expirationTtl: DISCOVERY_TTL_SECONDS,
    });
  } catch {
    // A failed cache WRITE degrades this call to uncached and must not fail the
    // operation — the three URLs in hand are correct either way.
    //
    // Swallowed SILENTLY, because ./.claude/CLAUDE.md §4 forbids logging it. That
    // is not a blind spot: `dav_diagnose` reports `cacheHit` per service, so a
    // namespace that has quietly stopped accepting writes shows up as a run
    // where nothing is ever a hit. It is one more reason D-54 is permanent
    // surface rather than scaffolding.
  }

  return { ...value, cacheHit: false };
}

/**
 * Delete one service's cache entry, or both (D-61).
 *
 * Both is the default because that is what `refresh: true` means: the caller is
 * saying they do not trust what is stored, and trusting half of it would make
 * the answer harder to read rather than easier.
 */
export async function clearDavCache(
  env: Env,
  principal: Principal,
  service?: DavService,
): Promise<void> {
  const appleId = requireAppleId(principal);
  const services = service ? [service] : DAV_SERVICES;
  // Sequential. Every KV operation counts against the same per-invocation
  // budget as an outbound request (./.claude/CLAUDE.md §3), and two deletes are
  // not worth a combinator.
  for (const one of services) {
    await env.DAV_CACHE.delete(await davCacheKey(appleId, one));
  }
}

/**
 * Whether D-60 permits ONE re-discovery and ONE retry for this failure.
 *
 * Two classes qualify, and the second is the one worth explaining.
 *
 * `DavNotFoundError` with `rediscoverable === true` is the enumerated status
 * list — 400, 404, 410 and any 3xx — classified by NUMBER at the fetch boundary
 * in `./transport.ts`. Its `false` sibling (415, 501) is a statement about a
 * missing capability rather than about a stale host, so it is excluded here by
 * the field rather than by the class.
 *
 * `DavConnectError` qualifies too, because a transport-level failure against a
 * host this module handed out FROM CACHE is the same event wearing different
 * clothes: a shard that has been retired answers a connection attempt with
 * nothing at all just as readily as it answers a PROPFIND with a 410. The
 * `cacheHit` guard below is what keeps this from becoming "retry the network
 * twice" — a connect failure on a freshly-resolved host is not eligible,
 * because there is no stale entry to blame for it.
 *
 * **`DavAuthError` and `DavThrottleError` cannot reach the retry from here, and
 * that is checked in code rather than left to a comment.** D-60 makes 401/403
 * and 429/503 immediate for reasons about Apple's account-level behaviour, not
 * about correctness: two services times two attempts on every tool call is
 * exactly the cadence that gets an account locked out of Mail.app on the user's
 * own devices, and a server that has just said it is throttling is the last
 * thing to send a second request to. Neither class is named below, so neither
 * can be added by accident — only by an edit that shows up in a diff.
 *
 * **`DavStaleResourceError` stands on exactly that footing, and it is the one
 * this function is silent about by design.** A 412 says the etag the write
 * named is no longer the resource's etag. Re-issuing that write against a
 * freshly-resolved host asks the same server the same question about the same
 * resource and gets the same refusal, so the retry cannot succeed and its only
 * effect is to make a failed commit cost two requests instead of one — against
 * the tightest budget this project has, on the path a user hits precisely when
 * something has already gone wrong. It is not named below, so it returns
 * `false` for free; and like the two above, adding it would show up in a diff
 * rather than arriving by accident.
 */
function isRediscoverable(err: unknown): boolean {
  if (err instanceof DavNotFoundError) return err.rediscoverable;
  return err instanceof DavConnectError;
}

/**
 * Run one operation against a resolved account, with D-60's single retry.
 *
 * The whole policy in one place: resolve, run, and — only when the account came
 * from CACHE and the failure is one a stale host would produce — delete that
 * entry, resolve live, and run the operation exactly once more.
 *
 * **`allowRediscovery` is a PARAMETER, and the shape of it is the point.** A
 * module-level flag would be shared across every request in an isolate, which
 * is the mistake the comment on `createServerFactory`'s session gate already
 * warns about. A counter would be mutable state whose test passes while the
 * recursion is still reachable — decrement it in the wrong branch and the loop
 * comes back with a green suite. A parameter that is `false` on the second call
 * cannot loop regardless of how the failure arrives, because the second call
 * has no branch that retries: the guard is read before the error is even
 * inspected. Two attempts is the ceiling, structurally.
 *
 * The cache-hit guard is the other half. A failure after a LIVE resolution has
 * no stale entry to blame, so re-running discovery would ask Apple the same
 * question again and get the same answer — one more request against a budget
 * that is already the tightest constraint this project has.
 *
 * The operation receives the resolved account, not a URL, so a caller that
 * needs `homeUrl` and one that needs a full `DAVAccount` via `davAccountFor`
 * are the same call site shape.
 */
export async function withRediscovery<T>(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  service: DavService,
  operation: (resolved: ResolvedDavAccount) => Promise<T>,
  allowRediscovery = true,
): Promise<T> {
  const resolved = await resolveDavAccount(env, principal, davFetch, service);

  try {
    return await operation(resolved);
  } catch (err) {
    // Read FIRST, before the error is classified. On the retry this is `false`
    // and the function is a plain pass-through — there is no path from here to
    // a third attempt.
    if (!allowRediscovery) throw err;
    if (!resolved.cacheHit) throw err;
    if (!isRediscoverable(err)) throw err;

    await clearDavCache(env, principal, service);
    return withRediscovery(env, principal, davFetch, service, operation, false);
  }
}

/**
 * Refuse a request target that is not this account's own (03-REVIEW.md CR-01).
 *
 * ## Why the check is here and not in the decoder
 *
 * An opaque DAV id is `base64url(JSON)` carrying absolute URLs, with no
 * signature and no server-side binding, and `./ids.ts` validates it as far as it
 * possibly can: `assertUrl` checks the field is an absolute `https` URL. That is
 * the CEILING of what that module can check, not an oversight in it. `./ids.ts`
 * runs BEFORE discovery and holds no account state, so there is nothing there to
 * compare a host against — "is this URL well-formed" is a different question
 * from "is this URL MINE", and only the second one is an authorisation.
 *
 * The consequence of leaving the second question unasked was concrete.
 * `./transport.ts` attaches `Basic` credentials to every call for any URL, so a
 * caller-supplied collection URL used directly as a request target sends the
 * Apple ID and the app-specific password wherever the token said. The model may
 * have read that token out of an event description a stranger wrote, which makes
 * this reachable from prompt-injected content rather than only from a hostile
 * caller. `pagedEvents` never had the problem, because intersecting a decoded
 * calendar id against the enumerated collections happens to be an authorisation
 * as well as a lookup — this function is that same check for the paths whose
 * whole argument was that they cost NO lookup.
 *
 * ## Why origin, and why the trailing slash
 *
 * `origin` folds scheme, host and port into one comparison, so a token naming
 * the real host on another port is a different origin, and the userinfo form
 * `https://realhost@attacker.example/` — which reads as the real host to a human
 * and to a substring test — parses to an origin of `attacker.example`. A
 * `hostname` comparison catches the first; only `origin` catches both.
 *
 * Normalising the home pathname to end in `/` before the prefix test is
 * load-bearing rather than tidy. Without it a home path of
 * `/1234567890/calendars` admits a sibling `/1234567890/calendarsEVIL/`, which
 * is SAME-ORIGIN — so the origin check cannot see it — and the credential
 * travels to a path this account does not own.
 *
 * ## Why it reports nothing
 *
 * `DavNotFoundError(false)` is the same construction both call sites already use
 * for a resource the server did not return, and `davToErrorCategory` dispatches
 * on type alone, so the refusal is byte-identical at the tool layer to a genuine
 * not-found. That is deliberate: a distinguishable refusal is a
 * collection-existence oracle handed to the same forged id this exists to
 * refuse. Nothing about the rejected URL is carried either — it is
 * attacker-chosen, and the home URL it was compared against holds the account
 * DSID and the resolved shard host, which are the two values this module exists
 * to keep off the wire.
 *
 * `rediscoverable` is FALSE for a reason specific to this check rather than by
 * convention: re-discovery re-resolves the account's OWN home URLs, and no
 * amount of re-resolving makes an attacker's host belong to the account. Passing
 * `true` would spend one of D-60's two permitted retries — a real PROPFIND
 * against iCloud — on every forged id ever submitted, turning a refusal into an
 * amplifier against the connection budget.
 *
 * Synchronous, and it reaches no network. A refusal therefore costs zero
 * outbound requests on a warm discovery cache.
 */
export function assertUnderHome(url: string, homeUrl: string): void {
  let target: URL;
  let home: URL;
  try {
    target = new URL(url);
    home = new URL(homeUrl);
  } catch {
    // The caught value is never read. One of the two strings is
    // attacker-chosen, and a `URL` parse failure's message quotes its input.
    throw new DavNotFoundError(false);
  }

  if (target.origin !== home.origin) throw new DavNotFoundError(false);

  const homePath = home.pathname.endsWith("/")
    ? home.pathname
    : `${home.pathname}/`;
  if (!target.pathname.startsWith(homePath)) throw new DavNotFoundError(false);
}
