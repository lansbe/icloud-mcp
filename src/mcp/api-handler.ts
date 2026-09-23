// MCP protocol termination, the adapter that gets the request there with its
// ExecutionContext intact, and the door in front of both: only the owner's
// grant is served, and every other grant gets a real 401.

import type { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import type { Env } from "../env";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import type { AllowList } from "../auth/allow-list";
// `isAllowed` is deliberately NOT imported. The door stopped asking the
// membership question, and a leftover import of it here would be a dead
// reference of exactly the kind `test/door.test.ts`'s source tripwire exists to
// catch — the behavioural cases would stay green with one sitting unused.
import { parseAllowList } from "../auth/allow-list";
import type { Principal } from "../principal";
import { normaliseAppleId, principalFromProps } from "../principal";
import { guardAgainstPause } from "../password-pause";
import { createServerFactory } from "./server";

/**
 * The single production hostname, as it must appear inside the Worker bundle.
 *
 * Its one source of truth is `routes[0].pattern` in wrangler.jsonc, so a
 * deployer sets the hostname in config and never edits code. That value cannot
 * be read here directly — this module runs inside a deployed Worker, which has
 * no filesystem and cannot read the config off disk — so it is baked into the
 * bundle at build time: `scripts/hostname.mjs` derives it from the config and
 * `scripts/write-hostname.mjs` writes it into the git-ignored generated module
 * re-exported below (regenerated on prepare/pretest/pretypecheck/predeploy).
 *
 * Re-exported from here, rather than imported from the generated file
 * throughout, so every existing importer (`src/auth/oauth.ts`, the tests) keeps
 * one stable import path. Do NOT reintroduce a hardcoded literal here: that
 * would be a second home nothing forces to match the route, and
 * `scanWranglerConfig` in scripts/forbidden-tokens.mjs fails the commit on it.
 */
export { DEPLOYED_HOSTNAME };

/** The options object `createMcpHandler` takes, named by where it goes. */
type HandlerOptions = NonNullable<Parameters<typeof createMcpHandler>[1]>;

/** A tool registrar the test fixture hands in. Production hands in none. */
type ExtraTool = (server: McpServer) => void;

/**
 * The options every per-request MCP handler is built with.
 *
 * One module-scope constant, so the door, the production handler and the test
 * fixture's handler cannot drift apart: all three are built from this object.
 * The handler itself is built per request (see `buildRequestHandler`). These
 * options are not.
 */
const HANDLER_OPTIONS: HandlerOptions = {
  route: "/mcp",

  // Neither of the next two is optional here, and for one reason. The handler
  // derives its accepted-host list from the workers.dev hostname when one
  // exists, and D-02 deliberately removed that, so on a custom domain the list
  // is otherwise undefined and Host-header validation is skipped entirely.
  // Passing it explicitly closes a gap that D-02 opened as a side effect.
  allowedHostnames: [DEPLOYED_HOSTNAME],

  // The identical derivation exists for origins, so the identical omission was
  // available. Left unset on a custom domain that is neither localhost nor a
  // workers.dev host, the accepted origin set collapses to localhost-class
  // origins — and the production origin is not among them, so a browser-hosted
  // MCP client served from this very hostname has its own Origin rejected.
  // That failure is fail-closed and therefore safe; it is also silent and
  // confusing, and it is the same oversight the line above was written to
  // prevent. Setting it stops the next reader concluding the omission was
  // deliberate.
  //
  // corsOptions is deliberately left at its default even though that default
  // emits a wide-open allow-origin header: this endpoint is bearer-only, with
  // no cookie and no credentialed request involved, so the header grants a
  // browser nothing it could not already fetch with a token it does not have.
  // Recorded here so it is not re-derived, and not narrowed on a hunch.
  allowedOriginHostnames: [DEPLOYED_HOSTNAME],

  // The 2025-era compatibility lane is SERVED, not refused. This reverses the
  // modern-clients-only decision that stood here, and the four things worth
  // knowing about that reversal are below.
  //
  // (a) Why it was reversed. Claude Desktop's connector posts `initialize`
  //     carrying no protocol-version envelope at all — no `_meta` claim and no
  //     protocol-version request header. Observed live against production with
  //     `wrangler tail`, user-agent `Claude-User`, answered 400 with an
  //     unsupported-protocol-version error; the same path's GET answered 405.
  //     Both are the modern-only refusal. The SDK will not guess a version, and
  //     it is right not to. But the consequence was that this endpoint was
  //     unreachable from the only client it exists to serve, having just
  //     completed the full authorization ceremony successfully — the worst
  //     possible shape of failure, because everything up to the last step
  //     works.
  //
  // (b) This is NOT a second way in. The original decision's concern was a
  //     second stateless TRANSPORT, and that concern was about transports, not
  //     about gates — worth saying plainly, because "a second path" reads like
  //     "a second door" to anyone skimming. There is one door. The OAuth
  //     provider routes /mcp to this handler only after validating the bearer
  //     token, and inside the handler the host check, the origin check and the
  //     OAuth auth-info resolution all run before the lane is chosen at all;
  //     the lane is selected last, from inside the authenticated boundary.
  //     `test/auth-ordering.test.ts` proves that rather than restating it: an
  //     unauthenticated claim-less tools/call answers 401 with a canary tool
  //     that records no invocation, against a positive control showing the very
  //     same request DOES reach the tool when the gate is stepped around. The
  //     control is what makes the proof worth having, and it is the assertion
  //     that fails if this option is ever changed without thought.
  //
  // (c) What the compatibility lane CHANGES. Two things, not one. An earlier
  //     draft of this paragraph said "exactly one capability", and code review
  //     disproved it by probe (02-REVIEW WR-01) — so read this one as
  //     measured rather than reasoned.
  //
  //     It GIVES UP one capability: server-to-client requests — elicitation
  //     and sampling — which the lane answers immediately with an
  //     internal-error response rather than leaving a tool handler waiting
  //     forever on a reply that cannot arrive. Streaming and keepalive are
  //     unaffected. This server's surface — five mail tools plus one
  //     diagnostic — makes no such request, so that loss is currently zero. It
  //     stops being zero the day a tool asks the client a question.
  //
  //     It also ADMITS a request shape the superseded value refused: an
  //     all-legacy JSON-RPC BATCH array. The superseded value answered such a
  //     post with 400 and the message that batches are not supported by this
  //     endpoint. This one serves it — and the SDK dispatches the batch's
  //     entries CONCURRENTLY against the single server the factory built for
  //     this request, so two mail tool handlers really can be in flight at
  //     once inside one Worker invocation. Confirmed in the real workerd pool,
  //     not inferred: a two-entry tools/call batch recorded entry, entry, exit,
  //     exit, in that order.
  //
  //     Both lanes still build the same server from the same factory, so the
  //     tool surface and the request-scoped session gate are identical — but
  //     note what "identical gate" now buys. Before this reversal, two mail
  //     handlers could not overlap here at all; it was structurally impossible
  //     rather than merely defended. It is now a race that `createSessionGate`
  //     WINS. CLAUDE.md §3's socket cap is intact, and for a specific reason
  //     rather than a hopeful one: `gate.acquire()` sits BEFORE the `try` in
  //     `withMailSessionOver`, so a refused second caller never reaches the
  //     `finally` and cannot release the first caller's slot; and
  //     `withMailSession`'s `if (gate.held)` → `connectImap()` →
  //     `withMailSessionOver` chain has no `await` ahead of that acquire, so
  //     there is no suspension point for a second entrant to interleave into.
  //     Anyone editing either of those is editing this guarantee, from a file
  //     that does not mention it. The promise of the principal the door makes
  //     below is awaited at the top of each tool callback, which is outside
  //     the check-and-acquire pair, so that pair is still atomic: two batch
  //     entries may both suspend on that await, and each then runs from the
  //     held check to the acquire with no suspension point in between.
  //
  //     One consequence is recorded rather than fixed. The second mail call in
  //     a batch is refused with `ImapThrottleError`, whose prose names iCloud
  //     rather than us — an inaccuracy accepted deliberately back when the only
  //     way to reach it was a genuine second session. In a batch it fires for a
  //     call that never touched the network, telling the model Apple is
  //     throttling the user when nothing of the sort happened. Left as is
  //     because no client this endpoint exists to serve sends batches; revisit
  //     it the day one does.
  //
  //     A second consequence is accepted rather than covered, and stated here
  //     because the absence is invisible from the test suite. NOTHING in the
  //     suite exercises a batch. The reasoning above is a TRACE — the acquire's
  //     position and the absent await were read, and the interleaving was
  //     measured once by a review probe that was not kept — so the guarantee
  //     rests on that reading plus these two structural facts, not on a
  //     regression test. A refactor that introduced an `await` ahead of
  //     `gate.acquire()` would breach the socket cap with the whole suite still
  //     green. Accepted knowingly (02-VERIFICATION.md, WR-01 acceptance): the
  //     shape is unreachable by any client this endpoint serves, and the lane
  //     is scheduled for retirement at (d) below rather than for hardening.
  //     If that retirement slips, write the test.
  //
  // (d) When to re-tighten. When Claude Desktop sends the 2026-07-28 envelope,
  //     this goes back to the modern-clients-only value and the compatibility
  //     lane is retired. That is a one-word edit here and nowhere else: the
  //     test fixture's handler is built from these same options.
  //
  // The value below is the library default and the option's documented
  // stateless-serving mode; the superseded value is the other of the two the
  // option accepts. Deliberately cited by behaviour rather than by a path into
  // the installed dependency tree — that bundle's filename carries a content
  // hash that changes on every release, so such a reference is stale by the
  // next install.
  legacy: "stateless",
};

/**
 * Is this a grant this server will still serve (D-07, GATE-03, GATE-05)?
 *
 * Yes only for a plain object with exactly three own keys, one of them a string
 * `appleId` this server can fold, on a deployment whose SEED is usable. That is
 * the shape the login page mints. Everything else is a no: the OLD single-key
 * owner grant (GATE-05 — those are what this replaces, and they must be refused
 * rather than honoured), any grant at all on a deployment whose seed is
 * missing, empty or malformed (GATE-03), an address this server cannot fold,
 * null, an array, and no props at all. The handler library only builds an auth
 * context when the props hold a key, so "nothing there" has to read as a bad
 * grant and not as a crash.
 *
 * **The seed is re-read on EVERY request, with no cache**, and that half of the
 * old claim survives intact: it costs one parse of a small string and no I/O at
 * all.
 *
 * **What this no longer does, stated bluntly rather than softened.** It used to
 * compare the grant's address against the whole allow list, which made removing
 * somebody take effect on their very next call. It cannot do that any more for
 * a STORE-LISTED address. The store is a KV namespace and there is no way to
 * read one synchronously; making this path async would break the never-awaits
 * contract on `createMcpApiHandler` below, and that contract is what makes an
 * unusable stored credential surface as a tool error rather than as a 401
 * telling the client to sign in again — advice that cannot help when the
 * password died at Apple.
 *
 * So a well-shaped grant carrying an address the seed does not name is SERVED.
 * The grant is itself the evidence that a login passed the store check when it
 * was minted.
 *
 * **What covers the gap.** Removal is two steps: take the person out of the
 * store so they cannot sign in again, then revoke their grants to end a live
 * session. Phase 12's LIFE-05 revoke script is that second half. Until it
 * ships, the stopgap is deleting BOTH the grant records and the token records
 * for that user id from `OAUTH_KV` by hand; the README gives the steps. The
 * grant record alone is not enough: an access token is checked against its own
 * token record, which carries a copy of the grant, so it keeps working for up
 * to an hour after the grant is gone.
 *
 * **What still holds today.** The allow list holds exactly one address — the
 * owner's — for the whole of this phase, and the store starts empty, so the
 * only grant that can exist is the owner's. Removing the owner leaves the seed
 * unusable, and an unusable seed still refuses every grant here on the next
 * request. The weakening becomes real with the first store entry, which is a
 * later phase, after LIFE-05 exists.
 *
 * **It checks the address and never the password.** A grant whose password
 * Apple has since revoked still passes here, and that is correct: the tool then
 * reports an authentication failure, which is the honest answer, where a 401
 * would tell the client to sign in again — advice that cannot help when the
 * problem is at Apple rather than here.
 *
 * It returns a boolean and never throws. A throw on this path becomes a 500
 * with no challenge (spike S1), and a client that gets a 500 has no way to know
 * it should sign in again. The narrowing is the cast-free idiom the principal
 * module uses.
 *
 * **`Reflect.ownKeys` rather than `Object.keys`, and the standard is chosen
 * deliberately.** `Object.keys` counts enumerable STRING keys only, so props
 * carrying a symbol key, or a non-enumerable one, would pass a count of three
 * while holding a fourth thing. `Reflect.ownKeys` counts every own key of
 * either kind. `principalFromProps` makes the same choice one module over, and
 * the two must agree: a grant this function admitted and that constructor then
 * refused would read to the caller as an authentication failure rather than as
 * the bad grant it is.
 *
 * THE CATCH IS WHAT MAKES "NEVER THROWS" TRUE (code review WR-01). Three of the
 * lines below run code this function did not write. The membership test and the
 * own-keys read go through a Proxy's traps if the value is a Proxy, and reading
 * the address runs an accessor if the key is one. Today none of that is
 * reachable: props reach the context only through a parse of the decrypted
 * grant, which builds plain objects with data properties, and the external-token
 * resolver is not configured. So the catch costs nothing today and the claim
 * above is a claim about the code rather than about what currently feeds it.
 *
 * IT FAILS CLOSED. A grant this function cannot inspect is not one it will
 * serve, so the catch returns false and the request gets the 401 every other
 * bad grant gets. The caught value is never read, never logged and never
 * echoed: it can carry text a stranger wrote.
 */
function servesThisGrant(props: unknown, allowed: AllowList): boolean {
  try {
    if (typeof props !== "object" || props === null || Array.isArray(props)) {
      return false;
    }
    if (!("appleId" in props)) return false;
    if (Reflect.ownKeys(props).length !== 3) return false;
    if (!Object.hasOwn(props, "appleId")) return false;
    const appleId = props.appleId;
    if (typeof appleId !== "string") return false;
    // The fold is kept even though nothing is compared against it any more: an
    // address this server cannot read is not one it can act for, and that is
    // the fail-closed edge for a grant carrying a mangled address.
    if (normaliseAppleId(appleId) === null) return false;
    // The seed's own usability test, which is the same expression the login
    // gate uses one module over. Anything other than "nobody" means this
    // deployment serves somebody, so it serves this grant.
    return allowed.kind !== "nobody";
  } catch {
    // Never read the caught value. A grant we cannot inspect is not one to
    // serve, so this answers the same way every other bad grant is answered.
    return false;
  }
}

/**
 * The door's own 401, for a grant that is not the owner's.
 *
 * Built from the same parts the OAuth library uses for its own 401, in the
 * same order: the realm, the protected-resource metadata document for the
 * requested path, the error code, and the one scope this server has. The
 * metadata URL comes from the request URL, never from a hostname literal.
 *
 * **Fixed strings and the request URL only.** Nothing from the props, the
 * environment or a caught value is ever put in the body or in a header.
 *
 * It skips the CORS headers the MCP handler adds to its own answers. The
 * library's own 401 skips them too, and this endpoint is bearer-only: no cookie
 * and no credentialed browser request is involved, so there is nothing for
 * those headers to allow.
 */
function unauthorized(request: Request): Response {
  const url = new URL(request.url);
  const metadataUrl = `${url.origin}/.well-known/oauth-protected-resource${url.pathname}`;
  return new Response(
    JSON.stringify({
      error: "invalid_token",
      error_description: "Stored login is out of date. Sign in again.",
    }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "WWW-Authenticate": `Bearer realm="OAuth", resource_metadata="${metadataUrl}", error="invalid_token", scope="mcp"`,
      },
    },
  );
}

/**
 * Build the MCP handler for ONE request.
 *
 * The factory closes over the promise of the principal, so the tool layer gets
 * the principal without ever reading the grant's props itself. The options are
 * the production ones, always. The test fixture's route that steps around the
 * gate and the door calls this too, so the composition under test is the one
 * that ships.
 *
 * Built per request rather than once at module scope because the principal
 * belongs to the request. Spike S1 ran this shape on both lanes and saw no
 * problem from it.
 *
 * **NOTHING PUTS A DOOR IN FRONT OF THIS FUNCTION** (code review IN-04). It
 * builds a fully served tool layer out of any promise of a principal, with no
 * owner check anywhere ahead of it. The long comment further up this file
 * argues that there is one door, and this export is a way to the same handler
 * that goes around it. Two callers today: `createMcpApiHandler` below, which
 * answers the 401 first and only then calls this; and the canary test fixture,
 * which calls it deliberately as the positive control that proves the door is
 * what stops a bad grant. Nothing routes it from `src/index.ts`, so nothing
 * deployed can reach it.
 *
 * A second caller under `src/` would be a change to the project's safety
 * boundary and not a refactor. Get a decision first.
 */
export function buildRequestHandler(
  principal: Promise<Principal>,
  extraTools: ExtraTool[] = [],
): ReturnType<typeof createMcpHandler> {
  return createMcpHandler(
    createServerFactory(principal, extraTools),
    HANDLER_OPTIONS,
  );
}

/**
 * Build the API handler: the door, and behind it the per-request MCP handler.
 *
 * `extraTools` is the same test-injection seam the server factory has.
 * Production passes nothing.
 *
 * **Nothing in `fetch` throws and nothing in it awaits.**
 *
 * - A throw here becomes a 500 with no challenge (spike S1). So the guard
 *   returns a boolean and the 401 is built right here. The guard's own catch is
 *   what holds that up against props this code did not build (code review
 *   WR-01): it inspects the grant, and inspecting is the part that can run
 *   someone else's code.
 * - The principal is handed on as a PROMISE (D-09, D-27). An unusable stored
 *   credential must read `auth_failed` from the tool and never a 401: a 401
 *   tells the client to sign in again, and signing in again cannot fix a
 *   password Apple has revoked — only making a new one at Apple can. So this
 *   function does not wait to find out. Each tool callback awaits the promise
 *   as the first line of its own `try`, and its own `catch` maps a refusal to
 *   the category.
 * - The allow list's SEED is parsed HERE, synchronously, on every request. The
 *   parse does no I/O — it reads a string off the environment and answers a
 *   verdict — so it costs nothing against the no-await rule above. The seed is
 *   the only one of the two allow-list sources this path can read at all: the
 *   store is a KV namespace, reading one is an await, and an await here is the
 *   one thing this function may not do. `servesThisGrant` above carries what
 *   that costs, what covers it, and why nothing regresses this phase.
 * - THE DEAD-PASSWORD PAUSE RIDES INSIDE THE PRINCIPAL PROMISE (LIFE-04), which
 *   is the only place it could go without breaking the line above. `fetch` stays
 *   synchronous because the store read happens after the promise is handed on,
 *   not before.
 * - It costs one OAuth-store read per API request. A tool awaits that read
 *   before it opens a socket or sends a DAV request, so the read never overlaps
 *   one and never spends a connection the request also wants.
 * - A paused user gets the same auth error an unusable stored credential gets,
 *   so the tool answers `auth_failed` — which is already the text telling them
 *   to reconnect and that retrying will not help. This is deliberately NOT a
 *   401: the address is still listed and the grant is still well-formed.
 * - TWO TOOLS ANSWER THROUGH A PAUSE: `mail_imap_diagnose` and `dav_diagnose`
 *   (owner decision, 2026-09-22 — code review WR-04). The exemption is granted in
 *   `src/mcp/server.ts`, at the registrations themselves, and not here: this
 *   function still builds ONE principal promise and still hands on ONE. A second
 *   promise threaded through `buildRequestHandler` was the shape declined, because
 *   the door would then be the place a reader has to look to find out which tools
 *   are gated, and the registrations are where that belongs.
 */
export function createMcpApiHandler(extraTools: ExtraTool[] = []): {
  fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response>;
} {
  return {
    fetch(
      request: Request,
      env: Env,
      ctx: ExecutionContext,
    ): Promise<Response> {
      // The one read of the grant's props in this codebase (D-08).
      if (
        !servesThisGrant(ctx.props, parseAllowList(env.ALLOWED_APPLE_IDS_SEED))
      ) {
        return Promise.resolve(unauthorized(request));
      }

      // Identity comes from the grant, never from the environment. That is the
      // whole of the Phase 11 switch at this line: the per-user principal is
      // the only live identity path from here on, and the environment-backed
      // constructor one module over is a retiring variant that Phase 13 deletes
      // along with the three secrets.
      // Adding this path ALONGSIDE the environment one is the shape that would
      // silently contradict the change — a second person could be stored and
      // never served, because the environment identity would still win here.
      //
      // **The retiring constructor is named here by ROLE and never by name, and
      // that is load-bearing rather than tidy.** `test/door.test.ts` carries a
      // source-text tripwire asserting this file spells its name nowhere, which
      // is what catches a later phase reintroducing the singular identity by
      // leaving a dead reference behind — the behavioural case one block over
      // would still pass with one sitting here unused. Describe it by role.
      //
      // The dead-password pause is checked INSIDE the promise (LIFE-04), and
      // the principal is armed to report a refusal there too. The guard is
      // wrapped around the constructor's promise rather than called after an
      // await, because an await on this line is the one thing this function may
      // not do. Only a principal that came through here is armed, which is what
      // stops the sign-in page — which builds its own — from pausing anybody.
      const principal = guardAgainstPause(
        principalFromProps(ctx.props),
        env.OAUTH_KV,
      );
      // A request that calls no tool never awaits this promise. If the stored
      // credential is unusable it rejects, and a rejection nobody handles is an
      // unhandled rejection. This one no-op handler prevents that. Everyone who
      // awaits `principal` itself still sees the rejection.
      principal.catch(() => {});

      return buildRequestHandler(principal, extraTools)(request, env, ctx);
    },
  };
}

/**
 * The API handler the OAuth provider dispatches to. **An explicit adapter,
 * never the handler itself.**
 *
 * The value `createMcpHandler` returns is a hybrid. It is callable as
 * `(request, env, ctx)`, and it *also* carries a `.fetch` property whose
 * second parameter is a per-request options object, not an environment. The
 * OAuth provider invokes `apiHandler.fetch(request, env, ctx)` — the
 * property, with three arguments. Assigning the handler straight to
 * `apiHandler` therefore lands `env` where request options are expected and
 * drops the ExecutionContext on the floor, taking the OAuth-decrypted
 * `ctx.props` with it.
 *
 * That failure is silent in every way that matters: it does not throw, it
 * does not fail the build, it does not fail a typecheck, and it looks
 * entirely correct in this phase because nothing consumes `props` yet. It
 * would surface much later as an unexplained `undefined` in whichever phase
 * first reads the authenticated principal.
 *
 * Phase 9 is the phase that paragraph predicted. The `fetch` built by
 * `createMcpApiHandler` is the one reader of the grant's props in this
 * codebase, and nothing else under `src/` may read them.
 */
export const mcpApiHandler = createMcpApiHandler();
