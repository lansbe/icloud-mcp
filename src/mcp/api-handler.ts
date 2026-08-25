// MCP protocol termination, and the adapter that gets the request there with
// its ExecutionContext intact.

import { createMcpHandler } from "agents/mcp/server";
import type { Env } from "../env";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
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

const handler = createMcpHandler(createServerFactory(), {
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
  //     that does not mention it.
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
  //     lane is retired. That is a one-word edit here plus the matching one in
  //     `test/fixtures/worker-with-canary.ts`, which pins this same option.
  //
  // The value below is the library default and the option's documented
  // stateless-serving mode; the superseded value is the other of the two the
  // option accepts. Deliberately cited by behaviour rather than by a path into
  // the installed dependency tree — that bundle's filename carries a content
  // hash that changes on every release, so such a reference is stale by the
  // next install.
  legacy: "stateless",
});

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
 */
export const mcpApiHandler = {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handler(request, env, ctx);
  },
};
