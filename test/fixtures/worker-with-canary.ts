// A test-only Worker entry whose tool surface can tell you whether it ran.
//
// The production entry composes the real OAuth provider over a factory that
// registers exactly one tool. This entry keeps every one of those parts — the
// real provider options, the real gate, the real handler composition — and
// changes exactly one thing: the server factory also registers a tool that
// records its own invocation.
//
// That single substitution is what turns "the response was 401" into "the tool
// layer was never reached". A handler could dispatch, run, and have its result
// discarded in favour of a 401, and the status code would look identical from
// outside. Only the tool itself can report that it did not run.
//
// This file lives under test/ so it never enters the deployed bundle: the
// shipped tool surface stays at exactly one tool, and nothing that deliberately
// misbehaves is present in production. The seam it uses — createServerFactory's
// extra-tools parameter — exists in src/ for precisely this purpose and is
// described there without naming this file.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { McpServer } from "@modelcontextprotocol/server";
import { oauthProviderOptions } from "../../src/auth/oauth";
import type { Env } from "../../src/env";
import {
  buildRequestHandler,
  createMcpApiHandler,
} from "../../src/mcp/api-handler";
import { ownerPrincipal } from "./bound-secrets";

/** The name the ordering test calls. Deliberately not a production tool. */
export const CANARY_TOOL_NAME = "canary";

/** Set by the tool callback, and by nothing else. */
let invoked = false;

/**
 * Registers the recording tool into a server built by the real factory.
 *
 * Handed to the API handler's builders, which pass it on to
 * `createServerFactory`, exactly as production passes nothing.
 */
export function registerCanary(server: McpServer): void {
  server.registerTool(
    CANARY_TOOL_NAME,
    { description: "Test-only. Records that the tool layer was reached." },
    async () => {
      invoked = true;
      return { content: [{ type: "text", text: "reached" }] };
    },
  );
}

// The same API handler production uses, door included, with the recording tool
// registered beside the real ones. It is built by production's own function
// from production's own options, so the composition under test is the one that
// ships rather than a convenient copy of it, and there is no option here to
// drift out of step.
const provider = new OAuthProvider<Env>({
  ...oauthProviderOptions,
  apiHandler: createMcpApiHandler([registerCanary]),
});

/** The observation routes. Kept off any production path by living here. */
const CANARY_ROUTE = "/__canary";
const CANARY_RESET_ROUTE = "/__canary/reset";

/**
 * Reaches the MCP handler with the gate AND the door deliberately stepped
 * around. The door serves only the owner's grant, and a bare test context
 * carries no grant at all, so a request sent through the door would get a 401
 * and the control below could never fire.
 *
 * This is the positive control, and without it the whole file proves nothing: a
 * canary that can never fire reports "never invoked" whatever the gate does, so
 * every assertion in the ordering test would pass against a tool that was
 * misregistered, misnamed, or wired to a server nobody consults. This route
 * establishes that the flag does flip when the tool layer is genuinely reached,
 * which is what makes "still false" downstream of the gate mean something.
 */
const CANARY_DISPATCH_ROUTE = "/__canary/dispatch";

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const { pathname } = new URL(request.url);

    // Read the flag. Reset it between cases, so a passing first case cannot
    // mask a failing second one.
    if (pathname === CANARY_RESET_ROUTE) {
      invoked = false;
      return new Response(null, { status: 204 });
    }
    if (pathname === CANARY_ROUTE) {
      return Response.json({ invoked });
    }
    if (pathname === CANARY_DISPATCH_ROUTE) {
      const url = new URL(request.url);
      url.pathname = "/mcp";
      // The per-request handler production builds, from production's options,
      // given the owner's principal the way the door would give it. The no-op
      // handler is the door's too: the recording tool never awaits the promise.
      //
      // The principal comes from the FIXTURE's two constants through the real
      // props constructor, not from the environment. Plan 13-03 deletes the
      // environment constructor, and this fixture had to stop calling it first.
      // Nothing about what the ordering test asserts changes: the constants are
      // the values the pool used to bind, so the principal is the same one.
      const principal = ownerPrincipal();
      principal.catch(() => {});
      return buildRequestHandler(principal, [registerCanary])(
        new Request(url, request),
        env,
        ctx,
      );
    }

    return provider.fetch(request, env, ctx);
  },
};
