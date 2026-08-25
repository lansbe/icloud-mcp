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
import { createMcpHandler } from "agents/mcp/server";
import { oauthProviderOptions } from "../../src/auth/oauth";
import type { Env } from "../../src/env";
import { DEPLOYED_HOSTNAME } from "../../src/mcp/api-handler";
import { createServerFactory } from "../../src/mcp/server";

/** The name the ordering test calls. Deliberately not a production tool. */
export const CANARY_TOOL_NAME = "canary";

/** Set by the tool callback, and by nothing else. */
let invoked = false;

/**
 * Registers the recording tool into a server built by the real factory.
 *
 * Passed to `createServerFactory` exactly as production passes nothing.
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

// Same handler options as production, so the composition under test is the one
// that ships rather than a convenient simplification of it.
const handler = createMcpHandler(createServerFactory([registerCanary]), {
  route: "/mcp",
  allowedHostnames: [DEPLOYED_HOSTNAME],
  // Mirrors production deliberately, and must move whenever production's does.
  // This option selects which serving lane answers a request, so a stale value
  // here does not merely diverge — it narrows the ordering proof to the lane
  // Claude Desktop does NOT use, leaving the lane it does use as the single
  // lane whose gate is unproven. The reasoning for the value itself lives at
  // the production call site; do not duplicate it here, where it would drift.
  legacy: "stateless",
});

// The same explicit adapter production uses. Assigning the handler directly
// would drop the ExecutionContext, which is a different bug from the one this
// fixture exists to catch — but it would change the composition under test.
const provider = new OAuthProvider<Env>({
  ...oauthProviderOptions,
  apiHandler: {
    fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      return handler(request, env, ctx);
    },
  },
});

/** The observation routes. Kept off any production path by living here. */
const CANARY_ROUTE = "/__canary";
const CANARY_RESET_ROUTE = "/__canary/reset";

/**
 * Reaches the MCP handler with the gate deliberately stepped around.
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
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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
      return handler(new Request(url, request), env, ctx);
    }

    return provider.fetch(request, env, ctx);
  },
};
