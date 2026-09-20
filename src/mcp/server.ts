// Per-request MCP server construction.
//
// `createMcpHandler` calls this factory once per request, so each request
// gets a fresh, isolated server instance and nothing is shared between
// callers.

import { McpServer } from "@modelcontextprotocol/server";
import type { McpServerFactory } from "@modelcontextprotocol/server";
import { createDavFetch } from "../dav/transport";
import { createSessionGate } from "../mail/service";
import type { Principal } from "../principal";
import { registerCalendarTools } from "./tools/calendar";
import { registerContactsTools } from "./tools/contacts";
import { registerDavDiagnoseTool } from "./tools/dav-diagnose";
import { registerDiagnoseTool } from "./tools/diagnose";
import { registerMailTools } from "./tools/mail";

/**
 * Build the per-request server factory.
 *
 * `extraTools` is the test-injection seam. Production passes nothing, so the
 * shipped tool surface is exactly the tools registered below — two
 * diagnostics, Phase 2's five mail tools, and Phase 3's calendar tools — and
 * nothing that deliberately
 * misbehaves reaches the deployed bundle. A later plan's ordering proof needs
 * a tool that records its own invocation in order to assert the tool layer
 * was never reached on an unauthenticated request; it registers that through
 * this parameter, from a test-only Worker entry, against this same real
 * factory. 01-02-SUMMARY.md records why that test's own name is kept out of
 * this file entirely.
 *
 * `principal` is a PROMISE of who this request acts for, and it comes first
 * because every caller must supply it. The API handler makes it and hands it in
 * by closure, so this file never reads the grant's props. The body below stays
 * synchronous and never awaits it: a rejection here would become a 500 with no
 * challenge. Each tool callback awaits it instead, as the first line of its own
 * `try`, where its own `catch` turns a refusal into `auth_failed`.
 */
export function createServerFactory(
  principal: Promise<Principal>,
  extraTools: Array<(server: McpServer) => void> = [],
): McpServerFactory {
  return () => {
    const server = new McpServer({ name: "icloud-mcp", version: "0.1.0" });
    // Request-scoped BY CONSTRUCTION. This factory body runs once per request,
    // so the gate below cannot be shared with another caller — no bookkeeping,
    // no isolate-wide counter, and therefore no false refusal of a legitimate
    // second request that happened to land in the same isolate. Moving this
    // line to module scope would silently reintroduce exactly that failure.
    //
    // The DAV fetch beside it is request-scoped for a RELATED but different
    // reason, and the difference is worth knowing before either line is moved.
    // The gate refuses a second acquisition, so an isolate-wide one would
    // falsely refuse a legitimate concurrent request. The DAV fetch queues
    // rather than refuses, so an isolate-wide one would not refuse anything —
    // it would quietly grow one caller's queue behind another's and turn the
    // whole isolate into a single-file line. Both belong here; neither belongs
    // at module scope.
    const gate = createSessionGate();
    // The DAV fetch takes the PROMISE and awaits it inside each request it
    // sends, so this body stays synchronous. It was this file's only use of the
    // ambient environment, which is why that import is gone.
    const davFetch = createDavFetch(principal);
    // Every registrar below gets the SAME promise of the principal. Each tool
    // callback awaits it as the first line of its own `try`. The DAV fetch
    // above awaits it too, at the top of every request it sends, so the login
    // and the cache key always belong to one identity (D-13).
    registerDiagnoseTool(server, principal);
    registerMailTools(server, gate, principal);
    registerDavDiagnoseTool(server, davFetch, principal);
    // The same `davFetch` the diagnostic takes, deliberately: one queue per
    // request means a calendar call and a diagnosis issued in the same request
    // serialise against each other rather than racing for the connection
    // budget §3 describes.
    registerCalendarTools(server, davFetch, principal);
    // The same `davFetch` again, for the same reason, and this line completes
    // Phase 3's tool surface: one diagnostic, four calendar tools and two
    // contacts tools, alongside Phase 2's mail tools.
    registerContactsTools(server, davFetch, principal);
    for (const register of extraTools) register(server);
    return server;
  };
}
