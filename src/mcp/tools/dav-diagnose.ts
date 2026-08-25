// The DAV tool boundary opens here: `dav_diagnose`, plus the two shapers every
// later DAV tool imports from this module.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import type { DavDiagnosticOutcome } from "../../dav/diagnose";
import { runDavDiagnosticOutcome } from "../../dav/diagnose";
import { davToErrorCategory } from "../../dav/errors";
import type { DavFetch } from "../../dav/transport";

/**
 * The MCP content result every DAV tool produces, success or failure.
 *
 * A type alias rather than an interface, deliberately: the SDK's callback
 * return type carries an index signature, and TypeScript will not treat an
 * interface as assignable to one — only an alias or an object literal.
 *
 * Declared locally rather than imported from `src/mcp/tools/mail.ts`, matching
 * that file's own local declaration of the same three lines. The alternative is
 * a shared module holding one type alias, which is more machinery than the
 * duplication costs.
 */
type ToolResult = {
  isError?: boolean;
  content: { type: "text"; text: string }[];
};

/**
 * The single translation boundary for every DAV tool.
 *
 * It lives in this module — the first DAV tool module — because all three DAV
 * tool modules in this phase need it and the alternative is three copies of the
 * same six lines. The calendar and contacts modules import it from here.
 *
 * Dispatches on the error's TYPE and never on any message text. The DAV-specific
 * reason is recorded on `davToErrorCategory` and is worth repeating at the
 * boundary that actually emits: tsdav throws bare `Error` objects whose message
 * embeds the resolved server URL, and the discovery layer exists precisely so
 * that the model never learns where the account physically lives.
 *
 * `extra` carries fields this SERVER derived — never anything a server said.
 * Nothing in this phase passes it; it is here because the contacts tool's
 * "which path ran" flag (D-62) has to ride out beside a failure category, and
 * discovering that after three tool modules had each grown their own shaper is
 * the outcome this parameter exists to prevent.
 */
export function davErrorResult(
  err: unknown,
  extra: Record<string, string> = {},
): ToolResult {
  const { category, message } = davToErrorCategory(err);

  return {
    isError: true,
    content: [
      { type: "text", text: JSON.stringify({ category, message, ...extra }) },
    ],
  };
}

/**
 * Turn a finished DAV diagnostic run into the tool's response.
 *
 * Exported for exactly the reason `diagnosticResult` is: no automated job in
 * this repository may authenticate against the real Apple ID (D-09), so a
 * response shaper welded to the transport would be untestable rather than
 * merely awkward.
 *
 * One content block, unfenced, because every value in the report is this
 * server's own observation — a URL it resolved, a hostname it read off that
 * URL, a count it made, a duration it measured. None of it is stranger-authored
 * text, so the untrusted fence would be framing this server's own answer as
 * somebody else's claim.
 *
 * The report is deliberately NOT attached to the failure branch. A failed run's
 * report is mostly nulls, and the one thing it would add — a partial timing —
 * is not worth the ambiguity of a response that looks successful and carries an
 * error category.
 */
export function davDiagnosticResult(outcome: DavDiagnosticOutcome): ToolResult {
  if (!outcome.failed) {
    return {
      content: [
        { type: "text", text: JSON.stringify(outcome.report, null, 2) },
      ],
    };
  }

  return davErrorResult(outcome.error);
}

/**
 * Register `dav_diagnose` on a per-request server instance (D-54).
 *
 * A permanent health check, not phase scaffolding — the DAV analog of D-08's
 * `mail_imap_diagnose`, and Phases 5 and 6 inherit it. When a calendar or
 * contacts tool fails later, "is it iCloud, my credentials, or our code?" is
 * answerable in one call with no deploy and no log dive. It is also the only
 * place a cache anomaly becomes visible, since a failed cache write is
 * swallowed silently under ./.claude/CLAUDE.md §4.
 *
 * **This carries an `inputSchema` where `mail_imap_diagnose` deliberately
 * carries none, and the divergence is not a regression.** D-06's decision there
 * existed so that no caller-supplied value could reach the connect call, which
 * is what keeps the port and transport-mode bans true by construction. Nothing
 * transfers here: the single boolean below reaches a KV delete and nothing
 * else — no host, no port, no transport mode, no URL. Its worst case is one
 * extra discovery round trip, which is the tool's own purpose.
 *
 * `davFetch` is passed in rather than built here, for the reason the comment on
 * `createSessionGate()` in `createServerFactory` already gives: per-request
 * construction is structural, and reaching for a module-scoped one would share
 * one caller's request queue with every other caller in the isolate.
 */
export function registerDavDiagnoseTool(
  server: McpServer,
  davFetch: DavFetch,
): void {
  server.registerTool(
    "dav_diagnose",
    {
      // Terse on purpose: a tool description is a token tax paid on every call
      // for the life of the server, and this tool is permanent surface.
      description:
        "Check iCloud CalDAV and CardDAV discovery: resolved URLs, shard host, " +
        "cache hit, and timings per service.",
      inputSchema: z.object({
        refresh: z
          .boolean()
          .optional()
          .describe("Clear the discovery cache first and resolve live."),
      }),
    },
    async ({ refresh }) => {
      try {
        return davDiagnosticResult(
          await runDavDiagnosticOutcome(env, davFetch, {
            refresh: refresh ?? false,
          }),
        );
      } catch (err) {
        // A backstop for anything the diagnostic did not already fold into an
        // outcome. Same boundary, same fixed vocabulary.
        return davErrorResult(err);
      }
    },
  );
}
