// The DAV tool boundary opens here: `dav_diagnose`, plus the two shapers every
// later DAV tool imports from this module.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import type { DavDiagnosticOutcome } from "../../dav/diagnose";
import {
  runCollectionWriteProbe,
  runDavDiagnosticOutcome,
  runTaskCollectionProbe,
} from "../../dav/diagnose";
import { davToErrorCategory } from "../../dav/errors";
import type { DavFetch } from "../../dav/transport";
import type { Principal } from "../../principal";

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
 * transfers here: `refresh` reaches a KV delete and nothing else — no host, no
 * port, no transport mode, no URL. Its worst case is one extra discovery round
 * trip, which is the tool's own purpose.
 *
 * **Phase 14 added two more booleans, and the D-06 argument above has to be
 * restated for each of them rather than assumed to carry over — one of them
 * reaches a WRITE, and the other returns the caller's own reminder titles.**
 *
 * `probeCollectionWrite` runs SPIKE-04's instrument: create a throwaway
 * calendar, rename and recolour it, delete it, then re-list the home set and
 * report whether it is actually gone. Four things bound it. It is OFF unless
 * asked for by name, and a run without it issues no mutating request at all.
 * It selects a fixed five-step code path and nothing else — the boolean reaches
 * no host, no URL and no identifier. The collection's URL is built from THIS
 * principal's own resolved home set plus one segment from
 * `crypto.randomUUID()`, so no caller value can aim it and it cannot address
 * another account. And the cleanup is CHECKED rather than trusted: the delete's
 * own status is not evidence of a deletion, so the probe looks again, and when
 * the collection is still there the response names the URL so the owner can
 * remove it by hand.
 *
 * `probeTaskObjects` runs SPIKE-02's object-level half: a bounded, read-only
 * `calendar-query` over the account's task collections. **It returns the TITLES
 * of the caller's own reminders, and that is stated here plainly rather than
 * left to be inferred from a field name** — those titles cross into a model's
 * context, on the same footing the shipped calendar tools' event titles already
 * do, and like those they are untrusted third-party text to report and never
 * instructions to follow. It is OFF unless asked for by name, capped at eight
 * collections and twenty-five objects apiece with both caps reported when they
 * bite, and it takes no title, name or id to match against and returns no
 * verdict — the comparison against what the owner named happens elsewhere.
 *
 * Both default to false, so the DEFAULT response is unchanged in cost and in
 * shape: a reader of an ordinary run sees exactly what they saw before.
 *
 * `davFetch` is passed in rather than built here, for the reason the comment on
 * `createSessionGate()` in `createServerFactory` already gives: per-request
 * construction is structural, and reaching for a module-scoped one would share
 * one caller's request queue with every other caller in the isolate.
 */
export function registerDavDiagnoseTool(
  server: McpServer,
  davFetch: DavFetch,
  principal: Promise<Principal>,
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
        probeCollectionWrite: z
          .boolean()
          .optional()
          .describe(
            "Create, rename, recolour and delete a throwaway calendar, then confirm it is gone.",
          ),
        probeTaskObjects: z
          .boolean()
          .optional()
          .describe(
            "List the to-do items in this account's task collections, with their titles.",
          ),
      }),
    },
    async ({ refresh, probeCollectionWrite, probeTaskObjects }) => {
      try {
        // Who this call acts for. First, so a refused principal reads
        // `auth_failed` before anything else is looked at (D-27).
        const actor = await principal;
        const outcome = await runDavDiagnosticOutcome(env, actor, davFetch, {
          refresh: refresh ?? false,
        });

        // Both probes run only after the two services have, and only when asked
        // for by name. `=== true` rather than a truthy test, so nothing but the
        // boolean itself can turn either of them on.
        //
        // **NEITHER PROBE MAY DISCARD THE REPORT, and that is why each is
        // total rather than throwing.** Both now fold every refusal into their
        // own returned value — per collection for the to-do listing, per step
        // for the write — so neither can reach the catch below and replace a
        // whole diagnostic with a bare category. That is not a convenience: the
        // live account answers 404 on two abandoned to-do lists, and while the
        // listing threw, asking for it discarded both services' discovery, the
        // collection enumeration, the timings, and the write report beside it.
        //
        // The READ still runs before the WRITE. The ordering no longer protects
        // the write report from a thrown read — nothing throws now — but it
        // keeps the cheap read ahead of the mutation, so a run that is going to
        // fail costs nothing on the account.
        if (!outcome.failed && probeTaskObjects === true) {
          outcome.report.caldav.taskObjects = await runTaskCollectionProbe(
            env,
            actor,
            davFetch,
          );
        }
        if (!outcome.failed && probeCollectionWrite === true) {
          outcome.report.caldav.collectionWrite = await runCollectionWriteProbe(
            env,
            actor,
            davFetch,
          );
        }

        return davDiagnosticResult(outcome);
      } catch (err) {
        // A backstop for anything the diagnostic did not already fold into an
        // outcome. Same boundary, same fixed vocabulary.
        return davErrorResult(err);
      }
    },
  );
}
