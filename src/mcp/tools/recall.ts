// Recall by meaning (Phase 26, RCLL-08, RCLL-10, RCLL-11, RCLL-12).
//
// One tool, `mail_recall`. The caller asks a question in plain words, and the
// answer is the person's own indexed messages that are nearest to it in
// meaning, best first: each one's opaque message id, the time it was indexed,
// and its subject line as it was when indexed. Nothing else.
//
// **The contract is SEED-006 D-1, and the answer is shaped so it cannot be read
// as anything stronger.** Recall is ranked and best-effort. An empty answer
// means nothing scored high enough, never that no such mail exists. So the
// answer holds no number at all: no score, which would read as confidence; no
// count or total, which would read as completeness; no rank, which the order
// already gives; and no coverage date, which would read as "complete since".
// The score floor that makes "nothing scored high enough" true lives inside the
// store module, and the score never leaves it.
//
// **The fence.** The ids, the indexed times, the index word and the note are
// this server's own, and sit in the trusted block. Every subject line was
// written by whoever sent the mail, and sits in the fenced untrusted block,
// keyed by id. The description carries the untrusted notice.
//
// **No model but the embedder (RCLL-12).** The only model call is the one
// embedding of the query, inside Phase 25's pipeline. Nothing generated is
// returned.
//
// **It opens no mail session and takes no connection lease.** It reads the
// person's own object once and their own part of the index once. The build
// step that follows a mail call comes from plan 26-07's driver, never from this
// handler.
//
// **Recall is inherent (owner, 2026-09-27).** Nothing is turned on first, and
// this module has no way to turn it off. The index word is `building` or
// `built` and nothing else.
//
// **A failure is never an empty list (D-09).** If the object, the store or the
// model cannot be reached, the answer is an error with one fixed sentence. An
// empty list there would read as "nothing matched". The caught value is never
// read.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { agentFor } from "../../agent/lease";
import { toErrorCategory } from "../../errors";
import { decodeMessageId } from "../../mail/ids";
import type { Principal } from "../../principal";
import type { RecallMatch } from "../../recall/index";
import { type RecallDeps, recallDeps, recallFor } from "../../recall/pipeline";
import { type ToolResult, UNTRUSTED_NOTICE, untrustedToolResult } from "../untrusted";

/** The tool's registered name. SEED-006 fixes it. */
export const RECALL_TOOL_NAME = "mail_recall";

/** How many matches one recall asks for. The server's number, never the caller's (D-06). */
export const RECALL_TOP_K = 10;

/** The longest question, in characters, after trimming (D-06). */
const MAX_QUERY_CHARS = 500;

/** Where the person's index is. There is no other word: recall is inherent. */
export type RecallIndexWord = "building" | "built";

/** The sentences every answer's note carries, in this order. No number in any. */
const NOTE_ALWAYS = [
  "Recall is ranked and best-effort: it finds mail by meaning, among the mail indexed so far.",
  "An empty answer means nothing scored high enough, not that no such mail exists.",
  "For an exhaustive answer in one folder, use mail_find.",
  "Open each result with mail_get_message. A result that no longer opens has been removed.",
] as const;

/** The one more sentence while the index is still being built. */
const NOTE_BUILDING =
  "The index is still being built as mail tools are used, so it covers less mail than it will.";

/** The one sentence a failed recall answers with (D-09). */
export const RECALL_UNAVAILABLE =
  "Recall could not be reached just now, so nothing was searched. mail_find still works.";

/** What the object reports, as far as this tool reads it. */
interface SyncStateView {
  readonly folders: readonly string[] | null;
  readonly sync: Readonly<Record<string, { readonly stage: string }>>;
}

/**
 * `built` only when a folder list exists and every listed folder is built.
 *
 * A folder's row is read as an own key only, because the name is the
 * account's own and may be `constructor` (26-REVIEW WR-06).
 */
export function indexWordOf(state: SyncStateView): RecallIndexWord {
  const folders = state.folders;
  if (folders === null || folders.length === 0) return "building";
  return folders.every(
    (mailbox) => Object.hasOwn(state.sync, mailbox) && state.sync[mailbox]?.stage === "built",
  )
    ? "built"
    : "building";
}

/** Whether `ref` is a message id this server minted. A thrown decode means no. */
function decodes(ref: string): boolean {
  try {
    decodeMessageId(ref);
    return true;
  } catch {
    return false;
  }
}

/**
 * The recall answer: ids and indexed times trusted, subjects fenced.
 *
 * Exported so the answer's shape can be asserted without a server. A match
 * whose ref does not decode is dropped, silently.
 */
export function recallResult(matches: readonly RecallMatch[], index: RecallIndexWord): ToolResult {
  const kept = matches.filter((match) => decodes(match.ref));
  const note = index === "building" ? [...NOTE_ALWAYS, NOTE_BUILDING] : [...NOTE_ALWAYS];
  return untrustedToolResult(
    {
      index,
      note: note.join(" "),
      results: kept.map((match) => ({
        id: match.ref,
        indexedAt: new Date(match.indexedAt).toISOString(),
      })),
    },
    { snippets: Object.fromEntries(kept.map((match) => [match.ref, match.snippet])) },
  );
}

/** The fixed error answer for a recall that could not run. No results key. */
function unavailableResult(): ToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ message: RECALL_UNAVAILABLE }) }],
  };
}

/**
 * Register `mail_recall` on a per-request server instance.
 *
 * `principal` is the same promise every mail tool gets, awaited as the first
 * line of the callback. A refusal answers the same fixed category every other
 * tool gives. It is the ONLY input that decides whose index is searched: the
 * tool has one argument, the question, and it reaches only the embedder.
 *
 * `deps` is a function so registering the tool reads no binding. Tests pass
 * fakes through it; production passes nothing.
 */
export function registerRecallTools(
  server: McpServer,
  principal: Promise<Principal>,
  deps: () => RecallDeps = recallDeps,
): void {
  server.registerTool(
    RECALL_TOOL_NAME,
    {
      description:
        "Ranked recall by meaning. Empty means nothing scored high enough, " +
        "not that none exists. " +
        UNTRUSTED_NOTICE,
      inputSchema: z.object({
        query: z
          .string()
          .trim()
          .min(1, "Say what the mail was about.")
          .max(MAX_QUERY_CHARS, "Keep the question to 500 characters.")
          .describe(
            "What the mail was about, in plain words. Results are message ids " +
              "and subjects; open one with mail_get_message.",
          ),
      }),
    },
    async ({ query }) => {
      let actor: Principal;
      try {
        actor = await principal;
      } catch (err) {
        const { category, message } = toErrorCategory(err);
        return {
          isError: true,
          content: [{ type: "text" as const, text: JSON.stringify({ category, message }) }],
        };
      }
      try {
        const state = await agentFor(actor).recallSyncState();
        const matches = await recallFor(actor, query, deps(), RECALL_TOP_K);
        return recallResult(matches, indexWordOf(state));
      } catch {
        return unavailableResult();
      }
    },
  );
}
