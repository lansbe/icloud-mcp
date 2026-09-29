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
// handler. The second tool in this module, the backfill at the bottom, is the
// one that does open sessions, one leased session at a time, through its runner
// in src/recall/drive.ts.
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
import { agentFor, type LeasedMail } from "../../agent/lease";
import { isParked } from "../../agent/recall-ledger";
import { toErrorCategory } from "../../errors";
import { decodeMessageId } from "../../mail/ids";
import type { Principal } from "../../principal";
import { type GrantClient, runRecallBackfill } from "../../recall/drive";
import type { RecallMatch } from "../../recall/index";
import { type RecallDeps, recallDeps, recallFor } from "../../recall/pipeline";
import { type BackfillOutcome, productionStepDeps, type StepDeps } from "../../recall/sync";
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

/**
 * The one more sentence while a folder is parked (26-REVIEW-2 WR-03): it
 * failed too often in a row, and is tried again about once a day.
 */
export const NOTE_PARKED =
  "A folder could not be read lately, so some of its mail may be missing from the index for now.";

/** The one sentence a failed recall answers with (D-09). */
export const RECALL_UNAVAILABLE =
  "Recall could not be reached just now, so nothing was searched. mail_find still works.";

/** One folder's row, as far as this tool reads it. */
interface SyncRowView {
  readonly stage: string;
  readonly failures: number;
  readonly failedAt: number | null;
}

/** What the object reports, as far as this tool reads it. */
interface SyncStateView {
  readonly folders: readonly string[] | null;
  readonly listedAt: number | null;
  readonly sync: Readonly<Record<string, SyncRowView>>;
}

/** Every listed folder's own row, or null when a listed folder has none yet. */
function listedRows(state: SyncStateView): SyncRowView[] | null {
  const folders = state.folders;
  if (folders === null || folders.length === 0) return null;
  const rows: SyncRowView[] = [];
  for (const mailbox of folders) {
    // An own key only: the name is the account's own and may be `constructor`
    // (26-REVIEW WR-06).
    if (!Object.hasOwn(state.sync, mailbox)) return null;
    rows.push(state.sync[mailbox]!);
  }
  return rows;
}

/**
 * `built` only when a folder list exists and every listed folder is built or
 * parked.
 *
 * A parked folder (26-REVIEW-2 WR-03) is not being built: the step leaves it
 * alone. Calling the index `building` for it would say, for as long as the
 * folder keeps failing, that more mail is on the way. `parkedIn` says it
 * instead.
 */
export function indexWordOf(state: SyncStateView): RecallIndexWord {
  const rows = listedRows(state);
  if (rows === null) return "building";
  return rows.every((row) => row.stage === "built" || isParked(row, state.listedAt))
    ? "built"
    : "building";
}

/** Whether any listed folder is parked (26-REVIEW-2 WR-03). */
export function parkedIn(state: SyncStateView): boolean {
  const rows = listedRows(state);
  if (rows === null) return false;
  return rows.some((row) => isParked(row, state.listedAt));
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
 * whose ref does not decode is dropped, silently. `parked` adds the sentence
 * that says a folder could not be read lately.
 */
export function recallResult(
  matches: readonly RecallMatch[],
  index: RecallIndexWord,
  parked = false,
): ToolResult {
  const kept = matches.filter((match) => decodes(match.ref));
  const note: string[] = [...NOTE_ALWAYS];
  if (index === "building") note.push(NOTE_BUILDING);
  if (parked) note.push(NOTE_PARKED);
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
        return recallResult(matches, indexWordOf(state), parkedIn(state));
      } catch {
        return unavailableResult();
      }
    },
  );
}

// ---------------------------------------------------------------------------
// The backfill tool (Phase 29.1.1, RCLL-14)
// ---------------------------------------------------------------------------
//
// One more tool, `mail_recall_backfill`. The person asks Claude to fill their
// recall index now, and Claude calls it again and again while they watch. Each
// call indexes up to about ten pages of the person's own mail, one leased
// iCloud session at a time, and says how far it got.
//
// It takes no argument (LD-8): the principal the door built is the only thing
// that decides whose index is filled. It runs only from a person's own sign-in
// in a Claude app, never on the autonomy key (LD-2, LD-3): the runner in
// src/recall/drive.ts checks the grant's client before it calls anything.
//
// Its answer is this server's own words and numbers, so it is one trusted
// block. No subject line or any other text from mail reaches it.

/** The backfill tool's registered name. */
export const RECALL_BACKFILL_TOOL_NAME = "mail_recall_backfill";

/** The one sentence a backfill refused by the grant check answers with. */
export const BACKFILL_REFUSED =
  "The recall backfill runs only from a person's own sign-in in a Claude app, so nothing was indexed.";

/** The one sentence a backfill that could not reach the index answers with. */
export const BACKFILL_UNAVAILABLE =
  "The recall index could not be reached just now, so nothing was indexed.";

/**
 * The backfill answer: one trusted block with where the index is, why this call
 * stopped, and what it did.
 *
 * Exported so the answer's shape can be asserted without a server.
 */
export function backfillResult(outcome: BackfillOutcome, index: RecallIndexWord): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          index,
          stopped: outcome.stopped,
          thisCall: { pages: outcome.pages },
        }),
      },
    ],
  };
}

/** A fixed error answer, with one sentence and nothing else. */
function fixedError(message: string): ToolResult {
  return { isError: true, content: [{ type: "text", text: JSON.stringify({ message }) }] };
}

/**
 * Register `mail_recall_backfill` on a per-request server instance.
 *
 * No input schema and no arguments, exactly as `account_whoami` does it (LD-8).
 * `principal` is the same promise every tool gets, awaited first. A refusal
 * answers the same fixed category every other tool gives. `mail` is the
 * request's lease runner, and `grantClient` says which client the request's
 * grant belongs to.
 *
 * `depsFor` is a function so registering the tool reads no binding. Tests pass
 * fakes through it; production passes nothing.
 */
export function registerRecallBackfillTool(
  server: McpServer,
  mail: LeasedMail,
  principal: Promise<Principal>,
  grantClient: GrantClient,
  depsFor: (mail: LeasedMail) => StepDeps = productionStepDeps,
): void {
  server.registerTool(
    RECALL_BACKFILL_TOOL_NAME,
    {
      description:
        "Fill your own recall index now, while you watch. Each call indexes up to " +
        "about 250 of your recent messages and says how far it got. Call it again " +
        "until it says the index is built.",
    },
    async () => {
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
        const ran = await runRecallBackfill(actor, mail, grantClient, depsFor);
        if (ran.kind === "refused") return fixedError(BACKFILL_REFUSED);
        const state = await agentFor(actor).recallSyncState();
        return backfillResult(ran.outcome, indexWordOf(state));
      } catch {
        return fixedError(BACKFILL_UNAVAILABLE);
      }
    },
  );
}
