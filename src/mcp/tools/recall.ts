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
import { ConnectionBusyError, toErrorCategory } from "../../errors";
import { decodeMessageId } from "../../mail/ids";
import type { Principal } from "../../principal";
import { type GrantClient, runRecallBackfill } from "../../recall/drive";
import type { RecallMatch } from "../../recall/index";
import { type RecallDeps, recallDeps, recallFor } from "../../recall/pipeline";
import { RECALL_MAX_VECTORS, RECALL_PAGE_SIZE, RECALL_TTL_MS } from "../../recall/retention";
import {
  type BackfillOutcome,
  type BackfillStop,
  productionStepDeps,
  RECALL_BACKFILL_MAX_PAGES,
  readyNow,
  type StepDeps,
} from "../../recall/sync";
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

/** The first listed folder, always. */
const INBOX = "INBOX";

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
 * The one sentence a backfill answers with when it indexed pages but could not
 * read its progress afterwards (29.1.1-REVIEW WR-01).
 */
export const BACKFILL_PROGRESS_UNREAD =
  "The build ran, but how far it got could not be read just now. Call mail_recall_backfill again to see.";

/** A folder's stage, as the backfill answer names it. */
export type BackfillStage = "not_started" | "building" | "built" | "waiting" | "parked";

/**
 * A folder's role. The first listed folder is always INBOX, so it is `inbox`;
 * any other is `archive`. A folder's name is untrusted data and never appears.
 */
export type FolderRole = "inbox" | "archive";

/** One listed folder's row in the backfill answer. */
export interface BackfillFolderRow {
  readonly role: FolderRole;
  readonly stage: BackfillStage;
  /** Messages indexed for this folder. */
  readonly indexed: number;
  /** About how many messages the folder has in the window, or null when it is too early to say. */
  readonly estimate: number | null;
  /** The UTC day of the oldest message indexed, as YYYY-MM-DD, or null with nothing indexed. */
  readonly reachedBack: string | null;
}

/** The object's progress read, as far as this tool reads it. */
interface ProgressView {
  readonly total: number;
  readonly mailboxes: readonly {
    readonly mailbox: string;
    readonly count: number;
    readonly oldestExpiry: number;
  }[];
}

/** What the backfill answer is built from. */
export interface BackfillAnswerInput {
  /** The object's progress read before the run. */
  readonly before: ProgressView;
  /** The object's progress read after the run. */
  readonly after: ProgressView;
  /** The object's sync state read after the run. */
  readonly state: SyncStateView;
  readonly outcome: BackfillOutcome;
  /** When the answer is built, in ms since the epoch. */
  readonly now: number;
  /** When the call began, in ms since the epoch. */
  readonly startedAt: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** The window in whole days, from RECALL_TTL_MS: 90. */
const WINDOW_DAYS = Math.round(RECALL_TTL_MS / DAY_MS);

/** A fixed English month table, so no locale reaches the answer. */
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

/** `n` with a comma between each group of three digits, in ASCII. */
function withCommas(n: number): string {
  return String(Math.trunc(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** `n` messages, with the right plural. */
function messagesWord(n: number): string {
  return n === 1 ? "1 message" : `${withCommas(n)} messages`;
}

/** The UTC day of `at` as "Mon D". */
function shortDay(at: number): string {
  const date = new Date(at);
  return `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}`;
}

/** Round an estimate up: to the nearest 50 below 1,000, and the nearest 100 from 1,000. */
function roundUpEstimate(raw: number): number {
  const step = raw < 1000 ? 50 : 100;
  return Math.ceil(raw / step) * step;
}

/**
 * About how many messages a folder that is still building has in the window.
 *
 * The build walks each folder newest first, so the messages indexed so far
 * cover the span from the oldest one indexed up to now. The estimate stretches
 * that rate over the whole window. Null when nothing is indexed, or when the
 * span covered is under a day: too early to say. Never below the count, and
 * never above RECALL_MAX_VECTORS.
 */
function estimateOf(count: number, oldestDate: number | null, now: number): number | null {
  if (count === 0 || oldestDate === null) return null;
  const span = now - oldestDate;
  if (span < DAY_MS) return null;
  const raw = (count * RECALL_TTL_MS) / span;
  return Math.min(Math.max(roundUpEstimate(raw), count), RECALL_MAX_VECTORS);
}

/**
 * A folder's stage, from its sync row, with the loop's own predicates so the
 * answer and the loop never disagree.
 */
function stageOf(row: SyncRowView | undefined, listedAt: number | null, now: number): BackfillStage {
  if (row === undefined) return "not_started";
  if (row.stage === "built") return "built";
  if (isParked(row, listedAt)) return "parked";
  if (!readyNow(row, listedAt, now)) return "waiting";
  return row.stage === "seed" ? "not_started" : "building";
}

/** Every folder's row, by role. With no folder list yet, one inbox row. */
function folderRows(state: SyncStateView, after: ProgressView, now: number): BackfillFolderRow[] {
  const folders = state.folders === null || state.folders.length === 0 ? [INBOX] : state.folders;
  return folders.map((mailbox, i) => {
    // An own key only: the name is the account's own and may be `constructor`.
    const row = Object.hasOwn(state.sync, mailbox) ? state.sync[mailbox] : undefined;
    const stage = stageOf(row, state.listedAt, now);
    const held = after.mailboxes.find((one) => one.mailbox === mailbox);
    const indexed = held?.count ?? 0;
    const oldestDate = held === undefined ? null : held.oldestExpiry - RECALL_TTL_MS;
    const role: FolderRole = i === 0 ? "inbox" : "archive";
    return {
      role,
      stage,
      indexed,
      estimate: stage === "built" ? indexed : estimateOf(indexed, oldestDate, now),
      reachedBack:
        oldestDate === null || indexed === 0 ? null : new Date(oldestDate).toISOString().slice(0, 10),
    };
  });
}

/** One row's sentence, in plain ASCII English. */
function rowSentence(row: BackfillFolderRow): string {
  const label = row.role === "inbox" ? "Inbox" : "Archive";
  if (row.stage === "not_started") return `${label}: not started yet.`;
  if (row.stage === "built") {
    return row.indexed === 0
      ? `${label}: built, with no messages from the last ${WINDOW_DAYS} days.`
      : `${label}: all ${messagesWord(row.indexed)} from the last ${WINDOW_DAYS} days indexed.`;
  }
  let sentence: string;
  if (row.indexed === 0 || row.reachedBack === null) {
    sentence = `${label}: started, no messages indexed yet. It is too early to estimate how many there are.`;
  } else {
    const back = shortDay(Date.parse(row.reachedBack));
    if (row.estimate === null) {
      sentence =
        `${label}: ${messagesWord(row.indexed)} indexed, back to ${back}. ` +
        "It is too early to estimate how many there are.";
    } else if (row.estimate >= RECALL_MAX_VECTORS) {
      sentence =
        `${label}: ${messagesWord(row.indexed)} indexed, back to ${back}. ` +
        "There is more mail than the index can hold.";
    } else {
      sentence = `${label}: ${withCommas(row.indexed)} of about ${messagesWord(row.estimate)} indexed, back to ${back}.`;
    }
  }
  if (row.stage === "waiting") sentence += " It is waiting a few minutes after a failed read.";
  if (row.stage === "parked") {
    sentence += " It could not be read lately, and is tried again about once a day.";
  }
  return sentence;
}

/** The one sentence that says what to do next, per stop word. */
const NEXT: Readonly<Record<Exclude<BackfillStop, "unnamed">, string>> = {
  budget: "Call mail_recall_backfill again to continue.",
  built:
    "The index is built. There is nothing more to do, and it stays current as the person uses mail.",
  waiting: "A folder is waiting a few minutes after a failed read. Stop now, and try again later.",
  busy:
    "Another part of the build or another request is using the connection. " +
    "Try again in a minute or two.",
  lease_busy:
    "Another part of the build or another request is using the connection. " +
    "Try again in a minute or two.",
  quota:
    "The backfill has read its most pages for today. Stop now. It continues tomorrow, " +
    "and ordinary mail use keeps building the index meanwhile.",
  full:
    `The index holds its most messages, ${withCommas(RECALL_MAX_VECTORS)}. ` +
    "The oldest mail in the window is not indexed. Stop now.",
  destroying: "This index is being deleted because access ended. Stop now.",
  failed:
    "A read failed, and that folder waits before it is tried again. Stop now. " +
    "mail_imap_diagnose checks the connection.",
};

/** The sentence every backfill answer carries. */
export const BACKFILL_NOTE =
  "These numbers describe how far the build has got. Recall itself stays ranked and best-effort.";

/**
 * The backfill answer (LD-9, LD-10): one trusted block of JSON with where the
 * index is, why this call stopped, what this call did, one row per listed
 * folder by role, a progress sentence, a next sentence and the note.
 *
 * Pure, and exported so the answer can be asserted without a server. It is
 * this server's own words and numbers, so it never goes through the untrusted
 * fence: no folder name, subject, sender, id or address is in it. The only
 * numbers in its sentences are counts, estimates, dates, the window's days and
 * the vector ceiling.
 *
 * `unnamed` never reaches here; the tool answers it with its fixed error.
 */
export function backfillResult(input: BackfillAnswerInput): ToolResult {
  const { before, after, state, outcome, now, startedAt } = input;
  const folders = folderRows(state, after, now);
  const stopped = outcome.stopped === "unnamed" ? "failed" : outcome.stopped;
  const index = indexWordOf(state);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          index,
          stopped,
          thisCall: {
            pages: outcome.pages,
            messages: Math.max(0, after.total - before.total),
            seconds: Math.max(0, Math.floor((now - startedAt) / 1000)),
          },
          folders,
          progress: folders.map(rowSentence).join(" "),
          // A call whose last page finished the build is told so (IN-02).
          next: stopped === "budget" && index === "built" ? NEXT.built : NEXT[stopped],
          note: BACKFILL_NOTE,
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
        `${RECALL_BACKFILL_MAX_PAGES} pages (${RECALL_PAGE_SIZE} messages each) of recent ` +
        "inbox and archive mail. Its time limit usually stops it after 4 or 5 pages. " +
        "It says how far it got. Call it again until it says the index is built.",
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
      const startedAt = Date.now();
      let indexed = false;
      try {
        const stub = agentFor(actor);
        // Read after the grant check passes and before the run, so a refused
        // grant makes no object call at all.
        let before = null as ProgressView | null;
        const ran = await runRecallBackfill(actor, mail, grantClient, depsFor, async () => {
          before = await stub.recallProgress();
        });
        if (ran.kind === "refused") return fixedError(BACKFILL_REFUSED);
        indexed = ran.outcome.pages > 0;
        if (ran.outcome.stopped === "unnamed" || before === null) {
          return fixedError(BACKFILL_UNAVAILABLE);
        }
        // Nothing was opened for anyone else: the standard busy answer.
        if (ran.outcome.stopped === "lease_busy" && ran.outcome.sessions === 0) {
          const { category, message } = toErrorCategory(new ConnectionBusyError());
          return {
            isError: true,
            content: [{ type: "text" as const, text: JSON.stringify({ category, message }) }],
          };
        }
        const state = await stub.recallSyncState();
        const after = await stub.recallProgress();
        return backfillResult({
          before,
          after,
          state,
          outcome: ran.outcome,
          now: Date.now(),
          startedAt,
        });
      } catch {
        return fixedError(indexed ? BACKFILL_PROGRESS_UNREAD : BACKFILL_UNAVAILABLE);
      }
    },
  );
}
