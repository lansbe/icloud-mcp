// What changed since last time (CHNG-01 … CHNG-09).
//
// One tool, `changes_since`. The caller hands back the marker an earlier call
// gave it, and the answer says, per source, whether anything changed since
// then: counts first, then who new mail is from and what it is about. Every
// answer that reached iCloud carries a fresh marker to pass back next time.
// Called with no marker, it answers with a starting point and a marker, and
// says so in words that cannot be read as "nothing changed".
//
// **It writes nothing and marks nothing read.** The mail half asks each folder
// for its numbers without opening it, and opens a folder only when its next
// UID moved, read-only, through the mail orchestrator. Header fields only, and
// every fetch peeks.
//
// **The protocol trees meet here and nowhere else.** The mail tree and the DAV
// tree never import each other. The marker module is protocol-neutral, and this
// module is where a mail answer and a calendar answer are put side by side.
//
// **The sentences are fixed.** Every sentence this module writes comes from the
// table below and carries integers only. No subject, sender, folder name or
// title is ever put into one: those are stranger-authored and live in the
// fenced block.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import type { FolderState, MarkerContent } from "../../change-marker";
import {
  MarkerRefusedError,
  readMarker,
  sealMarker,
} from "../../change-marker";
import {
  ImapAuthError,
  ImapNotFoundError,
  ImapThrottleError,
} from "../../errors";
import type { StatusSnapshot } from "../../mail/imap-parser";
import type { NewMailRow, SessionGate } from "../../mail/service";
import {
  DEFAULT_MAILBOX,
  folderSnapshots,
  newMail,
} from "../../mail/service";
import type { Principal } from "../../principal";
import type { ToolResult } from "../untrusted";
import { UNTRUSTED_NOTICE, untrustedToolResult } from "../untrusted";
import { mailErrorResult } from "./mail";

/**
 * The tool's name, in one place.
 *
 * The owner may still rename it before it is deployed (D-01). Every test and
 * every surface that needs the name reads this constant.
 */
export const CHANGES_TOOL_NAME = "changes_since";

/** A marker longer than this is refused by the input schema. */
export const MAX_MARKER_LENGTH = 4096;

/** Each source's state. A closed list (D-05). */
export type SourceState =
  | "started"
  | "no_changes"
  | "changes"
  | "restarted"
  | "not_checked"
  | "gone";

/** Why a source could not be checked. A closed list (D-05). */
export type NotCheckedReason =
  | "throttled"
  | "connection"
  | "unavailable"
  | "no_usable_answer";

/**
 * Which mail mechanism answered, so the live check can settle whether iCloud
 * returns a mod-sequence in a status reply (A1).
 */
export type MailMechanism = "status-modseq" | "status-uidnext";

/** What the change check found for one mail folder. */
export interface MailFolderAnswer {
  /** How the folder is named in the trusted block. `INBOX` is a protocol literal. */
  folder: string;
  state: SourceState;
  /** Exact, and only for `changes` and `no_changes`. */
  newMessages: number | null;
  /**
   * Whether something other than new mail happened (read status, flags,
   * removals), which this check does not list. `null` when it cannot say.
   */
  otherActivity: boolean | null;
  mechanism: MailMechanism | null;
  /** Only for `not_checked`. */
  reason?: NotCheckedReason;
  /** New-mail rows, newest first. Stranger-authored: fenced, never trusted. */
  rows: NewMailRow[];
}

/** Everything `changesResult` needs. */
export interface ChangesAnswer {
  mail: MailFolderAnswer[];
  /** The presented marker's `mintedAt`, in seconds, or `null`. */
  since: number | null;
  marker: string;
}

/**
 * The first step for one folder, from its old state and its status reply.
 *
 * Pure. `search` means the next UID moved and the range has to be counted.
 */
export type MailStep =
  | {
      kind: "settled";
      state: "started" | "restarted" | "no_changes";
      otherActivity: boolean | null;
      mechanism: MailMechanism;
    }
  | { kind: "search"; mechanism: MailMechanism };

/** Which mechanism answered: the mod-sequence only when both sides had one. */
function mechanismOf(
  prior: FolderState | null,
  snapshot: StatusSnapshot,
): MailMechanism {
  return prior !== null &&
    prior.highestModseq !== null &&
    snapshot.highestModseq !== null
    ? "status-modseq"
    : "status-uidnext";
}

/**
 * Compare a folder's old state with its status reply.
 *
 * No old state is a starting point. A different validity means the old UIDs
 * name different messages now, so the folder starts again. An unchanged next
 * UID means nothing arrived, and the mod-sequences, compared as strings, say
 * whether anything else happened. A moved next UID needs a search, because the
 * difference between the two counts mail that arrived and left.
 */
export function mailOutcome(
  prior: FolderState | null,
  snapshot: StatusSnapshot,
): MailStep {
  const mechanism = mechanismOf(prior, snapshot);
  if (prior === null) {
    return { kind: "settled", state: "started", otherActivity: null, mechanism };
  }
  if (
    snapshot.uidValidity !== prior.uidValidity ||
    snapshot.uidNext === null ||
    snapshot.uidNext < prior.uidNext
  ) {
    return {
      kind: "settled",
      state: "restarted",
      otherActivity: null,
      mechanism,
    };
  }
  if (snapshot.uidNext === prior.uidNext) {
    const otherActivity =
      prior.highestModseq === null || snapshot.highestModseq === null
        ? null
        : prior.highestModseq !== snapshot.highestModseq;
    return { kind: "settled", state: "no_changes", otherActivity, mechanism };
  }
  return { kind: "search", mechanism };
}

/** Dispatch on the failure's type. The caught value is never read. */
function reasonOf(err: unknown): NotCheckedReason {
  if (err instanceof ImapThrottleError) return "throttled";
  if (err instanceof ImapNotFoundError) return "unavailable";
  return "connection";
}

function notChecked(folder: string, reason: NotCheckedReason): MailFolderAnswer {
  return {
    folder,
    state: "not_checked",
    newMessages: null,
    otherActivity: null,
    mechanism: null,
    reason,
    rows: [],
  };
}

/** One folder's answer, and the state the fresh marker keeps for it. */
interface FolderCheck {
  answer: MailFolderAnswer;
  /** `null` only when there was no old state and none could be taken. */
  state: FolderState | null;
}

/**
 * Check one folder: its numbers first, then a search only if mail arrived.
 *
 * Two sessions, awaited one after the other, never together. A sign-in refusal
 * is rethrown, so the tool answers it as every mail tool does. Any other
 * failure is `not_checked`, and the folder keeps its OLD state, so the next
 * call covers the gap.
 */
async function checkMailFolder(
  actor: Principal,
  gate: SessionGate,
  mailbox: string,
  prior: FolderState | null,
  restartAll: boolean,
): Promise<FolderCheck> {
  let snapshot: StatusSnapshot;
  try {
    const [outcome] = await folderSnapshots(actor, gate, [mailbox]);
    if (outcome === undefined || !outcome.answered) {
      return { answer: notChecked(mailbox, "unavailable"), state: prior };
    }
    snapshot = outcome.snapshot;
  } catch (err) {
    if (err instanceof ImapAuthError) throw err;
    return { answer: notChecked(mailbox, reasonOf(err)), state: prior };
  }

  // Checked by `folderSnapshots` already; restated so the types agree.
  if (snapshot.uidValidity === null || snapshot.uidNext === null) {
    return { answer: notChecked(mailbox, "unavailable"), state: prior };
  }
  const fresh: FolderState = {
    mailbox,
    uidValidity: snapshot.uidValidity,
    uidNext: snapshot.uidNext,
    highestModseq: snapshot.highestModseq,
  };

  // A marker from an older format: every source starts again.
  const step: MailStep = restartAll
    ? {
        kind: "settled",
        state: "restarted",
        otherActivity: null,
        mechanism: mechanismOf(null, snapshot),
      }
    : mailOutcome(prior, snapshot);

  if (step.kind === "settled") {
    return {
      answer: {
        folder: mailbox,
        state: step.state,
        newMessages: step.state === "no_changes" ? 0 : null,
        otherActivity: step.otherActivity,
        mechanism: step.mechanism,
        rows: [],
      },
      state: fresh,
    };
  }

  // `search` is only returned with an old state in hand.
  const from = prior!.uidNext;
  let found: { count: number; rows: NewMailRow[] };
  try {
    found = await newMail(
      actor,
      gate,
      mailbox,
      fresh.uidValidity,
      from,
      fresh.uidNext,
    );
  } catch (err) {
    if (err instanceof ImapAuthError) throw err;
    return { answer: notChecked(mailbox, reasonOf(err)), state: prior };
  }

  return {
    answer: {
      folder: mailbox,
      state: found.count === 0 ? "no_changes" : "changes",
      newMessages: found.count,
      // Mail arrived and left again, so something happened that this check
      // does not list. With new mail present it cannot say either way.
      otherActivity: found.count === 0 ? true : null,
      mechanism: step.mechanism,
      rows: found.rows,
    },
    state: fresh,
  };
}

// ---------------------------------------------------------------------------
// The fixed sentences (D-06, D-07)
// ---------------------------------------------------------------------------

const STARTING_POINT =
  "This is a starting point; nothing is compared yet. Pass the marker back next time.";

const NOTHING_CHANGED =
  "Nothing has changed since the marker. Pass the new marker back next time.";

const MARKER_REFUSED =
  "The marker was not accepted, so changes since then cannot be listed. " +
  "Call again with no marker to get a new starting point.";

function sources(count: number): string {
  return count === 1 ? "1 source" : `${count} sources`;
}

/**
 * The overall sentence, from the states alone.
 *
 * "Nothing has changed" only when every source is `no_changes`. A source that
 * could not be checked is always named, with the fact that the marker keeps its
 * old starting point. Integers only.
 */
function overallSentence(states: readonly SourceState[]): string {
  const count = (state: SourceState) =>
    states.filter((one) => one === state).length;

  if (states.length > 0 && count("no_changes") === states.length) {
    return NOTHING_CHANGED;
  }
  if (states.length > 0 && count("started") === states.length) {
    return STARTING_POINT;
  }

  const parts: string[] = [];
  if (count("changes") > 0) {
    parts.push(`Changes were found in ${sources(count("changes"))}.`);
  }
  if (count("not_checked") > 0) {
    parts.push(
      `${sources(count("not_checked"))} could not be checked; the marker keeps ` +
        "the old starting point for them, so the next check covers the gap.",
    );
  }
  if (count("restarted") > 0) {
    parts.push(
      `The marker was too old for ${sources(count("restarted"))}, so they ` +
        "start again from here.",
    );
  }
  if (count("started") > 0) {
    parts.push(`${sources(count("started"))} start from here.`);
  }
  if (count("gone") > 0) {
    parts.push(`${sources(count("gone"))} no longer exist.`);
  }
  if (count("no_changes") > 0) {
    parts.push(`Nothing changed in ${sources(count("no_changes"))}.`);
  }
  parts.push("Pass the new marker back next time.");
  return parts.join(" ");
}

/**
 * Shape the answer. The pure half, with no transport in it.
 *
 * The trusted block's keys, in this order: `counts`, `overall`, `since`,
 * `marker`. Counts come before any detail (CHNG-06). The fenced block holds
 * everything stranger-authored.
 */
export function changesResult(answer: ChangesAnswer): ToolResult {
  const counts = answer.mail.map((folder) => ({
    source: "mail" as const,
    folder: folder.folder,
    state: folder.state,
    newMessages: folder.newMessages,
    otherActivity: folder.otherActivity,
    mechanism: folder.mechanism,
    ...(folder.state === "not_checked" && folder.reason !== undefined
      ? { reason: folder.reason }
      : {}),
  }));

  const trusted = {
    counts,
    overall: overallSentence(answer.mail.map((folder) => folder.state)),
    since:
      answer.since === null
        ? null
        : new Date(answer.since * 1000).toISOString(),
    marker: answer.marker,
  };

  // The rows, under the folder they came from. Every value here is either
  // stranger-authored or sits beside a value that is, so all of it is fenced.
  const untrusted: Record<string, NewMailRow[]> = {};
  for (const folder of answer.mail) {
    if (folder.rows.length > 0) untrusted[folder.folder] = folder.rows;
  }

  return untrustedToolResult(trusted, untrusted);
}

/**
 * The one answer for a marker this server will not read.
 *
 * On the success arm, not `isError`: nothing failed, a marker was refused. No
 * marker comes back, because nothing verified can be carried forward. The same
 * answer for every cause (D-13).
 */
export function refusedMarkerResult(): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          refusal: "marker-not-accepted",
          overall: MARKER_REFUSED,
        }),
      },
    ],
  };
}

/**
 * Register `changes_since` on a per-request server instance.
 *
 * The marker is read BEFORE any socket, so a refused one costs no iCloud
 * contact. The mail source runs in sessions awaited one after another on the
 * request-scoped gate.
 */
export function registerChangesTool(
  server: McpServer,
  gate: SessionGate,
  principal: Promise<Principal>,
): void {
  server.registerTool(
    CHANGES_TOOL_NAME,
    {
      description:
        "What changed since a marker from an earlier call. Counts first, then " +
        "new mail: sender and subject only, never a body. Call with no marker " +
        "for a starting point. Every answer returns a fresh marker; pass it " +
        `back exactly next time. Never marks mail read. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        marker: z
          .string()
          .max(MAX_MARKER_LENGTH)
          .optional()
          .describe(
            "The marker from the previous answer, exactly as given. Omit for a starting point.",
          ),
      }),
    },
    async ({ marker }) => {
      try {
        const actor = await principal;

        let prior: MarkerContent | null = null;
        let restartAll = false;
        if (marker !== undefined) {
          try {
            const reading = await readMarker(
              marker,
              actor.userId,
              env.CONFIRM_SECRET,
            );
            if (reading.kind === "current") prior = reading.content;
            else restartAll = true;
          } catch (err) {
            if (err instanceof MarkerRefusedError) return refusedMarkerResult();
            throw err;
          }
        }

        const inbox = await checkMailFolder(
          actor,
          gate,
          DEFAULT_MAILBOX,
          prior?.folders.find((one) => one.mailbox === DEFAULT_MAILBOX) ?? null,
          restartAll,
        );

        const fresh = await sealMarker(
          {
            folders: inbox.state === null ? [] : [inbox.state],
            calendar: prior?.calendar ?? null,
            mintedAt: Math.floor(Date.now() / 1000),
          },
          actor.userId,
          env.CONFIRM_SECRET,
        );

        return changesResult({
          mail: [inbox.answer],
          since: prior?.mintedAt ?? null,
          marker: fresh,
        });
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );
}
