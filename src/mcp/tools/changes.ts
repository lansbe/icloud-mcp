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
// every fetch peeks. The calendar half runs after the mail half has finished:
// one PROPFIND for every calendar's sync token, and one sync REPORT only for a
// calendar whose token moved, one calendar at a time. It counts; it lists no
// event yet.
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
import type { Env } from "../../env";
import { z } from "zod";
import type {
  CalendarBlock,
  CalendarState,
  FolderState,
  MarkerContent,
} from "../../change-marker";
import {
  MAX_CHANGE_FOLDERS,
  MAX_MARKER_LENGTH,
  MarkerRefusedError,
  fitsInMarker,
  importMarkerKey,
  readMarker,
  sealMarker,
} from "../../change-marker";
import {
  ImapAuthError,
  ImapNotFoundError,
  ImapThrottleError,
} from "../../errors";
import { calendarChangesSince } from "../../dav/calendar";
import type { CalendarChange, ChangedEventRow } from "../../dav/calendar";
import {
  DavAuthError,
  DavConnectError,
  DavThrottleError,
} from "../../dav/errors";
import type { DavFetch } from "../../dav/transport";
import type { StatusSnapshot } from "../../mail/imap-parser";
import { decodeFolderId, encodeFolderId } from "../../mail/ids";
import { decodeModifiedUtf7 } from "../../mail/imap-parser";
import type {
  FolderSnapshotOutcome,
  MailSessionOptions,
  NewMailRow,
  SessionGate,
} from "../../mail/service";
import {
  DEFAULT_MAILBOX,
  folderSnapshots,
  newMail,
} from "../../mail/service";
import type { Principal } from "../../principal";
import type { ToolResult } from "../untrusted";
import { UNTRUSTED_NOTICE, untrustedToolResult } from "../untrusted";
import { davErrorResult } from "./dav-diagnose";
import { mailErrorResult } from "./mail";

/**
 * The tool's name, in one place.
 *
 * The owner may still rename it before it is deployed (D-01). Every test and
 * every surface that needs the name reads this constant.
 */
export const CHANGES_TOOL_NAME = "changes_since";

/**
 * A marker longer than this is refused by the input schema. Defined once, in
 * the marker module, which refuses to seal past it (CR-01).
 */
export { MAX_MARKER_LENGTH };

/** Each source's state. A closed list (D-05). */
export type SourceState =
  | "started"
  | "no_changes"
  | "changes"
  | "restarted"
  | "not_checked"
  | "gone";

/**
 * Why a source could not be checked. A closed list (D-05), plus one.
 *
 * `marker_full` is calendar-only: the marker has no room for that calendar, so
 * it keeps no state for it, and the sentence says it is not tracked rather than
 * promising the next check covers the gap.
 */
export type NotCheckedReason =
  | "throttled"
  | "connection"
  | "unavailable"
  | "no_usable_answer"
  | "marker_full";

/**
 * Which mail mechanism answered, so the live check can settle whether iCloud
 * returns a mod-sequence in a status reply (A1).
 */
export type MailMechanism = "status-modseq" | "status-uidnext";

/** What the change check found for one mail folder. */
export interface MailFolderAnswer {
  /** How the folder is named in the trusted block. `INBOX` is a protocol literal. */
  folder: string;
  /**
   * The folder's display name, decoded as `mail_list_folders` decodes it. It
   * is the account owner's or a stranger's text, so it goes in the fenced
   * block only, keyed by `folder`, and never into the trusted block (D-04).
   */
  name?: string;
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

/** What the calendar half found. */
export interface CalendarSideAnswer {
  /** One per non-subscribed calendar, in URL order. */
  calendars: CalendarChange[];
  /** Subscriptions, never checked (D-22). Ids trusted, names fenced. */
  notCovered: { calendarId: string; displayName: string }[];
  /** Calendars in the marker that no longer exist. */
  gone: number;
  /**
   * Set when the calendar side as a whole could not be checked: the home
   * listing was throttled, failed to connect, or was not found. The marker's
   * old calendar block is carried unchanged.
   */
  unchecked: NotCheckedReason | null;
  /**
   * Calendars dropped from the carried block because the marker had no room
   * for them next to this call's mail states. Only when `unchecked` is set.
   */
  dropped?: number;
}

/** Everything `changesResult` needs. */
export interface ChangesAnswer {
  mail: MailFolderAnswer[];
  calendar: CalendarSideAnswer;
  /**
   * Folders in the presented marker that this call did not ask about, by
   * trusted key, carried into the fresh marker unchanged (D-16).
   */
  carried: string[];
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
 * With the restart flag, every folder is `restarted`, whatever the numbers
 * say. No old state is a starting point. A different validity means the old UIDs
 * name different messages now, so the folder starts again. An unchanged next
 * UID means nothing arrived, and the mod-sequences, compared as strings, say
 * whether anything else happened. A moved next UID needs a search, because the
 * difference between the two counts mail that arrived and left.
 */
export function mailOutcome(
  prior: FolderState | null,
  snapshot: StatusSnapshot,
  restartAll = false,
): MailStep {
  // A marker from an older format: every source starts again (D-09). Its
  // content is not read at all, so there is no old state to compare with.
  if (restartAll) {
    return {
      kind: "settled",
      state: "restarted",
      otherActivity: null,
      mechanism: mechanismOf(null, snapshot),
    };
  }
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

/**
 * How a folder is named in the trusted block (D-04).
 *
 * The inbox is `INBOX`, a protocol literal. Every other folder is its opaque
 * folder id, the same one `mail_list_folders` hands out, so a folder's own
 * name never reaches the trusted block.
 */
export function folderKeyOf(mailbox: string): string {
  return mailbox === DEFAULT_MAILBOX ? DEFAULT_MAILBOX : encodeFolderId({ mailbox });
}

function goneAnswer(folder: string): MailFolderAnswer {
  return {
    folder,
    state: "gone",
    newMessages: null,
    otherActivity: null,
    mechanism: null,
    rows: [],
  };
}

/** One folder's answer, and the state the fresh marker keeps for it. */
interface FolderCheck {
  mailbox: string;
  answer: MailFolderAnswer;
  /** `null` when the folder leaves the marker: gone, or never had a state. */
  state: FolderState | null;
}

/** A folder whose next UID moved, waiting for its search. */
interface PendingSearch {
  index: number;
  from: number;
  fresh: FolderState;
  mechanism: MailMechanism;
}

/**
 * Check a list of folders: their numbers first, then a search only where mail
 * arrived.
 *
 * One status session for every folder, then one read-only session per folder
 * whose next UID moved, each awaited before the next starts (D-18, CLAUDE.md
 * §3). Never two at once.
 *
 * A sign-in refusal is rethrown, so the tool answers it as every mail tool
 * does (D-08). A throttle or a connection failure stops the mail source at
 * once (D-29): every folder not yet answered is `not_checked` with that reason,
 * and nothing is retried. A refusal that is not NONEXISTENT is `unavailable`.
 * Every `not_checked` folder keeps its OLD state, so the next call covers the
 * gap. A NONEXISTENT folder is `gone` and leaves the marker.
 */
async function checkMail(
  actor: Principal,
  gate: SessionGate,
  mailboxes: readonly string[],
  prior: ReadonlyMap<string, FolderState>,
  restartAll: boolean,
  options: MailSessionOptions,
): Promise<FolderCheck[]> {
  const priorOf = (mailbox: string) => prior.get(mailbox) ?? null;
  const notCheckedAll = (reason: NotCheckedReason): FolderCheck[] =>
    mailboxes.map((mailbox) => ({
      mailbox,
      answer: notChecked(folderKeyOf(mailbox), reason),
      state: priorOf(mailbox),
    }));

  let outcomes: FolderSnapshotOutcome[];
  try {
    outcomes = await folderSnapshots(actor, gate, mailboxes, options);
  } catch (err) {
    if (err instanceof ImapAuthError) throw err;
    return notCheckedAll(reasonOf(err));
  }

  const checks: FolderCheck[] = [];
  const pending: PendingSearch[] = [];
  for (const mailbox of mailboxes) {
    const key = folderKeyOf(mailbox);
    const old = priorOf(mailbox);
    const outcome = outcomes.find((one) => one.mailbox === mailbox);

    if (outcome === undefined || !outcome.answered) {
      checks.push(
        outcome !== undefined && outcome.gone === true
          ? { mailbox, answer: goneAnswer(key), state: null }
          : { mailbox, answer: notChecked(key, "unavailable"), state: old },
      );
      continue;
    }

    const { snapshot } = outcome;
    // Checked by `folderSnapshots` already; restated so the types agree.
    if (snapshot.uidValidity === null || snapshot.uidNext === null) {
      checks.push({ mailbox, answer: notChecked(key, "unavailable"), state: old });
      continue;
    }
    const fresh: FolderState = {
      mailbox,
      uidValidity: snapshot.uidValidity,
      uidNext: snapshot.uidNext,
      highestModseq: snapshot.highestModseq,
    };

    const step = mailOutcome(old, snapshot, restartAll);
    if (step.kind === "settled") {
      checks.push({
        mailbox,
        answer: {
          folder: key,
          state: step.state,
          newMessages: step.state === "no_changes" ? 0 : null,
          otherActivity: step.otherActivity,
          mechanism: step.mechanism,
          rows: [],
        },
        state: fresh,
      });
      continue;
    }

    // `search` is only returned with an old state in hand. A placeholder holds
    // the folder's place in the order until its search has run.
    pending.push({
      index: checks.length,
      from: old!.uidNext,
      fresh,
      mechanism: step.mechanism,
    });
    checks.push({ mailbox, answer: notChecked(key, "unavailable"), state: old });
  }

  // One after another, each awaited before the next starts.
  let stopped: NotCheckedReason | null = null;
  for (const search of pending) {
    const check = checks[search.index]!;
    const key = check.answer.folder;
    if (stopped !== null) {
      check.answer = notChecked(key, stopped);
      continue;
    }

    let found: { count: number; rows: NewMailRow[] };
    try {
      found = await newMail(
        actor,
        gate,
        check.mailbox,
        search.fresh.uidValidity,
        search.from,
        search.fresh.uidNext,
        options,
      );
    } catch (err) {
      if (err instanceof ImapAuthError) throw err;
      const reason = reasonOf(err);
      check.answer = notChecked(key, reason);
      if (reason === "throttled" || reason === "connection") stopped = reason;
      continue;
    }

    check.answer = {
      folder: key,
      state: found.count === 0 ? "no_changes" : "changes",
      newMessages: found.count,
      // Mail arrived and left again, so something happened that this check
      // does not list. With new mail present it cannot say either way.
      otherActivity: found.count === 0 ? true : null,
      mechanism: search.mechanism,
      rows: found.rows,
    };
    check.state = search.fresh;
  }

  for (const check of checks) {
    check.answer.name = decodeModifiedUtf7(check.mailbox);
  }
  return checks;
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
 * The overall sentence, from the states and the carried count alone.
 *
 * "Nothing has changed" only when every source is `no_changes` and no folder
 * was carried unasked, because a carried folder was not looked at (D-07). A
 * source that could not be checked is always named, with the fact that the
 * marker keeps its old starting point. Integers only.
 */
function overallSentence(
  states: readonly SourceState[],
  carried: number,
  /** How many of the `not_checked` states are calendars with no room in the marker. */
  untracked = 0,
): string {
  const count = (state: SourceState) =>
    states.filter((one) => one === state).length;
  const one = (n: number, singular: string, plural: string) =>
    n === 1 ? singular : plural;

  if (carried === 0 && states.length > 0) {
    if (count("no_changes") === states.length) return NOTHING_CHANGED;
    if (count("started") === states.length) return STARTING_POINT;
  }

  const parts: string[] = [];
  const changes = count("changes");
  if (changes > 0) {
    parts.push(`Changes were found in ${sources(changes)}.`);
  }
  // A calendar the marker has no room for keeps no old starting point, so it
  // is never promised one.
  const notCheckedCount = count("not_checked") - untracked;
  if (notCheckedCount > 0) {
    parts.push(
      `${sources(notCheckedCount)} could not be checked; the marker keeps ` +
        `the old starting point for ${one(notCheckedCount, "it", "them")}, so ` +
        "the next check covers the gap.",
    );
  }
  if (untracked > 0) {
    parts.push(
      untracked === 1
        ? "1 calendar was not checked because the marker has no room for it; it is not tracked."
        : `${untracked} calendars were not checked because the marker has no room for them; they are not tracked.`,
    );
  }
  const restarted = count("restarted");
  if (restarted > 0) {
    parts.push(
      `The marker was too old for ${sources(restarted)}, so ` +
        `${one(restarted, "it starts", "they start")} again from here.`,
    );
  }
  const started = count("started");
  if (started > 0) {
    parts.push(`${sources(started)} ${one(started, "starts", "start")} from here.`);
  }
  const gone = count("gone");
  if (gone > 0) {
    parts.push(`${sources(gone)} no longer ${one(gone, "exists", "exist")}.`);
  }
  const unchanged = count("no_changes");
  if (unchanged > 0) {
    parts.push(`Nothing changed in ${sources(unchanged)}.`);
  }
  if (carried > 0) {
    parts.push(
      carried === 1
        ? "1 folder was not asked about this time and is kept as it was."
        : `${carried} folders were not asked about this time and are kept as they were.`,
    );
  }
  parts.push("Pass the new marker back next time.");
  return parts.join(" ");
}

/** One calendar's counts entry. Ids and integers only. */
function calendarCount(one: CalendarChange) {
  return {
    source: "calendar" as const,
    calendar: one.calendarId as string | null,
    state: one.state,
    added: one.added,
    changed: one.changed,
    addedOrChanged: one.addedOrChanged,
    removed: one.removed,
    more: one.more,
    mechanism: one.mechanism,
    ...(one.why !== undefined ? { why: one.why } : {}),
    ...(one.state === "not_checked" && one.reason !== undefined
      ? { reason: one.reason }
      : {}),
  };
}

/**
 * Shape the answer. The pure half, with no transport in it.
 *
 * The trusted block's keys, in this order: `counts`, `carried`, `notCovered`,
 * `goneCalendars`, `overall`, `since`, `marker`. Counts come before any detail
 * (CHNG-06): mail folders first, then calendars in URL order. Calendars are
 * named by id only. The fenced block holds everything stranger-authored,
 * calendar names included.
 */
export function changesResult(answer: ChangesAnswer): ToolResult {
  const mailCounts = answer.mail.map((folder) => ({
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

  // A calendar side that could not be checked at all is one source, named by
  // no id, because no calendar was listed.
  const calendarCounts =
    answer.calendar.unchecked !== null
      ? [
          {
            source: "calendar" as const,
            calendar: null as string | null,
            state: "not_checked" as const,
            added: null,
            changed: null,
            addedOrChanged: null,
            removed: null,
            more: false,
            mechanism: null,
            reason: answer.calendar.unchecked,
          },
        ]
      : answer.calendar.calendars.map(calendarCount);

  const states: SourceState[] = [
    ...answer.mail.map((folder) => folder.state),
    ...calendarCounts.map((one) => one.state),
    ...Array.from({ length: answer.calendar.gone }, () => "gone" as const),
  ];

  const trusted = {
    counts: [...mailCounts, ...calendarCounts],
    carried: answer.carried,
    notCovered: answer.calendar.notCovered.map((one) => one.calendarId),
    goneCalendars: answer.calendar.gone,
    overall: overallSentence(
      states,
      answer.carried.length,
      answer.calendar.calendars.filter(
        (one) => one.state === "not_checked" && one.reason === "marker_full",
      ).length + (answer.calendar.dropped ?? 0),
    ),
    since:
      answer.since === null
        ? null
        : new Date(answer.since * 1000).toISOString(),
    marker: answer.marker,
  };

  // The rows and the display name, under the folder's trusted key. Every
  // value here is either stranger-authored or sits beside a value that is, so
  // all of it is fenced. A folder other than the inbox is always listed, so
  // the key in the counts can be matched to a name; the inbox only when it
  // has rows, since its key is already its name.
  const untrusted: Record<
    string,
    | { name: string; rows: NewMailRow[] }
    | { name: string; rows: ChangedEventRow[] }
    | { name: string }
  > = {};
  for (const folder of answer.mail) {
    if (folder.rows.length > 0 || folder.folder !== DEFAULT_MAILBOX) {
      untrusted[folder.folder] = {
        name: folder.name ?? folder.folder,
        rows: folder.rows,
      };
    }
  }
  // Calendar names, keyed by the calendar id the counts carry (D-04), with
  // that calendar's event rows when it has any (D-26): titles are
  // stranger-authored, so a row never appears in the trusted block. The
  // not-covered subscriptions too, so their ids can be matched to a name.
  for (const one of answer.calendar.calendars) {
    untrusted[one.calendarId] =
      one.events.length > 0
        ? { name: one.displayName, rows: one.events }
        : { name: one.displayName };
  }
  for (const one of answer.calendar.notCovered) {
    untrusted[one.calendarId] = { name: one.displayName };
  }

  return untrustedToolResult(trusted, untrusted);
}

const MARKER_TOO_LONG =
  "These folders' names are too long to track together in one marker. " +
  "Ask about fewer folders, or ones with shorter names.";

/**
 * The answer when the folders asked about, with the ones the marker already
 * holds, could not fit in one marker however their numbers came back (CR-01).
 * Given before any socket, on the success arm, with no marker.
 */
export function markerTooLongResult(): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          refusal: "marker-too-long",
          overall: MARKER_TOO_LONG,
        }),
      },
    ],
  };
}

/** The largest numbers a folder's state can carry, for the worst-case size. */
const LARGEST_UID = 0xffffffff;
const LARGEST_MODSEQ = "9223372036854775807";

const MARKERS_UNAVAILABLE =
  "This server cannot make or read markers right now, so nothing was " +
  "checked. This is a fault on the server's side, not in the marker: keep " +
  "the marker you have and pass it back later.";

/**
 * The answer when the signing key is unusable (WR-04). Given before any
 * socket, and never the bad-marker answer: that one tells the caller to throw
 * their marker away, and a server fault is no reason to. No marker comes back,
 * because none could be made.
 */
export function markersUnavailableResult(): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          refusal: "markers-unavailable",
          overall: MARKERS_UNAVAILABLE,
        }),
      },
    ],
  };
}

const TOO_MANY_FOLDERS =
  "At most five folders can be watched with one marker, counting the ones it " +
  "already holds. Ask about fewer folders, or call with no marker to start over.";

/**
 * The answer when the folders asked about plus the ones the marker already
 * holds would come to more than five (D-21). Given before any socket.
 *
 * On the success arm, like the marker refusal: nothing failed, and the
 * caller's marker is still good for a smaller call. No marker comes back,
 * because none was made.
 */
export function tooManyFoldersResult(): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          refusal: "too-many-folders",
          overall: TOO_MANY_FOLDERS,
        }),
      },
    ],
  };
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
 * The signing key is imported first and the marker is read next, both BEFORE
 * any socket, so an unusable key or a refused marker costs no iCloud contact. The mail source runs in sessions awaited one after another on the
 * request-scoped gate. The calendar source runs only after the last mail
 * session has closed, through the one request-scoped DAV fetch.
 */
export function registerChangesTool(
  server: McpServer,
  gate: SessionGate,
  principal: Promise<Principal>,
  /** The same request-scoped DAV fetch the calendar tools get. */
  davFetch: DavFetch,
  /** The session bounds. Production passes none; tests inject short ones. */
  options: MailSessionOptions = {},
  /**
   * The environment the key and the calendar check read. Production passes
   * none and gets the Worker's own; a test passes a fresh copy with the key
   * overridden, never a write onto the shared one.
   */
  workerEnv: Env = env,
): void {
  server.registerTool(
    CHANGES_TOOL_NAME,
    {
      description:
        "What changed since a marker from an earlier call, in mail and on " +
        "every calendar. Counts first, then new mail: sender and subject " +
        "only, never a body. Events are counted as added or changed, and " +
        "removed. The inbox by default, or up to five folder ids. Call with " +
        "no marker for a starting point. Every answer returns a fresh " +
        "marker; pass it back exactly. Never marks mail read. " +
        UNTRUSTED_NOTICE,
      inputSchema: z.object({
        marker: z
          .string()
          .max(MAX_MARKER_LENGTH)
          .optional()
          .describe(
            "The marker from the previous answer, exactly as given. Omit for a starting point.",
          ),
        folders: z
          .array(z.string())
          .min(1, "Give at least one folder id, or leave folders out for the inbox.")
          .max(
            MAX_CHANGE_FOLDERS,
            "At most five folders can be checked in one call.",
          )
          .optional()
          .describe(
            "Folder ids from mail_list_folders, one to five. Omit for the inbox only.",
          ),
      }),
    },
    async ({ marker, folders }) => {
      try {
        const actor = await principal;

        // The key first, before any socket and apart from the marker's own
        // check, so an unusable secret is never read as a bad marker (WR-04).
        let key: CryptoKey;
        try {
          key = await importMarkerKey(workerEnv.CONFIRM_SECRET);
        } catch {
          // Nothing is read from the caught value.
          return markersUnavailableResult();
        }

        // Every id decoded before any socket, so a malformed or foreign one is
        // refused as the mail tools refuse it, at no connection cost. The
        // inbox is asked only by default or when listed (D-21). Duplicates are
        // asked once, in first-seen order.
        const mailboxes =
          folders === undefined
            ? [DEFAULT_MAILBOX]
            : [...new Set(folders.map((id) => decodeFolderId(id).mailbox))];

        let prior: MarkerContent | null = null;
        let restartAll = false;
        if (marker !== undefined) {
          try {
            const reading = await readMarker(marker, actor.userId, key);
            if (reading.kind === "current") prior = reading.content;
            else restartAll = true;
          } catch (err) {
            if (err instanceof MarkerRefusedError) return refusedMarkerResult();
            throw err;
          }
        }

        // Marker folders this call does not ask about are carried forward
        // unchanged (D-16). Checked and carried together may not pass five,
        // refused before any socket.
        const asked = new Set(mailboxes);
        const carried = (prior?.folders ?? []).filter(
          (one) => !asked.has(one.mailbox),
        );
        if (mailboxes.length + carried.length > MAX_CHANGE_FOLDERS) {
          return tooManyFoldersResult();
        }
        // The mail states at their largest, with an empty calendar block, must
        // fit one marker, or no answer this call gives could be passed back.
        const now = Math.floor(Date.now() / 1000);
        if (
          !fitsInMarker({
            folders: [
              ...mailboxes.map((mailbox) => ({
                mailbox,
                uidValidity: LARGEST_UID,
                uidNext: LARGEST_UID,
                highestModseq: LARGEST_MODSEQ,
              })),
              ...carried,
            ],
            calendar: { takenAt: now, calendars: [] },
            mintedAt: now,
          })
        ) {
          return markerTooLongResult();
        }

        const priorFolders = new Map<string, FolderState>(
          (prior?.folders ?? []).map((one) => [one.mailbox, one]),
        );
        const checks = await checkMail(
          actor,
          gate,
          mailboxes,
          priorFolders,
          restartAll,
          options,
        );

        const freshFolders: FolderState[] = [
          ...checks.flatMap((check) => (check.state === null ? [] : [check.state])),
          ...carried,
        ];
        // What the calendar side may keep: whatever still fits beside the mail.
        const fits = (states: readonly CalendarState[]): boolean =>
          fitsInMarker({
            folders: freshFolders,
            calendar: { takenAt: now, calendars: [...states] },
            mintedAt: now,
          });

        // The calendar side, only after the mail side has finished (D-32).
        // A sign-in refusal answers for the whole call with no marker (D-08).
        // Any other failure at the home listing leaves the calendar side not
        // checked and carries the old block unchanged.
        let calendar: CalendarSideAnswer;
        let freshCalendar: CalendarBlock | null;
        try {
          const result = await calendarChangesSince(
            workerEnv,
            actor,
            davFetch,
            prior?.calendar ?? null,
            restartAll,
            fits,
          );
          calendar = {
            calendars: result.calendars,
            notCovered: result.notCovered,
            gone: result.gone,
            unchecked: null,
          };
          freshCalendar = result.fresh;
        } catch (err) {
          if (err instanceof DavAuthError || err instanceof ImapAuthError) {
            return davErrorResult(err);
          }
          // The old block, carried whole where it fits beside this call's
          // mail states. What does not fit is dropped from the end and said.
          const kept = [...(prior?.calendar?.calendars ?? [])];
          while (kept.length > 0 && !fits(kept)) kept.pop();
          const dropped = (prior?.calendar?.calendars.length ?? 0) - kept.length;
          calendar = {
            calendars: [],
            notCovered: [],
            gone: 0,
            unchecked:
              err instanceof DavThrottleError
                ? "throttled"
                : err instanceof DavConnectError
                  ? "connection"
                  : "unavailable",
            ...(dropped > 0 ? { dropped } : {}),
          };
          freshCalendar =
            prior?.calendar == null ? null : { takenAt: prior.calendar.takenAt, calendars: kept };
        }

        const fresh = await sealMarker(
          {
            folders: freshFolders,
            calendar: freshCalendar,
            mintedAt: Math.floor(Date.now() / 1000),
          },
          actor.userId,
          key,
        );

        return changesResult({
          mail: checks.map((check) => check.answer),
          calendar,
          carried: carried.map((one) => folderKeyOf(one.mailbox)),
          since: prior?.mintedAt ?? null,
          marker: fresh,
        });
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );
}
