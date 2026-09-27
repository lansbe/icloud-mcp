// The narrow verbs that change a mailbox, and nothing else (D-05).
//
// This module is the only importer of the mutating orchestrator in
// `./service.ts`, and a scan count holds that in both directions: a second
// importer is a decision on the safety boundary, and zero means this capability
// was deleted. It exports verbs and never a session, a session callback or the
// orchestrator itself. A caller names what it wants done to one message; it
// never gets a mailbox opened for changing to do its own work in.
//
// Two verbs mark one message read, and mark it unread. Each sends one flag
// change and, when the server sent no echo, one flags-only re-read.
//
// Two more move a list of messages from one folder to another, one message at
// a time, in one session. iCloud has no move command, so each message is
// copied, the copy is proven from the server's own reply, the original gets
// the removal mark only if nothing changed since the preview, and then that
// one UID is removed. The only removal anywhere here names one UID whose copy
// was proven, so a failure at any step leaves a duplicate and never a loss.
// Every outcome is judged from a re-read of the source folder afterwards.
//
// Nothing here fetches a message body, and nothing may: a body fetch on a
// mailbox opened for changing is how mail gets marked read by accident.
//
// What a verb reports is what the server sent back about the message after the
// change, never the tagged OK alone (D-11, PITFALLS #33).
//
// This module contains no logging calls of any kind and must never acquire any.

import {
  ImapConnectError,
  ImapNotFoundError,
  ImapThrottleError,
} from "../errors";
import type { Principal } from "../principal";
import type { MessageRef } from "./ids";
import {
  FINGERPRINT_ITEMS,
  parseCompletionCode,
  parseCopyUid,
  parseFingerprint,
  parseModifiedUids,
  parseSearchLine,
  quoteMailbox,
  seenStateOf,
} from "./imap-parser";
import type { CommandResult, DuplexLike } from "./imap-session";
import { sendCommand } from "./imap-session";
import type {
  MailSessionOptions,
  MoveSource,
  MutatingMailSession,
  SessionGate,
} from "./service";
import {
  CALL_DEADLINE_MS,
  MAILBOX_NOT_WRITABLE,
  withMutatingMailbox,
  withMutatingMailboxOver,
} from "./service";

/**
 * What marking one message read or unread produced.
 *
 * `applied: true` carries the seen state the server reported after the change,
 * and where that report came from:
 *
 * - `store-echo`: the untagged reply to the flag change itself.
 * - `read-back`: a flags-only re-read, sent because the flag change had no
 *   reply for this message. RFC 3501 says a server "normally" sends one, which
 *   is not always.
 *
 * `seen` can disagree with what was asked. If it does, that is the answer: the
 * server's word about the message, not the request echoed back.
 *
 * `source: "unconfirmed"` carries no `seen` at all, on purpose. The server
 * accepted the flag change, sent no reply about the message, and then refused
 * the re-read. The change has probably landed, but nothing the server said
 * shows it, so there is no server state to report. Saying "does not exist"
 * here would be false: the message was there a moment ago and was just
 * changed. The caller reports the request, labelled as unconfirmed. Asking
 * again is safe, because setting a flag that is already set changes nothing.
 *
 * `applied: false` means the mailbox opened read-only, or opened without saying
 * it was writable. Nothing was changed. A value rather than an error, following
 * `AppendOutcome`: the call worked and reports a stated reason, and retrying
 * will not help.
 */
export type ReadStateOutcome =
  | { applied: true; seen: boolean; source: "store-echo" | "read-back" }
  | { applied: true; source: "unconfirmed" }
  | { applied: false; refusal: "mailbox-read-only" };

/**
 * Response codes that say the message itself is gone (RFC 5530).
 *
 * Only these make a refused command `not_found`. A refusal with no code says
 * nothing about the message, so it is not evidence that the message is gone.
 */
const GONE_CODES: ReadonlySet<string> = new Set(["NONEXISTENT"]);

/**
 * Response codes that say the server is busy or at a limit for now (RFC 5530).
 *
 * These are `rate_limited`, whose fixed message says to wait before retrying.
 */
const BUSY_CODES: ReadonlySet<string> = new Set(["UNAVAILABLE", "INUSE", "LIMIT"]);

/**
 * The error for a refused command on the mutating path, chosen by its code.
 *
 * Gone is `ImapNotFoundError`. Busy is `ImapThrottleError`, with no detail,
 * so no server text reaches the answer. Everything else, a BAD or a NO with no
 * code or another code, is `ImapConnectError`: this server cannot tell what
 * went wrong, and that category's fixed message says so. Neither of those two
 * says the message does not exist, because nothing shows that it doesn't.
 */
function refusalOf(result: CommandResult): Error {
  const code = parseCompletionCode(result.tagged.text);
  if (code !== null && GONE_CODES.has(code)) return new ImapNotFoundError();
  if (code !== null && BUSY_CODES.has(code)) return new ImapThrottleError();
  return new ImapConnectError();
}

/**
 * Set or clear the seen flag on one message, and read back what the server
 * says the flag now is.
 *
 * UID-scoped, so it names the message by its own identifier and never by a
 * position. Not the silent form, because the reply is the evidence. No
 * conditional modifier: that belongs to a later phase.
 *
 * A message that no longer exists gets a tagged OK and no reply about it. The
 * re-read then finds nothing either, and that is `ImapNotFoundError`.
 *
 * A refused flag change throws by its code (see `refusalOf`). It is
 * `not_found` only when the code says the message is gone. A refused re-read
 * after an accepted flag change is the same when its code says gone, and is
 * the `unconfirmed` outcome otherwise, because the change was accepted.
 */
async function changeSeen(
  session: MutatingMailSession,
  ref: MessageRef,
  direction: "+" | "-",
): Promise<ReadStateOutcome> {
  const stored = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID STORE ${ref.uid} ${direction}FLAGS (\\Seen)`,
  );
  if (stored.status !== "OK") throw refusalOf(stored);

  const echoed = seenStateOf(stored.untagged, ref.uid);
  if (echoed !== null) {
    return { applied: true, seen: echoed, source: "store-echo" };
  }

  // No reply for this message. Ask for its flags, and nothing else.
  const reread = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} (UID FLAGS)`,
  );
  if (reread.status !== "OK") {
    const refusal = refusalOf(reread);
    if (refusal instanceof ImapNotFoundError) throw refusal;
    return { applied: true, source: "unconfirmed" };
  }

  const seen = seenStateOf(reread.untagged, ref.uid);
  if (seen === null) throw new ImapNotFoundError();
  return { applied: true, seen, source: "read-back" };
}

/** Turn the orchestrator's refusal value into the verb's refusal arm. */
function outcomeOf(
  result: ReadStateOutcome | typeof MAILBOX_NOT_WRITABLE,
): ReadStateOutcome {
  if (result === MAILBOX_NOT_WRITABLE) {
    return { applied: false, refusal: "mailbox-read-only" };
  }
  return result;
}

/** Mark one message read, over an already-open stream pair. */
export async function markReadOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReadStateOutcome> {
  return outcomeOf(
    await withMutatingMailboxOver(
      duplex,
      principal,
      gate,
      ref.mailbox,
      ref.uidValidity,
      (session) => changeSeen(session, ref, "+"),
      options,
    ),
  );
}

/** Mark one message read. */
export async function markRead(
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReadStateOutcome> {
  return outcomeOf(
    await withMutatingMailbox(
      principal,
      gate,
      ref.mailbox,
      ref.uidValidity,
      (session) => changeSeen(session, ref, "+"),
      options,
    ),
  );
}

/** Mark one message unread, over an already-open stream pair. */
export async function markUnreadOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReadStateOutcome> {
  return outcomeOf(
    await withMutatingMailboxOver(
      duplex,
      principal,
      gate,
      ref.mailbox,
      ref.uidValidity,
      (session) => changeSeen(session, ref, "-"),
      options,
    ),
  );
}

/** Mark one message unread. */
export async function markUnread(
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReadStateOutcome> {
  return outcomeOf(
    await withMutatingMailbox(
      principal,
      gate,
      ref.mailbox,
      ref.uidValidity,
      (session) => changeSeen(session, ref, "-"),
      options,
    ),
  );
}

// ---------------------------------------------------------------------------
// Moving messages (Phase 21, D-06, D-07)
// ---------------------------------------------------------------------------

/** The most messages one move takes. The tool refuses more first, by name. */
export const MOVE_SET_CAP = 25;

/**
 * What happened to one message. Exactly one per message, never a bare success.
 *
 * - `moved`: a re-read of the source no longer lists it, and the copy was
 *   proven. Only the re-read can say this; a tagged OK never does (TRIA-05).
 * - `copied_not_removed`: the copy landed and the original is still in the
 *   source. Two copies exist; nothing is lost.
 * - `not_copied`: nothing was written for this message.
 * - `unknown`: a write was sent and its answer never came back.
 */
export type MoveResultCode = "moved" | "copied_not_removed" | "not_copied" | "unknown";

/** Why a message ended where it did. A fixed vocabulary; no server text. */
export type MoveReason =
  | "verified-gone"
  | "copy-refused"
  | "copy-unproven"
  | "changed-since-preview"
  | "mark-refused"
  | "removal-refused"
  | "still-in-source"
  | "verify-refused"
  | "connection-lost"
  | "stopped-for-time"
  | "not-attempted"
  | "removal-not-kept"
  | "commands-unavailable";

/** One message's result. */
export interface MessageMoveResult {
  /** The message's UID in the source folder. */
  uid: number;
  outcome: MoveResultCode;
  reason: MoveReason;
  /** The copy's UID in the destination, only when the server's reply proved it. */
  newUid: number | null;
  /** The destination's UIDVALIDITY, from the same reply, or `null` with `newUid`. */
  destinationUidValidity: number | null;
}

/** One message to move, with the fingerprint its preview sealed. */
export interface MoveEntry {
  uid: number;
  size: number;
  internalDate: number;
  /** Digits, never a number. See `Fingerprint.modSeq`. */
  modSeq: string;
}

/**
 * What a move produced.
 *
 * `applied: true` carries one result per entry, in the caller's order. The
 * refusals wrote nothing at all:
 *
 * - `mailbox-read-only`: the source did not open for changing.
 * - `removal-not-kept`: the open says the removal mark would not survive.
 * - `commands-unavailable`: the server does not advertise both UIDPLUS and
 *   CONDSTORE, so a copy cannot be proven or a change cannot be conditional.
 * - `changed-since-preview`: at least one message differs from its preview.
 *   The whole list is refused before the first write (TRIA-04, TRIA-08).
 */
export type MoveOutcome =
  | { applied: true; results: MessageMoveResult[] }
  | {
      applied: false;
      refusal: "mailbox-read-only" | "removal-not-kept" | "commands-unavailable";
    }
  | { applied: false; refusal: "changed-since-preview"; changedUids: number[] };

/**
 * Whether the capability line advertises both extensions a move needs.
 *
 * UIDPLUS gives the copy's proof, and CONDSTORE makes the removal mark
 * conditional. PITFALLS :44: the line was recorded once and Apple can change
 * it, so it is read on every call.
 */
function hasMoveCommands(capability: string | null): boolean {
  if (capability === null) return false;
  const atoms = new Set(capability.split(" ").map((atom) => atom.toUpperCase()));
  return atoms.has("UIDPLUS") && atoms.has("CONDSTORE");
}

/**
 * Whether the open says the removal mark is kept.
 *
 * `null` means the open sent no list, and RFC 3501 says every flag is kept
 * then. `\*` does not count, as in the seen-flag check: it is about keywords.
 */
function keepsRemovalMark(permanentFlags: readonly string[] | null): boolean {
  if (permanentFlags === null) return true;
  return permanentFlags.some((flag) => flag.toLowerCase() === "\\deleted");
}

/** One message's result, spelled once. */
function resultOf(
  uid: number,
  outcome: MoveResultCode,
  reason: MoveReason,
  newUid: number | null = null,
  destinationUidValidity: number | null = null,
): MessageMoveResult {
  return { uid, outcome, reason, newUid, destinationUidValidity };
}

/**
 * Move one message inside an open mutating session. Module-private.
 *
 * In order, and the order is the design: the copy, proven; then the removal
 * mark, conditional on the MODSEQ the preview sealed; then the removal of that
 * one UID; then a re-read. A failure at any step leaves the original in place.
 *
 * It never throws once its first write is handed over. A throw from the
 * channel after that is `unknown`, because the write may have landed.
 *
 * A hard stop sits before EACH write: the call deadline does not cancel the
 * work (R-7), so without it a late continuation could write while the
 * teardown runs.
 */
async function moveMessageWithin(
  session: MutatingMailSession,
  ref: MessageRef,
  destinationMailbox: string,
  modSeq: string,
  deadlineAt: number,
): Promise<MessageMoveResult> {
  // Step 1. No write yet.
  if (!hasMoveCommands(session.capability)) {
    return resultOf(ref.uid, "not_copied", "commands-unavailable");
  }
  if (!keepsRemovalMark(session.permanentFlags)) {
    return resultOf(ref.uid, "not_copied", "removal-not-kept");
  }
  if (Date.now() >= deadlineAt) {
    return resultOf(ref.uid, "not_copied", "not-attempted");
  }
  const quoted = quoteMailbox(destinationMailbox);
  if (quoted === null) throw new ImapNotFoundError();

  let newUid: number | null = null;
  let destinationUidValidity: number | null = null;
  try {
    // Step 2. The copy.
    const copied = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      `UID COPY ${ref.uid} ${quoted}`,
    );
    if (copied.status !== "OK") {
      return resultOf(ref.uid, "not_copied", "copy-refused");
    }
    const proof = parseCopyUid(copied.tagged.text);
    if (
      proof === null ||
      proof.source.length !== 1 ||
      proof.source[0] !== ref.uid ||
      proof.destination.length !== 1
    ) {
      // The copy may well have landed, but nothing proves where. So nothing
      // else is sent for this message (D-07).
      return resultOf(ref.uid, "copied_not_removed", "copy-unproven");
    }
    newUid = proof.destination[0]!;
    destinationUidValidity = proof.uidValidity;

    // Step 3.
    if (Date.now() >= deadlineAt) {
      return resultOf(
        ref.uid,
        "copied_not_removed",
        "stopped-for-time",
        newUid,
        destinationUidValidity,
      );
    }

    // Step 4. The removal mark, only if nothing changed since the preview.
    // Not the silent form: the reply is evidence.
    const marked = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      `UID STORE ${ref.uid} (UNCHANGEDSINCE ${modSeq}) +FLAGS (\\Deleted)`,
    );
    const modified = parseModifiedUids(marked.tagged.text);
    let stillThere: MoveReason | null = null;
    if (modified !== null) {
      stillThere = modified.includes(ref.uid) ? "changed-since-preview" : "mark-refused";
    } else if (marked.status !== "OK") {
      stillThere = "mark-refused";
    }

    // Step 5. The removal of that one UID, only when it was marked.
    if (stillThere === null) {
      if (Date.now() >= deadlineAt) {
        return resultOf(
          ref.uid,
          "copied_not_removed",
          "stopped-for-time",
          newUid,
          destinationUidValidity,
        );
      }
      const removed = await sendCommand(
        session.channel,
        session.channel.nextTag(),
        `UID EXPUNGE ${ref.uid}`,
      );
      if (removed.status !== "OK") stillThere = "removal-refused";
    }

    // Step 6. The verdict comes from a re-read, never from an OK (TRIA-06).
    const verified = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      `UID SEARCH UID ${ref.uid}`,
    );
    if (verified.status !== "OK") {
      return resultOf(ref.uid, "unknown", "verify-refused", newUid, destinationUidValidity);
    }
    let answered = false;
    let listed = false;
    for (const line of verified.untagged) {
      const uids = parseSearchLine(line);
      if (uids === null) continue;
      answered = true;
      if (uids.includes(ref.uid)) listed = true;
    }
    // No search reply at all is no evidence either way.
    if (!answered) {
      return resultOf(ref.uid, "unknown", "verify-refused", newUid, destinationUidValidity);
    }
    if (!listed) {
      return resultOf(ref.uid, "moved", "verified-gone", newUid, destinationUidValidity);
    }
    return resultOf(
      ref.uid,
      "copied_not_removed",
      stillThere ?? "still-in-source",
      newUid,
      destinationUidValidity,
    );
  } catch {
    return resultOf(ref.uid, "unknown", "connection-lost", newUid, destinationUidValidity);
  }
}

/** What a move has done so far, readable if the session dies mid-list. */
interface MoveLedger {
  results: MessageMoveResult[];
  /** The UID whose step is running now, or `null` between steps. */
  inFlight: number | null;
  /** Whether any step was started, so a write may have been sent. */
  started: boolean;
}

/** Refuse an empty list, or one over the cap, before any socket. */
function assertMoveList(entries: readonly MoveEntry[]): void {
  if (entries.length === 0 || entries.length > MOVE_SET_CAP) {
    throw new ImapNotFoundError();
  }
}

/** The whole move, inside an open mutating session. */
async function moveListWithin(
  session: MutatingMailSession,
  entries: readonly MoveEntry[],
  destinationMailbox: string,
  options: MailSessionOptions,
  ledger: MoveLedger,
): Promise<MoveOutcome> {
  const startedAt = Date.now();
  const deadlineAt = startedAt + (options.callDeadlineMs ?? CALL_DEADLINE_MS);

  // Whole-session refusals, with zero writes.
  if (!hasMoveCommands(session.capability)) {
    return { applied: false, refusal: "commands-unavailable" };
  }
  if (!keepsRemovalMark(session.permanentFlags)) {
    return { applied: false, refusal: "removal-not-kept" };
  }

  // Every message re-read before the first write (TRIA-04, TRIA-08).
  const reread = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${entries.map((entry) => entry.uid).join(",")} ${FINGERPRINT_ITEMS}`,
  );
  if (reread.status !== "OK") throw refusalOf(reread);
  const changedUids: number[] = [];
  for (const entry of entries) {
    const now = parseFingerprint(reread.untagged, entry.uid);
    if (
      now === null ||
      now.size !== entry.size ||
      now.internalDate !== entry.internalDate ||
      now.modSeq !== entry.modSeq
    ) {
      changedUids.push(entry.uid);
    }
  }
  if (changedUids.length > 0) {
    return { applied: false, refusal: "changed-since-preview", changedUids };
  }

  // Serial, one message at a time. No combinator anywhere: every step is a
  // conversation on the one socket this request holds.
  const halfway = (deadlineAt - startedAt) / 2;
  let stopped = false;
  for (const entry of entries) {
    if (stopped || Date.now() - startedAt >= halfway) {
      ledger.results.push(resultOf(entry.uid, "not_copied", "not-attempted"));
      continue;
    }
    ledger.inFlight = entry.uid;
    ledger.started = true;
    const result = await moveMessageWithin(
      session,
      { mailbox: session.mailbox, uidValidity: session.uidValidity, uid: entry.uid },
      destinationMailbox,
      entry.modSeq,
      deadlineAt,
    );
    ledger.results.push(result);
    ledger.inFlight = null;
    // The channel is gone. Nothing after this can be sent, so nothing after
    // this is attempted.
    if (result.reason === "connection-lost") stopped = true;
  }
  return { applied: true, results: [...ledger.results] };
}

/**
 * Turn the orchestrator's answer into the verb's.
 *
 * A connection error after a step started is not a whole-call failure: some
 * messages may have moved. So it becomes the per-message results recorded so
 * far, the running one `unknown`, and the rest not attempted (D-06). Before any
 * step started nothing was written, and the error goes up unchanged.
 */
async function settleMove(
  entries: readonly MoveEntry[],
  ledger: MoveLedger,
  run: () => Promise<MoveOutcome | typeof MAILBOX_NOT_WRITABLE>,
): Promise<MoveOutcome> {
  let answer: MoveOutcome | typeof MAILBOX_NOT_WRITABLE;
  try {
    answer = await run();
  } catch (err) {
    if (!(err instanceof ImapConnectError) || !ledger.started) throw err;
    const recorded = [...ledger.results];
    const inFlight = ledger.inFlight;
    const results = entries.map((entry, index): MessageMoveResult => {
      const done = recorded[index];
      if (done !== undefined) return done;
      if (entry.uid === inFlight) {
        return resultOf(entry.uid, "unknown", "connection-lost");
      }
      return resultOf(entry.uid, "not_copied", "not-attempted");
    });
    return { applied: true, results };
  }
  if (answer === MAILBOX_NOT_WRITABLE) {
    return { applied: false, refusal: "mailbox-read-only" };
  }
  return answer;
}

/** Move a list of messages from one folder, over an already-open stream pair. */
export async function moveMessagesOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  source: MoveSource,
  entries: readonly MoveEntry[],
  destinationMailbox: string,
  options: MailSessionOptions = {},
): Promise<MoveOutcome> {
  assertMoveList(entries);
  const ledger: MoveLedger = { results: [], inFlight: null, started: false };
  return settleMove(entries, ledger, () =>
    withMutatingMailboxOver(
      duplex,
      principal,
      gate,
      source.mailbox,
      source.uidValidity,
      (session) => moveListWithin(session, entries, destinationMailbox, options, ledger),
      options,
    ),
  );
}

/** Move a list of messages from one folder to another. */
export async function moveMessages(
  principal: Principal,
  gate: SessionGate,
  source: MoveSource,
  entries: readonly MoveEntry[],
  destinationMailbox: string,
  options: MailSessionOptions = {},
): Promise<MoveOutcome> {
  assertMoveList(entries);
  const ledger: MoveLedger = { results: [], inFlight: null, started: false };
  return settleMove(entries, ledger, () =>
    withMutatingMailbox(
      principal,
      gate,
      source.mailbox,
      source.uidValidity,
      (session) => moveListWithin(session, entries, destinationMailbox, options, ledger),
      options,
    ),
  );
}
