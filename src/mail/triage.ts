// The narrow verbs that change a mailbox, and nothing else (D-05).
//
// This module is the only importer of the mutating orchestrator in
// `./service.ts`, and a scan count holds that in both directions: a second
// importer is a decision on the safety boundary, and zero means this capability
// was deleted. It exports verbs and never a session, a session callback or the
// orchestrator itself. A caller names what it wants done to one message; it
// never gets a mailbox opened for changing to do its own work in.
//
// Today there are two verbs: mark one message read, and mark it unread. Each
// sends one flag change and, when the server sent no echo, one flags-only
// re-read. Nothing here fetches a message body, and nothing may: a body fetch on
// a mailbox opened for changing is how mail gets marked read by accident.
//
// What a verb reports is what the server sent back about the message after the
// change, never the tagged OK alone (D-11, PITFALLS #33).
//
// This module contains no logging calls of any kind and must never acquire any.

import { ImapNotFoundError } from "../errors";
import type { Principal } from "../principal";
import type { MessageRef } from "./ids";
import { seenStateOf } from "./imap-parser";
import type { DuplexLike } from "./imap-session";
import { sendCommand } from "./imap-session";
import type {
  MailSessionOptions,
  MutatingMailSession,
  SessionGate,
} from "./service";
import {
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
 * `applied: false` means the mailbox opened read-only, or opened without saying
 * it was writable. Nothing was changed. A value rather than an error, following
 * `AppendOutcome`: the call worked and reports a stated reason, and retrying
 * will not help.
 */
export type ReadStateOutcome =
  | { applied: true; seen: boolean; source: "store-echo" | "read-back" }
  | { applied: false; refusal: "mailbox-read-only" };

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
  if (stored.status !== "OK") throw new ImapNotFoundError();

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
  if (reread.status !== "OK") throw new ImapNotFoundError();

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
