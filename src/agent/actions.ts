// The two things the rules job can do (Phase 28, D-05 as revised, D-06, D-09).
//
// TWO ACTIONS, AND ONLY TWO. `setFlag` sets the flag on one message. It never
// clears one, and never marks anything read. `placeDraft` places one draft
// reply to one message's sender, in the rule's own words, through the same
// reply tool a person's own Claude calls. It never sends. That is the whole of
// what the job may do to a mailbox.
//
// Why two: the job acts with nobody present, on mail strangers wrote, so every
// action it can take is one a stranger can make it take. A flag costs the
// person nothing they cannot undo. A draft sits in Drafts until a person reads
// it and sends it, which is the backstop CLAUDE.md §2 relies on. Anything else
// (a move, a delete, a send, an event) has no such backstop. A third action is
// a decision on the safety boundary, not a refactor (PITFALLS #42).
//
// Each action reaches mail only through the `call` it is handed, which is Phase
// 27's session caller: one tool call at this Worker's own `/mcp`, where the
// door takes the person's connection lease. Nothing here takes the lease, opens
// a session, or imports mail code. This module logs nothing.

import { replyRecipient } from "./recipient";
import type { RuleDraft } from "./rules";
import type { ActionOutcome, CallAnswer, CallFn, EnvelopeRow } from "./tool-call";
import { readFirstJson, readToolError } from "./tool-reply";

/** A tool error's category, as an action outcome. */
function outcomeOfError(category: string): ActionOutcome {
  if (category === "connection_busy") return "busy";
  if (category === "auth_failed") return "auth_failed";
  return "error";
}

/**
 * The part of an answer every action reads first: a failed call, a tool error,
 * or the answer's first JSON part.
 */
function firstReading(
  answer: CallAnswer,
): { kind: "done"; outcome: ActionOutcome } | { kind: "body"; body: Record<string, unknown> } {
  if (answer.kind !== "ok") return { kind: "done", outcome: "failed" };
  const category = readToolError(answer.result);
  if (category !== null) return { kind: "done", outcome: outcomeOfError(category) };
  const body = readFirstJson(answer.result);
  if (body === null) return { kind: "done", outcome: "unreadable" };
  return { kind: "body", body };
}

/**
 * Set the flag on the row's message (D-06). Always `flagged: true`.
 *
 * Maps the flag tool's answer: `flagged` when iCloud confirmed the flag is set;
 * `unconfirmed` when the change was sent and the answer could not say; `refused`
 * when the tool refused, or iCloud reported the flag not set. A tool error maps
 * by its category; a failed call is `failed`. Never throws.
 */
export async function setFlag(call: CallFn, row: EnvelopeRow): Promise<ActionOutcome> {
  try {
    const reading = firstReading(await call("mail_flag", { id: row.id, flagged: true }));
    if (reading.kind === "done") return reading.outcome;
    const { body } = reading;
    if (typeof body.refusal === "string") return "refused";
    if (body.stateSource === "unconfirmed") return "unconfirmed";
    if (body.stateSource === "store-echo" || body.stateSource === "read-back") {
      return body.state === "flagged" ? "flagged" : "refused";
    }
    return "unreadable";
  } catch {
    return "failed";
  }
}

/**
 * Place one draft reply to the row's sender, in the rule's words (D-05 as
 * revised, D-29, D-30).
 *
 * The recipient comes from `replyRecipient` and nowhere else. On a skip, no
 * call is made and the skip is the outcome. Otherwise the reply tool is called
 * with exactly three arguments: the message's id, the rule's text, and a
 * one-element recipient list holding the From address. Passing the recipient is
 * what stops the tool from choosing it: with none given, the tool would take
 * the address the parent message asks replies to go to, ahead of its From
 * line. Nobody is copied, and nothing is attached.
 *
 * `self` is the account's own address, compared and never used as a recipient.
 * Maps the answer: `placed` when the draft reached the folder, `refused` when
 * the tool declined to write it; a tool error by its category; a failed call is
 * `failed`. Never throws.
 */
export async function placeDraft(
  call: CallFn,
  row: EnvelopeRow,
  draft: RuleDraft,
  self: string,
): Promise<ActionOutcome> {
  try {
    const recipient = replyRecipient(row, self);
    if (recipient.kind === "skip") {
      if (recipient.reason === "mailing-list") return "skipped_mailing_list";
      if (recipient.reason === "own-address") return "skipped_own_address";
      return "skipped_no_address";
    }
    const reading = firstReading(
      await call("mail_compose_reply", { parentId: row.id, text: draft.text, to: [recipient.to] }),
    );
    if (reading.kind === "done") return reading.outcome;
    if (reading.body.appended === true) return "placed";
    if (reading.body.appended === false) return "refused";
    return "unreadable";
  } catch {
    return "failed";
  }
}
