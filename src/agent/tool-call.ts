// The shapes the rules job passes around (Phase 28, D-04, D-09, D-19, D-30).
//
// TYPES ONLY. This module has no runtime code and no list of tool names. The
// names the job may call live in exactly one place, `AUTONOMY_TOOLS` in
// `./autonomy-client.ts`, and the tool-name type below is read off that list.
// Why one list: Phase 27's `call` refuses any name outside it at run time, so a
// second list here could only disagree with the one that is enforced, and the
// disagreement would look like a guard while guarding nothing.
//
// The row type is what the job keeps of one new inbox message: its id, when
// iCloud received it, the sender's address, the subject, and whether it came
// from a mailing list. It keeps nothing else. In particular it keeps no display
// name: the sender's display name is never read out of an answer, so no rule
// can match on it and no reply can be addressed to it.

import type { AUTONOMY_TOOLS } from "./autonomy-client";

/** One of the four tools the autonomy key may call. Read off the one list. */
export type AutonomyToolName = (typeof AUTONOMY_TOOLS)[number];

/** One tool call the job makes: a name from the one list, and plain arguments. */
export interface ToolCall {
  readonly tool: AutonomyToolName;
  readonly args: Readonly<Record<string, unknown>>;
}

/**
 * What one call answers. The same shape as Phase 27's `call`: `ok` carries the
 * tool's MCP result (`content`, and `isError` when it is set), and `failed`
 * carries nothing, whatever went wrong.
 */
export type CallAnswer = { kind: "ok"; result: unknown } | { kind: "failed" };

/**
 * The call function the job is handed inside a session. Phase 27's `call`
 * fits it: it takes any string, and this narrows the name to the one list.
 */
export type CallFn = (
  tool: AutonomyToolName,
  args: Record<string, unknown>,
) => Promise<CallAnswer>;

/**
 * One new inbox message, as the job holds it.
 *
 * `id` is the opaque message id the server wrote. `receivedAt` is iCloud's
 * receipt time in milliseconds, or null when it would not parse; a null time
 * matches no rule. `senderAddress` is the address in the From line, exactly as
 * the answer held it, or null. `subject` is the subject, or null. `mailingList`
 * is true when the message had a list id or an unsubscribe field.
 */
export interface EnvelopeRow {
  readonly id: string;
  readonly receivedAt: number | null;
  readonly senderAddress: string | null;
  readonly subject: string | null;
  readonly mailingList: boolean;
}

/**
 * What one action came to. A closed list.
 *
 * The flag: `flagged` (iCloud confirmed it), `unconfirmed` (sent, and iCloud's
 * answer did not say), `refused` (the tool refused, or iCloud reported the flag
 * not set).
 * The reply: `placed` (the draft reached the folder), `refused` (the tool
 * declined to write it).
 * Either: `busy` (the person's own request held the connection), `auth_failed`
 * (iCloud refused the sign-in), `error` (any other tool error), `failed` (the
 * call itself failed), `unreadable` (an answer this job could not read).
 * The reply skips (D-30), which make no call at all: `skipped_no_address`,
 * `skipped_own_address`, `skipped_mailing_list`, and `skipped_duplicate` (a
 * second reply to the same message in one run).
 * `skipped_cap`: past a per-run or per-day cap (plan 28-02), no call.
 */
export type ActionOutcome =
  | "flagged"
  | "unconfirmed"
  | "placed"
  | "refused"
  | "busy"
  | "auth_failed"
  | "error"
  | "failed"
  | "unreadable"
  | "skipped_no_address"
  | "skipped_own_address"
  | "skipped_mailing_list"
  | "skipped_duplicate"
  | "skipped_cap";

/**
 * What one run came to. A closed list.
 *
 * Before any I/O: `no_rules`, `not_armed` (no autonomy record), `retry` (the
 * platform's retry of an alarm, which the job never acts on), `not_due` (the
 * shared alarm fired for another job before this job's own time).
 * The session: `not_allowed`, `off`, `revoked`, `session_failed`.
 * The change check: `call_failed`, `unreadable`, `marker_refused`,
 * `markers_unavailable`, `inbox_not_checked`.
 * The end: `started` (a starting point: the marker was stored and nothing was
 * acted on), `done` (every verdict handled and the fresh marker stored),
 * `stopped` (an action failed, so the run stopped and kept the old marker).
 * `failed`: something threw inside the job. It is caught and never read.
 */
export type RunOutcome =
  | "no_rules"
  | "not_armed"
  | "retry"
  | "not_due"
  | "not_allowed"
  | "off"
  | "revoked"
  | "session_failed"
  | "call_failed"
  | "unreadable"
  | "marker_refused"
  | "markers_unavailable"
  | "inbox_not_checked"
  | "started"
  | "done"
  | "stopped"
  | "failed";
