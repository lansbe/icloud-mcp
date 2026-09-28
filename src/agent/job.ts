// The rules job: one run on the person's own object (Phase 28, D-02, D-14,
// D-15, D-25, D-27).
//
// Autonomy is inherent: every person who signs in holds an autonomy key. For a
// person who has written at least one rule, the object's one alarm runs this
// job. It asks the change check for new inbox mail, runs the rules over each new
// message's sender and subject, flags the messages a rule says to flag, and
// places a draft reply, in the rule's own words, to the sender of the messages a
// rule says to answer. It records what it did. For a person with no rules it
// does nothing at all.
//
// THE ORDER (D-14 as revised).
//   1. Due check, cheapest first: at least one rule (a local read), then an
//      autonomy record (presence only, through `autonomyArmed`), then not a
//      platform retry. Any "no" returns at once, having written nothing and
//      asked for nothing (D-25). Then its own time: a run the shared alarm
//      woke early for another job asks for its own time again and returns,
//      having written nothing.
//   2. Ask for the next wake through the object's one scheduling helper, before
//      any I/O, so a run that dies still leaves the alarm set.
//   3. One session, through the `withSession` it is handed. The object binds
//      that to Phase 27's `withAutonomySession`, inside the object's one
//      autonomy queue, with that run's ticket. Every call below happens inside
//      that one session, one after another, each awaited.
//   4. Ask the change check, with the stored marker, unless that marker is
//      more than a day old: then send none, and the run is a new starting
//      point that acts on nothing (D-26). Classify the answer.
//   5. Evaluate. If a reply is still to be decided, ask the sign-in check once
//      for the account's own address, before any action (D-30). Then act one
//      verdict at a time. For each: skip it if its "already acted" record
//      exists; past a cap, or a reply that must not be placed, write the
//      record in that final state and make no call; otherwise write the record
//      as `reserved` synchronously, make the one tool call, then write what
//      happened. So a redelivered alarm never acts twice (D-15). A failure that
//      means the account cannot be reached stops the run at once. A busy lease
//      or a sign-in that did not go through proves nothing was done, so that
//      reservation is removed and the next run tries again (28-REVIEW WR-02).
//   6. Store the fresh marker LAST, only when the run reached the end. A run
//      that stopped keeps the old marker, so the next run sees the same mail
//      and the records skip what was already done.
//   7. Remove "already acted" records older than 14 days, at most 500 a run.
//   8. Write the owner's status record to the sign-in store (D-17,
//      `./status.ts`), in its own `try`, for every run that got past step 1.
//
// THE REPLY. Its one recipient is the message's From address, through
// `replyRecipient`, which only `placeDraft` calls; the job never reads the
// sender's address itself. It is placed through the reply tool, so its subject,
// threading headers and quote are that tool's own. One reply per message per
// run. A reply that must not be placed (the account's own address, a mailing
// list, no usable address, a second reply to one message) makes no call and
// does not count toward a cap.
//
// THE CAPS (D-08). Per run: 10 flags and 3 replies. Per UTC day: 10 replies,
// kept under `job:draftDay`, which no sign-in resets.
//
// WHAT IT NEVER DOES. It never takes the connection lease: each tool call takes
// it inside the door, like any other request, and a lease taken here would make
// every one of its own calls answer busy (AUTO-13). It never reads the
// autonomy record's fields: it asks only whether one exists. It never reads a
// message body, and never reads the sender's address itself: the matcher and
// the reply's one recipient function do. It never indexes anything: the recall
// build skips requests made with the autonomy key. It never throws, and never
// reads a caught value. It logs nothing.
//
// THE CLOCK. The job wakes on its own fixed cadence, at an offset taken from the
// person's user id (`./cadence.ts`). Nothing here, and nothing a caller hands
// in, can change either.
//
// FAILURES (D-16 as revised, plan 28-03). Every call in a run goes through one
// guard. The first answer that is not a tool's plain answer (a failed call, or
// a tool error of any category) ends the run's calls: the guard refuses every
// later one without sending it, so nothing is retried inside a run.
//   - A tool error whose category is `auth_failed` AND whose answer says Apple
//     itself refused the saved password (`credentialRefused`, 28-REVIEW CR-01)
//     is the one failure counted, under `job:authFailures`. It costs an Apple
//     login (PITFALLS #43), and it is the person's own. A change answer the
//     job could read sets the count back to 0: the sign-in worked.
//   - Any other `auth_failed` is `sign_in_unavailable`: it stops the run and is
//     never counted. That is a server fault at the sign-in (`[SERVERBUG]`,
//     `[CONTACTADMIN]`, a `BAD`), the dead-password pause, a calendar refusal
//     inside the change check (the job reads only its mail half, D-02), or a
//     password this server will not send. Counting them would let an iCloud
//     outage end every person's key at once.
//   - The second in a row ends the key through Phase 27's `disarmWith`, the one
//     thing in the object that ends a key, called after the session and never
//     as an RPC. The count goes back to 0 and `job:state` says `off_auth`. The
//     rules and the activity stay. Nothing here arms: the person's next sign-in
//     makes a new key, and the job starts again on its own.
//   - Anything else (a busy lease, another tool error, a failed call, the
//     markers-unavailable refusal, an answer the job cannot read) stops the run
//     and keeps the marker. The count is left as it was. A failed call is never
//     counted: Phase 27 folds every HTTP failure into it, a 401 included, and a
//     config fault (an unusable seal key, `invalid_client`) or a refused second
//     session answers `failed` too. Counting those would end every person's key
//     at once for a fault that is not theirs.
//   - A busy answer is never waited on: the run ends, and the next wake is the
//     normal one.
// After the key ends, and after a session that answered `off` or `revoked`, the
// job asks the one scheduling helper again, so the alarm goes when no job is
// left (Phase 27's contract).

import { appendActivity, type ActivityKind } from "./activity";
import { placeDraft, setFlag } from "./actions";
import { autonomyArmed, type AutonomySessionOutcome } from "./autonomy";
import { JOB_CADENCE_MS, nextWakeAfter } from "./cadence";
import { evaluate } from "./evaluate";
import { type Rule, storedRuleOf } from "./rules";
import { type StatusStore, writeAutonomyStatus } from "./status";
import type { ActionOutcome, CallAnswer, CallFn, EnvelopeRow, RunOutcome } from "./tool-call";
import {
  isErrorAnswer,
  messageIdentity,
  readChangesAnswer,
  readCredentialRefused,
  readSignedInAs,
  readToolError,
} from "./tool-reply";

/** The storage key of the person's rules. */
export const RULES_KEY = "rules";

/** The storage key of the stored marker and the time it was stored. */
export const JOB_MARKER_KEY = "job:marker";

/** The storage key of the job's next wanted wake. */
export const JOB_NEXT_AT_KEY = "job:nextAt";

/** The storage key of the last run's time and outcome. */
export const JOB_LAST_RUN_KEY = "job:lastRun";

/** The storage key of the day's reply count: the UTC date and a count. */
export const JOB_DRAFT_DAY_KEY = "job:draftDay";

/**
 * The storage key of the count of consecutive auth failures (D-16 as revised).
 * The failure handling (plan 28-03) writes it; the rules view reads it.
 */
export const JOB_AUTH_FAILURES_KEY = "job:authFailures";

/**
 * The storage key of the job's stopped state (D-16 as revised). `off_auth`
 * means iCloud refused the sign-in twice in a row and the key was ended. The
 * failure handling (plan 28-03) writes it; the rules view reads it.
 */
export const JOB_STATE_KEY = "job:state";

/** The job's stopped state after the key was ended for refused sign-ins. */
export const JOB_OFF_AUTH = "off_auth";

/**
 * How many refusals of the password in a row end the key (D-16 as revised):
 * two, and they must be two separate refusals by Apple (28-REVIEW WR-01).
 *
 * Two, not one: a single refusal can be a blip on Apple's side. Only an answer
 * marked as Apple refusing the password is counted, and the dead-password
 * pause's answer is not one (28-REVIEW CR-01). The pause lasts 900 seconds and
 * the cadence is 900 seconds, so the run after a refusal almost always meets
 * the pause, which stops the run and leaves the count at 1. The second counted
 * refusal therefore comes from a run that reached Apple after the pause ran
 * out: in practice two refusals about 30 minutes apart. Before this was fixed,
 * the pause's own answer was counted, so one refusal ended the key 15 minutes
 * later. Decided by Claude, owner may revise.
 *
 * Not more: each counted refusal is a failed login against Apple's unpublished
 * lockout threshold.
 */
export const AUTH_FAILURES_TO_DISARM = 2;

/** The start of every "already acted" record's key. */
const ACTED = "acted:";

/**
 * How old a stored marker may be and still be sent: 24 hours (D-26).
 *
 * 24 × 60 × 60 × 1000 = 86 400 000. A gap longer than a day means the job was
 * not running for this person (the key was gone, or every rule had been
 * removed). The mail from that gap is not worked through: the run is a new
 * starting point instead. A sign-in does not reset this, because the marker
 * belongs to the mailbox, not to the key.
 */
export const JOB_MARKER_MAX_AGE_MS = 86400000;

/** The most flags one run makes (D-08). Each is one iCloud session. */
export const MAX_FLAGS_PER_RUN = 10;

/** The most replies one run places (D-08). Each is two iCloud sessions. */
export const MAX_DRAFTS_PER_RUN = 3;

/** The most replies one UTC day places, across runs and sign-ins (D-08, D-26). */
export const MAX_DRAFTS_PER_DAY = 10;

/** How long an "already acted" record is kept: 14 days (D-15). 14 × 86 400 000. */
export const ACTED_MAX_AGE_MS = 1209600000;

/** The most "already acted" records one run removes (D-15). */
export const ACTED_EXPIRY_PER_RUN = 500;

/** The part of the object's key-value storage the job uses. */
export interface JobStorage {
  get<T = unknown>(key: string): T | undefined;
  put<T>(key: string, value: T): void;
  delete(key: string): boolean;
  list<T = unknown>(options: { prefix: string }): Iterable<[string, T]>;
}

/**
 * Everything one run needs, handed in by the object.
 *
 * `name` is the object's own stored name, from `storedOwnName()`, never the
 * platform's id. `requestWake` is bound to the object's one scheduling helper.
 * `withSession` is bound to Phase 27's `withAutonomySession`, inside the
 * object's autonomy queue; tests replace it with a recording one. `disarm` is
 * bound to Phase 27's `disarmWith`, over the same storage, name and seam, and
 * is called only by the second-failure rule, inside the same queue run, after
 * the session has settled. `statusStore` is the sign-in store, where each run
 * leaves the owner's status record under `name` (D-17, `./status.ts`).
 */
export interface JobDeps {
  readonly storage: JobStorage;
  readonly name: string;
  readonly now: () => number;
  readonly isRetry: boolean;
  readonly requestWake: (wantedAt: number) => Promise<void>;
  readonly withSession: <T>(
    use: (call: CallFn) => Promise<T>,
  ) => Promise<AutonomySessionOutcome<T>>;
  readonly disarm: () => Promise<unknown>;
  readonly statusStore: StatusStore;
}

/** What the "already acted" record holds: its state and when it was written. */
export interface ActedRecord {
  readonly state: "reserved" | ActionOutcome;
  readonly at: number;
}

/** The stored marker, and when it was stored. */
interface StoredMarker {
  readonly marker: string;
  readonly at: number;
}

/** Every stored rule that parses. A value that does not is never acted on. */
export function readRules(storage: Pick<JobStorage, "get">): Rule[] {
  const value = storage.get<unknown>(RULES_KEY);
  if (!Array.isArray(value)) return [];
  const rules: Rule[] = [];
  for (const one of value) {
    const rule = storedRuleOf(one);
    if (rule !== null) rules.push(rule);
  }
  return rules;
}

/** The stored marker, or null. */
function storedMarker(storage: JobStorage): StoredMarker | null {
  const value = storage.get<unknown>(JOB_MARKER_KEY);
  if (typeof value !== "object" || value === null) return null;
  const m = value as { marker?: unknown; at?: unknown };
  if (typeof m.marker !== "string" || m.marker.length === 0) return null;
  if (typeof m.at !== "number" || !Number.isFinite(m.at)) return null;
  return { marker: m.marker, at: m.at };
}

/** Lower-case hex SHA-256 of `text`. */
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The key of the "already acted" record for one rule, one action and one
 * message (D-15).
 *
 * The message is named by what survives a move: iCloud's receipt time, the
 * From address (without case) and the subject, through `messageIdentity` in
 * `./tool-reply.ts`, the module that reads a row's fields (28-REVIEW WR-03). Not by its
 * id, because the id names the message's PLACE: moving a message to another
 * folder and back gives it a new id above the stored marker, so the change
 * check lists it as new mail, and a key on the id let the job flag it again
 * (a flag the user cleared came back) and place a second reply. The receipt
 * time is iCloud's, not the sender's, so two different messages share a key
 * only when the same sender sent the same subject within the same second; then
 * the second is not acted on, which is the safe direction (a missed draft
 * beats two). The three values are hashed, so no address or subject sits in a
 * key and every key has the same length.
 *
 * Not the Message-ID header: the change check's rows do not carry it, a header
 * fetch change is a read-path decision, and a stranger chooses it.
 */
export async function actedKey(ruleId: string, action: "flag" | "draft", row: EnvelopeRow): Promise<string> {
  return `${ACTED}${ruleId}:${action}:${await sha256Hex(messageIdentity(row))}`;
}

/** Outcomes that mean the account could not be reached: the run stops. */
const STOPS_THE_RUN: readonly ActionOutcome[] = ["busy", "auth_failed", "error", "failed", "unreadable"];

/**
 * Outcomes that prove nothing reached the mailbox (28-REVIEW WR-02). A busy
 * lease is refused at the door before any socket, and a sign-in that did not
 * go through writes nothing. So the reservation is removed rather than kept:
 * the run stops and keeps the old marker, and the next run, which sees the same
 * message, acts on it then. Every other outcome may have reached iCloud (an
 * error, a failed call, an unreadable answer), so it stays final: a missed
 * draft beats two (D-15).
 */
const NOTHING_DONE: readonly ActionOutcome[] = ["busy", "auth_failed"];

/** Reply outcomes that made no call. They never count toward a cap (D-30). */
const REPLY_SKIPS: readonly ActionOutcome[] = [
  "skipped_no_address",
  "skipped_own_address",
  "skipped_mailing_list",
];

/** Whether a stored "already acted" record is still `reserved`. */
function isReserved(value: unknown): boolean {
  return typeof value === "object" && value !== null && (value as { state?: unknown }).state === "reserved";
}

/** The stored count of consecutive auth failures; 0 for anything else. */
export function authFailuresOf(storage: Pick<JobStorage, "get">): number {
  const value = storage.get<unknown>(JOB_AUTH_FAILURES_KEY);
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

/**
 * Why a call's answer stopped the run, as a run outcome: a failed call, or a
 * tool error by its category. Only for an answer that is one of those.
 */
function stopOfAnswer(answer: CallAnswer): RunOutcome {
  if (answer.kind !== "ok") return "call_failed";
  const category = readToolError(answer.result);
  // Only Apple refusing the saved password is counted (28-REVIEW CR-01).
  if (category === "auth_failed") {
    return readCredentialRefused(answer.result) ? "auth_failed" : "sign_in_unavailable";
  }
  if (category === "connection_busy") return "busy";
  return "tool_error";
}

/** Whether an answer is a failed call or a tool error: it stops the run. */
function stops(answer: CallAnswer): boolean {
  return answer.kind !== "ok" || isErrorAnswer(answer.result);
}

/**
 * Why an action's outcome stopped the run, as a run outcome. `counted` says
 * whether the guard counted this run's auth failure: an `auth_failed` it did
 * not count was not Apple refusing the password (28-REVIEW CR-01).
 */
function stopOfAction(outcome: ActionOutcome, counted: boolean): RunOutcome {
  if (outcome === "auth_failed") return counted ? "auth_failed" : "sign_in_unavailable";
  if (outcome === "busy") return "busy";
  return "stopped";
}

/** The session's answer as a run outcome, when it did not reach `use`'s value. */
function sessionOutcome(kind: "not_allowed" | "off" | "revoked" | "failed"): RunOutcome {
  if (kind === "failed") return "session_failed";
  return kind;
}

/** The UTC date of `ms`, as `YYYY-MM-DD`. */
function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** How many replies were placed on `day`, from the stored count. Any other day is 0. */
function draftsOn(storage: JobStorage, day: string): number {
  const value = storage.get<unknown>(JOB_DRAFT_DAY_KEY);
  if (typeof value !== "object" || value === null) return 0;
  const v = value as { day?: unknown; count?: unknown };
  if (v.day !== day || typeof v.count !== "number" || !Number.isSafeInteger(v.count) || v.count < 0) return 0;
  return v.count;
}

/**
 * Remove "already acted" records older than `ACTED_MAX_AGE_MS`, at most
 * `ACTED_EXPIRY_PER_RUN` of them (D-15). A record that is not the shape this
 * module writes has no age to trust and goes too. The keys are collected first
 * and removed after, so nothing is removed while the listing is being read.
 */
function expireActed(storage: JobStorage, now: number): void {
  const expired: string[] = [];
  for (const [key, value] of storage.list<unknown>({ prefix: ACTED })) {
    if (expired.length >= ACTED_EXPIRY_PER_RUN) break;
    const at = typeof value === "object" && value !== null ? (value as { at?: unknown }).at : undefined;
    if (typeof at !== "number" || !Number.isFinite(at) || now - at > ACTED_MAX_AGE_MS) expired.push(key);
  }
  for (const key of expired) storage.delete(key);
}

/**
 * One run, in D-14's order. Returns a run outcome from the closed list. Never
 * throws.
 */
export async function runAutonomyJob(deps: JobDeps): Promise<RunOutcome> {
  let runId = "";
  let now = 0;
  let nextAtForStatus: number | null = null;
  let ruleCount = 0;
  // The owner's status record, at the end of every run that got past the due
  // check (D-17), in its own `try`: a failed write changes nothing about the
  // run. Runs that ended before any I/O write none.
  const finish = async (outcome: RunOutcome): Promise<RunOutcome> => {
    if (runId === "") return outcome;
    try {
      await writeAutonomyStatus(deps.statusStore, deps.name, {
        nextAt: nextAtForStatus,
        authFailures: authFailuresOf(deps.storage),
        lastRunAt: now,
        lastOutcome: outcome,
        rules: ruleCount,
      });
    } catch {
      // The run's outcome stands. The next run writes the record again.
    }
    return outcome;
  };
  const record = (
    kind: ActivityKind,
    ruleId: string | null,
    messageId: string | null,
    outcome: string,
    count?: number,
  ) => {
    appendActivity(deps.storage, {
      at: now,
      runId,
      kind,
      ruleId,
      messageId,
      outcome,
      ...(count === undefined ? {} : { count }),
    });
  };
  try {
    // 1. Due check, cheapest first (D-25, D-27). Nothing written before here.
    const rules = readRules(deps.storage);
    if (rules.length === 0) return "no_rules";
    if (!autonomyArmed(deps.storage)) return "not_armed";
    if (deps.isRetry) return "retry";

    now = deps.now();
    // Its own time: the alarm is shared, so it may have fired for another
    // job. Then the job asks for its own time again and writes nothing. A
    // stored time more than one cadence ahead was not written by this code
    // path, so it is not trusted and the run goes ahead.
    const storedNextAt = deps.storage.get<unknown>(JOB_NEXT_AT_KEY);
    if (
      typeof storedNextAt === "number" &&
      Number.isFinite(storedNextAt) &&
      now < storedNextAt &&
      storedNextAt <= now + JOB_CADENCE_MS
    ) {
      await deps.requestWake(storedNextAt);
      return "not_due";
    }

    runId = crypto.randomUUID();
    ruleCount = rules.length;

    // 2. The next wake, on the person's own offset, asked for before any I/O.
    const nextAt = nextWakeAfter(now, deps.name);
    nextAtForStatus = nextAt;
    deps.storage.put(JOB_NEXT_AT_KEY, nextAt);
    await deps.requestWake(nextAt);

    // The stored marker is sent only while it is at most a day old (D-26). The
    // autonomy record is not read: a new sign-in changes nothing here.
    const previous = storedMarker(deps.storage);
    const sendable = previous !== null && now - previous.at <= JOB_MARKER_MAX_AGE_MS ? previous : null;

    // 3. One session; every call inside it, one after another.
    let authFailed = false;
    const session = await deps.withSession(async (sessionCall): Promise<RunOutcome> => {
      // The one guard every call goes through (D-16). After an answer that
      // stops the run, it sends nothing more. An auth failure is counted here,
      // once, at the moment it arrives.
      let halted = false;
      const call: CallFn = async (tool, args) => {
        if (halted) return { kind: "failed" };
        const answer = await sessionCall(tool, args);
        if (stops(answer)) {
          halted = true;
          if (stopOfAnswer(answer) === "auth_failed") {
            authFailed = true;
            deps.storage.put(JOB_AUTH_FAILURES_KEY, authFailuresOf(deps.storage) + 1);
          }
        }
        return answer;
      };

      // 4. The change check. INBOX only: no folders argument (D-02).
      const answer = await call("changes_since", sendable === null ? {} : { marker: sendable.marker });
      if (answer.kind !== "ok" || isErrorAnswer(answer.result)) return stopOfAnswer(answer);
      const reading = readChangesAnswer(answer.result);
      if (reading.kind === "unreadable") return "unreadable";
      if (reading.kind === "markers-unavailable") return "markers_unavailable";
      if (reading.kind === "marker-not-accepted") {
        // The next run starts fresh (D-16).
        deps.storage.delete(JOB_MARKER_KEY);
        return "marker_refused";
      }
      if (reading.state === "not_checked" || reading.state === "gone") return "inbox_not_checked";
      // The inbox was checked, so the sign-in worked. The count of refused
      // sign-ins starts again, and a job stopped after refused sign-ins is
      // running again (a new sign-in made a new key).
      if (authFailuresOf(deps.storage) !== 0) deps.storage.put(JOB_AUTH_FAILURES_KEY, 0);
      if (deps.storage.get<unknown>(JOB_STATE_KEY) !== undefined) deps.storage.delete(JOB_STATE_KEY);
      if (reading.state === "started" || reading.state === "restarted") {
        // A starting point: store the marker, act on nothing.
        deps.storage.put<StoredMarker>(JOB_MARKER_KEY, { marker: reading.marker, at: now });
        return "started";
      }
      // New mail the answer counted and did not list is never acted on. Say so.
      if (reading.newMessages !== null && reading.newMessages > reading.rows.length) {
        record("run", null, null, "not_seen", reading.newMessages - reading.rows.length);
      }

      // 5. Evaluate. Each verdict's record key first, so the sign-in check is
      //    asked only when a reply might actually be placed.
      const verdicts: { rule: Rule; row: EnvelopeRow; action: "flag" | "draft"; key: string }[] = [];
      for (const verdict of evaluate(rules, reading.rows)) {
        const rule = rules[verdict.rule];
        const row = reading.rows[verdict.row];
        if (rule === undefined || row === undefined) continue;
        verdicts.push({ rule, row, action: verdict.action, key: await actedKey(rule.id, verdict.action, row) });
      }

      // The account's own address, read once, before any action, and only in a
      // run with a reply still to decide (D-30). It is compared, never used as a
      // recipient, and never stored. If it cannot be read, nothing is acted on
      // and the marker is kept.
      let self = "";
      if (verdicts.some((v) => v.action === "draft" && deps.storage.get<unknown>(v.key) === undefined)) {
        const who = await call("account_whoami", {});
        // An auth failure or a busy lease here is what it is anywhere else.
        if (stops(who) && who.kind === "ok") {
          const stop = stopOfAnswer(who);
          if (stop === "auth_failed" || stop === "sign_in_unavailable" || stop === "busy") return stop;
        }
        const address = who.kind === "ok" ? readSignedInAs(who.result) : null;
        if (address === null) return "own_address_unreadable";
        self = address;
      }

      // Act one verdict at a time, inside the caps (D-08). A verdict past a cap,
      // and a reply skip, writes its record in that final state and its entry,
      // makes no call, and is never retried.
      const day = utcDay(now);
      let draftsToday = draftsOn(deps.storage, day);
      let flagsThisRun = 0;
      let draftsThisRun = 0;
      const replied = new Set<string>();
      const settle = (v: (typeof verdicts)[number], outcome: ActionOutcome) => {
        deps.storage.put<ActedRecord>(v.key, { state: outcome, at: now });
        record(v.action, v.rule.id, v.row.id, outcome);
      };
      // An answer that proves nothing was done: the reservation goes, so the
      // next run tries again, and the entry still says what happened (WR-02).
      const release = (v: (typeof verdicts)[number], outcome: ActionOutcome) => {
        deps.storage.delete(v.key);
        record(v.action, v.rule.id, v.row.id, outcome);
      };

      for (const v of verdicts) {
        const prior = deps.storage.get<unknown>(v.key);
        const done = prior !== undefined;
        // A record an earlier run left `reserved`: its call went out and what
        // happened was never written down (the run died in between). It is
        // never tried again (D-15). It becomes `unknown`, once, with its entry,
        // so the person can see the job cannot say.
        if (isReserved(prior)) settle(v, "unknown");
        if (v.action === "flag") {
          if (done) continue;
          if (flagsThisRun >= MAX_FLAGS_PER_RUN) {
            settle(v, "skipped_cap");
            continue;
          }
          deps.storage.put<ActedRecord>(v.key, { state: "reserved", at: now });
          flagsThisRun += 1;
          const outcome = await setFlag(call, v.row);
          if (NOTHING_DONE.includes(outcome)) release(v, outcome);
          else settle(v, outcome);
          if (STOPS_THE_RUN.includes(outcome)) return stopOfAction(outcome, authFailed);
          continue;
        }

        // The reply. One per message per run: a message some rule already
        // decided a reply for, in this run or in an earlier one that stopped
        // part-way, gets no second one.
        if (done) {
          replied.add(v.row.id);
          continue;
        }
        if (replied.has(v.row.id)) {
          settle(v, "skipped_duplicate");
          continue;
        }
        replied.add(v.row.id);
        const draft = v.rule.then.draft;
        if (draft === undefined) continue;
        if (draftsThisRun >= MAX_DRAFTS_PER_RUN || draftsToday >= MAX_DRAFTS_PER_DAY) {
          settle(v, "skipped_cap");
          continue;
        }
        deps.storage.put<ActedRecord>(v.key, { state: "reserved", at: now });
        const outcome = await placeDraft(call, v.row, draft, self);
        if (!REPLY_SKIPS.includes(outcome) && !NOTHING_DONE.includes(outcome)) {
          draftsThisRun += 1;
          draftsToday += 1;
          deps.storage.put(JOB_DRAFT_DAY_KEY, { day, count: draftsToday });
        }
        if (NOTHING_DONE.includes(outcome)) release(v, outcome);
        else settle(v, outcome);
        if (STOPS_THE_RUN.includes(outcome)) return stopOfAction(outcome, authFailed);
      }

      // 6. Only a run that reached the end stores the fresh marker.
      deps.storage.put<StoredMarker>(JOB_MARKER_KEY, { marker: reading.marker, at: now });
      return "done";
    });

    let outcome: RunOutcome = session.kind === "ok" ? session.value : sessionOutcome(session.kind);

    // The second auth failure in a row ends the key (D-16 as revised). After
    // the session, never inside it, and inside the same queue run, so no other
    // autonomy operation is between the failure and the disarm. Only this
    // run's own auth failure can trigger it: a stored count alone never does.
    if (authFailed && authFailuresOf(deps.storage) >= AUTH_FAILURES_TO_DISARM) {
      await deps.disarm();
      deps.storage.put(JOB_AUTH_FAILURES_KEY, 0);
      deps.storage.put(JOB_STATE_KEY, JOB_OFF_AUTH);
      outcome = "off_auth";
    }
    // The key is gone (ended here, or found gone by the session): ask the one
    // scheduling helper again, so the alarm goes when no job is left. It asks
    // for the same time as before, never an earlier one.
    if (outcome === "off_auth" || session.kind === "off" || session.kind === "revoked") {
      await deps.requestWake(nextAt);
    }

    record("run", null, null, outcome);
    deps.storage.put(JOB_LAST_RUN_KEY, { at: now, outcome });
    // 7. Bounded records: old "already acted" records go, a few hundred a run.
    expireActed(deps.storage, now);
    return await finish(outcome);
  } catch {
    try {
      if (runId !== "") {
        record("run", null, null, "failed");
        deps.storage.put(JOB_LAST_RUN_KEY, { at: now, outcome: "failed" });
      }
    } catch {
      // Nothing left to record.
    }
    return await finish("failed");
  }
}
