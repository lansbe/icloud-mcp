// The rules job: one run on the person's own object (Phase 28, D-02, D-14,
// D-15, D-25, D-27).
//
// Autonomy is inherent: every person who signs in holds an autonomy key. For a
// person who has written at least one rule, the object's one alarm runs this
// job. It asks the change check for new inbox mail, runs the rules over each new
// message's sender and subject, and flags the messages a rule says to flag. It
// records what it did. For a person with no rules it does nothing at all.
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
//   4. Ask the change check, with the stored marker. Classify the answer.
//   5. Evaluate. Act one verdict at a time. For each: skip it if its "already
//      acted" record exists; otherwise write that record as `reserved`
//      synchronously, then make the one tool call, then write what happened.
//      So a redelivered alarm never acts twice (D-15). A failure that means
//      the account cannot be reached stops the run at once.
//   6. Store the fresh marker LAST, only when the run reached the end. A run
//      that stopped keeps the old marker, so the next run sees the same mail
//      and the records skip what was already done.
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
// Plan 28-02 adds the reply in the run, the caps and the marker's 24-hour rule;
// plan 28-03 the failure counter and the owner's status.

import { appendActivity, type ActivityKind } from "./activity";
import { setFlag } from "./actions";
import { autonomyArmed, type AutonomySessionOutcome } from "./autonomy";
import { JOB_CADENCE_MS, nextWakeAfter } from "./cadence";
import { evaluate } from "./evaluate";
import { type Rule, storedRuleOf } from "./rules";
import type { ActionOutcome, CallFn, RunOutcome } from "./tool-call";
import { readChangesAnswer } from "./tool-reply";

/** The storage key of the person's rules. */
export const RULES_KEY = "rules";

/** The storage key of the stored marker and the time it was stored. */
export const JOB_MARKER_KEY = "job:marker";

/** The storage key of the job's next wanted wake. */
export const JOB_NEXT_AT_KEY = "job:nextAt";

/** The storage key of the last run's time and outcome. */
export const JOB_LAST_RUN_KEY = "job:lastRun";

/** The start of every "already acted" record's key. */
const ACTED = "acted:";

/** The part of the object's key-value storage the job uses. */
export interface JobStorage {
  get<T = unknown>(key: string): T | undefined;
  put<T>(key: string, value: T): void;
  delete(key: string): boolean;
}

/**
 * Everything one run needs, handed in by the object.
 *
 * `name` is the object's own stored name, from `storedOwnName()`, never the
 * platform's id. `requestWake` is bound to the object's one scheduling helper.
 * `withSession` is bound to Phase 27's `withAutonomySession`, inside the
 * object's autonomy queue; tests replace it with a recording one.
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
 * message (D-15). The message id is hashed, so no mailbox name sits in a key
 * and every key has the same length.
 */
export async function actedKey(ruleId: string, action: "flag" | "draft", messageId: string): Promise<string> {
  return `${ACTED}${ruleId}:${action}:${await sha256Hex(messageId)}`;
}

/** Outcomes that mean the account could not be reached: the run stops. */
const STOPS_THE_RUN: readonly ActionOutcome[] = ["busy", "auth_failed", "error", "failed", "unreadable"];

/** The session's answer as a run outcome, when it did not reach `use`'s value. */
function sessionOutcome(kind: "not_allowed" | "off" | "revoked" | "failed"): RunOutcome {
  if (kind === "failed") return "session_failed";
  return kind;
}

/**
 * One run, in D-14's order. Returns a run outcome from the closed list. Never
 * throws.
 */
export async function runAutonomyJob(deps: JobDeps): Promise<RunOutcome> {
  let runId = "";
  let now = 0;
  const record = (kind: ActivityKind, ruleId: string | null, messageId: string | null, outcome: string) => {
    appendActivity(deps.storage, { at: now, runId, kind, ruleId, messageId, outcome });
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

    // 2. The next wake, on the person's own offset, asked for before any I/O.
    const nextAt = nextWakeAfter(now, deps.name);
    deps.storage.put(JOB_NEXT_AT_KEY, nextAt);
    await deps.requestWake(nextAt);

    // 3. One session; every call inside it, one after another.
    const previous = storedMarker(deps.storage);
    const session = await deps.withSession(async (call): Promise<RunOutcome> => {
      // 4. The change check. INBOX only: no folders argument (D-02).
      const answer = await call("changes_since", previous === null ? {} : { marker: previous.marker });
      if (answer.kind !== "ok") return "call_failed";
      const reading = readChangesAnswer(answer.result);
      if (reading.kind === "unreadable") return "unreadable";
      if (reading.kind === "markers-unavailable") return "markers_unavailable";
      if (reading.kind === "marker-not-accepted") {
        // The next run starts fresh (D-16).
        deps.storage.delete(JOB_MARKER_KEY);
        return "marker_refused";
      }
      if (reading.state === "not_checked" || reading.state === "gone") return "inbox_not_checked";
      if (reading.state === "started" || reading.state === "restarted") {
        // A starting point: store the marker, act on nothing.
        deps.storage.put<StoredMarker>(JOB_MARKER_KEY, { marker: reading.marker, at: now });
        return "started";
      }

      // 5. Evaluate, then act one verdict at a time.
      for (const verdict of evaluate(rules, reading.rows)) {
        const rule = rules[verdict.rule];
        const row = reading.rows[verdict.row];
        if (rule === undefined || row === undefined) continue;
        // The reply joins the run in plan 28-02. Until then a draft verdict
        // is passed over: no record, no call.
        if (verdict.action !== "flag") continue;

        const key = await actedKey(rule.id, verdict.action, row.id);
        if (deps.storage.get<unknown>(key) !== undefined) continue;
        deps.storage.put<ActedRecord>(key, { state: "reserved", at: now });
        const outcome = await setFlag(call, row);
        deps.storage.put<ActedRecord>(key, { state: outcome, at: now });
        record("flag", rule.id, row.id, outcome);
        if (STOPS_THE_RUN.includes(outcome)) return "stopped";
      }

      // 6. Only a run that reached the end stores the fresh marker.
      deps.storage.put<StoredMarker>(JOB_MARKER_KEY, { marker: reading.marker, at: now });
      return "done";
    });

    const outcome: RunOutcome = session.kind === "ok" ? session.value : sessionOutcome(session.kind);
    record("run", null, null, outcome);
    deps.storage.put(JOB_LAST_RUN_KEY, { at: now, outcome });
    return outcome;
  } catch {
    try {
      if (runId !== "") {
        record("run", null, null, "failed");
        deps.storage.put(JOB_LAST_RUN_KEY, { at: now, outcome: "failed" });
      }
    } catch {
      // Nothing left to record.
    }
    return "failed";
  }
}
