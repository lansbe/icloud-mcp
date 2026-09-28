// The owner's status record for one person's rules job (Phase 28, D-17,
// AUTO-15, plan 28-03).
//
// WHY IT EXISTS. The job's state lives in the person's own Durable Object, and
// the owner's grants script cannot read an object's storage. So each run also
// writes one small record to the sign-in store, where the script can list it:
// when the job next wakes, how many sign-ins in a row iCloud refused, when it
// last ran and how that run ended, and how many rules the person holds. The
// dead-password marker in the same store is the precedent for an app key there.
//
// WHAT IT MUST NEVER HOLD. No address, no subject, no rule value, no draft
// text, no message id and no marker. Only the six fixed keys below, each a
// number or a word from the job's closed list of run outcomes. The person reads
// their own activity through a tool; the owner reads this, and it must not
// become a second copy of anybody's mail.
//
// THE KEY. The prefix, then the person's user id straight after it, with
// nothing between (the `store-key-without-a-user` rule). The id is the one the
// object stored for itself (Phase 25, D-22), handed in by the job, never a value
// a caller chose. An id that is not a user id's shape writes nothing, so a key
// with no user segment is never written.
//
// It expires three days after the last run, so a person whose job stopped
// leaves no record behind for long.
//
// This module logs nothing.

import type { RunOutcome } from "./tool-call";

/**
 * The record's key prefix. The user id follows it directly. Exported so a test
 * asserts against the real value, and the owner's script lists by it.
 */
export const AUTONOMY_STATUS_KEY_PREFIX = "autonomy-status:v1:";

/** How long a record lives after the run that wrote it: three days, 3 × 86 400 seconds. */
export const AUTONOMY_STATUS_TTL_SECONDS = 259200;

/** 64 lower-case hex characters: the shape of a user id. */
const USER_ID = /^[0-9a-f]{64}$/;

/** The shape of a word on the closed list of run outcomes. */
const OUTCOME_WORD = /^[a-z_]{1,40}$/;

/** What one run reports. Numbers and a closed word only. */
export interface AutonomyStatus {
  /** When the job next wakes, in ms since the epoch, or null when not known. */
  readonly nextAt: number | null;
  /** Consecutive sign-ins iCloud refused, after this run. */
  readonly authFailures: number;
  /** When this run ran, in ms since the epoch. */
  readonly lastRunAt: number;
  /** How this run ended. */
  readonly lastOutcome: RunOutcome;
  /** How many rules the person holds. */
  readonly rules: number;
}

/** The part of the sign-in store this module writes to. */
export interface StatusStore {
  put(key: string, value: string, options: { expirationTtl: number }): Promise<unknown>;
}

/** A finite number, or null. */
function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** A count: a safe integer at least 0, else 0. */
function count(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

/**
 * Write this person's status record. The value is built from the listed keys
 * only, so nothing else a caller passes can reach the store. Writes nothing for
 * an id that is not a user id's shape. A failed write rejects; the job catches
 * it, and it never changes the run's outcome.
 */
export async function writeAutonomyStatus(
  kv: StatusStore,
  userId: string,
  status: AutonomyStatus,
): Promise<void> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return;
  const value = {
    v: 1,
    nextAt: finiteOrNull(status.nextAt),
    authFailures: count(status.authFailures),
    lastRunAt: finiteOrNull(status.lastRunAt),
    lastOutcome: typeof status.lastOutcome === "string" && OUTCOME_WORD.test(status.lastOutcome)
      ? status.lastOutcome
      : null,
    rules: count(status.rules),
  };
  await kv.put(`${AUTONOMY_STATUS_KEY_PREFIX}${userId}`, JSON.stringify(value), {
    expirationTtl: AUTONOMY_STATUS_TTL_SECONDS,
  });
}
