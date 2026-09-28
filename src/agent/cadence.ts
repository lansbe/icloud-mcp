// The rules job's clock (Phase 28, D-07, AUTO-08).
//
// ONE LITERAL, AND NOTHING CAN SET IT. The job wakes every `JOB_CADENCE_MS`.
// No tool input, no rule field and no method on the object names a time: the
// rule parser refuses every key it does not know, a time-like one included, and
// the object's only way to ask for a wake is its one scheduling helper, with a
// time this module computed. A faster cadence is a decision on the safety
// boundary, made by editing this literal, never an input.
//
// WHY EACH PERSON HAS AN OFFSET. Everyone with rules would otherwise wake on the
// same quarter hours and reach iCloud together. The offset is read off the
// person's own user id, which is already a 64-hex digest, so it is stable for
// that person and spread across people without a second hash. The id is the
// object's stored own name (25 D-22), never the platform's id.
//
// No runtime import, and this module logs nothing.

/**
 * How often the job wakes, in milliseconds: 15 minutes (D-07).
 *
 * 15 × 60 × 1000 = 900 000.
 *
 * The arithmetic that makes 15 the number: each wake is at least one iCloud
 * session (the change check), and a wake that acts adds one per flag and two per
 * reply. At 15 minutes a person is 96 wakes a day, so a handful of people with
 * rules is a few hundred sessions a day before any action. iCloud's own
 * per-account ceiling is undocumented and deliberately unmeasured, and running
 * into it locks the person out of their own mail on their own devices. So the
 * cadence stays slow, and a faster one is a decision, not a refactor.
 */
export const JOB_CADENCE_MS = 900000;

/** Exactly what a user id is: 64 lower-case hex digits. */
const USER_ID = /^[0-9a-f]{64}$/;

/**
 * The person's stable offset into the cadence, in milliseconds: an integer in
 * [0, JOB_CADENCE_MS).
 *
 * The first 8 hex digits of the user id, read as an integer, modulo the
 * cadence. Anything that is not exactly a user id gets 0, so a malformed name
 * still wakes, just on the shared quarter hour.
 */
export function jobOffsetMs(userId: string): number {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return 0;
  return Number.parseInt(userId.slice(0, 8), 16) % JOB_CADENCE_MS;
}

/**
 * The person's next wake: the first time strictly after `now` that falls on
 * their offset. Always in (now, now + JOB_CADENCE_MS].
 */
export function nextWakeAfter(now: number, userId: string): number {
  const offset = jobOffsetMs(userId);
  const into = (((now - offset) % JOB_CADENCE_MS) + JOB_CADENCE_MS) % JOB_CADENCE_MS;
  return now - into + JOB_CADENCE_MS;
}
