// The rules job's clock (Phase 28, D-07). Skeleton for the RED commit: the
// behaviour 28-01 had (no offset, a wake one cadence after now).

/** How often the job wakes: 15 × 60 × 1000 = 900 000 ms. */
export const JOB_CADENCE_MS = 900000;

/** The person's offset into the cadence. Not built yet. */
export function jobOffsetMs(_userId: string): number {
  return 0;
}

/** The person's next wake after `now`. Not built yet. */
export function nextWakeAfter(now: number, _userId: string): number {
  return now + JOB_CADENCE_MS;
}
