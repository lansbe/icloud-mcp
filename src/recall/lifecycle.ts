// Expiry and the wholesale destroy for recall (Phase 25, RCLL-05, RCLL-06).
//
// Both run in the person's object, from its alarm, over a small ledger handle
// the object supplies and a recall store. Both delete from the STORE FIRST and
// only then remove the rows from the ledger, so the ledger is always a superset
// of what the store holds: a failure between the two leaves rows for vectors
// already gone, and deleting those again is harmless. The other order would
// leave a vector no row knows about, which nothing could ever delete.
//
// A store rejection reaches the caller unchanged (`RecallStoreError`). No caught
// value is read here and nothing is logged (./.claude/CLAUDE.md §4).

import type { RecallStore } from "./index";

/** The most ids in one batch. */
const BATCH = 1000;

/** The most batches one sweep runs before it asks to be run again. */
const SWEEP_MAX_BATCHES = 50;

/** What the object hands in: reads and removals over its own ledger. */
export interface LedgerHandle {
  expiredIds(now: number, limit: number): string[];
  anyIds(limit: number): string[];
  forget(ids: readonly string[]): void;
}

/**
 * Delete expired vectors, store first. At most 50 batches of 1000. Answers
 * whether expired rows remain, so the caller can come back in a minute.
 */
export async function sweepExpired(
  ledger: LedgerHandle,
  store: RecallStore,
  now: number,
): Promise<boolean> {
  for (let batch = 0; batch < SWEEP_MAX_BATCHES; batch += 1) {
    const ids = ledger.expiredIds(now, BATCH);
    if (ids.length === 0) return false;
    await store.deleteIds(ids);
    ledger.forget(ids);
  }
  return ledger.expiredIds(now, 1).length > 0;
}

/** Delete every vector the ledger holds, store first, until none remain. */
export async function destroyAll(ledger: LedgerHandle, store: RecallStore): Promise<void> {
  for (;;) {
    const ids = ledger.anyIds(BATCH);
    if (ids.length === 0) return;
    await store.deleteIds(ids);
    ledger.forget(ids);
  }
}
