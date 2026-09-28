// One recall build step: at most one IMAP session of work (Phase 26, D-12 to
// D-14 as revised by D-27, D-29).
//
// WHEN IT RUNS. The build runs on the person's own mail calls (CONTEXT D-01 as
// re-decided, D-26): after a mail tool answers, one step moves that person's
// index forward. Plan 26-07's driver calls this; nothing else does, and the
// object never imports this module.
//
// THE SLOT FIRST (D-29). A step reads the person's object before anything
// else. When the object says a build page may not start now (destroying, busy,
// paused, quota or full), the step answers that word and stops: no lease, no
// session, no write.
//
// ONE SESSION PER STEP (D-27). Otherwise the step does exactly one of these,
// each one IMAP session under the person's connection lease, and holds the
// lease for that session only:
//
//   1. no folder list yet: list the folders and store INBOX plus the account's
//      archive folder (D-12);
//   2. the first folder not built is at seed: run the status check for that
//      folder alone and store what it said (D-14, D-15);
//   3. that folder is at build: read and index one page of it through Phase
//      25's engine, which takes the page slot and keeps the cursor.
//
// KEEPING A BUILT FOLDER CURRENT (plan 26-04; D-14, D-17 as revised by D-27,
// D-30). A built folder is kept current the way Phase 23 finds new mail, with
// Phase 23's own state and status check, held here by the object instead of
// the caller. It takes two steps, never one:
//
//   4. a folder whose last status check left something due goes first. New
//      mail: one page of the oldest new messages, in a range bounded at both
//      ends, taking the page slot as a build page, so it counts toward the
//      daily cap and is refused at the ceiling. A deletion sync: Phase 25's
//      reconcile over the window's UIDs, which takes the slot as a reconcile.
//   5. otherwise the built folder checked longest ago, if that was at least
//      RECALL_CHECK_INTERVAL_MS ago: the status check alone, in a session
//      that opens no mailbox. It records what is due and what it saw, and
//      stops. The next step does that one thing.
//
// THE ORDER (26-REVIEW WR-04). A due folder first; then a built folder whose
// status check is due; then the first folder not built. So a built folder is
// kept current while another folder is still building: an archive of a few
// thousand messages takes days of mail calls to fill, and without this INBOX
// would get no new-mail page and no deletion sync for all of that time. The
// build loses at most one step in five minutes per built folder to it, and
// that step takes no page slot.
//
// There is no loop over pages, no second read after the first, no sleep, no
// retry and no combinator. Nothing sweeps every folder. The pace is the
// object's: a step that comes too early is told `paused` and stops. Recall is
// inherent (owner, 2026-09-27), so there is no off state to check.
//
// A lease refusal answers `lease_busy` and stores nothing.
//
// A FAILURE IS RECORDED AND WAITED OUT (26-REVIEW CR-01). Any other failure on
// a folder, and a status check that gives no answer, is written on that
// folder's sync row as the time it failed and how many times in a row it has.
// The step then leaves that folder alone for `recallRetryWaitMs(failures)`:
// five minutes after the first failure, doubling after each more, at most a
// day. While it waits, the step works on the other folders, so one folder that
// keeps failing never stops the rest and never opens a session on every mail
// call. What the failure clears depends on the stage:
//   - built: whatever was due is cleared and the check time is stamped, so the
//     next attempt is a fresh status check. That check sees a new validity or
//     a folder that is gone, which a retried read never would.
//   - build: after RECALL_RESEED_AFTER_FAILURES failures in a row the folder
//     goes back to seed, so its status check can find it gone. Its cursor is
//     kept: nothing says the validity changed, and the engine resets the
//     cursor itself when it did.
//   - seed: the row stays at seed.
// A failed folder listing is recorded on the object the same way, and waited
// out the same way. Success clears the count: a page, a new-mail page or a
// deletion sync that worked. A status check that worked keeps the count, so a
// folder whose reads keep failing waits longer each time and does not start
// over at five minutes.
//
// The failure itself still propagates, as `RecallBuildError`. No caught value
// is read (./.claude/CLAUDE.md §4), and nothing here logs.

import { agentFor, type LeasedMail } from "../agent/lease";
import {
  MAX_COUNTED_FAILURES,
  PAGE_REFUSALS,
  type PageRefusal,
  type SyncRow,
  syncRowIn,
} from "../agent/recall-ledger";
import type { CursorUpdate } from "../agent/user-agent";
import type { FolderState } from "../change-marker";
import { ConnectionBusyError } from "../errors";
import {
  DEFAULT_MAILBOX,
  type FolderListing,
  type FolderSnapshotOutcome,
  folderSnapshots,
  listFolders,
  resolveRoleFolder,
  type SessionGate,
} from "../mail/service";
import type { Principal } from "../principal";
import {
  type BuildDeps,
  type BuildStatus,
  forgetMailbox,
  indexNextPage,
  RECALL_PAGE_SIZE,
  RecallBuildError,
  reconcileMailbox,
} from "./build";
import { mailRecallSource, type NewMailPage, newMailPage } from "./mail-source";
import { indexItems, RecallRefusedError, recallDeps } from "./pipeline";

/**
 * How long a built folder's last status check stands before it is checked
 * again: five minutes, so a person's mail calls do not each become a status
 * check.
 */
export const RECALL_CHECK_INTERVAL_MS = 5 * 60 * 1000;

/**
 * The least time between two deletion syncs of one folder: an hour, because a
 * deletion sync reads the window's whole UID list.
 */
export const RECALL_RECONCILE_INTERVAL_MS = 60 * 60 * 1000;

/**
 * How many failed build pages in a row send a folder back to seed, so its
 * status check can find out whether it is gone (26-REVIEW CR-01).
 */
export const RECALL_RESEED_AFTER_FAILURES = 3;

/** The longest a failing folder, or a failing listing, is left alone: a day. */
export const RECALL_MAX_RETRY_WAIT_MS = 24 * 60 * 60 * 1000;

/**
 * How long a folder, or the folder listing, is left alone after `failures`
 * failed attempts in a row (26-REVIEW CR-01): RECALL_CHECK_INTERVAL_MS after
 * the first, doubling after each more, and never more than a day. No wait at
 * all when nothing failed.
 */
export function recallRetryWaitMs(failures: number): number {
  if (failures < 1) return 0;
  const doublings = Math.min(failures - 1, 16);
  return Math.min(RECALL_CHECK_INTERVAL_MS * 2 ** doublings, RECALL_MAX_RETRY_WAIT_MS);
}

/** Whether something that failed at `failedAt`, `failures` times in a row, is still waiting at `now`. */
function waiting(
  retry: { readonly failedAt: number | null; readonly failures: number } | null | undefined,
  now: number,
): boolean {
  if (retry === null || retry === undefined || retry.failedAt === null) return false;
  return now - retry.failedAt < recallRetryWaitMs(retry.failures);
}

/** The reads a step makes, each inside the person's connection lease. */
export interface StepReads {
  /** The folders the build covers: INBOX first, then the archive folder. */
  folders(gate: SessionGate, principal: Principal): Promise<string[]>;
  /** One folder's status check. */
  snapshot(
    gate: SessionGate,
    principal: Principal,
    mailbox: string,
  ): Promise<FolderSnapshotOutcome>;
  /** One page of the new mail in `[fromUid, toUidExclusive)`, oldest first. */
  newMail(
    gate: SessionGate,
    principal: Principal,
    mailbox: string,
    uidValidity: number,
    fromUid: number,
    toUidExclusive: number,
  ): Promise<NewMailPage>;
}

/** What a step needs: the build engine's deps, the reads, and a clock. */
export type StepDeps = BuildDeps & {
  readonly reads: StepReads;
  now(): number;
};

/**
 * What one step came to.
 *
 * `folders`: the folder list was stored. `seeded`: a folder's status check was
 * stored. `gone`: the status check said the folder no longer exists, and it was
 * dropped. `unanswered`: the status check gave no answer; nothing was stored.
 * `idle`: every folder is built and none is due a status check. `checked`: a
 * built folder's status check found nothing to do. `due`: it found new mail or
 * a deletion sync to do, and recorded it for the next step. Or any build
 * status, which carries `lease_busy` and every page refusal.
 */
export type StepOutcome =
  | "folders"
  | "seeded"
  | "gone"
  | "unanswered"
  | "idle"
  | "checked"
  | "due"
  | BuildStatus;

/** The row a folder starts from, and goes back to on a validity reset. */
const SEED_ROW: SyncRow = {
  stage: "seed",
  state: null,
  checkedAt: null,
  reconciledAt: null,
  due: null,
  seen: null,
  failedAt: null,
  failures: 0,
};

/** No failure recorded: what a success writes. */
const NO_FAILURE = { failedAt: null, failures: 0 } as const;

/**
 * `row` after one more failed attempt at `now` (26-REVIEW CR-01).
 *
 * A built folder has what was due cleared and its check time stamped, so the
 * next attempt is a fresh status check. A build folder goes back to seed after
 * RECALL_RESEED_AFTER_FAILURES failures in a row, keeping its count and its
 * cursor. A seed folder stays at seed.
 */
function failedRow(row: SyncRow, now: number): SyncRow {
  const failures = Math.min(row.failures + 1, MAX_COUNTED_FAILURES);
  const mark = { failedAt: now, failures };
  if (row.stage === "built") return { ...row, checkedAt: now, due: null, seen: null, ...mark };
  if (row.stage === "build" && failures >= RECALL_RESEED_AFTER_FAILURES) {
    return { ...SEED_ROW, ...mark };
  }
  return { ...row, ...mark };
}

/** Record one failed attempt on `mailbox`. Never throws: a failed write leaves the row as it was. */
async function noteFailure(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<void> {
  try {
    await agentFor(principal).recallSetSync(mailbox, failedRow(row, deps.now()));
  } catch {
    // The next step finds the row as it was and tries again. Not read.
  }
}

/**
 * Run one attempt on `mailbox`. A throw records the failure on the folder's
 * row, and becomes `RecallBuildError`. The caught value is not read.
 */
async function attempt(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
  work: () => Promise<StepOutcome>,
): Promise<StepOutcome> {
  try {
    return await work();
  } catch {
    await noteFailure(principal, mailbox, row, deps);
    throw new RecallBuildError();
  }
}

/** A status check that gave no answer: recorded as a failure, answered `unanswered`. */
async function unanswered(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<StepOutcome> {
  await noteFailure(principal, mailbox, row, deps);
  return "unanswered";
}

/**
 * The folders a listing gives the build (D-12): INBOX, then the folder the
 * account marks as its archive, when exactly one is. Never Drafts, Sent, Junk
 * or Trash.
 *
 * The archive folder is found the way the archive tool finds it, so the index
 * covers exactly the folder that tool moves mail into. Two candidates is no
 * archive folder: the build does not guess.
 */
export function recallFoldersOf(listing: FolderListing): string[] {
  const found = resolveRoleFolder(listing, "archive");
  if (!("folder" in found)) return [DEFAULT_MAILBOX];
  const archive = found.folder.wireName;
  return archive === DEFAULT_MAILBOX ? [DEFAULT_MAILBOX] : [DEFAULT_MAILBOX, archive];
}

/** The production deps, over the real bindings and the request's lease runner. */
export function productionStepDeps(leased: LeasedMail): StepDeps {
  return {
    ...recallDeps(),
    leased,
    source: mailRecallSource,
    reads: {
      async folders(gate, principal) {
        return recallFoldersOf(await listFolders(principal, gate));
      },
      async snapshot(gate, principal, mailbox) {
        const [outcome] = await folderSnapshots(principal, gate, [mailbox]);
        return outcome ?? { mailbox, answered: false };
      },
      newMail: newMailPage,
    },
    now: () => Date.now(),
  };
}

/** The busy marker `underLease` answers with. */
const LEASE_BUSY = Symbol("lease-busy");

/** Run `fn` under the person's lease, or answer LEASE_BUSY when it is held. */
async function underLease<T>(
  principal: Principal,
  deps: StepDeps,
  fn: (gate: SessionGate) => Promise<T>,
): Promise<T | typeof LEASE_BUSY> {
  try {
    return await deps.leased.withConnectionLease(principal, fn);
  } catch (error) {
    if (error instanceof ConnectionBusyError) return LEASE_BUSY;
    throw error;
  }
}

/** A setter's answer as a step outcome: nothing on success, else a stop. */
function afterSet(
  answer: { ok: true } | { ok: false; reason: string },
): "destroying" | null {
  if (answer.ok) return null;
  if (answer.reason === "destroying") return "destroying";
  throw new RecallBuildError();
}

/** A status check's answer as the folder's state, or null when it is not one. */
function folderStateOf(mailbox: string, outcome: FolderSnapshotOutcome): FolderState | null {
  if (!outcome.answered) return null;
  const { uidValidity, uidNext, highestModseq } = outcome.snapshot;
  if (uidValidity === null || uidNext === null) return null;
  return { mailbox, uidValidity, uidNext, highestModseq };
}

/**
 * Move `principal`'s recall build forward by at most one IMAP session.
 *
 * Reads the object's slot first and stops on any refusal. Otherwise lists the
 * folders, does what a built folder's last check left due, checks a built
 * folder, or seeds or indexes one page of a folder not built yet, in that
 * order of need, and answers what it did.
 */
export async function recallStep(principal: Principal, deps: StepDeps): Promise<StepOutcome> {
  const stub = agentFor(principal);

  // 1. The slot, before anything else (D-29).
  const state = await stub.recallSyncState();
  if (state.slot !== "free") return state.slot;
  const now = deps.now();

  // 2. No folder list yet: list them, store them, stop. A listing that failed
  //    is left alone until its wait has passed (CR-01).
  if (state.folders === null) {
    if (waiting(state.listing, now)) return "idle";
    try {
      const folders = await underLease(principal, deps, (gate) =>
        deps.reads.folders(gate, principal),
      );
      if (folders === LEASE_BUSY) return "lease_busy";
      return afterSet(await stub.recallSetFolders(folders)) ?? "folders";
    } catch {
      try {
        await stub.recallListingFailed(deps.now());
      } catch {
        // The next step lists again. Not read.
      }
      throw new RecallBuildError();
    }
  }

  const folders = state.folders;
  // A folder name is the account's own, so it is only ever an own key (WR-06).
  const rowOf = (mailbox: string): SyncRow | undefined => syncRowIn(state.sync, mailbox);

  // 3. A built folder whose last status check left something due goes first.
  const dueFolder = folders.find((one) => {
    const row = rowOf(one);
    return row !== undefined && row.stage === "built" && row.due !== null;
  });
  if (dueFolder !== undefined) {
    const row = rowOf(dueFolder)!;
    return attempt(principal, dueFolder, row, deps, () =>
      row.due === "new_mail"
        ? indexNewMail(principal, dueFolder, row, deps)
        : syncDeletions(principal, dueFolder, row, deps),
    );
  }

  // 4. A built folder whose status check is due: the one checked longest ago,
  //    never-checked first, once its last check is RECALL_CHECK_INTERVAL_MS
  //    old. This comes before the build of another folder (WR-04). A folder
  //    waiting out a failure is not a candidate.
  let oldest: string | null = null;
  let oldestRow: SyncRow | null = null;
  for (const one of folders) {
    const row = rowOf(one);
    if (row === undefined || row.stage !== "built" || waiting(row, now)) continue;
    if (oldestRow === null) {
      oldest = one;
      oldestRow = row;
      continue;
    }
    const best = oldestRow.checkedAt;
    if (best !== null && (row.checkedAt === null || row.checkedAt < best)) {
      oldest = one;
      oldestRow = row;
    }
  }
  if (
    oldest !== null &&
    oldestRow !== null &&
    (oldestRow.checkedAt === null || now - oldestRow.checkedAt >= RECALL_CHECK_INTERVAL_MS)
  ) {
    const checked = oldest;
    const checkedRow = oldestRow;
    return attempt(principal, checked, checkedRow, deps, () =>
      checkBuilt(principal, folders, checked, checkedRow, deps),
    );
  }

  // 5. The first listed folder not built, and not waiting out a failure. A
  //    folder with no row is at seed.
  const unbuilt = folders.find((one) => {
    const row = rowOf(one) ?? SEED_ROW;
    return row.stage !== "built" && !waiting(row, now);
  });
  if (unbuilt !== undefined) {
    const row = rowOf(unbuilt) ?? SEED_ROW;
    return attempt(principal, unbuilt, row, deps, () =>
      advanceUnbuilt(principal, folders, unbuilt, row, deps),
    );
  }

  // Nothing is due, no check is due, and nothing is left to build.
  return "idle";
}

/**
 * One step of a folder that is not built yet: its status check at seed, or one
 * page through Phase 25's engine at build.
 */
async function advanceUnbuilt(
  principal: Principal,
  folders: readonly string[],
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<StepOutcome> {
  const stub = agentFor(principal);

  // Seed: the status check alone. The first page is the next step.
  if (row.stage === "seed") {
    const outcome = await underLease(principal, deps, (gate) =>
      deps.reads.snapshot(gate, principal, mailbox),
    );
    if (outcome === LEASE_BUSY) return "lease_busy";
    const gone = await dropIfGone(principal, folders, mailbox, row, outcome, deps);
    if (gone !== null) return gone;

    const folderState = folderStateOf(mailbox, outcome);
    if (folderState === null) return unanswered(principal, mailbox, row, deps);
    // A status check that worked keeps the failure count (see the header).
    const seeded: SyncRow = {
      stage: "build",
      state: folderState,
      checkedAt: deps.now(),
      reconciledAt: null,
      due: null,
      seen: null,
      failedAt: row.failedAt,
      failures: row.failures,
    };
    return afterSet(await stub.recallSetSync(mailbox, seeded)) ?? "seeded";
  }

  // Build: one page through Phase 25's engine.
  const status = await indexNextPage(principal, mailbox, deps);
  if (status === "done") {
    const built: SyncRow = { ...row, stage: "built", ...NO_FAILURE };
    return afterSet(await stub.recallSetSync(mailbox, built)) ?? status;
  }
  if (status === "reset") {
    return afterSet(await stub.recallSetSync(mailbox, SEED_ROW)) ?? status;
  }
  if (status === "indexed" && row.failures > 0) {
    return afterSet(await stub.recallSetSync(mailbox, { ...row, ...NO_FAILURE })) ?? status;
  }
  return status;
}

/**
 * Drop `mailbox` from the folder list when the status check says it is gone,
 * and answer `gone`. INBOX is never dropped: it answers `unanswered`, recorded
 * as a failure like any check with no answer. Answers null when the check did
 * not say gone.
 *
 * Its vectors go first (26-REVIEW CR-03): a dropped folder gets no further
 * sync, so anything it left in the index would stay recallable until it
 * expired. They are removed under the page slot, as a reconcile, before the
 * list is changed. A refusal of that slot answers the refusal and drops
 * nothing, so the next status check tries again. Storing the shorter list also
 * clears the folder's sync row and build cursor.
 */
async function dropIfGone(
  principal: Principal,
  folders: readonly string[],
  mailbox: string,
  row: SyncRow,
  outcome: FolderSnapshotOutcome,
  deps: StepDeps,
): Promise<StepOutcome | null> {
  if (outcome.answered || outcome.gone !== true) return null;
  if (mailbox === DEFAULT_MAILBOX) return unanswered(principal, mailbox, row, deps);
  const removed = await forgetMailbox(principal, mailbox, deps);
  if (removed !== "removed") return removed;
  const kept = folders.filter((one) => one !== mailbox);
  return afterSet(await agentFor(principal).recallSetFolders(kept)) ?? "gone";
}

/** Whether two mod-sequences are the same, compared as the digit strings they are. */
function sameModseq(a: string | null, b: string | null): boolean {
  return a !== null && b !== null && a === b;
}

/**
 * A built folder's status check (D-14, D-27): Phase 23's check for this one
 * folder, in a session that opens no mailbox, compared with the stored state.
 *
 * Records what is due, and what the check saw, for the next step to do. Never
 * reads a message here. With nothing to do, records the check time. A check
 * with no answer is recorded as a failure (CR-01), so the check time moves and
 * the folder cannot stay the oldest for ever.
 */
async function checkBuilt(
  principal: Principal,
  folders: readonly string[],
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<StepOutcome> {
  const outcome = await underLease(principal, deps, (gate) =>
    deps.reads.snapshot(gate, principal, mailbox),
  );
  if (outcome === LEASE_BUSY) return "lease_busy";
  const gone = await dropIfGone(principal, folders, mailbox, row, outcome, deps);
  if (gone !== null) return gone;

  const seen = folderStateOf(mailbox, outcome);
  if (seen === null) return unanswered(principal, mailbox, row, deps);

  const now = deps.now();
  const stored = row.state;
  const stub = agentFor(principal);
  const record = async (due: SyncRow["due"]): Promise<StepOutcome> => {
    const next: SyncRow =
      due === null ? { ...row, checkedAt: now } : { ...row, checkedAt: now, due, seen };
    return afterSet(await stub.recallSetSync(mailbox, next)) ?? (due === null ? "checked" : "due");
  };

  // No stored state to compare with reads as a changed validity: the deletion
  // sync then sends the folder back to seed.
  if (stored === null || seen.uidValidity !== stored.uidValidity) return record("reconcile");
  if (seen.uidNext > stored.uidNext) return record("new_mail");
  const moved = !sameModseq(seen.highestModseq, stored.highestModseq);
  const lastSync = row.reconciledAt;
  if (moved && (lastSync === null || now - lastSync >= RECALL_RECONCILE_INTERVAL_MS)) {
    return record("reconcile");
  }
  return record(null);
}

const KEEP: CursorUpdate = { kind: "keep" };

/** Whether `reason` is one of the object's page refusals. */
function isPageRefusal(reason: unknown): reason is PageRefusal {
  return (PAGE_REFUSALS as readonly unknown[]).includes(reason);
}

/** Whether `page` is a new-mail page for the range `[from, to)` that moved forward. */
function isNewMailPage(page: unknown, from: number, to: number): page is NewMailPage {
  if (typeof page !== "object" || page === null) return false;
  const p = page as { items?: unknown; nextFrom?: unknown };
  if (!Array.isArray(p.items) || p.items.length > RECALL_PAGE_SIZE) return false;
  const next = p.nextFrom;
  return typeof next === "number" && Number.isSafeInteger(next) && next > from && next <= to;
}

/**
 * One page of a built folder's new mail (D-16, D-30).
 *
 * Takes the object's page slot as a build page first, so the page is paced,
 * counted toward the daily cap and refused at the vector ceiling exactly like
 * a build page. Then reads up to 25 of the OLDEST new messages, in the range
 * from the stored next UID to the seen next UID minus one, under the lease,
 * and indexes them. Only after the slot has ended is the stored next UID moved,
 * to exactly past what was read. A failure part-way leaves it where it was.
 * The step then records the failure and clears what was due (CR-01), so the
 * next attempt, once the wait has passed, is a fresh status check: it finds the
 * same new mail again when nothing else changed, and a new validity or a folder
 * that is gone when something did.
 */
export async function indexNewMail(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<StepOutcome> {
  const stub = agentFor(principal);
  const stored = row.state;
  const seen = row.seen;
  // A due row always carries both. One that does not has its due cleared, and
  // the next status check works it out again.
  if (stored === null || seen === null) {
    const cleared: SyncRow = { ...row, due: null, seen: null };
    return afterSet(await stub.recallSetSync(mailbox, cleared)) ?? "checked";
  }
  if (seen.uidValidity !== stored.uidValidity || seen.uidNext <= stored.uidNext) {
    const redo: SyncRow = { ...row, due: "reconcile" };
    return afterSet(await stub.recallSetSync(mailbox, redo)) ?? "due";
  }

  let begun: Awaited<ReturnType<typeof stub.recallBeginPage>>;
  try {
    begun = await stub.recallBeginPage(mailbox, "build");
  } catch {
    throw new RecallBuildError();
  }
  if (!begun.ok) {
    if (isPageRefusal(begun.reason)) return begun.reason;
    throw new RecallBuildError();
  }
  const { pageToken } = begun;
  const end = async (): Promise<void> => {
    try {
      await stub.recallEndPage(pageToken, mailbox, KEEP);
    } catch {
      // The token expires on its own.
    }
  };

  let nextFrom: number;
  try {
    const page = await underLease(principal, deps, (gate) =>
      deps.reads.newMail(gate, principal, mailbox, stored.uidValidity, stored.uidNext, seen.uidNext),
    );
    if (page === LEASE_BUSY) {
      await end();
      return "lease_busy";
    }
    if (!isNewMailPage(page, stored.uidNext, seen.uidNext)) throw new RecallBuildError();

    try {
      await indexItems(principal, page.items, deps);
    } catch (error) {
      if (error instanceof RecallRefusedError && isPageRefusal(error.reason)) {
        await end();
        return error.reason;
      }
      throw error;
    }
    nextFrom = page.nextFrom;
  } catch {
    await end();
    throw new RecallBuildError();
  }
  await end();

  const reached = nextFrom >= seen.uidNext;
  const moved: SyncRow = {
    ...row,
    state: { ...stored, uidNext: nextFrom },
    due: reached ? null : "new_mail",
    seen: reached ? null : seen,
    ...NO_FAILURE,
  };
  return afterSet(await stub.recallSetSync(mailbox, moved)) ?? "indexed";
}

/**
 * A built folder's deletion sync (D-17b, c): Phase 25's reconcile over the
 * window's UIDs, which takes the slot as a reconcile, so it counts and is
 * never refused as full.
 *
 * When the status check saw a new validity, the old generation is removed, the
 * folder goes back to seed and its build cursor is reset, whether or not the
 * ledger held any old rows (26-REVIEW CR-02). Otherwise the stored mod-sequence becomes the
 * one the check saw, and the sync time is recorded. A refusal leaves the sync
 * due for the next step. A failure is recorded by the step, which clears what
 * was due (CR-01).
 */
async function syncDeletions(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<StepOutcome> {
  const stub = agentFor(principal);
  const stored = row.state;
  const seen = row.seen;
  const reset = stored === null || (seen !== null && seen.uidValidity !== stored.uidValidity);
  // On a reset the cursor goes with the slot's end, in the same object call,
  // so the folder is never back at seed with the old build's cursor still set.
  const status = await reconcileMailbox(principal, mailbox, deps, { resetCursor: reset });

  if (reset) {
    if (status === "indexed") {
      return afterSet(await stub.recallSetSync(mailbox, SEED_ROW)) ?? status;
    }
    return status;
  }
  if (status !== "indexed") return status;

  const now = deps.now();
  const synced: SyncRow = {
    ...row,
    state: seen === null ? stored : { ...stored, highestModseq: seen.highestModseq },
    checkedAt: now,
    reconciledAt: now,
    due: null,
    seen: null,
    ...NO_FAILURE,
  };
  return afterSet(await stub.recallSetSync(mailbox, synced)) ?? status;
}
