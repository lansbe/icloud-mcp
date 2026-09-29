// One recall build step: at most one IMAP session of work (Phase 26, D-12 to
// D-14 as revised by D-27, D-29).
//
// WHEN IT RUNS. The build runs on the person's own mail calls (CONTEXT D-01 as
// re-decided, D-26): after a mail tool answers, one step moves that person's
// index forward. Plan 26-07's driver calls this; nothing else does, and the
// object never imports this module.
//
// THE SLOT FIRST (D-29). A step reads the person's object before anything
// else. When the object says a page may not start now (destroying, busy,
// paused or quota), or that it does not know whose it is (unnamed, so it
// would refuse every write, 26-REVIEW-2 IN-02), the step answers that word
// and stops: no lease, no session, no write.
//
// AT THE VECTOR CEILING ONLY ADDING STOPS (26-REVIEW-2 WR-04). `full` is not
// one of those stops. At the ceiling the step still lists folders, runs status
// checks, runs deletion syncs and removes a folder that is gone, because those
// are what shrink the index; stopping them would keep it at the ceiling, and
// keep deleted mail recallable. Only what adds vectors waits: a due new-mail
// page is passed over, and a build page is refused as `full` by the object
// before any lease is taken.
//
// ONE LEASE PER STEP (D-27). Otherwise the step does exactly one of these,
// each under the person's connection lease taken once, and holds the lease
// only for that. Each is one IMAP session, except that a build page can take
// up to three, one after another, in two rare cases (./drive.ts says which):
//
//   1. no folder list yet, or it is a day old, or a folder was just dropped as
//      gone: list the folders and store INBOX plus the account's archive
//      folder (D-12; 26-REVIEW-2 WR-02). An archive folder that was replaced
//      loses its vectors first. See `listFoldersStep`;
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
// There is no loop over pages in the step, no second read after the first, no
// sleep, no retry and no combinator. Nothing sweeps every folder. The pace is
// the object's: a step that comes too early is told `paused` and stops. Recall
// is inherent (owner, 2026-09-27), so there is no off state to check.
//
// THE BACKFILL IS THE ONE LOOP OVER PAGES (Phase 29.1.1). `recallBackfill`, at
// the bottom of this module, fills a person's index faster while they watch.
// It is driven only by the backfill tool the person calls, through its runner
// in ./drive.ts, never by the seam that drives steps and never by the object's
// alarm. What it does, and what it does not:
//   - one serial loop, bounded by RECALL_BACKFILL_MAX_PAGES pages,
//     RECALL_BACKFILL_MAX_STEPS sessions and RECALL_BACKFILL_BUDGET_MS of time;
//   - one lease per session, taken and given back before the next one starts,
//     and a page slot per page from the object, asked for as a backfill page;
//   - only folders whose first build is not finished: the listing when there is
//     no folder list yet, a seed, and build pages. It never runs a status check
//     on a built folder, a new-mail page or a deletion sync. Those remain the
//     step's upkeep;
//   - the object skips the one-minute pause and the ordinary day count for a
//     backfill page, and nothing else. It still refuses as destroying, busy,
//     quota (on its own day counter) and full, and it grants the page only for
//     a folder at build;
//   - it stops at the first failure, recorded exactly as a step records it, and
//     does not try a folder that is waiting out a failure or is parked.
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
//   - build: after every RECALL_RESEED_AFTER_FAILURES failures in a row the
//     folder goes back to seed, so its status check can find it gone. Its
//     cursor is kept: nothing says the validity changed, and the engine resets
//     the cursor itself when it did.
//   - seed: the row stays at seed.
// A failed folder listing is recorded on the object the same way, and waited
// out the same way. Success clears the count: a page, a new-mail page or a
// deletion sync that worked. A status check that worked keeps the count, at
// seed too, so a folder whose reads keep failing waits longer each time and
// does not start over at five minutes (26-REVIEW-2 WR-03). A seed check that
// works proves nothing about reading the folder's mail; clearing the count
// there would let a folder whose pages always fail go round build, fail,
// reseed, seed for ever. That is why the reseed comes every three failures,
// counted from the last one, and not whenever the count is three or more.
//
// A FOLDER THAT ALWAYS FAILS IS PARKED (26-REVIEW-2 WR-03). After
// RECALL_PARK_AFTER_FAILURES failures in a row, the step leaves the folder
// alone until the folders are next listed (at most a day), and the recall
// answer stops counting it as still being built. The next listing gives it one
// more try at once, without the retry wait; a failure then parks it again.
// `isParked` in ../agent/recall-ledger.ts is the one predicate, shared with
// the recall answer. A parked folder keeps its vectors: nothing says its mail
// is gone, and a gone folder is found by its status check, as before.
//
// A FAILURE THAT CANNOT BE RECORDED STILL HOLDS THE NEXT STEP OFF (26-REVIEW-2
// IN-02). When the object refuses the failure write, or the call to it fails,
// the step takes the page slot and ends it at once, as a removal that removes
// nothing. The object's pause then stops every step for a minute, at the slot,
// before any session, and the day's page cap counts it. So the worst case is
// one attempt a minute and RECALL_MAX_PAGES_PER_DAY a day, never one on every
// mail call. If even that call fails, the object is out of reach, and the next
// step's first call to it fails too, before any session.
//
// The failure itself still propagates, as `RecallBuildError`. No caught value
// is read (./.claude/CLAUDE.md §4), and nothing here logs.

import { agentFor, type LeasedMail } from "../agent/lease";
import {
  isParked,
  MAX_COUNTED_FAILURES,
  MAX_RECALL_FOLDERS,
  PAGE_REFUSALS,
  RECALL_PARK_AFTER_FAILURES,
  type PageKind,
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
  RecallSlotInvalidError,
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
 * How old the stored folder list may get before the step lists the folders
 * again: a day (26-REVIEW-2 WR-02). So an archive folder the account renames,
 * or replaces with another, is found within a day, at the cost of one session
 * a day per person.
 */
export const RECALL_RELIST_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * How many failed build pages in a row send a folder back to seed, so its
 * status check can find out whether it is gone (26-REVIEW CR-01). It happens
 * at every multiple of this, counted from the last success (26-REVIEW-2
 * WR-03).
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

/**
 * Whether something that failed at `failedAt`, `failures` times in a row, is
 * still waiting at `now`. Exported so the backfill's progress answer names a
 * folder as waiting with the loop's own logic (Phase 29.1.1).
 */
export function waiting(
  retry: { readonly failedAt: number | null; readonly failures: number } | null | undefined,
  now: number,
): boolean {
  if (retry === null || retry === undefined || retry.failedAt === null) return false;
  return now - retry.failedAt < recallRetryWaitMs(retry.failures);
}

/**
 * Whether a folder may be tried now: not while it waits out a failure (CR-01),
 * and not while it is parked (WR-03). A folder un-parked by a listing since its
 * last failure is tried at once, without the wait. `listedAt` is when the
 * folder list was listed. The step and the backfill both ask this, and the
 * backfill's progress answer asks it too, so the answer and the loop never
 * disagree (Phase 29.1.1).
 */
export function readyNow(
  row: { readonly failures: number; readonly failedAt: number | null },
  listedAt: number | null,
  now: number,
): boolean {
  return row.failures >= RECALL_PARK_AFTER_FAILURES ? !isParked(row, listedAt) : !waiting(row, now);
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
 * `idle`: every folder is built and none is due a status check. `unnamed`:
 * the object does not know whose it is, so nothing was opened. `checked`: a
 * built folder's status check found nothing to do. `due`: it found new mail or
 * a deletion sync to do, and recorded it for the next step. `moved`: a
 * backfill page found its folder no longer at build, because another request
 * moved the row; only the backfill loop answers it (29.1.1-REVIEW WR-02). Or
 * any build status, which carries `lease_busy` and every page refusal.
 */
export type StepOutcome =
  | "unnamed"
  | "moved"
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
 * next attempt is a fresh status check. A build folder goes back to seed at
 * every RECALL_RESEED_AFTER_FAILURES-th failure in a row, keeping its count
 * and its cursor, so a seed that worked in between does not make the next
 * single failure reseed at once (26-REVIEW-2 WR-03). A seed folder stays at
 * seed.
 */
function failedRow(row: SyncRow, now: number): SyncRow {
  const failures = Math.min(row.failures + 1, MAX_COUNTED_FAILURES);
  const mark = { failedAt: now, failures };
  if (row.stage === "built") return { ...row, checkedAt: now, due: null, seen: null, ...mark };
  if (row.stage === "build" && failures % RECALL_RESEED_AFTER_FAILURES === 0) {
    return { ...SEED_ROW, ...mark };
  }
  return { ...row, ...mark };
}

/**
 * Hold the next step off for the object's page pause, because a failure could
 * not be recorded (26-REVIEW-2 IN-02): take the page slot as a removal and end
 * it at once, changing nothing else. A refusal means a pause or a stop is
 * already in force. Never throws.
 */
async function holdOff(principal: Principal, mailbox: string): Promise<void> {
  const stub = agentFor(principal);
  try {
    const begun = await stub.recallBeginPage(mailbox, "reconcile");
    if (begun.ok) await stub.recallEndPage(begun.pageToken, mailbox, KEEP);
  } catch {
    // The object is out of reach: the next step's first call to it fails too,
    // before any session. Not read.
  }
}

/**
 * Record one failed attempt on `mailbox`. Never throws. A write the object
 * refuses, or a call that fails, holds the next step off instead (IN-02).
 */
async function noteFailure(
  principal: Principal,
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
): Promise<void> {
  let recorded = false;
  try {
    recorded = (await agentFor(principal).recallSetSync(mailbox, failedRow(row, deps.now()))).ok;
  } catch {
    // Not read.
  }
  if (!recorded) await holdOff(principal, mailbox);
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

  // 1. The slot, before anything else (D-29). `full` is not a stop: at the
  //    ceiling only what adds vectors waits (WR-04).
  const state = await stub.recallSyncState();
  if (state.slot !== "free") return state.slot;
  const full = state.full;
  const now = deps.now();

  // 2. No folder list yet, or it is due to be listed again (WR-02): list them,
  //    store them, stop. A listing that failed is left alone until its wait
  //    has passed (CR-01); meanwhile a stored list is worked on as it is.
  const relistDue =
    state.folders === null ||
    state.listedAt === null ||
    now - state.listedAt >= RECALL_RELIST_INTERVAL_MS;
  if (relistDue && !waiting(state.listing, now)) {
    return listFoldersStep(principal, state.folders, deps);
  }
  if (state.folders === null) return "idle";

  const folders = state.folders;
  // A folder name is the account's own, so it is only ever an own key (WR-06).
  const rowOf = (mailbox: string): SyncRow | undefined => syncRowIn(state.sync, mailbox);
  // Whether a folder may be tried now: not while it waits out a failure
  // (CR-01), and not while it is parked (WR-03). A folder un-parked by a
  // listing since its last failure is tried at once, without the wait.
  const ready = (row: SyncRow): boolean => readyNow(row, state.listedAt, now);

  // 3. A built folder whose last status check left something due goes first.
  //    At the vector ceiling a new-mail page would add vectors, so it waits;
  //    a deletion sync does not (WR-04).
  const dueFolder = folders.find((one) => {
    const row = rowOf(one);
    if (row === undefined || row.stage !== "built" || row.due === null) return false;
    return !(full && row.due === "new_mail");
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
  //    waiting out a failure, or parked, is not a candidate.
  let oldest: string | null = null;
  let oldestRow: SyncRow | null = null;
  for (const one of folders) {
    const row = rowOf(one);
    if (row === undefined || row.stage !== "built" || !ready(row)) continue;
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

  // 5. The first listed folder not built, and not waiting out a failure or
  //    parked. A folder with no row is at seed.
  const unbuilt = folders.find((one) => {
    const row = rowOf(one) ?? SEED_ROW;
    return row.stage !== "built" && ready(row);
  });
  if (unbuilt !== undefined) {
    const row = rowOf(unbuilt) ?? SEED_ROW;
    return attempt(principal, unbuilt, row, deps, () =>
      advanceUnbuilt(principal, folders, unbuilt, row, deps),
    );
  }

  // Nothing is due, no check is due, and nothing is left to build. At the
  // ceiling, say so: new mail may be waiting for room.
  return full ? "full" : "idle";
}

/**
 * The folder listing, as one step (D-12; 26-REVIEW-2 WR-02): list the folders
 * in one session, and store what the build should cover.
 *
 * `stored` is the list stored now, or null before the first listing. The new
 * list is what the listing gives, with two rules for the archive folder:
 *   - The listing names a different archive folder than the stored one (it was
 *     renamed, or the account marks another folder as its archive). The old
 *     one's vectors go first, under the page slot as a removal, the same way a
 *     folder dropped as gone loses them (CR-03). Then the new list is stored,
 *     and the old folder's sync row and cursor go with it. A refused slot
 *     stores nothing, so the next step lists again.
 *   - The listing names no archive folder, or two, while one is stored. The
 *     stored one is kept. A listing that names none is no evidence the folder
 *     changed, and dropping it would throw its index away. If the folder was
 *     deleted, its own status check finds it gone, and the drop then asks for
 *     another listing.
 *
 * The time stored is this step's, so the next listing is a day later. A
 * failure is recorded on the object, so the next listing waits (CR-01).
 */
async function listFoldersStep(
  principal: Principal,
  stored: readonly string[] | null,
  deps: StepDeps,
): Promise<StepOutcome> {
  const stub = agentFor(principal);
  try {
    const listed = await underLease(principal, deps, (gate) =>
      deps.reads.folders(gate, principal),
    );
    if (listed === LEASE_BUSY) return "lease_busy";
    const keepStored = stored !== null && stored.length > 1 && listed.length < 2;
    const next = keepStored ? stored : listed;
    // One replaced folder per step: each removal takes the page slot, and the
    // slot's pause refuses a second in the same step. Any other stays listed,
    // and the next step lists again for it.
    const replaced = (stored ?? []).filter((one) => !next.includes(one));
    if (replaced.length > 0) {
      const removed = await forgetMailbox(principal, replaced[0]!, deps);
      if (removed !== "removed") return removed;
    }
    const pending = replaced.slice(1);
    const listedAt = pending.length > 0 ? null : deps.now();
    return afterSet(await stub.recallSetFolders([...next, ...pending], listedAt)) ?? "folders";
  } catch {
    let recorded = false;
    try {
      recorded = (await stub.recallListingFailed(deps.now())).ok;
    } catch {
      // Not read.
    }
    // Not recorded: the page pause holds the next listing off instead (IN-02).
    if (!recorded) await holdOff(principal, DEFAULT_MAILBOX);
    throw new RecallBuildError();
  }
}

/**
 * One step of a folder that is not built yet: its status check at seed, or one
 * page through Phase 25's engine at build.
 *
 * `kind` is the page kind a build page asks the object for: a build page
 * unless the caller says otherwise. Only the backfill loop passes one.
 */
async function advanceUnbuilt(
  principal: Principal,
  folders: readonly string[],
  mailbox: string,
  row: SyncRow,
  deps: StepDeps,
  kind: Exclude<PageKind, "reconcile"> = "build",
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
  const status = await indexNextPage(principal, mailbox, deps, kind);
  if (status === "done") {
    const built: SyncRow = { ...row, stage: "built", ...NO_FAILURE };
    return afterSet(await stub.recallSetSync(mailbox, built)) ?? status;
  }
  if (status === "reset") {
    // The cursor goes in the same write as the row (26-REVIEW-2 WR-01).
    return afterSet(await stub.recallSetSync(mailbox, SEED_ROW, "reset")) ?? status;
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
 *
 * The shorter list is stored with no listing time, so the next step lists the
 * folders again (26-REVIEW-2 WR-02). A folder that was deleted and recreated,
 * or replaced by another the account marks as its archive, is then found and
 * built, instead of being left out of recall for as long as the grant lives.
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
  return afterSet(await agentFor(principal).recallSetFolders(kept, null)) ?? "gone";
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
  // A deletion sync that is owed goes before new mail (26-REVIEW-2 WR-05).
  // New mail also moves the mod-sequence, so a folder that gets mail before
  // every check would otherwise always be due new mail and never a sync, and
  // mail deleted from it would stay recallable. The new mail is not lost: the
  // sync hands it on as the next thing due.
  const moved = !sameModseq(seen.highestModseq, stored.highestModseq);
  const lastSync = row.reconciledAt;
  if (moved && (lastSync === null || now - lastSync >= RECALL_RECONCILE_INTERVAL_MS)) {
    return record("reconcile");
  }
  if (seen.uidNext > stored.uidNext) return record("new_mail");
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
 *
 * The reset does not rest on the page slot's end (26-REVIEW-2 WR-01). That end
 * changes nothing once the slot's token has expired, for example when the
 * reconcile ran past the slot's lifetime and another page took it, and its
 * answer is not read. So the row goes back to seed and the cursor is forgotten
 * in one object write, and that write's answer is checked. The folder can
 * never be at seed with the old build's finished cursor still set.
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
  const status = await reconcileMailbox(principal, mailbox, deps, { resetCursor: reset });

  if (reset) {
    if (status === "indexed") {
      return afterSet(await stub.recallSetSync(mailbox, SEED_ROW, "reset")) ?? status;
    }
    return status;
  }
  if (status !== "indexed") return status;

  // New mail the check also saw is due next (WR-05): the sync went first only
  // because it was owed.
  const newMail = stored !== null && seen !== null && seen.uidNext > stored.uidNext;
  const now = deps.now();
  const synced: SyncRow = {
    ...row,
    state: seen === null ? stored : { ...stored, highestModseq: seen.highestModseq },
    checkedAt: now,
    reconciledAt: now,
    due: newMail ? "new_mail" : null,
    seen: newMail ? seen : null,
    ...NO_FAILURE,
  };
  return afterSet(await stub.recallSetSync(mailbox, synced)) ?? status;
}

// ---------------------------------------------------------------------------
// The backfill (Phase 29.1.1)
// ---------------------------------------------------------------------------

/**
 * The most pages one backfill call indexes (LD-4): about 250 messages.
 *
 * Why 10:
 * - the owner asked for "up to about 10" pages a call;
 * - one call stays far under the platform's per-invocation limits. Measured in
 *   the pool on 2026-09-28 (test/recall-backfill-wire.test.ts), one 10-page call
 *   costs 10 sockets, 64 object calls, 10 model calls, 10 store calls and 1
 *   grant read: 95 in all, against a bound of 200, and against 1,000 internal
 *   calls and 10,000 subrequests on the paid plan;
 * - sessions are serial, one socket open at a time, so the six-connection
 *   budget is never approached;
 * - RECALL_BACKFILL_BUDGET_MS bounds wall-clock time whatever a real page
 *   costs.
 * CPU time and real per-page seconds cannot be measured in the pool. The
 * owner's first live run records both (plan 29.1.1-04).
 */
export const RECALL_BACKFILL_MAX_PAGES = 10;

/** The most time one backfill call spends starting new work, in ms (LD-7). */
export const RECALL_BACKFILL_BUDGET_MS = 20000;

/**
 * The most iCloud sessions one backfill call opens: one listing, one seed per
 * folder, and the pages. Each session is a sign-in. This is a hard bound: a
 * pass starts only while RECALL_PASS_MAX_SESSIONS more still fit under it
 * (29.1.1-REVIEW WR-03).
 */
export const RECALL_BACKFILL_MAX_STEPS = RECALL_BACKFILL_MAX_PAGES + MAX_RECALL_FOLDERS + 1;

/**
 * The most iCloud sessions one pass of the backfill can open. A build page
 * opens up to three, one after another under its one lease: the page read, the
 * read again from the top after a validity change, and the validity read for a
 * page with no rows (./mail-source.ts). A seed or a listing opens one.
 */
export const RECALL_PASS_MAX_SESSIONS = 3;

/**
 * Why a backfill call stopped.
 *
 * `built`: every listed folder is built or parked. `budget`: it reached its
 * page, session or time limit, and the next call goes on. `waiting`: the only
 * folders left are waiting out a failure. `lease_busy`: another request holds
 * the person's connection. `failed`: an attempt failed, and the failure is
 * recorded where a step records it. Or one of the object's refusals.
 */
export type BackfillStop =
  | "built"
  | "budget"
  | "waiting"
  | "busy"
  | "lease_busy"
  | "quota"
  | "full"
  | "destroying"
  | "unnamed"
  | "failed";

/** What one backfill call came to: why it stopped, and what it did. */
export interface BackfillOutcome {
  readonly stopped: BackfillStop;
  /** Pages indexed in this call. */
  readonly pages: number;
  /**
   * iCloud sessions this call opened, one after another, counted at the
   * session gate: a lease can hold up to three.
   */
  readonly sessions: number;
}

/** The limits of one backfill call. A test passes smaller ones. */
export interface BackfillLimits {
  readonly maxPages?: number;
  readonly maxSteps?: number;
  readonly budgetMs?: number;
}

/** A step outcome as the reason a backfill call stops. */
function backfillStopOf(outcome: StepOutcome): BackfillStop {
  switch (outcome) {
    case "lease_busy":
    case "busy":
    case "quota":
    case "full":
    case "destroying":
    case "unnamed":
      return outcome;
    // A backfill page is never paused. Should the object say so anyway, stop
    // as busy rather than try again.
    case "paused":
      return "busy";
    default:
      // Nothing else stops a backfill here; stop rather than loop.
      return "failed";
  }
}

/**
 * Index several pages of `principal`'s own index in one call, one leased
 * session at a time (Phase 29.1.1, LD-4 to LD-6, LD-10).
 *
 * Reads the object first, and stops on any refusal it gives a backfill page,
 * with nothing opened. With no folder list yet, lists the folders. Then, one
 * pass at a time: stops when it has reached its page, session or time limit;
 * re-reads the object, since rows change between passes; picks the first
 * listed folder that is not built and is ready (not waiting out a failure, not
 * parked); and seeds it or indexes one page of it, as a step would, under the
 * backfill page kind. It stops as `built` when every listed folder is built or
 * parked, so a call on a built index opens nothing and changes nothing.
 *
 * `sessions` counts every session opened on the gate the lease hands over, so
 * it is the number of iCloud sessions the call opened, failed ones included.
 * One lease can hold up to three (RECALL_PASS_MAX_SESSIONS), so a pass starts
 * only while that many more fit under the session limit, and the limit is never
 * passed. `pages` counts pages indexed. A page that found the folder's validity
 * changed is a session and not a page.
 *
 * Never throws for a failure on a folder or the listing: those are recorded
 * where a step records them, and the call stops as `failed`. A throw from the
 * first object read means the object is out of reach, and propagates. A later
 * object read that fails stops the call as `failed`, since pages may already
 * be indexed. No caught value is read, nothing here logs, and there is no
 * combinator, sleep or retry.
 */
export async function recallBackfill(
  principal: Principal,
  deps: StepDeps,
  limits: BackfillLimits = {},
): Promise<BackfillOutcome> {
  const maxPages = limits.maxPages ?? RECALL_BACKFILL_MAX_PAGES;
  const maxSteps = limits.maxSteps ?? RECALL_BACKFILL_MAX_STEPS;
  const budgetMs = limits.budgetMs ?? RECALL_BACKFILL_BUDGET_MS;
  const stub = agentFor(principal);
  const started = deps.now();
  let pages = 0;
  let sessions = 0;
  const stop = (stopped: BackfillStop): BackfillOutcome => ({ stopped, pages, sessions });

  // The same deps, except that each session opened on the lease's gate is
  // counted (WR-03). A session takes the gate once, after its socket opened.
  const counted: StepDeps = {
    ...deps,
    leased: {
      withConnectionLease: (who, fn) =>
        deps.leased.withConnectionLease(who, (gate) =>
          fn({
            acquire() {
              sessions += 1;
              gate.acquire();
            },
            release: () => gate.release(),
            get held() {
              return gate.held;
            },
          }),
        ),
    },
  };

  // 1. The object first. A refusal opens nothing.
  const first = await stub.recallSyncState();
  if (first.backfill !== "free") return stop(first.backfill);

  // 2. No folder list yet: list them, unless the listing is waiting out a
  //    failure. The listing's own code records a failure.
  if (first.folders === null) {
    if (waiting(first.listing, deps.now())) return stop("waiting");
    let listed: StepOutcome;
    try {
      listed = await listFoldersStep(principal, null, counted);
    } catch {
      return stop("failed");
    }
    if (listed !== "folders") return stop(backfillStopOf(listed));
  }

  // 3. One pass at a time, strictly one after another.
  for (;;) {
    if (
      pages >= maxPages ||
      sessions + RECALL_PASS_MAX_SESSIONS > maxSteps ||
      deps.now() - started >= budgetMs
    ) {
      return stop("budget");
    }
    // Only the first read may throw out of here (29.1.1-REVIEW WR-01): pages
    // may already be indexed, and the caller must not say nothing was.
    let state: Awaited<ReturnType<typeof stub.recallSyncState>>;
    try {
      state = await stub.recallSyncState();
    } catch {
      return stop("failed");
    }
    if (state.backfill !== "free") return stop(state.backfill);
    const folders = state.folders;
    if (folders === null) return stop("waiting");
    const now = deps.now();
    const rowOf = (mailbox: string): SyncRow | undefined => syncRowIn(state.sync, mailbox);

    const next = folders.find((one) => {
      const row = rowOf(one) ?? SEED_ROW;
      return row.stage !== "built" && readyNow(row, state.listedAt, now);
    });
    if (next === undefined) {
      const finished = folders.every((one) => {
        const row = rowOf(one);
        return row !== undefined && (row.stage === "built" || isParked(row, state.listedAt));
      });
      return stop(finished ? "built" : "waiting");
    }

    const row = rowOf(next) ?? SEED_ROW;
    let outcome: StepOutcome;
    try {
      outcome = await attempt(principal, next, row, counted, async () => {
        try {
          return await advanceUnbuilt(principal, folders, next, row, counted, "backfill");
        } catch (error) {
          // The row left build after it was read (WR-02): another request
          // moved it. Not a failure: read the rows again.
          if (error instanceof RecallSlotInvalidError) return "moved";
          throw error;
        }
      });
    } catch {
      return stop("failed");
    }
    if (outcome === "indexed" || outcome === "done") {
      pages += 1;
      continue;
    }
    if (outcome === "moved" || outcome === "seeded" || outcome === "gone" || outcome === "reset") {
      continue;
    }
    if (outcome === "unanswered") return stop("failed");
    return stop(backfillStopOf(outcome));
  }
}
