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
// There is no loop over pages, no second read after the first, no sleep, no
// retry and no combinator. The pace is the object's: a step that comes too
// early is told `paused` and stops. Recall is inherent (owner, 2026-09-27), so
// there is no off state to check.
//
// A lease refusal answers `lease_busy` and stores nothing. Every other failure
// propagates to the caller. No caught value is read (./.claude/CLAUDE.md §4),
// and nothing here logs.

import { agentFor, type LeasedMail } from "../agent/lease";
import type { SyncRow } from "../agent/recall-ledger";
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
import { type BuildDeps, type BuildStatus, indexNextPage, RecallBuildError } from "./build";
import { mailRecallSource } from "./mail-source";
import { recallDeps } from "./pipeline";

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
 * `idle`: every folder is built. Or any build status, which carries
 * `lease_busy` and every page refusal.
 */
export type StepOutcome = "folders" | "seeded" | "gone" | "unanswered" | "idle" | BuildStatus;

/** The row a folder starts from, and goes back to on a validity reset. */
const SEED_ROW: SyncRow = {
  stage: "seed",
  state: null,
  checkedAt: null,
  reconciledAt: null,
  due: null,
  seen: null,
};

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
 * folders, seeds one folder, or indexes one page of one folder, in that order
 * of need, and answers what it did.
 */
export async function recallStep(principal: Principal, deps: StepDeps): Promise<StepOutcome> {
  const stub = agentFor(principal);

  // 1. The slot, before anything else (D-29).
  const state = await stub.recallSyncState();
  if (state.slot !== "free") return state.slot;

  // 2. No folder list yet: list them, store them, stop.
  if (state.folders === null) {
    const folders = await underLease(principal, deps, (gate) =>
      deps.reads.folders(gate, principal),
    );
    if (folders === LEASE_BUSY) return "lease_busy";
    return afterSet(await stub.recallSetFolders(folders)) ?? "folders";
  }

  // 3. The first listed folder not built. A folder with no row is at seed.
  const mailbox = state.folders.find((one) => state.sync[one]?.stage !== "built");
  if (mailbox === undefined) return "idle";
  const row = state.sync[mailbox] ?? SEED_ROW;

  // 4. Seed: the status check alone. The first page is the next step.
  if (row.stage === "seed") {
    const outcome = await underLease(principal, deps, (gate) =>
      deps.reads.snapshot(gate, principal, mailbox),
    );
    if (outcome === LEASE_BUSY) return "lease_busy";

    if (!outcome.answered && outcome.gone === true) {
      if (mailbox === DEFAULT_MAILBOX) return "unanswered";
      const kept = state.folders.filter((one) => one !== mailbox);
      return afterSet(await stub.recallSetFolders(kept)) ?? "gone";
    }
    const folderState = folderStateOf(mailbox, outcome);
    if (folderState === null) return "unanswered";
    const seeded: SyncRow = {
      stage: "build",
      state: folderState,
      checkedAt: deps.now(),
      reconciledAt: null,
      due: null,
      seen: null,
    };
    return afterSet(await stub.recallSetSync(mailbox, seeded)) ?? "seeded";
  }

  // 5. Build: one page through Phase 25's engine.
  const status = await indexNextPage(principal, mailbox, deps);
  if (status === "done") {
    const built: SyncRow = { ...row, stage: "built" };
    return afterSet(await stub.recallSetSync(mailbox, built)) ?? status;
  }
  if (status === "reset") {
    return afterSet(await stub.recallSetSync(mailbox, SEED_ROW)) ?? status;
  }
  return status;
}
