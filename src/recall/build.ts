// The recall build engine: one page per call, and the sync-time clean-up
// (Phase 25, RCLL-04, RCLL-07, D-12, D-15, D-24).
//
// WHAT INDEXING COSTS PER PERSON. Recall is inherent (owner, 2026-09-27), so
// once Phase 26 drives this engine it runs for everyone who signs in, not only
// for people who ask for it. The pace is one page of at most 25 messages, at
// most one page a minute, one page in flight, per person. The person's
// connection lease is held for the mail read only. The person's object refuses
// a page once 200 pages began for that person in a UTC day
// (RECALL_MAX_PAGES_PER_DAY), and refuses a build page within one page of
// 10,000 vectors for that person (RECALL_MAX_VECTORS). From the live price
// pages, assuming at most 1,000 tokens per embedded message and 300 recall
// queries a month, before the account's included allowances: a typical person
// with 1,500 vectors costs about $0.02 once to embed and about $0.02 a month to
// hold and query; a person at the vector ceiling about $0.12 once and about
// $0.11 a month; and the daily page cap holds a runaway build to about $0.06 of
// embedding per person per day. The numbers live in src/recall/retention.ts,
// and the owner records them with the retention terms at plan 25-05.
//
// ONE PAGE PER CALL. `indexNextPage` asks the person's object for a page slot,
// reads one page through the injected source inside the connection lease,
// gives the lease back, then embeds, records and writes, and only then commits
// the cursor. There is no loop over pages, no queue, no sleep and no retry
// here. The pause is not a sleep: a call that comes back too early is simply
// told `paused` by the object. Scheduling the next call is the caller's job
// (Phase 26). The object owns the pause, the one-in-flight rule and both
// ceilings, so no caller can hurry a build.
//
// RESUME. The cursor is committed only after the store write succeeded. A
// failure part-way leaves the cursor where it was, so the next call reads the
// same page again, and because every write is an upsert, re-indexing it leaves
// the store with the same ids.
//
// THE SOURCE. `RecallSource` is injected. Phase 26 writes the real one over
// IMAP, and it must peek: reading mail for the index must never mark it read
// (./.claude/CLAUDE.md §5). The engine always calls the source inside the
// lease. This module holds no IMAP code and reaches no socket.
//
// DISAPPEARED MAIL. `reconcileMailbox` takes a mailbox's full UID list and
// validity, and removes every ledger id for that mailbox that should no longer
// exist: UIDs that are gone, and every id recorded under an older UIDVALIDITY.
// Store first, then ledger, batch by batch, so the ledger stays a superset of
// the store. `forgetRefs` removes named refs without finding them first.
//
// Serial only (./.claude/CLAUDE.md §3): nothing here runs two sessions, two
// pages or two deletes at once. A caught value is never read; failures become
// `RecallBuildError`. No logging (./.claude/CLAUDE.md §4).

import { agentFor, type LeasedMail } from "../agent/lease";
import { PAGE_REFUSALS, type PageRefusal } from "../agent/recall-ledger";
import type { CursorUpdate } from "../agent/user-agent";
import { ConnectionBusyError } from "../errors";
import {
  decodeCursor,
  encodeCursor,
  encodeMessageId,
  type MessageRef,
  type PageCursor,
} from "../mail/ids";
import type { SessionGate } from "../mail/service";
import type { Principal } from "../principal";
import { vectorIdOf } from "./ids";
import { indexItems, type RecallDeps, type RecallItem, RecallRefusedError } from "./pipeline";
import { RECALL_PAGE_SIZE } from "./retention";

export { RECALL_PAGE_SIZE };

/** The most ids sent in one store delete or one ledger forget. */
const DELETE_BATCH = 1000;

/**
 * The cursor value the engine stores once a mailbox's build reached its oldest
 * message. The tilde is not in the cursor token's alphabet, so no real cursor
 * can equal it. The object stores it without reading it.
 */
const DONE_CURSOR = "~done";

/** One page the source read: at most RECALL_PAGE_SIZE items, newest first. */
export interface RecallPage {
  readonly uidValidity: number;
  readonly items: RecallItem[];
  /** Where the next page starts, or null when this was the oldest page. */
  readonly next: PageCursor | null;
}

/** Reads mail for the index. Called only inside the connection lease. */
export interface RecallSource {
  /** One page of `mailbox`, starting below `cursor`, or from the newest when null. */
  page(
    gate: SessionGate,
    principal: Principal,
    mailbox: string,
    cursor: PageCursor | null,
  ): Promise<RecallPage>;
  /** Every UID in `mailbox`, and its UIDVALIDITY. */
  uids(
    gate: SessionGate,
    principal: Principal,
    mailbox: string,
  ): Promise<{ uidValidity: number; uids: number[] }>;
}

/** What the engine needs: the store and embedder, the lease runner, the source. */
export type BuildDeps = RecallDeps & {
  readonly leased: LeasedMail;
  readonly source: RecallSource;
};

/** What one call came to. The object's refusals are statuses, not errors. */
export type BuildStatus = "indexed" | "done" | "reset" | "lease_busy" | PageRefusal;

/** Thrown when a page or a clean-up fails. Carries nothing about why. */
export class RecallBuildError extends Error {
  readonly kind = "recall-build" as const;

  constructor() {
    super("recall-build-failed");
    this.name = "RecallBuildError";
  }
}

const KEEP: CursorUpdate = { kind: "keep" };
const RESET: CursorUpdate = { kind: "reset" };

/** Whether `reason` is one of the object's page refusals. */
function isPageRefusal(reason: unknown): reason is PageRefusal {
  return (PAGE_REFUSALS as readonly unknown[]).includes(reason);
}

/** The stored cursor as a cursor for this mailbox, or null to start from the top. */
function cursorFrom(stored: string | null, mailbox: string): PageCursor | null {
  if (stored === null) return null;
  try {
    const cursor = decodeCursor(stored);
    return cursor.mailbox === mailbox ? cursor : null;
  } catch {
    return null;
  }
}

/** Whether `page` keeps the source contract. */
function isValidPage(page: unknown): page is RecallPage {
  if (typeof page !== "object" || page === null) return false;
  const p = page as { uidValidity?: unknown; items?: unknown; next?: unknown };
  if (typeof p.uidValidity !== "number" || !Number.isSafeInteger(p.uidValidity)) return false;
  if (!Array.isArray(p.items) || p.items.length > RECALL_PAGE_SIZE) return false;
  return p.next === null || (typeof p.next === "object" && p.next !== undefined);
}

/**
 * A slot on the person's object: the page token and a way to end the page.
 * Ending never throws: a failed end leaves the token to expire on its own.
 */
async function beginSlot(
  principal: Principal,
  mailbox: string,
  kind: "build" | "reconcile",
): Promise<
  | { ok: true; cursor: string | null; end: (update: CursorUpdate) => Promise<void> }
  | { ok: false; reason: PageRefusal }
> {
  const stub = agentFor(principal);
  let answer: Awaited<ReturnType<typeof stub.recallBeginPage>>;
  try {
    answer = await stub.recallBeginPage(mailbox, kind);
  } catch {
    throw new RecallBuildError();
  }
  if (!answer.ok) {
    if (isPageRefusal(answer.reason)) return { ok: false, reason: answer.reason };
    throw new RecallBuildError();
  }
  const { pageToken } = answer;
  return {
    ok: true,
    cursor: answer.cursor,
    end: async (update) => {
      try {
        await stub.recallEndPage(pageToken, mailbox, update);
      } catch {
        // The token expires on its own; the cursor stays where it was.
      }
    },
  };
}

/** Every ledger row of `mailbox`, read one bounded batch after another. */
async function mailboxRows(
  principal: Principal,
  mailbox: string,
): Promise<{ vectorId: string; uidValidity: number }[]> {
  const stub = agentFor(principal);
  const rows: { vectorId: string; uidValidity: number }[] = [];
  let after: string | null = null;
  for (;;) {
    const batch: { vectorId: string; uidValidity: number }[] = await stub.recallIdsForMailbox(
      mailbox,
      after,
      DELETE_BATCH,
    );
    rows.push(...batch);
    if (batch.length < DELETE_BATCH) return rows;
    after = batch[batch.length - 1]!.vectorId;
  }
}

/** Delete `ids` from the store, then from the ledger, one batch after another. */
async function removeIds(
  principal: Principal,
  ids: readonly string[],
  deps: RecallDeps,
): Promise<void> {
  const stub = agentFor(principal);
  for (let i = 0; i < ids.length; i += DELETE_BATCH) {
    const batch = ids.slice(i, i + DELETE_BATCH);
    await deps.store.deleteIds(batch);
    await stub.recallForget(batch);
  }
}

/** Remove every id of `mailbox` recorded under a validity other than `current`. */
async function removeStaleGeneration(
  principal: Principal,
  mailbox: string,
  current: number,
  deps: RecallDeps,
): Promise<void> {
  const rows = await mailboxRows(principal, mailbox);
  const stale = rows.filter((row) => row.uidValidity !== current).map((row) => row.vectorId);
  await removeIds(principal, stale, deps);
}

/**
 * Index at most one page of `mailbox` for `principal`.
 *
 * Answers `indexed` (more to come), `done` (the oldest page is indexed),
 * `reset` (the mailbox's UIDVALIDITY changed: the old generation is removed and
 * the build starts again from the top on the next call), `lease_busy` (another
 * request holds the person's connection), or one of the object's refusals.
 * Throws `RecallBuildError` on any other failure, with the cursor unchanged.
 */
export async function indexNextPage(
  principal: Principal,
  mailbox: string,
  deps: BuildDeps,
): Promise<BuildStatus> {
  const slot = await beginSlot(principal, mailbox, "build");
  if (!slot.ok) return slot.reason;

  if (slot.cursor === DONE_CURSOR) {
    await slot.end(KEEP);
    return "done";
  }
  const cursor = cursorFrom(slot.cursor, mailbox);

  try {
    let page: RecallPage;
    try {
      page = await deps.leased.withConnectionLease(principal, (gate) =>
        deps.source.page(gate, principal, mailbox, cursor),
      );
    } catch (error) {
      if (error instanceof ConnectionBusyError) {
        await slot.end(KEEP);
        return "lease_busy";
      }
      throw error;
    }
    if (!isValidPage(page)) throw new RecallBuildError();

    if (cursor !== null && page.uidValidity !== cursor.uidValidity) {
      await removeStaleGeneration(principal, mailbox, page.uidValidity, deps);
      await slot.end(RESET);
      return "reset";
    }

    try {
      await indexItems(principal, page.items, deps);
    } catch (error) {
      if (error instanceof RecallRefusedError && isPageRefusal(error.reason)) {
        await slot.end(KEEP);
        return error.reason;
      }
      throw error;
    }

    if (page.next === null) {
      await slot.end({ kind: "set", cursor: DONE_CURSOR });
      return "done";
    }
    await slot.end({ kind: "set", cursor: encodeCursor(page.next) });
    return "indexed";
  } catch {
    await slot.end(KEEP);
    throw new RecallBuildError();
  }
}

/**
 * Remove what disappeared from `mailbox` since it was indexed (RCLL-04, D-12).
 *
 * Takes the same page slot as a build page, so it is paced, exclusive and
 * counted the same way, and it is never refused as full. Reads the mailbox's
 * UID list inside the lease, recomputes the ids that should exist, and removes
 * every other ledger id for that mailbox: UIDs that are gone, and every id
 * recorded under another UIDVALIDITY. Store first, then ledger. When the
 * ledger held rows under another validity, the mailbox's build cursor is reset.
 *
 * `resetCursor` resets it whatever the ledger held (26-REVIEW CR-02). A caller
 * that already knows the validity changed passes it, because a ledger with no
 * rows for the mailbox (nothing in the window when it was built, every vector
 * expired, or every row already removed) shows no old generation, and a cursor
 * left at the end of the old build would end the new one before it started.
 */
export async function reconcileMailbox(
  principal: Principal,
  mailbox: string,
  deps: BuildDeps,
  options: { readonly resetCursor?: boolean } = {},
): Promise<BuildStatus> {
  const slot = await beginSlot(principal, mailbox, "reconcile");
  if (!slot.ok) return slot.reason;

  try {
    let snapshot: { uidValidity: number; uids: number[] };
    try {
      snapshot = await deps.leased.withConnectionLease(principal, (gate) =>
        deps.source.uids(gate, principal, mailbox),
      );
    } catch (error) {
      if (error instanceof ConnectionBusyError) {
        await slot.end(KEEP);
        return "lease_busy";
      }
      throw error;
    }
    if (!Number.isSafeInteger(snapshot.uidValidity) || !Array.isArray(snapshot.uids)) {
      throw new RecallBuildError();
    }

    const wanted = new Set<string>();
    for (const uid of snapshot.uids) {
      const ref: MessageRef = { mailbox, uidValidity: snapshot.uidValidity, uid };
      wanted.add(await vectorIdOf(principal, encodeMessageId(ref)));
    }

    const rows = await mailboxRows(principal, mailbox);
    const validityChanged = rows.some((row) => row.uidValidity !== snapshot.uidValidity);
    const doomed = rows
      .filter((row) => row.uidValidity !== snapshot.uidValidity || !wanted.has(row.vectorId))
      .map((row) => row.vectorId);
    await removeIds(principal, doomed, deps);

    await slot.end(validityChanged || options.resetCursor === true ? RESET : KEEP);
    return "indexed";
  } catch {
    await slot.end(KEEP);
    throw new RecallBuildError();
  }
}

/**
 * Remove named refs from the store and the ledger, without finding them first.
 *
 * Phase 26 calls this when a recall hit fails to open, so a dead ref is removed
 * at once (ARCHITECTURE §4.6(a)). It reads no mail, so it takes no page slot
 * and no lease. A ref that was never indexed is a harmless no-op.
 */
export async function forgetRefs(
  principal: Principal,
  refs: readonly MessageRef[],
  deps: RecallDeps,
): Promise<void> {
  try {
    const ids: string[] = [];
    for (const ref of refs) ids.push(await vectorIdOf(principal, encodeMessageId(ref)));
    await removeIds(principal, ids, deps);
  } catch {
    throw new RecallBuildError();
  }
}
