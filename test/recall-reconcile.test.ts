// Removing what disappeared, on the next sync (Phase 25, RCLL-04, plan 25-02).
//
// `reconcileMailbox` takes a mailbox's UID list and validity and removes every
// ledger id that should no longer exist, store first and ledger second.
// `forgetRefs` removes named refs without finding them first. Both run against
// the REAL `UserAgent` and the REAL strict lease; the store, the model and the
// mail source are fakes.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { createLeasedMail } from "../src/agent/lease";
import { ensureRecallSchema, readState, utcDay, writeState } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { encodeMessageId, type MessageRef } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import type { Principal } from "../src/principal";
import {
  type BuildDeps,
  forgetRefs,
  indexNextPage,
  RecallBuildError,
  reconcileMailbox,
} from "../src/recall/build";
import { createEmbedder } from "../src/recall/embed";
import { vectorIdOf } from "../src/recall/ids";
import { createRecallStore } from "../src/recall/index";
import { RECALL_MAX_PAGES_PER_DAY, RECALL_MAX_VECTORS, RECALL_PAGE_SIZE } from "../src/recall/retention";
import { createFakeAi } from "./fixtures/fake-embedder";
import {
  createFakeRecallSource,
  type FakeRecallSource,
  scriptedMessages,
} from "./fixtures/fake-recall-source";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";

const DAY_MS = 24 * 60 * 60 * 1000;

function objectFor(userId: string): DurableObjectStub<UserAgent> {
  return env.USER_AGENT.getByName(userId);
}

function resetObject(userId: string) {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    state.storage.kv.delete("lease");
  });
}

function withSql<T>(userId: string, fn: (sql: SqlStorage) => T): Promise<T> {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    return fn(state.storage.sql);
  });
}

function passPause(userId: string) {
  return withSql(userId, (sql) => writeState(sql, "last_page_at", String(Date.now() - 61_000)));
}

function ledgerIds(userId: string, mailbox?: string): Promise<string[]> {
  return withSql(userId, (sql) =>
    (mailbox === undefined
      ? sql.exec<{ vector_id: string }>("select vector_id from recall_vectors")
      : sql.exec<{ vector_id: string }>("select vector_id from recall_vectors where mailbox = ?", mailbox)
    )
      .toArray()
      .map((row) => row.vector_id),
  );
}

function idOf(principal: Principal, mailbox: string, uidValidity: number, uid: number) {
  const ref: MessageRef = { mailbox, uidValidity, uid };
  return vectorIdOf(principal, encodeMessageId(ref));
}

interface Harness {
  deps: BuildDeps;
  index: FakeVectorize;
}

function harness(source: FakeRecallSource, index = createFakeVectorize()): Harness {
  return {
    deps: {
      store: createRecallStore(index),
      embedder: createEmbedder(createFakeAi()),
      leased: createLeasedMail(createSessionGate()),
      source,
    },
    index,
  };
}

function source(mailbox: string, count: number, uidValidity = 100): FakeRecallSource {
  return createFakeRecallSource({ mailbox, uidValidity, messages: scriptedMessages(count) });
}

/** The id lists every store delete received, in order. */
function deleteBatches(index: FakeVectorize): string[][] {
  return index.calls.filter((c) => c.method === "deleteByIds").map((c) => c.args[0] as string[]);
}

/** Index `count` messages of INBOX for `principal`, then let the pause pass. */
async function indexInbox(principal: Principal, userId: string, h: Harness) {
  expect(await indexNextPage(principal, "INBOX", h.deps)).toBe("done");
  await passPause(userId);
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
  await resetObject(USER_B.userId);
});

describe("reconcile: mail that disappeared is removed on the next sync (RCLL-04)", () => {
  it("removes exactly the ids of UIDs that are gone, and keeps the rest", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 5);
    const h = harness(inbox);
    await indexInbox(a, USER_A.userId, h);

    inbox.setUids([1, 2, 4]);
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("indexed");

    const gone = [await idOf(a, "INBOX", 100, 3), await idOf(a, "INBOX", 100, 5)];
    const kept = [1, 2, 4];
    expect(deleteBatches(h.index).flat().sort()).toEqual([...gone].sort());
    const left = await ledgerIds(USER_A.userId);
    expect(left.sort()).toEqual((await Promise.all(kept.map((uid) => idOf(a, "INBOX", 100, uid)))).sort());
    expect(h.index.vectors.size).toBe(3);
  });

  it("removes every id under an old validity, resets the cursor, and leaves another mailbox alone", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 5);
    const archive = source("Archive", 3);
    const index = createFakeVectorize();
    const hi = harness(inbox, index);
    const ha = harness(archive, index);
    await indexInbox(a, USER_A.userId, hi);
    expect(await indexNextPage(a, "Archive", ha.deps)).toBe("done");
    await passPause(USER_A.userId);
    expect(await withSql(USER_A.userId, (sql) => readState(sql, "cursor:INBOX"))).not.toBeNull();

    inbox.setValidity(200);
    inbox.setUids([1, 2]);
    expect(await reconcileMailbox(a, "INBOX", hi.deps)).toBe("indexed");

    expect(await ledgerIds(USER_A.userId, "INBOX")).toHaveLength(0);
    expect(await ledgerIds(USER_A.userId, "Archive")).toHaveLength(3);
    expect(await withSql(USER_A.userId, (sql) => readState(sql, "cursor:INBOX"))).toBeNull();
    expect(await withSql(USER_A.userId, (sql) => readState(sql, "cursor:Archive"))).not.toBeNull();
  });

  it("asks the store to delete before the ledger loses anything, and keeps every row when the store delete fails", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 5);
    const h = harness(inbox);
    await indexInbox(a, USER_A.userId, h);

    // Read the ledger at the moment the store delete runs.
    const rowsAtDelete: number[] = [];
    const realDelete = h.index.deleteByIds.bind(h.index);
    (h.index as { deleteByIds: typeof realDelete }).deleteByIds = async (ids: string[]) => {
      rowsAtDelete.push((await ledgerIds(USER_A.userId)).length);
      return realDelete(ids);
    };
    h.index.failing.add("deleteByIds");

    inbox.setUids([1]);
    await expect(reconcileMailbox(a, "INBOX", h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect(rowsAtDelete).toEqual([5]);
    expect(await ledgerIds(USER_A.userId)).toHaveLength(5);
  });

  it("reads the UID list inside the lease, and deletes nothing when the lease is held", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 5);
    const h = harness(inbox);
    await indexInbox(a, USER_A.userId, h);

    let leaseDuringRead: unknown;
    const realUids = inbox.uids.bind(inbox);
    inbox.uids = async (gate, principal, mailbox) => {
      leaseDuringRead = await runInDurableObject(objectFor(USER_A.userId), (_instance, state) =>
        state.storage.kv.get<unknown>("lease"),
      );
      return realUids(gate, principal, mailbox);
    };
    inbox.setUids([1, 2, 3, 4]);
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("indexed");
    expect(leaseDuringRead).toBeDefined();

    await passPause(USER_A.userId);
    await runInDurableObject(objectFor(USER_A.userId), (_instance, state) => {
      state.storage.kv.put("lease", { token: "other-request", expiresAt: Date.now() + 30_000 });
    });
    const deletesBefore = deleteBatches(h.index).length;
    inbox.setUids([]);
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("lease_busy");
    expect(deleteBatches(h.index)).toHaveLength(deletesBefore);
    expect(await ledgerIds(USER_A.userId)).toHaveLength(4);
  });

  it("obeys the page slot: paused, busy and quota like a build page, counts toward the day, and is never full", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 60);
    const h = harness(inbox);

    expect(await indexNextPage(a, "INBOX", h.deps)).toBe("indexed");
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("paused");

    await passPause(USER_A.userId);
    const release = inbox.holdNextPage();
    const inFlight = indexNextPage(a, "INBOX", h.deps);
    for (let i = 0; i < 400 && inbox.calls.length < 2; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("busy");
    release();
    expect(await inFlight).toBe("indexed");

    await passPause(USER_A.userId);
    const today = utcDay(Date.now());
    const countBefore = Number(await withSql(USER_A.userId, (sql) => readState(sql, "pages_count")));
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("indexed");
    expect(Number(await withSql(USER_A.userId, (sql) => readState(sql, "pages_count")))).toBe(
      countBefore + 1,
    );

    await passPause(USER_A.userId);
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", today);
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("quota");

    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_count", "0");
      sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'Archive', 1, ? FROM c`,
        RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1,
        Date.now() + DAY_MS,
      );
    });
    expect(await indexNextPage(a, "INBOX", h.deps)).toBe("full");
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("indexed");
  });

  it("never touches another person's ledger", async () => {
    const a = await testPrincipal(USER_A);
    const b = await testPrincipal(USER_B);
    const index = createFakeVectorize();
    const inboxA = source("INBOX", 5);
    const inboxB = source("INBOX", 5);
    const ha = harness(inboxA, index);
    const hb = harness(inboxB, index);
    await indexInbox(a, USER_A.userId, ha);
    await indexInbox(b, USER_B.userId, hb);

    inboxA.setUids([]);
    expect(await reconcileMailbox(a, "INBOX", ha.deps)).toBe("indexed");
    expect(await ledgerIds(USER_A.userId)).toHaveLength(0);
    expect(await ledgerIds(USER_B.userId)).toHaveLength(5);
    const bIds = await ledgerIds(USER_B.userId);
    for (const id of deleteBatches(index).flat()) expect(bIds).not.toContain(id);
  });

  it("sends the store its deletes in batches of at most 1000", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 0);
    const h = harness(inbox);
    await withSql(USER_A.userId, (sql) => {
      sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2500)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'INBOX', 100, ? FROM c`,
        Date.now() + DAY_MS,
      );
    });

    inbox.setUids([]);
    expect(await reconcileMailbox(a, "INBOX", h.deps)).toBe("indexed");
    expect(deleteBatches(h.index).map((batch) => batch.length)).toEqual([1000, 1000, 500]);
    expect(await ledgerIds(USER_A.userId)).toHaveLength(0);
  });
});

describe("forgetRefs: a dead ref is removed without finding it first", () => {
  it("deletes the recomputed id from the store and the ledger with no query, and a never-indexed ref is a no-op", async () => {
    const a = await testPrincipal(USER_A);
    const inbox = source("INBOX", 5);
    const h = harness(inbox);
    await indexInbox(a, USER_A.userId, h);

    const ref: MessageRef = { mailbox: "INBOX", uidValidity: 100, uid: 3 };
    await forgetRefs(a, [ref], h.deps);
    expect(deleteBatches(h.index)).toEqual([[await vectorIdOf(a, encodeMessageId(ref))]]);
    expect(h.index.calls.filter((c) => c.method === "query")).toHaveLength(0);
    expect(await ledgerIds(USER_A.userId)).toHaveLength(4);
    expect(await ledgerIds(USER_A.userId)).not.toContain(await vectorIdOf(a, encodeMessageId(ref)));

    await forgetRefs(a, [{ mailbox: "INBOX", uidValidity: 100, uid: 999 }], h.deps);
    expect(await ledgerIds(USER_A.userId)).toHaveLength(4);
  });
});
