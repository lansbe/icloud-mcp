// The recall build engine: one page per call (Phase 25, RCLL-07, plan 25-02).
//
// Everything runs against the REAL `UserAgent` in the pool and the REAL
// connection lease (`createLeasedMail(createSessionGate())`, strict, as SPIKE-11
// left it). The store, the model and the mail source are fakes. The lease cases
// assert the ORDER of calls, never that the lease record is gone afterwards, so
// they hold under an advisory lease too.
//
// Recall is inherent: nothing is turned on before the first page.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { createLeasedMail, type LeasedMail } from "../src/agent/lease";
import {
  ensureRecallSchema,
  readState,
  utcDay,
  writeState,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { decodeCursor, encodeMessageId } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { type BuildDeps, indexNextPage, RecallBuildError, type RecallSource } from "../src/recall/build";
import { createEmbedder, type Embedder } from "../src/recall/embed";
import { vectorIdOf } from "../src/recall/ids";
import { createRecallStore, type RecallStore } from "../src/recall/index";
import {
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
} from "../src/recall/retention";
import { createFakeAi, type FakeAi } from "./fixtures/fake-embedder";
import {
  createFakeRecallSource,
  type FakeRecallSource,
  scriptedMessages,
} from "./fixtures/fake-recall-source";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";

const DAY_MS = 24 * 60 * 60 * 1000;
const MAILBOX = "INBOX";

function objectFor(userId: string): DurableObjectStub<UserAgent> {
  return env.USER_AGENT.getByName(userId);
}

/** Drop the recall tables, the stored name and the lease. */
function resetObject(userId: string) {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    state.storage.kv.delete("lease");
  });
}

/** Run `fn` over the object's SQL storage, with the schema in place. */
function withSql<T>(userId: string, fn: (sql: SqlStorage) => T): Promise<T> {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    return fn(state.storage.sql);
  });
}

/** Move the last page's start 61 s back, so the pause has passed. */
function passPause(userId: string) {
  return withSql(userId, (sql) => writeState(sql, "last_page_at", String(Date.now() - 61_000)));
}

function stateOf(userId: string, k: string) {
  return withSql(userId, (sql) => readState(sql, k));
}

function ledgerCount(userId: string) {
  return withSql(
    userId,
    (sql) => sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n,
  );
}

/** A lease runner over the real one that logs `enter` before and `exit` after. */
function recordingLease(log: string[]): LeasedMail {
  const real = createLeasedMail(createSessionGate());
  return {
    async withConnectionLease(principal, fn) {
      log.push("enter");
      const result = await real.withConnectionLease(principal, fn);
      log.push("exit");
      return result;
    },
  };
}

interface Harness {
  deps: BuildDeps;
  index: FakeVectorize;
  ai: FakeAi;
  source: FakeRecallSource;
  log: string[];
}

function harness(
  source: FakeRecallSource,
  wrap: { store?: (base: RecallStore) => RecallStore } = {},
): Harness {
  const log: string[] = [];
  const index = createFakeVectorize();
  const ai = createFakeAi();
  const base = createEmbedder(ai);
  const embedder: Embedder = {
    embed: async (texts) => {
      log.push("embed");
      return base.embed(texts);
    },
  };
  const store = createRecallStore(index);
  return {
    deps: {
      store: wrap.store ? wrap.store(store) : store,
      embedder,
      leased: recordingLease(log),
      source: source as RecallSource,
    },
    index,
    ai,
    source,
    log,
  };
}

function inbox(count: number, uidValidity = 100): FakeRecallSource {
  return createFakeRecallSource({ mailbox: MAILBOX, uidValidity, messages: scriptedMessages(count) });
}

/** Wait until `check` is true, a turn of the event loop at a time. */
async function until(check: () => boolean): Promise<void> {
  for (let i = 0; i < 400 && !check(); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  expect(check()).toBe(true);
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
  await resetObject(USER_B.userId);
});

describe("recall build: one page per call (RCLL-07)", () => {
  it("indexes the first page of a fresh mailbox with nothing turned on first, and stores the next cursor", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(30));

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    expect(h.source.calls).toEqual([{ kind: "page", mailbox: MAILBOX, cursor: null }]);
    expect(await ledgerCount(USER_A.userId)).toBe(RECALL_PAGE_SIZE);

    const stored = await stateOf(USER_A.userId, `cursor:${MAILBOX}`);
    expect(stored).not.toBeNull();
    expect(decodeCursor(stored!)).toEqual({ mailbox: MAILBOX, uidValidity: 100, lastUid: 6 });
  });

  it("answers done for the oldest page, and done again later without calling the source", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(20));

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("done");
    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("done");
    expect(h.source.calls).toHaveLength(1);
  });

  it("answers paused within a minute of the last page, without calling the source, and proceeds once the pause has passed", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(60));

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("paused");
    expect(h.source.calls).toHaveLength(1);

    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    expect(h.source.calls).toHaveLength(2);
  });

  it("answers busy while a page is in flight, and an expired in-flight token does not block", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(60));

    const release = h.source.holdNextPage();
    const first = indexNextPage(a, MAILBOX, h.deps);
    await until(() => h.source.calls.length === 1);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("busy");
    release();
    expect(await first).toBe("indexed");

    await withSql(USER_A.userId, (sql) =>
      writeState(sql, "page", JSON.stringify({ token: "stale", expiresAt: Date.now() - 1 })),
    );
    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
  });

  it("reads inside the lease and embeds only after the lease runner returned (enter, source, exit, embed)", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(10));
    let leaseDuringRead: unknown;
    h.source.onPage = async () => {
      h.log.push("source");
      leaseDuringRead = await runInDurableObject(objectFor(USER_A.userId), (_instance, state) =>
        state.storage.kv.get<unknown>("lease"),
      );
    };

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("done");
    expect(h.log).toEqual(["enter", "source", "exit", "embed"]);
    expect(leaseDuringRead, "the person's lease must be held during the read").toBeDefined();
  });

  it("answers lease_busy when another request holds the person's connection, reads nothing and records nothing", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(10));
    await runInDurableObject(objectFor(USER_A.userId), (_instance, state) => {
      state.storage.kv.put("lease", { token: "other-request", expiresAt: Date.now() + 30_000 });
    });

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("lease_busy");
    expect(h.source.calls).toHaveLength(0);
    expect(await stateOf(USER_A.userId, "page")).toBeNull();
    expect(await ledgerCount(USER_A.userId)).toBe(0);
    expect(h.ai.calls).toHaveLength(0);
  });

  it("answers quota once the day's page cap is reached, and starts counting again on a new UTC day", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(10));
    const today = utcDay(Date.now());
    const yesterday = utcDay(Date.now() - DAY_MS);

    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", today);
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("quota");
    expect(h.source.calls).toHaveLength(0);

    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", yesterday);
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("done");
    expect(await stateOf(USER_A.userId, "pages_day")).toBe(today);
    expect(await stateOf(USER_A.userId, "pages_count")).toBe("1");
  });

  it("answers full within one page of the vector ceiling without reading, while a reconcile page is not refused as full", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(10));
    const seeded = RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1;
    await withSql(USER_A.userId, (sql) => {
      sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'Archive', 1, ? FROM c`,
        seeded,
        Date.now() + DAY_MS,
      );
    });

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("full");
    expect(h.source.calls).toHaveLength(0);

    const stub = objectFor(USER_A.userId);
    const begun = await stub.recallBeginPage(MAILBOX, "reconcile");
    expect(begun.ok).toBe(true);
    if (begun.ok) await stub.recallEndPage(begun.pageToken, MAILBOX, { kind: "keep" });
  });

  it("keeps the cursor when the source throws, clears the page slot, and asks for the same cursor next time", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(60));

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    const before = await stateOf(USER_A.userId, `cursor:${MAILBOX}`);

    await passPause(USER_A.userId);
    h.source.failNextPage();
    await expect(indexNextPage(a, MAILBOX, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect(await stateOf(USER_A.userId, `cursor:${MAILBOX}`)).toBe(before);
    expect(await stateOf(USER_A.userId, "page")).toBeNull();

    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    expect(h.source.calls[2]!.cursor).toEqual(decodeCursor(before!));
  });

  it("keeps the cursor when the store write fails after the ledger was written, and a re-run leaves the same ids", async () => {
    const a = await testPrincipal(USER_A);
    let failWrite = true;
    const h = harness(inbox(60), {
      store: (base) => ({
        ...base,
        upsert: async (principal, entries) => {
          if (failWrite) {
            failWrite = false;
            throw new Error("store write set to fail");
          }
          return base.upsert(principal, entries);
        },
      }),
    });

    await expect(indexNextPage(a, MAILBOX, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect(await stateOf(USER_A.userId, `cursor:${MAILBOX}`)).toBeNull();
    expect(await ledgerCount(USER_A.userId)).toBe(RECALL_PAGE_SIZE);

    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");

    const expected = new Set<string>();
    for (let uid = 60; uid > 60 - RECALL_PAGE_SIZE; uid -= 1) {
      expected.add(await vectorIdOf(a, encodeMessageId({ mailbox: MAILBOX, uidValidity: 100, uid })));
    }
    expect(new Set(h.index.vectors.keys())).toEqual(expected);
    expect(await ledgerCount(USER_A.userId)).toBe(RECALL_PAGE_SIZE);
  });

  it("neither records nor embeds a message older than the retention window", async () => {
    const a = await testPrincipal(USER_A);
    const messages = [
      ...scriptedMessages(5, 100),
      ...scriptedMessages(10, 1).slice(5),
    ];
    const source = createFakeRecallSource({ mailbox: MAILBOX, uidValidity: 100, messages });
    const h = harness(source);

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("done");
    expect(await ledgerCount(USER_A.userId)).toBe(5);
    const embedded = (h.ai.calls[0]!.input as { text: string[] }).text;
    expect(embedded).toHaveLength(5);
    for (const text of embedded) expect(text).not.toMatch(/number [1-5] /);
  });

  it("answers reset when the mailbox's validity changed: the old generation is removed, store then ledger, and the cursor cleared", async () => {
    const a = await testPrincipal(USER_A);
    const h = harness(inbox(60, 100));

    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("indexed");
    expect(h.index.vectors.size).toBe(RECALL_PAGE_SIZE);

    h.source.setValidity(200);
    await passPause(USER_A.userId);
    expect(await indexNextPage(a, MAILBOX, h.deps)).toBe("reset");
    expect(await ledgerCount(USER_A.userId)).toBe(0);
    expect(h.index.vectors.size).toBe(0);
    expect(await stateOf(USER_A.userId, `cursor:${MAILBOX}`)).toBeNull();
  });

  it("builds two people independently: A's page in flight never makes B busy", async () => {
    const a = await testPrincipal(USER_A);
    const b = await testPrincipal(USER_B);
    const ha = harness(inbox(10));
    const hb = harness(inbox(10));

    const release = ha.source.holdNextPage();
    const first = indexNextPage(a, MAILBOX, ha.deps);
    await until(() => ha.source.calls.length === 1);
    expect(await indexNextPage(b, MAILBOX, hb.deps)).toBe("done");
    release();
    expect(await first).toBe("done");
  });
});
