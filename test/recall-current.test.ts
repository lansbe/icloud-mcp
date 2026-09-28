// Keeping a built index current (Phase 26, D-14 to D-17 as revised by D-27,
// D-29 and D-30, plan 26-04).
//
// Everything runs against the REAL `UserAgent` in the pool and the REAL
// connection lease. The store, the model, the page source and the reads are the
// shared fakes in ./fixtures/fake-step-deps.ts, which log every lease entry and
// every read's start and end. Every step here goes through `step()`, which
// fails the case if a step took the lease twice or returned before a read it
// started had finished.
//
// What is proved: a built folder's status check runs alone and at most once in
// five minutes; what it finds is recorded and done by the next step; new mail
// is read oldest first, a page at a time, counted toward the daily cap, and the
// stored next UID moves only past what was stored; a validity change drops the
// old generation; a moved mod-sequence runs the deletion sync at most once an
// hour.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ensureRecallSchema,
  RECALL_PARK_AFTER_FAILURES,
  type SyncRow,
  utcDay,
  writeState,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import type { FolderState } from "../src/change-marker";
import type { Principal } from "../src/principal";
import { indexWordOf, NOTE_PARKED, parkedIn, recallResult } from "../src/mcp/tools/recall";
import { RecallBuildError } from "../src/recall/build";
import {
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
} from "../src/recall/retention";
import {
  indexNewMail,
  RECALL_CHECK_INTERVAL_MS,
  RECALL_RECONCILE_INTERVAL_MS,
  RECALL_RELIST_INTERVAL_MS,
  recallRetryWaitMs,
  recallStep,
  type StepOutcome,
} from "../src/recall/sync";
import { type FakeMessage, scriptedMessages } from "./fixtures/fake-recall-source";
import { fakeStepDeps, type StepHarness } from "./fixtures/fake-step-deps";
import { USER_A, testPrincipal } from "./fixtures/two-users";

const MINUTE = 60 * 1000;
const INBOX = "INBOX";
const ARCHIVE = "Archive";

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

function ledgerCount(userId: string) {
  return withSql(
    userId,
    (sql) => sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n,
  );
}

/** How many pages the object counted today. */
function pagesToday(userId: string) {
  return withSql(userId, (sql) => {
    const rows = sql
      .exec<{ k: string; v: string }>(
        "select k, v from recall_state where k in ('pages_day', 'pages_count')",
      )
      .toArray();
    const day = rows.find((row) => row.k === "pages_day")?.v;
    const count = rows.find((row) => row.k === "pages_count")?.v;
    return day === utcDay(Date.now()) ? Number(count ?? "0") : 0;
  });
}

/** Everything the object's recall tables hold, for a before-and-after compare. */
function recallTables(userId: string) {
  return withSql(userId, (sql) => ({
    state: sql
      .exec<{ k: string; v: string }>("select k, v from recall_state order by k")
      .toArray()
      .map((row) => `${row.k}=${row.v}`),
    vectors: sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n,
  }));
}

/**
 * Run one step and check the one-session rule on what it logged: at most one
 * call of the lease runner, every read it started finished before it returned,
 * and every lease entry exited.
 */
async function step(a: Principal, h: StepHarness): Promise<{ outcome: StepOutcome; log: string[] }> {
  const from = h.log.length;
  const outcome = await recallStep(a, h.deps);
  const log = h.log.slice(from);
  expect(log.filter((entry) => entry === "lease").length).toBeLessThanOrEqual(1);
  expect(log.filter((entry) => entry === "enter").length).toBeLessThanOrEqual(1);
  const starts = log.filter((entry) => entry.endsWith(":start")).length;
  const ends = log.filter((entry) => entry.endsWith(":end")).length;
  expect(ends).toBe(starts);
  expect(log.filter((entry) => entry === "exit").length).toBe(
    log.filter((entry) => entry === "enter").length,
  );
  return { outcome, log };
}

async function rowOf(userId: string, mailbox: string): Promise<SyncRow | undefined> {
  return (await objectFor(userId).recallSyncState()).sync[mailbox];
}

function stateOf(
  mailbox: string,
  uidValidity: number,
  uidNext: number,
  highestModseq: string | null = "7",
): FolderState {
  return { mailbox, uidValidity, uidNext, highestModseq };
}

/** A built row, as a finished build leaves it. */
function builtRow(state: FolderState, over: Partial<SyncRow> = {}): SyncRow {
  return {
    stage: "built",
    state,
    checkedAt: null,
    reconciledAt: null,
    due: null,
    seen: null,
    failedAt: null,
    failures: 0,
    ...over,
  };
}

/** Store the folder list and these rows on the real object. */
async function seedRows(userId: string, folders: string[], rows: Record<string, SyncRow>) {
  const stub = objectFor(userId);
  expect(await stub.recallSetFolders(folders)).toEqual({ ok: true });
  for (const [mailbox, row] of Object.entries(rows)) {
    expect(await stub.recallSetSync(mailbox, row)).toEqual({ ok: true });
  }
}

/** `count` messages from UID `from` up, dated yesterday, with distinct text. */
function messagesFrom(from: number, count: number): FakeMessage[] {
  return Array.from({ length: count }, (_, i) => ({
    uid: from + i,
    date: Date.now() - 24 * 60 * MINUTE,
    text: `new message ${from + i}`,
    snippet: `New ${from + i}`,
  }));
}

/** Every vector id the store was asked to upsert, in order, repeats kept. */
function upsertedIds(h: StepHarness): string[] {
  return h.index.calls
    .filter((call) => call.method === "upsert")
    .flatMap((call) => (call.args[0] as { id: string }[]).map((v) => v.id));
}

/** Drive INBOX (alone) to built through real steps: folders, seed, one page. */
async function buildInbox(a: Principal, h: StepHarness): Promise<void> {
  expect((await step(a, h)).outcome).toBe("folders");
  expect((await step(a, h)).outcome).toBe("seeded");
  expect((await step(a, h)).outcome).toBe("done");
  expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("built");
  await passPause(USER_A.userId);
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
});

// ---------------------------------------------------------------------------
// The status check (D-14, D-27, D-30)
// ---------------------------------------------------------------------------

describe("a built folder's status check runs alone, at most once in five minutes", () => {
  it("checks the folder checked longest ago, alone, and with nothing changed records the time and answers checked", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    const archiveRow = builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now - 2 * MINUTE });
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now - 10 * MINUTE }),
      [ARCHIVE]: archiveRow,
    });

    const run = await step(a, h);

    expect(run.outcome).toBe("checked");
    expect(run.log).toEqual([
      "lease",
      "enter",
      `snapshot:${INBOX}:start`,
      `snapshot:${INBOX}:end`,
      "exit",
    ]);
    expect(h.newMailCalls).toEqual([]);
    expect(h.sources[INBOX]!.calls).toEqual([]);
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 31), { checkedAt: now }),
    );
    expect(await rowOf(USER_A.userId, ARCHIVE)).toEqual(archiveRow);
    expect(await pagesToday(USER_A.userId)).toBe(0);
  });

  it("a folder never checked goes before one checked long ago", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now - 60 * MINUTE }),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 11)),
    });

    const run = await step(a, h);

    expect(run.outcome).toBe("checked");
    expect(run.log).toContain(`snapshot:${ARCHIVE}:start`);
    expect(run.log).not.toContain(`snapshot:${INBOX}:start`);
  });

  it("every built folder checked under five minutes ago: idle, and nothing is read", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), {
        checkedAt: now - RECALL_CHECK_INTERVAL_MS + 1,
      }),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now - MINUTE }),
    });
    const before = await recallTables(USER_A.userId);

    const run = await step(a, h);

    expect(run.outcome).toBe("idle");
    expect(run.log).toEqual([]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("the status check reporting the archive folder gone drops it; INBOX never is, and is recorded as a failure", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now - 10 * MINUTE }),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now - 20 * MINUTE }),
    });

    h.setSnapshot(ARCHIVE, { mailbox: ARCHIVE, answered: false, gone: true });
    h.setFolders([INBOX]);
    expect((await step(a, h)).outcome).toBe("gone");
    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    // The drop asks for another listing (26-REVIEW-2 WR-02). The drop's
    // removal took the page slot, so the pause is waited out first.
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("folders");

    h.setSnapshot(INBOX, { mailbox: INBOX, answered: false, gone: true });
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    // Not dropped, but the check time moves and the failure is counted (CR-01),
    // so INBOX waits five minutes before it is asked again.
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 31), { checkedAt: now, failedAt: now, failures: 1 }),
    );
    expect((await step(a, h)).outcome).toBe("idle");
  });
});

// ---------------------------------------------------------------------------
// New mail (D-16, D-27, D-30)
// ---------------------------------------------------------------------------

/**
 * INBOX built at next UID 100, checked and synced 10 minutes ago, with 40 new
 * messages waiting. The new mail moved the mod-sequence, and the recent sync
 * means no deletion sync is owed, so new mail is what the check finds.
 */
async function inboxWithBurst(): Promise<{ h: StepHarness; now: number }> {
  const h = fakeStepDeps({
    folders: [INBOX],
    mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(99) } },
  });
  const now = Date.now();
  h.setNow(now);
  await seedRows(USER_A.userId, [INBOX], {
    [INBOX]: builtRow(stateOf(INBOX, 100, 100), {
      checkedAt: now - 10 * MINUTE,
      reconciledAt: now - 10 * MINUTE,
    }),
  });
  h.addMessages(INBOX, messagesFrom(100, 40));
  h.setModseq(INBOX, "9");
  return { h, now };
}

describe("new mail is found by the status check and read by the next step, oldest first", () => {
  it("a burst of 40: the check records it, then 100-124, then 125-139, each stored once", async () => {
    const a = await testPrincipal(USER_A);
    const { h, now } = await inboxWithBurst();
    const seen = stateOf(INBOX, 100, 140, "9");

    // Step one: the status check alone. Nothing is read.
    let run = await step(a, h);
    expect(run.outcome).toBe("due");
    expect(run.log).toEqual([
      "lease",
      "enter",
      `snapshot:${INBOX}:start`,
      `snapshot:${INBOX}:end`,
      "exit",
    ]);
    expect(h.newMailCalls).toEqual([]);
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 100), {
        checkedAt: now,
        reconciledAt: now - 10 * MINUTE,
        due: "new_mail",
        seen,
      }),
    );
    expect(await ledgerCount(USER_A.userId)).toBe(0);

    // Step two: the oldest 25, and the mark moves to 125 with the mail still due.
    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(run.log).toEqual([
      "lease",
      "enter",
      `newMail:${INBOX}:start`,
      `newMail:${INBOX}:end`,
      "exit",
    ]);
    expect(h.newMailCalls).toEqual([
      { mailbox: INBOX, uidValidity: 100, fromUid: 100, toUidExclusive: 140 },
    ]);
    expect(await ledgerCount(USER_A.userId)).toBe(25);
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 125), {
        checkedAt: now,
        reconciledAt: now - 10 * MINUTE,
        due: "new_mail",
        seen,
      }),
    );

    // Too early for the next page.
    expect((await step(a, h)).outcome).toBe("paused");

    // Step three, after the pause: the rest, and the due is cleared.
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(h.newMailCalls[1]).toEqual({
      mailbox: INBOX,
      uidValidity: 100,
      fromUid: 125,
      toUidExclusive: 140,
    });
    expect(await ledgerCount(USER_A.userId)).toBe(40);
    // The validity and mod-sequence are the stored ones: only the next UID moved.
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 140), { checkedAt: now, reconciledAt: now - 10 * MINUTE }),
    );

    const ids = upsertedIds(h);
    expect(ids).toHaveLength(40);
    expect(new Set(ids).size).toBe(40);
  });

  it("a new-mail page counts toward the day's pages", async () => {
    const a = await testPrincipal(USER_A);
    const { h } = await inboxWithBurst();
    expect((await step(a, h)).outcome).toBe("due");
    const before = await pagesToday(USER_A.userId);

    expect((await step(a, h)).outcome).toBe("indexed");

    expect(await pagesToday(USER_A.userId)).toBe(before + 1);
  });

  it("at the day's cap, the new-mail step answers quota and reads nothing", async () => {
    const a = await testPrincipal(USER_A);
    const { h } = await inboxWithBurst();
    expect((await step(a, h)).outcome).toBe("due");
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    const before = await recallTables(USER_A.userId);

    const run = await step(a, h);

    expect(run.outcome).toBe("quota");
    expect(run.log).toEqual([]);
    expect(h.newMailCalls).toEqual([]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("the page slot refusing at begin, after the slot read said free: busy, nothing read, nothing stored", async () => {
    const a = await testPrincipal(USER_A);
    const { h } = await inboxWithBurst();
    expect((await step(a, h)).outcome).toBe("due");
    const row = (await rowOf(USER_A.userId, INBOX))!;

    // Another page began between the slot read and the begin.
    await withSql(USER_A.userId, (sql) =>
      writeState(sql, "page", JSON.stringify({ token: "live", expiresAt: Date.now() + 60_000 })),
    );
    const before = await recallTables(USER_A.userId);
    const from = h.log.length;

    const outcome = await indexNewMail(a, INBOX, row, h.deps);

    expect(outcome).toBe("busy");
    expect(h.log.slice(from)).toEqual([]);
    expect(h.newMailCalls).toEqual([]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("the store failing part-way leaves the mark where it was and clears the due; after the wait the check finds the same mail and the next step reads the same range", async () => {
    const a = await testPrincipal(USER_A);
    const { h, now } = await inboxWithBurst();
    expect((await step(a, h)).outcome).toBe("due");
    const due = (await rowOf(USER_A.userId, INBOX))!;

    h.index.failing.add("upsert");
    await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    // The mark did not move. What was due is cleared and the failure recorded
    // (CR-01), so the next attempt is a fresh status check.
    expect(await rowOf(USER_A.userId, INBOX)).toEqual({
      ...due,
      checkedAt: now,
      due: null,
      seen: null,
      failedAt: now,
      failures: 1,
    });
    expect((await objectFor(USER_A.userId).recallSyncState()).slot).not.toBe("busy");

    // Inside the wait: nothing is read.
    h.index.failing.delete("upsert");
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("idle");

    // After it: the check finds the same new mail, and the next step reads it
    // from the same place, and clears the failure.
    h.setNow(now + RECALL_CHECK_INTERVAL_MS);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await step(a, h)).outcome).toBe("indexed");
    expect(h.newMailCalls.map((call) => call.fromUid)).toEqual([100, 100]);
    const after = (await rowOf(USER_A.userId, INBOX))!;
    expect(after.state!.uidNext).toBe(125);
    expect(after.failedAt).toBeNull();
    expect(after.failures).toBe(0);
  });

  it("a folder with something due is served before a folder waiting to be built", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(99) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    h.addMessages(INBOX, messagesFrom(100, 3));
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 100), {
        checkedAt: Date.now(),
        due: "new_mail",
        seen: stateOf(INBOX, 100, 103),
      }),
    });

    const run = await step(a, h);

    expect(run.outcome).toBe("indexed");
    expect(run.log).toContain(`newMail:${INBOX}:start`);
    expect(run.log.some((entry) => entry.includes(ARCHIVE))).toBe(false);
    expect(await rowOf(USER_A.userId, ARCHIVE)).toBeUndefined();
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 103), { checkedAt: expect.any(Number) }),
    );
  });
});

// ---------------------------------------------------------------------------
// Removals: a validity change and the deletion sync (D-17b, D-17c)
// ---------------------------------------------------------------------------

describe("removals reach the index on the folder's next sync", () => {
  it("a validity change: the check records a reconcile, the next step removes the old generation and the folder goes back to seed", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);
    expect(await ledgerCount(USER_A.userId)).toBe(5);

    h.setNow(now + 6 * MINUTE);
    h.setValidity(INBOX, 200);
    let run = await step(a, h);
    expect(run.outcome).toBe("due");
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBe("reconcile");
    expect(h.index.calls.some((call) => call.method === "deleteByIds")).toBe(false);

    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(run.log).toEqual(["lease", "enter", `uids:${INBOX}:start`, `uids:${INBOX}:end`, "exit"]);
    const deletes = h.index.calls.filter((call) => call.method === "deleteByIds");
    expect(deletes).toHaveLength(1);
    expect(deletes[0]!.args[0] as string[]).toHaveLength(5);
    expect(h.index.vectors.size).toBe(0);
    expect(await ledgerCount(USER_A.userId)).toBe(0);
    expect(await rowOf(USER_A.userId, INBOX)).toEqual({
      stage: "seed",
      state: null,
      checkedAt: null,
      reconciledAt: null,
      due: null,
      seen: null,
      failedAt: null,
      failures: 0,
    });
  });

  it("a validity change on a folder whose ledger holds no rows still resets the build, so the new generation is indexed (26-REVIEW CR-02)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);

    // Every row gone before the reset: expired, or removed as dead refs. The
    // build's cursor still says it reached the oldest page.
    await withSql(USER_A.userId, (sql) => sql.exec("delete from recall_vectors"));
    h.index.vectors.clear();
    expect(await ledgerCount(USER_A.userId)).toBe(0);

    h.setNow(now + 6 * MINUTE);
    h.setValidity(INBOX, 200);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await step(a, h)).outcome).toBe("indexed");
    expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("seed");

    // Seed, then the build starts again from the top and indexes all five
    // under the new validity.
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("seeded");
    const pagesBefore = h.sources[INBOX]!.calls.filter((call) => call.kind === "page").length;
    expect((await step(a, h)).outcome).toBe("done");
    const pages = h.sources[INBOX]!.calls.filter((call) => call.kind === "page");
    expect(pages).toHaveLength(pagesBefore + 1);
    expect(pages[pages.length - 1]).toEqual({ kind: "page", mailbox: INBOX, cursor: null });
    expect(await ledgerCount(USER_A.userId)).toBe(5);
    expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("built");
  });

  it("a validity reset whose slot end changes nothing (the token expired) still resets the build, so the new generation is indexed (26-REVIEW-2 WR-01)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);

    h.setNow(now + 6 * MINUTE);
    h.setValidity(INBOX, 200);
    expect((await step(a, h)).outcome).toBe("due");

    // The reconcile's end comes too late: its token expired and the object
    // answers false and changes nothing, as it does for any stale token.
    const stub = objectFor(USER_A.userId);
    await runInDurableObject(stub, (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      const real = prototype.recallEndPage;
      let first = true;
      vi.spyOn(prototype, "recallEndPage").mockImplementation(function (
        this: UserAgent,
        _token: unknown,
        mailbox: unknown,
        update: unknown,
      ) {
        if (first) {
          first = false;
          return real.call(this, "an-expired-token", mailbox, update);
        }
        return real.call(this, _token, mailbox, update);
      });
    });
    try {
      expect((await step(a, h)).outcome).toBe("indexed");
    } finally {
      vi.restoreAllMocks();
    }
    expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("seed");
    expect(await ledgerCount(USER_A.userId)).toBe(0);

    // The token the end never cleared expires on its own.
    await withSql(USER_A.userId, (sql) => sql.exec("delete from recall_state where k = 'page'"));
    await passPause(USER_A.userId);

    // Seed, then the build starts again from the top and indexes all five.
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    const pages = h.sources[INBOX]!.calls.filter((call) => call.kind === "page");
    expect(pages[pages.length - 1]).toEqual({ kind: "page", mailbox: INBOX, cursor: null });
    expect(await ledgerCount(USER_A.userId)).toBe(5);
    expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("built");
  });

  it("a folder dropped as gone takes its vectors, its sync row and its cursor with it (26-REVIEW CR-03)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(3) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(4) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    expect(await ledgerCount(USER_A.userId)).toBe(7);
    await passPause(USER_A.userId);

    // The archive folder is deleted in iCloud. INBOX's check comes first (same
    // check time, listed first), then the archive's finds it gone.
    h.setGone(ARCHIVE, true);
    h.setNow(now + 6 * MINUTE);
    expect((await step(a, h)).outcome).toBe("checked");
    expect((await step(a, h)).outcome).toBe("gone");

    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    expect(await ledgerCount(USER_A.userId)).toBe(3);
    expect(h.index.vectors.size).toBe(3);
    const keys = (await recallTables(USER_A.userId)).state.map((row) => row.split("=")[0]);
    expect(keys).not.toContain(`sync:${ARCHIVE}`);
    expect(keys).not.toContain(`cursor:${ARCHIVE}`);
    expect(keys).toContain(`sync:${INBOX}`);
    expect(keys).toContain(`cursor:${INBOX}`);
  });

  it("a gone folder whose removal is refused by the slot stays listed, and the next check drops it", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(3) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(4) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 4), { checkedAt: now + MINUTE }),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 5), { checkedAt: now - 10 * MINUTE }),
    });
    h.setGone(ARCHIVE, true);
    // Another page starts between the slot read and the removal's slot.
    const stub = objectFor(USER_A.userId);
    await runInDurableObject(stub, (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      const real = prototype.recallBeginPage;
      let first = true;
      vi.spyOn(prototype, "recallBeginPage").mockImplementation(function (
        this: UserAgent,
        mailbox: unknown,
        kind: unknown,
      ) {
        if (first) {
          first = false;
          return { ok: false, reason: "busy" };
        }
        return real.call(this, mailbox, kind);
      });
    });

    try {
      expect((await step(a, h)).outcome).toBe("busy");
      expect((await stub.recallSyncState()).folders).toEqual([INBOX, ARCHIVE]);

      expect((await step(a, h)).outcome).toBe("gone");
      expect((await stub.recallSyncState()).folders).toEqual([INBOX]);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("the mod-sequence moved and the last sync was two hours ago: the deletion sync removes what iCloud no longer has, and counts", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);
    const built = (await rowOf(USER_A.userId, INBOX))!;
    expect(
      await objectFor(USER_A.userId).recallSetSync(INBOX, {
        ...built,
        reconciledAt: now - 2 * 60 * MINUTE,
      }),
    ).toEqual({ ok: true });

    // Messages 4 and 5 were deleted in iCloud: the mod-sequence moved, the
    // next UID did not.
    h.sources[INBOX]!.setUids([1, 2, 3]);
    h.setModseq(INBOX, "12");
    const later = now + 6 * MINUTE;
    h.setNow(later);

    let run = await step(a, h);
    expect(run.outcome).toBe("due");
    expect(await rowOf(USER_A.userId, INBOX)).toMatchObject({
      due: "reconcile",
      seen: stateOf(INBOX, 100, 6, "12"),
    });
    const before = await pagesToday(USER_A.userId);

    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(await ledgerCount(USER_A.userId)).toBe(3);
    expect(h.index.vectors.size).toBe(3);
    expect(await pagesToday(USER_A.userId)).toBe(before + 1);
    expect(await rowOf(USER_A.userId, INBOX)).toEqual(
      builtRow(stateOf(INBOX, 100, 6, "12"), { checkedAt: later, reconciledAt: later }),
    );
  });

  it("the mod-sequence moved but the last sync was 20 minutes ago: no sync is due, and the check answers checked", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);
    const built = (await rowOf(USER_A.userId, INBOX))!;
    const later = now + 6 * MINUTE;
    expect(
      await objectFor(USER_A.userId).recallSetSync(INBOX, {
        ...built,
        reconciledAt: later - 20 * MINUTE,
      }),
    ).toEqual({ ok: true });
    h.setModseq(INBOX, "12");
    h.setNow(later);

    const run = await step(a, h);

    expect(run.outcome).toBe("checked");
    const row = (await rowOf(USER_A.userId, INBOX))!;
    expect(row.due).toBeNull();
    expect(row.checkedAt).toBe(later);
    expect(row.state!.highestModseq).toBe("7");
  });

  it("at the vector ceiling a deletion sync still runs and a gone folder's vectors still go, while new mail waits with no read (26-REVIEW-2 WR-04)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(4) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    await passPause(USER_A.userId);
    expect(await ledgerCount(USER_A.userId)).toBe(9);

    // Fill the ledger past the ceiling's threshold with rows of a folder the
    // build does not cover, far enough that it stays full after the two
    // removals below (six rows between them).
    await withSql(USER_A.userId, (sql) =>
      sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'Elsewhere', 1, ? FROM c`,
        RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1 + 6 - 9,
        Date.now() + 24 * 60 * MINUTE,
      ),
    );
    expect((await objectFor(USER_A.userId).recallSyncState()).full).toBe(true);
    const built = (await rowOf(USER_A.userId, INBOX))!;
    expect(
      await objectFor(USER_A.userId).recallSetSync(INBOX, {
        ...built,
        reconciledAt: now - 2 * 60 * MINUTE,
      }),
    ).toEqual({ ok: true });

    // INBOX: messages 4 and 5 deleted in iCloud. The archive: deleted.
    h.sources[INBOX]!.setUids([1, 2, 3]);
    h.setModseq(INBOX, "12");
    h.setGone(ARCHIVE, true);
    let t = now + 6 * MINUTE;
    h.setNow(t);

    expect((await step(a, h)).outcome).toBe("due");
    const sync = await step(a, h);
    expect(sync.outcome).toBe("indexed");
    expect(sync.log).toContain(`uids:${INBOX}:start`);
    expect(await ledgerCount(USER_A.userId)).toBe(RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1 + 6 - 2);
    expect(h.index.vectors.size).toBe(7);
    await passPause(USER_A.userId);

    // Still full. The archive's check finds it gone, and its vectors go. The
    // listing that follows the drop runs at the ceiling too.
    expect((await objectFor(USER_A.userId).recallSyncState()).full).toBe(true);
    h.setFolders([INBOX]);
    expect((await step(a, h)).outcome).toBe("gone");
    expect(h.index.vectors.size).toBe(3);
    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("folders");

    // Still full. New mail is found by the check, then waits: no read, no
    // lease, and the step says the index is full.
    expect((await objectFor(USER_A.userId).recallSyncState()).full).toBe(true);
    h.addMessages(INBOX, messagesFrom(6, 2));
    t += RECALL_CHECK_INTERVAL_MS;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBe("new_mail");
    const waited = await step(a, h);
    expect(waited.outcome).toBe("full");
    expect(waited.log).toEqual([]);
    expect(h.newMailCalls).toEqual([]);
  });

  it("new mail before every status check does not starve the deletion sync: it runs once the hour is up, and the new mail follows it (26-REVIEW-2 WR-05)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);
    const built = (await rowOf(USER_A.userId, INBOX))!;
    expect(
      await objectFor(USER_A.userId).recallSetSync(INBOX, { ...built, reconciledAt: now }),
    ).toEqual({ ok: true });

    // Message 2 is deleted in iCloud right after that sync. Then one new
    // message arrives before every five-minute check, for 65 minutes, and each
    // moves the mod-sequence.
    const outcomes: StepOutcome[][] = [];
    for (let i = 1; i <= 13; i += 1) {
      h.addMessages(INBOX, messagesFrom(5 + i, 1));
      h.setModseq(INBOX, String(7 + i));
      h.sources[INBOX]!.setUids([1, 3, 4, 5, ...Array.from({ length: i }, (_, k) => 6 + k)]);
      h.setNow(now + i * RECALL_CHECK_INTERVAL_MS);
      const round: StepOutcome[] = [];
      for (let n = 0; n < 4; n += 1) {
        await passPause(USER_A.userId);
        const outcome = (await step(a, h)).outcome;
        round.push(outcome);
        if (outcome === "idle") break;
      }
      outcomes.push(round);
    }

    // Before the hour: new mail each time, and no sync.
    for (const round of outcomes.slice(0, 11)) expect(round).toEqual(["due", "indexed", "idle"]);
    // At the hour: the check records the sync, the sync runs, then the new mail.
    expect(outcomes[11]).toEqual(["due", "indexed", "indexed", "idle"]);
    expect(h.log.filter((entry) => entry === `uids:${INBOX}:start`)).toHaveLength(1);
    // After it: new mail again.
    expect(outcomes[12]).toEqual(["due", "indexed", "idle"]);

    // Message 2 is gone from the index; every new message is in it.
    expect(await ledgerCount(USER_A.userId)).toBe(4 + 13);
    expect(h.index.vectors.size).toBe(4 + 13);
    const row = (await rowOf(USER_A.userId, INBOX))!;
    expect(row.reconciledAt).toBe(now + 12 * RECALL_CHECK_INTERVAL_MS);
    expect(row.state!.uidNext).toBe(19);
    expect(row.due).toBeNull();
  });

  it("iCloud reporting no mod-sequence: a deletion sync is due at most once an hour", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);
    h.setModseq(INBOX, null);

    // Never synced: due, then run.
    let t = now + 6 * MINUTE;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await step(a, h)).outcome).toBe("indexed");
    const synced = (await rowOf(USER_A.userId, INBOX))!;
    expect(synced.reconciledAt).toBe(t);
    expect(synced.state!.highestModseq).toBeNull();
    await passPause(USER_A.userId);

    // Ten minutes later: checked, not due.
    t += 10 * MINUTE;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("checked");

    // An hour after the sync: due again.
    t = synced.reconciledAt! + RECALL_RECONCILE_INTERVAL_MS;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBe("reconcile");
  });
});

// ---------------------------------------------------------------------------
// A folder that keeps failing does not wedge the build (26-REVIEW CR-01)
// ---------------------------------------------------------------------------

describe("a failure is recorded and waited out, and never stops the other folders (26-REVIEW CR-01)", () => {
  /** How many times the log shows `entry`. */
  function count(h: StepHarness, entry: string): number {
    return h.log.filter((one) => one === entry).length;
  }

  it("a folder deleted while its new mail is due: one failed read, nothing more until the wait has passed, then the check drops it", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      // Checked a minute in the future, so INBOX is not due a check in this case.
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now + MINUTE }),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 11), {
        checkedAt: now,
        due: "new_mail",
        seen: stateOf(ARCHIVE, 300, 14),
      }),
    });
    h.setGone(ARCHIVE, true);

    await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect(count(h, `newMail:${ARCHIVE}:start`)).toBe(1);
    expect(await rowOf(USER_A.userId, ARCHIVE)).toEqual(
      builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now, failedAt: now, failures: 1 }),
    );

    // Ten more mail calls inside the wait: not one of them touches the archive.
    for (let i = 0; i < 10; i += 1) {
      await passPause(USER_A.userId);
      const run = await step(a, h);
      expect(run.outcome).toBe("idle");
      expect(run.log).toEqual([]);
    }
    expect(count(h, `newMail:${ARCHIVE}:start`)).toBe(1);

    // After the wait, a fresh status check finds it gone, and it is dropped.
    await passPause(USER_A.userId);
    h.setNow(now + RECALL_CHECK_INTERVAL_MS);
    const run = await step(a, h);
    expect(run.outcome).toBe("gone");
    expect(run.log).toContain(`snapshot:${ARCHIVE}:start`);
    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    expect(count(h, `newMail:${ARCHIVE}:start`)).toBe(1);
  });

  it("the validity changing between the status check and the new-mail read: one failed read, then the next check sees the new validity and the folder goes back to seed", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);

    h.addMessages(INBOX, messagesFrom(6, 3));
    let t = now + 6 * MINUTE;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBe("new_mail");

    // The mailbox is recreated before the read.
    h.setValidity(INBOX, 200);
    await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect(h.newMailCalls).toHaveLength(1);
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBeNull();

    // Inside the wait: nothing is read.
    for (let i = 0; i < 5; i += 1) {
      await passPause(USER_A.userId);
      expect((await step(a, h)).outcome).toBe("idle");
    }
    expect(h.newMailCalls).toHaveLength(1);

    // After it: the check sees the new validity, and the deletion sync sends
    // the folder back to seed.
    t += RECALL_CHECK_INTERVAL_MS;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("due");
    expect((await rowOf(USER_A.userId, INBOX))!.due).toBe("reconcile");
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("indexed");
    expect((await rowOf(USER_A.userId, INBOX))!.stage).toBe("seed");
    expect(h.newMailCalls).toHaveLength(1);
  });

  it("the archive refusing its status check with a plain refusal does not stop INBOX's checks, and is asked less often each time", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now - 10 * MINUTE }),
    });
    h.setSnapshot(ARCHIVE, { mailbox: ARCHIVE, answered: false });

    // INBOX's check is due, so it goes first (WR-04); then the archive is
    // asked, and does not answer.
    let run = await step(a, h);
    expect(run.outcome).toBe("checked");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect((await step(a, h)).outcome).toBe("idle");

    // Five minutes on: INBOX is checked, then the archive is asked again.
    h.setNow(now + RECALL_CHECK_INTERVAL_MS);
    run = await step(a, h);
    expect(run.outcome).toBe("checked");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect((await rowOf(USER_A.userId, ARCHIVE))!.failures).toBe(2);

    // Five more: INBOX is checked, and the archive is still waiting (ten
    // minutes after its second failure), so nothing else runs.
    h.setNow(now + 2 * RECALL_CHECK_INTERVAL_MS);
    run = await step(a, h);
    expect(run.outcome).toBe("checked");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
    expect((await step(a, h)).outcome).toBe("idle");
    expect(count(h, `snapshot:${ARCHIVE}:start`)).toBe(2);
  });

  it("while the archive is still building, INBOX still gets its status check and its new mail (26-REVIEW WR-04)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(80) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now - 10 * MINUTE }),
      [ARCHIVE]: { ...builtRow(stateOf(ARCHIVE, 300, 81), { checkedAt: now }), stage: "build" },
    });
    h.addMessages(INBOX, messagesFrom(31, 2));

    // INBOX's check, and its new mail, come before the archive's next page.
    let run = await step(a, h);
    expect(run.outcome).toBe("due");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(run.log).toContain(`newMail:${INBOX}:start`);
    expect((await rowOf(USER_A.userId, INBOX))!.state!.uidNext).toBe(33);

    // Then the archive's build goes on, page by page.
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(run.log).toContain(`page:${ARCHIVE}:start`);
    await passPause(USER_A.userId);
    expect((await step(a, h)).log).toContain(`page:${ARCHIVE}:start`);

    // Five minutes after INBOX's check, it is checked again, still before the
    // archive's next page.
    h.setNow(now + RECALL_CHECK_INTERVAL_MS);
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("checked");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
    expect((await rowOf(USER_A.userId, ARCHIVE))!.stage).toBe("build");
  });

  it("a build page that keeps failing goes back to seed after three, and its status check then drops the folder", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      // Checked a day ahead, so INBOX's checks stay out of this case.
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now + 24 * 60 * MINUTE }),
      [ARCHIVE]: {
        ...builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now }),
        stage: "build",
      },
    });
    h.setGone(ARCHIVE, true);

    // Three failed pages, each after the last one's wait: 5, then 10 minutes.
    let t = now;
    for (const wait of [0, 5 * MINUTE, 10 * MINUTE]) {
      t += wait;
      h.setNow(t);
      await passPause(USER_A.userId);
      await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
      // Inside the wait that follows: nothing.
      await passPause(USER_A.userId);
      expect((await step(a, h)).outcome).toBe("idle");
    }
    expect(count(h, `page:${ARCHIVE}:start`)).toBe(3);
    expect(await rowOf(USER_A.userId, ARCHIVE)).toMatchObject({
      stage: "seed",
      failedAt: t,
      failures: 3,
    });

    // Twenty minutes after the third: the status check finds it gone.
    h.setNow(t + 20 * MINUTE);
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("gone");
    expect((await objectFor(USER_A.userId).recallSyncState()).folders).toEqual([INBOX]);
    expect(count(h, `page:${ARCHIVE}:start`)).toBe(3);
  });

  it("after a reseed and a seed that works, one more failed page does not reseed at once: the next reseed is three failures later (26-REVIEW-2 WR-03)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now + 2 * 24 * 60 * MINUTE }),
      [ARCHIVE]: { ...builtRow(stateOf(ARCHIVE, 300, 11), { checkedAt: now }), stage: "build" },
    });
    // The archive's status check works, but every page of it fails at the store.
    h.index.failing.add("upsert");

    /** Run the next step once the archive's wait has passed. */
    async function next(): Promise<StepOutcome | "failed"> {
      const row = (await rowOf(USER_A.userId, ARCHIVE))!;
      h.setNow((row.failedAt ?? now) + recallRetryWaitMs(row.failures));
      await passPause(USER_A.userId);
      try {
        return await recallStep(a, h.deps);
      } catch (error) {
        expect(error).toBeInstanceOf(RecallBuildError);
        return "failed";
      }
    }

    const stages: string[] = [];
    for (let i = 0; i < 8; i += 1) {
      const outcome = await next();
      const row = (await rowOf(USER_A.userId, ARCHIVE))!;
      stages.push(`${outcome}:${row.stage}:${row.failures}`);
    }
    expect(stages).toEqual([
      "failed:build:1",
      "failed:build:2",
      "failed:seed:3",
      "seeded:build:3",
      "failed:build:4",
      "failed:build:5",
      "failed:seed:6",
      "seeded:build:6",
    ]);
  });

  it("a folder that keeps failing is parked after nine: the step leaves it alone, the answer stops saying building, and the next listing gives it one more try (26-REVIEW-2 WR-03)", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
      },
    });
    const now = Date.now();
    h.setNow(now);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), { checkedAt: now + 4 * 24 * 60 * MINUTE }),
    });
    // The archive refuses its status check with a plain refusal, every time.
    h.setSnapshot(ARCHIVE, { mailbox: ARCHIVE, answered: false });
    const stub = objectFor(USER_A.userId);

    let failedAt = now;
    for (let i = 1; i <= RECALL_PARK_AFTER_FAILURES; i += 1) {
      const row = await rowOf(USER_A.userId, ARCHIVE);
      failedAt = row === undefined ? now : row.failedAt! + recallRetryWaitMs(row.failures);
      h.setNow(failedAt);
      // Listed just before this failure, so no listing comes due in this case.
      expect(await stub.recallSetFolders([INBOX, ARCHIVE], failedAt - 1)).toEqual({ ok: true });
      expect((await step(a, h)).outcome).toBe("unanswered");
      // Short of nine, the answer still says building.
      if (i < RECALL_PARK_AFTER_FAILURES) {
        expect(indexWordOf(await stub.recallSyncState())).toBe("building");
      }
    }
    expect((await rowOf(USER_A.userId, ARCHIVE))!.failures).toBe(RECALL_PARK_AFTER_FAILURES);
    const checks = () => h.log.filter((entry) => entry === `snapshot:${ARCHIVE}:start`).length;
    expect(checks()).toBe(RECALL_PARK_AFTER_FAILURES);

    // Parked: the answer calls the index built and says a folder could not be read.
    const parked = await stub.recallSyncState();
    expect(indexWordOf(parked)).toBe("built");
    expect(parkedIn(parked)).toBe(true);
    const note = JSON.parse(
      (recallResult([], indexWordOf(parked), parkedIn(parked)).content[0] as { text: string }).text,
    ).note as string;
    expect(note).toContain(NOTE_PARKED);
    expect(note).not.toContain("still being built");

    // Past the retry wait, and short of the next listing: still left alone.
    const late = failedAt + recallRetryWaitMs(RECALL_PARK_AFTER_FAILURES) + MINUTE;
    expect(late).toBeLessThan(failedAt - 1 + RECALL_RELIST_INTERVAL_MS);
    h.setNow(late);
    const run = await step(a, h);
    expect(run.outcome).toBe("idle");
    expect(run.log).toEqual([]);
    expect(checks()).toBe(RECALL_PARK_AFTER_FAILURES);

    // The next listing un-parks it for one more try, at once.
    const listed = failedAt - 1 + RECALL_RELIST_INTERVAL_MS;
    h.setNow(listed);
    expect((await step(a, h)).outcome).toBe("folders");
    expect(indexWordOf(await stub.recallSyncState())).toBe("building");
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect(checks()).toBe(RECALL_PARK_AFTER_FAILURES + 1);
    // That try failed, so it is parked again until the listing after.
    expect(parkedIn(await stub.recallSyncState())).toBe(true);
    expect((await step(a, h)).outcome).toBe("idle");
  });

  it("a folder listing that fails is recorded, and is not tried again until its wait has passed", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(3) } },
    });
    const now = Date.now();
    h.setNow(now);
    h.setListingFails(true);

    await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect((await objectFor(USER_A.userId).recallSyncState()).listing).toEqual({
      failedAt: now,
      failures: 1,
    });
    for (let i = 0; i < 5; i += 1) {
      const run = await step(a, h);
      expect(run.outcome).toBe("idle");
      expect(run.log).toEqual([]);
    }
    expect(count(h, "folders:start")).toBe(1);

    h.setListingFails(false);
    h.setNow(now + RECALL_CHECK_INTERVAL_MS);
    expect((await step(a, h)).outcome).toBe("folders");
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state.folders).toEqual([INBOX]);
    expect(state.listing).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The folder list is listed again (26-REVIEW-2 WR-02, 26-REVIEW IN-04)
// ---------------------------------------------------------------------------

describe("the folder list is listed again, so a replaced archive folder is found (26-REVIEW-2 WR-02)", () => {
  const ARCHIVE_2 = "Archive 2";

  /** INBOX (3), the archive (4) and a second folder (6) the listing may name later. */
  function threeFolders(): StepHarness {
    return fakeStepDeps({
      folders: [INBOX, ARCHIVE],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: scriptedMessages(3) },
        [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(4) },
        [ARCHIVE_2]: { uidValidity: 500, messages: scriptedMessages(6) },
      },
    });
  }

  /** Drive INBOX and the archive to built through real steps. */
  async function buildBoth(a: Principal, h: StepHarness): Promise<void> {
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    await passPause(USER_A.userId);
    expect(await ledgerCount(USER_A.userId)).toBe(7);
  }

  it("a folder dropped as gone is followed by a listing, and the folder the account now marks as its archive is built", async () => {
    const a = await testPrincipal(USER_A);
    const h = threeFolders();
    const now = Date.now();
    h.setNow(now);
    await buildBoth(a, h);

    // The archive is deleted, and another folder is marked as the archive.
    h.setGone(ARCHIVE, true);
    h.setFolders([INBOX, ARCHIVE_2]);
    const t = now + 6 * MINUTE;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("checked");
    expect((await step(a, h)).outcome).toBe("gone");
    expect(await ledgerCount(USER_A.userId)).toBe(3);
    expect((await objectFor(USER_A.userId).recallSyncState()).listedAt).toBeNull();

    await passPause(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("folders");
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state.folders).toEqual([INBOX, ARCHIVE_2]);
    expect(state.listedAt).toBe(t);

    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("done");
    expect(await ledgerCount(USER_A.userId)).toBe(3 + 6);
    expect((await rowOf(USER_A.userId, ARCHIVE_2))!.stage).toBe("built");
  });

  it("a day after the last listing the folders are listed again; a renamed archive loses its old vectors first, and the new name is built", async () => {
    const a = await testPrincipal(USER_A);
    const h = threeFolders();
    const now = Date.now();
    h.setNow(now);
    await buildBoth(a, h);

    // A minute short of a day: no listing, INBOX's check instead.
    h.setFolders([INBOX, ARCHIVE_2]);
    h.setNow(now + RECALL_RELIST_INTERVAL_MS - MINUTE);
    expect((await step(a, h)).outcome).toBe("checked");
    expect(h.log.filter((entry) => entry === "folders:start")).toHaveLength(1);
    await passPause(USER_A.userId);

    // A day: the listing comes before any check.
    const t = now + RECALL_RELIST_INTERVAL_MS;
    h.setNow(t);
    const run = await step(a, h);
    expect(run.outcome).toBe("folders");
    expect(run.log).toEqual(["lease", "enter", "folders:start", "folders:end", "exit"]);
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state.folders).toEqual([INBOX, ARCHIVE_2]);
    expect(state.listedAt).toBe(t);
    // The old archive's vectors, sync row and cursor are gone; INBOX's stay.
    expect(await ledgerCount(USER_A.userId)).toBe(3);
    expect(h.index.vectors.size).toBe(3);
    const keys = (await recallTables(USER_A.userId)).state.map((row) => row.split("=")[0]);
    expect(keys).not.toContain(`sync:${ARCHIVE}`);
    expect(keys).not.toContain(`cursor:${ARCHIVE}`);
    expect(keys).toContain(`sync:${INBOX}`);

    // Then the new name is seeded and built, with no second listing.
    await passPause(USER_A.userId);
    const outcomes: StepOutcome[] = [];
    for (let n = 0; n < 4; n += 1) {
      await passPause(USER_A.userId);
      outcomes.push((await step(a, h)).outcome);
    }
    expect(outcomes).toContain("seeded");
    expect(outcomes).not.toContain("folders");
    expect((await rowOf(USER_A.userId, ARCHIVE_2))!.stage).toBe("built");
    expect(await ledgerCount(USER_A.userId)).toBe(3 + 6);
  });

  it("a listing that names no archive folder keeps the stored one and its index", async () => {
    const a = await testPrincipal(USER_A);
    const h = threeFolders();
    const now = Date.now();
    h.setNow(now);
    await buildBoth(a, h);

    h.setFolders([INBOX]);
    const t = now + RECALL_RELIST_INTERVAL_MS;
    h.setNow(t);
    expect((await step(a, h)).outcome).toBe("folders");
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state.folders).toEqual([INBOX, ARCHIVE]);
    expect(state.listedAt).toBe(t);
    expect(await ledgerCount(USER_A.userId)).toBe(7);
    expect((await rowOf(USER_A.userId, ARCHIVE))!.stage).toBe("built");
    // Listed: the next step is a check, not another listing.
    expect((await step(a, h)).outcome).toBe("checked");
  });

  it("a listing again that fails is waited out, and the stored list is worked on meanwhile", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(5) } },
    });
    const now = Date.now();
    h.setNow(now);
    await buildInbox(a, h);

    h.setListingFails(true);
    const t = now + RECALL_RELIST_INTERVAL_MS;
    h.setNow(t);
    await expect(recallStep(a, h.deps)).rejects.toBeInstanceOf(RecallBuildError);
    expect((await objectFor(USER_A.userId).recallSyncState()).listing).toEqual({
      failedAt: t,
      failures: 1,
    });

    // Inside the listing's wait: INBOX is still checked, then nothing.
    expect((await step(a, h)).outcome).toBe("checked");
    expect((await step(a, h)).outcome).toBe("idle");
    expect(h.log.filter((entry) => entry === "folders:start")).toHaveLength(2);

    // After it: listed again.
    h.setListingFails(false);
    h.setNow(t + RECALL_CHECK_INTERVAL_MS);
    expect((await step(a, h)).outcome).toBe("folders");
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state.listing).toBeNull();
    expect(state.listedAt).toBe(t + RECALL_CHECK_INTERVAL_MS);
  });
});
