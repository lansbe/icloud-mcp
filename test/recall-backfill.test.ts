// The recall backfill: one call, several pages, one leased session at a time
// (Phase 29.1.1, RCLL-14, RCLL-15; LD-4 to LD-10 in 29.1.1-01-PLAN.md).
//
// Everything runs against the REAL `UserAgent` in the pool and the REAL
// connection lease. The store, the model, the page source and the reads are the
// shared fakes in ./fixtures/fake-step-deps.ts, which log every lease entry and
// every read's start and end. Slot state is seeded through `runInDurableObject`,
// the way test/recall-sync.test.ts seeds it.
//
// What is proved: a backfill page skips the ordinary one-minute pause and the
// ordinary day count, and nothing else; the object grants it only for a folder
// whose first build is not finished; one call fills several pages, and every
// page takes the lease itself, opens one session and gives the lease back before
// the next one starts.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ensureRecallSchema,
  RECALL_PARK_AFTER_FAILURES,
  readState,
  type SyncRow,
  utcDay,
  writeState,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import type { FolderState } from "../src/change-marker";
import type { Principal } from "../src/principal";
import { runRecallBackfill } from "../src/recall/drive";
import {
  BACKFILL_REFUSED,
  RECALL_BACKFILL_TOOL_NAME,
  registerRecallBackfillTool,
} from "../src/mcp/tools/recall";
import { createRecallStore } from "../src/recall/index";
import {
  RECALL_BACKFILL_MAX_PAGES_PER_DAY,
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
} from "../src/recall/retention";
import {
  type BackfillLimits,
  type BackfillOutcome,
  RECALL_BACKFILL_BUDGET_MS,
  RECALL_BACKFILL_MAX_PAGES,
  recallBackfill,
  recallStep,
  type StepDeps,
} from "../src/recall/sync";
import { type FakeMessage, scriptedMessages } from "./fixtures/fake-recall-source";
import { fakeStepDeps, type StepHarness } from "./fixtures/fake-step-deps";
import { createFakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, testPrincipal } from "./fixtures/two-users";

const INBOX = "INBOX";
const ARCHIVE = "Archive";
const ORDINARY_CLIENT = "claude-desktop-client";
const DAY_MS = 24 * 60 * 60 * 1000;

/** The page kind under test, spelled once. */
const BACKFILL = "backfill";

type ToolAnswer = { isError?: boolean; content: { type: "text"; text: string }[] };
type BackfillCallback = () => Promise<ToolAnswer>;

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

function ledgerCount(userId: string): Promise<number> {
  return withSql(
    userId,
    (sql) => sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n,
  );
}

/** The ordinary day count, as the object stores it, for today. */
function ordinaryCount(userId: string): Promise<string | null> {
  return withSql(userId, (sql) =>
    readState(sql, "pages_day") === utcDay(Date.now()) ? readState(sql, "pages_count") : null,
  );
}

/** The backfill day count, as the object stores it, for today. */
function backfillCount(userId: string): Promise<string | null> {
  return withSql(userId, (sql) =>
    readState(sql, "backfill_day") === utcDay(Date.now()) ? readState(sql, "backfill_count") : null,
  );
}

function stateOf(mailbox: string, uidValidity: number, uidNext: number): FolderState {
  return { mailbox, uidValidity, uidNext, highestModseq: "7" };
}

/** A row at the build stage, as a seed leaves it. */
function buildRow(state: FolderState, over: Partial<SyncRow> = {}): SyncRow {
  return {
    stage: "build",
    state,
    checkedAt: Date.now(),
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

/**
 * The one-session rule, read from the harness log: every `lease` is followed by
 * at most one enter/exit pair, enter and exit alternate strictly, and every
 * read's start and end fall inside an enter/exit pair.
 */
function expectOneSessionAtATime(log: readonly string[]): void {
  let inside = false;
  let pairsSinceLease = 0;
  for (const entry of log) {
    if (entry === "lease") {
      expect(inside, "a lease was taken while a session was open").toBe(false);
      pairsSinceLease = 0;
    } else if (entry === "enter") {
      expect(inside, "a session was entered while another was open").toBe(false);
      pairsSinceLease += 1;
      expect(pairsSinceLease, "one lease held across two sessions").toBeLessThanOrEqual(1);
      inside = true;
    } else if (entry === "exit") {
      expect(inside, "a session exited that was not open").toBe(true);
      inside = false;
    } else if (entry.endsWith(":start") || entry.endsWith(":end")) {
      expect(inside, `${entry} outside a session`).toBe(true);
    }
  }
  expect(inside, "a session was left open").toBe(false);
}

/** The backfill tool's callback, taken from its registrar with a fake server. */
function backfillTool(
  h: StepHarness,
  grantClient: () => Promise<string | null> = async () => ORDINARY_CLIENT,
): BackfillCallback {
  let call: BackfillCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: BackfillCallback) {
      if (name === RECALL_BACKFILL_TOOL_NAME) call = handler;
    },
  };
  registerRecallBackfillTool(
    server as unknown as McpServer,
    h.deps.leased,
    testPrincipal(USER_A),
    grantClient,
    () => h.deps,
  );
  expect(call, `${RECALL_BACKFILL_TOOL_NAME} is not registered`).toBeDefined();
  return call!;
}

/** The trusted block, parsed. */
function trustedOf(answer: ToolAnswer): Record<string, unknown> {
  return JSON.parse(answer.content[0]!.text) as Record<string, unknown>;
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
});

// ---------------------------------------------------------------------------
// The tracer: one call, three pages, one leased session at a time
// ---------------------------------------------------------------------------

describe("the tracer: one backfill call indexes several pages, one leased session at a time (LD-4, LD-5)", () => {
  it("fills three pages of a folder mid-build, past an active pause and a spent ordinary day cap", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(60) } },
    });
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "last_page_at", String(Date.now()));
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });

    const answer = await backfillTool(h)();

    expect(answer.isError).not.toBe(true);
    expect(answer.content).toHaveLength(1);
    const trusted = trustedOf(answer);
    expect(trusted.thisCall).toMatchObject({ pages: 3, messages: 60 });
    expect(trusted.index).toBe("built");
    expect(await ledgerCount(USER_A.userId)).toBe(60);

    expect(h.log.filter((entry) => entry === "lease")).toHaveLength(3);
    expect(h.log.filter((entry) => entry === "enter")).toHaveLength(3);
    expectOneSessionAtATime(h.log);

    expect(await ordinaryCount(USER_A.userId)).toBe(String(RECALL_MAX_PAGES_PER_DAY));
    expect(await backfillCount(USER_A.userId)).toBe("3");
  });
});

// ---------------------------------------------------------------------------
// The object holds the backfill's limits (LD-5, LD-6)
// ---------------------------------------------------------------------------

/** Fill the ledger to within one page of the ceiling. */
function fillToCeiling(sql: SqlStorage): void {
  sql.exec(
    `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
     INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
     SELECT printf('%064x', x), 'INBOX', 100, ? FROM c`,
    RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1,
    Date.now() + DAY_MS,
  );
}

/** Every recall_state row, for a before-and-after compare. */
function stateRows(userId: string): Promise<string[]> {
  return withSql(userId, (sql) =>
    sql
      .exec<{ k: string; v: string }>("select k, v from recall_state order by k")
      .toArray()
      .map((row) => `${row.k}=${row.v}`),
  );
}

describe("the object grants a backfill page only for a folder at build, and keeps its limits", () => {
  it("RECALL_BACKFILL_MAX_PAGES_PER_DAY is exactly enough pages to fill the ceiling once: 400", () => {
    expect(RECALL_BACKFILL_MAX_PAGES_PER_DAY).toBe(RECALL_MAX_VECTORS / RECALL_PAGE_SIZE);
    expect(RECALL_BACKFILL_MAX_PAGES_PER_DAY).toBe(400);
  });

  const notAtBuild: [string, (userId: string) => Promise<void>][] = [
    ["no row", async (userId) => seedRows(userId, [INBOX], {})],
    [
      "a row at seed",
      async (userId) =>
        seedRows(userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61), { stage: "seed", state: null }) }),
    ],
    [
      "a row that is built",
      async (userId) =>
        seedRows(userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61), { stage: "built" }) }),
    ],
  ];

  it.each(notAtBuild)("%s: answers invalid and writes nothing", async (_label, seed) => {
    await seed(USER_A.userId);
    const before = await stateRows(USER_A.userId);

    const answer = await objectFor(USER_A.userId).recallBeginPage(INBOX, BACKFILL);

    expect(answer).toEqual({ ok: false, reason: "invalid" });
    expect(await stateRows(USER_A.userId)).toEqual(before);
  });

  it("refuses in the page start's own order, and skips only the pause and the ordinary count", async () => {
    const stub = objectFor(USER_A.userId);
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "destroy_pending", "1");
      writeState(sql, "page", JSON.stringify({ token: "live", expiresAt: Date.now() + 60_000 }));
      writeState(sql, "last_page_at", String(Date.now() - 1000));
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
      writeState(sql, "backfill_day", utcDay(Date.now()));
      writeState(sql, "backfill_count", String(RECALL_BACKFILL_MAX_PAGES_PER_DAY));
      fillToCeiling(sql);
    });

    expect(await stub.recallBeginPage(INBOX, BACKFILL)).toEqual({ ok: false, reason: "destroying" });
    await withSql(USER_A.userId, (sql) => sql.exec("delete from recall_state where k = 'destroy_pending'"));
    expect(await stub.recallBeginPage(INBOX, BACKFILL)).toEqual({ ok: false, reason: "busy" });
    await withSql(USER_A.userId, (sql) => sql.exec("delete from recall_state where k = 'page'"));
    // The pause 1 s ago and the ordinary count at its cap do not refuse.
    expect(await stub.recallBeginPage(INBOX, BACKFILL)).toEqual({ ok: false, reason: "quota" });
    await withSql(USER_A.userId, (sql) =>
      writeState(sql, "backfill_count", String(RECALL_BACKFILL_MAX_PAGES_PER_DAY - 1)),
    );
    expect(await stub.recallBeginPage(INBOX, BACKFILL)).toEqual({ ok: false, reason: "full" });
    await withSql(USER_A.userId, (sql) => sql.exec("delete from recall_vectors"));
    const granted = await stub.recallBeginPage(INBOX, BACKFILL);
    expect(granted.ok).toBe(true);
  });

  it("a granted page writes the slot and the start, counts on its own counter, and pauses an ordinary page", async () => {
    const stub = objectFor(USER_A.userId);
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", "7");
    });
    const before = Date.now();

    const granted = await stub.recallBeginPage(INBOX, BACKFILL);

    expect(granted.ok).toBe(true);
    const after = await withSql(USER_A.userId, (sql) => ({
      page: readState(sql, "page"),
      last: Number(readState(sql, "last_page_at")),
    }));
    expect(after.page).not.toBeNull();
    expect(after.last).toBeGreaterThanOrEqual(before);
    expect(await backfillCount(USER_A.userId)).toBe("1");
    expect(await ordinaryCount(USER_A.userId)).toBe("7");

    if (granted.ok) expect(await stub.recallEndPage(granted.pageToken, INBOX, { kind: "keep" })).toBe(true);
    await withSql(USER_A.userId, (sql) =>
      writeState(sql, "last_page_at", String(Number(readState(sql, "last_page_at")) - 1000)),
    );
    expect(await stub.recallBeginPage(INBOX, "build")).toEqual({ ok: false, reason: "paused" });
    expect(await ordinaryCount(USER_A.userId)).toBe("7");
  });

  it("the backfill count is per UTC day: yesterday's count reads as nothing today", async () => {
    const stub = objectFor(USER_A.userId);
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "backfill_day", utcDay(Date.now() - DAY_MS));
      writeState(sql, "backfill_count", String(RECALL_BACKFILL_MAX_PAGES_PER_DAY));
    });
    expect((await stub.recallSyncState()).backfill).toBe("free");

    expect((await stub.recallBeginPage(INBOX, BACKFILL)).ok).toBe(true);
    expect(await backfillCount(USER_A.userId)).toBe("1");
  });

  it("a destroy clears both backfill rows with the rest of recall_state", async () => {
    const stub = objectFor(USER_A.userId);
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    const granted = await stub.recallBeginPage(INBOX, BACKFILL);
    expect(granted.ok).toBe(true);
    expect(await backfillCount(USER_A.userId)).toBe("1");

    await runInDurableObject(stub, async (instance: UserAgent) => {
      const spy = vi.spyOn(instance, "vectorStore").mockReturnValue(createRecallStore(createFakeVectorize()));
      try {
        expect(await instance.destroyRecall()).toEqual({ ok: true });
      } finally {
        spy.mockRestore();
      }
    });

    expect(await stateRows(USER_A.userId)).toEqual([]);
  });

  it("recallSyncState answers the backfill field: free, a refusal, or unnamed, and never paused", async () => {
    const stub = objectFor(USER_A.userId);
    await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, 61)) });
    await withSql(USER_A.userId, (sql) => writeState(sql, "last_page_at", String(Date.now())));

    let state = await stub.recallSyncState();
    expect(state.slot).toBe("paused");
    expect(state.backfill).toBe("free");

    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "backfill_day", utcDay(Date.now()));
      writeState(sql, "backfill_count", String(RECALL_BACKFILL_MAX_PAGES_PER_DAY));
    });
    expect((await stub.recallSyncState()).backfill).toBe("quota");

    await withSql(USER_A.userId, (sql) => {
      sql.exec("delete from recall_state where k = 'backfill_count'");
      fillToCeiling(sql);
    });
    state = await stub.recallSyncState();
    expect(state.backfill).toBe("full");

    await withSql(USER_A.userId, (sql) => writeState(sql, "destroy_pending", "1"));
    expect((await stub.recallSyncState()).backfill).toBe("destroying");

    await resetObject(USER_A.userId);
    await runInDurableObject(stub, (_instance, st) => {
      st.storage.kv.put("own-name", "not-a-user-id");
    });
    expect((await stub.recallSyncState()).backfill).toBe("unnamed");
  });
});

// ---------------------------------------------------------------------------
// The engine loop, whole: listing, seed, both folders, and every stop
// ---------------------------------------------------------------------------

/** Run one backfill call, and hold the one-session rule on what it logged. */
async function backfill(
  a: Principal,
  h: StepHarness,
  deps: StepDeps = h.deps,
  limits: BackfillLimits = {},
): Promise<{ outcome: BackfillOutcome; log: string[] }> {
  const from = h.log.length;
  const outcome = await recallBackfill(a, deps, limits);
  const log = h.log.slice(from);
  expectOneSessionAtATime(log);
  expect(log.filter((entry) => entry === "enter")).toHaveLength(outcome.sessions);
  return { outcome, log };
}

function syncRowOf(userId: string, mailbox: string): Promise<SyncRow | undefined> {
  return objectFor(userId)
    .recallSyncState()
    .then((state) => state.sync[mailbox]);
}

/** A built row, as a finished build leaves it. */
function builtRow(state: FolderState, over: Partial<SyncRow> = {}): SyncRow {
  return buildRow(state, { stage: "built", ...over });
}

/** Every recall table, for a before-and-after compare. */
async function recallTables(userId: string) {
  return { state: await stateRows(userId), vectors: await ledgerCount(userId) };
}

/** Two scripted folders: `inbox` messages in INBOX, `archive` in the archive. */
function twoFolders(inbox: number, archive: number): StepHarness {
  return fakeStepDeps({
    folders: [INBOX, ARCHIVE],
    mailboxes: {
      [INBOX]: { uidValidity: 100, messages: scriptedMessages(inbox) },
      [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(archive) },
    },
  });
}

/** One folder, INBOX, with `count` messages, at build. */
async function inboxAtBuild(count: number): Promise<StepHarness> {
  const h = fakeStepDeps({
    folders: [INBOX],
    mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(count) } },
  });
  await seedRows(USER_A.userId, [INBOX], { [INBOX]: buildRow(stateOf(INBOX, 100, count + 1)) });
  return h;
}

/** Every vector id the store was asked to upsert, repeats kept. */
function upsertedIds(h: StepHarness): string[] {
  return h.index.calls
    .filter((call) => call.method === "upsert")
    .flatMap((call) => (call.args[0] as { id: string }[]).map((v) => v.id));
}

/** `count` messages from UID `from` up, dated yesterday. */
function messagesFrom(from: number, count: number): FakeMessage[] {
  return Array.from({ length: count }, (_, i) => ({
    uid: from + i,
    date: Date.now() - DAY_MS,
    text: `new message ${from + i}`,
    snippet: `New ${from + i}`,
  }));
}

describe("recallBackfill fills a person's index across calls, one session at a time", () => {
  it("a fresh person: one call lists, seeds INBOX, pages it, seeds the archive and pages it", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "built", pages: 3, sessions: 6 });
    expect(await ledgerCount(USER_A.userId)).toBe(40);
    expect((await syncRowOf(USER_A.userId, INBOX))!.stage).toBe("built");
    expect((await syncRowOf(USER_A.userId, ARCHIVE))!.stage).toBe("built");
    expect(log.filter((entry) => entry === "folders:start")).toHaveLength(1);
  });

  it("300 messages: the first call stops at the page limit, and the next resumes without reading a message twice", async () => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(300);

    const first = await backfill(a, h);
    expect(first.outcome).toEqual({
      stopped: "budget",
      pages: RECALL_BACKFILL_MAX_PAGES,
      sessions: RECALL_BACKFILL_MAX_PAGES,
    });
    expect(await ledgerCount(USER_A.userId)).toBe(250);
    const cursor = await withSql(USER_A.userId, (sql) => readState(sql, `cursor:${INBOX}`));
    expect(cursor).not.toBeNull();

    const second = await backfill(a, h);
    expect(second.outcome).toEqual({ stopped: "built", pages: 2, sessions: 2 });
    expect(await ledgerCount(USER_A.userId)).toBe(300);
    const ids = upsertedIds(h);
    expect(ids).toHaveLength(300);
    expect(new Set(ids).size).toBe(300);
    expect(h.sources[INBOX]!.calls).toHaveLength(12);
  });

  it("the time budget: no page starts once RECALL_BACKFILL_BUDGET_MS has passed since the call began", async () => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(300);
    const base = Date.now();
    // A clock that moves 3 s on every read.
    const reads = () => h.log.filter((entry) => entry.endsWith(":start")).length;
    const deps: StepDeps = { ...h.deps, now: () => base + 3000 * reads() };

    const { outcome } = await backfill(a, h, deps);

    const allowed = Math.ceil(RECALL_BACKFILL_BUDGET_MS / 3000);
    expect(allowed).toBeLessThan(RECALL_BACKFILL_MAX_PAGES);
    expect(outcome).toEqual({ stopped: "budget", pages: allowed, sessions: allowed });
    // The last page started before the budget ran out, and the next would not have.
    expect(3000 * (allowed - 1)).toBeLessThan(RECALL_BACKFILL_BUDGET_MS);
    expect(3000 * allowed).toBeGreaterThanOrEqual(RECALL_BACKFILL_BUDGET_MS);
  });

  it("the session budget: with maxSteps 4, no more than four sessions are opened", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(300, 10);

    const { outcome, log } = await backfill(a, h, h.deps, { maxPages: 50, maxSteps: 4 });

    expect(outcome).toEqual({ stopped: "budget", pages: 2, sessions: 4 });
    expect(log.filter((entry) => entry === "enter")).toHaveLength(4);
  });

  it("every folder built: stops as built, opens nothing and changes nothing", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31)),
      [ARCHIVE]: builtRow(stateOf(ARCHIVE, 300, 11)),
    });
    const before = await recallTables(USER_A.userId);

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "built", pages: 0, sessions: 0 });
    expect(log.filter((entry) => entry === "lease")).toHaveLength(0);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("a parked folder and a built one: built, with no session", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31)),
      [ARCHIVE]: buildRow(stateOf(ARCHIVE, 300, 11), {
        failures: RECALL_PARK_AFTER_FAILURES,
        failedAt: Date.now() + 1000,
      }),
    });

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "built", pages: 0, sessions: 0 });
    expect(log).toEqual([]);
  });

  it("a folder waiting out a failure, with nothing else to build: waiting, with no session", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31)),
      [ARCHIVE]: buildRow(stateOf(ARCHIVE, 300, 11), { failures: 1, failedAt: Date.now() }),
    });

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "waiting", pages: 0, sessions: 0 });
    expect(log).toEqual([]);
  });

  it("a page that fails is recorded as a step records it, and nothing opens after it", async () => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(60);
    const now = Date.now();
    h.setNow(now);
    h.setGone(INBOX, true);

    const { outcome, log } = await backfill(a, h);

    // The session that failed is counted; nothing opens after it.
    expect(outcome).toEqual({ stopped: "failed", pages: 0, sessions: 1 });
    expect(log).toEqual(["lease", "enter", `page:${INBOX}:start`, `page:${INBOX}:end`, "exit"]);
    const row = (await syncRowOf(USER_A.userId, INBOX))!;
    expect(row.failures).toBe(1);
    expect(row.failedAt).toBe(now);
  });

  it("a listing that fails is recorded; the next call, inside the wait, is waiting with no session", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    const now = Date.now();
    h.setNow(now);
    h.setListingFails(true);

    const first = await backfill(a, h);
    expect(first.outcome.stopped).toBe("failed");
    expect((await objectFor(USER_A.userId).recallSyncState()).listing).toEqual({
      failedAt: now,
      failures: 1,
    });

    const second = await backfill(a, h);
    expect(second.outcome).toEqual({ stopped: "waiting", pages: 0, sessions: 0 });
    expect(second.log).toEqual([]);
  });

  it("a lease held by another request at the first session: lease_busy, and nothing stored", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    expect((await objectFor(USER_A.userId).acquire()).held).toBe(true);
    const before = await recallTables(USER_A.userId);

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "lease_busy", pages: 0, sessions: 0 });
    expect(log).toEqual(["lease"]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("the lease taken by another request between pages 2 and 3: lease_busy after two pages, and the slot is ended", async () => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(100);
    const stub = objectFor(USER_A.userId);
    let leases = 0;
    const deps: StepDeps = {
      ...h.deps,
      leased: {
        async withConnectionLease(principal, fn) {
          leases += 1;
          if (leases === 3) expect((await stub.acquire()).held).toBe(true);
          return h.deps.leased.withConnectionLease(principal, fn);
        },
      },
    };

    const { outcome } = await backfill(a, h, deps);

    expect(outcome).toEqual({ stopped: "lease_busy", pages: 2, sessions: 2 });
    expect(await withSql(USER_A.userId, (sql) => readState(sql, "page"))).toBeNull();
    expect(await ledgerCount(USER_A.userId)).toBe(50);
  });

  const refusals: [BackfillOutcome["stopped"], (sql: SqlStorage) => void][] = [
    ["destroying", (sql) => writeState(sql, "destroy_pending", "1")],
    [
      "busy",
      (sql) =>
        writeState(sql, "page", JSON.stringify({ token: "live", expiresAt: Date.now() + 60_000 })),
    ],
    [
      "quota",
      (sql) => {
        writeState(sql, "backfill_day", utcDay(Date.now()));
        writeState(sql, "backfill_count", String(RECALL_BACKFILL_MAX_PAGES_PER_DAY));
      },
    ],
    ["full", fillToCeiling],
  ];

  it.each(refusals)("the object refuses as %s: stopped before any session", async (word, seed) => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(60);
    await withSql(USER_A.userId, seed);

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: word, pages: 0, sessions: 0 });
    expect(log).toEqual([]);
  });

  it("an object that does not know whose it is: unnamed, before any session", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    await runInDurableObject(objectFor(USER_A.userId), (_instance, state) => {
      state.storage.kv.put("own-name", "not-a-user-id");
    });

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "unnamed", pages: 0, sessions: 0 });
    expect(log).toEqual([]);
  });

  it("a built folder is never touched: no status check, no new mail and no deletion sync", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31), {
        checkedAt: Date.now() - DAY_MS,
        due: "new_mail",
        seen: stateOf(INBOX, 100, 33),
      }),
      [ARCHIVE]: buildRow(stateOf(ARCHIVE, 300, 11)),
    });
    h.addMessages(INBOX, messagesFrom(31, 2));

    const { outcome, log } = await backfill(a, h);

    expect(outcome).toEqual({ stopped: "built", pages: 1, sessions: 1 });
    for (const read of [`snapshot:${INBOX}:start`, `newMail:${INBOX}:start`, `uids:${INBOX}:start`]) {
      expect(log).not.toContain(read);
    }
    expect((await syncRowOf(USER_A.userId, INBOX))!.due).toBe("new_mail");
  });

  it("a validity change during the archive's build: back to seed, seeded again and paged from the top in the same call", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 60);
    await seedRows(USER_A.userId, [INBOX, ARCHIVE], {
      [INBOX]: builtRow(stateOf(INBOX, 100, 31)),
      [ARCHIVE]: buildRow(stateOf(ARCHIVE, 300, 61)),
    });
    let archivePages = 0;
    h.sources[ARCHIVE]!.onPage = () => {
      archivePages += 1;
      if (archivePages === 2) h.setValidity(ARCHIVE, 301);
    };

    const { outcome } = await backfill(a, h);

    // Page 1 under the old validity, the page that found the change (a
    // session, not a page), the seed, then three pages from the top.
    expect(outcome).toEqual({ stopped: "built", pages: 4, sessions: 6 });
    const validities = await withSql(USER_A.userId, (sql) =>
      sql
        .exec<{ v: number; n: number }>(
          "select uid_validity as v, count(*) as n from recall_vectors where mailbox = ? group by uid_validity",
          ARCHIVE,
        )
        .toArray(),
    );
    expect(validities).toEqual([{ v: 301, n: 60 }]);
    expect((await syncRowOf(USER_A.userId, ARCHIVE))!.state!.uidValidity).toBe(301);
  });

  it("the ordinary step is unchanged: paused for a minute after a backfill, and its day count did not move", async () => {
    const a = await testPrincipal(USER_A);
    const h = await inboxAtBuild(60);
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", "5");
    });

    const { outcome } = await backfill(a, h);
    expect(outcome.pages).toBe(3);

    const from = h.log.length;
    expect(await recallStep(a, h.deps)).toBe("paused");
    expect(h.log.slice(from)).toEqual([]);
    expect(await ordinaryCount(USER_A.userId)).toBe("5");
  });
});

// ---------------------------------------------------------------------------
// The runner: only an ordinary client's grant runs a backfill (LD-2, LD-3)
// ---------------------------------------------------------------------------

describe("runRecallBackfill runs only for an ordinary client's grant", () => {
  const refused: [string, string | null][] = [
    ["the autonomy client", AUTONOMY_CLIENT_ID],
    ["an empty client", ""],
    ["an unknown client", null],
  ];

  it.each(refused)("%s: refused, with no object call and no session", async (_label, client) => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);
    const ownName = () =>
      runInDurableObject(objectFor(USER_A.userId), (_i, state) => state.storage.kv.get("own-name"));
    // Every recall call to the object stores its own name; none has been made yet.
    expect(await ownName()).toBeUndefined();

    const run = await runRecallBackfill(a, h.deps.leased, async () => client, () => h.deps);

    expect(run).toEqual({ kind: "refused" });
    expect(h.log).toEqual([]);
    expect(await ownName()).toBeUndefined();
  });

  it("an ordinary client: runs", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders(30, 10);

    const run = await runRecallBackfill(a, h.deps.leased, async () => ORDINARY_CLIENT, () => h.deps);

    expect(run).toEqual({ kind: "ran", outcome: { stopped: "built", pages: 3, sessions: 6 } });
  });

  it("the tool answers the refusal with one fixed sentence, and indexes nothing", async () => {
    const h = twoFolders(30, 10);

    const answer = await backfillTool(h, async () => AUTONOMY_CLIENT_ID)();

    expect(answer.isError).toBe(true);
    expect(trustedOf(answer)).toEqual({ message: BACKFILL_REFUSED });
    expect(h.log).toEqual([]);
    expect(await ledgerCount(USER_A.userId)).toBe(0);
  });
});
