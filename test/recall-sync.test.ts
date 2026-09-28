// One recall build step: the slot first, then at most one IMAP session
// (Phase 26, D-12 to D-15, D-27, D-29, plan 26-03).
//
// Everything runs against the REAL `UserAgent` in the pool and the REAL
// connection lease. The store, the model, the page source and the reads are
// the shared fakes in ./fixtures/fake-step-deps.ts, which log every lease entry
// and every read's start and end. Slot state is seeded through
// `runInDurableObject`, the way test/recall-build.test.ts seeds it.
//
// Recall is inherent: nothing is turned on before the first step.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import {
  ensureRecallSchema,
  type SyncRow,
  utcDay,
  writeState,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import type { FolderListing, FolderSummary } from "../src/mail/service";
import type { Principal } from "../src/principal";
import {
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
} from "../src/recall/retention";
import { recallFoldersOf, recallStep, type StepOutcome } from "../src/recall/sync";
import { scriptedMessages } from "./fixtures/fake-recall-source";
import { fakeStepDeps, type StepHarness } from "./fixtures/fake-step-deps";
import { USER_A, testPrincipal } from "./fixtures/two-users";

const DAY_MS = 24 * 60 * 60 * 1000;
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

/** Two scripted folders: 30 messages in INBOX, 10 in the archive. */
function twoFolders(): StepHarness {
  return fakeStepDeps({
    folders: [INBOX, ARCHIVE],
    mailboxes: {
      [INBOX]: { uidValidity: 100, messages: scriptedMessages(30) },
      [ARCHIVE]: { uidValidity: 300, messages: scriptedMessages(10) },
    },
  });
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

function syncState(userId: string) {
  return objectFor(userId).recallSyncState();
}

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

beforeEach(async () => {
  await resetObject(USER_A.userId);
});

// ---------------------------------------------------------------------------
// The slot, before anything else (D-29)
// ---------------------------------------------------------------------------

describe("recallStep reads the slot first, and a refusal opens nothing (D-29, T-26-45)", () => {
  const seeds: [StepOutcome, (sql: SqlStorage) => void][] = [
    ["destroying", (sql) => writeState(sql, "destroy_pending", "1")],
    [
      "busy",
      (sql) =>
        writeState(sql, "page", JSON.stringify({ token: "live", expiresAt: Date.now() + 60_000 })),
    ],
    ["paused", (sql) => writeState(sql, "last_page_at", String(Date.now() - 10_000))],
    [
      "quota",
      (sql) => {
        writeState(sql, "pages_day", utcDay(Date.now()));
        writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
      },
    ],
    [
      "full",
      (sql) => {
        sql.exec(
          `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
           INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
           SELECT printf('%064x', x), 'Archive', 1, ? FROM c`,
          RECALL_MAX_VECTORS - RECALL_PAGE_SIZE + 1,
          Date.now() + DAY_MS,
        );
      },
    ],
  ];

  it.each(seeds)("answers %s with no lease, no read and no write", async (word, seed) => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    await withSql(USER_A.userId, seed);
    const before = await recallTables(USER_A.userId);

    const { outcome, log } = await step(a, h);

    expect(outcome).toBe(word);
    expect(log).toEqual([]);
    expect(h.sources[INBOX]!.calls).toEqual([]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("stops at the slot even when a folder is waiting to be seeded", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    expect((await step(a, h)).outcome).toBe("folders");
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });

    const { outcome, log } = await step(a, h);

    expect(outcome).toBe("quota");
    expect(log).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Folders, seed, pages, built, idle (D-12, D-13, D-14, D-27)
// ---------------------------------------------------------------------------

describe("recallStep does one session of work, in the fixed order (D-13, D-27)", () => {
  it("lists folders, seeds, builds page by page to built, then the archive, then idles", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    const now = Date.now();
    h.setNow(now);

    // 1. No folder list: list them in one session and store them.
    let run = await step(a, h);
    expect(run.outcome).toBe("folders");
    expect(run.log).toEqual(["lease", "enter", "folders:start", "folders:end", "exit"]);
    expect((await syncState(USER_A.userId)).folders).toEqual([INBOX, ARCHIVE]);

    // 2. INBOX is at seed: the status check alone, and no page.
    run = await step(a, h);
    expect(run.outcome).toBe("seeded");
    expect(run.log).toEqual([
      "lease",
      "enter",
      `snapshot:${INBOX}:start`,
      `snapshot:${INBOX}:end`,
      "exit",
    ]);
    expect(h.sources[INBOX]!.calls).toEqual([]);
    expect((await syncState(USER_A.userId)).sync[INBOX]).toEqual({
      stage: "build",
      state: { mailbox: INBOX, uidValidity: 100, uidNext: 31, highestModseq: "7" },
      checkedAt: now,
      reconciledAt: null,
      due: null,
      seen: null,
      failedAt: null,
      failures: 0,
    });

    // 3. INBOX is at build: one page from the top, indexed.
    run = await step(a, h);
    expect(run.outcome).toBe("indexed");
    expect(run.log).toEqual(["lease", "enter", `page:${INBOX}:start`, `page:${INBOX}:end`, "exit"]);
    expect(h.sources[INBOX]!.calls).toEqual([{ kind: "page", mailbox: INBOX, cursor: null }]);
    expect(await ledgerCount(USER_A.userId)).toBe(RECALL_PAGE_SIZE);
    expect((await syncState(USER_A.userId)).sync[INBOX]!.stage).toBe("build");

    // 4. Too early: the object says paused, and nothing runs.
    run = await step(a, h);
    expect(run.outcome).toBe("paused");
    expect(run.log).toEqual([]);

    // 5. After the pause: the next page from the stored cursor; the source has
    //    no more, so INBOX is built.
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("done");
    expect(h.sources[INBOX]!.calls[1]).toEqual({
      kind: "page",
      mailbox: INBOX,
      cursor: { mailbox: INBOX, uidValidity: 100, lastUid: 6 },
    });
    expect(await ledgerCount(USER_A.userId)).toBe(30);
    expect((await syncState(USER_A.userId)).sync[INBOX]!.stage).toBe("built");

    // 6. The archive is the first folder not built: it seeds, then builds.
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("seeded");
    expect(run.log).toContain(`snapshot:${ARCHIVE}:start`);
    run = await step(a, h);
    expect(run.outcome).toBe("done");
    expect(h.sources[ARCHIVE]!.calls).toEqual([{ kind: "page", mailbox: ARCHIVE, cursor: null }]);
    expect(await ledgerCount(USER_A.userId)).toBe(40);
    expect((await syncState(USER_A.userId)).sync[ARCHIVE]!.stage).toBe("built");

    // 7. Every folder built: idle, and nothing is read.
    await passPause(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("idle");
    expect(run.log).toEqual([]);
  });

  it("stores INBOX alone when the listing gives no archive folder", async () => {
    const a = await testPrincipal(USER_A);
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: scriptedMessages(3) } },
    });

    expect((await step(a, h)).outcome).toBe("folders");
    expect((await syncState(USER_A.userId)).folders).toEqual([INBOX]);
  });

  it("a validity reset sends the folder back to seed with no state", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await step(a, h)).outcome).toBe("seeded");
    expect((await step(a, h)).outcome).toBe("indexed");

    await passPause(USER_A.userId);
    h.sources[INBOX]!.setValidity(200);
    const run = await step(a, h);

    expect(run.outcome).toBe("reset");
    expect((await syncState(USER_A.userId)).sync[INBOX]).toEqual(SEED_ROW);
  });

  it("a folder the status check reports gone is dropped from the list; INBOX never is", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    const stub = objectFor(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("folders");
    expect(
      await stub.recallSetSync(INBOX, { ...SEED_ROW, stage: "built" }),
    ).toEqual({ ok: true });

    h.setSnapshot(ARCHIVE, { mailbox: ARCHIVE, answered: false, gone: true });
    expect((await step(a, h)).outcome).toBe("gone");
    expect((await syncState(USER_A.userId)).folders).toEqual([INBOX]);

    // INBOX reported gone: nothing is dropped. The check is recorded as a
    // failure (CR-01), so INBOX is not asked again on the very next call. The
    // archive's removal took the page slot, so the pause is waited out first.
    await passPause(USER_A.userId);
    expect(await stub.recallSetSync(INBOX, SEED_ROW)).toEqual({ ok: true });
    h.setSnapshot(INBOX, { mailbox: INBOX, answered: false, gone: true });
    const now = Date.now();
    h.setNow(now);
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect((await syncState(USER_A.userId)).folders).toEqual([INBOX]);
    expect((await syncState(USER_A.userId)).sync[INBOX]).toEqual({
      ...SEED_ROW,
      failedAt: now,
      failures: 1,
    });
    expect((await step(a, h)).outcome).toBe("idle");
  });

  it("a status check that does not answer is recorded as a failure; the next step moves on, and the folder is asked again once its wait has passed", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    const now = Date.now();
    h.setNow(now);
    expect((await step(a, h)).outcome).toBe("folders");

    h.setSnapshot(INBOX, { mailbox: INBOX, answered: false });
    expect((await step(a, h)).outcome).toBe("unanswered");
    expect((await syncState(USER_A.userId)).sync[INBOX]).toEqual({
      ...SEED_ROW,
      failedAt: now,
      failures: 1,
    });

    // INBOX is waiting, so the next step seeds the archive instead.
    let run = await step(a, h);
    expect(run.outcome).toBe("seeded");
    expect(run.log).toContain(`snapshot:${ARCHIVE}:start`);
    expect(run.log).not.toContain(`snapshot:${INBOX}:start`);

    // Once the wait has passed, INBOX is asked again, and seeds.
    h.setSnapshot(INBOX, null);
    h.setNow(now + 5 * 60 * 1000);
    run = await step(a, h);
    expect(run.outcome).toBe("seeded");
    expect(run.log).toContain(`snapshot:${INBOX}:start`);
  });
});

// ---------------------------------------------------------------------------
// The lease (D-27)
// ---------------------------------------------------------------------------

describe("recallStep and the person's connection lease", () => {
  it("a lease held by another request: lease_busy, nothing read, nothing stored", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    const stub = objectFor(USER_A.userId);

    // No folder list yet.
    expect((await stub.acquire()).held).toBe(true);
    let run = await step(a, h);
    expect(run.outcome).toBe("lease_busy");
    expect(run.log).toEqual(["lease"]);
    expect((await syncState(USER_A.userId)).folders).toBeNull();

    // At seed, once the other request's lease is gone.
    await runInDurableObject(objectFor(USER_A.userId), (_i, state) => {
      state.storage.kv.delete("lease");
    });
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await stub.acquire()).held).toBe(true);
    const before = await recallTables(USER_A.userId);
    run = await step(a, h);
    expect(run.outcome).toBe("lease_busy");
    expect(run.log).toEqual(["lease"]);
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });

  it("at build, a held lease reads no page and leaves the folder at build", async () => {
    const a = await testPrincipal(USER_A);
    const h = twoFolders();
    const stub = objectFor(USER_A.userId);
    expect((await step(a, h)).outcome).toBe("folders");
    expect((await step(a, h)).outcome).toBe("seeded");

    expect((await stub.acquire()).held).toBe(true);
    const run = await step(a, h);

    expect(run.outcome).toBe("lease_busy");
    expect(h.sources[INBOX]!.calls).toEqual([]);
    expect((await syncState(USER_A.userId)).sync[INBOX]!.stage).toBe("build");
  });
});

// ---------------------------------------------------------------------------
// The folder choice (D-12)
// ---------------------------------------------------------------------------

function folder(wireName: string, role: FolderSummary["role"], roleSource: FolderSummary["roleSource"]): FolderSummary {
  return {
    id: `id-${wireName}`,
    wireName,
    displayName: wireName,
    attributes: [],
    role,
    roleSource,
    totalCount: null,
    unreadCount: null,
  };
}

function listing(folders: FolderSummary[]): FolderListing {
  return { folders, delimiter: "/", countsSource: "list-status" };
}

describe("recallFoldersOf keeps INBOX and the archive folder, and nothing else (D-12)", () => {
  const others = [
    folder("INBOX", "inbox", "name-match"),
    folder("Drafts", "drafts", "special-use"),
    folder("Sent Messages", "sent", "special-use"),
    folder("Junk", "junk", "special-use"),
    folder("Deleted Messages", "trash", "special-use"),
    folder("Receipts", null, null),
  ];

  it("INBOX then the archive folder's wire name", () => {
    expect(recallFoldersOf(listing([...others, folder("Archive", "archive", "special-use")]))).toEqual([
      "INBOX",
      "Archive",
    ]);
  });

  it("INBOX alone when there is no archive folder", () => {
    expect(recallFoldersOf(listing(others))).toEqual(["INBOX"]);
  });

  it("INBOX alone when two folders claim the archive role in the same tier", () => {
    expect(
      recallFoldersOf(
        listing([
          ...others,
          folder("Archive", "archive", "special-use"),
          folder("Archive 2", "archive", "special-use"),
        ]),
      ),
    ).toEqual(["INBOX"]);
  });
});

// ---------------------------------------------------------------------------
// The object's two setters (D-15, T-26-46)
// ---------------------------------------------------------------------------

describe("recallSetFolders and recallSetSync refuse what they must not store", () => {
  const state = (mailbox: string) => ({
    mailbox,
    uidValidity: 100,
    uidNext: 31,
    highestModseq: "7",
  });

  it("recallSetSync stores a row parseSyncRow accepts for its own mailbox, and refuses others", async () => {
    const stub = objectFor(USER_A.userId);
    const good = { ...SEED_ROW, stage: "build", state: state(INBOX), checkedAt: 1 };

    expect(await stub.recallSetSync(INBOX, good)).toEqual({ ok: true });
    expect((await stub.recallSyncState()).sync[INBOX]).toEqual(good);

    expect(await stub.recallSetSync(INBOX, { ...good, stage: "done" })).toEqual({
      ok: false,
      reason: "invalid",
    });
    expect(await stub.recallSetSync(INBOX, { ...good, due: undefined })).toEqual({
      ok: false,
      reason: "invalid",
    });
    expect(await stub.recallSetSync(INBOX, { ...good, state: state(ARCHIVE) })).toEqual({
      ok: false,
      reason: "invalid",
    });
    expect(await stub.recallSetSync(INBOX, { ...good, seen: state(ARCHIVE) })).toEqual({
      ok: false,
      reason: "invalid",
    });
    expect(await stub.recallSetSync("", good)).toEqual({ ok: false, reason: "invalid" });
    expect(await stub.recallSetSync(42, good)).toEqual({ ok: false, reason: "invalid" });
    expect((await stub.recallSyncState()).sync[INBOX]).toEqual(good);
  });

  it("recallSetFolders stores INBOX first, up to four, and refuses anything else", async () => {
    const stub = objectFor(USER_A.userId);

    expect(await stub.recallSetFolders([INBOX, ARCHIVE])).toEqual({ ok: true });
    for (const bad of [
      [],
      [ARCHIVE, INBOX],
      ["inbox"],
      [INBOX, "a", "b", "c", "d"],
      [INBOX, ""],
      [INBOX, INBOX],
      [INBOX, 7],
      [INBOX, "x".repeat(1025)],
      "INBOX",
      null,
    ]) {
      expect(await stub.recallSetFolders(bad)).toEqual({ ok: false, reason: "invalid" });
    }
    expect(await stub.recallSetFolders([INBOX, "a", "b", "c"])).toEqual({ ok: true });
    expect((await stub.recallSyncState()).folders).toEqual([INBOX, "a", "b", "c"]);
  });

  it("both refuse destroying while the pending-destroy flag is set, and write nothing", async () => {
    const stub = objectFor(USER_A.userId);
    await withSql(USER_A.userId, (sql) => writeState(sql, "destroy_pending", "1"));
    const before = await recallTables(USER_A.userId);

    expect(await stub.recallSetFolders([INBOX])).toEqual({ ok: false, reason: "destroying" });
    expect(await stub.recallSetSync(INBOX, SEED_ROW)).toEqual({
      ok: false,
      reason: "destroying",
    });
    expect(await recallTables(USER_A.userId)).toEqual(before);
  });
});
