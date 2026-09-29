// The backfill tool's progress answer (Phase 29.1.1, RCLL-14, RCLL-16; LD-8 to
// LD-10 in 29.1.1-01-PLAN.md).
//
// Two halves. The pure half drives `backfillResult` directly, with progress
// reads and sync rows built by hand, so every stage, estimate rule and stop
// word is pinned without a server. The live half drives the tool's own
// callback through `registerRecallBackfillTool`, against the REAL `UserAgent`
// in the pool and the REAL connection lease, with the shared fakes in
// ./fixtures/fake-step-deps.ts behind its `depsFor` seam.
//
// What is proved: the answer is one trusted block of plain ASCII that says how
// far the build has got, names folders by role and never by name, quotes no
// mail, and says what to do next; a built index answers built and opens
// nothing; a refused grant makes no object call; and one person's call leaves
// another person's index exactly as it was.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AUTONOMY_CLIENT_ID, AUTONOMY_TOOLS } from "../src/agent/autonomy-client";
import {
  ensureRecallSchema,
  RECALL_PARK_AFTER_FAILURES,
  readState,
  type SyncRow,
  utcDay,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import type { FolderState } from "../src/change-marker";
import { toErrorCategory, ConnectionBusyError } from "../src/errors";
import {
  BACKFILL_NOTE,
  BACKFILL_PROGRESS_UNREAD,
  BACKFILL_REFUSED,
  BACKFILL_UNAVAILABLE,
  type BackfillAnswerInput,
  backfillResult,
  RECALL_BACKFILL_TOOL_NAME,
  registerRecallBackfillTool,
} from "../src/mcp/tools/recall";
import { RECALL_MAX_VECTORS, RECALL_TTL_MS } from "../src/recall/retention";
import { type BackfillOutcome, type BackfillStop, RECALL_BACKFILL_MAX_PAGES } from "../src/recall/sync";
import type { FakeMessage } from "./fixtures/fake-recall-source";
import { fakeStepDeps, type StepHarness } from "./fixtures/fake-step-deps";
import { USER_A, USER_B, type TestUser, testPrincipal } from "./fixtures/two-users";

const INBOX = "INBOX";
const ARCHIVE = "Archive";
const ORDINARY_CLIENT = "claude-desktop-client";
const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 8, 28, 12, 0, 0);

/** Every character in the answer is printable ASCII. */
const PLAIN_ASCII = /^[\x20-\x7e]*$/;

type ToolAnswer = { isError?: boolean; content: { type: "text"; text: string }[] };
type BackfillCallback = () => Promise<ToolAnswer>;

interface Answer {
  index: string;
  stopped: string;
  thisCall: { pages: number; messages: number; seconds: number };
  folders: {
    role: string;
    stage: string;
    indexed: number;
    estimate: number | null;
    reachedBack: string | null;
  }[];
  progress: string;
  next: string;
  note: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function ledgerCount(userId: string): Promise<number> {
  return withSql(
    userId,
    (sql) => sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n,
  );
}

function stateRows(userId: string): Promise<string[]> {
  return withSql(userId, (sql) =>
    sql
      .exec<{ k: string; v: string }>("select k, v from recall_state order by k")
      .toArray()
      .map((row) => `${row.k}=${row.v}`),
  );
}

function vectorRows(userId: string): Promise<string[]> {
  return withSql(userId, (sql) =>
    sql
      .exec<{ vector_id: string; mailbox: string; uid_validity: number; expires_at: number }>(
        "select vector_id, mailbox, uid_validity, expires_at from recall_vectors order by vector_id",
      )
      .toArray()
      .map((row) => `${row.vector_id}|${row.mailbox}|${row.uid_validity}|${row.expires_at}`),
  );
}

function backfillCount(userId: string): Promise<string | null> {
  return withSql(userId, (sql) =>
    readState(sql, "backfill_day") === utcDay(Date.now()) ? readState(sql, "backfill_count") : null,
  );
}

/** Insert `count` ledger rows for `mailbox`, each expiring at `expiresAt`. */
function insertRows(sql: SqlStorage, mailbox: string, count: number, expiresAt: number, tag: string) {
  for (let i = 0; i < count; i += 1) {
    sql.exec(
      "insert into recall_vectors (vector_id, mailbox, uid_validity, expires_at) values (?, ?, ?, ?)",
      `${tag}-${i}`,
      mailbox,
      1,
      expiresAt + i * 1000,
    );
  }
}

function stateOf(mailbox: string, uidValidity: number, uidNext: number): FolderState {
  return { mailbox, uidValidity, uidNext, highestModseq: "7" };
}

function row(stage: SyncRow["stage"], over: Partial<SyncRow> = {}): SyncRow {
  return {
    stage,
    state: stage === "seed" ? null : stateOf(INBOX, 100, 1000),
    checkedAt: NOW - DAY_MS,
    reconciledAt: null,
    due: null,
    seen: null,
    failedAt: null,
    failures: 0,
    ...over,
  };
}

/** Messages `daysAgo` days back, with a subject and text carrying `canary`. */
function canaryMessages(count: number, daysAgo: number, canary: string): FakeMessage[] {
  const out: FakeMessage[] = [];
  for (let uid = 1; uid <= count; uid += 1) {
    out.push({
      uid,
      date: Date.now() - daysAgo * DAY_MS,
      text: `From: ${canary}@example.com about ${canary} number ${uid}`,
      snippet: `Subject ${canary} ${uid}`,
    });
  }
  return out;
}

/** The backfill tool's callback and its registered config, taken with a fake server. */
function backfillTool(
  h: StepHarness,
  user: TestUser = USER_A,
  grantClient: () => Promise<string | null> = async () => ORDINARY_CLIENT,
): { call: BackfillCallback; config: Record<string, unknown> } {
  let call: BackfillCallback | undefined;
  let config: Record<string, unknown> | undefined;
  const server = {
    registerTool(name: string, options: Record<string, unknown>, handler: BackfillCallback) {
      if (name === RECALL_BACKFILL_TOOL_NAME) {
        call = handler;
        config = options;
      }
    },
  };
  registerRecallBackfillTool(
    server as unknown as McpServer,
    h.deps.leased,
    testPrincipal(user),
    grantClient,
    () => h.deps,
  );
  expect(call, `${RECALL_BACKFILL_TOOL_NAME} is not registered`).toBeDefined();
  return { call: call!, config: config! };
}

function parse(answer: ToolAnswer): Answer {
  expect(answer.content).toHaveLength(1);
  return JSON.parse(answer.content[0]!.text) as Answer;
}

/** A pure answer input with defaults a test overrides. */
function input(over: Partial<BackfillAnswerInput> = {}): BackfillAnswerInput {
  return {
    before: { total: 0, mailboxes: [] },
    after: { total: 0, mailboxes: [] },
    state: { folders: [INBOX], listedAt: NOW - DAY_MS, sync: {} },
    outcome: { stopped: "budget", pages: 0, sessions: 0 },
    now: NOW,
    startedAt: NOW,
    ...over,
  };
}

/** The pure answer, parsed, for one inbox holding `count` messages back `daysBack` days. */
function inboxAnswer(stage: SyncRow["stage"], count: number, daysBack: number): Answer {
  const oldestExpiry = NOW - daysBack * DAY_MS + RECALL_TTL_MS;
  return parse(
    backfillResult(
      input({
        state: { folders: [INBOX], listedAt: NOW - DAY_MS, sync: { [INBOX]: row(stage) } },
        after: { total: count, mailboxes: [{ mailbox: INBOX, count, oldestExpiry }] },
      }),
    ) as ToolAnswer,
  );
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
  await resetObject(USER_B.userId);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// The object's progress read
// ---------------------------------------------------------------------------

describe("recallProgress: this object's own ledger, per mailbox", () => {
  it("an empty ledger: total 0 and an empty list", async () => {
    expect(await objectFor(USER_A.userId).recallProgress()).toEqual({ total: 0, mailboxes: [] });
  });

  it("answers each mailbox's count and earliest expiry, as a list, and writes nothing", async () => {
    await withSql(USER_A.userId, (sql) => {
      insertRows(sql, INBOX, 3, 5_000_000, "i");
      insertRows(sql, ARCHIVE, 2, 7_000_000, "a");
    });
    const stateBefore = await stateRows(USER_A.userId);
    const vectorsBefore = await vectorRows(USER_A.userId);

    const progress = await objectFor(USER_A.userId).recallProgress();

    expect(progress.total).toBe(5);
    expect(Array.isArray(progress.mailboxes)).toBe(true);
    expect([...progress.mailboxes].sort((x, y) => x.mailbox.localeCompare(y.mailbox))).toEqual([
      { mailbox: ARCHIVE, count: 2, oldestExpiry: 7_000_000 },
      { mailbox: INBOX, count: 3, oldestExpiry: 5_000_000 },
    ]);
    expect(await stateRows(USER_A.userId)).toEqual(stateBefore);
    expect(await vectorRows(USER_A.userId)).toEqual(vectorsBefore);
  });

  it("answers only about the object it is called on", async () => {
    await withSql(USER_B.userId, (sql) => insertRows(sql, INBOX, 4, 5_000_000, "b"));

    expect(await objectFor(USER_A.userId).recallProgress()).toEqual({ total: 0, mailboxes: [] });
    expect((await objectFor(USER_B.userId).recallProgress()).total).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// The answer, pure
// ---------------------------------------------------------------------------

describe("backfillResult: stages, estimates and sentences", () => {
  it("a building inbox: the owner's example shape, with an estimate and how far back", () => {
    // 1,250 messages over the last 45 days of a 90-day window: about 2,500.
    const answer = inboxAnswer("build", 1250, 45);
    const back = new Date(NOW - 45 * DAY_MS);

    expect(answer.folders).toEqual([
      {
        role: "inbox",
        stage: "building",
        indexed: 1250,
        estimate: 2500,
        reachedBack: back.toISOString().slice(0, 10),
      },
    ]);
    expect(answer.progress).toBe("Inbox: 1,250 of about 2,500 messages indexed, back to Aug 14.");
  });

  it("rounds the estimate up: to 50 below 1,000, and to 100 from 1,000", () => {
    // 130 over 45 days: 260, rounded up to 300.
    expect(inboxAnswer("build", 130, 45).folders[0]!.estimate).toBe(300);
    // 1,234 over 45 days: 2,468, rounded up to 2,500.
    expect(inboxAnswer("build", 1234, 45).folders[0]!.estimate).toBe(2500);
    // 1,010 over 90 days: 1,010, rounded up to 1,100.
    expect(inboxAnswer("build", 1010, 90).folders[0]!.estimate).toBe(1100);
  });

  it("never estimates below the count", () => {
    // 500 over 100 days (a message dated outside the window): 450, but at least 500.
    expect(inboxAnswer("build", 500, 100).folders[0]!.estimate).toBe(500);
  });

  it("caps the estimate at the vector ceiling, and says there is more mail than the index can hold", () => {
    const answer = inboxAnswer("build", 6000, 30);

    expect(answer.folders[0]!.estimate).toBe(RECALL_MAX_VECTORS);
    expect(answer.progress).toBe(
      "Inbox: 6,000 messages indexed, back to Aug 29. There is more mail than the index can hold.",
    );
  });

  it("a span under a day: no estimate, and it says it is too early", () => {
    const answer = inboxAnswer("build", 75, 0.5);

    expect(answer.folders[0]!.estimate).toBeNull();
    expect(answer.progress).toBe(
      "Inbox: 75 messages indexed, back to Sep 28. It is too early to estimate how many there are.",
    );
  });

  it("a built folder: the estimate is the count, and it says all of the window is indexed", () => {
    const answer = inboxAnswer("built", 1980, 88);

    expect(answer.folders[0]).toMatchObject({ stage: "built", indexed: 1980, estimate: 1980 });
    expect(answer.progress).toBe("Inbox: all 1,980 messages from the last 90 days indexed.");
  });

  it("the window's day count in the sentence comes from RECALL_TTL_MS", () => {
    expect(inboxAnswer("built", 10, 3).progress).toContain(
      `from the last ${RECALL_TTL_MS / DAY_MS} days`,
    );
  });

  it("not started: no row, or a row at seed; no estimate and no date", () => {
    const answer = parse(
      backfillResult(
        input({
          state: {
            folders: [INBOX, ARCHIVE],
            listedAt: NOW - DAY_MS,
            sync: { [INBOX]: row("seed") },
          },
        }),
      ) as ToolAnswer,
    );

    expect(answer.folders).toEqual([
      { role: "inbox", stage: "not_started", indexed: 0, estimate: null, reachedBack: null },
      { role: "archive", stage: "not_started", indexed: 0, estimate: null, reachedBack: null },
    ]);
    expect(answer.progress).toBe("Inbox: not started yet. Archive: not started yet.");
  });

  it("no folder list yet: one inbox row, not started", () => {
    const answer = parse(
      backfillResult(input({ state: { folders: null, listedAt: null, sync: {} } })) as ToolAnswer,
    );

    expect(answer.folders).toEqual([
      { role: "inbox", stage: "not_started", indexed: 0, estimate: null, reachedBack: null },
    ]);
  });

  it("waiting and parked use the loop's own predicates", () => {
    const listedAt = NOW - DAY_MS;
    const answer = parse(
      backfillResult(
        input({
          state: {
            folders: [INBOX, ARCHIVE],
            listedAt,
            sync: {
              [INBOX]: row("build", { failures: 1, failedAt: NOW - 1000 }),
              [ARCHIVE]: row("build", {
                failures: RECALL_PARK_AFTER_FAILURES,
                failedAt: listedAt + 1000,
              }),
            },
          },
        }),
      ) as ToolAnswer,
    );

    expect(answer.folders.map((one) => one.stage)).toEqual(["waiting", "parked"]);
    expect(answer.progress).toContain("waiting a few minutes after a failed read");
    expect(answer.progress).toContain("tried again about once a day");
  });

  it("a failure already waited out is building again", () => {
    const answer = parse(
      backfillResult(
        input({
          state: {
            folders: [INBOX],
            listedAt: NOW - DAY_MS,
            sync: { [INBOX]: row("build", { failures: 1, failedAt: NOW - DAY_MS }) },
          },
        }),
      ) as ToolAnswer,
    );

    expect(answer.folders[0]!.stage).toBe("building");
  });

  it("thisCall: pages from the outcome, messages as after minus before (never below 0), whole seconds", () => {
    const grew = parse(
      backfillResult(
        input({
          before: { total: 100, mailboxes: [] },
          after: { total: 350, mailboxes: [] },
          outcome: { stopped: "budget", pages: 10, sessions: 10 },
          startedAt: NOW - 12_900,
        }),
      ) as ToolAnswer,
    );
    expect(grew.thisCall).toEqual({ pages: 10, messages: 250, seconds: 12 });

    const shrank = parse(
      backfillResult(
        input({ before: { total: 400, mailboxes: [] }, after: { total: 380, mailboxes: [] } }),
      ) as ToolAnswer,
    );
    expect(shrank.thisCall.messages).toBe(0);
  });

  const nextFor: [Exclude<BackfillStop, "unnamed">, string][] = [
    ["budget", "Call mail_recall_backfill again to continue."],
    [
      "built",
      "The index is built. There is nothing more to do, and it stays current as the person uses mail.",
    ],
    ["waiting", "A folder is waiting a few minutes after a failed read. Stop now, and try again later."],
    [
      "busy",
      "Another part of the build or another request is using the connection. Try again in a minute or two.",
    ],
    [
      "lease_busy",
      "Another part of the build or another request is using the connection. Try again in a minute or two.",
    ],
    [
      "quota",
      "The backfill has read its most pages for today. Stop now. It continues tomorrow, and ordinary mail use keeps building the index meanwhile.",
    ],
    [
      "full",
      "The index holds its most messages, 10,000. The oldest mail in the window is not indexed. Stop now.",
    ],
    ["destroying", "This index is being deleted because access ended. Stop now."],
    [
      "failed",
      "A read failed, and that folder waits before it is tried again. Stop now. mail_imap_diagnose checks the connection.",
    ],
  ];

  it.each(nextFor)("stopped %s: one fixed next sentence, the note, one plain ASCII block", (word, next) => {
    const outcome: BackfillOutcome = { stopped: word, pages: 1, sessions: 1 };
    const result = backfillResult(input({ outcome })) as ToolAnswer;
    const answer = parse(result);

    expect(result.isError).not.toBe(true);
    expect(answer.stopped).toBe(word);
    expect(answer.next).toBe(next);
    expect(answer.note).toBe(BACKFILL_NOTE);
    expect(result.content[0]!.text).toMatch(PLAIN_ASCII);
  });

  it("the ceiling in the full sentence is RECALL_MAX_VECTORS", () => {
    const answer = parse(
      backfillResult(input({ outcome: { stopped: "full", pages: 0, sessions: 0 } })) as ToolAnswer,
    );
    expect(answer.next).toContain(RECALL_MAX_VECTORS.toLocaleString("en-US"));
  });

  it("the note says the numbers describe the build, and recall stays ranked and best-effort", () => {
    expect(BACKFILL_NOTE).toContain("how far the build has got");
    expect(BACKFILL_NOTE).toContain("ranked and best-effort");
  });

  it("names folders by role: a folder's own name never appears", () => {
    const canary = "Canary-Folder-7f3e";
    const answer = backfillResult(
      input({
        state: {
          folders: [INBOX, canary],
          listedAt: NOW - DAY_MS,
          sync: { [INBOX]: row("built"), [canary]: row("build") },
        },
        after: {
          total: 30,
          mailboxes: [
            { mailbox: INBOX, count: 20, oldestExpiry: NOW - 5 * DAY_MS + RECALL_TTL_MS },
            { mailbox: canary, count: 10, oldestExpiry: NOW - 5 * DAY_MS + RECALL_TTL_MS },
          ],
        },
      }),
    ) as ToolAnswer;

    expect(answer.content[0]!.text).not.toContain(canary);
    expect(answer.content[0]!.text).not.toContain(INBOX);
    expect(parse(answer).folders.map((one) => one.role)).toEqual(["inbox", "archive"]);
  });
});

// ---------------------------------------------------------------------------
// The tool, live
// ---------------------------------------------------------------------------

/** Spy the object's recall reads through its prototype. */
async function spyRecallReads(userId: string) {
  return runInDurableObject(objectFor(userId), (instance: UserAgent) => {
    const prototype = Object.getPrototypeOf(instance) as UserAgent;
    return {
      state: vi.spyOn(prototype, "recallSyncState"),
      progress: vi.spyOn(prototype, "recallProgress"),
    };
  });
}

describe("the backfill tool, live against the real object", () => {
  it("a fresh person: one call indexes both folders, and the answer says so without naming or quoting anything", async () => {
    const folderCanary = "Canary-Archive-91ab";
    const mailCanary = "canarysender-5c2d";
    const h = fakeStepDeps({
      folders: [INBOX, folderCanary],
      mailboxes: {
        [INBOX]: { uidValidity: 100, messages: canaryMessages(40, 3, mailCanary) },
        [folderCanary]: { uidValidity: 300, messages: canaryMessages(20, 5, mailCanary) },
      },
    });

    const answer = await backfillTool(h).call();

    expect(answer.isError).not.toBe(true);
    const text = answer.content[0]!.text;
    const parsed = parse(answer);
    expect(parsed.index).toBe("built");
    expect(parsed.stopped).toBe("built");
    expect(parsed.thisCall.pages).toBe(3);
    expect(parsed.thisCall.messages).toBe(60);
    expect(parsed.folders.map((one) => [one.role, one.stage, one.indexed])).toEqual([
      ["inbox", "built", 40],
      ["archive", "built", 20],
    ]);
    expect(parsed.progress).toBe(
      "Inbox: all 40 messages from the last 90 days indexed. " +
        "Archive: all 20 messages from the last 90 days indexed.",
    );
    expect(text).toMatch(PLAIN_ASCII);
    expect(text).not.toContain(folderCanary);
    expect(text).not.toContain(mailCanary);
    expect(text).not.toContain("@");
    // No vector id, and no message id: every stored id is absent from the text.
    const ids = await withSql(USER_A.userId, (sql) =>
      sql.exec<{ id: string }>("select vector_id as id from recall_vectors").toArray(),
    );
    expect(ids).toHaveLength(60);
    for (const { id } of ids) expect(text).not.toContain(id);
    expect(Object.keys(parsed).sort()).toEqual(
      ["folders", "index", "next", "note", "progress", "stopped", "thisCall"].sort(),
    );
  });

  it("a built index: built, 0 pages and 0 messages, no session, and nothing more to do", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "x") } },
    });
    await backfillTool(h).call();
    const from = h.log.length;

    const answer = parse(await backfillTool(h).call());

    expect(answer.stopped).toBe("built");
    expect(answer.index).toBe("built");
    expect(answer.thisCall).toMatchObject({ pages: 0, messages: 0 });
    expect(answer.next).toContain("nothing more to do");
    expect(h.log.slice(from)).toEqual([]);
  });

  it("a budget stop part-way: building, with an estimate and how far back, and says to continue", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(400, 10, "y") } },
    });

    const answer = parse(await backfillTool(h).call());

    expect(answer.stopped).toBe("budget");
    expect(answer.thisCall.pages).toBe(RECALL_BACKFILL_MAX_PAGES);
    expect(answer.thisCall.messages).toBe(RECALL_BACKFILL_MAX_PAGES * 25);
    expect(answer.folders[0]).toMatchObject({ role: "inbox", stage: "building", indexed: 250 });
    // 250 messages, all ten days back: 250 * 90 / 10 = 2,250.
    expect(answer.folders[0]!.estimate).toBe(2300);
    expect(answer.progress).toMatch(/^Inbox: 250 of about 2,300 messages indexed, back to [A-Z][a-z]{2} \d{1,2}\.$/);
    expect(answer.next).toBe("Call mail_recall_backfill again to continue.");
  });

  it("the lease held before the first session: the standard connection_busy error, and no session", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "z") } },
    });
    expect((await objectFor(USER_A.userId).acquire()).held).toBe(true);

    const answer = await backfillTool(h).call();

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual(
      toErrorCategory(new ConnectionBusyError()),
    );
    expect(JSON.parse(answer.content[0]!.text).category).toBe("connection_busy");
    expect(h.log).not.toContain("enter");
  });

  it("an object that does not know whose it is: the fixed unavailable error", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "u") } },
    });
    await runInDurableObject(objectFor(USER_A.userId), (_instance, state) => {
      state.storage.kv.put("own-name", "not-a-user-id");
    });

    const answer = await backfillTool(h).call();

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual({ message: BACKFILL_UNAVAILABLE });
    expect(h.log).toEqual([]);
  });

  it("the object throws: the fixed unavailable error, and the thrown value is not read", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "t") } },
    });
    const spies = await spyRecallReads(USER_A.userId);
    spies.progress.mockImplementationOnce(() => {
      throw new Error("secret-canary-in-a-thrown-value");
    });

    const answer = await backfillTool(h).call();

    expect(answer.isError).toBe(true);
    expect(answer.content[0]!.text).toBe(JSON.stringify({ message: BACKFILL_UNAVAILABLE }));
    expect(h.log).toEqual([]);
  });

  // 29.1.1-REVIEW WR-01: an object read that fails after a page was indexed
  // must not answer that nothing was indexed.
  it("the object read fails mid-call, after a page: the call stops as failed and the answer says what was indexed", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(60, 2, "w") } },
    });
    // Reads 1 to 3: the loop's first read, the seed pass and the first page's
    // pass. Read 4, the next pass, fails; every read after it works.
    await runInDurableObject(objectFor(USER_A.userId), (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      const original = prototype.recallSyncState;
      let calls = 0;
      vi.spyOn(prototype, "recallSyncState").mockImplementation(function (this: UserAgent) {
        calls += 1;
        if (calls === 4) throw new Error("object-out-of-reach");
        return original.call(this);
      });
    });

    const answer = await backfillTool(h).call();

    expect(answer.isError).not.toBe(true);
    const parsed = parse(answer);
    expect(parsed.stopped).toBe("failed");
    expect(parsed.thisCall).toMatchObject({ pages: 1, messages: 25 });
    expect(await ledgerCount(USER_A.userId)).toBe(25);
  });

  it("the read after the run fails, after pages were indexed: a fixed error that does not say nothing was indexed", async () => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "v") } },
    });
    // The read before the run works; the read after it fails.
    await runInDurableObject(objectFor(USER_A.userId), (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      const original = prototype.recallProgress;
      let calls = 0;
      vi.spyOn(prototype, "recallProgress").mockImplementation(function (this: UserAgent) {
        calls += 1;
        if (calls === 2) throw new Error("object-out-of-reach");
        return original.call(this);
      });
    });

    const answer = await backfillTool(h).call();

    expect(await ledgerCount(USER_A.userId)).toBe(30);
    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual({ message: BACKFILL_PROGRESS_UNREAD });
    expect(BACKFILL_PROGRESS_UNREAD).not.toMatch(/nothing was indexed/);
  });

  const refused: [string, string | null][] = [
    ["the autonomy client", AUTONOMY_CLIENT_ID],
    ["an empty client", ""],
    ["an unknown client", null],
  ];

  it.each(refused)("%s: the fixed refusal, and no object call at all", async (_label, client) => {
    const h = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(30, 2, "r") } },
    });
    const spies = await spyRecallReads(USER_A.userId);

    const answer = await backfillTool(h, USER_A, async () => client).call();

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual({ message: BACKFILL_REFUSED });
    expect(spies.state).not.toHaveBeenCalled();
    expect(spies.progress).not.toHaveBeenCalled();
    expect(h.log).toEqual([]);
  });

  it("two people: A's call leaves B's ledger, state rows and backfill count exactly as they were", async () => {
    const hb = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(35, 2, "b") } },
    });
    expect(parse(await backfillTool(hb, USER_B).call()).thisCall.messages).toBe(35);
    const bVectors = await vectorRows(USER_B.userId);
    const bState = await stateRows(USER_B.userId);
    const bBackfill = await backfillCount(USER_B.userId);

    const ha = fakeStepDeps({
      folders: [INBOX],
      mailboxes: { [INBOX]: { uidValidity: 100, messages: canaryMessages(20, 2, "a") } },
    });
    const answer = parse(await backfillTool(ha, USER_A).call());

    expect(answer.thisCall.messages).toBe(20);
    expect(answer.folders[0]!.indexed).toBe(20);
    expect(await ledgerCount(USER_A.userId)).toBe(20);
    expect(await vectorRows(USER_B.userId)).toEqual(bVectors);
    expect(await stateRows(USER_B.userId)).toEqual(bState);
    expect(await backfillCount(USER_B.userId)).toBe(bBackfill);
  });
});

describe("the tool's registration", () => {
  it("no input schema, a short description naming the page cap, and not an autonomy tool", () => {
    const h = fakeStepDeps({ folders: [INBOX], mailboxes: {} });
    const { config } = backfillTool(h);

    expect(config.inputSchema).toBeUndefined();
    const description = config.description as string;
    expect(description.length).toBeLessThan(280);
    expect(description).toContain(`up to ${RECALL_BACKFILL_MAX_PAGES} pages`);
    expect(description).toMatch(PLAIN_ASCII);
    expect((AUTONOMY_TOOLS as readonly string[]).includes(RECALL_BACKFILL_TOOL_NAME)).toBe(false);
  });
});
