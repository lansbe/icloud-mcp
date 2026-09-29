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
import { beforeEach, describe, expect, it } from "vitest";
import {
  ensureRecallSchema,
  readState,
  type SyncRow,
  utcDay,
  writeState,
} from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import type { FolderState } from "../src/change-marker";
import { RECALL_BACKFILL_TOOL_NAME, registerRecallBackfillTool } from "../src/mcp/tools/recall";
import { RECALL_MAX_PAGES_PER_DAY } from "../src/recall/retention";
import { scriptedMessages } from "./fixtures/fake-recall-source";
import { fakeStepDeps, type StepHarness } from "./fixtures/fake-step-deps";
import { USER_A, testPrincipal } from "./fixtures/two-users";

const INBOX = "INBOX";
const ORDINARY_CLIENT = "claude-desktop-client";

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
    expect(trusted.thisCall).toEqual({ pages: 3 });
    expect(trusted.index).toBe("built");
    expect(await ledgerCount(USER_A.userId)).toBe(60);

    expect(h.log.filter((entry) => entry === "lease")).toHaveLength(3);
    expect(h.log.filter((entry) => entry === "enter")).toHaveLength(3);
    expectOneSessionAtATime(h.log);

    expect(await ordinaryCount(USER_A.userId)).toBe(String(RECALL_MAX_PAGES_PER_DAY));
    expect(await backfillCount(USER_A.userId)).toBe("3");
  });
});
