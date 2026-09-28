// `mail_recall`: ask a question, get ids and subjects back (Phase 26, RCLL-08,
// RCLL-10, RCLL-11, RCLL-12, plan 26-01).
//
// The tool is driven through its real callback, captured with a fake server as
// test/changes-tool.test.ts does. The person's object is the REAL `UserAgent`
// in the pool, and the pipeline is Phase 25's real one. Only the vector store
// and the model are fakes, passed through the tool's `deps` seam, because the
// pool cannot reach either for real (vitest.config.ts says why).
//
// Recall is inherent: nothing is turned on before the first record or the first
// question.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ensureRecallSchema, utcDay, writeState } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { decodeMessageId, encodeMessageId, type MessageRef } from "../src/mail/ids";
import {
  RECALL_TOOL_NAME,
  RECALL_UNAVAILABLE,
  registerRecallTools,
} from "../src/mcp/tools/recall";
import { UNTRUSTED_NOTICE } from "../src/mcp/untrusted";
import { createEmbedder } from "../src/recall/embed";
import { createRecallStore } from "../src/recall/index";
import { indexItems, type RecallDeps } from "../src/recall/pipeline";
import { RECALL_MAX_PAGES_PER_DAY } from "../src/recall/retention";
import { createFakeAi, type FakeAi } from "./fixtures/fake-embedder";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B, testPrincipal, type TestUser } from "./fixtures/two-users";

type ToolAnswer = { isError?: boolean; content: { type: "text"; text: string }[] };
type RecallCallback = (args: { query: string }) => Promise<ToolAnswer>;

const DAY_MS = 24 * 60 * 60 * 1000;
const VALIDITY = 1234567890;

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

interface Fakes {
  index: FakeVectorize;
  ai: FakeAi;
  deps: RecallDeps;
}

function fakes(): Fakes {
  const index = createFakeVectorize();
  const ai = createFakeAi();
  return { index, ai, deps: { store: createRecallStore(index), embedder: createEmbedder(ai) } };
}

/** The `mail_recall` callback for `user`, over `deps`, and its registered options. */
function recallTool(
  user: TestUser,
  deps: RecallDeps,
): { call: RecallCallback; description: string } {
  let call: RecallCallback | undefined;
  let description = "";
  const server = {
    registerTool(name: string, options: { description: string }, handler: RecallCallback) {
      if (name === RECALL_TOOL_NAME) {
        call = handler;
        description = options.description;
      }
    },
  };
  registerRecallTools(server as unknown as McpServer, testPrincipal(user), () => deps);
  expect(call, `${RECALL_TOOL_NAME} is not registered`).toBeDefined();
  return { call: call!, description };
}

function ref(uid: number, mailbox = "INBOX"): MessageRef {
  return { mailbox, uidValidity: VALIDITY, uid };
}

/** Index one message for `user`, with nothing turned on first. */
async function indexOne(
  user: TestUser,
  deps: RecallDeps,
  message: { ref: MessageRef; text: string; snippet: string },
): Promise<void> {
  const principal = await testPrincipal(user);
  const indexed = await indexItems(
    principal,
    [{ ...message, messageDate: Date.now() - DAY_MS }],
    deps,
  );
  expect(indexed).toBe(1);
}

/** The trusted block, parsed. */
function trustedOf(answer: ToolAnswer): Record<string, unknown> {
  return JSON.parse(answer.content[0]!.text) as Record<string, unknown>;
}

/** The JSON inside the fenced second block. */
function untrustedOf(answer: ToolAnswer): Record<string, unknown> {
  const text = answer.content[1]!.text;
  const lines = text.split("\n");
  expect(lines[1]).toMatch(/^---BEGIN UNTRUSTED [0-9a-f-]{36}---$/);
  expect(lines[3]).toMatch(/^---END UNTRUSTED [0-9a-f-]{36}---$/);
  return JSON.parse(lines[2]!) as Record<string, unknown>;
}

beforeEach(async () => {
  await resetObject(USER_A.userId);
  await resetObject(USER_B.userId);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("mail_recall, the tracer (RCLL-08, RCLL-11)", () => {
  it("returns the indexed message's id and subject through the fence, with nothing turned on first", async () => {
    const { deps } = fakes();
    const indexedRef = ref(42);
    await indexOne(USER_A, deps, {
      ref: indexedRef,
      text: "Staff engineer role",
      snippet: "Staff role",
    });

    const { call } = recallTool(USER_A, deps);
    const answer = await call({ query: "staff engineer" });

    expect(answer.isError).toBeUndefined();
    expect(answer.content).toHaveLength(2);
    // The answer went through the fence.
    expect(answer.content[1]!.text).toContain("---BEGIN UNTRUSTED ");

    const trusted = trustedOf(answer);
    expect(trusted.index).toBe("building");
    const results = trusted.results as { id: string; indexedAt: string }[];
    expect(results).toHaveLength(1);
    const [only] = results;
    expect(only!.id).toBe(encodeMessageId(indexedRef));
    expect(decodeMessageId(only!.id)).toEqual(indexedRef);
    expect(new Date(only!.indexedAt).toISOString()).toBe(only!.indexedAt);

    const untrusted = untrustedOf(answer);
    expect(untrusted).toEqual({ snippets: { [only!.id]: "Staff role" } });
  });

  it("a person whose index is empty gets building, no results and the note, and it is not an error", async () => {
    const { deps } = fakes();
    const { call } = recallTool(USER_B, deps);

    const answer = await call({ query: "staff engineer" });

    expect(answer.isError).toBeUndefined();
    const trusted = trustedOf(answer);
    expect(trusted.index).toBe("building");
    expect(trusted.results).toEqual([]);
    expect(trusted.note).toContain("nothing scored high enough");
    expect(trusted.note).toContain("still being built");
    expect(untrustedOf(answer)).toEqual({ snippets: {} });
    expect(JSON.stringify(answer)).not.toContain(RECALL_UNAVAILABLE);
  });

  it("the description carries the untrusted notice and the empty-answer clause, under the ceiling", () => {
    const { deps } = fakes();
    const { description } = recallTool(USER_A, deps);
    expect(description).toContain(UNTRUSTED_NOTICE);
    expect(description).toContain("nothing scored high enough");
    expect(description.length).toBeLessThan(280);
  });
});

describe("the object's sync-state read (D-29)", () => {
  it("answers quota exactly when a build page start would", async () => {
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "pages_day", utcDay(Date.now()));
      writeState(sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    const stub = objectFor(USER_A.userId);

    const state = await stub.recallSyncState();
    expect(state.slot).toBe("quota");

    const begin = await stub.recallBeginPage("INBOX", "build");
    expect(begin).toEqual({ ok: false, reason: "quota" });
  });

  it("answers free, no folder list and no sync rows for a fresh object", async () => {
    const state = await objectFor(USER_A.userId).recallSyncState();
    expect(state).toEqual({ slot: "free", folders: null, sync: {} });
  });

  it("reads the folder list and every sync row that parses, leaving out one that does not", async () => {
    const seen = { mailbox: "INBOX", uidValidity: VALIDITY, uidNext: 43, highestModseq: "9001" };
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "folders", JSON.stringify(["INBOX", "Archive"]));
      writeState(
        sql,
        "sync:INBOX",
        JSON.stringify({
          stage: "built",
          state: seen,
          checkedAt: 1,
          reconciledAt: null,
          due: "new_mail",
          seen,
        }),
      );
      writeState(sql, "sync:Archive", JSON.stringify({ stage: "off" }));
    });

    const state = await objectFor(USER_A.userId).recallSyncState();

    expect(state.folders).toEqual(["INBOX", "Archive"]);
    expect(Object.keys(state.sync)).toEqual(["INBOX"]);
    expect(state.sync.INBOX).toEqual({
      stage: "built",
      state: seen,
      checkedAt: 1,
      reconciledAt: null,
      due: "new_mail",
      seen,
    });
  });

  it("index is built only when every listed folder is built", async () => {
    const { deps } = fakes();
    await indexOne(USER_A, deps, { ref: ref(42), text: "Staff engineer role", snippet: "Staff role" });
    const row = (stage: string) =>
      JSON.stringify({ stage, state: null, checkedAt: null, reconciledAt: null, due: null, seen: null });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "folders", JSON.stringify(["INBOX", "Archive"]));
      writeState(sql, "sync:INBOX", row("built"));
      writeState(sql, "sync:Archive", row("build"));
    });
    const { call } = recallTool(USER_A, deps);

    const building = trustedOf(await call({ query: "staff engineer" }));
    expect(building.index).toBe("building");
    expect(building.note).toContain("still being built");

    await withSql(USER_A.userId, (sql) => writeState(sql, "sync:Archive", row("built")));
    const built = trustedOf(await call({ query: "staff engineer" }));
    expect(built.index).toBe("built");
    expect(built.note).not.toContain("still being built");
    expect(built.note).toContain("nothing scored high enough");
  });
});
