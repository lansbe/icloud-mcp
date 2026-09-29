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
  NOTE_PARKED,
  RECALL_UNAVAILABLE,
  registerRecallTools,
} from "../src/mcp/tools/recall";
import { UNTRUSTED_NOTICE } from "../src/mcp/untrusted";
import { createEmbedder, RECALL_MODEL } from "../src/recall/embed";
import { createRecallStore } from "../src/recall/index";
import { indexItems, type RecallDeps } from "../src/recall/pipeline";
import { RECALL_MAX_PAGES_PER_DAY, SNIPPET_MAX_CHARS } from "../src/recall/retention";
import { createFakeAi, type FakeAi, fakeVectorOf } from "./fixtures/fake-embedder";
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
    expect(state).toEqual({
      slot: "free",
      backfill: "free",
      full: false,
      folders: null,
      listedAt: null,
      listing: null,
      sync: {},
    });
  });

  it("reads the folder list and every sync row that parses, leaving out one that does not; a row stored before the failure fields reads as never failed", async () => {
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
      failedAt: null,
      failures: 0,
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

  it("a parked folder is not counted as being built, and the note says a folder could not be read (26-REVIEW-2 WR-03)", async () => {
    const { deps } = fakes();
    await indexOne(USER_A, deps, { ref: ref(42), text: "Staff engineer role", snippet: "Staff role" });
    const row = (stage: string, failures: number, failedAt: number | null) =>
      JSON.stringify({
        stage,
        state: null,
        checkedAt: null,
        reconciledAt: null,
        due: null,
        seen: null,
        failedAt,
        failures,
      });
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "folders", JSON.stringify(["INBOX", "Archive"]));
      writeState(sql, "folders_listed_at", "1000");
      writeState(sql, "sync:INBOX", row("built", 0, null));
      writeState(sql, "sync:Archive", row("seed", 9, 2000));
    });
    const { call } = recallTool(USER_A, deps);

    const parked = trustedOf(await call({ query: "staff engineer" }));
    expect(parked.index).toBe("built");
    expect(parked.note).toContain(NOTE_PARKED);
    expect(parked.note).not.toContain("still being built");

    // Eight failures: still being built, and no parked sentence.
    await withSql(USER_A.userId, (sql) => writeState(sql, "sync:Archive", row("seed", 8, 2000)));
    const eight = trustedOf(await call({ query: "staff engineer" }));
    expect(eight.index).toBe("building");
    expect(eight.note).not.toContain(NOTE_PARKED);

    // Nine, but listed since: it is being tried again, so building.
    await withSql(USER_A.userId, (sql) => {
      writeState(sql, "sync:Archive", row("seed", 9, 2000));
      writeState(sql, "folders_listed_at", "3000");
    });
    const tried = trustedOf(await call({ query: "staff engineer" }));
    expect(tried.index).toBe("building");
    expect(tried.note).not.toContain(NOTE_PARKED);
  });
});

/** Every path in `value` that holds a JSON number, and every key named like a count. */
function numbersAndCountKeys(value: unknown, path = "$"): string[] {
  const found: string[] = [];
  if (typeof value === "number") return [path];
  if (Array.isArray(value)) {
    value.forEach((item, i) => found.push(...numbersAndCountKeys(item, `${path}[${i}]`)));
    return found;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, inner] of Object.entries(value)) {
      if (/^(score|count|total|rank|of)$/i.test(key)) found.push(`${path}.${key} (key)`);
      found.push(...numbersAndCountKeys(inner, `${path}.${key}`));
    }
  }
  return found;
}

/** Three unrelated messages for `user`, with uids 1, 2 and 3. */
async function indexThree(user: TestUser, deps: RecallDeps): Promise<void> {
  await indexOne(user, deps, { ref: ref(1), text: "Staff engineer role", snippet: "Staff role" });
  await indexOne(user, deps, { ref: ref(2), text: "Dentist appointment reminder", snippet: "Dentist" });
  await indexOne(user, deps, { ref: ref(3), text: "Quarterly tax invoice", snippet: "Tax invoice" });
}

/** The error body of a failed recall, parsed. */
function failureOf(answer: ToolAnswer): Record<string, unknown> {
  expect(answer.isError).toBe(true);
  expect(answer.content).toHaveLength(1);
  return JSON.parse(answer.content[0]!.text) as Record<string, unknown>;
}

describe("the recall contract (RCLL-08, RCLL-10, RCLL-11, RCLL-12)", () => {
  it("no numbers: no JSON number and no score, count, total, rank or of key anywhere in the answer", async () => {
    const { deps } = fakes();
    await indexThree(USER_A, deps);
    const { call } = recallTool(USER_A, deps);

    const answer = await call({ query: "staff engineer" });

    const trusted = trustedOf(answer);
    expect((trusted.results as unknown[]).length).toBeGreaterThan(0);
    expect(numbersAndCountKeys(trusted)).toEqual([]);
    expect(numbersAndCountKeys(untrustedOf(answer))).toEqual([]);
  });

  it("no body: the stored subject comes back and the embedded body text does not", async () => {
    const { deps } = fakes();
    await indexOne(USER_A, deps, {
      ref: ref(7),
      text: "Offer letter BODY-CANARY-9",
      snippet: "Offer letter",
    });
    const { call } = recallTool(USER_A, deps);

    const answer = await call({ query: "offer letter" });

    const text = JSON.stringify(answer);
    expect(text).toContain("Offer letter");
    expect(text).not.toContain("BODY-CANARY-9");
  });

  it("every snippet is at most SNIPPET_MAX_CHARS code points", async () => {
    const { deps } = fakes();
    const long = "Staff engineer role " + "\u{1F600}".repeat(400);
    await indexOne(USER_A, deps, { ref: ref(8), text: "Staff engineer role", snippet: long });
    const { call } = recallTool(USER_A, deps);

    const snippets = untrustedOf(await call({ query: "staff engineer" })).snippets as Record<
      string,
      string
    >;

    const values = Object.values(snippets);
    expect(values).toHaveLength(1);
    for (const snippet of values) {
      expect(Array.from(snippet).length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    }
  });

  it("the fence: snippets only in the untrusted block, the trusted block holds only index, note and results", async () => {
    const { deps } = fakes();
    await indexThree(USER_A, deps);
    const { call, description } = recallTool(USER_A, deps);

    const answer = await call({ query: "staff engineer role" });

    const trusted = trustedOf(answer);
    expect(Object.keys(trusted).sort()).toEqual(["index", "note", "results"]);
    for (const row of trusted.results as Record<string, unknown>[]) {
      expect(Object.keys(row).sort()).toEqual(["id", "indexedAt"]);
    }
    const snippets = untrustedOf(answer).snippets as Record<string, string>;
    expect(Object.values(snippets)).toContain("Staff role");
    for (const snippet of Object.values(snippets)) {
      expect(answer.content[0]!.text).not.toContain(snippet);
      expect(answer.content[1]!.text).toContain(snippet);
    }
    expect(description).toContain(UNTRUSTED_NOTICE);
  });

  it("the floor: a query sharing no words answers an empty list and the note; a query sharing the subject's words finds it", async () => {
    const { deps } = fakes();
    await indexThree(USER_A, deps);
    const { call } = recallTool(USER_A, deps);

    const nonsense = await call({ query: "zebra kumquat xylophone" });
    expect(nonsense.isError).toBeUndefined();
    const empty = trustedOf(nonsense);
    expect(empty.results).toEqual([]);
    expect(empty.note).toContain(
      "An empty answer means nothing scored high enough, not that no such mail exists.",
    );
    expect(untrustedOf(nonsense)).toEqual({ snippets: {} });

    const hit = trustedOf(await call({ query: "dentist appointment" }));
    const ids = (hit.results as { id: string }[]).map((row) => row.id);
    expect(ids).toEqual([encodeMessageId(ref(2))]);
  });

  it("failure is not empty: the store rejecting answers the fixed error with no results key", async () => {
    const { deps, index } = fakes();
    await indexThree(USER_A, deps);
    index.failing.add("query");
    const { call } = recallTool(USER_A, deps);

    const body = failureOf(await call({ query: "staff engineer" }));

    expect(body).toEqual({ message: RECALL_UNAVAILABLE });
    expect("results" in body).toBe(false);
  });

  it("failure is not empty: the model rejecting answers the fixed error with no results key", async () => {
    const { deps, index } = fakes();
    await indexThree(USER_A, deps);
    const broken: RecallDeps = {
      store: createRecallStore(index),
      embedder: createEmbedder(createFakeAi({ reject: true })),
    };
    const { call } = recallTool(USER_A, broken);

    const body = failureOf(await call({ query: "staff engineer" }));

    expect(body).toEqual({ message: RECALL_UNAVAILABLE });
  });

  it("failure is not empty: the object read rejecting answers the fixed error, and nothing is searched", async () => {
    const { deps, index, ai } = fakes();
    await runInDurableObject(objectFor(USER_A.userId), (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      vi.spyOn(prototype, "recallSyncState").mockImplementation(() => {
        throw new Error("the object could not answer");
      });
    });
    const { call } = recallTool(USER_A, deps);

    const body = failureOf(await call({ query: "staff engineer" }));

    expect(body).toEqual({ message: RECALL_UNAVAILABLE });
    expect(index.calls.filter((one) => one.method === "query")).toEqual([]);
    expect(ai.calls).toEqual([]);
  });

  it("only the embedder: one recall makes exactly one model call, to the recall model, with text", async () => {
    const indexing = fakes();
    await indexThree(USER_A, indexing.deps);
    const ai = createFakeAi();
    const deps: RecallDeps = {
      store: createRecallStore(indexing.index),
      embedder: createEmbedder(ai),
    };
    const { call } = recallTool(USER_A, deps);

    await call({ query: "staff engineer" });

    expect(ai.calls).toHaveLength(1);
    expect(ai.calls[0]!.model).toBe(RECALL_MODEL);
    expect(ai.calls[0]!.input).toEqual({ text: ["staff engineer"] });
  });

  it("a match whose ref does not decode is dropped, and the others come back", async () => {
    const { deps, index } = fakes();
    await indexOne(USER_A, deps, { ref: ref(42), text: "Staff engineer role", snippet: "Staff role" });
    index.vectors.set("f".repeat(64), {
      id: "f".repeat(64),
      values: fakeVectorOf("Staff engineer role"),
      namespace: USER_A.userId,
      metadata: { u: USER_A.userId, r: "garbage", s: "Junk", a: Date.now() },
    });
    const { call } = recallTool(USER_A, deps);

    const answer = await call({ query: "staff engineer" });

    const ids = (trustedOf(answer).results as { id: string }[]).map((row) => row.id);
    expect(ids).toEqual([encodeMessageId(ref(42))]);
    expect(untrustedOf(answer)).toEqual({ snippets: { [ids[0]!]: "Staff role" } });
    expect(JSON.stringify(answer)).not.toContain("Junk");
  });
});
