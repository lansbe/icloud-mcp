// Recall isolation, layer by layer (Phase 25, RCLL-01), and vector ids
// (RCLL-03).
//
// WHAT THIS PROVES, AND WHAT IT DOES NOT. The pool cannot hold vectors, so no
// test here watches the real store keep two people apart. What these tests
// prove is narrower and honest: no code path can ask the store for another
// person's partition, and anything the store hands back for another person is
// thrown away. Each of the three layers has its own test, named for the layer,
// and removing that layer turns that test red.
//
// The store and the model are fakes (test/fixtures/fake-vectorize.ts models the
// cautious reading: no partition searches everything, ids are index-wide). The
// person's object is the real `UserAgent`, so indexing runs through the real
// ledger too. Recall is inherent: nothing is turned on first.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { ensureRecallSchema } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { encodeMessageId, type MessageRef } from "../src/mail/ids";
import type { Principal } from "../src/principal";
import { createEmbedder } from "../src/recall/embed";
import { vectorIdOf } from "../src/recall/ids";
import { createRecallStore, type RecallQueryOptions, RecallStoreError } from "../src/recall/index";
import { indexItems, type RecallDeps, type RecallItem, recallFor } from "../src/recall/pipeline";
import { createFakeAi } from "./fixtures/fake-embedder";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";

const DAY_MS = 24 * 60 * 60 * 1000;
const CANARY = "zebra-canary-7";

function objectFor(userId: string): DurableObjectStub<UserAgent> {
  return env.USER_AGENT.getByName(userId);
}

function resetRecall(stub: DurableObjectStub<UserAgent>) {
  return runInDurableObject(stub, (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
  });
}

function ledgerIds(stub: DurableObjectStub<UserAgent>): Promise<string[]> {
  return runInDurableObject(stub, (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql
      .exec<{ vector_id: string }>("select vector_id from recall_vectors")
      .toArray()
      .map((row) => row.vector_id);
  });
}

function item(ref: MessageRef, text: string, snippet: string): RecallItem {
  return { ref, text, snippet, messageDate: Date.now() - DAY_MS };
}

const A_REF: MessageRef = { mailbox: "INBOX", uidValidity: 1757000000, uid: 42 };
const A_REF_2: MessageRef = { mailbox: "INBOX", uidValidity: 1757000000, uid: 43 };
const B_REF: MessageRef = { mailbox: "INBOX", uidValidity: 1757000000, uid: 900 };

/** The options of every query the fake received. */
function queryOptions(fake: FakeVectorize): VectorizeQueryOptions[] {
  return fake.calls
    .filter((c) => c.method === "query")
    .map((c) => c.args[1] as VectorizeQueryOptions);
}

/** Every vector every upsert sent. */
function upsertedVectors(fake: FakeVectorize): VectorizeVector[] {
  return fake.calls
    .filter((c) => c.method === "upsert")
    .flatMap((c) => c.args[0] as VectorizeVector[]);
}

let fake: FakeVectorize;
let deps: RecallDeps;
let a: Principal;
let b: Principal;

beforeEach(async () => {
  fake = createFakeVectorize();
  deps = { store: createRecallStore(fake), embedder: createEmbedder(createFakeAi()) };
  a = await testPrincipal(USER_A);
  b = await testPrincipal(USER_B);
  await resetRecall(objectFor(USER_A.userId));
  await resetRecall(objectFor(USER_B.userId));
});

/** Index A's two messages and B's canary. */
async function indexBoth(): Promise<void> {
  await indexItems(
    a,
    [
      item(A_REF, "Staff engineer interview on Tuesday", "Staff interview"),
      item(A_REF_2, "Recruiter follow up about the platform role", "Recruiter follow up"),
    ],
    deps,
  );
  await indexItems(b, [item(B_REF, `Secret note ${CANARY} for B only`, `B canary ${CANARY}`)], deps);
}

describe("recall isolation (RCLL-01)", () => {
  it("layer 1, the partition: every query and every write for A names A's user id as its partition", async () => {
    await indexItems(a, [item(A_REF, "Staff engineer interview", "Staff interview")], deps);
    await recallFor(a, "staff engineer", deps);

    const queries = queryOptions(fake);
    expect(queries.length).toBeGreaterThan(0);
    for (const options of queries) expect(options.namespace).toBe(a.userId);

    const vectors = upsertedVectors(fake);
    expect(vectors.length).toBeGreaterThan(0);
    for (const vector of vectors) expect(vector.namespace).toBe(a.userId);
  });

  it("layer 2, the metadata filter: every query filters on u equal to A's user id, and every write stores that u", async () => {
    await indexItems(a, [item(A_REF, "Staff engineer interview", "Staff interview")], deps);
    await recallFor(a, "staff engineer", deps);

    const queries = queryOptions(fake);
    expect(queries.length).toBeGreaterThan(0);
    for (const options of queries) expect(options.filter).toEqual({ u: a.userId });

    const vectors = upsertedVectors(fake);
    expect(vectors.length).toBeGreaterThan(0);
    for (const vector of vectors) {
      expect(vector.metadata?.u).toBe(a.userId);
      expect(String(vector.metadata?.u)).toHaveLength(64);
    }
  });

  it("layer 3, the returned-match check: a store that ignores both scopes still never hands A anything of B's", async () => {
    await indexBoth();
    fake.ignoreScopes = true;

    const forCanary = await recallFor(a, CANARY, deps, 50);
    const bRef = encodeMessageId(B_REF);
    expect(forCanary.length, "A's own result set must not be empty").toBeGreaterThan(0);
    for (const match of forCanary) {
      expect(match.ref).not.toBe(bRef);
      expect(match.snippet).not.toContain(CANARY);
    }
  });

  it("canary: with both people indexed, A's recall for B's canary returns nothing of B's, while A's own search is non-empty", async () => {
    await indexBoth();

    const forCanary = await recallFor(a, CANARY, deps, 50);
    const bRef = encodeMessageId(B_REF);
    for (const match of forCanary) {
      expect(match.ref).not.toBe(bRef);
      expect(match.snippet).not.toContain(CANARY);
    }

    const own = await recallFor(a, "Staff engineer interview", deps);
    expect(own.length).toBeGreaterThan(0);
    expect(own[0]!.ref).toBe(encodeMessageId(A_REF));
  });

  it("hostile options: a caller's options naming B's partition and filter still send A's id in both (set last)", async () => {
    const hostile = { namespace: b.userId, filter: { u: b.userId }, topK: 3 } as RecallQueryOptions;
    await deps.store.query(a, new Array<number>(1024).fill(0.5), hostile);

    const [options] = queryOptions(fake);
    expect(options!.namespace).toBe(a.userId);
    expect(options!.filter).toEqual({ u: a.userId });
    expect(options!.topK).toBe(3);
  });

  it("drops a returned match with no u, or with a u of another length", async () => {
    await indexItems(a, [item(A_REF, "Staff engineer interview", "Staff interview")], deps);
    const values = new Array<number>(1024).fill(0).map((_, i) => (i === 0 ? 1 : 0));
    fake.vectors.set("1".repeat(64), {
      id: "1".repeat(64),
      values,
      namespace: a.userId,
      metadata: { r: "no-u", s: "no u", a: 1 },
    });
    fake.vectors.set("2".repeat(64), {
      id: "2".repeat(64),
      values,
      namespace: a.userId,
      metadata: { u: a.userId.slice(0, 63), r: "short-u", s: "short u", a: 1 },
    });
    fake.ignoreScopes = true;

    const matches = await deps.store.query(a, values, { topK: 50 });
    const refs = matches.map((m) => m.ref);
    expect(refs).not.toContain("no-u");
    expect(refs).not.toContain("short-u");
    expect(refs).toContain(encodeMessageId(A_REF));
  });

  it("re-indexing the same message replaces its stored snippet (the store only ever upserts)", async () => {
    await indexItems(a, [item(A_REF, "first text", "First subject")], deps);
    await indexItems(a, [item(A_REF, "second text", "Second subject")], deps);

    const id = await vectorIdOf(a, encodeMessageId(A_REF));
    const stored = [...fake.vectors.values()].filter((v) => v.id === id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.metadata?.s).toBe("Second subject");
  });

  it("deleteIds refuses an id of the wrong shape and sends nothing", async () => {
    await expect(deps.store.deleteIds(["a".repeat(64), "A".repeat(64)])).rejects.toBeInstanceOf(
      RecallStoreError,
    );
    await expect(deps.store.deleteIds(["a".repeat(63)])).rejects.toBeInstanceOf(RecallStoreError);
    expect(fake.calls.filter((c) => c.method === "deleteByIds")).toHaveLength(0);
  });

  it("B's object holds no ledger row for anything indexed as A", async () => {
    await indexBoth();
    const aIds = await ledgerIds(objectFor(USER_A.userId));
    const bIds = await ledgerIds(objectFor(USER_B.userId));
    expect(aIds).toHaveLength(2);
    expect(bIds).toHaveLength(1);
    for (const id of aIds) expect(bIds).not.toContain(id);
    expect(bIds).toEqual([await vectorIdOf(b, encodeMessageId(B_REF))]);
  });
});

describe("vector ids (RCLL-03)", () => {
  it("gives the same id for the same person and message, every time", async () => {
    const token = encodeMessageId(A_REF);
    expect(await vectorIdOf(a, token)).toBe(await vectorIdOf(a, token));
  });

  it("gives different people with the identical message ref different ids", async () => {
    const token = encodeMessageId(A_REF);
    expect(await vectorIdOf(a, token)).not.toBe(await vectorIdOf(b, token));
  });

  it("always gives 64 lower-case hex characters", async () => {
    for (const ref of [A_REF, A_REF_2, B_REF, { mailbox: "Sent Messages", uidValidity: 4294967295, uid: 1 }]) {
      expect(await vectorIdOf(a, encodeMessageId(ref))).toMatch(/^[0-9a-f]{64}$/);
      expect(await vectorIdOf(b, encodeMessageId(ref))).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
