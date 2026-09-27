// The recall store's tracer (Phase 25, plan 25-01): one message goes in for one
// person and comes back out as that person, through every layer this phase
// touches.
//
// The person's object is the REAL `UserAgent` in the pool, reached by user id
// and read through `runInDurableObject`. The store and the model are fakes
// passed to their factories (test/fixtures/fake-vectorize.ts,
// test/fixtures/fake-embedder.ts), because the pool cannot simulate either and
// is set so that a call through the real binding fails (case 4 pins that).
//
// Recall is inherent: nothing is turned on before the first index.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { ensureRecallSchema } from "../src/agent/recall-ledger";
import { decodeMessageId, encodeMessageId, type MessageRef } from "../src/mail/ids";
import { createEmbedder, RECALL_DIMENSIONS, RECALL_MODEL, RecallEmbedError } from "../src/recall/embed";
import { vectorIdOf } from "../src/recall/ids";
import { createRecallStore, type RecallStore } from "../src/recall/index";
import {
  indexItems,
  type RecallDeps,
  type RecallItem,
  RecallRefusedError,
  recallFor,
} from "../src/recall/pipeline";
import { RECALL_MAX_VECTORS, RECALL_TTL_MS } from "../src/recall/retention";
import { createFakeAi, type FakeAi } from "./fixtures/fake-embedder";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";

const DAY_MS = 24 * 60 * 60 * 1000;

/** The person's object, reached the way tests may: by the user id. */
function objectFor(userId: string) {
  return env.USER_AGENT.getByName(userId);
}

/** Drop this object's recall tables and its stored name. The lease is left alone. */
function resetRecall(stub: DurableObjectStub<import("../src/agent/user-agent").UserAgent>) {
  return runInDurableObject(stub, (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
  });
}

/** Every ledger row of this object. */
function ledgerRows(stub: DurableObjectStub<import("../src/agent/user-agent").UserAgent>) {
  return runInDurableObject(stub, (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql
      .exec<{ vector_id: string; mailbox: string; uid_validity: number; expires_at: number }>(
        "SELECT vector_id, mailbox, uid_validity, expires_at FROM recall_vectors",
      )
      .toArray();
  });
}

/** The value stored under `own-name`, or undefined. */
function ownName(stub: DurableObjectStub<import("../src/agent/user-agent").UserAgent>) {
  return runInDurableObject(stub, (_instance, state) => state.storage.kv.get<unknown>("own-name"));
}

function item(ref: MessageRef, text: string, snippet: string, messageDate = Date.now() - DAY_MS): RecallItem {
  return { ref, text, snippet, messageDate };
}

const STAFF_REF: MessageRef = { mailbox: "INBOX", uidValidity: 1757000000, uid: 42 };

let fakeIndex: FakeVectorize;
let fakeAi: FakeAi;
let deps: RecallDeps;

beforeEach(async () => {
  fakeIndex = createFakeVectorize();
  fakeAi = createFakeAi();
  deps = { store: createRecallStore(fakeIndex), embedder: createEmbedder(fakeAi) };
  await resetRecall(objectFor(USER_A.userId));
  await resetRecall(objectFor(USER_B.userId));
});

describe("recall tracer: one message in, the same message out (plan 25-01)", () => {
  it("indexes one message for A with nothing turned on first, ledger before store, and recalls it as a ref and snippet with no score", async () => {
    const a = await testPrincipal(USER_A);
    const stub = objectFor(USER_A.userId);
    const messageDate = Date.now() - 3 * DAY_MS;

    // Wrap the store's write, to read the ledger at the moment the write runs.
    let rowsWhenWritten = -1;
    const store: RecallStore = {
      ...deps.store,
      upsert: async (principal, entries) => {
        rowsWhenWritten = (await ledgerRows(stub)).length;
        return deps.store.upsert(principal, entries);
      },
    };

    const indexed = await indexItems(
      a,
      [item(STAFF_REF, "Hiring a staff engineer for the platform team", "Staff role", messageDate)],
      { store, embedder: deps.embedder },
    );
    expect(indexed).toBe(1);

    const rows = await ledgerRows(stub);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.vector_id).toBe(await vectorIdOf(a, encodeMessageId(STAFF_REF)));
    expect(rows[0]!.mailbox).toBe("INBOX");
    expect(rows[0]!.uid_validity).toBe(1757000000);
    expect(Math.abs(rows[0]!.expires_at - (messageDate + RECALL_TTL_MS))).toBeLessThan(1000);
    expect(rowsWhenWritten, "the ledger row must exist before the store write runs").toBe(1);

    const matches = await recallFor(a, "staff engineer", deps);
    expect(matches).toHaveLength(1);
    expect(decodeMessageId(matches[0]!.ref)).toEqual(STAFF_REF);
    expect(matches[0]!.snippet).toBe("Staff role");
    expect(typeof matches[0]!.indexedAt).toBe("number");
    expect(Object.keys(matches[0]!)).not.toContain("score");

    // D-22: the object stored the platform's name at the RPC call.
    expect(await ownName(stub)).toBe(USER_A.userId);
  });

  it("keeps the stored name: a second index leaves it unchanged, and a seeded name is never overwritten", async () => {
    const a = await testPrincipal(USER_A);
    const stub = objectFor(USER_A.userId);

    await indexItems(a, [item(STAFF_REF, "first", "one")], deps);
    expect(await ownName(stub)).toBe(USER_A.userId);
    await indexItems(a, [item({ ...STAFF_REF, uid: 43 }, "second", "two")], deps);
    expect(await ownName(stub)).toBe(USER_A.userId);

    await resetRecall(stub);
    const seeded = "f".repeat(64);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.kv.put("own-name", seeded);
    });
    await indexItems(a, [item(STAFF_REF, "third", "three")], deps);
    expect(await ownName(stub)).toBe(seeded);
  });

  it("refuses to record as unnamed on an object with no stored name and no platform name", async () => {
    const stub = env.USER_AGENT.get(env.USER_AGENT.newUniqueId());
    const answer = await stub.recallRecord([
      { vectorId: "a".repeat(64), mailbox: "INBOX", uidValidity: 1, messageDate: Date.now() },
    ]);
    expect(answer).toEqual({ ok: false, reason: "unnamed" });
    expect(await ledgerRows(stub)).toHaveLength(0);
    expect(await ownName(stub)).toBeUndefined();
  });

  it(
    "never reaches the account: calls through the pool's own vector and AI bindings both reject",
    async () => {
      await expect((async () => env.RECALL_INDEX.describe())()).rejects.toBeDefined();
      await expect((async () => env.AI.run(RECALL_MODEL, { text: ["x"] }))()).rejects.toBeDefined();
    },
    10_000,
  );

  it("pins the dimension at 1024 and refuses a model answer of another length before anything is written", async () => {
    expect(RECALL_DIMENSIONS).toBe(1024);
    const a = await testPrincipal(USER_A);
    const shortAi = createFakeAi({ dimensions: 768 });
    await expect(
      indexItems(a, [item(STAFF_REF, "text", "snippet")], {
        store: deps.store,
        embedder: createEmbedder(shortAi),
      }),
    ).rejects.toBeInstanceOf(RecallEmbedError);
    expect(fakeIndex.calls.filter((c) => c.method === "upsert")).toHaveLength(0);
  });

  it("gives a 64-character lower-case hex id for a realistic ref", async () => {
    const a = await testPrincipal(USER_A);
    const ref = encodeMessageId({ mailbox: "Sent Messages", uidValidity: 1757000000, uid: 98765 });
    expect(await vectorIdOf(a, ref)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses as full a record past the per-person ceiling, and still accepts a re-index of an id already held (D-24)", async () => {
    const b = await testPrincipal(USER_B);
    const stub = objectFor(USER_B.userId);
    const heldRef: MessageRef = { mailbox: "INBOX", uidValidity: 7, uid: 1 };
    const heldId = await vectorIdOf(b, encodeMessageId(heldRef));

    // RECALL_MAX_VECTORS - 1 rows: the held message's real id plus fillers.
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      ensureRecallSchema(sql);
      sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'INBOX', 7, ? FROM c`,
        RECALL_MAX_VECTORS - 2,
        Date.now() + DAY_MS,
      );
      sql.exec(
        "INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at) VALUES (?, 'INBOX', 7, ?)",
        heldId,
        Date.now() + DAY_MS,
      );
    });
    expect(await ledgerRows(stub)).toHaveLength(RECALL_MAX_VECTORS - 1);

    const refused = await indexItems(
      b,
      [
        item({ mailbox: "INBOX", uidValidity: 7, uid: 2 }, "two", "two"),
        item({ mailbox: "INBOX", uidValidity: 7, uid: 3 }, "three", "three"),
      ],
      deps,
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(refused).toBeInstanceOf(RecallRefusedError);
    expect((refused as RecallRefusedError).reason).toBe("full");
    expect(fakeIndex.calls.filter((c) => c.method === "upsert")).toHaveLength(0);
    expect(fakeAi.calls).toHaveLength(0);
    expect(await ledgerRows(stub)).toHaveLength(RECALL_MAX_VECTORS - 1);

    expect(await indexItems(b, [item(heldRef, "held again", "held")], deps)).toBe(1);
    expect(await ledgerRows(stub)).toHaveLength(RECALL_MAX_VECTORS - 1);
  });
});
