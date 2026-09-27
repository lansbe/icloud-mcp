// Losing access destroys a person's recall index (Phase 25, RCLL-06, plan 25-03).
//
// Runs the REAL `UserAgent`: its destroy (an instance property, reached here
// inside `runInDurableObject` because RPC cannot reach it) and its alarm
// (through `runDurableObjectAlarm`). The store seam is replaced with a fake.
// The grant cases use the pool's own OAUTH_KV: a grant record in the library's
// summary shape is written under the library's key, and it is revoked with the
// library's own `revokeGrant`, as the owner's grants script does it.
//
// Recall is inherent: there is no opt-out, and nothing outside the object can
// start a destroy.

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ensureRecallSchema, readState, writeState } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { grantsRemainFor } from "../src/recall/grant-check";
import { createRecallStore } from "../src/recall/index";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A, USER_B } from "./fixtures/two-users";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const GRANT_ID = "recall-destroy-grant";

type Stub = DurableObjectStub<UserAgent>;

function named(userId: string): Stub {
  return env.USER_AGENT.getByName(userId);
}

function hexId(n: number): string {
  return n.toString(16).padStart(64, "0");
}

async function reset(stub: Stub) {
  await runInDurableObject(stub, async (_i, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    await state.storage.deleteAlarm();
  });
}

function seedRows(stub: Stub, count: number, expiresAt: number, from = 1) {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    state.storage.sql.exec(
      `WITH RECURSIVE c(x) AS (SELECT ? UNION ALL SELECT x + 1 FROM c WHERE x < ?)
       INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
       SELECT printf('%064x', x), 'INBOX', 1, ? FROM c`,
      from,
      from + count - 1,
      expiresAt,
    );
  });
}

function ledgerCount(stub: Stub): Promise<number> {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql.exec<{ n: number }>("select count(*) as n from recall_vectors").one().n;
  });
}

function stateRows(stub: Stub): Promise<string[]> {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql
      .exec<{ k: string }>("select k from recall_state order by k")
      .toArray()
      .map((row) => row.k);
  });
}

function alarmAt(stub: Stub): Promise<number | null> {
  return runInDurableObject(stub, (_i, state) => state.storage.getAlarm());
}

function setAlarm(stub: Stub, at: number) {
  return runInDurableObject(stub, (_i, state) => state.storage.setAlarm(at));
}

function useFakeStore(stub: Stub, fake: FakeVectorize) {
  return runInDurableObject(stub, (instance: UserAgent) => {
    vi.spyOn(instance, "vectorStore").mockReturnValue(createRecallStore(fake));
  });
}

function deleteBatches(fake: FakeVectorize): string[][] {
  return fake.calls.filter((c) => c.method === "deleteByIds").map((c) => c.args[0] as string[]);
}

function validRow(uid = 1) {
  return { vectorId: hexId(900_000 + uid), mailbox: "INBOX", uidValidity: 1, messageDate: Date.now() - DAY };
}

/** The library's helpers over the pool's own store, as the grants script builds them. */
function oauthHelpers() {
  const handler = { fetch: () => new Response(null, { status: 404 }) };
  return getOAuthApi(
    {
      apiRoute: "/mcp",
      apiHandler: handler,
      defaultHandler: handler,
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/oauth/token",
    },
    { OAUTH_KV: env.OAUTH_KV },
  );
}

/** A grant for `userId` in the library's summary shape, under the library's key. */
function seedGrant(userId: string) {
  return env.OAUTH_KV.put(
    `grant:${userId}:${GRANT_ID}`,
    JSON.stringify({
      id: GRANT_ID,
      clientId: "recall-destroy-client",
      userId,
      scope: ["mcp"],
      metadata: { clientName: "a client" },
      encryptedProps: "not-real-ciphertext-written-by-a-test",
      createdAt: 1_780_000_000,
    }),
  );
}

async function clearGrants(userId: string) {
  const listed = await env.OAUTH_KV.list({ prefix: `grant:${userId}:` });
  for (const key of listed.keys) await env.OAUTH_KV.delete(key.name);
}

beforeEach(async () => {
  await reset(named(USER_A.userId));
  await reset(named(USER_B.userId));
  await clearGrants(USER_A.userId);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await clearGrants(USER_A.userId);
});

describe("the destroy (RCLL-06, D-10)", () => {
  it("deletes every id once in batches of at most 1000, clears all recall state, keeps the name, removes the alarm, and recording works again", async () => {
    const a = named(USER_A.userId);
    await a.recallRecord([validRow()]);
    await seedRows(a, 2499, Date.now() + DAY);
    await runInDurableObject(a, (_i, state) => {
      for (const [k, v] of [
        ["cursor:INBOX", "c"],
        ["page", JSON.stringify({ token: "t", expiresAt: Date.now() + MIN })],
        ["last_page_at", String(Date.now())],
        ["pages_day", "2026-09-27"],
        ["pages_count", "3"],
      ] as const) {
        writeState(state.storage.sql, k, v);
      }
    });
    const fake = createFakeVectorize();
    await useFakeStore(a, fake);

    expect(await runInDurableObject(a, (instance: UserAgent) => instance.destroyRecall())).toEqual({ ok: true });

    const batches = deleteBatches(fake);
    for (const batch of batches) expect(batch.length).toBeLessThanOrEqual(1000);
    const all = batches.flat();
    expect(all).toHaveLength(2500);
    expect(new Set(all).size).toBe(2500);
    expect(await ledgerCount(a)).toBe(0);
    expect(await stateRows(a)).toEqual([]);
    expect(await runInDurableObject(a, (_i, state) => state.storage.kv.get("own-name"))).toBe(USER_A.userId);
    expect(await runInDurableObject(a, (instance: UserAgent) => instance.anyJobPending())).toBe(false);
    expect(await alarmAt(a)).toBeNull();
    expect(await a.recallRecord([validRow(2)])).toEqual({ ok: true });
  });

  it("when the store fails part-way: the flag stays, records and pages are refused as destroying, and the next alarm finishes", async () => {
    const a = named(USER_A.userId);
    await a.recallRecord([validRow()]);
    await seedRows(a, 2499, Date.now() + DAY);
    const fake = createFakeVectorize();
    let deletes = 0;
    const realDelete = fake.deleteByIds.bind(fake);
    (fake as { deleteByIds: typeof realDelete }).deleteByIds = async (ids: string[]) => {
      deletes += 1;
      if (deletes === 2) throw new Error("second batch set to fail");
      return realDelete(ids);
    };
    await useFakeStore(a, fake);

    expect(await runInDurableObject(a, (instance: UserAgent) => instance.destroyRecall())).toEqual({ ok: false });
    expect(await runInDurableObject(a, (_i, state) => readState(state.storage.sql, "destroy_pending"))).not.toBeNull();
    expect(await ledgerCount(a)).toBe(1500);
    expect(await a.recallRecord([validRow(3)])).toEqual({ ok: false, reason: "destroying" });
    expect(await a.recallBeginPage("INBOX", "build")).toEqual({ ok: false, reason: "destroying" });
    const retry = (await alarmAt(a))! - Date.now();
    expect(retry).toBeGreaterThan(55 * MIN);
    expect(retry).toBeLessThan(65 * MIN);

    await useFakeStore(a, createFakeVectorize());
    await runDurableObjectAlarm(a);
    expect(await ledgerCount(a)).toBe(0);
    expect(await runInDurableObject(a, (_i, state) => readState(state.storage.sql, "destroy_pending"))).toBeNull();
    expect(await alarmAt(a)).toBeNull();
  });

  it("keeps the alarm while a destroy is pending, even with an empty ledger", async () => {
    const a = named(USER_A.userId);
    await runInDurableObject(a, (_i, state) => {
      ensureRecallSchema(state.storage.sql);
      writeState(state.storage.sql, "destroy_pending", "1");
    });
    expect(await runInDurableObject(a, (instance: UserAgent) => instance.anyJobPending())).toBe(true);
    await runInDurableObject(a, (instance: UserAgent) => instance.scheduleAlarm(Date.now() + HOUR));
    expect(await alarmAt(a)).not.toBeNull();
  });
});

describe("revocation on the alarm, by the object's stored name (RCLL-06, D-09, D-22, D-25)", () => {
  it("destroys nothing while the person still holds a grant, and everything once the library revokes it", async () => {
    const a = named(USER_A.userId);
    await a.recallRecord([validRow()]);
    await seedRows(a, 9, Date.now() + DAY);
    await useFakeStore(a, createFakeVectorize());
    await seedGrant(USER_A.userId);

    await setAlarm(a, Date.now() + 1000);
    await runDurableObjectAlarm(a);
    expect(await ledgerCount(a)).toBe(10);

    await oauthHelpers().revokeGrant(GRANT_ID, USER_A.userId);
    await setAlarm(a, Date.now() + 1000);
    await runDurableObjectAlarm(a);
    expect(await ledgerCount(a)).toBe(0);
    expect(await alarmAt(a)).toBeNull();
  });

  it("finds the person by the stored name on an object with no platform name", async () => {
    const unnamed = env.USER_AGENT.get(env.USER_AGENT.newUniqueId());
    await runInDurableObject(unnamed, (_i, state) => {
      state.storage.kv.put("own-name", USER_A.userId);
    });
    await seedRows(unnamed, 5, Date.now() + DAY);
    await useFakeStore(unnamed, createFakeVectorize());
    const asked: string[] = [];
    await runInDurableObject(unnamed, (instance: UserAgent) => {
      vi.spyOn(instance, "grantsRemain").mockImplementation(async (userId: string) => {
        asked.push(userId);
        return "none";
      });
    });

    await setAlarm(unnamed, Date.now() + 1000);
    await runDurableObjectAlarm(unnamed);
    expect(await ledgerCount(unnamed)).toBe(0);
    expect(asked).toEqual([USER_A.userId]);
  });

  it("with no stored name at all, never asks about grants, still sweeps expired rows, and resolves", async () => {
    const unnamed = env.USER_AGENT.get(env.USER_AGENT.newUniqueId());
    await seedRows(unnamed, 2, Date.now() - MIN);
    await seedRows(unnamed, 3, Date.now() + DAY, 100);
    await useFakeStore(unnamed, createFakeVectorize());
    let asked = 0;
    await runInDurableObject(unnamed, (instance: UserAgent) => {
      vi.spyOn(instance, "grantsRemain").mockImplementation(async () => {
        asked += 1;
        return "none";
      });
    });

    await setAlarm(unnamed, Date.now() + 1000);
    await expect(runDurableObjectAlarm(unnamed)).resolves.toBe(true);
    expect(asked).toBe(0);
    expect(await ledgerCount(unnamed)).toBe(3);
  });

  it("destroys nothing when the grant check answers unknown, and still sweeps expired rows", async () => {
    const a = named(USER_A.userId);
    await a.recallRecord([validRow()]);
    await seedRows(a, 2, Date.now() - MIN);
    await useFakeStore(a, createFakeVectorize());
    await runInDurableObject(a, (instance: UserAgent) => {
      vi.spyOn(instance, "grantsRemain").mockResolvedValue("unknown");
    });

    await setAlarm(a, Date.now() + 1000);
    await runDurableObjectAlarm(a);
    expect(await ledgerCount(a)).toBe(1);
  });

  it("destroying A leaves B's ledger exactly as it was", async () => {
    const a = named(USER_A.userId);
    const b = named(USER_B.userId);
    await a.recallRecord([validRow()]);
    await b.recallRecord([validRow(7)]);
    await seedRows(b, 4, Date.now() + DAY);
    await useFakeStore(a, createFakeVectorize());

    await runInDurableObject(a, (instance: UserAgent) => instance.destroyRecall());
    expect(await ledgerCount(a)).toBe(0);
    expect(await ledgerCount(b)).toBe(5);
  });
});

describe("grantsRemainFor", () => {
  it("answers none with no grants, some with one, unknown on a failing store and for a malformed id", async () => {
    expect(await grantsRemainFor(env.OAUTH_KV, "e".repeat(64))).toBe("none");
    await seedGrant(USER_A.userId);
    expect(await grantsRemainFor(env.OAUTH_KV, USER_A.userId)).toBe("some");

    const failing = {
      list: async () => {
        throw new Error("store unreachable");
      },
      get: async () => {
        throw new Error("store unreachable");
      },
    } as unknown as KVNamespace;
    expect(await grantsRemainFor(failing, USER_A.userId)).toBe("unknown");
    expect(await grantsRemainFor(env.OAUTH_KV, "NOT-HEX")).toBe("unknown");
    expect(await grantsRemainFor(env.OAUTH_KV, USER_A.userId.toUpperCase())).toBe("unknown");
  });
});
