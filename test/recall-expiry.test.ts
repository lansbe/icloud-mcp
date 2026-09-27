// Every recall vector expires on its own clock (Phase 25, RCLL-05, plan 25-03).
//
// Runs the REAL `UserAgent` alarm through `runDurableObjectAlarm`. The object's
// store seam (`vectorStore`, an instance property RPC cannot reach) is replaced
// with a fake store inside `runInDurableObject`. The scheduling helper is called
// directly on the instance for the helper cases.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ensureRecallSchema } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { createRecallStore } from "../src/recall/index";
import { RECALL_TTL_MS } from "../src/recall/retention";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import { USER_A } from "./fixtures/two-users";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function stub(): DurableObjectStub<UserAgent> {
  return env.USER_AGENT.getByName(USER_A.userId);
}

function inObject<T>(fn: (instance: UserAgent, state: DurableObjectState) => T | Promise<T>) {
  return runInDurableObject(stub(), fn);
}

function hexId(n: number): string {
  return n.toString(16).padStart(64, "0");
}

/** Insert rows with these expiries, ids 1..n in order. */
function seedRows(expiries: number[], mailbox = "INBOX") {
  return inObject((_i, state) => {
    ensureRecallSchema(state.storage.sql);
    expiries.forEach((expiresAt, i) => {
      state.storage.sql.exec(
        "INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at) VALUES (?, ?, 1, ?)",
        hexId(i + 1),
        mailbox,
        expiresAt,
      );
    });
  });
}

function ledger(): Promise<{ vector_id: string; expires_at: number }[]> {
  return inObject((_i, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql
      .exec<{ vector_id: string; expires_at: number }>(
        "select vector_id, expires_at from recall_vectors order by vector_id",
      )
      .toArray();
  });
}

function alarmAt(): Promise<number | null> {
  return inObject((_i, state) => state.storage.getAlarm());
}

function setAlarm(at: number) {
  return inObject((_i, state) => state.storage.setAlarm(at));
}

/** Point the object's store seam at `fake`. */
function useFakeStore(fake: FakeVectorize) {
  return inObject((instance) => {
    vi.spyOn(instance, "vectorStore").mockReturnValue(createRecallStore(fake));
  });
}

function deleteBatches(fake: FakeVectorize): string[][] {
  return fake.calls.filter((c) => c.method === "deleteByIds").map((c) => c.args[0] as string[]);
}

function row(messageDate: number, uid = 1) {
  return { vectorId: hexId(1000 + uid), mailbox: "INBOX", uidValidity: 1, messageDate };
}

beforeEach(async () => {
  await inObject(async (_i, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    await state.storage.deleteAlarm();
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("recall expiry on the object's alarm (RCLL-05)", () => {
  it("sets the alarm on the first record, and a later record never pushes an earlier alarm later", async () => {
    expect(await alarmAt()).toBeNull();
    expect(await stub().recallRecord([row(Date.now() - DAY)])).toEqual({ ok: true });
    const first = await alarmAt();
    expect(first).not.toBeNull();
    expect(first!).toBeLessThanOrEqual(Date.now() + DAY);

    const early = Date.now() + 10 * MIN;
    await setAlarm(early);
    expect(await stub().recallRecord([row(Date.now() - DAY, 2)])).toEqual({ ok: true });
    expect(await alarmAt()).toBe(early);
  });

  it("deletes exactly the expired ids, store then ledger, keeps the rest, and sets the alarm at the next expiry", async () => {
    const now = Date.now();
    await seedRows([now - 3 * HOUR, now - 2 * HOUR, now - HOUR, now + 2 * HOUR, now + 3 * DAY]);
    const fake = createFakeVectorize();
    await useFakeStore(fake);
    await setAlarm(now + 1000);

    expect(await runDurableObjectAlarm(stub())).toBe(true);
    expect(deleteBatches(fake).flat().sort()).toEqual([hexId(1), hexId(2), hexId(3)]);
    expect((await ledger()).map((r) => r.vector_id)).toEqual([hexId(4), hexId(5)]);
    const next = await alarmAt();
    expect(Math.abs(next! - (now + 2 * HOUR))).toBeLessThan(2000);
  });

  it("with every row expired, empties the ledger and leaves no alarm set", async () => {
    const now = Date.now();
    await seedRows([now - HOUR, now - MIN]);
    await useFakeStore(createFakeVectorize());
    await setAlarm(now + 1000);

    await runDurableObjectAlarm(stub());
    expect(await ledger()).toHaveLength(0);
    expect(await alarmAt()).toBeNull();
  });

  it("clamps a message date ten years in the future: the row expires no later than the window from now", async () => {
    const before = Date.now();
    await stub().recallRecord([row(before + 3650 * DAY)]);
    const [stored] = await ledger();
    expect(stored!.expires_at).toBeLessThanOrEqual(Date.now() + RECALL_TTL_MS);
    expect(stored!.expires_at).toBeGreaterThanOrEqual(before + RECALL_TTL_MS);
  });

  it("gives a message dated 30 days ago an expiry of that date plus the window", async () => {
    const date = Date.now() - 30 * DAY;
    await stub().recallRecord([row(date)]);
    const [stored] = await ledger();
    expect(stored!.expires_at).toBe(date + RECALL_TTL_MS);
  });

  it("never throws when the store delete fails: the rows stay and the alarm is set about an hour out", async () => {
    const now = Date.now();
    await seedRows([now - HOUR, now - MIN]);
    const fake = createFakeVectorize();
    fake.failing.add("deleteByIds");
    await useFakeStore(fake);
    await setAlarm(now + 1000);

    await expect(runDurableObjectAlarm(stub())).resolves.toBe(true);
    expect(await ledger()).toHaveLength(2);
    const next = (await alarmAt())! - Date.now();
    expect(next).toBeGreaterThan(55 * MIN);
    expect(next).toBeLessThan(65 * MIN);
  });

  it("sweeps at most 50 batches of 1000 in one run, and comes back in about a minute when more remain", async () => {
    const now = Date.now();
    await inObject((_i, state) => {
      ensureRecallSchema(state.storage.sql);
      state.storage.sql.exec(
        `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 50005)
         INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
         SELECT printf('%064x', x), 'INBOX', 1, ? FROM c`,
        now - HOUR,
      );
    });
    const fake = createFakeVectorize();
    await useFakeStore(fake);
    await setAlarm(now + 1000);

    await runDurableObjectAlarm(stub());
    const batches = deleteBatches(fake);
    expect(batches).toHaveLength(50);
    for (const batch of batches) expect(batch.length).toBeLessThanOrEqual(1000);
    expect(await ledger()).toHaveLength(5);
    const next = (await alarmAt())! - Date.now();
    expect(next).toBeGreaterThan(30_000);
    expect(next).toBeLessThan(90_000);
  });

  it("removes an expired row that was never queried, exactly like any other", async () => {
    await stub().recallRecord([row(Date.now() - DAY)]);
    await inObject((_i, state) => {
      state.storage.sql.exec("UPDATE recall_vectors SET expires_at = ?", Date.now() - 1);
    });
    const fake = createFakeVectorize();
    await useFakeStore(fake);
    await setAlarm(Date.now() + 1000);

    await runDurableObjectAlarm(stub());
    expect(fake.calls.filter((c) => c.method === "query")).toHaveLength(0);
    expect(await ledger()).toHaveLength(0);
  });
});

describe("the one scheduling helper and anyJobPending (D-23)", () => {
  it("keeps the earlier time, moves an alarm earlier, and never sets one later than a day out", async () => {
    await seedRows([Date.now() + 3 * DAY]);
    const tenMinutes = Date.now() + 10 * MIN;
    await setAlarm(tenMinutes);

    await inObject((instance) => instance.scheduleAlarm(Date.now() + HOUR));
    expect(await alarmAt()).toBe(tenMinutes);

    const fiveMinutes = Date.now() + 5 * MIN;
    await inObject((instance) => instance.scheduleAlarm(fiveMinutes));
    expect(await alarmAt()).toBe(fiveMinutes);

    await inObject((_i, state) => state.storage.deleteAlarm());
    await inObject((instance) => instance.scheduleAlarm(Date.now() + 2 * DAY));
    expect((await alarmAt())!).toBeLessThanOrEqual(Date.now() + DAY);
  });

  it("asks the predicate: with an empty ledger the helper removes the alarm, with one row it keeps one set", async () => {
    await setAlarm(Date.now() + HOUR);
    expect(await inObject((instance) => instance.anyJobPending())).toBe(false);
    await inObject((instance) => instance.scheduleAlarm(Date.now() + HOUR));
    expect(await alarmAt()).toBeNull();

    await seedRows([Date.now() + DAY]);
    expect(await inObject((instance) => instance.anyJobPending())).toBe(true);
    await inObject((instance) => instance.scheduleAlarm(Date.now() + HOUR));
    expect(await alarmAt()).not.toBeNull();
  });
});
