// The autonomy job on the object's one alarm (Phase 27, plan 27-05).
//
// The key lives exactly as long as the person's ordinary connection (owner's
// answers, 2026-09-27). A session asks at every use whether it still stands.
// These cases pin the other half: the alarm asks too, at least once a day while
// a record exists, so a key nobody uses still ends within a day. They drive the
// REAL alarm through `runDurableObjectAlarm`.
//
// Grants are written straight into the pool's sign-in store in the library's
// summary shape, the way test/recall-destroy.test.ts does it, and revoked with
// the library's own `revokeGrant`, as the owner's grants script does. Records
// are sealed with the pool's seal key and seeded with the object's stored name,
// except in the case that is about having no stored name. The arming cases arm
// through the real object and this Worker's real token endpoint, the way
// test/autonomy.test.ts does.
//
// Every alarm case replaces the object's one seam to this Worker with a
// recorder and asserts it saw nothing: the alarm job never unseals, never
// redeems, and never calls this Worker.
//
// Each case uses its own fresh user id where the allow list does not matter, and
// cleans up its grants, its record, its name, its recall tables and its alarm.

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AUTONOMY_KEY,
  type AutonomyRecord,
  disarmWith,
  seal,
  STANDING_GRACE_SECONDS,
} from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID, AUTONOMY_CLIENT_NAME } from "../src/agent/autonomy-client";
import type { KeyStanding } from "../src/agent/autonomy-grants";
import { ensureRecallSchema, readState, writeState } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { oauthProviderOptions } from "../src/auth/oauth";
import { userIdOf } from "../src/principal";
import { grantsRemainFor } from "../src/recall/grant-check";
import { createRecallStore } from "../src/recall/index";
import { AUTONOMY_REDIRECT_URI, installAutonomyClient } from "./fixtures/autonomy-client";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeVectorize } from "./fixtures/fake-vectorize";
import { FAKE_APP_PASSWORD, LISTED_APPLE_ID } from "./fixtures/worker-with-login-proof";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Eleven minutes, in seconds: past the standing check's grace. */
const PAST_GRACE_SECONDS = 11 * 60;

type Stub = DurableObjectStub<UserAgent>;

/** Everything a case touched, cleaned up after it. */
const touched: { stub: Stub; userId: string }[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const { stub, userId } of touched.splice(0)) {
    await clearGrants(userId);
    await runInDurableObject(stub, async (_i, state) => {
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
      state.storage.kv.delete(AUTONOMY_KEY);
      state.storage.kv.delete("own-name");
      await state.storage.deleteAlarm();
    });
  }
});

/** A fresh 64-hex user id nothing else touches. */
function freshUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The object for `userId`, by name, remembered for clean-up. */
function objectFor(userId: string): Stub {
  const stub = entryEnv().USER_AGENT.getByName(userId);
  touched.push({ stub, userId });
  return stub;
}

/** An object with no platform name, remembered for clean-up under `userId`. */
function unnamedObject(userId: string): Stub {
  const ns = entryEnv().USER_AGENT;
  const stub = ns.get(ns.newUniqueId());
  touched.push({ stub, userId });
  return stub;
}

/** The library's helpers over the pool's own store. */
function helpers() {
  return getOAuthApi(oauthProviderOptions, entryEnv());
}

/**
 * A grant for `userId` in the library's summary shape, under the library's key.
 * `extra` overrides fields, such as `createdAt`, or adds a code's wrapped key
 * to make a grant whose code has not been exchanged.
 */
function seedGrant(
  userId: string,
  id: string,
  clientId: string,
  extra: Record<string, unknown> = {},
): Promise<void> {
  return entryEnv().OAUTH_KV.put(
    `grant:${userId}:${id}`,
    JSON.stringify({
      id,
      clientId,
      userId,
      scope: ["mcp"],
      metadata: { clientName: "a client" },
      encryptedProps: "not-real-ciphertext-written-by-a-test",
      createdAt: 1_780_000_000,
      ...extra,
    }),
  );
}

/** Delete every grant key and token key for `userId`. Serial. */
async function clearGrants(userId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const prefix of [`grant:${userId}:`, `token:${userId}:`]) {
    for (const key of (await kv.list({ prefix })).keys) await kv.delete(key.name);
  }
}

/** Every grant the library lists for `userId`, as summaries. */
async function grantsOf(userId: string) {
  return (await helpers().listUserGrants(userId)).items;
}

/** The ids of every autonomy grant the library lists for `userId`. */
async function autonomyGrantIds(userId: string): Promise<string[]> {
  return (await grantsOf(userId))
    .filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID)
    .map((grant) => grant.id);
}

/** Seconds since the epoch, `ago` seconds in the past. */
function secondsAgo(ago: number): number {
  return Math.floor(Date.now() / 1000) - ago;
}

/** Seed a sealed record, and the object's stored name unless told not to. */
async function seedRecord(
  stub: Stub,
  userId: string,
  grantId: string,
  options: { armedAt?: number; generation?: number; storeName?: boolean } = {},
): Promise<AutonomyRecord> {
  const sealed = await seal(entryEnv().AUTONOMY_SEAL_KEY, userId, `${userId}:${grantId}:not-a-real-secret`);
  expect(sealed).not.toBeNull();
  const record: AutonomyRecord = {
    v: 1,
    grantId,
    sealedRefreshToken: sealed!.sealedRefreshToken,
    iv: sealed!.iv,
    armedAt: options.armedAt ?? secondsAgo(PAST_GRACE_SECONDS),
    generation: options.generation ?? 1,
  };
  await runInDurableObject(stub, (_i, state) => {
    state.storage.kv.put(AUTONOMY_KEY, record);
    if (options.storeName !== false) state.storage.kv.put("own-name", userId);
  });
  return record;
}

/** The stored record, or undefined. */
function storedRecord(stub: Stub): Promise<AutonomyRecord | undefined> {
  return runInDurableObject(stub, (_i, state) => state.storage.kv.get<AutonomyRecord>(AUTONOMY_KEY));
}

function alarmAt(stub: Stub): Promise<number | null> {
  return runInDurableObject(stub, (_i, state) => state.storage.getAlarm());
}

function setAlarm(stub: Stub, at: number): Promise<void> {
  return runInDurableObject(stub, (_i, state) => state.storage.setAlarm(at));
}

function anyJobPending(stub: Stub): Promise<boolean> {
  return runInDurableObject(stub, (instance: UserAgent) => instance.anyJobPending());
}

/** Seed `count` ledger rows expiring at `expiresAt`. */
function seedRows(stub: Stub, count: number, expiresAt: number): Promise<void> {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    state.storage.sql.exec(
      `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
       INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
       SELECT printf('%064x', x), 'INBOX', 1, ? FROM c`,
      count,
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

function markDestroyPending(stub: Stub): Promise<void> {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    writeState(state.storage.sql, "destroy_pending", "1");
  });
}

function destroyPendingFlag(stub: Stub): Promise<string | null> {
  return runInDurableObject(stub, (_i, state) => {
    ensureRecallSchema(state.storage.sql);
    return readState(state.storage.sql, "destroy_pending");
  });
}

/** Replace the store seam with a fake, so a destroy deletes nothing real. */
function useFakeStore(stub: Stub): Promise<void> {
  return runInDurableObject(stub, (instance: UserAgent) => {
    vi.spyOn(instance, "vectorStore").mockReturnValue(createRecallStore(createFakeVectorize()));
  });
}

/**
 * Replace the object's seam to this Worker with a recorder that answers 500 and
 * forwards nothing. Answers the list of paths it saw.
 */
async function recordSelfCalls(stub: Stub): Promise<string[]> {
  const seen: string[] = [];
  await runInDurableObject(stub, (instance: UserAgent) => {
    instance.autonomySelfFetch = async (request: Request) => {
      seen.push(new URL(request.url).pathname);
      return new Response(null, { status: 500 });
    };
  });
  return seen;
}

/** Spy the standing seam. Answers the list of `[name, grantId]` it was asked. */
async function spyStanding(stub: Stub, answer: KeyStanding): Promise<[string, string][]> {
  const asked: [string, string][] = [];
  await runInDurableObject(stub, (instance: UserAgent) => {
    vi.spyOn(instance, "keyStanding").mockImplementation(async (name: string, grantId: string) => {
      asked.push([name, grantId]);
      return answer;
    });
  });
  return asked;
}

/** Run the real alarm, after making sure one is set. */
async function runAlarm(stub: Stub): Promise<void> {
  if ((await alarmAt(stub)) === null) await setAlarm(stub, Date.now() + 1000);
  expect(await runDurableObjectAlarm(stub)).toBe(true);
}

/** Mint a real autonomy grant through the library. Answers its code and id. */
async function mintAutonomyGrant(userId: string): Promise<{ code: string; grantId: string }> {
  const minted = await helpers().completeAuthorization({
    request: {
      responseType: "code",
      clientId: AUTONOMY_CLIENT_ID,
      redirectUri: AUTONOMY_REDIRECT_URI,
      scope: ["mcp"],
      state: "",
    },
    userId,
    metadata: { clientName: AUTONOMY_CLIENT_NAME },
    scope: ["mcp"],
    props: { v: 1, appleId: LISTED_APPLE_ID, appPassword: FAKE_APP_PASSWORD },
    revokeExistingGrants: false,
  });
  const code = new URL(minted.redirectTo).searchParams.get("code") as string;
  return { code, grantId: code.split(":")[1] as string };
}

// ---------------------------------------------------------------------------

describe("the autonomy job on the alarm: when the key ends (AUTO-04, AUTO-06, D-33)", () => {
  it("keeps a standing key, asks nothing of this Worker, and keeps the alarm within a day", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    const record = await seedRecord(a, userId, "auto-1");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toEqual(record);
    const at = await alarmAt(a);
    expect(at).not.toBeNull();
    expect(at!).toBeLessThanOrEqual(Date.now() + DAY);
    expect(seen).toEqual([]);
  });

  it("deletes the record once the autonomy grant is revoked through the library, with no call to this Worker", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    await seedRecord(a, userId, "auto-1");
    await helpers().revokeGrant("auto-1", userId);
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toBeUndefined();
    expect(seen).toEqual([]);
  });

  it("ends the key with the last ordinary grant: no record, no autonomy grant listed, no call, and recall's destroy runs in the same alarm", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    await seedRecord(a, userId, "auto-1");
    await seedRows(a, 5, Date.now() + DAY);
    await useFakeStore(a);
    await helpers().revokeGrant("ordinary-1", userId);
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toBeUndefined();
    expect(await autonomyGrantIds(userId)).toEqual([]);
    expect(seen).toEqual([]);
    // Recall's grant check, later in the same run, saw nobody left.
    const destroyed = (await ledgerCount(a)) === 0 || (await destroyPendingFlag(a)) !== null;
    expect(destroyed).toBe(true);
  });

  it("keeps the key and the autonomy grant while the person still holds another ordinary grant", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    await seedGrant(userId, "ordinary-2", "another-claude-client");
    const record = await seedRecord(a, userId, "auto-1");
    await helpers().revokeGrant("ordinary-1", userId);
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toEqual(record);
    expect(await autonomyGrantIds(userId)).toEqual(["auto-1"]);
    expect(seen).toEqual([]);
  });

  it("a standing key past its grace: the alarm ends stray autonomy grants, keeps its own, and spares a code not yet exchanged (review R2-WR-02)", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    const now = Math.floor(Date.now() / 1000);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    // An old stray: a replaced grant whose revoke failed, long ago.
    await seedGrant(userId, "auto-old-stray", AUTONOMY_CLIENT_ID);
    // A young stray that was exchanged: an arm that died after its exchange.
    await seedGrant(userId, "auto-young-exchanged", AUTONOMY_CLIENT_ID, { createdAt: now - 30 });
    // A young grant whose code is still unexchanged: a sign-in whose arm has
    // not reached the object yet. It must be left alone.
    await seedGrant(userId, "auto-young-code", AUTONOMY_CLIENT_ID, {
      createdAt: now - 30,
      authCodeWrappedKey: "not-a-real-wrapped-key",
    });
    const record = await seedRecord(a, userId, "auto-1");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toEqual(record);
    expect((await autonomyGrantIds(userId)).sort()).toEqual(["auto-1", "auto-young-code"]);
    expect((await grantsOf(userId)).map((grant) => grant.id)).toContain("ordinary-1");
    expect(seen).toEqual([]);
    expect(await alarmAt(a)).not.toBeNull();
  });

  it("inside the grace after arming, keeps the record and does not ask", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    const record = await seedRecord(a, userId, "auto-1", { armedAt: secondsAgo(5 * 60) });
    const asked = await spyStanding(a, "connection_ended");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(asked).toEqual([]);
    expect(await storedRecord(a)).toEqual(record);
    expect(await alarmAt(a)).not.toBeNull();
    expect(seen).toEqual([]);
    expect(STANDING_GRACE_SECONDS).toBeGreaterThan(5 * 60);
  });

  it("keeps the record when the listing cannot be read", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    const record = await seedRecord(a, userId, "auto-1");
    const asked = await spyStanding(a, "unknown");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(asked).toHaveLength(1);
    expect(await storedRecord(a)).toEqual(record);
    expect(await alarmAt(a)).not.toBeNull();
    expect(seen).toEqual([]);
  });
});

describe("the autonomy job beside recall's jobs (D-25, T-27-38, T-27-40)", () => {
  it("still runs when recall's pending destroy stops recall's branch early", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    await seedRecord(a, userId, "auto-gone");
    await markDestroyPending(a);
    await useFakeStore(a);
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await storedRecord(a)).toBeUndefined();
    expect(await destroyPendingFlag(a)).toBeNull();
    expect(seen).toEqual([]);
  });

  it("a storage read that throws inside the autonomy job: the alarm resolves and recall's expiry still runs", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    await seedRecord(a, userId, "auto-1");
    await seedRows(a, 3, Date.now() - MIN);
    await useFakeStore(a);
    await setAlarm(a, Date.now() + 1000);
    const seen = await recordSelfCalls(a);
    let thrown = 0;
    await runInDurableObject(a, (_i, state) => {
      const kv = state.storage.kv;
      const realGet = kv.get.bind(kv);
      vi.spyOn(kv, "get").mockImplementation(((key: string) => {
        if (key === AUTONOMY_KEY && thrown === 0) {
          thrown += 1;
          throw new Error("storage read set to fail");
        }
        return realGet(key);
      }) as typeof kv.get);
    });

    await expect(runDurableObjectAlarm(a)).resolves.toBe(true);

    expect(thrown).toBe(1);
    expect(await ledgerCount(a)).toBe(0);
    expect((await storedRecord(a))?.grantId).toBe("auto-1");
    expect(await alarmAt(a)).not.toBeNull();
    expect(seen).toEqual([]);
  });

  it("an empty ledger with a standing key: the record stays, anyJobPending is true, and the alarm is still set", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    const record = await seedRecord(a, userId, "auto-1");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await ledgerCount(a)).toBe(0);
    expect(await storedRecord(a)).toEqual(record);
    expect(await anyJobPending(a)).toBe(true);
    expect(await alarmAt(a)).not.toBeNull();
    expect(seen).toEqual([]);
  });

  it("a pending destroy with a standing key: the ledger is emptied, the record stays, and the alarm is still set", async () => {
    const userId = freshUserId();
    const a = objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    const record = await seedRecord(a, userId, "auto-1");
    await seedRows(a, 4, Date.now() + DAY);
    await markDestroyPending(a);
    await useFakeStore(a);
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(await ledgerCount(a)).toBe(0);
    expect(await destroyPendingFlag(a)).toBeNull();
    expect(await storedRecord(a)).toEqual(record);
    expect(await alarmAt(a)).not.toBeNull();
    expect(seen).toEqual([]);
  });
});

describe("the name the job asks about is the stored one (25 D-22, T-27-64)", () => {
  it("on an object with no platform name, asks about the stored name", async () => {
    const userId = freshUserId();
    const a = unnamedObject(userId);
    await seedRecord(a, userId, "auto-1");
    const asked = await spyStanding(a, "standing");
    const seen = await recordSelfCalls(a);

    await runAlarm(a);

    expect(asked).toEqual([[userId, "auto-1"]]);
    expect(seen).toEqual([]);
  });

  it("with no stored name, asks nothing, keeps the record, resolves, and keeps the alarm", async () => {
    const userId = freshUserId();
    const a = unnamedObject(userId);
    const record = await seedRecord(a, userId, "auto-1", { storeName: false });
    const asked = await spyStanding(a, "revoked");
    const seen = await recordSelfCalls(a);

    await setAlarm(a, Date.now() + 1000);
    await expect(runDurableObjectAlarm(a)).resolves.toBe(true);

    expect(asked).toEqual([]);
    expect(await storedRecord(a)).toEqual(record);
    expect(await anyJobPending(a)).toBe(true);
    // Set by recall's own path (a day out), not by the failure retry (an hour
    // out): an object that never had a recall call still runs recall's jobs.
    const at = await alarmAt(a);
    expect(at).not.toBeNull();
    expect(at! - Date.now()).toBeGreaterThan(2 * HOUR);
    expect(seen).toEqual([]);
  });
});

describe("scheduling through the one helper (25 D-23)", () => {
  it("arming on an object with no alarm sets one, within a day", async () => {
    const env = entryEnv();
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    const removeClient = await installAutonomyClient(env);
    const a = objectFor(userId);
    try {
      expect(await alarmAt(a)).toBeNull();
      const { code, grantId } = await mintAutonomyGrant(userId);
      expect(await a.armAutonomy(code)).toEqual({ kind: "armed", grantId });
      const at = await alarmAt(a);
      expect(at).not.toBeNull();
      expect(at!).toBeLessThanOrEqual(Date.now() + DAY);
    } finally {
      await removeClient();
    }
  });

  it("arming leaves an earlier alarm where it was", async () => {
    const env = entryEnv();
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    const removeClient = await installAutonomyClient(env);
    const a = objectFor(userId);
    try {
      const earlier = Date.now() + HOUR;
      await setAlarm(a, earlier);
      const { code, grantId } = await mintAutonomyGrant(userId);
      expect(await a.armAutonomy(code)).toEqual({ kind: "armed", grantId });
      expect(await alarmAt(a)).toBe(earlier);
    } finally {
      await removeClient();
    }
  });

  it("after disarmWith deletes the record, the helper removes the alarm when no job is left, and keeps it while the ledger has rows", async () => {
    for (const rows of [0, 3]) {
      const userId = freshUserId();
      const a = objectFor(userId);
      await seedRecord(a, userId, "auto-1");
      if (rows > 0) await seedRows(a, rows, Date.now() + DAY);
      await setAlarm(a, Date.now() + HOUR);
      await runInDurableObject(a, async (instance: UserAgent, state) => {
        await disarmWith({
          storage: state.storage.kv,
          name: userId,
          env: entryEnv(),
          selfFetch: async () => new Response(null, { status: 200 }),
          now: () => Date.now(),
        });
        await instance.scheduleAlarm(Date.now() + DAY);
      });
      expect(await storedRecord(a)).toBeUndefined();
      if (rows === 0) expect(await alarmAt(a)).toBeNull();
      else expect(await alarmAt(a)).not.toBeNull();
    }
  });
});

describe("one autonomy operation at a time (D-27, T-27-54)", () => {
  it("an alarm run waits behind an arm held in the queue, then keeps the new record", async () => {
    const env = entryEnv();
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    const removeClient = await installAutonomyClient(env);
    const a = objectFor(userId);
    try {
      // An old record whose grant is gone: a job that did not wait would ask.
      await seedRecord(a, userId, "auto-old");
      await setAlarm(a, Date.now() + 1000);
      const asked = await spyStanding(a, "revoked");

      // The hold is released from inside the object, so the forwarded call
      // continues in the object's own context: a promise settled from the test
      // would carry the test's context into the object's outbound call.
      let release!: () => void;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      let held = false;
      await runInDurableObject(a, (instance: UserAgent) => {
        const forward = instance.autonomySelfFetch;
        instance.autonomySelfFetch = async (request: Request) => {
          if (!held) {
            held = true;
            await released;
          }
          return forward(request);
        };
      });

      const { code, grantId } = await mintAutonomyGrant(userId);
      const arming = a.armAutonomy(code);
      for (let i = 0; i < 200 && !held; i += 1) await new Promise((r) => setTimeout(r, 10));
      expect(held).toBe(true);
      const alarming = runDurableObjectAlarm(a);
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(asked).toEqual([]);

      await runInDurableObject(a, () => release());
      expect(await arming).toEqual({ kind: "armed", grantId });
      expect(await alarming).toBe(true);

      const after = await storedRecord(a);
      expect(after?.grantId).toBe(grantId);
      expect(after?.generation).toBe(2);
      // The new record is inside its grace when the job reads it, so it is not asked.
      expect(asked).toEqual([]);
      expect(await autonomyGrantIds(userId)).toEqual([grantId]);
    } finally {
      await removeClient();
    }
  });
});

describe("recall ignores the autonomy grant (D-32, T-27-55)", () => {
  it("answers none for a person whose only grant is the autonomy one, and some once they hold an ordinary one", async () => {
    const userId = freshUserId();
    objectFor(userId);
    await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
    expect(await grantsRemainFor(entryEnv().OAUTH_KV, userId)).toBe("none");
    await seedGrant(userId, "ordinary-1", "some-claude-client");
    expect(await grantsRemainFor(entryEnv().OAUTH_KV, userId)).toBe("some");
  });

  it("follows the pages past a page of autonomy grants only, and a page it cannot read is unknown", async () => {
    const userId = freshUserId();
    objectFor(userId);
    // Listed in key order: the autonomy grant's page comes first.
    await seedGrant(userId, "a-auto", AUTONOMY_CLIENT_ID);
    await seedGrant(userId, "b-ordinary", "some-claude-client");
    const real = entryEnv().OAUTH_KV;
    const paged = (rejectLater: boolean) =>
      new Proxy(real, {
        get(target, prop) {
          if (prop === "list") {
            return (options: KVNamespaceListOptions = {}) => {
              if (rejectLater && options.cursor !== undefined) {
                return Promise.reject(new Error("the store could not list this page"));
              }
              return target.list({ ...options, limit: 1 });
            };
          }
          const value = Reflect.get(target, prop, target) as unknown;
          return typeof value === "function"
            ? (value as (...args: unknown[]) => unknown).bind(target)
            : value;
        },
      });
    expect(await grantsRemainFor(paged(false), userId)).toBe("some");
    expect(await grantsRemainFor(paged(true), userId)).toBe("unknown");
    await helpers().revokeGrant("b-ordinary", userId);
    expect(await grantsRemainFor(paged(false), userId)).toBe("none");
  });
});
