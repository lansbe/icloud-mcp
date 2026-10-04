// The rules job's clock (Phase 28, plan 28-02 Task 1; AUTO-08, D-07, D-14, D-25).
//
// The job wakes every 15 minutes, a literal nobody can set, at an offset taken
// from the person's own user id, so the people who have rules do not all wake
// at once. It asks for every wake through the object's one scheduling helper
// (25 D-23), which keeps the earliest time any job asked for, so the job never
// moves another job's earlier alarm later. It asks for its next wake before any
// outbound call, so a run that dies still leaves the alarm set. And a person
// with no rules costs nothing at all.
//
// Three layers of case: the pure cadence functions; the job driven directly
// with recording deps; and the real object, driven through its real alarm.
// Objects are seeded with a sealed record the way test/autonomy-alarm.test.ts
// does it, except the zero-cost case, which signs in for real through the
// login-proof worker, because D-25 is about a real signed-in person.

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(() => {
    throw new Error("no iCloud session is expected in this file");
  }),
}));

import { AUTONOMY_KEY, type AutonomyRecord, seal } from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import { JOB_CADENCE_MS, jobOffsetMs, nextWakeAfter } from "../src/agent/cadence";
import { JOB_NEXT_AT_KEY, type JobDeps, RULES_KEY, runAutonomyJob } from "../src/agent/job";
import { parseRule, type Rule } from "../src/agent/rules";
import { UserAgent } from "../src/agent/user-agent";
import { oauthProviderOptions } from "../src/auth/oauth";
import { userIdOf } from "../src/principal";
import { connectImap } from "../src/mail/socket";
// The two modules' own source, read at build time by Vite, for the literal pin.
// @ts-expect-error — a raw import has no ambient declaration here.
import CADENCE_SOURCE from "../src/agent/cadence.ts?raw";
// @ts-expect-error — a raw import has no ambient declaration here.
import JOB_SOURCE from "../src/agent/job.ts?raw";
import { entryEnv } from "./fixtures/bound-secrets";
import { signInArmed, type Stub } from "./fixtures/rules-job";
import { LISTED_APPLE_ID } from "./fixtures/worker-with-login-proof";

const MIN = 60_000;
const DAY = 24 * 60 * MIN;

// ------------------------------------------------------------------ helpers

/** Lower-case hex SHA-256 of `text`: a valid user id. */
async function hexId(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A fresh 64-hex user id nothing else touches. */
function freshUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The listed address's user id. The session admits only a person on the allow
 * list, so a case that needs the job to reach this Worker uses this id; the
 * file's cases run one after another and each cleans its object up.
 */
function listedUserId(): Promise<string> {
  return userIdOf(LISTED_APPLE_ID) as Promise<string>;
}

/** A fresh user id whose next wake is at least `gapMs` after now. */
function freshUserIdWithGap(gapMs: number): string {
  for (;;) {
    const id = freshUserId();
    if (nextWakeAfter(Date.now(), id) - Date.now() >= gapMs) return id;
  }
}

/** A flag rule, stored shape, for the job's own storage. */
function storedFlagRule(id = "rule-1", createdAt = 0): Rule {
  return { v: 1, id, createdAt, when: { fromAddresses: ["a@example.com"] }, then: { flag: true } };
}

/** A key-value store in memory, in the shape the job uses. */
function memoryStorage(seed: Record<string, unknown> = {}) {
  const map = new Map<string, unknown>(Object.entries(seed));
  return {
    map,
    get<T = unknown>(key: string): T | undefined {
      return map.get(key) as T | undefined;
    },
    put<T>(key: string, value: T): void {
      map.set(key, value);
    },
    delete(key: string): boolean {
      return map.delete(key);
    },
    *list<T = unknown>(options: { prefix?: string } = {}): Iterable<[string, T]> {
      for (const [key, value] of [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
        if (options.prefix === undefined || key.startsWith(options.prefix)) yield [key, value as T];
      }
    },
  };
}

/** Everything a direct run recorded, in order. */
interface Recorded {
  readonly events: string[];
  readonly wakes: number[];
}

/** Deps for a direct run whose session fails before any call. */
function directDeps(
  storage: ReturnType<typeof memoryStorage>,
  name: string,
  now: number,
  over: Partial<JobDeps> = {},
): { deps: JobDeps; recorded: Recorded } {
  const recorded: Recorded = { events: [], wakes: [] };
  const deps: JobDeps = {
    storage,
    name,
    now: () => now,
    isRetry: false,
    requestWake: async (wantedAt) => {
      recorded.events.push("wake");
      recorded.wakes.push(wantedAt);
    },
    withSession: async () => {
      recorded.events.push("session");
      return { kind: "failed" };
    },
    disarm: async () => {
      recorded.events.push("disarm");
    },
    statusStore: { put: async () => {} },
    ...over,
  };
  return { deps, recorded };
}

type Touched = { stub: Stub; userId: string };
const touched: Touched[] = [];

/** Seams replaced on a live instance, put back after each case. */
const restores: (() => Promise<void>)[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const restore of restores.splice(0).reverse()) await restore();
  const kv = entryEnv().OAUTH_KV;
  for (const { stub, userId } of touched.splice(0)) {
    for (const prefix of [`grant:${userId}:`, `token:${userId}:`]) {
      for (const key of (await kv.list({ prefix })).keys) await kv.delete(key.name);
    }
    // The owner's status record a run writes (plan 28-03).
    await kv.delete(`autonomy-status:v1:${userId}`);
    await runInDurableObject(stub, async (_i, state) => {
      for (const [key] of state.storage.kv.list()) state.storage.kv.delete(key);
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
      await state.storage.deleteAlarm();
    });
  }
});

/** The object for `userId`, by name, remembered for clean-up. */
function objectFor(userId: string): Stub {
  const stub = entryEnv().USER_AGENT.getByName(userId);
  touched.push({ stub, userId });
  return stub;
}

/** A grant in the library's summary shape, under the library's key. */
function seedGrant(userId: string, id: string, clientId: string): Promise<void> {
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
    }),
  );
}

/**
 * An armed object: an autonomy grant and an ordinary one in the store, a
 * sealed record past the standing check's grace, and the object's stored name.
 */
async function seedArmed(userId: string): Promise<Stub> {
  const stub = objectFor(userId);
  await seedGrant(userId, "auto-1", AUTONOMY_CLIENT_ID);
  await seedGrant(userId, "ordinary-1", "some-claude-client");
  const sealed = await seal(entryEnv().AUTONOMY_SEAL_KEY, userId, `${userId}:auto-1:not-a-real-secret`);
  expect(sealed).not.toBeNull();
  const record: AutonomyRecord = {
    v: 1,
    grantId: "auto-1",
    sealedRefreshToken: sealed!.sealedRefreshToken,
    iv: sealed!.iv,
    armedAt: Math.floor(Date.now() / 1000) - 11 * 60,
    generation: 1,
  };
  await runInDurableObject(stub, (_i, state) => {
    state.storage.kv.put(AUTONOMY_KEY, record);
    state.storage.kv.put("own-name", userId);
  });
  return stub;
}

/** Replace the object's seam to this Worker. Answers the paths it saw. */
async function recordSelfCalls(
  stub: Stub,
  answer: () => Promise<Response> = async () => new Response(null, { status: 500 }),
): Promise<string[]> {
  const seen: string[] = [];
  await runInDurableObject(stub, (instance: UserAgent) => {
    // The instance outlives the case, so the real seam is put back after it.
    const real = instance.autonomySelfFetch;
    restores.push(() =>
      runInDurableObject(stub, (again: UserAgent) => {
        again.autonomySelfFetch = real;
      }),
    );
    instance.autonomySelfFetch = async (request: Request) => {
      seen.push(new URL(request.url).pathname);
      return answer();
    };
  });
  return seen;
}

function alarmAt(stub: Stub): Promise<number | null> {
  return runInDurableObject(stub, (_i, state) => state.storage.getAlarm());
}

/** Run the real alarm, after making sure one is set. */
async function runAlarm(stub: Stub): Promise<void> {
  if ((await alarmAt(stub)) === null) {
    await runInDurableObject(stub, (_i, state) => state.storage.setAlarm(Date.now() + 1000));
  }
  expect(await runDurableObjectAlarm(stub)).toBe(true);
}

/** Every key in the object's storage. */
function storedKeys(stub: Stub): Promise<string[]> {
  return runInDurableObject(stub, (_i, state) => [...state.storage.kv.list()].map(([key]) => key));
}

function storedNextAt(stub: Stub): Promise<unknown> {
  return runInDurableObject(stub, (_i, state) => state.storage.kv.get(JOB_NEXT_AT_KEY));
}

async function addFlagRule(stub: Stub): Promise<string> {
  const added = await stub.addRule({ when: { fromAddresses: ["a@example.com"] }, then: { flag: true } });
  expect(added.ok).toBe(true);
  return added.ok ? added.id : "";
}

// ------------------------------------------------------ the pure functions

describe("the cadence is one literal (AUTO-08, D-07)", () => {
  it("is 15 minutes, 900 000 ms, with its arithmetic written beside it", () => {
    expect(JOB_CADENCE_MS).toBe(900000);
    expect(JOB_CADENCE_MS).toBe(15 * 60 * 1000);
    expect(CADENCE_SOURCE).toContain("export const JOB_CADENCE_MS = 900000;");
    expect(CADENCE_SOURCE).toContain("15 × 60 × 1000 = 900 000");
  });

  it("lives in cadence.ts only: job.ts holds no copy of the number", () => {
    expect(JOB_SOURCE).not.toMatch(/900[_ ]?000/);
    expect(JOB_SOURCE).not.toMatch(/15 \* 60/);
  });
});

describe("the per-person offset (D-07)", () => {
  it("is an integer in [0, cadence) and the same on every call for one id", async () => {
    for (let i = 0; i < 16; i += 1) {
      const id = await hexId(`person-${i}`);
      const offset = jobOffsetMs(id);
      expect(Number.isInteger(offset)).toBe(true);
      expect(offset).toBeGreaterThanOrEqual(0);
      expect(offset).toBeLessThan(JOB_CADENCE_MS);
      expect(jobOffsetMs(id)).toBe(offset);
    }
  });

  it("is the first 8 hex digits read as an integer, modulo the cadence", () => {
    const id = `0000ffff${"0".repeat(56)}`;
    expect(jobOffsetMs(id)).toBe(0xffff % JOB_CADENCE_MS);
    const high = `ffffffff${"a".repeat(56)}`;
    expect(jobOffsetMs(high)).toBe(0xffffffff % JOB_CADENCE_MS);
  });

  it("spreads 64 distinct ids over at least 32 distinct seconds of the cadence", async () => {
    const seconds = new Set<number>();
    for (let i = 0; i < 64; i += 1) seconds.add(Math.floor(jobOffsetMs(await hexId(`spread-${i}`)) / 1000));
    expect(seconds.size).toBeGreaterThanOrEqual(32);
  });

  const refused: Array<[string, unknown]> = [
    ["upper-case hex", "A".repeat(64)],
    ["63 digits", "a".repeat(63)],
    ["65 digits", "a".repeat(65)],
    ["a non-hex letter", `g${"a".repeat(63)}`],
    ["the empty string", ""],
    ["not a string", 12345],
  ];
  for (const [name, value] of refused) {
    it(`answers 0 for ${name}`, () => {
      expect(jobOffsetMs(value as string)).toBe(0);
    });
  }
});

describe("the next wake (D-07)", () => {
  it("is strictly after now, at most one cadence after it, and on the person's offset", async () => {
    const id = await hexId("wake-person");
    const offset = jobOffsetMs(id);
    const starts = [0, 1, offset, offset - 1, offset + 1, 1_790_000_000_000, 1_790_000_000_000 + offset];
    for (const now of starts) {
      const next = nextWakeAfter(now, id);
      expect(next).toBeGreaterThan(now);
      expect(next - now).toBeLessThanOrEqual(JOB_CADENCE_MS);
      expect((((next - offset) % JOB_CADENCE_MS) + JOB_CADENCE_MS) % JOB_CADENCE_MS).toBe(0);
    }
  });

  it("a time exactly on the offset gives the next slot, a whole cadence later", async () => {
    const id = await hexId("on-the-slot");
    const now = 1_790_000_000_000 - (1_790_000_000_000 % JOB_CADENCE_MS) + jobOffsetMs(id);
    expect(nextWakeAfter(now, id)).toBe(now + JOB_CADENCE_MS);
  });
});

describe("no rule field can name a time (AUTO-08)", () => {
  const keys = ["every", "interval", "cadence", "schedule", "at", "minutes"];
  const base = { when: { fromAddresses: ["a@example.com"] }, then: { flag: true } };
  for (const key of keys) {
    it(`refuses "${key}" at the top, in when and in then`, () => {
      expect(parseRule({ ...base, [key]: 5 })).toMatchObject({ ok: false, refusal: "unknown-key" });
      expect(parseRule({ ...base, when: { ...base.when, [key]: 5 } })).toMatchObject({
        ok: false,
        refusal: "unknown-key",
      });
      expect(parseRule({ ...base, then: { ...base.then, [key]: 5 } })).toMatchObject({
        ok: false,
        refusal: "unknown-key",
      });
    });
  }

  it("no method the object exposes names a time, a cadence or a schedule", () => {
    const names = Object.getOwnPropertyNames(UserAgent.prototype);
    expect(names).toContain("addRule");
    for (const name of names) {
      expect(name).not.toMatch(/cadence|interval|schedule|every|wake|timer|period|alarmat/i);
    }
  });
});

// ------------------------------------------------------- the job, directly

describe("the job's due check and its wake, driven directly (D-14, D-25)", () => {
  it("with no rules: asks for no wake, opens no session, writes nothing", async () => {
    const storage = memoryStorage({ [AUTONOMY_KEY]: { any: "record" } });
    const { deps, recorded } = directDeps(storage, await hexId("no-rules"), 1_790_000_000_000);
    expect(await runAutonomyJob(deps)).toBe("no_rules");
    expect(recorded.events).toEqual([]);
    expect([...storage.map.keys()]).toEqual([AUTONOMY_KEY]);
  });

  it("with no autonomy record: asks for no wake, opens no session, writes nothing", async () => {
    const storage = memoryStorage({ [RULES_KEY]: [storedFlagRule()] });
    const { deps, recorded } = directDeps(storage, await hexId("no-record"), 1_790_000_000_000);
    expect(await runAutonomyJob(deps)).toBe("not_armed");
    expect(recorded.events).toEqual([]);
    expect([...storage.map.keys()]).toEqual([RULES_KEY]);
  });

  it("a due run asks for nextWakeAfter(now, name) FIRST, then opens its session, and stores it", async () => {
    const name = await hexId("due");
    const now = 1_790_000_000_123;
    const storage = memoryStorage({ [RULES_KEY]: [storedFlagRule()], [AUTONOMY_KEY]: {} });
    const { deps, recorded } = directDeps(storage, name, now);
    expect(await runAutonomyJob(deps)).toBe("session_failed");
    expect(recorded.events).toEqual(["wake", "session"]);
    expect(recorded.wakes).toEqual([nextWakeAfter(now, name)]);
    expect(storage.get(JOB_NEXT_AT_KEY)).toBe(nextWakeAfter(now, name));
  });

  it("a session that throws still leaves the wake asked for", async () => {
    const name = await hexId("throws");
    const now = 1_790_000_000_000;
    const storage = memoryStorage({ [RULES_KEY]: [storedFlagRule()], [AUTONOMY_KEY]: {} });
    const { deps, recorded } = directDeps(storage, name, now, {
      withSession: async () => {
        throw new Error("the redemption seam threw");
      },
    });
    expect(await runAutonomyJob(deps)).toBe("failed");
    expect(recorded.wakes).toEqual([nextWakeAfter(now, name)]);
  });

  it("a run whose time has not come opens no session, writes nothing, and asks for its own time again", async () => {
    const name = await hexId("early");
    const now = 1_790_000_000_000;
    const own = nextWakeAfter(now, name);
    const storage = memoryStorage({
      [RULES_KEY]: [storedFlagRule()],
      [AUTONOMY_KEY]: {},
      [JOB_NEXT_AT_KEY]: own,
    });
    const before = new Map(storage.map);
    const { deps, recorded } = directDeps(storage, name, now);
    expect(await runAutonomyJob(deps)).toBe("not_due");
    expect(recorded.events).toEqual(["wake"]);
    expect(recorded.wakes).toEqual([own]);
    expect(storage.map).toEqual(before);
  });

  it("a stored next wake more than one cadence ahead is not trusted: the run is due", async () => {
    const name = await hexId("far");
    const now = 1_790_000_000_000;
    const storage = memoryStorage({
      [RULES_KEY]: [storedFlagRule()],
      [AUTONOMY_KEY]: {},
      [JOB_NEXT_AT_KEY]: now + 3 * DAY,
    });
    const { deps, recorded } = directDeps(storage, name, now);
    expect(await runAutonomyJob(deps)).toBe("session_failed");
    expect(recorded.events).toEqual(["wake", "session"]);
  });

  it("a platform retry asks for nothing and opens no session", async () => {
    const storage = memoryStorage({ [RULES_KEY]: [storedFlagRule()], [AUTONOMY_KEY]: {} });
    const { deps, recorded } = directDeps(storage, await hexId("retry"), 1_790_000_000_000, { isRetry: true });
    expect(await runAutonomyJob(deps)).toBe("retry");
    expect(recorded.events).toEqual([]);
  });
});

// ------------------------------------------------- the job, on the object

describe("the job on the one shared alarm (D-14, 25 D-23)", () => {
  it("armed with one rule: after a run the alarm is at or before the person's next wake, on their offset", async () => {
    const userId = await listedUserId();
    const stub = await seedArmed(userId);
    await addFlagRule(stub);
    const seen = await recordSelfCalls(stub);

    await runAlarm(stub);

    const after = Date.now();
    const alarm = await alarmAt(stub);
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeLessThanOrEqual(nextWakeAfter(after, userId));
    const nextAt = (await storedNextAt(stub)) as number;
    expect((((nextAt - jobOffsetMs(userId)) % JOB_CADENCE_MS) + JOB_CADENCE_MS) % JOB_CADENCE_MS).toBe(0);
    expect(nextAt).toBeLessThanOrEqual(nextWakeAfter(after, userId));
    // The session was tried: the redemption asked this Worker's token endpoint.
    expect(seen).toContain("/oauth/token");
  });

  it("an earlier alarm another job already holds is kept earlier", async () => {
    const userId = freshUserIdWithGap(5 * MIN);
    const stub = await seedArmed(userId);
    await addFlagRule(stub);
    await recordSelfCalls(stub);
    const earlier = Date.now() + 2 * MIN;
    expect(earlier).toBeLessThan(nextWakeAfter(Date.now(), userId));

    const alarm = await runInDurableObject(stub, async (instance: UserAgent, state) => {
      await state.storage.setAlarm(earlier);
      await instance.alarm();
      return state.storage.getAlarm();
    });

    expect(alarm).toBe(earlier);
    // The job did run and did ask for its own, later, time.
    expect(await storedNextAt(stub)).toBeGreaterThan(earlier);
  });

  it("no autonomy record: the job makes no outbound call and stores no wake", async () => {
    const userId = freshUserId();
    const stub = objectFor(userId);
    await addFlagRule(stub);
    const seen = await recordSelfCalls(stub);

    await runAlarm(stub);

    expect(seen).toEqual([]);
    expect(await storedNextAt(stub)).toBeUndefined();
  });

  it("a run fired early for another job makes no outbound call and re-asks for its own time", async () => {
    const userId = await listedUserId();
    const stub = await seedArmed(userId);
    await addFlagRule(stub);
    const seen = await recordSelfCalls(stub);

    await runAlarm(stub);
    const own = (await storedNextAt(stub)) as number;
    expect(own).toBeGreaterThan(Date.now());
    const callsAfterFirst = seen.length;
    expect(callsAfterFirst).toBeGreaterThan(0);

    // Fire the actual handler early, with its consumed alarm cleared as the
    // runtime does. A real +10 ms alarm races the simulator's own delivery
    // against runDurableObjectAlarm() on a busy CI host.
    await runInDurableObject(stub, async (instance: UserAgent, state) => {
      await state.storage.deleteAlarm();
      await instance.alarm();
    });

    expect(seen.length).toBe(callsAfterFirst);
    expect(await storedNextAt(stub)).toBe(own);
    const alarm = await alarmAt(stub);
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeLessThanOrEqual(own);
  });

  it("addRule on an armed object with no alarm sets one no later than the next wake", async () => {
    const userId = freshUserId();
    const stub = await seedArmed(userId);
    await runInDurableObject(stub, (_i, state) => state.storage.deleteAlarm());

    const before = Date.now();
    await addFlagRule(stub);
    const after = Date.now();

    const alarm = await alarmAt(stub);
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeGreaterThanOrEqual(before);
    expect(alarm!).toBeLessThanOrEqual(nextWakeAfter(after, userId));
  });

  it("removing the last rule leaves the job asking for nothing: the next alarm makes no call", async () => {
    const userId = freshUserId();
    const stub = await seedArmed(userId);
    const id = await addFlagRule(stub);
    expect(await stub.removeRule(id)).toEqual({ removed: true });
    const seen = await recordSelfCalls(stub);

    await runAlarm(stub);

    expect(seen).toEqual([]);
    expect(await storedNextAt(stub)).toBeUndefined();
    expect(await runInDurableObject(stub, (_i, state) => state.storage.kv.get(RULES_KEY))).toBeUndefined();
  });

  it("a redemption seam that throws still leaves the alarm set at the next wake", async () => {
    const userId = await listedUserId();
    const stub = await seedArmed(userId);
    await addFlagRule(stub);
    const seen = await recordSelfCalls(stub, async () => {
      throw new Error("the seam threw");
    });

    await runAlarm(stub);

    expect(seen).toContain("/oauth/token");
    const alarm = await alarmAt(stub);
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeLessThanOrEqual(nextWakeAfter(Date.now(), userId));
  });

  it("addRule refuses a rule that names a time, and stores nothing", async () => {
    const userId = freshUserId();
    const stub = objectFor(userId);
    const answer = await stub.addRule({
      when: { fromAddresses: ["a@example.com"] },
      then: { flag: true },
      every: 60_000,
    });
    expect(answer).toMatchObject({ ok: false, refusal: "unknown-key" });
    expect(await runInDurableObject(stub, (_i, state) => state.storage.kv.get(RULES_KEY))).toBeUndefined();
  });
});

describe("an armed person with no rules costs nothing (D-25)", () => {
  it("three alarm runs: no self-call, no job, acted or activity key, no status record, no iCloud session; Phase 27's job still runs", async () => {
    const armed = await signInArmed();
    try {
      const seen: string[] = [];
      let standingAsked = 0;
      await runInDurableObject(armed.stub, (instance: UserAgent, state) => {
        // Past the standing check's grace, so Phase 27's job asks the listing
        // each run and the count below shows it ran.
        const record = state.storage.kv.get<AutonomyRecord>(AUTONOMY_KEY) as AutonomyRecord;
        state.storage.kv.put(AUTONOMY_KEY, { ...record, armedAt: record.armedAt - 11 * 60 });
        const realFetch = instance.autonomySelfFetch;
        const real = instance.keyStanding;
        restores.push(() =>
          runInDurableObject(armed.stub, (again: UserAgent) => {
            again.autonomySelfFetch = realFetch;
            again.keyStanding = real;
          }),
        );
        instance.autonomySelfFetch = async (request: Request) => {
          seen.push(new URL(request.url).pathname);
          return new Response(null, { status: 500 });
        };
        instance.keyStanding = async (name: string, grantId: string) => {
          standingAsked += 1;
          return real(name, grantId);
        };
      });
      vi.mocked(connectImap).mockClear();

      for (let run = 1; run <= 3; run += 1) {
        await runAlarm(armed.stub);
        expect(standingAsked).toBe(run);
      }

      expect(seen).toEqual([]);
      const keys = await storedKeys(armed.stub);
      expect(keys.filter((key) => key.startsWith("job:"))).toEqual([]);
      expect(keys.filter((key) => key.startsWith("acted:"))).toEqual([]);
      expect(keys).not.toContain("activity");
      expect(keys).not.toContain(RULES_KEY);
      expect(keys).toContain(AUTONOMY_KEY);
      const status = await entryEnv().OAUTH_KV.list({ prefix: "autonomy-status:v1:" });
      expect(status.keys).toEqual([]);
      expect(vi.mocked(connectImap)).not.toHaveBeenCalled();
      // The key still stands: nothing about having no rules ended it.
      const grants = (await getOAuthApi(oauthProviderOptions, armed.env).listUserGrants(armed.userId)).items;
      expect(grants.filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID)).toHaveLength(1);
    } finally {
      await armed.cleanup();
    }
  });

  it("the same storage, driven directly: the scheduling helper is asked for no wake on the job's behalf", async () => {
    const storage = memoryStorage({ [AUTONOMY_KEY]: {}, "own-name": await hexId("nobody") });
    for (let run = 0; run < 3; run += 1) {
      const { deps, recorded } = directDeps(storage, await hexId("nobody"), 1_790_000_000_000 + run * MIN);
      expect(await runAutonomyJob(deps)).toBe("no_rules");
      expect(recorded.wakes).toEqual([]);
      expect(recorded.events).toEqual([]);
    }
  });
});
