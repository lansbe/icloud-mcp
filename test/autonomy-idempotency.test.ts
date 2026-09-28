// Never a second draft, and the owner's status record (Phase 28, plan 28-03
// Task 2; AUTO-12, AUTO-15; D-15, D-17; PITFALLS #44).
//
// AT MOST ONCE (D-15). Before each action the job writes an "already acted"
// record as `reserved`, synchronously, then makes the one call, then writes
// what happened. A redelivered alarm, or a run that died between the call and
// its bookkeeping, finds the record and never acts again. A missed draft is
// better than two. A record found still `reserved` becomes `unknown`, once, and
// the activity says so.
//
// THE OWNER'S RECORD (D-17). Each run writes `autonomy-status:v1:<userId>` to
// the sign-in store: the next wake, the count of refused sign-ins, the last
// run's time and outcome, and the rule count. Nothing else, and it expires
// after three days. The key's user id is the object's stored own name.
//
// Two layers: the job driven directly with recording deps, and the real object
// through its real alarm. Nothing here opens a network connection.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { ACTIVITY_KEY, type ActivityEntry } from "../src/agent/activity";
import { AUTONOMY_KEY } from "../src/agent/autonomy";
import { JOB_AUTH_FAILURES_KEY, JOB_NEXT_AT_KEY, RULES_KEY } from "../src/agent/job";
import { nextWakeAfter } from "../src/agent/cadence";
import type { UserAgent } from "../src/agent/user-agent";
import { ConnectionBusyError } from "../src/errors";
import { connectImap } from "../src/mail/socket";
import { entryEnv } from "./fixtures/bound-secrets";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import {
  DRAFT,
  FLAG,
  MIN,
  NAME,
  RULE_TEXT,
  T0,
  actions,
  armedStorage,
  directRun,
  newRow,
  rule,
  toolError,
} from "./fixtures/job-direct";
import { routeSelfCalls, signInArmed, statusSession } from "./fixtures/rules-job";

/** The owner's status key for a user id: the literal D-17 names. */
function statusKey(userId: string): string {
  return `autonomy-status:v1:${userId}`;
}

/** The ring, oldest first. */
function ring(storage: ReturnType<typeof armedStorage>): ActivityEntry[] {
  return (storage.get<ActivityEntry[]>(ACTIVITY_KEY) ?? []).slice();
}

/** Every acted record, by key. */
function acted(storage: ReturnType<typeof armedStorage>): [string, { state: string }][] {
  return [...storage.list<{ state: string }>({ prefix: "acted:" })];
}

// ===================================================== at most once (AUTO-12)

describe("never a second draft (AUTO-12, D-15)", () => {
  it("the same change answer delivered to two runs: one reply in total", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const rows = [newRow(1)];
    const first = await directRun(storage, { rows });
    const second = await directRun(storage, { rows, now: T0 + 15 * MIN });
    const replies = [...first.calls, ...second.calls].filter((call) => call.tool === "mail_compose_reply");
    expect(replies).toHaveLength(1);
    expect(second.outcome).toBe("done");
  });

  it("a run that dies after the draft call and before its bookkeeping: the next run makes no draft call and says unknown", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const put = storage.put.bind(storage);
    let armed = true;
    storage.put = <T>(key: string, value: T) => {
      const state = (value as { state?: unknown } | null)?.state;
      if (armed && key.startsWith("acted:") && state !== "reserved") {
        armed = false;
        throw new Error("the write after the call did not land");
      }
      put(key, value);
    };
    const first = await directRun(storage, { rows: [newRow(1)] });
    expect(first.outcome).toBe("failed");
    expect(actions(first.calls).map((call) => call.tool)).toEqual(["mail_compose_reply"]);
    expect(acted(storage).map(([, value]) => value.state)).toEqual(["reserved"]);

    const second = await directRun(storage, { rows: [newRow(1)], now: T0 + 15 * MIN });
    expect(actions(second.calls)).toEqual([]);
    expect(second.calls.map((call) => call.tool)).toEqual(["changes_since"]);
    const draftEntries = ring(storage).filter((entry) => entry.kind === "draft");
    expect(draftEntries.map((entry) => [entry.messageId, entry.outcome])).toEqual([["INBOX-msg-1", "unknown"]]);
    expect(acted(storage).map(([, value]) => value.state)).toEqual(["unknown"]);

    // Said once: a third run over the same answer adds no second entry.
    await directRun(storage, { rows: [newRow(1)], now: T0 + 30 * MIN });
    expect(ring(storage).filter((entry) => entry.kind === "draft")).toHaveLength(1);
  });

  for (const [name, then] of [
    ["a flag", FLAG],
    ["a draft", DRAFT],
  ] as const) {
    it(`a reserved record left by an earlier run: ${name} is never attempted again`, async () => {
      const storage = armedStorage([rule("r1", then)]);
      const primed = armedStorage([rule("r1", then)]);
      await directRun(primed, { rows: [newRow(1)] });
      const [key] = acted(primed)[0] as [string, unknown];
      storage.put(key, { state: "reserved", at: T0 - MIN });
      const run = await directRun(storage, { rows: [newRow(1)], now: T0 + 15 * MIN });
      expect(actions(run.calls)).toEqual([]);
      expect(ring(storage).filter((entry) => entry.kind !== "run").map((entry) => entry.outcome)).toEqual(["unknown"]);
    });
  }

  for (const [name, then, tool] of [
    ["a flag", FLAG, "mail_flag"],
    ["a draft", DRAFT, "mail_compose_reply"],
  ] as const) {
    it(`the order for ${name}: the record stored as reserved, then the call, then the record updated`, async () => {
      const storage = armedStorage([rule("r1", then)]);
      const run = await directRun(storage, { rows: [newRow(1)] });
      const around = run.events.filter((event) => event.startsWith("put acted:") || event === `call ${tool}`);
      expect(around).toHaveLength(3);
      expect(around[0]?.startsWith("put acted:")).toBe(true);
      expect(around[1]).toBe(`call ${tool}`);
      expect(around[2]).toBe(around[0]);
    });
  }
});

// ============================================== the owner's record (AUTO-15)

/** The one status write a run made, parsed. */
function onlyStatus(run: Awaited<ReturnType<typeof directRun>>): {
  key: string;
  value: Record<string, unknown>;
  ttl: number;
} {
  expect(run.statuses).toHaveLength(1);
  const [write] = run.statuses;
  return { key: write!.key, value: JSON.parse(write!.value) as Record<string, unknown>, ttl: write!.options.expirationTtl };
}

describe("the owner's status record, from the job (AUTO-15, D-17)", () => {
  const ends: Array<[string, Parameters<typeof directRun>[1], string]> = [
    ["a run that reached the end", { rows: [newRow(1)] }, "done"],
    [
      "a run that stopped",
      { rows: [newRow(1)], answer: (tool) => (tool === "changes_since" ? toolError(new ConnectionBusyError()) : undefined) },
      "busy",
    ],
    // A call that throws inside the recording session escapes it, so the job's
    // own catch answers `failed`.
    ["a run that threw", { rows: [newRow(1)], answer: () => { throw new Error("thrown"); } }, "failed"],
  ];

  for (const [name, options, expected] of ends) {
    it(`${name}: one record under the person's own key, exactly the six keys, three days`, async () => {
      const storage = armedStorage([rule("r1", FLAG), rule("r2", DRAFT)]);
      storage.put(JOB_AUTH_FAILURES_KEY, 1);
      const run = await directRun(storage, options);
      expect(run.outcome).toBe(expected);
      const status = onlyStatus(run);
      expect(status.key).toBe(statusKey(NAME));
      expect(Object.keys(status.value).sort()).toEqual(
        ["authFailures", "lastOutcome", "lastRunAt", "nextAt", "rules", "v"].sort(),
      );
      expect(status.value).toEqual({
        v: 1,
        nextAt: nextWakeAfter(T0, NAME),
        authFailures: expected === "done" ? 0 : 1,
        lastRunAt: T0,
        lastOutcome: expected,
        rules: 2,
      });
      expect(status.ttl).toBe(3 * 24 * 60 * 60);
      // Written at the end of the run.
      expect(run.events.at(-1)).toBe("status");
    });
  }

  it("runs that end before any I/O write no record: no rules, no key, a retry, not yet due", async () => {
    const noRules = armedStorage([]);
    expect((await directRun(noRules, { rows: [newRow(1)] })).statuses).toEqual([]);
    const noKey = armedStorage([rule("r1", FLAG)]);
    noKey.delete(AUTONOMY_KEY);
    expect((await directRun(noKey, { rows: [newRow(1)] })).statuses).toEqual([]);
    const retry = armedStorage([rule("r1", FLAG)]);
    expect((await directRun(retry, { rows: [newRow(1)], isRetry: true })).statuses).toEqual([]);
    const notDue = armedStorage([rule("r1", FLAG)]);
    notDue.put(JOB_NEXT_AT_KEY, T0 + 5 * MIN);
    const early = await directRun(notDue, { rows: [newRow(1)], keepNextAt: true });
    expect(early.outcome).toBe("not_due");
    expect(early.statuses).toEqual([]);
  });

  it("mail whose subject and sender are unique marker strings: the record holds neither, and no @", async () => {
    const SUBJECT = "subject-marker-7f3a91c2";
    const SENDER_LOCAL = "sender-marker-4be0d5";
    const storage = armedStorage([
      rule("r1", { flag: true, draft: { text: `${RULE_TEXT} text-marker-19ac` } }, { fromAddresses: [`${SENDER_LOCAL}@example.com`] }),
    ]);
    const run = await directRun(storage, {
      rows: [newRow(1, { subject: SUBJECT, fromAddress: `${SENDER_LOCAL}@example.com` })],
    });
    expect(run.outcome).toBe("done");
    expect(actions(run.calls)).toHaveLength(2);
    expect(run.statuses).toHaveLength(1);
    const raw = run.statuses[0]?.value ?? "";
    expect(raw).not.toContain(SUBJECT);
    expect(raw).not.toContain(SENDER_LOCAL);
    expect(raw).not.toContain("text-marker-19ac");
    expect(raw).not.toContain("INBOX-msg-1");
    expect(raw).not.toContain("@");
  });

  it("the status write failing does not change the run's outcome, and the run resolves", async () => {
    const storage = armedStorage([rule("r1", FLAG)]);
    const run = await directRun(storage, {
      rows: [newRow(1)],
      over: {
        statusStore: {
          put: async () => {
            throw new Error("the store refused");
          },
        },
      } as never,
    });
    expect(run.outcome).toBe("done");
    expect(acted(storage).map(([, value]) => value.state)).toEqual(["flagged"]);
  });
});

// ======================================================= through the object

const handedOut: FakeDuplex[] = [];
let queued: (() => FakeDuplex)[] = [];

beforeEach(() => {
  handedOut.length = 0;
  queued = [];
  vi.mocked(connectImap).mockReset();
  vi.mocked(connectImap).mockImplementation((() => {
    const next = queued.shift();
    if (next === undefined) throw new Error("the test queued no more sessions");
    const duplex = next();
    handedOut.push(duplex);
    return duplex;
  }) as never);
  vi.stubGlobal("fetch", async () => new Response(null, { status: 500 }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the owner's status record, through the real alarm (AUTO-15, D-17)", () => {
  it("after a run, the sign-in store holds the record under the object's stored own name: six keys, about three days", async () => {
    const armed = await signInArmed();
    try {
      await routeSelfCalls(armed);
      const added = await armed.stub.addRule({ when: { fromAddresses: ["a@example.invalid"] }, then: { flag: true } });
      expect(added.ok).toBe(true);
      queued.push(() => statusSession(4393, "118"));
      const before = Date.now();
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
      expect(queued).toHaveLength(0);

      const kv = entryEnv().OAUTH_KV;
      const raw = await kv.get(statusKey(armed.userId));
      expect(raw).not.toBeNull();
      const value = JSON.parse(raw as string) as Record<string, unknown>;
      expect(Object.keys(value).sort()).toEqual(["authFailures", "lastOutcome", "lastRunAt", "nextAt", "rules", "v"]);
      expect(value).toMatchObject({ v: 1, authFailures: 0, lastOutcome: "started", rules: 1 });
      expect(value.lastRunAt as number).toBeGreaterThanOrEqual(before);
      expect(value.nextAt).toBe(await runInDurableObject(armed.stub, (_i, state) => state.storage.kv.get(JOB_NEXT_AT_KEY)));
      expect(raw).not.toContain("@");

      const listed = (await kv.list({ prefix: statusKey(armed.userId) })).keys;
      expect(listed).toHaveLength(1);
      const expiration = listed[0]?.expiration as number;
      const threeDays = 3 * 24 * 60 * 60;
      expect(expiration).toBeGreaterThanOrEqual(Math.floor(before / 1000) + threeDays - 5);
      expect(expiration).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + threeDays + 5);
    } finally {
      await armed.cleanup();
    }
  });

  it("an object with no stored own name runs no job, writes no record and makes no outbound call", async () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const userId = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const stub = entryEnv().USER_AGENT.getByName(userId);
    const seen: string[] = [];
    try {
      await runInDurableObject(stub, (instance: UserAgent, state) => {
        state.storage.kv.put(AUTONOMY_KEY, { v: 1, grantId: "g", sealedRefreshToken: "x", iv: "y", armedAt: 0, generation: 1 });
        state.storage.kv.put(RULES_KEY, [{ v: 1, id: "r1", createdAt: 0, when: { fromAddresses: ["a@example.com"] }, then: { flag: true } }]);
        instance.autonomySelfFetch = async (request: Request) => {
          seen.push(new URL(request.url).pathname);
          return new Response(null, { status: 500 });
        };
      });
      expect(await runInDurableObject(stub, (instance: UserAgent) => instance.storedOwnName())).toBeNull();
      await runInDurableObject(stub, (_i, state) => state.storage.setAlarm(Date.now() + 1000));
      expect(await runDurableObjectAlarm(stub)).toBe(true);
      expect(seen).toEqual([]);
      expect(await entryEnv().OAUTH_KV.get(statusKey(userId))).toBeNull();
      const keys = await runInDurableObject(stub, (_i, state) => [...state.storage.kv.list()].map(([key]) => key));
      expect(keys.filter((key) => key.startsWith("job:") || key === ACTIVITY_KEY)).toEqual([]);
    } finally {
      await runInDurableObject(stub, async (_i, state) => {
        for (const [key] of state.storage.kv.list()) state.storage.kv.delete(key);
        await state.storage.deleteAlarm();
      });
    }
  });
});
