// The rules job, end to end on the thinnest real slice (Phase 28, plan 28-01).
//
// One person signs in through the login-proof worker, which arms their
// autonomy key, because autonomy is inherent. They add one rule, "flag mail
// from this address", through the object's own method. Then the REAL alarm runs
// twice through `runDurableObjectAlarm`: the first is a starting point; the
// second finds two new messages, one from the rule's address. The job reaches
// mail only through Phase 27's session, which calls this Worker's own `/mcp`.
//
// THE ROUTE. The object's one seam to this Worker is pointed at the login-proof
// worker's default export, in this test's own module graph, so the socket
// module mocked below is the one the door's mail tools reach. So this is the
// real alarm, the real redemption, the real door, the real `changes_since` and
// the real `mail_flag`, over the fake duplex. Each duplex is built at the moment
// the socket is asked for, inside whatever request asked for it.
//
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID (D-09, D-13). The calendar half of the change check sees a stub that
// answers 500 for every request; the job ignores that half (D-02).

import {
  createExecutionContext,
  runDurableObjectAlarm,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { AUTONOMY_KEY } from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID, AUTONOMY_TOOLS } from "../src/agent/autonomy-client";
import type { UserAgent } from "../src/agent/user-agent";
import { AUTONOMY_NOTICE_FIELD, AUTONOMY_NOTICE_VERSION } from "../src/auth/login-page";
import { oauthProviderOptions } from "../src/auth/oauth";
import type { Env } from "../src/env";
import { connectImap } from "../src/mail/socket";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { userIdOf } from "../src/principal";
import { installAutonomyClient } from "./fixtures/autonomy-client";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  flagEcho,
  logoutExchange,
  selectResponse,
  statusResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  resetLoginProof,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The PKCE pair this file redeems ordinary codes with. Copied, pair intact. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";
const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** The rule's one sender, and a sender it does not name. */
const MATCHING_SENDER = "recruiter@example.invalid";
const OTHER_SENDER = "someone-else@example.invalid";

/** The two new messages the second run finds. */
const MATCHING_UID = 4393;
const OTHER_UID = 4392;

type Stub = DurableObjectStub<UserAgent>;

/** A rate-limit binding stub that always lets the request through. */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** The pool's environment with both limiters replaced, as a copy. */
function allowAllEnv(): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
  } as unknown as Env;
}

/** Hand a request to the Worker, in process, with a context of its own. */
async function callWorker(request: Request, env: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** A signed-in, armed person, and how to clean up after them. */
interface Armed {
  readonly env: Env;
  readonly userId: string;
  readonly stub: Stub;
  cleanup(): Promise<void>;
}

/**
 * Sign the listed address in through the login-proof worker with the autonomy
 * client installed, and settle the execution context, which is when the arm
 * runs. Copied in shape from test/autonomy.test.ts.
 */
async function signInArmed(): Promise<Armed> {
  const env = allowAllEnv();
  const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
  const stub = entryEnv().USER_AGENT.getByName(userId);
  const removeAutonomyClient = await installAutonomyClient(env);
  const registered = await callWorker(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "rules job tracer",
        redirect_uris: [CLAUDE_WEB_REDIRECT],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
    env,
  );
  const clientId = ((await registered.json()) as { client_id: string }).client_id;

  const cleanup = async () => {
    const kv = entryEnv().OAUTH_KV;
    for (const prefix of [`grant:${userId}:`, `token:${userId}:`]) {
      for (const key of (await kv.list({ prefix })).keys) await kv.delete(key.name);
    }
    await runInDurableObject(stub, async (_i, state) => {
      for (const [key] of state.storage.kv.list()) state.storage.kv.delete(key);
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
      state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
      await state.storage.deleteAlarm();
    });
    await kv.delete(`client:${clientId}`);
    await removeAutonomyClient();
  };

  try {
    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: CLAUDE_WEB_REDIRECT,
      code_challenge: CODE_CHALLENGE,
      code_challenge_method: "S256",
      state: "rules-job",
    }).toString();
    resetLoginProof();
    const ctx = createExecutionContext();
    const answer = await worker.fetch(
      new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": `test-source-${crypto.randomUUID()}`,
        },
        body: new URLSearchParams({
          apple_id: LISTED_APPLE_ID,
          app_password: FAKE_APP_PASSWORD,
          oauth_request: query,
          [AUTONOMY_NOTICE_FIELD]: AUTONOMY_NOTICE_VERSION,
        }).toString(),
      }),
      env,
      ctx,
    );
    expect(answer.status).toBe(302);
    await waitOnExecutionContext(ctx);
    const code = new URL(answer.headers.get("location") as string).searchParams.get("code");
    const exchanged = await callWorker(
      new Request(`${ORIGIN}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code as string,
          redirect_uri: CLAUDE_WEB_REDIRECT,
          client_id: clientId,
          code_verifier: CODE_VERIFIER,
        }).toString(),
      }),
      env,
    );
    expect(exchanged.status).toBe(200);
    const grants = (await getOAuthApi(oauthProviderOptions, env).listUserGrants(userId)).items;
    expect(grants.filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID)).toHaveLength(1);
    const armed = await runInDurableObject(stub, (_i, state) =>
      state.storage.kv.get(AUTONOMY_KEY) !== undefined,
    );
    expect(armed).toBe(true);
    return { env, userId, stub, cleanup };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

/** One self-call the object made, and what storage held when it left. */
interface SelfCall {
  readonly path: string;
  readonly grantType: string | null;
  readonly tool: string | null;
  /** Every "already acted" record at that moment, by key. */
  readonly acted: Record<string, unknown>;
  /** The stored marker at that moment, or null. */
  readonly marker: string | null;
}

/**
 * Point the object's seam at the login-proof worker, in process, recording
 * each call and a snapshot of the job's storage as the call leaves.
 */
async function routeSelfCalls(armed: Armed): Promise<SelfCall[]> {
  const calls: SelfCall[] = [];
  await runInDurableObject(armed.stub, (instance: UserAgent, state) => {
    const kv = state.storage.kv;
    instance.autonomySelfFetch = async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      let grantType: string | null = null;
      if (url.pathname === "/oauth/token") {
        const field = (await request.clone().formData()).get("grant_type");
        grantType = typeof field === "string" ? field : null;
      }
      const acted: Record<string, unknown> = {};
      for (const [key, value] of kv.list({ prefix: "acted:" })) acted[key] = value;
      const stored = kv.get<{ marker?: unknown }>("job:marker");
      calls.push({
        path: url.pathname,
        grantType,
        tool: request.headers.get("Mcp-Name"),
        acted,
        marker: typeof stored?.marker === "string" ? stored.marker : null,
      });
      return callWorker(request, armed.env);
    };
  });
  return calls;
}

/** The four turns every session opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A session that answers one status command for the inbox. */
function statusSession(uidNext: number, modseq: string): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    statusResponse("a4", "INBOX", INBOX_UIDVALIDITY, uidNext, 172, modseq),
    logoutExchange("a5"),
  ]);
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A time as the protocol's receipt-time form, in UTC. */
function receiptTime(ms: number): string {
  const d = new Date(ms);
  const two = (n: number) => String(n).padStart(2, "0");
  return (
    `${two(d.getUTCDate())}-${MONTHS[d.getUTCMonth()]}-${d.getUTCFullYear()} ` +
    `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} +0000`
  );
}

const ENCODER = new TextEncoder();

/** One header-only fetch reply per row, received at `at`, then the completion. */
function headerFetchReply(
  tag: string,
  at: number,
  rows: readonly { uid: number; subject: string; from: string }[],
): Uint8Array {
  const parts: Uint8Array[] = [];
  rows.forEach((row, index) => {
    const header = ENCODER.encode(`Subject: ${row.subject}\r\nFrom: ${row.from}\r\n\r\n`);
    parts.push(
      ENCODER.encode(
        `* ${index + 1} FETCH (UID ${row.uid} FLAGS () INTERNALDATE "${receiptTime(at)}" ` +
          `BODY[HEADER.FIELDS (SUBJECT FROM LIST-ID LIST-UNSUBSCRIBE)] {${header.length}}\r\n`,
      ),
      header,
      ENCODER.encode(")\r\n"),
    );
  });
  parts.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Every duplex handed out, in order, and the queue of ones still to hand out. */
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

/** Every line every duplex was sent, in order. */
function allLines(): string[] {
  return handedOut.flatMap((duplex) => duplex.writtenLines());
}

describe("the rules job, end to end (AUTO-09, AUTO-12, AUTO-13, D-06, D-14)", () => {
  it("one flag rule: a starting point, then exactly one flag, on the matching message, through the real door", async () => {
    const armed = await signInArmed();
    try {
      const calls = await routeSelfCalls(armed);

      // The rule, through the object's own method.
      const added = await armed.stub.addRule({
        when: { fromAddresses: [MATCHING_SENDER] },
        then: { flag: true },
      });
      expect(added.ok).toBe(true);
      const alarmAfterAdd = await runInDurableObject(armed.stub, (_i, state) => state.storage.getAlarm());
      expect(alarmAfterAdd).not.toBeNull();

      // ---- Run one: no marker, so a starting point.
      queued.push(() => statusSession(4392, "118"));
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);

      const afterOne = await runInDurableObject(armed.stub, async (instance: UserAgent, state) => ({
        marker: state.storage.kv.get<{ marker: string; at: number }>("job:marker"),
        acted: [...state.storage.kv.list({ prefix: "acted:" })],
        view: instance.rulesView(),
        alarm: await state.storage.getAlarm(),
      }));
      expect(typeof afterOne.marker?.marker).toBe("string");
      expect(afterOne.acted).toEqual([]);
      expect(afterOne.view.activity).toHaveLength(1);
      expect(afterOne.view.activity[0]).toMatchObject({ kind: "run", outcome: "started" });
      expect(afterOne.view.armed).toBe(true);
      expect(afterOne.alarm).not.toBeNull();
      const runOneCalls = calls.splice(0);
      expect(runOneCalls.filter((call) => call.path === "/mcp").map((call) => call.tool)).toEqual([
        "changes_since",
      ]);
      expect(runOneCalls.filter((call) => call.grantType === "refresh_token")).toHaveLength(1);
      expect(allLines().some((line) => /UID STORE/.test(line))).toBe(false);

      // ---- Run two: two new messages, one from the rule's sender. The alarm
      // is driven at once, long before the job's own next wake (28-02), so
      // that stored wake is forgotten first to make this run due.
      await runInDurableObject(armed.stub, (_i, state) => {
        state.storage.kv.delete("job:nextAt");
      });
      const received = Date.now() + 60_000;
      queued.push(
        () => statusSession(4394, "120"),
        () =>
          createFakeDuplex([
            ...authPrefix(),
            examineResponse("a4"),
            wire(`* SEARCH ${OTHER_UID} ${MATCHING_UID}`, "a5 OK SEARCH completed"),
            headerFetchReply("a6", received, [
              { uid: MATCHING_UID, subject: "About the role", from: MATCHING_SENDER },
              { uid: OTHER_UID, subject: "About the role", from: OTHER_SENDER },
            ]),
            logoutExchange("a7"),
          ]),
        () =>
          createFakeDuplex([
            ...authPrefix(),
            selectResponse("a4", "[READ-WRITE]"),
            flagEcho("a5", 17, MATCHING_UID, "\\Flagged"),
            logoutExchange("a6"),
          ]),
      );
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
      expect(queued).toHaveLength(0);

      const afterTwo = await runInDurableObject(armed.stub, async (instance: UserAgent, state) => ({
        marker: state.storage.kv.get<{ marker: string; at: number }>("job:marker"),
        acted: [...state.storage.kv.list({ prefix: "acted:" })],
        view: instance.rulesView(),
        alarm: await state.storage.getAlarm(),
      }));

      // Exactly one flag change on the wire, for the matching message.
      const stores = allLines().filter((line) => /UID STORE/.test(line));
      expect(stores).toEqual([`a5 UID STORE ${MATCHING_UID} +FLAGS (\\Flagged)`]);

      // Exactly one "already acted" record, in its final state.
      expect(afterTwo.acted).toHaveLength(1);
      expect((afterTwo.acted[0]?.[1] as { state: string }).state).toBe("flagged");

      // The record was written before the flag call left, and the marker after.
      const runTwoCalls = calls.splice(0);
      const toolCalls = runTwoCalls.filter((call) => call.path === "/mcp");
      expect(toolCalls.map((call) => call.tool)).toEqual(["changes_since", "mail_flag"]);
      const flagCall = toolCalls[1] as SelfCall;
      expect(Object.values(flagCall.acted)).toEqual([{ state: "reserved", at: expect.any(Number) }]);
      expect(flagCall.marker).toBe(afterOne.marker?.marker);
      expect(afterTwo.marker?.marker).not.toBe(afterOne.marker?.marker);

      // Every tool named is on the one list; one redemption per run.
      const allowed: readonly string[] = AUTONOMY_TOOLS;
      for (const call of [...runOneCalls, ...runTwoCalls]) {
        if (call.path === "/mcp") expect(allowed).toContain(call.tool);
      }
      expect(runTwoCalls.filter((call) => call.grantType === "refresh_token")).toHaveLength(1);

      // The activity: the flag, then the run.
      expect(afterTwo.view.activity.slice(0, 2)).toMatchObject([
        { kind: "run", outcome: "done" },
        { kind: "flag", outcome: "flagged", ruleId: added.ok ? added.id : "" },
      ]);
      expect(afterTwo.alarm).not.toBeNull();
    } finally {
      await armed.cleanup();
    }
  });
});
