// The autonomy credential (Phase 27, plan 27-01).
//
// Autonomy is inherent: every interactive sign-in also mints a grant for the
// autonomy client, and the person's own Durable Object keeps that grant's
// refresh token, sealed. These cases drive that path on the real provider, the
// real login handler and a real object in the pool.
//
// **No real Apple ID is ever authenticated (D-09).** Every sign-in goes through
// `test/fixtures/worker-with-login-proof.ts`, whose proof is a counter. The
// addresses are under the reserved `.invalid` domain and the password is
// plainly fake.
//
// **The four hygiene rules from `test/self-binding.test.ts` hold here too.**
// 1. Every sign-in runs against a SPREAD COPY of the pool's environment whose
//    two login limiters are allow-all stubs.
// 2. Never write onto the shared environment object.
// 3. Check keys by the grant id THIS case minted, never by a total.
// 4. Clean up in a `finally`: grants, their tokens, and the client records.
//
// The helpers are copied from `test/self-binding.test.ts` rather than imported,
// which is this repository's habit for test helpers.

import {
  createExecutionContext,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { describe, expect, it } from "vitest";
import {
  AUTONOMY_KEY,
  type AutonomyDeps,
  type AutonomyEnv,
  type AutonomyStorage,
  seal,
  sealKeyUsable,
  unseal,
  withAutonomySession,
} from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID, AUTONOMY_CLIENT_NAME } from "../src/agent/autonomy-client";
import type { UserAgent } from "../src/agent/user-agent";
import { ALLOW_LIST_KEY } from "../src/auth/allow-list";
import { autonomyConfigured, createLoginHandler, signInNotices } from "../src/auth/login-handler";
import {
  AUTONOMY_NOTICE,
  AUTONOMY_NOTICE_FIELD,
  AUTONOMY_NOTICE_VERSION,
  RECALL_NOTICE,
} from "../src/auth/login-page";
import { oauthProviderOptions } from "../src/auth/oauth";
import type { Env } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { userIdOf } from "../src/principal";
import { AUTONOMY_REDIRECT_URI, installAutonomyClient } from "./fixtures/autonomy-client";
import { entryEnv } from "./fixtures/bound-secrets";
import { USER_A, USER_B } from "./fixtures/two-users";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  loginProofCalls,
  resetLoginProof,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The PKCE verifier this file redeems ordinary codes with. Copied, pair intact. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";

/** `BASE64URL(SHA256(ASCII(CODE_VERIFIER)))`. Copied together with the above. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** A rate-limit binding stub that always lets the request through (rule 1). */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** The pool's environment with both limiters replaced, as a COPY (rule 2). */
function allowAllEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
    ...overrides,
  } as unknown as Env;
}

/** Hand a request to the Worker's fetch, with a context of its own, and settle it. */
async function callWorker(request: Request, env: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Register a real public client through the real registration endpoint. */
async function register(env: Env, clientName: string, redirectUri: string): Promise<string> {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: clientName,
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
    env,
  );
  expect(response.status).toBeLessThan(300);
  return ((await response.json()) as { client_id: string }).client_id;
}

/** An authorization query the real provider parses and re-validates. */
function authorizeQuery(clientId: string, redirectUri: string, state: string): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    state,
  }).toString();
}

/** A source key this invocation owns and nothing else in the repository uses. */
function freshSource(): string {
  return `test-source-${crypto.randomUUID()}`;
}

/** A sign-in POST at the real Worker, from a named source connection. */
function postFrom(source: string, appleId: string, query: string): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": source,
    },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
      // The field the page renders when it shows the autonomy notice (D-30).
      [AUTONOMY_NOTICE_FIELD]: AUTONOMY_NOTICE_VERSION,
    }).toString(),
  });
}

/** Redeem an ordinary authorization code at the real token endpoint. */
async function exchangeCode(env: Env, clientId: string, redirectUri: string, code: string) {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    }),
    env,
  );
  const text = await response.text();
  expect(`${response.status} ${text}`).toBe(`200 ${text}`);
  return JSON.parse(text) as { access_token: string; refresh_token: string };
}

/** Every key listed under a prefix, with the expiry the store reports. */
async function keysUnder(prefix: string): Promise<Array<{ name: string; expiration?: number }>> {
  return (await entryEnv().OAUTH_KV.list({ prefix })).keys;
}

/** Delete a grant and every access token under it (rule 4). Serial, always. */
async function forgetGrant(userId: string, grantId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const key of await keysUnder(`token:${userId}:${grantId}:`)) {
    await kv.delete(key.name);
  }
  await kv.delete(`grant:${userId}:${grantId}`);
}

/** Every grant the library lists for a person, as summaries. */
async function grantsOf(env: Env, userId: string) {
  return (await getOAuthApi(oauthProviderOptions, env).listUserGrants(userId)).items;
}

/** The stored grant record, parsed. */
async function grantRecord(userId: string, grantId: string): Promise<Record<string, unknown>> {
  const raw = await entryEnv().OAUTH_KV.get(`grant:${userId}:${grantId}`);
  expect(raw).not.toBeNull();
  return JSON.parse(raw as string) as Record<string, unknown>;
}

/** The KV expiration the store reports for one grant record. */
async function grantExpiration(userId: string, grantId: string): Promise<number | undefined> {
  const keys = await keysUnder(`grant:${userId}:${grantId}`);
  expect(keys.map((key) => key.name)).toEqual([`grant:${userId}:${grantId}`]);
  return keys[0]?.expiration;
}

/** One self-call the object made, as the recorder saw it. */
interface Recorded {
  readonly path: string;
  readonly grantType: string | null;
}

/**
 * Replace the object's seam with a recorder that forwards to this Worker.
 *
 * The forward goes to the pool's `SELF` binding, which the probe case below
 * shows reaches this Worker's own provider.
 */
async function recordSelfCalls(userId: string): Promise<Recorded[]> {
  const recorded: Recorded[] = [];
  await runInDurableObject(entryEnv().USER_AGENT.getByName(userId), (instance: UserAgent) => {
    instance.autonomySelfFetch = async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      let grantType: string | null = null;
      if (url.pathname === "/oauth/token") {
        const field = (await request.clone().formData()).get("grant_type");
        grantType = typeof field === "string" ? field : null;
      }
      recorded.push({ path: url.pathname, grantType });
      return entryEnv().SELF.fetch(request);
    };
  });
  return recorded;
}

describe("autonomy credential: the tracer (AUTO-01, AUTO-02, AUTO-06, D-26)", () => {
  it("probe: the pool's SELF binding reaches this Worker's own provider", async () => {
    const response = await entryEnv().SELF.fetch(
      `${ORIGIN}/.well-known/oauth-authorization-server`,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token_endpoint?: unknown };
    expect(body.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
  });

  it("an ordinary sign-in answers as before and arms the key, sealed, in the person's own object", async () => {
    const env = allowAllEnv();
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    expect(userId).toMatch(/^[0-9a-f]{64}$/);
    const removeAutonomyClient = await installAutonomyClient(env);
    const clientId = await register(env, "autonomy tracer", CLAUDE_WEB_REDIRECT);
    const recorded = await recordSelfCalls(userId);
    const minted: string[] = [];

    try {
      const query = authorizeQuery(clientId, CLAUDE_WEB_REDIRECT, "tracer");

      // 1. The form, for the ordinary client.
      const form = await callWorker(new Request(`${ORIGIN}/authorize?${query}`), env);
      expect(form.status).toBe(200);
      expect(await form.text()).toContain("<form");

      // 2. The POST answers the ordinary 302, with a code, after one proof.
      resetLoginProof();
      const ctx = createExecutionContext();
      const answer = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, query), env, ctx);
      expect(answer.status).toBe(302);
      const location = answer.headers.get("location") as string;
      expect(location.startsWith(`${CLAUDE_WEB_REDIRECT}?`)).toBe(true);
      const ordinaryCode = new URL(location).searchParams.get("code") as string;
      expect(ordinaryCode).toMatch(new RegExp(`^${userId}:`));
      expect(loginProofCalls()).toBe(1);
      const answerBody = await answer.text();
      await waitOnExecutionContext(ctx);

      const ordinary = await exchangeCode(env, clientId, CLAUDE_WEB_REDIRECT, ordinaryCode);
      const ordinaryGrantId = ordinary.access_token.split(":")[1] as string;
      minted.push(ordinaryGrantId);

      // 3. Exactly one autonomy grant, with no expiry of its own, the same as the ordinary one.
      const all = await grantsOf(env, userId);
      const autonomyGrants = all.filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID);
      for (const grant of autonomyGrants) minted.push(grant.id);
      expect(autonomyGrants).toHaveLength(1);
      const autonomyGrantId = autonomyGrants[0]?.id as string;
      expect((await grantRecord(userId, autonomyGrantId)).expiresAt).toBeUndefined();
      expect(await grantExpiration(userId, autonomyGrantId)).toBeUndefined();
      expect((await grantRecord(userId, ordinaryGrantId)).expiresAt).toBeUndefined();
      expect(await grantExpiration(userId, ordinaryGrantId)).toBeUndefined();

      // 4. Nothing of the autonomy grant reached the browser.
      const tokenShape = `${userId}:${autonomyGrantId}:`;
      for (const [name, value] of answer.headers) {
        expect(`${name}: ${value}`).not.toContain(autonomyGrantId);
        expect(`${name}: ${value}`).not.toContain(tokenShape);
      }
      expect(answerBody).not.toContain(autonomyGrantId);

      // 5, 7. The record, sealed, holding exactly six fields; and the object's own name.
      const inside = await runInDurableObject(
        entryEnv().USER_AGENT.getByName(userId),
        (instance: UserAgent, state) => {
          const values: string[] = [];
          for (const [, value] of state.storage.kv.list()) values.push(JSON.stringify(value));
          return {
            record: state.storage.kv.get<Record<string, unknown>>("autonomy"),
            values,
            ownName: instance.storedOwnName(),
          };
        },
      );
      expect(Object.keys(inside.record ?? {}).sort()).toEqual(
        ["armedAt", "generation", "grantId", "iv", "sealedRefreshToken", "v"].sort(),
      );
      expect(inside.record?.grantId).toBe(autonomyGrantId);
      expect(inside.record?.v).toBe(1);
      expect(inside.record?.generation).toBe(1);
      for (const value of inside.values) expect(value).not.toContain(tokenShape);
      expect(inside.ownName).toBe(userId);

      // 6. The object's self-calls, in order: the exchange, one refresh, one tool call.
      expect(recorded).toEqual([
        { path: "/oauth/token", grantType: "authorization_code" },
        { path: "/oauth/token", grantType: "refresh_token" },
        { path: "/mcp", grantType: null },
      ]);
    } finally {
      for (const grant of await grantsOf(env, userId)) {
        if (grant.clientId === AUTONOMY_CLIENT_ID || minted.includes(grant.id)) {
          await forgetGrant(userId, grant.id);
        }
      }
      await runInDurableObject(entryEnv().USER_AGENT.getByName(userId), (_i, state) => {
        state.storage.kv.delete("autonomy");
      });
      await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
      await removeAutonomyClient();
    }
  });
});

// ---------------------------------------------------------------------------
// Task 2: pin the things the tracer only passes through.

/** The five outcome kinds a session may answer, and no expiry kind. */
const SESSION_KINDS = ["ok", "not_allowed", "off", "revoked", "failed"];

/** A second 32-byte seal key, plainly fake, for the wrong-key case. */
const OTHER_SEAL_KEY = "b3RoZXItc2VhbC1rZXktMzItYnl0ZXMtbm90LXJlYWw";

/** Bytes from base64url, for the tamper case. */
function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** Base64url from bytes, for the tamper case. */
function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The pool's seal key, which the pool's objects seal under. */
function poolSealKey(): string {
  return entryEnv().AUTONOMY_SEAL_KEY as string;
}

/** A user id nothing in this repository has ever touched, as a fresh object name. */
function freshUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** An address under the reserved domain that no other case uses. */
function freshAddress(): string {
  return `autonomy-${crypto.randomUUID()}@example.invalid`;
}

/** A storage wrapper that counts reads by key and forwards everything. */
function countingStorage(kv: AutonomyStorage): { storage: AutonomyStorage; reads: Map<string, number> } {
  const reads = new Map<string, number>();
  return {
    reads,
    storage: {
      get<T = unknown>(key: string): T | undefined {
        reads.set(key, (reads.get(key) ?? 0) + 1);
        return kv.get<T>(key);
      },
      put<T>(key: string, value: T): void {
        kv.put(key, value);
      },
      delete(key: string): boolean {
        return kv.delete(key);
      },
    },
  };
}

/** A `selfFetch` that records every request and forwards it to this Worker. */
function recordingFetch(): { selfFetch: (request: Request) => Promise<Response>; paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    selfFetch: async (request: Request) => {
      paths.push(new URL(request.url).pathname);
      return entryEnv().SELF.fetch(request);
    },
  };
}

/** A `selfFetch` that records and never forwards: any call is a failure of the case. */
function refusingFetch(): { selfFetch: (request: Request) => Promise<Response>; paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    selfFetch: async (request: Request) => {
      paths.push(new URL(request.url).pathname);
      return new Response(null, { status: 500 });
    },
  };
}

/** Assert an outcome is one of the five kinds and carries no token of this grant. */
function expectCleanOutcome(outcome: unknown, userId: string, grantId: string | null): void {
  expect(SESSION_KINDS).toContain((outcome as { kind?: unknown }).kind);
  const text = JSON.stringify(outcome);
  expect(text).not.toContain(`${userId}:`);
  if (grantId !== null) expect(text).not.toContain(`${userId}:${grantId}:`);
}

/** A KV wrapper that records every key written, and forwards everything. */
function recordingKv(real: KVNamespace): { kv: KVNamespace; written: string[] } {
  const written: string[] = [];
  const kv = new Proxy(real, {
    get(target, prop) {
      if (prop === "put") {
        return (key: string, ...rest: unknown[]) => {
          written.push(key);
          return (target.put as (...args: unknown[]) => Promise<void>).call(target, key, ...rest);
        };
      }
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
  return { kv, written };
}

/** A signed-in, armed person, and how to clean up after them. */
interface Armed {
  readonly env: Env;
  readonly userId: string;
  readonly autonomyGrantId: string;
  readonly ordinaryGrantId: string;
  cleanup(): Promise<void>;
}

/**
 * Sign `appleId` in through the real Worker with the autonomy client
 * installed, settle the arm, and redeem the ordinary code. The arm uses the
 * object's own seam, which in the pool reaches this Worker through `SELF`.
 */
async function signInArmed(appleId: string, name: string): Promise<Armed> {
  const env = allowAllEnv();
  const userId = (await userIdOf(appleId)) as string;
  const removeAutonomyClient = await installAutonomyClient(env);
  const clientId = await register(env, name, CLAUDE_WEB_REDIRECT);
  const cleanup = async () => {
    for (const grant of await grantsOf(env, userId)) await forgetGrant(userId, grant.id);
    await runInDurableObject(entryEnv().USER_AGENT.getByName(userId), (_i, state) => {
      state.storage.kv.delete(AUTONOMY_KEY);
    });
    await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
    await removeAutonomyClient();
  };
  try {
    const query = authorizeQuery(clientId, CLAUDE_WEB_REDIRECT, name);
    const ctx = createExecutionContext();
    const answer = await worker.fetch(postFrom(freshSource(), appleId, query), env, ctx);
    expect(answer.status).toBe(302);
    await waitOnExecutionContext(ctx);
    const code = new URL(answer.headers.get("location") as string).searchParams.get("code") as string;
    const ordinary = await exchangeCode(env, clientId, CLAUDE_WEB_REDIRECT, code);
    const autonomy = (await grantsOf(env, userId)).filter((g) => g.clientId === AUTONOMY_CLIENT_ID);
    expect(autonomy).toHaveLength(1);
    return {
      env,
      userId,
      autonomyGrantId: autonomy[0]?.id as string,
      ordinaryGrantId: ordinary.access_token.split(":")[1] as string,
      cleanup,
    };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

/** Session deps over a real object's storage, reaching this Worker. */
function depsOver(
  storage: AutonomyStorage,
  name: string,
  selfFetch: (request: Request) => Promise<Response>,
  env: AutonomyEnv = entryEnv(),
): AutonomyDeps {
  return { storage, name, env, selfFetch, now: () => Date.now() };
}

/** A sealed record for `sealedFor`, carrying a token-shaped plaintext. */
async function sealedRecordFor(sealedFor: string, generation = 1): Promise<Record<string, unknown>> {
  const sealed = await seal(poolSealKey(), sealedFor, `${sealedFor}:fakegrant:not-a-real-token`);
  expect(sealed).not.toBeNull();
  return {
    v: 1,
    grantId: "fakegrant",
    sealedRefreshToken: sealed?.sealedRefreshToken,
    iv: sealed?.iv,
    // Armed now, so plan 27-02's standing check is inside its grace and these
    // cases still reach the step they are about.
    armedAt: Math.floor(Date.now() / 1000),
    generation,
  };
}

describe("autonomy credential: no expiry, seal, order, not configured (AUTO-02, AUTO-05, AUTO-06, D-17)", () => {
  it("sets no token exchange callback, and keeps the refresh lifetime present and undefined", () => {
    expect(Object.hasOwn(oauthProviderOptions, "tokenExchangeCallback")).toBe(false);
    expect("tokenExchangeCallback" in oauthProviderOptions).toBe(false);
    expect(Object.hasOwn(oauthProviderOptions, "refreshTokenTTL")).toBe(true);
    expect(oauthProviderOptions.refreshTokenTTL).toBeUndefined();
  });

  it("gives the autonomy grant no expiry, before and after three sessions, the same as the ordinary grant", async () => {
    const armed = await signInArmed(LISTED_APPLE_ID, "autonomy no expiry");
    try {
      for (const grantId of [armed.autonomyGrantId, armed.ordinaryGrantId]) {
        expect((await grantRecord(armed.userId, grantId)).expiresAt).toBeUndefined();
        expect(await grantExpiration(armed.userId, grantId)).toBeUndefined();
      }
      const fetcher = recordingFetch();
      const outcomes = await runInDurableObject(
        entryEnv().USER_AGENT.getByName(armed.userId),
        async (_i, state) => {
          const deps = depsOver(state.storage.kv, armed.userId, fetcher.selfFetch);
          const out: unknown[] = [];
          for (let i = 0; i < 3; i += 1) {
            out.push(await withAutonomySession(deps, (call) => call("account_whoami", {})));
          }
          return out;
        },
      );
      for (const outcome of outcomes) {
        expect((outcome as { kind: string }).kind).toBe("ok");
        expect((outcome as { value: { kind: string } }).value.kind).toBe("ok");
        expectCleanOutcome(outcome, armed.userId, armed.autonomyGrantId);
      }
      expect(fetcher.paths).toEqual(["/oauth/token", "/mcp", "/oauth/token", "/mcp", "/oauth/token", "/mcp"]);
      for (const grantId of [armed.autonomyGrantId, armed.ordinaryGrantId]) {
        expect((await grantRecord(armed.userId, grantId)).expiresAt).toBeUndefined();
        expect(await grantExpiration(armed.userId, grantId)).toBeUndefined();
      }
    } finally {
      await armed.cleanup();
    }
  });

  it("seals so that only the same key, the same person and the same bytes open it", async () => {
    const userId = USER_A.userId;
    const autonomyRefreshToken = `${userId}:grant:not-a-real-token`;
    const first = await seal(poolSealKey(), userId, autonomyRefreshToken);
    const second = await seal(poolSealKey(), userId, autonomyRefreshToken);
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    if (first === null || second === null) return;

    expect(await unseal(poolSealKey(), userId, first)).toBe(autonomyRefreshToken);
    expect(first.sealedRefreshToken).not.toContain(userId);
    expect(first.iv).not.toBe(second.iv);
    expect(first.sealedRefreshToken).not.toBe(second.sealedRefreshToken);

    expect(await unseal(poolSealKey(), USER_B.userId, first)).toBeNull();
    expect(await unseal(OTHER_SEAL_KEY, userId, first)).toBeNull();
    const bytes = fromBase64Url(first.sealedRefreshToken);
    bytes[0] = (bytes[0] ?? 0) ^ 0x01;
    expect(await unseal(poolSealKey(), userId, { ...first, sealedRefreshToken: toBase64Url(bytes) })).toBeNull();
    const iv = fromBase64Url(first.iv);
    iv[0] = (iv[0] ?? 0) ^ 0x01;
    expect(await unseal(poolSealKey(), userId, { ...first, iv: toBase64Url(iv) })).toBeNull();

    // A key that does not decode to exactly 32 bytes is refused both ways.
    const short = toBase64Url(new Uint8Array(16));
    expect(await seal(short, userId, autonomyRefreshToken)).toBeNull();
    expect(await unseal(short, userId, first)).toBeNull();
    expect(await seal(undefined, userId, autonomyRefreshToken)).toBeNull();
  });

  it("a record sealed for one person, copied into another's object, is off there and deleted, with no token call", async () => {
    const record = await sealedRecordFor(USER_A.userId);
    const fetcher = refusingFetch();
    const result = await runInDurableObject(
      entryEnv().USER_AGENT.getByName(USER_B.userId),
      async (_i, state) => {
        state.storage.kv.put(AUTONOMY_KEY, record);
        const deps = depsOver(state.storage.kv, USER_B.userId, fetcher.selfFetch, {
          ...entryEnv(),
          ALLOWED_APPLE_IDS_SEED: '["*"]',
        });
        const outcome = await withAutonomySession(deps, (call) => call("account_whoami", {}));
        return { outcome, after: state.storage.kv.get(AUTONOMY_KEY) };
      },
    );
    expect(result.outcome).toEqual({ kind: "off" });
    expect(result.after).toBeUndefined();
    expect(fetcher.paths).toEqual([]);
  });

  it("refuses a person on neither list before the record is read, and keeps the record byte for byte", async () => {
    const name = freshUserId();
    const record = await sealedRecordFor(name, 7);
    const fetcher = refusingFetch();
    const result = await runInDurableObject(entryEnv().USER_AGENT.getByName(name), async (_i, state) => {
      state.storage.kv.put(AUTONOMY_KEY, record);
      const before = JSON.stringify(state.storage.kv.get(AUTONOMY_KEY));
      const counted = countingStorage(state.storage.kv);
      const outcome = await withAutonomySession(depsOver(counted.storage, name, fetcher.selfFetch), (call) =>
        call("account_whoami", {}),
      );
      const after = JSON.stringify(state.storage.kv.get(AUTONOMY_KEY));
      state.storage.kv.delete(AUTONOMY_KEY);
      return { outcome, before, after, reads: counted.reads.get(AUTONOMY_KEY) ?? 0 };
    });
    expect(result.outcome).toEqual({ kind: "not_allowed" });
    expect(result.reads).toBe(0);
    expect(fetcher.paths).toEqual([]);
    expect(result.after).toBe(result.before);
  });

  it("admits a person the store lists and the seed does not: they arm at sign-in and a session proceeds", async () => {
    const address = freshAddress();
    await entryEnv().ALLOW_LIST_KV.put(ALLOW_LIST_KEY, JSON.stringify([address]));
    let armed: Armed | null = null;
    try {
      armed = await signInArmed(address, "autonomy store-listed");
      const userId = armed.userId;
      const grantId = armed.autonomyGrantId;
      const fetcher = recordingFetch();
      const outcome = await runInDurableObject(entryEnv().USER_AGENT.getByName(userId), async (_i, state) =>
        withAutonomySession(depsOver(state.storage.kv, userId, fetcher.selfFetch), (call) =>
          call("account_whoami", {}),
        ),
      );
      expect(outcome.kind).toBe("ok");
      expectCleanOutcome(outcome, userId, grantId);
      expect(fetcher.paths).toEqual(["/oauth/token", "/mcp"]);
    } finally {
      await entryEnv().ALLOW_LIST_KV.delete(ALLOW_LIST_KEY);
      if (armed !== null) await armed.cleanup();
    }
  });

  it("refuses a store-only person when the store cannot be read, and keeps their record", async () => {
    const address = freshAddress();
    const name = (await userIdOf(address)) as string;
    const record = await sealedRecordFor(name);
    const fetcher = refusingFetch();
    const brokenStore = {
      async get(): Promise<never> {
        throw new Error("the store is unreachable");
      },
    } as unknown as KVNamespace;
    const result = await runInDurableObject(entryEnv().USER_AGENT.getByName(name), async (_i, state) => {
      state.storage.kv.put(AUTONOMY_KEY, record);
      const before = JSON.stringify(state.storage.kv.get(AUTONOMY_KEY));
      const deps = depsOver(state.storage.kv, name, fetcher.selfFetch, {
        ...entryEnv(),
        ALLOW_LIST_KV: brokenStore,
      });
      const outcome = await withAutonomySession(deps, (call) => call("account_whoami", {}));
      const after = JSON.stringify(state.storage.kv.get(AUTONOMY_KEY));
      state.storage.kv.delete(AUTONOMY_KEY);
      return { outcome, before, after };
    });
    expect(result.outcome).toEqual({ kind: "not_allowed" });
    expect(result.after).toBe(result.before);
    expect(fetcher.paths).toEqual([]);
  });

  it("refuses every tool but the one the key may call, with no request, and stops once the session ends", async () => {
    const armed = await signInArmed(LISTED_APPLE_ID, "autonomy tool list");
    try {
      const fetcher = recordingFetch();
      const outcome = await runInDurableObject(
        entryEnv().USER_AGENT.getByName(armed.userId),
        async (_i, state) => {
          let kept: ((tool: string, args: Record<string, unknown>) => Promise<unknown>) | null = null;
          const session = await withAutonomySession(
            depsOver(state.storage.kv, armed.userId, fetcher.selfFetch),
            async (call) => {
              kept = call;
              const refused: unknown[] = [];
              for (const tool of ["mail_find", "mail_list_messages", "calendar_commit", "ACCOUNT_WHOAMI", ""]) {
                refused.push(await call(tool, {}));
              }
              return refused;
            },
          );
          const late = kept === null ? null : await (kept as (t: string, a: Record<string, unknown>) => Promise<unknown>)("account_whoami", {});
          return { session, late };
        },
      );
      expect(outcome.session.kind).toBe("ok");
      const refused = (outcome.session as { value: unknown[] }).value;
      expect(refused).toHaveLength(5);
      for (const answer of refused) expect(answer).toEqual({ kind: "failed" });
      expect(outcome.late).toEqual({ kind: "failed" });
      expect(fetcher.paths).toEqual(["/oauth/token"]);
      expectCleanOutcome(outcome.session, armed.userId, armed.autonomyGrantId);
    } finally {
      await armed.cleanup();
    }
  });

  it("answers armAutonomy with the grant id or not_armed, and never a token", async () => {
    const env = allowAllEnv();
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    const removeAutonomyClient = await installAutonomyClient(env);
    const stub = entryEnv().USER_AGENT.getByName(userId);
    try {
      const helpers = getOAuthApi(oauthProviderOptions, env);
      const minted = await helpers.completeAuthorization({
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
      const grantId = code.split(":")[1] as string;

      const armed = await stub.armAutonomy(code);
      expect(armed).toEqual({ kind: "armed", grantId });
      expect(JSON.stringify(armed)).not.toContain(`${userId}:${grantId}:`);

      // The same code again: already redeemed, so not armed, and the record goes.
      const again = await stub.armAutonomy(code);
      expect(again).toEqual({ kind: "not_armed" });

      // Not a string, and a code for somebody else: refused.
      expect(await stub.armAutonomy(42)).toEqual({ kind: "not_armed" });
      expect(await stub.armAutonomy(`${USER_B.userId}:${grantId}:x`)).toEqual({ kind: "not_armed" });
    } finally {
      for (const grant of await grantsOf(env, userId)) await forgetGrant(userId, grant.id);
      await runInDurableObject(stub, (_i, state) => {
        state.storage.kv.delete(AUTONOMY_KEY);
      });
      await removeAutonomyClient();
    }
  });

  /**
   * Sign in once with `envOverrides` and a KV wrapper on the case's OAuth
   * store, and answer the 302 and every `grant:` key the sign-in wrote.
   */
  async function signInCountingGrants(
    envOverrides: Record<string, unknown>,
    options: { install: boolean; withContext: boolean },
  ): Promise<{ status: number; location: string; grantsWritten: string[]; autonomyGrants: number }> {
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    const recorder = recordingKv(entryEnv().OAUTH_KV);
    const env = allowAllEnv({ ...envOverrides, OAUTH_KV: recorder.kv, OAUTH_PROVIDER: undefined });
    const removeAutonomyClient = options.install ? await installAutonomyClient(allowAllEnv()) : null;
    const clientId = await register(allowAllEnv(), "autonomy not configured", CLAUDE_WEB_REDIRECT);
    try {
      const query = authorizeQuery(clientId, CLAUDE_WEB_REDIRECT, "not-configured");
      recorder.written.length = 0;
      let answer: Response;
      if (options.withContext) {
        const ctx = createExecutionContext();
        answer = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, query), env, ctx);
        await waitOnExecutionContext(ctx);
      } else {
        const handlerEnv = { ...env, OAUTH_PROVIDER: getOAuthApi(oauthProviderOptions, env) } as Env;
        answer = await createLoginHandler(async () => {}).fetch(
          postFrom(freshSource(), LISTED_APPLE_ID, query),
          handlerEnv,
        );
      }
      const autonomyGrants = (await grantsOf(env, userId)).filter(
        (grant) => grant.clientId === AUTONOMY_CLIENT_ID,
      ).length;
      return {
        status: answer.status,
        location: answer.headers.get("location") ?? "",
        grantsWritten: recorder.written.filter((key) => key.startsWith("grant:")),
        autonomyGrants,
      };
    } finally {
      for (const grant of await grantsOf(entryEnv(), userId)) await forgetGrant(userId, grant.id);
      await runInDurableObject(entryEnv().USER_AGENT.getByName(userId), (_i, state) => {
        state.storage.kv.delete(AUTONOMY_KEY);
      });
      await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
      if (removeAutonomyClient !== null) await removeAutonomyClient();
    }
  }

  /** The ordinary 302: to the client's redirect, with a code for this person. */
  async function expectOrdinaryAnswer(result: { status: number; location: string }): Promise<void> {
    const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
    expect(result.status).toBe(302);
    expect(result.location.startsWith(`${CLAUDE_WEB_REDIRECT}?`)).toBe(true);
    expect(new URL(result.location).searchParams.get("code")).toMatch(new RegExp(`^${userId}:`));
  }

  it("control: with both secrets set and the client installed, the sign-in writes two grants", async () => {
    const result = await signInCountingGrants({}, { install: true, withContext: true });
    await expectOrdinaryAnswer(result);
    expect(result.grantsWritten.length).toBeGreaterThanOrEqual(2);
    expect(result.autonomyGrants).toBe(1);
  });

  it("with the seal key unset, answers the same 302 and writes exactly one grant, the ordinary one", async () => {
    const result = await signInCountingGrants(
      { AUTONOMY_SEAL_KEY: undefined },
      { install: true, withContext: true },
    );
    await expectOrdinaryAnswer(result);
    expect(result.grantsWritten).toHaveLength(1);
    expect(result.autonomyGrants).toBe(0);
  });

  it("with the client secret unset, answers the same 302 and writes exactly one grant", async () => {
    const result = await signInCountingGrants(
      { AUTONOMY_CLIENT_SECRET: undefined },
      { install: true, withContext: true },
    );
    await expectOrdinaryAnswer(result);
    expect(result.grantsWritten).toHaveLength(1);
    expect(result.autonomyGrants).toBe(0);
  });

  it("with no execution context, answers the same 302 and writes exactly one grant", async () => {
    const result = await signInCountingGrants({}, { install: true, withContext: false });
    await expectOrdinaryAnswer(result);
    expect(result.grantsWritten).toHaveLength(1);
    expect(result.autonomyGrants).toBe(0);
  });

  it("with the autonomy client record absent, answers the same 302 and no autonomy grant exists", async () => {
    const result = await signInCountingGrants({}, { install: false, withContext: true });
    await expectOrdinaryAnswer(result);
    expect(result.grantsWritten).toHaveLength(1);
    expect(result.autonomyGrants).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Review fix WR-03: a seal key that is set but that the seal would refuse.

/** 16 zero bytes, base64url: set, but not the 32 bytes the seal needs. */
const SHORT_SEAL_KEY = toBase64Url(new Uint8Array(16));

describe("autonomy credential: a seal key the seal would refuse counts as not set up (review WR-03)", () => {
  it("sealKeyUsable accepts exactly a 32-byte base64url value, the same shape the seal needs", () => {
    expect(sealKeyUsable(poolSealKey())).toBe(true);
    expect(sealKeyUsable(toBase64Url(new Uint8Array(32)))).toBe(true);
    for (const refused of [
      undefined,
      null,
      42,
      "",
      SHORT_SEAL_KEY,
      toBase64Url(new Uint8Array(24)),
      toBase64Url(new Uint8Array(33)),
      // Standard base64 of 32 bytes: padding, and the two letters base64url swaps.
      btoa(String.fromCharCode(...new Uint8Array(32).fill(0xfb))),
      `${poolSealKey()}=`,
    ]) {
      expect(sealKeyUsable(refused)).toBe(false);
    }
  });

  it("the page shows no autonomy notice when the seal key is not 32 bytes", () => {
    const env = allowAllEnv({ AUTONOMY_SEAL_KEY: SHORT_SEAL_KEY });
    expect(autonomyConfigured(env)).toBe(false);
    expect(signInNotices(env)).toEqual([RECALL_NOTICE]);
    expect(signInNotices(allowAllEnv())).toEqual([RECALL_NOTICE, AUTONOMY_NOTICE]);
  });

  it("a sign-in with a 16-byte seal key: the same 302, one grant written, and the key the person had is untouched", async () => {
    const armed = await signInArmed(LISTED_APPLE_ID, "autonomy short seal key, first");
    const clientId = await register(allowAllEnv(), "autonomy short seal key", CLAUDE_WEB_REDIRECT);
    try {
      const readRecord = () =>
        runInDurableObject(entryEnv().USER_AGENT.getByName(armed.userId), (_i, state) =>
          JSON.stringify(state.storage.kv.get(AUTONOMY_KEY)),
        );
      const before = await readRecord();
      expect(before).toContain(armed.autonomyGrantId);

      const recorder = recordingKv(entryEnv().OAUTH_KV);
      const env = allowAllEnv({
        AUTONOMY_SEAL_KEY: SHORT_SEAL_KEY,
        OAUTH_KV: recorder.kv,
        OAUTH_PROVIDER: undefined,
      });
      const query = authorizeQuery(clientId, CLAUDE_WEB_REDIRECT, "short-seal-key");
      recorder.written.length = 0;
      const ctx = createExecutionContext();
      const answer = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, query), env, ctx);
      await waitOnExecutionContext(ctx);

      expect(answer.status).toBe(302);
      const location = answer.headers.get("location") ?? "";
      expect(location.startsWith(`${CLAUDE_WEB_REDIRECT}?`)).toBe(true);
      expect(new URL(location).searchParams.get("code")).toMatch(new RegExp(`^${armed.userId}:`));
      expect(recorder.written.filter((key) => key.startsWith("grant:"))).toHaveLength(1);
      const autonomy = (await grantsOf(env, armed.userId)).filter(
        (grant) => grant.clientId === AUTONOMY_CLIENT_ID,
      );
      expect(autonomy.map((grant) => grant.id)).toEqual([armed.autonomyGrantId]);
      expect(await readRecord()).toBe(before);
    } finally {
      await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
      await armed.cleanup();
    }
  });
});
