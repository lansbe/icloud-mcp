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
import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import type { UserAgent } from "../src/agent/user-agent";
import { oauthProviderOptions } from "../src/auth/oauth";
import type { Env } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { userIdOf } from "../src/principal";
import { installAutonomyClient } from "./fixtures/autonomy-client";
import { entryEnv } from "./fixtures/bound-secrets";
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
