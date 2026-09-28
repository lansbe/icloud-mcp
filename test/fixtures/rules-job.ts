// The rules job's object-level harness (Phase 28, plans 28-01 and 28-02).
//
// A person signs in through the login-proof worker with the autonomy client
// installed, which arms their autonomy key because autonomy is inherent. The
// object's one seam to this Worker can then be pointed back at the login-proof
// worker in process, so the job's calls go through the real redemption, the
// real door and the real mail tools. The IMAP turns the tools need are built
// here; the test file that uses them mocks the socket module and queues the
// sessions, because a mock belongs to the file that declares it.
//
// The shapes are copied from test/autonomy-job.test.ts (28-01), which keeps its
// own copies. Nothing here opens a network connection and nothing signs in to a
// real Apple ID (D-09, D-13).

import {
  createExecutionContext,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { expect } from "vitest";
import { AUTONOMY_KEY } from "../../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID } from "../../src/agent/autonomy-client";
import type { UserAgent } from "../../src/agent/user-agent";
import { AUTONOMY_NOTICE_FIELD, AUTONOMY_NOTICE_VERSION } from "../../src/auth/login-page";
import { oauthProviderOptions } from "../../src/auth/oauth";
import type { Env } from "../../src/env";
import { DEPLOYED_HOSTNAME } from "../../src/mcp/api-handler";
import { userIdOf } from "../../src/principal";
import { installAutonomyClient } from "./autonomy-client";
import { entryEnv } from "./bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fake-duplex";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  statusResponse,
  taggedOk,
} from "./icloud-bytes";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  resetLoginProof,
} from "./worker-with-login-proof";

export const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The PKCE pair ordinary codes are redeemed with. Copied, pair intact. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";
const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

export type Stub = DurableObjectStub<UserAgent>;

/** A rate-limit binding stub. */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** The pool's environment with both limiters replaced, as a copy. */
export function allowAllEnv(): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
  } as unknown as Env;
}

/** Hand a request to the Worker, in process, with a context of its own. */
export async function callWorker(request: Request, env: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** A signed-in, armed person, and how to clean up after them. */
export interface Armed {
  readonly env: Env;
  readonly userId: string;
  readonly stub: Stub;
  /** The ordinary connection's access token, for a direct tool call. */
  readonly accessToken: string;
  cleanup(): Promise<void>;
}

/**
 * Sign the listed address in through the login-proof worker with the autonomy
 * client installed, and settle the execution context, which is when the arm
 * runs.
 */
export async function signInArmed(): Promise<Armed> {
  const env = allowAllEnv();
  const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
  const stub = entryEnv().USER_AGENT.getByName(userId);
  const removeAutonomyClient = await installAutonomyClient(env);
  const registered = await callWorker(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "rules job harness",
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
    const accessToken = ((await exchanged.json()) as { access_token: string }).access_token;
    const grants = (await getOAuthApi(oauthProviderOptions, env).listUserGrants(userId)).items;
    expect(grants.filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID)).toHaveLength(1);
    const armed = await runInDurableObject(stub, (_i, state) =>
      state.storage.kv.get(AUTONOMY_KEY) !== undefined,
    );
    expect(armed).toBe(true);
    return { env, userId, stub, accessToken, cleanup };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

/** One self-call the object made, and what storage held when it left. */
export interface SelfCall {
  readonly path: string;
  readonly grantType: string | null;
  readonly tool: string | null;
  /** The tool call's arguments, for a `/mcp` tool call; else null. */
  readonly args: Record<string, unknown> | null;
  /** Every "already acted" record at that moment, by key. */
  readonly acted: Record<string, unknown>;
  /** The stored marker at that moment, or null. */
  readonly marker: string | null;
}

/** The arguments of a JSON-RPC tool call body, or null. */
async function toolArgs(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = (await request.clone().json()) as {
      method?: unknown;
      params?: { arguments?: unknown };
    };
    if (body.method !== "tools/call") return null;
    const args = body.params?.arguments;
    return typeof args === "object" && args !== null ? (args as Record<string, unknown>) : {};
  } catch {
    return null;
  }
}

/**
 * Point the object's seam at the login-proof worker, in process, recording
 * each call, its tool arguments and a snapshot of the job's storage as the
 * call leaves.
 */
export async function routeSelfCalls(armed: Armed): Promise<SelfCall[]> {
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
      const args = url.pathname === "/mcp" ? await toolArgs(request) : null;
      const acted: Record<string, unknown> = {};
      for (const [key, value] of kv.list({ prefix: "acted:" })) acted[key] = value;
      const stored = kv.get<{ marker?: unknown }>("job:marker");
      calls.push({
        path: url.pathname,
        grantType,
        tool: request.headers.get("Mcp-Name"),
        args,
        acted,
        marker: typeof stored?.marker === "string" ? stored.marker : null,
      });
      return callWorker(request, armed.env);
    };
  });
  return calls;
}

/** Make the job's own time come: forget its stored next wake. */
export function makeJobDue(stub: Stub): Promise<void> {
  return runInDurableObject(stub, (_i, state) => {
    state.storage.kv.delete("job:nextAt");
  });
}

/** The four turns every session opens with. The next tag is `a4`. */
export function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A session that answers one status command for the inbox. */
export function statusSession(uidNext: number, modseq: string): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    statusResponse("a4", "INBOX", INBOX_UIDVALIDITY, uidNext, 172, modseq),
    logoutExchange("a5"),
  ]);
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A time as the protocol's receipt-time form, in UTC. */
export function receiptTime(ms: number): string {
  const d = new Date(ms);
  const two = (n: number) => String(n).padStart(2, "0");
  return (
    `${two(d.getUTCDate())}-${MONTHS[d.getUTCMonth()]}-${d.getUTCFullYear()} ` +
    `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} +0000`
  );
}

const ENCODER = new TextEncoder();

/** Join byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** One new message, as the change check's header fetch returns it. */
export interface NewMessage {
  readonly uid: number;
  readonly subject: string;
  readonly from: string;
  /** Extra header lines inside the fetched block, such as a list id. */
  readonly extra?: readonly string[];
}

/** One header-only fetch reply per row, received at `at`, then the completion. */
export function headerFetchReply(tag: string, at: number, rows: readonly NewMessage[]): Uint8Array {
  const parts: Uint8Array[] = [];
  rows.forEach((row, index) => {
    const lines = [`Subject: ${row.subject}`, `From: ${row.from}`, ...(row.extra ?? [])];
    const header = ENCODER.encode(`${lines.join("\r\n")}\r\n\r\n`);
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
  return concatBytes(...parts);
}

/**
 * One tool call on the person's ORDINARY connection, straight into this Worker,
 * the way a Claude client makes it. Answers the HTTP response.
 */
export function directToolCall(
  armed: Armed,
  name: string,
  args: Record<string, unknown>,
): Promise<Response> {
  return callWorker(
    new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        host: DEPLOYED_HOSTNAME,
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
        authorization: `Bearer ${armed.accessToken}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name,
          arguments: args,
          _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
          },
        },
      }),
    }),
    armed.env,
  );
}
