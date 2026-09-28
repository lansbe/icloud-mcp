// The autonomy key's lifecycle (Phase 27, plan 27-02).
//
// Plan 27-01 armed the key at sign-in. These cases pin what happens around it:
// every sign-in re-arms and leaves exactly one autonomy grant; a failed arming
// leaves the sign-in untouched and the person not armed; a revocation, or the
// end of the person's ordinary connection, ends the key at the next use; and
// nothing is minted without an interactive sign-in, and nothing extra stored.
//
// **No real Apple ID is ever authenticated (D-09).** Every sign-in goes through
// `test/fixtures/worker-with-login-proof.ts`, whose proof is a counter. The
// addresses are under the reserved `.invalid` domain and the password is
// plainly fake.
//
// **The hygiene rules of test/autonomy.test.ts hold here too.** Every sign-in
// runs against a SPREAD COPY of the pool's environment; nothing is written onto
// the shared one; keys are checked by the grant id this case minted; and every
// case cleans up in a `finally`: grants, their tokens, the object's record, the
// object's seam, and the client records.
//
// The socket module is mocked for this file only, as test/lease.test.ts does,
// so the one mail tool call in the nothing-extra case talks to an in-memory
// duplex. Nothing here opens a network connection.
//
// The helpers are copied from test/autonomy.test.ts rather than imported,
// which is this repository's habit for test helpers.

import type { McpServer } from "@modelcontextprotocol/server";
import {
  createExecutionContext,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { createLeasedMail } from "../src/agent/lease";
import {
  AUTONOMY_KEY,
  type AutonomyDeps,
  type AutonomyRecord,
  type AutonomyStorage,
  disarmWith,
  recordOf,
  seal,
  STANDING_GRACE_SECONDS,
  withAutonomySession,
} from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID, AUTONOMY_CLIENT_NAME } from "../src/agent/autonomy-client";
import {
  type KeyStanding,
  keyStandingFor,
  sweepAutonomyGrants,
} from "../src/agent/autonomy-grants";
import type { UserAgent } from "../src/agent/user-agent";
import { oauthProviderOptions } from "../src/auth/oauth";
import type { Env } from "../src/env";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { registerMailTools } from "../src/mcp/tools/mail";
import { principalFromProps, userIdOf } from "../src/principal";
import { AUTONOMY_REDIRECT_URI, installAutonomyClient } from "./fixtures/autonomy-client";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  resetLoginProof,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** The PKCE verifier this file redeems ordinary codes with. Copied, pair intact. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";

/** `BASE64URL(SHA256(ASCII(CODE_VERIFIER)))`. Copied together with the above. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** Eleven minutes, in seconds: past the standing check's grace. */
const PAST_GRACE_SECONDS = 11 * 60;

beforeEach(() => {
  resetLoginProof();
  vi.mocked(connectImap).mockReset();
});

/** A rate-limit binding stub that always lets the request through. */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** The pool's environment with both limiters replaced, as a COPY. */
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
async function exchangeCode(env: Env, clientId: string, code: string) {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CLAUDE_WEB_REDIRECT,
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

/** Every key listed under a prefix. */
async function keysUnder(prefix: string): Promise<string[]> {
  return (await entryEnv().OAUTH_KV.list({ prefix })).keys.map((key) => key.name);
}

/** Delete a grant and every token under it. Serial, always. */
async function forgetGrant(userId: string, grantId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const name of await keysUnder(`token:${userId}:${grantId}:`)) await kv.delete(name);
  await kv.delete(`grant:${userId}:${grantId}`);
}

/** Every grant the library lists for a person, as summaries. */
async function grantsOf(userId: string) {
  return (await getOAuthApi(oauthProviderOptions, entryEnv()).listUserGrants(userId)).items;
}

/** The ids of every autonomy grant the library lists for a person. */
async function autonomyGrantIds(userId: string): Promise<string[]> {
  return (await grantsOf(userId))
    .filter((grant) => grant.clientId === AUTONOMY_CLIENT_ID)
    .map((grant) => grant.id);
}

/** The ids of every grant from any other client. */
async function ordinaryGrantIds(userId: string): Promise<string[]> {
  return (await grantsOf(userId))
    .filter((grant) => grant.clientId !== AUTONOMY_CLIENT_ID)
    .map((grant) => grant.id);
}

/** The person's object. */
function objectOf(userId: string) {
  return entryEnv().USER_AGENT.getByName(userId);
}

/** The object's autonomy record, as stored. */
async function storedRecord(userId: string): Promise<AutonomyRecord | undefined> {
  return runInDurableObject(objectOf(userId), (_i, state) =>
    state.storage.kv.get<AutonomyRecord>(AUTONOMY_KEY),
  );
}

/** One request a seam saw. */
interface Seen {
  readonly path: string;
  readonly grantType: string | null;
  readonly revokes: boolean;
}

/** What a request to this Worker is, read from a clone. */
async function describeRequest(request: Request): Promise<Seen> {
  const url = new URL(request.url);
  if (url.pathname !== "/oauth/token") return { path: url.pathname, grantType: null, revokes: false };
  const form = await request.clone().formData();
  const grantType = form.get("grant_type");
  return {
    path: url.pathname,
    grantType: typeof grantType === "string" ? grantType : null,
    revokes: form.has("token"),
  };
}

/** A `selfFetch` that records every request and forwards it to this Worker. */
function recordingFetch(): { selfFetch: (request: Request) => Promise<Response>; seen: Seen[] } {
  const seen: Seen[] = [];
  return {
    seen,
    selfFetch: async (request: Request) => {
      seen.push(await describeRequest(request));
      return entryEnv().SELF.fetch(request);
    },
  };
}

/**
 * Replace the object's seam. `make` is handed the seam that was there, to
 * forward to. Answers a function that puts the original back.
 */
async function replaceSeam(
  userId: string,
  make: (forward: (request: Request) => Promise<Response>) => (request: Request) => Promise<Response>,
): Promise<() => Promise<void>> {
  let original: ((request: Request) => Promise<Response>) | null = null;
  await runInDurableObject(objectOf(userId), (instance: UserAgent) => {
    original = instance.autonomySelfFetch;
    const forward = original;
    instance.autonomySelfFetch = make((request) => forward(request));
  });
  return async () => {
    await runInDurableObject(objectOf(userId), (instance: UserAgent) => {
      if (original !== null) instance.autonomySelfFetch = original;
    });
  };
}

/** Session deps over a real object's storage. */
function depsOver(
  storage: AutonomyStorage,
  name: string,
  selfFetch: (request: Request) => Promise<Response>,
  extra: Partial<Pick<AutonomyDeps, "now" | "keyStanding">> = {},
): AutonomyDeps {
  return { storage, name, env: entryEnv(), selfFetch, now: () => Date.now(), ...extra };
}

/** A clock `seconds` after the stored record was armed. */
function clockAfterArming(record: AutonomyRecord, seconds: number): () => number {
  return () => (record.armedAt + seconds) * 1000;
}

/** A person with the autonomy client installed and one ordinary client registered. */
interface World {
  readonly env: Env;
  readonly userId: string;
  readonly clientId: string;
  /** One sign-in, settled, with its ordinary code redeemed. */
  signIn(): Promise<{ status: number; location: string; ordinaryGrantId: string; refreshToken: string }>;
  /** Install the autonomy client, if it was not installed at the start. */
  install(): Promise<void>;
  /** Run a session inside the object with these deps' extras. */
  session(
    fetcher: (request: Request) => Promise<Response>,
    extra?: Partial<Pick<AutonomyDeps, "now" | "keyStanding">>,
  ): Promise<unknown>;
  cleanup(): Promise<void>;
}

async function setUp(name: string, options: { install: boolean } = { install: true }): Promise<World> {
  const env = allowAllEnv();
  const userId = (await userIdOf(LISTED_APPLE_ID)) as string;
  let removeAutonomyClient = options.install ? await installAutonomyClient(env) : null;
  const clientId = await register(env, name, CLAUDE_WEB_REDIRECT);
  let signIns = 0;

  return {
    env,
    userId,
    clientId,
    async signIn() {
      signIns += 1;
      const query = authorizeQuery(clientId, CLAUDE_WEB_REDIRECT, `${name}-${signIns}`);
      const ctx = createExecutionContext();
      const answer = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, query), env, ctx);
      await waitOnExecutionContext(ctx);
      const location = answer.headers.get("location") ?? "";
      const code = location === "" ? "" : (new URL(location).searchParams.get("code") ?? "");
      const ordinary = await exchangeCode(env, clientId, code);
      return {
        status: answer.status,
        location,
        ordinaryGrantId: ordinary.access_token.split(":")[1] as string,
        refreshToken: ordinary.refresh_token,
      };
    },
    async install() {
      removeAutonomyClient = await installAutonomyClient(env);
    },
    async session(fetcher, extra = {}) {
      return runInDurableObject(objectOf(userId), async (_i, state) =>
        withAutonomySession(depsOver(state.storage.kv, userId, fetcher, extra), (call) =>
          call("account_whoami", {}),
        ),
      );
    },
    async cleanup() {
      for (const grant of await grantsOf(userId)) await forgetGrant(userId, grant.id);
      await runInDurableObject(objectOf(userId), (_i, state) => {
        state.storage.kv.delete(AUTONOMY_KEY);
      });
      await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
      if (removeAutonomyClient !== null) await removeAutonomyClient();
      else await entryEnv().OAUTH_KV.delete(`client:${AUTONOMY_CLIENT_ID}`);
    },
  };
}

/** The ordinary 302: to the client's redirect, with a code for this person. */
function expectOrdinaryAnswer(result: { status: number; location: string }, userId: string): void {
  expect(result.status).toBe(302);
  expect(result.location.startsWith(`${CLAUDE_WEB_REDIRECT}?`)).toBe(true);
  expect(new URL(result.location).searchParams.get("code")).toMatch(new RegExp(`^${userId}:`));
}

/** Mint an autonomy grant through the library, never armed. Answers its id. */
async function mintStrayAutonomyGrant(env: Env, userId: string): Promise<string> {
  const minted = await getOAuthApi(oauthProviderOptions, env).completeAuthorization({
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
  return new URL(minted.redirectTo).searchParams.get("code")?.split(":")[1] as string;
}

// ---------------------------------------------------------------------------

describe("autonomy credential: re-arm, sweep and failure isolation (D-11, D-13, D-26, D-28)", () => {
  it("two sign-ins, one after the other, leave exactly one autonomy grant, the one the record names, at generation 2", async () => {
    const world = await setUp("lifecycle re-arm");
    try {
      await world.signIn();
      const first = await autonomyGrantIds(world.userId);
      expect(first).toHaveLength(1);
      const firstGrantId = first[0] as string;

      const second = await world.signIn();
      expectOrdinaryAnswer(second, world.userId);
      const after = await autonomyGrantIds(world.userId);
      const record = await storedRecord(world.userId);
      expect(after).toHaveLength(1);
      expect(after[0]).toBe(record?.grantId);
      expect(after[0]).not.toBe(firstGrantId);
      expect(record?.generation).toBe(2);
      expect(await keysUnder(`token:${world.userId}:${firstGrantId}:`)).toEqual([]);
    } finally {
      await world.cleanup();
    }
  });

  it("revokes an autonomy grant minted and never armed, at the next successful arm", async () => {
    const world = await setUp("lifecycle stray");
    try {
      await world.signIn();
      const stray = await mintStrayAutonomyGrant(world.env, world.userId);
      expect(await autonomyGrantIds(world.userId)).toContain(stray);

      await world.signIn();
      const after = await autonomyGrantIds(world.userId);
      expect(after).toHaveLength(1);
      expect(after).not.toContain(stray);
      expect(after[0]).toBe((await storedRecord(world.userId))?.grantId);
    } finally {
      await world.cleanup();
    }
  });

  it("a failed proof at re-arm answers the same 302 and ends the key the person had: no record, no autonomy grant", async () => {
    const world = await setUp("lifecycle failed proof");
    let restore: (() => Promise<void>) | null = null;
    try {
      await world.signIn();
      expect(await autonomyGrantIds(world.userId)).toHaveLength(1);
      expect(await storedRecord(world.userId)).toBeDefined();

      restore = await replaceSeam(world.userId, (forward) => async (request) => {
        if (new URL(request.url).pathname === "/mcp") return new Response(null, { status: 500 });
        return forward(request);
      });

      // signIn redeems the ordinary code, so the code still exchanges.
      const second = await world.signIn();
      expectOrdinaryAnswer(second, world.userId);
      expect(await ordinaryGrantIds(world.userId)).toContain(second.ordinaryGrantId);
      expect(await autonomyGrantIds(world.userId)).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      if (restore !== null) await restore();
      await world.cleanup();
    }
  });

  it("a refused code exchange arms nothing, and the minted autonomy grant is gone once the sign-in settles", async () => {
    const world = await setUp("lifecycle refused exchange");
    const restore = await replaceSeam(world.userId, (forward) => async (request) => {
      const seen = await describeRequest(request);
      if (seen.grantType === "authorization_code") {
        return Response.json({ error: "server_error" }, { status: 500 });
      }
      return forward(request);
    });
    try {
      const result = await world.signIn();
      expectOrdinaryAnswer(result, world.userId);
      expect(await autonomyGrantIds(world.userId)).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      await restore();
      await world.cleanup();
    }
  });
});

describe("autonomy credential: revocation and the standing check (AUTO-04, D-33)", () => {
  it("finds a revocation through the listing, past the grace: no token call, revoked, then off with no call", async () => {
    const world = await setUp("lifecycle revoked by listing");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      await getOAuthApi(oauthProviderOptions, world.env).revokeGrant(record.grantId, world.userId);

      const fetcher = recordingFetch();
      const now = clockAfterArming(record, PAST_GRACE_SECONDS);
      expect(await world.session(fetcher.selfFetch, { now })).toEqual({ kind: "revoked" });
      expect(fetcher.seen).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();

      expect(await world.session(fetcher.selfFetch, { now })).toEqual({ kind: "off" });
      expect(fetcher.seen).toEqual([]);
    } finally {
      await world.cleanup();
    }
  });

  it("finds a revocation at the token endpoint, inside the grace: one call, revoked, and no retry", async () => {
    const world = await setUp("lifecycle revoked at endpoint");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      await getOAuthApi(oauthProviderOptions, world.env).revokeGrant(record.grantId, world.userId);

      const fetcher = recordingFetch();
      let asked = 0;
      const keyStanding = async (): Promise<KeyStanding> => {
        asked += 1;
        return "standing";
      };
      const outcome = await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, 60),
        keyStanding,
      });
      expect(outcome).toEqual({ kind: "revoked" });
      expect(asked).toBe(0);
      expect(fetcher.seen).toEqual([{ path: "/oauth/token", grantType: "refresh_token", revokes: false }]);
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      await world.cleanup();
    }
  });

  it("treats a deleted autonomy client as final: one call, revoked, record deleted", async () => {
    const world = await setUp("lifecycle client gone");
    try {
      await world.signIn();
      await entryEnv().OAUTH_KV.delete(`client:${AUTONOMY_CLIENT_ID}`);
      const fetcher = recordingFetch();
      expect(await world.session(fetcher.selfFetch)).toEqual({ kind: "revoked" });
      expect(fetcher.seen).toHaveLength(1);
      expect(fetcher.seen[0]?.path).toBe("/oauth/token");
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      await world.cleanup();
    }
  });

  it("ends the key when the person's only ordinary grant is revoked: no token call, revoked, no autonomy grant left", async () => {
    const world = await setUp("lifecycle connection ended");
    try {
      const signedIn = await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      await getOAuthApi(oauthProviderOptions, world.env).revokeGrant(
        signedIn.ordinaryGrantId,
        world.userId,
      );
      expect(await ordinaryGrantIds(world.userId)).toEqual([]);

      const fetcher = recordingFetch();
      const outcome = await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, PAST_GRACE_SECONDS),
      });
      expect(outcome).toEqual({ kind: "revoked" });
      expect(fetcher.seen).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();
      expect(await autonomyGrantIds(world.userId)).toEqual([]);
    } finally {
      await world.cleanup();
    }
  });

  it("leaves the key alone while the person still holds another ordinary grant", async () => {
    const world = await setUp("lifecycle connection still there");
    try {
      const first = await world.signIn();
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      expect(await ordinaryGrantIds(world.userId)).toHaveLength(2);
      await getOAuthApi(oauthProviderOptions, world.env).revokeGrant(first.ordinaryGrantId, world.userId);

      const fetcher = recordingFetch();
      const outcome = (await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, PAST_GRACE_SECONDS),
      })) as { kind: string; value?: { kind: string } };
      expect(outcome.kind).toBe("ok");
      expect(outcome.value?.kind).toBe("ok");
      const after = (await storedRecord(world.userId)) as AutonomyRecord;
      expect(after.grantId).toBe(record.grantId);
      expect(after.generation).toBe(record.generation);
      expect(after.armedAt).toBe(record.armedAt);
      expect(await autonomyGrantIds(world.userId)).toEqual([record.grantId]);
    } finally {
      await world.cleanup();
    }
  });

  it("inside the grace, an empty listing ends nothing: the listing is not asked and the session succeeds", async () => {
    const world = await setUp("lifecycle inside grace");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      let asked = 0;
      const keyStanding = async (): Promise<KeyStanding> => {
        asked += 1;
        return "connection_ended";
      };
      const fetcher = recordingFetch();
      const outcome = (await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, 5 * 60),
        keyStanding,
      })) as { kind: string };
      expect(outcome.kind).toBe("ok");
      expect(asked).toBe(0);
      expect((await storedRecord(world.userId))?.grantId).toBe(record.grantId);

      // The same seam, one second past the grace, is asked and ends the key.
      const late = await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, STANDING_GRACE_SECONDS),
        keyStanding,
      });
      expect(asked).toBe(1);
      expect(late).toEqual({ kind: "revoked" });
    } finally {
      await world.cleanup();
    }
  });

  it("a listing that fails keeps the key and answers failed, with no token call", async () => {
    const world = await setUp("lifecycle listing fails");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      const before = JSON.stringify(record);
      const fetcher = recordingFetch();
      const outcome = await world.session(fetcher.selfFetch, {
        now: clockAfterArming(record, PAST_GRACE_SECONDS),
        keyStanding: async () => {
          throw new Error("the listing could not be read");
        },
      });
      expect(outcome).toEqual({ kind: "failed" });
      expect(fetcher.seen).toEqual([]);
      expect(JSON.stringify(await storedRecord(world.userId))).toBe(before);
    } finally {
      await world.cleanup();
    }
  });
});

/** A fresh 64-hex user id nothing else touches. */
function freshUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A store that lists one key per page, so every page must be followed. */
function onePerPage(real: KVNamespace, rejectLaterPages = false): KVNamespace {
  return new Proxy(real, {
    get(target, prop) {
      if (prop === "list") {
        return (options: KVNamespaceListOptions = {}) => {
          if (rejectLaterPages && options.cursor !== undefined) {
            return Promise.reject(new Error("the store could not list this page"));
          }
          return target.list({ ...options, limit: 1 });
        };
      }
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

describe("autonomy credential: the library, asked once (autonomy-grants)", () => {
  /** Mint grants for a fresh user: `autonomy` autonomy grants and `ordinary` from one client. */
  async function mintFor(autonomy: number, ordinary: number) {
    const env = allowAllEnv();
    const userId = freshUserId();
    const removeAutonomyClient = await installAutonomyClient(env);
    const clientId = await register(env, "lifecycle library", CLAUDE_WEB_REDIRECT);
    const helpers = getOAuthApi(oauthProviderOptions, env);
    const mint = async (client: string, redirectUri: string) => {
      // The ordinary client is public, so the library wants PKCE on its request.
      const pkce =
        client === AUTONOMY_CLIENT_ID
          ? {}
          : { codeChallenge: CODE_CHALLENGE, codeChallengeMethod: "S256" };
      const minted = await helpers.completeAuthorization({
        request: { responseType: "code", clientId: client, redirectUri, scope: ["mcp"], state: "", ...pkce },
        userId,
        metadata: {},
        scope: ["mcp"],
        props: { v: 1, appleId: "library@example.invalid", appPassword: FAKE_APP_PASSWORD },
        revokeExistingGrants: false,
      });
      return new URL(minted.redirectTo).searchParams.get("code")?.split(":")[1] as string;
    };
    const autonomyIds: string[] = [];
    const ordinaryIds: string[] = [];
    for (let i = 0; i < autonomy; i += 1) autonomyIds.push(await mint(AUTONOMY_CLIENT_ID, AUTONOMY_REDIRECT_URI));
    for (let i = 0; i < ordinary; i += 1) ordinaryIds.push(await mint(clientId, CLAUDE_WEB_REDIRECT));
    return {
      userId,
      autonomyIds,
      ordinaryIds,
      async cleanup() {
        for (const grant of await grantsOf(userId)) await forgetGrant(userId, grant.id);
        await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
        await removeAutonomyClient();
      },
    };
  }

  it("keyStandingFor answers standing, revoked, connection_ended and unknown, following every page", async () => {
    const minted = await mintFor(2, 1);
    try {
      const kv = onePerPage(entryEnv().OAUTH_KV);
      const [kept, other] = minted.autonomyIds as [string, string];
      expect(await keyStandingFor(kv, minted.userId, kept)).toBe("standing");
      expect(await keyStandingFor(kv, minted.userId, other)).toBe("standing");
      expect(await keyStandingFor(kv, minted.userId, "not-a-listed-grant")).toBe("revoked");
      expect(await keyStandingFor(onePerPage(entryEnv().OAUTH_KV, true), minted.userId, kept)).toBe("unknown");
      expect(await keyStandingFor(kv, minted.userId.toUpperCase(), kept)).toBe("unknown");
      expect(await keyStandingFor(kv, "not-a-user-id", kept)).toBe("unknown");

      await forgetGrant(minted.userId, minted.ordinaryIds[0] as string);
      expect(await keyStandingFor(kv, minted.userId, kept)).toBe("connection_ended");
    } finally {
      await minted.cleanup();
    }
  });

  it("sweepAutonomyGrants revokes every autonomy grant but the kept one, across pages, and never an ordinary grant", async () => {
    const minted = await mintFor(3, 2);
    try {
      const kv = onePerPage(entryEnv().OAUTH_KV);
      const kept = minted.autonomyIds[1] as string;
      expect(await sweepAutonomyGrants(kv, minted.userId, kept)).toBe("done");
      expect(await autonomyGrantIds(minted.userId)).toEqual([kept]);
      expect((await ordinaryGrantIds(minted.userId)).sort()).toEqual([...minted.ordinaryIds].sort());

      expect(await sweepAutonomyGrants(kv, "not-a-user-id", null)).toBe("incomplete");
      expect(await sweepAutonomyGrants(onePerPage(entryEnv().OAUTH_KV, true), minted.userId, null)).toBe(
        "incomplete",
      );
      expect(await autonomyGrantIds(minted.userId)).toEqual([kept]);

      expect(await sweepAutonomyGrants(kv, minted.userId, null)).toBe("done");
      expect(await autonomyGrantIds(minted.userId)).toEqual([]);
      expect(await ordinaryGrantIds(minted.userId)).toHaveLength(2);
    } finally {
      await minted.cleanup();
    }
  });
});

describe("autonomy credential: disarm (D-16 as revised)", () => {
  it("revokes a record that unseals, through the endpoint, and deletes it; answers off", async () => {
    const world = await setUp("lifecycle disarm");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      const fetcher = recordingFetch();
      const outcome = await runInDurableObject(objectOf(world.userId), async (_i, state) =>
        disarmWith(depsOver(state.storage.kv, world.userId, fetcher.selfFetch)),
      );
      expect(outcome).toEqual({ kind: "off" });
      expect(fetcher.seen).toEqual([{ path: "/oauth/token", grantType: null, revokes: true }]);
      expect(await storedRecord(world.userId)).toBeUndefined();
      expect(await autonomyGrantIds(world.userId)).not.toContain(record.grantId);
    } finally {
      await world.cleanup();
    }
  });

  it("only deletes a record that does not unseal, with no request; answers off", async () => {
    const name = freshUserId();
    const sealed = await seal(entryEnv().AUTONOMY_SEAL_KEY, freshUserId(), `${name}:g:not-a-real-token`);
    const fetcher = recordingFetch();
    const result = await runInDurableObject(objectOf(name), async (_i, state) => {
      state.storage.kv.put(AUTONOMY_KEY, {
        v: 1,
        grantId: "g",
        sealedRefreshToken: sealed?.sealedRefreshToken,
        iv: sealed?.iv,
        armedAt: 1,
        generation: 1,
      });
      const outcome = await disarmWith(depsOver(state.storage.kv, name, fetcher.selfFetch));
      return { outcome, after: state.storage.kv.get(AUTONOMY_KEY) };
    });
    expect(result.outcome).toEqual({ kind: "off" });
    expect(result.after).toBeUndefined();
    expect(fetcher.seen).toEqual([]);
  });
});

/**
 * A server that signs in and answers the folder listing. Copied from
 * test/lease.test.ts's `folderListingServer`.
 */
function folderListingServer() {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 172 UNSEEN 4)',
      '* LIST (\\HasNoChildren) "/" "Drafts"',
      '* STATUS "Drafts" (MESSAGES 3 UNSEEN 0)',
      "a4 OK LIST completed",
    ),
    logoutExchange("a5"),
  ]);
}

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };

describe("autonomy credential: nothing without a sign-in, and nothing extra (D-03, D-26)", () => {
  it("a Claude app refreshing its own token, with no sign-in, gets no autonomy grant and no record", async () => {
    const world = await setUp("lifecycle refresh only", { install: false });
    try {
      const signedIn = await world.signIn();
      expect(await autonomyGrantIds(world.userId)).toEqual([]);
      await world.install();

      const response = await callWorker(
        new Request(`${ORIGIN}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: signedIn.refreshToken,
            client_id: world.clientId,
          }).toString(),
        }),
        world.env,
      );
      expect(response.status).toBe(200);
      await response.arrayBuffer();

      expect(await autonomyGrantIds(world.userId)).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      await world.cleanup();
    }
  });

  it("after one sign-in and one mail tool call, stores one sealed record, one autonomy grant, and the password nowhere in the clear", async () => {
    const world = await setUp("lifecycle nothing extra");
    try {
      await world.signIn();

      vi.mocked(connectImap).mockReturnValue(folderListingServer() as never);
      let callback: (() => Promise<ToolAnswer>) | undefined;
      const server = {
        registerTool(name: string, _options: unknown, handler: () => Promise<ToolAnswer>) {
          if (name === "mail_list_folders") callback = handler;
        },
      };
      const principal = principalFromProps({
        v: 1,
        appleId: LISTED_APPLE_ID,
        appPassword: FAKE_APP_PASSWORD,
      });
      registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), principal);
      expect(callback).toBeDefined();
      const answer = await (callback as () => Promise<ToolAnswer>)();
      expect(answer.isError).toBeUndefined();
      expect(connectImap).toHaveBeenCalledTimes(1);

      const inside = await runInDurableObject(objectOf(world.userId), (_i, state) => {
        const keys: string[] = [];
        const values: string[] = [];
        for (const [key, value] of state.storage.kv.list()) {
          keys.push(key);
          values.push(JSON.stringify(value));
        }
        const tables = state.storage.sql
          .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
          .toArray()
          .map((row) => row.name)
          .filter((name) => !name.startsWith("_cf_") && !name.startsWith("sqlite_"));
        const rows: string[] = [];
        for (const table of tables) {
          for (const row of state.storage.sql.exec(`SELECT * FROM "${table}"`).toArray()) {
            rows.push(JSON.stringify(row));
          }
        }
        return { keys, values, rows };
      });

      for (const key of inside.keys) expect(["lease", "own-name", AUTONOMY_KEY]).toContain(key);
      expect(inside.keys).toContain(AUTONOMY_KEY);
      expect(inside.keys).toContain("own-name");
      expect(recordOf((await storedRecord(world.userId)) as unknown)).not.toBeNull();
      for (const text of [...inside.values, ...inside.rows]) expect(text).not.toContain(FAKE_APP_PASSWORD);

      expect(await autonomyGrantIds(world.userId)).toHaveLength(1);
      const kv = entryEnv().OAUTH_KV;
      for (const prefix of [`grant:${world.userId}:`, `token:${world.userId}:`]) {
        for (const name of await keysUnder(prefix)) {
          expect((await kv.get(name)) ?? "").not.toContain(FAKE_APP_PASSWORD);
        }
      }
    } finally {
      await world.cleanup();
    }
  });
});
