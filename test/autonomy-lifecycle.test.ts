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
  armWith,
  type AutonomyCall,
  type AutonomyDeps,
  type AutonomyQueue,
  type AutonomyRecord,
  type AutonomySessionOutcome,
  type AutonomyStorage,
  disarmWith,
  oneAtATime,
  recordOf,
  seal,
  STANDING_GRACE_SECONDS,
  unseal,
  withAutonomySession,
} from "../src/agent/autonomy";
import { AUTONOMY_CLIENT_ID, AUTONOMY_CLIENT_NAME } from "../src/agent/autonomy-client";
import {
  type KeyStanding,
  keyStandingFor,
  sweepAutonomyGrants,
} from "../src/agent/autonomy-grants";
import { UserAgent as UserAgentClass } from "../src/agent/user-agent";
import type { UserAgent } from "../src/agent/user-agent";
import { oauthProviderOptions } from "../src/auth/oauth";
import { AUTONOMY_NOTICE_FIELD, AUTONOMY_NOTICE_VERSION } from "../src/auth/login-page";
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
      // The field the page renders when it shows the autonomy notice (D-30).
      [AUTONOMY_NOTICE_FIELD]: AUTONOMY_NOTICE_VERSION,
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

/**
 * Open one session the way the object does: inside a queue's run, with the
 * ticket that run hands out (review WR-04). The queue here is the case's own.
 */
function sessionInQueue<T>(
  deps: AutonomyDeps,
  use: (call: AutonomyCall) => Promise<T>,
): Promise<AutonomySessionOutcome<T>> {
  return oneAtATime().run((ticket) => withAutonomySession({ ...deps, ticket }, use));
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
        sessionInQueue(depsOver(state.storage.kv, userId, fetcher, extra), (call) =>
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
  return (await mintAutonomyCode(env, userId)).split(":")[1] as string;
}

/** Mint an autonomy grant through the library, never armed. Answers its one-time code. */
async function mintAutonomyCode(env: Env, userId: string): Promise<string> {
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
  return new URL(minted.redirectTo).searchParams.get("code") as string;
}

/** Rewrite a grant's `createdAt` to `seconds` ago. Test-only; the grant keeps no TTL after. */
async function backdateGrant(userId: string, grantId: string, seconds: number): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  const key = `grant:${userId}:${grantId}`;
  const raw = await kv.get(key);
  expect(raw).not.toBeNull();
  const record = JSON.parse(raw as string) as Record<string, unknown>;
  record.createdAt = Math.floor(Date.now() / 1000) - seconds;
  await kv.put(key, JSON.stringify(record));
}

/**
 * A store whose listing does not show `hidden` yet, the way a KV listing can
 * lag a fresh write by up to a minute. Reads, writes and deletes are the real
 * store's.
 */
function listingWithout(real: KVNamespace, hidden: string): KVNamespace {
  return new Proxy(real, {
    get(target, prop) {
      if (prop === "list") {
        return async (options: KVNamespaceListOptions = {}) => {
          const page = await target.list(options);
          return { ...page, keys: page.keys.filter((key) => key.name !== hidden) };
        };
      }
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
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

  it("revokes an autonomy grant minted and never armed, older than a code's lifetime, at the next successful arm", async () => {
    const world = await setUp("lifecycle stray");
    try {
      await world.signIn();
      const stray = await mintStrayAutonomyGrant(world.env, world.userId);
      expect(await autonomyGrantIds(world.userId)).toContain(stray);
      // Minted eleven minutes ago: past the code's ten-minute lifetime, so no
      // sign-in can still be about to arm it (review WR-01).
      await backdateGrant(world.userId, stray, PAST_GRACE_SECONDS);

      await world.signIn();
      const after = await autonomyGrantIds(world.userId);
      expect(after).toHaveLength(1);
      expect(after).not.toContain(stray);
      expect(after[0]).toBe((await storedRecord(world.userId))?.grantId);
    } finally {
      await world.cleanup();
    }
  });

  it("a successful arm's sweep leaves a sibling sign-in's fresh grant that is not yet pending, and that sign-in then arms (review WR-01)", async () => {
    const world = await setUp("lifecycle sibling in flight");
    try {
      await world.signIn();
      // Two submissions of one form. A's code is armed first. B's grant is
      // already minted, but B's arm has not reached the object, so it is not
      // in the pending list when A's sweep runs.
      const codeA = await mintAutonomyCode(world.env, world.userId);
      const codeB = await mintAutonomyCode(world.env, world.userId);
      const grantA = codeA.split(":")[1] as string;
      const grantB = codeB.split(":")[1] as string;
      const stub = objectOf(world.userId);

      expect(await stub.armAutonomy(codeA)).toEqual({ kind: "armed", grantId: grantA });
      expect(await autonomyGrantIds(world.userId)).toContain(grantB);

      expect(await stub.armAutonomy(codeB)).toEqual({ kind: "armed", grantId: grantB });
      expect(await autonomyGrantIds(world.userId)).toEqual([grantB]);
      expect((await storedRecord(world.userId))?.grantId).toBe(grantB);
    } finally {
      await world.cleanup();
    }
  });

  it("a re-arm revokes the grant it replaced by id, even when the listing does not show that grant yet (review WR-02)", async () => {
    const world = await setUp("lifecycle replaced by id");
    try {
      await world.signIn();
      const replaced = (await storedRecord(world.userId)) as AutonomyRecord;
      const code = await mintAutonomyCode(world.env, world.userId);
      const newGrantId = code.split(":")[1] as string;
      const lagging = listingWithout(entryEnv().OAUTH_KV, `grant:${world.userId}:${replaced.grantId}`);

      const outcome = await runInDurableObject(objectOf(world.userId), async (instance: UserAgent, state) =>
        instance.autonomyQueue.run(async (ticket) =>
          armWith(
            {
              storage: state.storage.kv,
              name: world.userId,
              env: { ...entryEnv(), OAUTH_KV: lagging },
              selfFetch: (request) => entryEnv().SELF.fetch(request),
              now: () => Date.now(),
              ticket,
            },
            code,
          ),
        ),
      );

      expect(outcome).toEqual({ kind: "armed", grantId: newGrantId });
      expect((await storedRecord(world.userId))?.generation).toBe(replaced.generation + 1);
      expect(await autonomyGrantIds(world.userId)).toEqual([newGrantId]);
      expect(await keysUnder(`token:${world.userId}:${replaced.grantId}:`)).toEqual([]);
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
      // Keeping one, at "now": every grant is younger than a code's lifetime,
      // so each may be a sign-in still in flight, and all are left (WR-01).
      expect(await sweepAutonomyGrants(kv, minted.userId, kept)).toBe("done");
      expect((await autonomyGrantIds(minted.userId)).sort()).toEqual([...minted.autonomyIds].sort());
      // Eleven minutes on, the same sweep revokes all but the kept one.
      const later = Math.floor(Date.now() / 1000) + PAST_GRACE_SECONDS;
      expect(await sweepAutonomyGrants(kv, minted.userId, kept, new Set(), later)).toBe("done");
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

// ---------------------------------------------------------------------------
// Task 2: one at a time, and the generation guards.

/** A promise this case resolves by hand. */
function gate(): { promise: Promise<void>; open(): void } {
  let open = (): void => {};
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

/** The refresh token a token-endpoint answer carries, read from a clone, or null. */
async function refreshTokenIn(response: Response): Promise<string | null> {
  try {
    const body = (await response.clone().json()) as { refresh_token?: unknown };
    return typeof body.refresh_token === "string" ? body.refresh_token : null;
  } catch {
    return null;
  }
}

describe("autonomy credential: one at a time (D-27, RESEARCH §7)", () => {
  it("two sign-ins at once leave exactly one autonomy grant, the one the record names, and it works", async () => {
    const world = await setUp("lifecycle two at once");
    // A's first token request is held until B's arm is known to be WAITING in
    // the object: both grant ids are in `pendingArmGrants` (review WR-05). So
    // the two arms really overlap, and the case fails if they do not. Before,
    // A was held for at most 200 ms and the case passed whether or not B had
    // arrived. While A is held, the queue must keep every request of B's away
    // from the seam.
    let heldCount = 0;
    let overlapped = false;
    let seenWhileHeld = 0;
    let holding = false;
    let original: ((request: Request) => Promise<Response>) | null = null;
    await runInDurableObject(objectOf(world.userId), (instance: UserAgent) => {
      original = instance.autonomySelfFetch;
      const forward = original;
      instance.autonomySelfFetch = async (request: Request): Promise<Response> => {
        if (holding) seenWhileHeld += 1;
        if (heldCount === 0 && new URL(request.url).pathname === "/oauth/token") {
          heldCount += 1;
          holding = true;
          // At most three seconds, inside the case's timeout. A request of B's
          // reaching the seam ends the hold at once: the queue has failed, and
          // the assertion below says so.
          for (let i = 0; i < 300 && instance.pendingArmGrants.size < 2 && seenWhileHeld === 0; i += 1) {
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          overlapped = instance.pendingArmGrants.size >= 2;
          holding = false;
        }
        return forward(request);
      };
    });
    const restore = async () => {
      await runInDurableObject(objectOf(world.userId), (instance: UserAgent) => {
        if (original !== null) instance.autonomySelfFetch = original;
      });
    };    try {
      const queryA = authorizeQuery(world.clientId, CLAUDE_WEB_REDIRECT, "at-once-a");
      const queryB = authorizeQuery(world.clientId, CLAUDE_WEB_REDIRECT, "at-once-b");
      const ctxA = createExecutionContext();
      const ctxB = createExecutionContext();
      const answerA = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, queryA), world.env, ctxA);      const answerB = await worker.fetch(postFrom(freshSource(), LISTED_APPLE_ID, queryB), world.env, ctxB);
      expect(answerA.status).toBe(302);
      expect(answerB.status).toBe(302);
      await waitOnExecutionContext(ctxA);
      await waitOnExecutionContext(ctxB);

      expect(heldCount).toBe(1);
      expect(overlapped).toBe(true);
      expect(seenWhileHeld).toBe(0);
      const grants = await autonomyGrantIds(world.userId);
      const record = await storedRecord(world.userId);
      expect(grants).toHaveLength(1);
      expect(grants[0]).toBe(record?.grantId);
      expect(record?.generation).toBe(2);

      const outcome = (await world.session(recordingFetch().selfFetch)) as { kind: string; value?: { kind: string } };
      expect(outcome.kind).toBe("ok");
      expect(outcome.value?.kind).toBe("ok");
    } finally {
      await restore();
      await world.cleanup();
    }
  });

  it("two sessions through the object's queue: the second refresh starts only after the first answered", async () => {
    const world = await setUp("lifecycle two sessions");
    try {
      await world.signIn();
      const events: string[] = [];
      const returned: string[] = [];
      const result = await runInDurableObject(objectOf(world.userId), async (instance: UserAgent, state) => {
        let refreshes = 0;
        const selfFetch = async (request: Request): Promise<Response> => {
          const seen = await describeRequest(request);
          if (seen.grantType !== "refresh_token") return entryEnv().SELF.fetch(request);
          refreshes += 1;
          const n = refreshes;
          events.push(`start ${n}`);
          // Give a second caller every chance to start while this one is out.
          await new Promise((resolve) => setTimeout(resolve, 50));
          const response = await entryEnv().SELF.fetch(request);
          const token = await refreshTokenIn(response);
          if (token !== null) returned.push(token);
          events.push(`answered ${n}`);
          return response;
        };
        const deps = depsOver(state.storage.kv, world.userId, selfFetch);
        const run = () =>
          instance.autonomyQueue.run((ticket) =>
            withAutonomySession({ ...deps, ticket }, (call) => call("account_whoami", {})),
          );
        const first = run();
        const second = run();
        return { first: await first, second: await second, stored: state.storage.kv.get<AutonomyRecord>(AUTONOMY_KEY) };
      });
      expect(result.first.kind).toBe("ok");
      expect(result.second.kind).toBe("ok");
      expect(events).toEqual(["start 1", "answered 1", "start 2", "answered 2"]);
      expect(returned).toHaveLength(2);
      const stored = result.stored as AutonomyRecord;
      expect(await unseal(entryEnv().AUTONOMY_SEAL_KEY, world.userId, stored)).toBe(returned[1]);
    } finally {
      await world.cleanup();
    }
  });

  /**
   * Run one session below the queue, held at its refresh, and do `meanwhile`
   * to the object's storage while it is held. Answers the outcome, what the
   * seam saw, and the record afterwards.
   */
  async function heldSession(
    userId: string,
    meanwhile: (storage: AutonomyStorage) => void,
  ): Promise<{ outcome: unknown; seen: Seen[]; after: unknown }> {
    return runInDurableObject(objectOf(userId), async (_i, state) => {
      const seen: Seen[] = [];
      const reached = gate();
      const release = gate();
      const selfFetch = async (request: Request): Promise<Response> => {
        const described = await describeRequest(request);
        seen.push(described);
        if (described.grantType === "refresh_token") {
          reached.open();
          await release.promise;
        }
        return entryEnv().SELF.fetch(request);
      };
      const pending = sessionInQueue(depsOver(state.storage.kv, userId, selfFetch), (call) =>
        call("account_whoami", {}),
      );
      await reached.promise;
      meanwhile(state.storage.kv);
      release.open();
      const outcome = await pending;
      return { outcome, seen, after: state.storage.kv.get(AUTONOMY_KEY) };
    });
  }

  it("a record replaced by a higher generation while the refresh waited is left alone, and the fresh token is revoked", async () => {
    const world = await setUp("lifecycle replaced while waiting");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      const sealed = await seal(entryEnv().AUTONOMY_SEAL_KEY, world.userId, `${world.userId}:replaced:not-a-real-token`);
      const replacement: AutonomyRecord = {
        v: 1,
        grantId: "replaced",
        sealedRefreshToken: sealed?.sealedRefreshToken as string,
        iv: sealed?.iv as string,
        armedAt: Math.floor(Date.now() / 1000),
        generation: record.generation + 1,
      };
      const result = await heldSession(world.userId, (storage) => {
        storage.put(AUTONOMY_KEY, replacement);
      });
      expect(result.outcome).toEqual({ kind: "off" });
      expect(JSON.stringify(result.after)).toBe(JSON.stringify(replacement));
      expect(result.seen).toEqual([
        { path: "/oauth/token", grantType: "refresh_token", revokes: false },
        { path: "/oauth/token", grantType: null, revokes: true },
      ]);
      expect(await autonomyGrantIds(world.userId)).not.toContain(record.grantId);
    } finally {
      await world.cleanup();
    }
  });

  it("a record deleted while the refresh waited stays deleted, and the fresh token is revoked", async () => {
    const world = await setUp("lifecycle deleted while waiting");
    try {
      await world.signIn();
      const record = (await storedRecord(world.userId)) as AutonomyRecord;
      const result = await heldSession(world.userId, (storage) => {
        storage.delete(AUTONOMY_KEY);
      });
      expect(result.outcome).toEqual({ kind: "off" });
      expect(result.after).toBeUndefined();
      expect(result.seen).toEqual([
        { path: "/oauth/token", grantType: "refresh_token", revokes: false },
        { path: "/oauth/token", grantType: null, revokes: true },
      ]);
      expect(await autonomyGrantIds(world.userId)).not.toContain(record.grantId);
    } finally {
      await world.cleanup();
    }
  });

  it("a session with no interference changes only the sealed token and the IV", async () => {
    const world = await setUp("lifecycle no interference");
    try {
      await world.signIn();
      const before = (await storedRecord(world.userId)) as AutonomyRecord;
      const outcome = (await world.session(recordingFetch().selfFetch)) as { kind: string };
      expect(outcome.kind).toBe("ok");
      const after = (await storedRecord(world.userId)) as AutonomyRecord;
      expect(after.sealedRefreshToken).not.toBe(before.sealedRefreshToken);
      expect(after.iv).not.toBe(before.iv);
      expect({ ...after, sealedRefreshToken: "", iv: "" }).toEqual({ ...before, sealedRefreshToken: "", iv: "" });
    } finally {
      await world.cleanup();
    }
  });

  it("a stub reaches armAutonomy and nothing else autonomy holds: the seam and the queue are refused", async () => {
    // Workers RPC serves only what is on the class's prototype. The seam, the
    // queue and the pending list are instance properties, so they are not.
    for (const member of ["autonomySelfFetch", "autonomyQueue", "pendingArmGrants"]) {
      expect(Object.getOwnPropertyNames(UserAgentClass.prototype)).not.toContain(member);
    }
    expect(Object.getOwnPropertyNames(UserAgentClass.prototype)).toContain("armAutonomy");

    // And through a real stub: reading any of the three is refused, while
    // armAutonomy answers. Awaiting the property is the one read of it.
    const stub = entryEnv().USER_AGENT.getByName(freshUserId()) as unknown as Record<string, unknown>;
    for (const member of ["autonomySelfFetch", "autonomyQueue", "pendingArmGrants"]) {
      await expect(Promise.resolve().then(async () => await stub[member])).rejects.toThrow(
        /does not implement/,
      );
    }
    expect(await (stub.armAutonomy as (code: unknown) => Promise<unknown>)(42)).toEqual({ kind: "not_armed" });
  });

  it("an arm whose queue rejects: the same 302, and the handler revokes the grant it minted", async () => {
    const world = await setUp("lifecycle rejected arm");
    let original: AutonomyQueue | null = null;
    await runInDurableObject(objectOf(world.userId), (instance: UserAgent) => {
      original = instance.autonomyQueue;
      instance.autonomyQueue = {
        run: () => Promise.reject(new Error("the queue refused")),
      };
    });
    try {
      const result = await world.signIn();
      expectOrdinaryAnswer(result, world.userId);
      expect(await autonomyGrantIds(world.userId)).toEqual([]);
      expect(await storedRecord(world.userId)).toBeUndefined();
    } finally {
      await runInDurableObject(objectOf(world.userId), (instance: UserAgent) => {
        if (original !== null) instance.autonomyQueue = original;
      });
      await world.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Task 3: the notice field is a condition of arming.

describe("autonomy credential: nobody is armed from a page that did not show the notice (D-30)", () => {
  /** A sign-in POST whose notice field is `field`, or absent when null. */
  function postWithField(query: string, field: string | null): Request {
    const form: Record<string, string> = {
      apple_id: LISTED_APPLE_ID,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
    };
    if (field !== null) form[AUTONOMY_NOTICE_FIELD] = field;
    return new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": freshSource(),
      },
      body: new URLSearchParams(form).toString(),
    });
  }

  for (const [label, field, armed] of [
    ["carried no field", null, 0],
    ["carried a different value", "0", 0],
    ["carried an empty value", "", 0],
    ["carried the field", AUTONOMY_NOTICE_VERSION, 1],
  ] as const) {
    it(`a POST that ${label} answers the same 302 and mints ${armed} autonomy grant(s)`, async () => {
      const world = await setUp(`lifecycle notice field ${label}`);
      try {
        const query = authorizeQuery(world.clientId, CLAUDE_WEB_REDIRECT, "notice-field");
        const ctx = createExecutionContext();
        const answer = await worker.fetch(postWithField(query, field), world.env, ctx);
        await waitOnExecutionContext(ctx);
        expectOrdinaryAnswer(
          { status: answer.status, location: answer.headers.get("location") ?? "" },
          world.userId,
        );
        expect(await autonomyGrantIds(world.userId)).toHaveLength(armed);
        expect((await storedRecord(world.userId)) !== undefined).toBe(armed === 1);
      } finally {
        await world.cleanup();
      }
    });
  }
});
