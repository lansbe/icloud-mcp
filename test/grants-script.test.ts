// The owner's grants script, against real grants (LIFE-05).
//
// **What this file proves that its neighbours do not.** Every other suite in
// this phase drives the Worker. This one drives the OWNER's tool: the pure core
// of `scripts/grants.mjs`, imported into the pool so it runs against the real
// provider, the real store, and the real `userIdOf` and `maskAppleId`. The
// script is the only way a lost laptop or a rotated password gets cut off now
// that logins never expire, so the thing worth proving is not that it prints
// something — it is that it prints the RIGHT things, prints nothing dangerous,
// and cannot delete anything it has not shown you first.
//
// Three groups:
//
//   Listing. A grant minted through the real sign-in flow is grouped under the
//   MASKED address, carries `never` for its expiry, and says whether its client
//   record still exists. The full address never appears, and neither does the
//   stored record's ciphertext — read straight from the store so the assertion
//   is against the real bytes rather than against a guess at them.
//
//   Revoking. Nothing goes without `--yes`. With it, the grant and every one of
//   its tokens are gone, the access token it issued is refused at `/mcp`, and a
//   sibling grant is untouched. An unknown id, an ambiguous prefix, and a
//   missing target each refuse everything.
//
//   The store adapter. Every argument array carries the binding and the remote
//   flag and never a namespace id. Pitfall 5: without the remote flag wrangler
//   reads the local simulator, lists nothing, and looks exactly like "no
//   grants" — the trap `11-RUNBOOK.md` already records against a hand-typed
//   command.
//
// ---------------------------------------------------------------------------
// **Hygiene, copied from test/grant-lifetime.test.ts. Do not undo it.**
//
// 1. EVERY sign-in runs against a SPREAD COPY of `entryEnv()` whose two limiter
//    bindings are allow-all stubs. The pool's real binding refuses a fourth
//    sign-in per address per minute and nothing clears its windows between
//    files or runs.
//
// 2. NEVER write onto the shared environment object. The `env-assignment` scan
//    rule refuses it, and the object is shared by every test in the file.
//
// 3. Assert only on the grant ids and the labels THIS case produced, never on
//    a total. Sibling files read and write the same namespaces at the same
//    time, so `listGrants` here sees their grants too.
//
// 4. CLEAN UP in a `finally`: every grant, every token under it, every client
//    record registered, and every record written by hand — the `grant:owner:`
//    ones included.
//
// **No real Apple ID is ever authenticated (D-09).** Sign-ins go through
// `test/fixtures/worker-with-login-proof.ts`, whose proof is a counter, under
// the reserved `.invalid` domain, with a plainly fake password.
// ---------------------------------------------------------------------------

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  AUTONOMY_CLIENT_ID,
  AUTONOMY_CLIENT_NAME,
  AUTONOMY_REDIRECT_PATH,
} from "../src/agent/autonomy-client";
import type { Env } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { maskAppleId, userIdOf } from "../src/principal";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import {
  AUTONOMY_SECRET_NAMES,
  NOTHING_PRUNED,
  NOTHING_REVOKED,
  REPLACE_ENDS_KEYS,
  USAGE,
  createWranglerKv,
  createWranglerSecrets,
  installAutonomyClientRecord,
  listGrants,
  orphanClientIds,
  prunedSummary,
  renderGrants,
  runGrants,
} from "../scripts/grants-core.mjs";
import type {
  AutonomySetupDeps,
  GrantDeps,
  GrantGroup,
  GrantStore,
} from "../scripts/grants-core.mjs";
import { oauthProviderOptions } from "../src/auth/oauth";
import { entryEnv } from "./fixtures/bound-secrets";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;
const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** The PKCE pair `test/grant-lifetime.test.ts` computed. Copied, not re-derived. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

/** The pool's store, typed as the core's three-method slice. */
function store(): GrantStore {
  return entryEnv().OAUTH_KV as unknown as GrantStore;
}

/** Hygiene rule 1: a limiter binding that always lets the request through. */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** Hygiene rule 2: the pool's environment with both limiters replaced, as a COPY. */
function allowAllEnv(): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
  } as unknown as Env;
}

/** Drive the fixture Worker through its real fetch, on a real execution context. */
async function callWorker(request: Request, env: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Register a real public client through the real registration endpoint. */
async function register(
  env: Env,
  clientName: string,
  redirectUri = CLAUDE_WEB_REDIRECT,
): Promise<string> {
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
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

/** A source key this invocation owns, so no case spends another's window. */
function freshSource(): string {
  return `test-source-${crypto.randomUUID()}`;
}

/** Sign the listed address in, and hand back the authorization code. */
async function signIn(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string,
): Promise<string> {
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    state,
  }).toString();

  const response = await callWorker(
    new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": freshSource(),
      },
      body: new URLSearchParams({
        apple_id: LISTED_APPLE_ID,
        app_password: FAKE_APP_PASSWORD,
        oauth_request: query,
      }).toString(),
    }),
    env,
  );

  expect(response.status).toBe(302);
  const location = response.headers.get("location");
  expect(location).not.toBeNull();
  const code = new URL(location as string).searchParams.get("code");
  expect(code).not.toBeNull();
  return code as string;
}

/** Redeem an authorization code at the real token endpoint. */
async function exchangeCode(
  env: Env,
  clientId: string,
  redirectUri: string,
  code: string,
): Promise<{ accessToken: string; refreshToken: string }> {
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
  const body = JSON.parse(text) as {
    access_token: string;
    refresh_token: string;
  };
  return { accessToken: body.access_token, refreshToken: body.refresh_token };
}

/** Both token kinds are `userId:grantId:secret`, so the middle segment is the grant. */
function grantIdOf(token: string): string {
  const segments = token.split(":");
  expect(segments).toHaveLength(3);
  return segments[1] as string;
}

/** Mint one real grant: register, sign in, exchange. */
async function mintGrant(
  env: Env,
  clientName: string,
  state: string,
): Promise<{ clientId: string; grantId: string; accessToken: string }> {
  const clientId = await register(env, clientName);
  const code = await signIn(env, clientId, CLAUDE_WEB_REDIRECT, state);
  const { accessToken } = await exchangeCode(
    env,
    clientId,
    CLAUDE_WEB_REDIRECT,
    code,
  );
  return { clientId, grantId: grantIdOf(accessToken), accessToken };
}

/** Every key under a prefix, read through the pool's own binding. */
async function keysUnder(prefix: string): Promise<string[]> {
  const listed = await entryEnv().OAUTH_KV.list({ prefix });
  return listed.keys.map((key) => key.name);
}

/** Hygiene rule 4: delete a grant and every access token under it. Serial. */
async function forgetGrant(userKey: string, grantId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const name of await keysUnder(`token:${userKey}:${grantId}:`)) {
    await kv.delete(name);
  }
  await kv.delete(`grant:${userKey}:${grantId}`);
}

/** Hygiene rule 4: delete a client record this file registered. */
async function forgetClient(clientId: string): Promise<void> {
  await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
}

/** The listed address's user id, from the real function. Never hashed here. */
async function listedUserId(): Promise<string> {
  const userId = await userIdOf(LISTED_APPLE_ID);
  expect(userId).not.toBeNull();
  return userId as string;
}

/**
 * Write one grant record by hand, in the library's own summary shape.
 *
 * Used for the two groups a sign-in cannot produce: the legacy `owner` segment,
 * which the door has refused since Phase 11, and an unlabelled 64-hex segment.
 * Both are deleted in the same `finally` as everything else.
 */
async function writeGrantByHand(
  userKey: string,
  grantId: string,
  fields: { clientId: string; clientName: string; createdAt: number },
): Promise<void> {
  await entryEnv().OAUTH_KV.put(
    `grant:${userKey}:${grantId}`,
    JSON.stringify({
      id: grantId,
      clientId: fields.clientId,
      userId: userKey,
      scope: ["mcp"],
      metadata: { clientName: fields.clientName },
      encryptedProps: "not-real-ciphertext-written-by-a-test",
      createdAt: fields.createdAt,
    }),
  );
}

/** A well-formed 2026-07-28 `tools/list` carrying a bearer token. */
function toolsList(accessToken: string): Request {
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: DEPLOYED_HOSTNAME,
      "Mcp-Method": "tools/list",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/** The status the door answers an access token with. */
async function doorStatus(env: Env, accessToken: string): Promise<number> {
  const response = await callWorker(toolsList(accessToken), env);
  return response.status;
}

/** A sink that records everything written, plus the text so far. */
function sink(): { write(text: string): void; text(): string } {
  const chunks: string[] = [];
  return {
    write(text: string) {
      chunks.push(text);
    },
    text() {
      return chunks.join("");
    },
  };
}

/** Deps over the pool's real store, with a fixed known-address list. */
function depsOver(
  addresses: readonly string[],
  out: { write(text: string): void },
): GrantDeps {
  return {
    kv: store(),
    async knownAddresses() {
      return addresses;
    },
    write: out.write,
    writeError: out.write,
  };
}

/**
 * Deps whose store and address function both refuse to be used.
 *
 * The point is what does NOT happen. A usage error must be refused during
 * argument parsing, which in the owner's terminal means before any wrangler
 * call — so these record a call rather than serving one.
 */
function refusingDeps(
  calls: string[],
  out: { write(text: string): void },
): GrantDeps {
  const kv: GrantStore = {
    async list() {
      calls.push("list");
      return { keys: [], list_complete: true };
    },
    async get() {
      calls.push("get");
      return null;
    },
    async delete() {
      calls.push("delete");
    },
  };
  return {
    kv,
    async knownAddresses() {
      calls.push("knownAddresses");
      return [];
    },
    write: out.write,
    writeError: out.write,
  };
}

/**
 * A store this case OWNS, so a delete cannot reach a sibling file's records.
 *
 * Hygiene rule 3 forbids asserting on a total against the pool's shared store,
 * and `prune-clients --yes` makes that rule sharper than it is anywhere else in
 * this file: the command's target set is "every client record no grant names",
 * which against the shared store is every record every OTHER suite registered
 * and has not yet cleaned up. So the prune runs here and nowhere else.
 *
 * Values are stored as parsed objects, which the library's `get` accepts for
 * every `type` it asks for.
 */
function ownStore(records: Record<string, unknown>): GrantStore {
  const data = new Map(Object.entries(records));
  return {
    async list(options?: { prefix?: string }) {
      const prefix = options?.prefix ?? "";
      return {
        keys: [...data.keys()]
          .filter((name) => name.startsWith(prefix))
          .sort()
          .map((name) => ({ name })),
        list_complete: true,
      };
    },
    async get(name: string) {
      return data.has(name) ? data.get(name) : null;
    },
    async delete(name: string) {
      data.delete(name);
    },
  };
}

/**
 * A store this case owns that CHANGES between the prune's two views.
 *
 * WHY THIS EXISTS (code review WR-03). `prune-clients --yes` reads both prefixes
 * a SECOND time and deletes only the ids orphaned in both views. That one branch
 * is the whole of its race protection — it is what stands between a delete and
 * signing somebody out — and against `ownStore` it cannot fail: a deterministic
 * store answers both reads identically, so `orphans.filter(stillOrphan.has)` is
 * always exactly `orphans` and the second read is computable but unobservable.
 * Deleting the entire second read left every test in the suite green.
 *
 * `shift` runs once, at the START of the second `client:` listing, which is the
 * first read of the fresh view. Hooking it there rather than on a grant listing
 * is deliberate: the fresh view reads the clients first and the grants second, so
 * a change applied here is seen by BOTH halves of that view, which is what a real
 * sign-in completing in that window would look like.
 */
function shiftingStore(
  records: Record<string, unknown>,
  shift: (data: Map<string, unknown>) => void,
): GrantStore {
  const data = new Map(Object.entries(records));
  let clientListings = 0;
  return {
    async list(options?: { prefix?: string }) {
      const prefix = options?.prefix ?? "";
      if (prefix === "client:") {
        clientListings += 1;
        if (clientListings === 2) shift(data);
      }
      return {
        keys: [...data.keys()]
          .filter((name) => name.startsWith(prefix))
          .sort()
          .map((name) => ({ name })),
        list_complete: true,
      };
    },
    async get(name: string) {
      return data.has(name) ? data.get(name) : null;
    },
    async delete(name: string) {
      data.delete(name);
    },
  };
}

/** Every key in a store this case owns, read through the store's own list. */
async function namesIn(kv: GrantStore): Promise<string[]> {
  return (await kv.list({})).keys.map((key) => key.name);
}

/** A grant record in the library's own summary shape, for a store we own. */
function grantRecord(
  userKey: string,
  grantId: string,
  clientId: string,
): Record<string, unknown> {
  return {
    id: grantId,
    clientId,
    userId: userKey,
    scope: ["mcp"],
    metadata: { clientName: "a client" },
    encryptedProps: "not-real-ciphertext-written-by-a-test",
    createdAt: 1_780_000_000,
  };
}

/** The group holding one user segment, or undefined. */
function groupFor(
  groups: readonly GrantGroup[],
  userKey: string,
): GrantGroup | undefined {
  return groups.find((group) => group.userKey === userKey);
}

describe("LIFE-05: the owner lists grants by masked address and revokes them", () => {
  // Titled so `-t "LIFE-05"` matches. A name filter that matches nothing passes
  // SILENTLY, which would leave the requirement looking covered while measuring
  // nothing, so 12-VALIDATION.md's command and this title move together.

  it("groups a real grant under the masked address, with never and client present", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let minted: { clientId: string; grantId: string } | null = null;

    try {
      minted = await mintGrant(env, "LIFE-05 listing client", "life-05-list");

      const groups = await listGrants(store(), [LISTED_APPLE_ID]);
      const group = groupFor(groups, userKey);
      expect(group).toBeDefined();
      expect(group?.kind).toBe("address");

      // The label comes from the ONE masking rule, compared against that
      // function's own output rather than against a second copy of the form.
      expect(group?.label).toBe(maskAppleId(LISTED_APPLE_ID));
      expect(group?.label).toBe("l\u2022\u2022\u2022@example.invalid");

      // Hygiene rule 3: found by the id THIS case minted, never by a total.
      const row = group?.grants.find((grant) => grant.id === minted?.grantId);
      expect(row).toBeDefined();
      expect(row?.clientName).toBe("LIFE-05 listing client");
      expect(row?.expires).toBe("never");
      expect(row?.clientPresent).toBe(true);
      // An ISO day, not a raw epoch count. Asserted as a shape because the day
      // itself is whatever day the suite runs on.
      expect(row?.created).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      const text = renderGrants(groups);
      expect(text).toContain("l\u2022\u2022\u2022@example.invalid");
      expect(text).toContain(minted.grantId);
      expect(text).toContain("LIFE-05 listing client");
      expect(text).toContain("expires never");
      expect(text).toContain("client present");
    } finally {
      if (minted !== null) {
        await forgetGrant(userKey, minted.grantId);
        await forgetClient(minted.clientId);
      }
    }
  });

  it("prints neither the full address nor the stored record's ciphertext", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let minted: { clientId: string; grantId: string } | null = null;

    try {
      minted = await mintGrant(env, "LIFE-05 containment client", "life-05-safe");

      // Read the REAL record, so the assertion below is against the bytes the
      // provider actually wrote rather than against a guess at their shape.
      const stored = (await entryEnv().OAUTH_KV.get(
        `grant:${userKey}:${minted.grantId}`,
        { type: "json" },
      )) as { encryptedProps?: unknown } | null;
      expect(stored).not.toBeNull();
      const ciphertext = stored?.encryptedProps;
      // Non-vacuity: `not.toContain("")` is true of every string.
      expect(typeof ciphertext).toBe("string");
      expect((ciphertext as string).length).toBeGreaterThan(0);

      const text = renderGrants(await listGrants(store(), [LISTED_APPLE_ID]));
      expect(text).not.toContain(LISTED_APPLE_ID);
      expect(text).not.toContain(ciphertext as string);
      // The masked form is present, which is what makes the absence above mean
      // "masked" rather than "this group was never listed".
      expect(text).toContain(maskAppleId(LISTED_APPLE_ID));
    } finally {
      if (minted !== null) {
        await forgetGrant(userKey, minted.grantId);
        await forgetClient(minted.clientId);
      }
    }
  });

  it("labels the legacy owner segment and an unmatched id, and says client gone", async () => {
    const legacyId = `legacy-${crypto.randomUUID().replaceAll("-", "")}`;
    const strangerKey = Array.from({ length: 64 }, () => "b").join("");
    const strangerId = `stray-${crypto.randomUUID().replaceAll("-", "")}`;

    try {
      // Written by hand because the door has refused the `owner` segment since
      // Phase 11, so no sign-in this suite can perform produces one.
      await writeGrantByHand("owner", legacyId, {
        clientId: "a-client-record-that-is-not-there",
        clientName: "Claude",
        createdAt: 1_755_000_000,
      });
      await writeGrantByHand(strangerKey, strangerId, {
        clientId: "another-absent-client-record",
        clientName: "Claude Code",
        createdAt: 1_755_000_000,
      });

      const groups = await listGrants(store(), [LISTED_APPLE_ID]);

      const legacy = groupFor(groups, "owner");
      expect(legacy?.kind).toBe("legacy");
      expect(legacy?.label).toBe("legacy v1.0 owner grants");
      expect(legacy?.grants.map((grant) => grant.id)).toContain(legacyId);

      const stranger = groupFor(groups, strangerKey);
      expect(stranger?.kind).toBe("unknown");
      // Only the first eight characters of an id nobody could label. The whole
      // 64 would be a stable handle on a person this server cannot name.
      expect(stranger?.label).toBe("unknown (id bbbbbbbb\u2026)");
      expect(stranger?.label).not.toContain(strangerKey);

      // Both records name a client that does not exist, which is spike S2's
      // failure: that grant is already dead at its next refresh.
      const strangerRow = stranger?.grants.find(
        (grant) => grant.id === strangerId,
      );
      expect(strangerRow?.clientPresent).toBe(false);
      expect(renderGrants(groups)).toContain("client gone");
    } finally {
      await forgetGrant("owner", legacyId);
      await forgetGrant(strangerKey, strangerId);
    }
  });

  it("neutralises control characters in a client name and cuts it to 60", async () => {
    const hostileKey = Array.from({ length: 64 }, () => "c").join("");
    const hostileId = `hostile-${crypto.randomUUID().replaceAll("-", "")}`;
    // A client name is chosen by whoever registered. An escape sequence printed
    // raw drives the owner's terminal, so it is neutralised rather than trusted.
    const hostileName = `\u001b[2JClaude\nCode\u009b6n${"x".repeat(120)}`;

    try {
      await writeGrantByHand(hostileKey, hostileId, {
        clientId: "an-absent-client-record",
        clientName: hostileName,
        createdAt: 1_755_000_000,
      });

      const groups = await listGrants(store(), []);
      const row = groupFor(groups, hostileKey)?.grants.find(
        (grant) => grant.id === hostileId,
      );
      expect(row?.clientName).toBe(hostileName);

      const text = renderGrants(groups);
      expect(text).not.toContain("\u001b");
      expect(text).not.toContain("\u009b");
      // The line break is gone too: one grant is one line, and a name that
      // could add lines could forge a whole row.
      expect(text).toContain("?[2JClaude?Code?6n");

      const rendered = text
        .split("\n")
        .find((line) => line.includes(hostileId));
      expect(rendered).toBeDefined();
      const quoted = /client "([^"]*)"/.exec(rendered as string);
      expect(quoted).not.toBeNull();
      expect((quoted as RegExpExecArray)[1]?.length).toBeLessThanOrEqual(60);
    } finally {
      await forgetGrant(hostileKey, hostileId);
    }
  });

  it("neutralises bidi controls, and cuts on a code-point boundary", async () => {
    // WR-02. A trailing right-to-left override REVERSES the display order of
    // everything after it on the row — and the client name is printed one column
    // to the LEFT of the grant id the owner is about to type into a revoke, with
    // `created`, `expires` and the client marker after it. The file's own rule 2
    // says an escape printed raw "would drive the owner's terminal"; the same
    // argument reaches these, and they are not in the C0/C1 blocks the original
    // replacement set covered.
    //
    // IN-02 rides along: the cut counts CODE POINTS now, so a surrogate pair is
    // kept or dropped whole rather than being sliced into a lone surrogate.
    const hostileKey = Array.from({ length: 64 }, () => "d").join("");
    const hostileId = `bidi-${crypto.randomUUID().replaceAll("-", "")}`;
    const hostileName =
      "Claude‮Code⁦x⁩y​z w﻿q⁠r";

    try {
      await writeGrantByHand(hostileKey, hostileId, {
        clientId: "an-absent-client-record",
        clientName: hostileName,
        createdAt: 1_755_000_000,
      });

      const groups = await listGrants(store(), []);
      const text = renderGrants(groups);

      // Every one of them, named individually: a range typed one character short
      // leaves exactly one of these in and nothing else fails.
      for (const control of [
        "‪",
        "‫",
        "‬",
        "‭",
        "‮",
        "⁦",
        "⁧",
        "⁨",
        "⁩",
        "​",
        "‌",
        "‍",
        "‎",
        "‏",
        " ",
        " ",
        "⁠",
        "﻿",
      ]) {
        expect(
          text,
          `U+${control.codePointAt(0)?.toString(16)} reached the terminal`,
        ).not.toContain(control);
      }
      expect(text).toContain("Claude?Code?x?y?z?w?q?r");

      // The ellipsis the renderer appends to a cut id is NOT in the replaced
      // set, and it sits one code point below the first banned range — so this
      // also pins that the range does not start one character too low.
      expect(text).toContain("…");
    } finally {
      await forgetGrant(hostileKey, hostileId);
    }
  });

  it("neutralises the Arabic letter mark and the deprecated format controls", async () => {
    // IN-02, iteration 2. The first pass covered C0, C1, the U+200B–200F marks,
    // U+2028–202E, U+2060–2069 and the byte-order mark, and missed two things:
    // U+061C ARABIC LETTER MARK, a bidi control of the same family as the marks
    // it did cover but nowhere near them in the code space, and U+206A–206F, the
    // deprecated Unicode format controls.
    //
    // Written as ESCAPES rather than as literal characters, unlike the case
    // above: these are invisible by definition, so a literal in the source is a
    // value nobody can proof-read and a diff nobody can review.
    const deprecated = [
      "\u206a",
      "\u206b",
      "\u206c",
      "\u206d",
      "\u206e",
      "\u206f",
    ];
    const hostileKey = Array.from({ length: 64 }, () => "f").join("");
    const hostileId = `marks-${crypto.randomUUID().replaceAll("-", "")}`;
    // U+2070 SUPERSCRIPT ZERO rides along on the end: it is the code point one
    // above the new range and an ordinary visible character, so it pins that the
    // range was not typed one too wide at the top.
    const hostileName = `A\u061cB${deprecated.join("")}C\u2070D`;

    try {
      await writeGrantByHand(hostileKey, hostileId, {
        clientId: "an-absent-client-record",
        clientName: hostileName,
        createdAt: 1_755_000_000,
      });

      const text = renderGrants(await listGrants(store(), []));

      // Each one named individually, so a range typed one short leaves exactly
      // one of them in and a case still goes red.
      for (const control of ["\u061c", ...deprecated]) {
        expect(
          text,
          `U+${control.codePointAt(0)?.toString(16).toUpperCase()} reached the terminal`,
        ).not.toContain(control);
      }
      // The visible neighbour one code point above the range SURVIVES, which is
      // what stops the range being widened at the top. Asserted as part of the
      // whole rendered name, so the two facts cannot drift apart.
      expect(text).toContain("A?B??????C\u2070D");
    } finally {
      await forgetGrant(hostileKey, hostileId);
    }
  });

  it("cuts a surrogate pair whole rather than in half", async () => {
    // IN-02. The loop used to index UTF-16 code units and stop at a length in
    // code units, so a cut landing between a high and a low surrogate emitted a
    // lone surrogate — which renders as a replacement character and means `max`
    // did not mean what it says.
    const hostileKey = Array.from({ length: 64 }, () => "e").join("");
    const hostileId = `pair-${crypto.randomUUID().replaceAll("-", "")}`;
    // One BMP character then 40 astral ones: 81 code units, 41 code points. The
    // odd leading character is what made the old loop's 60-code-unit cut land
    // BETWEEN a high and a low surrogate rather than on a pair boundary.
    const hostileName = `x${"\u{1f600}".repeat(40)}`;

    try {
      await writeGrantByHand(hostileKey, hostileId, {
        clientId: "an-absent-client-record",
        clientName: hostileName,
        createdAt: 1_755_000_000,
      });

      const text = renderGrants(await listGrants(store(), []));
      const rendered = text.split("\n").find((line) => line.includes(hostileId));
      expect(rendered).toBeDefined();
      const quoted = /client "([^"]*)"/.exec(rendered as string);
      expect(quoted).not.toBeNull();
      const name = (quoted as RegExpExecArray)[1] as string;

      // No UNPAIRED surrogate anywhere in it: a high one with no low one after,
      // or a low one with no high one before. A paired one is a perfectly ordinary
      // astral character and must not be reported.
      const lone =
        /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
      expect(lone.test(name), "a lone surrogate reached the terminal").toBe(false);

      // All 41 fit, because the cut now counts characters rather than code units.
      expect([...name]).toHaveLength(41);
      expect(name).toBe(hostileName);
    } finally {
      await forgetGrant(hostileKey, hostileId);
    }
  });

  it("revoke without --yes prints the target, says so, and deletes nothing", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let minted: { clientId: string; grantId: string } | null = null;

    try {
      minted = await mintGrant(env, "LIFE-05 dry-run client", "life-05-dry");
      const before = await keysUnder(`grant:${userKey}:${minted.grantId}`);
      const tokensBefore = await keysUnder(
        `token:${userKey}:${minted.grantId}:`,
      );
      expect(before).toHaveLength(1);
      expect(tokensBefore.length).toBeGreaterThan(0);

      const out = sink();
      const code = await runGrants(
        ["revoke", minted.grantId],
        depsOver([LISTED_APPLE_ID], out),
      );

      expect(code).toBe(0);
      // The target is shown FIRST. A revoke that acted before printing would
      // pass a "nothing was deleted" check and still be the wrong shape.
      expect(out.text()).toContain(minted.grantId);
      expect(out.text()).toContain("LIFE-05 dry-run client");
      // Plan 12-05 greps for this sentence, so it is compared against the
      // export rather than against a second copy of the words.
      expect(out.text()).toContain(NOTHING_REVOKED);
      expect(NOTHING_REVOKED).toBe(
        "Nothing was revoked. Re-run with --yes to revoke the grants listed above.",
      );

      expect(await keysUnder(`grant:${userKey}:${minted.grantId}`)).toEqual(
        before,
      );
      expect(await keysUnder(`token:${userKey}:${minted.grantId}:`)).toEqual(
        tokensBefore,
      );
    } finally {
      if (minted !== null) {
        await forgetGrant(userKey, minted.grantId);
        await forgetClient(minted.clientId);
      }
    }
  });

  it("revoke --yes removes the grant and its tokens, and the door refuses that token", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let cut: { clientId: string; grantId: string; accessToken: string } | null =
      null;
    let kept: { clientId: string; grantId: string; accessToken: string } | null =
      null;

    try {
      cut = await mintGrant(env, "LIFE-05 revoked app", "life-05-cut");
      kept = await mintGrant(env, "LIFE-05 surviving app", "life-05-kept");
      expect(cut.grantId).not.toBe(kept.grantId);

      // The positive control, taken BEFORE the revoke: both tokens are served,
      // so the 401 below cannot be explained by the door refusing either one
      // for some other reason.
      expect(await doorStatus(env, cut.accessToken)).toBe(200);
      expect(await doorStatus(env, kept.accessToken)).toBe(200);

      const out = sink();
      const code = await runGrants(
        ["revoke", cut.grantId, "--yes"],
        depsOver([LISTED_APPLE_ID], out),
      );
      expect(`${code} ${out.text()}`).toBe(`0 ${out.text()}`);

      expect(await keysUnder(`grant:${userKey}:${cut.grantId}`)).toEqual([]);
      // The tokens go too, and this is the half that matters: the door checks
      // an access token against its own `token:` record, which carries its own
      // copy of the grant and never reads the `grant:` key. Deleting only the
      // grant leaves the token working for up to an hour.
      expect(await keysUnder(`token:${userKey}:${cut.grantId}:`)).toEqual([]);

      expect(await keysUnder(`grant:${userKey}:${kept.grantId}`)).toHaveLength(
        1,
      );
      expect(
        (await keysUnder(`token:${userKey}:${kept.grantId}:`)).length,
      ).toBeGreaterThan(0);

      expect(await doorStatus(env, cut.accessToken)).toBe(401);
      expect(await doorStatus(env, kept.accessToken)).toBe(200);
    } finally {
      if (cut !== null) {
        await forgetGrant(userKey, cut.grantId);
        await forgetClient(cut.clientId);
      }
      if (kept !== null) {
        await forgetGrant(userKey, kept.grantId);
        await forgetClient(kept.clientId);
      }
    }
  });

  it("revoke --address targets every grant under that address", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let first: { clientId: string; grantId: string } | null = null;
    let second: { clientId: string; grantId: string } | null = null;

    try {
      first = await mintGrant(env, "LIFE-05 address app one", "life-05-addr-1");
      second = await mintGrant(env, "LIFE-05 address app two", "life-05-addr-2");

      const out = sink();
      const code = await runGrants(
        ["revoke", "--address", LISTED_APPLE_ID],
        depsOver([LISTED_APPLE_ID], out),
      );

      expect(code).toBe(0);
      expect(out.text()).toContain(first.grantId);
      expect(out.text()).toContain(second.grantId);
      expect(out.text()).toContain(NOTHING_REVOKED);
      // The address a person typed is never echoed back, only its masked form.
      expect(out.text()).not.toContain(LISTED_APPLE_ID);
      expect(out.text()).toContain(maskAppleId(LISTED_APPLE_ID));

      // Hygiene rule 3: this asserts the two ids THIS case minted are still
      // there, not that the store holds some number of grants.
      expect(await keysUnder(`grant:${userKey}:${first.grantId}`)).toHaveLength(
        1,
      );
      expect(
        await keysUnder(`grant:${userKey}:${second.grantId}`),
      ).toHaveLength(1);
    } finally {
      if (first !== null) {
        await forgetGrant(userKey, first.grantId);
        await forgetClient(first.clientId);
      }
      if (second !== null) {
        await forgetGrant(userKey, second.grantId);
        await forgetClient(second.clientId);
      }
    }
  });

  it("revoke --legacy-owner targets every grant under the owner segment", async () => {
    const legacyA = `legacy-a-${crypto.randomUUID().replaceAll("-", "")}`;
    const legacyB = `legacy-b-${crypto.randomUUID().replaceAll("-", "")}`;

    try {
      await writeGrantByHand("owner", legacyA, {
        clientId: "gone-a",
        clientName: "Claude",
        createdAt: 1_755_000_000,
      });
      await writeGrantByHand("owner", legacyB, {
        clientId: "gone-b",
        clientName: "Claude Code",
        createdAt: 1_755_100_000,
      });

      const out = sink();
      const code = await runGrants(
        ["revoke", "--legacy-owner", "--yes"],
        depsOver([LISTED_APPLE_ID], out),
      );

      expect(`${code} ${out.text()}`).toBe(`0 ${out.text()}`);
      expect(out.text()).toContain("legacy v1.0 owner grants");
      expect(await keysUnder(`grant:owner:${legacyA}`)).toEqual([]);
      expect(await keysUnder(`grant:owner:${legacyB}`)).toEqual([]);
    } finally {
      await forgetGrant("owner", legacyA);
      await forgetGrant("owner", legacyB);
    }
  });

  it("revoke --legacy-owner names nothing and deletes nothing when the owner segment is empty", async () => {
    // **This is the command the cutover runbook runs at step 10**, and it runs
    // it expecting exactly this answer: after the owner's own grants are gone,
    // `revoke --legacy-owner` is the preview that evidences there is nothing
    // left under the legacy segment. The two cases above it are an EMPTY store
    // and a POPULATED legacy segment; neither is this one, which is a store with
    // real grants in it that simply has none under `owner`.
    //
    // A store holding one grant under a hashed user segment — the shape every
    // grant written since the login page landed has — and nothing under the
    // legacy one.
    const hashedUser = "a".repeat(64);
    const kv = ownStore({
      [`grant:${hashedUser}:g1`]: grantRecord(hashedUser, "g1", "a-client"),
      "client:a-client": { clientId: "a-client" },
    });
    const before = (await namesIn(kv)).sort();
    const out = sink();

    // With --yes, which is the sharper case: a command told to go ahead with an
    // empty target set must still delete nothing.
    const code = await runGrants(["revoke", "--legacy-owner", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("No grants match that target");
    // It named no target, so the legacy label never appears. Without this the
    // case would pass against a run that listed the hashed user's grant and
    // then declined to delete it, which is a different answer.
    expect(out.text()).not.toContain("legacy v1.0 owner grants");
    expect(out.text()).not.toContain("g1");
    expect((await namesIn(kv)).sort()).toEqual(before);
  });

  it("refuses an unknown id and an ambiguous prefix, and deletes nothing", async () => {
    // Two hand-written ids sharing an eight-character prefix. A real grant id
    // is sixteen random characters, so two that collide on eight cannot be
    // minted on demand — and the collision is the case worth pinning, because
    // a prefix match that picked the first hit would delete the wrong person's
    // connection.
    const shared = "abcdef12";
    const ambiguousA = `${shared}00000001`;
    const ambiguousB = `${shared}00000002`;

    try {
      await writeGrantByHand("owner", ambiguousA, {
        clientId: "gone-a",
        clientName: "Claude",
        createdAt: 1_755_000_000,
      });
      await writeGrantByHand("owner", ambiguousB, {
        clientId: "gone-b",
        clientName: "Claude",
        createdAt: 1_755_000_000,
      });

      const missing = sink();
      expect(
        await runGrants(
          ["revoke", "no-such-grant-id-at-all", "--yes"],
          depsOver([LISTED_APPLE_ID], missing),
        ),
      ).not.toBe(0);
      expect(missing.text()).toContain("No grant matches");

      const ambiguous = sink();
      expect(
        await runGrants(
          ["revoke", shared, "--yes"],
          depsOver([LISTED_APPLE_ID], ambiguous),
        ),
      ).not.toBe(0);
      expect(ambiguous.text()).toContain("more than one grant");

      // Neither refusal deleted either record. A refusal that deleted one of
      // the two would be worse than no prefix matching at all.
      expect(await keysUnder(`grant:owner:${ambiguousA}`)).toHaveLength(1);
      expect(await keysUnder(`grant:owner:${ambiguousB}`)).toHaveLength(1);
    } finally {
      await forgetGrant("owner", ambiguousA);
      await forgetGrant("owner", ambiguousB);
    }
  });

  it("refuses a missing target and an unknown flag without touching the store", async () => {
    for (const argv of [
      ["revoke"],
      ["revoke", "--yes"],
      ["revoke", "--address"],
      ["list", "--purge"],
      ["purge"],
    ]) {
      const calls: string[] = [];
      const out = sink();
      const code = await runGrants(argv, refusingDeps(calls, out));

      expect(`${argv.join(" ")} -> ${code}`).not.toBe(
        `${argv.join(" ")} -> 0`,
      );
      // THE POINT OF THIS CASE. Arguments are validated first, so in the
      // owner's terminal a usage error costs no wrangler call at all — and a
      // `revoke` that reached the store with no target is the one mistake this
      // script must never make quietly.
      expect(calls).toEqual([]);
      expect(out.text().length).toBeGreaterThan(0);
    }
  });

  it("takes a positional id that begins with a dash, rather than calling it a flag", async () => {
    // THE DEFECT THIS CLOSES. A grant id is base64url and that alphabet
    // contains "-", so roughly one id in sixty-four begins with one. Reading a
    // leading dash as "this is a flag" refused those ids with "Unknown flag." —
    // a message that sends the reader hunting a typo that is not there, while
    // the id they pasted off the listing was correct. The runbook revokes named
    // grants by id, so the failure landed on the exact path it documents.
    //
    // Reaching the store is the ASSERTION and not an accident: arguments are
    // validated before any store call, so a recorded call is the only evidence
    // from out here that the parser accepted the id.
    const calls: string[] = [];
    const out = sink();
    const code = await runGrants(
      ["revoke", "-bcdefgh12345678", "--yes"],
      refusingDeps(calls, out),
    );

    expect(out.text()).not.toContain("Unknown flag");
    expect(calls, "the id was refused before any store call").not.toEqual([]);
    // It is not a real grant, so this still fails — on the right grounds.
    expect(out.text()).toContain("No grant matches that id");
    expect(code).not.toBe(0);
  });

  it("takes an id spelled exactly like a known flag, after --", async () => {
    // The dash count separates a flag from an id for every case but two: an id
    // beginning with TWO dashes, and an id spelled exactly like a flag. Both
    // are legal base64url, and `--` is the only way to reach either.
    const calls: string[] = [];
    const out = sink();
    const code = await runGrants(
      ["revoke", "--yes", "--", "--legacy-owner"],
      refusingDeps(calls, out),
    );

    expect(out.text()).not.toContain("Unknown flag");
    expect(calls, "the id was refused before any store call").not.toEqual([]);
    // It was read as an ID and not as the flag: the legacy-owner path would
    // have had a target of its own and would never reach "no grant matches".
    expect(out.text()).toContain("No grant matches that id");
    expect(code).not.toBe(0);
  });

  it("still refuses a genuinely unknown flag, without touching the store", async () => {
    // The half a bare "treat anything dashed as an id" would have thrown away.
    // Every flag here is long-form, so a `--` token matching none of them is
    // still a typo and still gets the message that says so — rather than "No
    // grant matches that id", which would send the reader looking at the id.
    for (const argv of [
      ["list", "--purge"],
      ["revoke", "--bogus", "--yes"],
      ["revoke", "--addres", "someone@example.invalid", "--yes"],
    ]) {
      const calls: string[] = [];
      const out = sink();
      const code = await runGrants(argv, refusingDeps(calls, out));

      expect(code, `${argv.join(" ")} was not refused`).toBe(2);
      expect(calls, `${argv.join(" ")} reached the store`).toEqual([]);
      expect(out.text()).toContain("Unknown flag");
    }
  });

  it("--address refuses a swallowed FLAG as its value, not merely a dashed one", async () => {
    // The guard moved with the parser and the reason moved with it: it exists
    // so `--address --yes` cannot silently label a group with a flag, not to
    // refuse a dashed value. A single-dash token is not a flag in this tool,
    // so it cannot be a swallowed one — and the value only ever labels a group.
    for (const argv of [
      ["revoke", "--address"],
      ["revoke", "--address", "--yes"],
      ["revoke", "--address", "--"],
    ]) {
      const calls: string[] = [];
      const out = sink();
      const code = await runGrants(argv, refusingDeps(calls, out));

      expect(code, `${argv.join(" ")} was not refused`).toBe(2);
      expect(calls, `${argv.join(" ")} reached the store`).toEqual([]);
      expect(out.text()).toContain("--address needs an address after it");
    }

    // And the other direction, which is what keeps the guard honest: a dashed
    // value is now taken, so the refusal above is about the flag and not about
    // the dash.
    const calls: string[] = [];
    const out = sink();
    await runGrants(
      ["revoke", "--address", "-dashed@example.invalid", "--yes"],
      refusingDeps(calls, out),
    );
    expect(out.text()).not.toContain("--address needs an address after it");
    expect(calls, "a dashed address was refused before any store call").not.toEqual(
      [],
    );
  });

  it("still requires --yes after --, and --yes after -- is an id rather than the flag", async () => {
    const env = allowAllEnv();
    const userKey = await listedUserId();
    let minted: { clientId: string; grantId: string } | null = null;

    try {
      minted = await mintGrant(env, "13-04 dash-parse client", "dash-parse");
      const before = await keysUnder(`grant:${userKey}:${minted.grantId}`);
      expect(before).toHaveLength(1);

      // `--` reaches a real id, and the delete is still unarmed.
      const dry = sink();
      const dryCode = await runGrants(
        ["revoke", "--", minted.grantId],
        depsOver([LISTED_APPLE_ID], dry),
      );
      expect(dryCode).toBe(0);
      expect(dry.text()).toContain(minted.grantId);
      expect(dry.text()).toContain(NOTHING_REVOKED);
      expect(await keysUnder(`grant:${userKey}:${minted.grantId}`)).toEqual(
        before,
      );

      // And `--yes` written AFTER `--` is an id, not the flag — so it cannot be
      // the accidental way past the gate that `--` would otherwise open.
      const after = sink();
      const afterCode = await runGrants(
        ["revoke", "--", minted.grantId, "--yes"],
        depsOver([LISTED_APPLE_ID], after),
      );
      expect(afterCode).not.toBe(0);
      expect(await keysUnder(`grant:${userKey}:${minted.grantId}`)).toEqual(
        before,
      );
    } finally {
      if (minted !== null) {
        await forgetGrant(userKey, minted.grantId);
        await forgetClient(minted.clientId);
      }
    }
  });

  it("the store adapter always passes the binding and the remote flag", async () => {
    const seen: string[][] = [];
    const replies: string[] = [
      JSON.stringify([
        { name: "grant:u1:g1" },
        { name: "grant:u1:g2", expiration: 1_800_000_000 },
      ]),
      JSON.stringify({ id: "g1", clientId: "c1" }),
      "",
    ];
    const run = (args: readonly string[]): string => {
      seen.push([...args]);
      return replies.shift() ?? "";
    };

    const kv = createWranglerKv(run, "OAUTH_KV");

    const listed = await kv.list({ prefix: "grant:" });
    expect(listed.keys.map((key) => key.name)).toEqual([
      "grant:u1:g1",
      "grant:u1:g2",
    ]);
    // wrangler paginates internally, so one call is the whole prefix. Reporting
    // anything else would make the library's cursor loop ask for a page that
    // does not exist.
    expect(listed.list_complete).toBe(true);

    expect(await kv.get("grant:u1:g1", { type: "json" })).toEqual({
      id: "g1",
      clientId: "c1",
    });
    await kv.delete("grant:u1:g1");

    expect(seen).toHaveLength(3);
    for (const args of seen) {
      expect(args).toContain("--binding");
      expect(args).toContain("OAUTH_KV");
      // Pitfall 5. Without this flag wrangler reads the local simulator, lists
      // nothing, and "no grants" is indistinguishable from a clean account.
      expect(args).toContain("--remote");
      // A namespace id in a committed file is the shape that silently points at
      // the wrong namespace after a re-provision. Binding names only.
      expect(args.some((arg) => arg.startsWith("--namespace"))).toBe(false);
      expect(args.some((arg) => /^[0-9a-f]{32}$/.test(arg))).toBe(false);
    }
    expect(seen[0]).toEqual([
      "kv",
      "key",
      "list",
      "--binding",
      "OAUTH_KV",
      "--remote",
      "--prefix",
      "grant:",
    ]);
    expect(seen[1]?.slice(0, 3)).toEqual(["kv", "key", "get"]);
    expect(seen[1]).toContain("--text");
    expect(seen[2]?.slice(0, 3)).toEqual(["kv", "key", "delete"]);
  });

  it("the adapter reports a read it could not complete rather than dropping the row", async () => {
    // A key can vanish between the listing and the read: legacy grants still
    // carry a TTL. A silently dropped row reads as "that grant is already
    // gone", which is the one answer this script must not invent.
    const run = (args: readonly string[]): string => {
      if (args[2] === "get") throw new Error("wrangler said no");
      return "[]";
    };
    const kv = createWranglerKv(run, "OAUTH_KV");

    expect(kv.readFailures?.()).toBe(0);
    expect(await kv.get("grant:u1:g1", { type: "json" })).toBeNull();
    expect(kv.readFailures?.()).toBe(1);
  });

  // -------------------------------------------------------------------------
  // prune-clients (CR-01). A client registration is unauthenticated, never
  // expires, and nothing in this repository removed one before this command.
  // The library's own sweeper has no client sweep, and calling it would perform
  // the forced logout LIFE-01 exists to remove.
  // -------------------------------------------------------------------------

  it("a revoke that fails on one grant still tries the rest and reports the truth", async () => {
    // WR-08. `revokeGrant` under the wrangler adapter is a command that throws
    // on any non-zero exit, and it can legitimately hit a key that vanished
    // between the listing and the delete — legacy grants still carry a TTL.
    // Before this, a throw on grant 2 of 3 escaped the whole run: the
    // verification pass never happened and the owner read "Nothing was revoked
    // unless a line above says it was", with no line above saying anything.
    //
    // Driven over a store this case OWNS, whose delete refuses ONE key. The
    // pool's shared store cannot express that.
    const base = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "c1"),
      "grant:u1:g2": grantRecord("u1", "g2", "c1"),
      "grant:u1:g3": grantRecord("u1", "g3", "c1"),
      "client:c1": { clientId: "c1" },
    });
    const kv: GrantStore = {
      list: base.list.bind(base),
      get: base.get.bind(base),
      async delete(name: string) {
        if (name === "grant:u1:g2") throw new Error("wrangler said no");
        await base.delete(name);
      },
    };
    const out = sink();

    const failed = await runGrants(["revoke", "g1", "g2", "g3", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    // Non-zero, because the verification pass found a record still there.
    expect(failed).toBe(1);
    // The two that could go, went. The one that refused is named.
    expect(await namesIn(kv)).toContain("grant:u1:g2");
    expect(await namesIn(kv)).not.toContain("grant:u1:g1");
    expect(await namesIn(kv)).not.toContain("grant:u1:g3");
    expect(out.text()).toContain("could not be revoked");
    // And the verification pass ran at all, which is the half that used to be
    // skipped entirely.
    expect(out.text()).toContain("still has records in the store");
  });

  it("a revoke whose delete threw on an already-gone key does not contradict itself", async () => {
    // IN-04. The case the WR-08 fix left behind: a delete THROWS but the
    // verification pass finds nothing left, because the key had already vanished.
    // `left` is 0, so stdout said `Revoked 3 grants and every token under them.`
    // while stderr had already said one of the three could not be revoked. Both
    // were true and they interleave in a terminal.
    const base = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "c1"),
      "grant:u1:g2": grantRecord("u1", "g2", "c1"),
      "grant:u1:g3": grantRecord("u1", "g3", "c1"),
      "client:c1": { clientId: "c1" },
    });
    const kv: GrantStore = {
      list: base.list.bind(base),
      get: base.get.bind(base),
      async delete(name: string) {
        // Gone, AND the command reports a failure — which is exactly what
        // wrangler does when it is asked to delete a key that is not there.
        await base.delete(name);
        if (name === "grant:u1:g2") throw new Error("wrangler said no");
      },
    };
    const out = sink();

    const code = await runGrants(["revoke", "g1", "g2", "g3", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    // Zero, because the store really is clean. The verification pass is the
    // authority and it found nothing left.
    expect(code).toBe(0);
    expect(await namesIn(kv)).toEqual(["client:c1"]);

    // Both halves of the account are present, and the second one is what stops
    // them reading as a contradiction.
    expect(out.text()).toContain("could not be revoked");
    expect(out.text()).toContain("Revoked 3 grants");
    expect(out.text()).toContain("1 of those deletes reported a failure");
    // The verification pass found nothing, so it says nothing.
    expect(out.text()).not.toContain("still has records in the store");
  });

  it("orphanClientIds reads no store and never names a record a grant claims", () => {
    const groups: GrantGroup[] = [
      {
        userKey: "u1",
        label: "somebody",
        kind: "address",
        grants: [
          {
            id: "g1",
            userKey: "u1",
            clientId: "claimed-one",
            clientName: "",
            created: "2026-01-01",
            expires: "never",
            clientPresent: true,
          },
          // An empty client id claims nothing. It must neither make a record
          // safe nor make one unsafe.
          {
            id: "g2",
            userKey: "u1",
            clientId: "",
            clientName: "",
            created: "2026-01-01",
            expires: "never",
            clientPresent: false,
          },
        ],
      },
    ];

    expect(
      orphanClientIds(
        new Set(["claimed-one", "orphan-b", "orphan-a"]),
        groups,
      ),
    ).toEqual(["orphan-a", "orphan-b"]);

    // Every record claimed: nothing to do, and in particular not an empty-string
    // entry conjured from the second grant.
    expect(orphanClientIds(new Set(["claimed-one"]), groups)).toEqual([]);
    // No records at all: a grant naming a record that is gone is already dead
    // (spike S2) and is not this command's business.
    expect(orphanClientIds(new Set(), groups)).toEqual([]);
  });

  it("prune-clients without --yes lists the orphan and deletes nothing", async () => {
    const kv = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
      "client:claimed-client-id": { clientId: "claimed-client-id" },
      "client:orphan-client-id": { clientId: "orphan-client-id" },
    });
    const out = sink();

    const code = await runGrants(["prune-clients"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    // Eight characters and an ellipsis, the same cut an unlabelled user segment
    // gets. The record itself is never READ: a client_name can be most of a MiB,
    // and pulling that through the owner's terminal is the one thing this must
    // not do.
    expect(out.text()).toContain(`orphan-c…`);
    expect(out.text()).not.toContain("orphan-client-id");
    expect(out.text()).not.toContain("claimed-c");
    // Compared against the export, not a second copy of the sentence.
    expect(out.text()).toContain(NOTHING_PRUNED);

    expect((await namesIn(kv)).sort()).toEqual([
      "client:claimed-client-id",
      "client:orphan-client-id",
      "grant:u1:g1",
    ]);
  });

  it("prune-clients --yes deletes only the orphan, and never the claimed record", async () => {
    const kv = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
      "client:claimed-client-id": { clientId: "claimed-client-id" },
      "client:orphan-client-id": { clientId: "orphan-client-id" },
    });
    const out = sink();

    const code = await runGrants(["prune-clients", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    // The claimed record survives, and so does the grant. Deleting a claimed
    // record makes that grant's next refresh answer `invalid_client` and signs
    // the person out even though their grant is perfect (spike S2) — which is
    // the whole reason this command computes its targets from the grants.
    expect((await namesIn(kv)).sort()).toEqual([
      "client:claimed-client-id",
      "grant:u1:g1",
    ]);
    expect(out.text()).toContain("Deleted 1 client record");
  });

  it("prune-clients --yes KEEPS a record a grant claimed between the two reads", async () => {
    // WR-03. The window is real: somebody registers a client and completes a
    // sign-in in the seconds between the owner reading the list and re-running
    // with --yes. Deleting that record makes their next refresh answer
    // `invalid_client` and signs them out of a connection that is perfectly fine.
    const kv = shiftingStore(
      {
        "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
        "client:claimed-client-id": { clientId: "claimed-client-id" },
        "client:orphan-client-id": { clientId: "orphan-client-id" },
      },
      (data) => {
        // The late sign-in, landing between the two views.
        data.set(
          "grant:u2:g2",
          grantRecord("u2", "g2", "orphan-client-id"),
        );
      },
    );
    const out = sink();

    const code = await runGrants(["prune-clients", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    // The record the first view called an orphan is still there, and so is the
    // grant that now names it.
    expect((await namesIn(kv)).sort()).toEqual([
      "client:claimed-client-id",
      "client:orphan-client-id",
      "grant:u1:g1",
      "grant:u2:g2",
    ]);
    // And the run EXPLAINS the zero rather than printing it bare. Compared
    // against the real renderer, not a second copy of the sentences.
    expect(out.text()).toContain(prunedSummary(0, 1, 0));
    expect(out.text()).toContain("KEPT");
  });

  it("prune-clients --yes explains a candidate that VANISHED between the two reads", async () => {
    // The other way a candidate drops out. Nothing was at risk here, but a bare
    // `Deleted 0 client records.` would leave the owner unable to tell this from
    // the case above — and from a command that had stopped working.
    const kv = shiftingStore(
      {
        "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
        "client:claimed-client-id": { clientId: "claimed-client-id" },
        "client:orphan-client-id": { clientId: "orphan-client-id" },
      },
      (data) => {
        data.delete("client:orphan-client-id");
      },
    );
    const out = sink();

    const code = await runGrants(["prune-clients", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect((await namesIn(kv)).sort()).toEqual([
      "client:claimed-client-id",
      "grant:u1:g1",
    ]);
    expect(out.text()).toContain(prunedSummary(0, 0, 1));
    expect(out.text()).toContain("already gone");
    // NOT the other sentence. The two reasons are counted apart because the
    // owner's reading of them differs.
    expect(out.text()).not.toContain("KEPT");
  });

  it("prune-clients says so when there is nothing to prune, and deletes nothing", async () => {
    const kv = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
      "client:claimed-client-id": { clientId: "claimed-client-id" },
    });
    const out = sink();

    // With --yes, which is the sharper case: a command told to go ahead with an
    // empty target set must still delete nothing.
    const code = await runGrants(["prune-clients", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("No orphan client registrations");
    expect(out.text()).not.toContain("Deleted");
    expect((await namesIn(kv)).sort()).toEqual([
      "client:claimed-client-id",
      "grant:u1:g1",
    ]);
  });

  it("list reports the orphan count, so the growth is not silent", async () => {
    const kv = ownStore({
      "grant:u1:g1": grantRecord("u1", "g1", "claimed-client-id"),
      "client:claimed-client-id": { clientId: "claimed-client-id" },
      "client:orphan-one": { clientId: "orphan-one" },
      "client:orphan-two": { clientId: "orphan-two" },
    });
    const out = sink();

    const code = await runGrants(["list"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("2 client registrations no grant names");
    expect(out.text()).toContain("prune-clients");
    // Still no full record id in the listing's note.
    expect(out.text()).not.toContain("orphan-one");
  });

  it("tells the owner what --legacy-owner means for list, not that it is unknown", async () => {
    // IN-05. The flag IS known; it just has no meaning for `list`, which already
    // shows every group including the legacy one. "Unknown flag." sent the owner
    // looking for a typo that was not there.
    const calls: string[] = [];
    const out = sink();
    const code = await runGrants(["list", "--legacy-owner"], refusingDeps(calls, out));

    expect(code).toBe(2);
    expect(calls, "a usage refusal reached the store").toEqual([]);
    expect(out.text()).toContain("list shows every group already");
    expect(out.text()).not.toContain("Unknown flag");
  });

  it("prune-clients refuses a target without touching the store", async () => {
    // It deliberately takes none. The safe set is computed FROM the grants, so
    // letting the owner name a record would be letting them name the one thing
    // the computation exists to refuse.
    for (const argv of [
      ["prune-clients", "some-client-id"],
      ["prune-clients", "--address", "someone@example.invalid"],
      ["prune-clients", "--legacy-owner", "--yes"],
    ]) {
      const calls: string[] = [];
      const out = sink();
      const code = await runGrants(argv, refusingDeps(calls, out));

      expect(code).toBe(2);
      expect(calls, `${argv.join(" ")} reached the store`).toEqual([]);
      expect(out.text()).toContain("prune-clients takes no grant id");
    }
  });

  it("says it read the remote store when it found nothing", async () => {
    // Driven over an EMPTY store rather than the pool's shared one, which
    // sibling files are writing to while this runs (hygiene rule 3).
    const empty: GrantStore = {
      async list() {
        return { keys: [], list_complete: true };
      },
      async get() {
        return null;
      },
      async delete() {},
    };
    const out = sink();
    const code = await runGrants(["list"], {
      kv: empty,
      async knownAddresses() {
        return [LISTED_APPLE_ID];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("REMOTE");
  });
});

// ---------------------------------------------------------------------------
// Autonomy in the owner's listing (Phase 27, AUTO-03, AUTO-04, D-18).
//
// Every case here runs over a store it OWNS. The autonomy grant is written in
// the library's own summary shape rather than minted by a sign-in, because
// minting one needs the autonomy client installed in the pool's shared store,
// and a sibling file signing in at the same moment would then arm a key too.
// test/autonomy.test.ts and test/autonomy-lifecycle.test.ts already prove the
// grant a real sign-in mints carries AUTONOMY_CLIENT_ID; this file proves what
// the owner's tool does with a grant that carries it.
// ---------------------------------------------------------------------------

/** A grant record naming a client and a client name, for a store we own. */
function namedGrantRecord(
  userKey: string,
  grantId: string,
  clientId: string,
  clientName: string,
): Record<string, unknown> {
  return { ...grantRecord(userKey, grantId, clientId), metadata: { clientName } };
}

/** The one rendered line carrying a grant id. */
function lineFor(text: string, grantId: string): string {
  const line = text.split("\n").find((candidate) => candidate.includes(grantId));
  expect(line, `no line for ${grantId}`).toBeDefined();
  return line as string;
}

describe("AUTO-03, AUTO-04: the owner's listing marks autonomy grants by client id", () => {
  it("marks the autonomy grant, and only by its client id, never by its name", async () => {
    const userKey = await listedUserId();
    const kv = ownStore({
      [`grant:${userKey}:auto-grant-1`]: namedGrantRecord(
        userKey,
        "auto-grant-1",
        AUTONOMY_CLIENT_ID,
        AUTONOMY_CLIENT_NAME,
      ),
      // A registrant chooses its own name. One that picks the autonomy client's
      // name must not be labelled autonomy (T-27-24).
      [`grant:${userKey}:posing-grant-1`]: namedGrantRecord(
        userKey,
        "posing-grant-1",
        "a-random-client-id",
        AUTONOMY_CLIENT_NAME,
      ),
      [`grant:${userKey}:plain-grant-1`]: namedGrantRecord(
        userKey,
        "plain-grant-1",
        "another-client-id",
        "Claude",
      ),
      [`client:${AUTONOMY_CLIENT_ID}`]: { clientId: AUTONOMY_CLIENT_ID },
      "client:a-random-client-id": { clientId: "a-random-client-id" },
      "client:another-client-id": { clientId: "another-client-id" },
    });

    const groups = await listGrants(kv, [LISTED_APPLE_ID]);
    const rows = groupFor(groups, userKey)?.grants ?? [];
    const row = (id: string) => rows.find((grant) => grant.id === id);
    expect(row("auto-grant-1")?.autonomy).toBe(true);
    expect(row("posing-grant-1")?.autonomy).toBe(false);
    expect(row("plain-grant-1")?.autonomy).toBe(false);

    // No timer of its own: the autonomy row shows the same expiry as every
    // ordinary row, and only the marker tells it apart.
    expect(row("auto-grant-1")?.expires).toBe("never");

    const text = renderGrants(groups);
    expect(lineFor(text, "auto-grant-1")).toBe(
      `  auto-grant-1  client "${AUTONOMY_CLIENT_NAME}"  created 2026-05-28` +
        "  expires never  client present  autonomy",
    );
    // Every other row is byte-identical to the listing before this phase.
    expect(lineFor(text, "posing-grant-1")).toBe(
      `  posing-grant-1  client "${AUTONOMY_CLIENT_NAME}"  created 2026-05-28` +
        "  expires never  client present",
    );
    expect(lineFor(text, "plain-grant-1")).toBe(
      '  plain-grant-1  client "Claude"  created 2026-05-28  expires never  client present',
    );
  });

  it("after revoke --address --yes the listing shows no row for that person, autonomy included", async () => {
    const userKey = await listedUserId();
    const otherKey = "9".repeat(64);
    const kv = ownStore({
      [`grant:${userKey}:plain-grant-2`]: namedGrantRecord(
        userKey,
        "plain-grant-2",
        "a-client-id",
        "Claude",
      ),
      [`token:${userKey}:plain-grant-2:t1`]: { id: "t1" },
      [`grant:${userKey}:auto-grant-2`]: namedGrantRecord(
        userKey,
        "auto-grant-2",
        AUTONOMY_CLIENT_ID,
        AUTONOMY_CLIENT_NAME,
      ),
      [`token:${userKey}:auto-grant-2:t2`]: { id: "t2" },
      [`grant:${otherKey}:someone-else-grant`]: namedGrantRecord(
        otherKey,
        "someone-else-grant",
        AUTONOMY_CLIENT_ID,
        AUTONOMY_CLIENT_NAME,
      ),
      "client:a-client-id": { clientId: "a-client-id" },
      [`client:${AUTONOMY_CLIENT_ID}`]: { clientId: AUTONOMY_CLIENT_ID },
    });
    const deps = (out: { write(text: string): void }): GrantDeps => ({
      kv,
      async knownAddresses() {
        return [LISTED_APPLE_ID];
      },
      write: out.write,
      writeError: out.write,
    });

    // The positive control, before the revoke: the person's autonomy row is
    // listed and marked, so its absence afterwards means something.
    const before = sink();
    expect(await runGrants(["list"], deps(before))).toBe(0);
    expect(before.text()).toContain(maskAppleId(LISTED_APPLE_ID));
    expect(lineFor(before.text(), "auto-grant-2")).toMatch(/ {2}autonomy$/);

    const revoke = sink();
    const code = await runGrants(
      ["revoke", "--address", LISTED_APPLE_ID, "--yes"],
      deps(revoke),
    );
    expect(`${code} ${revoke.text()}`).toBe(`0 ${revoke.text()}`);

    const after = sink();
    expect(await runGrants(["list"], deps(after))).toBe(0);
    expect(after.text()).not.toContain(maskAppleId(LISTED_APPLE_ID));
    expect(after.text()).not.toContain("auto-grant-2");
    expect(after.text()).not.toContain("plain-grant-2");
    // Nothing of the person's is left in the store, tokens included.
    const names = await namesIn(kv);
    expect(names.filter((name) => name.includes(userKey))).toEqual([]);
    // Somebody else's autonomy key is untouched, and still marked.
    expect(lineFor(after.text(), "someone-else-grant")).toMatch(/ {2}autonomy$/);
  });

  it("orphanClientIds never names the autonomy client, with or without a grant naming it", () => {
    const withGrant: GrantGroup[] = [
      {
        userKey: "u1",
        label: "somebody",
        kind: "address",
        grants: [
          {
            id: "g1",
            userKey: "u1",
            clientId: AUTONOMY_CLIENT_ID,
            clientName: AUTONOMY_CLIENT_NAME,
            created: "2026-01-01",
            expires: "never",
            clientPresent: true,
            autonomy: true,
          },
        ],
      },
    ];
    const present = new Set([AUTONOMY_CLIENT_ID, "orphan-z", "orphan-a"]);

    // Right after setup nobody has signed in, so no grant names the client.
    expect(orphanClientIds(present, [])).toEqual(["orphan-a", "orphan-z"]);
    expect(orphanClientIds(present, withGrant)).toEqual(["orphan-a", "orphan-z"]);
    expect(orphanClientIds(new Set([AUTONOMY_CLIENT_ID]), [])).toEqual([]);
  });

  it("prune-clients --yes deletes a true orphan and keeps the autonomy client", async () => {
    const kv = ownStore({
      [`client:${AUTONOMY_CLIENT_ID}`]: { clientId: AUTONOMY_CLIENT_ID },
      "client:true-orphan-id": { clientId: "true-orphan-id" },
    });
    const out = sink();

    const code = await runGrants(["prune-clients", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
    });

    expect(code).toBe(0);
    expect(await namesIn(kv)).toEqual([`client:${AUTONOMY_CLIENT_ID}`]);
    expect(out.text()).toContain("Deleted 1 client record");
    // The orphan listing never showed it as a candidate either.
    expect(out.text()).not.toContain(`${AUTONOMY_CLIENT_ID.slice(0, 8)}…`);
  });
});

// ---------------------------------------------------------------------------
// The owner's autonomy setup (Phase 27, AUTO-03, D-05, D-07, D-18, D-29).
//
// Nothing here touches a real store or a real Worker. The setup runs against a
// store double, or against a fake wrangler that records every argument list and
// every standard-input value separately, so the one thing this command must
// never do -- put a secret on a command line or on the screen -- is checked
// against what was actually passed.
// ---------------------------------------------------------------------------

/** The one redirect URI the client must carry. */
const AUTONOMY_REDIRECT = `https://${DEPLOYED_HOSTNAME}${AUTONOMY_REDIRECT_PATH}`;

/** A store this case owns that can be written, and remembers each write's options. */
function writableStore(records: Record<string, string> = {}): {
  kv: GrantStore;
  data: Map<string, string>;
  puts: Array<{ name: string; options: unknown }>;
} {
  const data = new Map(Object.entries(records));
  const puts: Array<{ name: string; options: unknown }> = [];
  const kv: GrantStore = {
    async list(options?: { prefix?: string }) {
      const prefix = options?.prefix ?? "";
      return {
        keys: [...data.keys()]
          .filter((name) => name.startsWith(prefix))
          .sort()
          .map((name) => ({ name })),
        list_complete: true,
      };
    },
    async get(name: string, options?: unknown) {
      const value = data.get(name);
      if (value === undefined) return null;
      const type =
        typeof options === "string" ? options : (options as { type?: string })?.type;
      return type === "json" ? JSON.parse(value) : value;
    },
    async put(name: string, value: string, options?: unknown) {
      puts.push({ name, options });
      data.set(name, value);
    },
    async delete(name: string) {
      data.delete(name);
    },
  };
  return { kv, data, puts };
}

/** The library's hash of a client secret, computed here so it is not trusted. */
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** base64url with no padding, decoded, for checking the seal key's length. */
function bytesOf(base64url: string): Uint8Array {
  const padded =
    base64url.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (base64url.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

/** A secret store that records names and values apart. */
function recordingSecrets(): {
  secrets: AutonomySetupDeps["secrets"];
  set: Array<{ name: string; value: string }>;
} {
  const set: Array<{ name: string; value: string }> = [];
  return {
    set,
    secrets: {
      async put(name: string, value: string) {
        set.push({ name, value });
      },
    },
  };
}

/** The setup's own dependencies, with the pool's hostname and real randomness. */
function setupDeps(secrets: AutonomySetupDeps["secrets"]): AutonomySetupDeps {
  return {
    hostname: () => DEPLOYED_HOSTNAME,
    randomBytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)),
    secrets,
  };
}

/**
 * A fake wrangler. It serves the four `kv key` verbs from memory, and records
 * every argument list, and every standard-input value, separately.
 */
function fakeWrangler(): {
  run(args: readonly string[]): string;
  runWithInput(args: readonly string[], input: string): string;
  argumentLists: string[][];
  inputs: Array<{ args: string[]; input: string }>;
  data: Map<string, string>;
} {
  const data = new Map<string, string>();
  const argumentLists: string[][] = [];
  const inputs: Array<{ args: string[]; input: string }> = [];
  return {
    data,
    argumentLists,
    inputs,
    run(args) {
      argumentLists.push([...args]);
      const verb = args[2];
      if (args[0] !== "kv" || args[1] !== "key") throw new Error("not a kv command");
      if (verb === "list") {
        const prefix = args[args.indexOf("--prefix") + 1] ?? "";
        return JSON.stringify(
          [...data.keys()].filter((name) => name.startsWith(prefix)).map((name) => ({ name })),
        );
      }
      if (verb === "get") {
        const name = args[args.length - 1] as string;
        const value = data.get(name);
        if (value === undefined) throw new Error("no such key");
        return value;
      }
      if (verb === "put") {
        data.set(args[args.length - 2] as string, args[args.length - 1] as string);
        return "";
      }
      if (verb === "delete") {
        data.delete(args[args.length - 1] as string);
        return "";
      }
      throw new Error("unknown kv verb");
    },
    runWithInput(args, input) {
      argumentLists.push([...args]);
      inputs.push({ args: [...args], input });
      return "";
    },
  };
}

describe("AUTO-03: the owner's autonomy setup creates the client and sets both secrets unseen", () => {
  it("installAutonomyClientRecord makes one client, under the fixed id, with the library's hash", async () => {
    const { kv, data, puts } = writableStore();
    const helpers = getOAuthApi(oauthProviderOptions, { OAUTH_KV: kv } as never);
    const clientSecret = "a-known-test-client-secret-not-real";

    const installed = await installAutonomyClientRecord({
      helpers,
      kv,
      redirectUris: [AUTONOMY_REDIRECT],
      clientSecret,
      replace: false,
    });
    expect(installed).toEqual({ kind: "installed", replaced: false });

    const client = await helpers.lookupClient(AUTONOMY_CLIENT_ID);
    expect(client).not.toBeNull();
    expect(client?.clientId).toBe(AUTONOMY_CLIENT_ID);
    expect(client?.redirectUris).toEqual([AUTONOMY_REDIRECT]);
    expect(client?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(client?.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(client?.responseTypes).toEqual(["code"]);
    expect(client?.clientName).toBe(AUTONOMY_CLIENT_NAME);

    // No random-id copy left behind (T-27-27).
    expect([...data.keys()].filter((name) => name.startsWith("client:"))).toEqual([
      `client:${AUTONOMY_CLIENT_ID}`,
    ]);

    // The library's hash of the value given, and never the value.
    const stored = JSON.parse(data.get(`client:${AUTONOMY_CLIENT_ID}`) as string) as {
      clientSecret?: string;
    };
    expect(stored.clientSecret).toBe(await sha256Hex(clientSecret));
    expect(data.get(`client:${AUTONOMY_CLIENT_ID}`)).not.toContain(clientSecret);

    // No write of a client record carried an expiry (T-27-26).
    const clientPuts = puts.filter((put) => put.name.startsWith("client:"));
    expect(clientPuts.length).toBeGreaterThanOrEqual(3);
    for (const put of clientPuts) {
      const options = put.options as { expiration?: unknown; expirationTtl?: unknown } | undefined;
      expect(options?.expiration, put.name).toBeUndefined();
      expect(options?.expirationTtl, put.name).toBeUndefined();
    }
  });

  it("refuses when the client exists and changes nothing, unless replace is true", async () => {
    const { kv, data } = writableStore();
    const helpers = getOAuthApi(oauthProviderOptions, { OAUTH_KV: kv } as never);
    await installAutonomyClientRecord({
      helpers,
      kv,
      redirectUris: [AUTONOMY_REDIRECT],
      clientSecret: "first-secret-not-real",
      replace: false,
    });
    const before = new Map(data);

    const refused = await installAutonomyClientRecord({
      helpers,
      kv,
      redirectUris: [AUTONOMY_REDIRECT],
      clientSecret: "second-secret-not-real",
      replace: false,
    });
    expect(refused).toEqual({ kind: "exists" });
    expect(new Map(data)).toEqual(before);

    const replaced = await installAutonomyClientRecord({
      helpers,
      kv,
      redirectUris: [AUTONOMY_REDIRECT],
      clientSecret: "second-secret-not-real",
      replace: true,
    });
    expect(replaced).toEqual({ kind: "installed", replaced: true });
    const stored = JSON.parse(data.get(`client:${AUTONOMY_CLIENT_ID}`) as string) as {
      clientSecret?: string;
    };
    expect(stored.clientSecret).toBe(await sha256Hex("second-secret-not-real"));
    expect([...data.keys()].filter((name) => name.startsWith("client:"))).toEqual([
      `client:${AUTONOMY_CLIENT_ID}`,
    ]);
  });

  it("refuses anything but exactly one redirect URI (D-29)", async () => {
    const { kv, data } = writableStore();
    const helpers = getOAuthApi(oauthProviderOptions, { OAUTH_KV: kv } as never);
    for (const redirectUris of [[], [AUTONOMY_REDIRECT, `${AUTONOMY_REDIRECT}/2`]]) {
      await expect(
        installAutonomyClientRecord({
          helpers,
          kv,
          redirectUris,
          clientSecret: "a-secret-not-real",
        }),
      ).rejects.toThrow();
    }
    expect(data.size).toBe(0);
  });

  it("autonomy-setup without --yes says what it would do and changes nothing", async () => {
    const { kv, data, puts } = writableStore();
    const { secrets, set } = recordingSecrets();
    const out = sink();

    const code = await runGrants(["autonomy-setup"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
      autonomy: setupDeps(secrets),
    });

    expect(code).toBe(0);
    expect(out.text()).toContain(`Would create the autonomy client ${AUTONOMY_CLIENT_ID}`);
    expect(out.text()).toContain(AUTONOMY_REDIRECT);
    expect(out.text()).toContain("AUTONOMY_CLIENT_SECRET");
    expect(out.text()).toContain("AUTONOMY_SEAL_KEY");
    expect(out.text()).toContain("Nothing was changed");
    expect(puts).toEqual([]);
    expect(data.size).toBe(0);
    expect(set).toEqual([]);
  });

  it("autonomy-setup --yes writes the client with no expiry, over the script's own options", async () => {
    // The script builds its helpers over its OWN minimal options, not the
    // Worker's. Without `clientRegistrationTTL: undefined` there, the library's
    // 90-day default reaches `updateClient` and the record would lapse.
    const { kv, data, puts } = writableStore();
    const { secrets, set } = recordingSecrets();
    const out = sink();

    const code = await runGrants(["autonomy-setup", "--yes"], {
      kv,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
      autonomy: setupDeps(secrets),
    });
    expect(`${code} ${out.text()}`).toBe(`0 ${out.text()}`);

    const clientPuts = puts.filter((put) => put.name.startsWith("client:"));
    expect(clientPuts.length).toBeGreaterThanOrEqual(3);
    for (const put of clientPuts) {
      const options = put.options as { expiration?: unknown; expirationTtl?: unknown } | undefined;
      expect(options?.expiration, put.name).toBeUndefined();
      expect(options?.expirationTtl, put.name).toBeUndefined();
    }
    expect([...data.keys()]).toEqual([`client:${AUTONOMY_CLIENT_ID}`]);

    // The secret the Worker is given is the one the record's hash is of.
    const clientSecret = set.find((entry) => entry.name === "AUTONOMY_CLIENT_SECRET")?.value;
    expect(typeof clientSecret).toBe("string");
    const stored = JSON.parse(data.get(`client:${AUTONOMY_CLIENT_ID}`) as string) as {
      clientSecret?: string;
      redirectUris?: string[];
    };
    expect(stored.clientSecret).toBe(await sha256Hex(clientSecret as string));
    expect(stored.redirectUris).toEqual([AUTONOMY_REDIRECT]);
  });

  it("autonomy-setup --yes puts each secret on standard input only, and never shows one", async () => {
    const wrangler = fakeWrangler();
    const out = sink();

    const code = await runGrants(["autonomy-setup", "--yes"], {
      kv: createWranglerKv(wrangler.run, "OAUTH_KV"),
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
      autonomy: setupDeps(createWranglerSecrets(wrangler.runWithInput)),
    });
    expect(`${code} ${out.text()}`).toBe(`0 ${out.text()}`);

    // Exactly two secret puts, by name, in this order, each value on stdin.
    expect(wrangler.inputs.map((entry) => entry.args)).toEqual([
      ["secret", "put", "AUTONOMY_CLIENT_SECRET"],
      ["secret", "put", "AUTONOMY_SEAL_KEY"],
    ]);
    expect(AUTONOMY_SECRET_NAMES).toEqual(["AUTONOMY_CLIENT_SECRET", "AUTONOMY_SEAL_KEY"]);
    const clientSecret = wrangler.inputs[0]?.input as string;
    const sealKey = wrangler.inputs[1]?.input as string;
    // Non-vacuity: `not.toContain("")` would be true of anything.
    expect(clientSecret.length).toBeGreaterThan(0);
    expect(sealKey.length).toBeGreaterThan(0);
    expect(clientSecret).not.toBe(sealKey);
    expect(bytesOf(sealKey)).toHaveLength(32);
    expect(bytesOf(clientSecret)).toHaveLength(32);
    expect(sealKey).toMatch(/^[A-Za-z0-9_-]+$/);

    // Neither value on any command line, and neither on the screen (T-27-23).
    for (const args of wrangler.argumentLists) {
      for (const arg of args) {
        expect(arg).not.toContain(clientSecret);
        expect(arg).not.toContain(sealKey);
      }
    }
    expect(out.text()).not.toContain(clientSecret);
    expect(out.text()).not.toContain(sealKey);
    // The names are printed, and so is the client id.
    expect(out.text()).toContain("AUTONOMY_CLIENT_SECRET");
    expect(out.text()).toContain("AUTONOMY_SEAL_KEY");
    expect(out.text()).toContain(AUTONOMY_CLIENT_ID);

    // Every store command carried the binding and the remote flag, and no write
    // carried an expiry.
    const kvCommands = wrangler.argumentLists.filter((args) => args[0] === "kv");
    expect(kvCommands.length).toBeGreaterThan(0);
    for (const args of kvCommands) {
      expect(args).toContain("--remote");
      expect(args.slice(3, 5)).toEqual(["--binding", "OAUTH_KV"]);
      expect(args).not.toContain("--ttl");
      expect(args).not.toContain("--expiration");
    }
    expect(kvCommands.some((args) => args[2] === "put")).toBe(true);

    // One client record, under the fixed id, holding the hash of the value the
    // Worker was given.
    expect([...wrangler.data.keys()]).toEqual([`client:${AUTONOMY_CLIENT_ID}`]);
    const stored = JSON.parse(wrangler.data.get(`client:${AUTONOMY_CLIENT_ID}`) as string) as {
      clientSecret?: string;
    };
    expect(stored.clientSecret).toBe(await sha256Hex(clientSecret));
  });

  it("autonomy-setup --yes refuses an existing client and says what --replace costs", async () => {
    const { kv: seeded, data } = writableStore();
    await installAutonomyClientRecord({
      helpers: getOAuthApi(oauthProviderOptions, { OAUTH_KV: seeded } as never),
      kv: seeded,
      redirectUris: [AUTONOMY_REDIRECT],
      clientSecret: "the-existing-secret-not-real",
    });
    const before = new Map(data);
    const { secrets, set } = recordingSecrets();
    const out = sink();
    const deps: GrantDeps = {
      kv: seeded,
      async knownAddresses() {
        return [];
      },
      write: out.write,
      writeError: out.write,
      autonomy: setupDeps(secrets),
    };

    expect(await runGrants(["autonomy-setup", "--yes"], deps)).toBe(1);
    expect(out.text()).toContain("already exists");
    expect(out.text()).toContain(REPLACE_ENDS_KEYS);
    expect(REPLACE_ENDS_KEYS).toBe(
      "--replace ends everyone's autonomy key until their next sign-in.",
    );
    expect(new Map(data)).toEqual(before);
    expect(set).toEqual([]);

    const replaced = sink();
    expect(
      await runGrants(["autonomy-setup", "--replace", "--yes"], { ...deps, write: replaced.write }),
    ).toBe(0);
    expect(replaced.text()).toContain(`Replaced the autonomy client ${AUTONOMY_CLIENT_ID}`);
    expect(replaced.text()).toContain("Every stored autonomy key has stopped working");
    expect(set.map((entry) => entry.name)).toEqual([
      "AUTONOMY_CLIENT_SECRET",
      "AUTONOMY_SEAL_KEY",
    ]);
    const stored = JSON.parse(data.get(`client:${AUTONOMY_CLIENT_ID}`) as string) as {
      clientSecret?: string;
    };
    expect(stored.clientSecret).toBe(await sha256Hex(set[0]?.value as string));
    expect([...data.keys()]).toEqual([`client:${AUTONOMY_CLIENT_ID}`]);
  });

  it("refuses --replace elsewhere, and a target on autonomy-setup, without touching the store", async () => {
    for (const argv of [
      ["list", "--replace"],
      ["revoke", "some-grant-id", "--replace", "--yes"],
      ["prune-clients", "--replace"],
      ["autonomy-setup", "some-id"],
      ["autonomy-setup", "--address", "someone@example.invalid"],
      ["autonomy-setup", "--legacy-owner"],
    ]) {
      const calls: string[] = [];
      const out = sink();
      const code = await runGrants(argv, refusingDeps(calls, out));
      expect(code, `${argv.join(" ")} was not refused`).toBe(2);
      expect(calls, `${argv.join(" ")} reached the store`).toEqual([]);
    }
  });

  it("autonomy-setup refuses when it has no way to set secrets, before any store call", async () => {
    const calls: string[] = [];
    const out = sink();
    const code = await runGrants(["autonomy-setup", "--yes"], refusingDeps(calls, out));
    expect(code).toBe(1);
    expect(calls).toEqual([]);
    expect(out.text()).toContain("Nothing was changed");
  });

  it("the store adapter refuses an expiring write, and reads back its own write", async () => {
    const seen: string[][] = [];
    const kv = createWranglerKv((args) => {
      seen.push([...args]);
      return "";
    }, "OAUTH_KV");

    await expect(kv.put?.("client:x", "{}", { expirationTtl: 60 })).rejects.toThrow();
    await expect(kv.put?.("client:x", "{}", { expiration: 1_900_000_000 })).rejects.toThrow();
    expect(seen).toEqual([]);

    await kv.put?.("client:x", '{"clientId":"x"}');
    expect(seen).toEqual([
      ["kv", "key", "put", "--binding", "OAUTH_KV", "--remote", "client:x", '{"clientId":"x"}'],
    ]);
    // Served from memory: the remote store may not show a fresh write to a
    // read for up to a minute, and the setup reads back what it just wrote.
    expect(await kv.get("client:x", { type: "json" })).toEqual({ clientId: "x" });
    expect(seen).toHaveLength(1);
  });

  it("names autonomy-setup in the usage text", () => {
    expect(USAGE).toContain("autonomy-setup [--replace] [--yes]");
    expect(USAGE).toContain(REPLACE_ENDS_KEYS);
  });
});
