// The dead-password pause (LIFE-04).
//
// **What this file proves.** When Apple refuses the password saved in a grant,
// every later tool call for that user answers `auth_failed` for fifteen minutes
// without contacting Apple. And — the half that needs as much proof — that
// nothing ELSE sets the pause: not a throttle, not a connection error, not a
// DAV 403, not a credential this server refused before Apple, not a missing
// staging secret, and above all not a refused sign-in on the login page.
//
// The message half of LIFE-04 already shipped in Phase 11: `auth_failed` says
// to reconnect and that retrying will not help. This file pins that the paused
// answer is that exact string, so the two halves cannot drift apart.
//
// ---------------------------------------------------------------------------
// **Two hygiene rules, each with its reason. Do not undo them.**
//
// 1. THIS FILE USES ITS OWN IDENTITY, and every case deletes any marker it
//    wrote, in a `finally`. The pool's stores are shared with every sibling
//    file running at the same time. A marker left behind for USER_A would pause
//    USER_A across the whole suite for fifteen minutes, and `test/door.test.ts`
//    serves USER_A as its positive control — so a leak here turns a neighbour
//    red with no visible connection to this file. The address below is under
//    the reserved `.invalid` domain and is used by no other file.
//
// 2. A REFUSED SIGN-IN NEVER GOES THROUGH THE POOL'S REAL STORE. A refusal on
//    the login page writes a failure record for the address it was given, and
//    five of those in an hour lock that address out of every suite that signs
//    it in. The login-page cases below drive `createLoginHandler(proof).fetch`
//    over a RECORDING STUB store instead, which is also what lets them assert
//    that no pause key was written at all — a listing cannot tell "no key" from
//    "the request never reached the store".
//
// The one exception is the last "clears" case, which needs the real provider to
// show the clear happening in production wiring. It signs the LISTED address in
// on a GOOD sign-in, which writes no failure record, and it deletes both the
// marker and the grant it minted in a `finally`.
// ---------------------------------------------------------------------------
//
// **No real Apple ID is ever authenticated (D-09).** Every login below is a
// fake duplex or an injected proof, and both passwords here are plainly fake.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LoginProof } from "../src/auth/login-handler";
import { createLoginHandler } from "../src/auth/login-handler";
import { createDavFetch } from "../src/dav/transport";
import {
  DavAuthError,
  DavConnectError,
  DavThrottleError,
} from "../src/dav/errors";
import type { Env, EntryEnv, LoginGateSecret } from "../src/env";
import {
  ImapAuthError,
  ImapConnectError,
  ImapThrottleError,
  SAFE_MESSAGES,
} from "../src/errors";
import { runDiagnosticOver } from "../src/mail/diagnose";
import { createSessionGate, withMailSessionOver } from "../src/mail/service";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import type { Principal } from "../src/principal";
import { maskAppleId, principalFromProps, userIdOf } from "../src/principal";
import {
  PASSWORD_PAUSE_KEY_PREFIX,
  PASSWORD_PAUSE_SECONDS,
  answersDuringPause,
  guardAgainstPause,
} from "../src/password-pause";
import { mintUploadUrl } from "../src/staging/presign";
import { entryEnv } from "./fixtures/bound-secrets";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { createFailingDuplex, createFakeDuplex } from "./fixtures/fake-duplex";
import {
  AUTH_CONTACTADMIN_TEXT,
  AUTH_REFUSED_PROSE_TEXT,
  AUTH_REJECTED_LEGACY_TEXT,
  AUTH_REJECTED_TEXT,
  AUTH_SERVER_FAULT_TEXT,
  AUTH_UNCLASSIFIED_TEXT,
  CONNECTION_LIMIT_TEXT,
  GREETING,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedBad,
  taggedNo,
} from "./fixtures/icloud-bytes";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// `test/door.test.ts` carries the same comment for the same reason. `?raw`
// inlines the file's text at build time, which is how a Workers isolate with no
// filesystem reads source.
const SERVER_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/server.ts",
  { query: "?raw", import: "default", eager: true },
);

/** The per-request server factory's source, for the WR-04 wiring assertion. */
const SERVER_SOURCE: string = Object.values(SERVER_SOURCE_GLOB)[0] ?? "";

/**
 * This file's own address, used by nothing else in the repository.
 *
 * Hygiene rule 1. `.invalid` is reserved by RFC 6761 so it can never resolve,
 * and no other suite signs this one in — so a marker that escaped a `finally`
 * would pause nobody a neighbour depends on. It is deliberately NOT user A's
 * address: `test/door.test.ts` serves that one as its positive control.
 */
const PAUSED_APPLE_ID = "paused-user@example.invalid";

/** A password shaped like an app-specific one, and plainly fake. */
const PAUSED_APP_PASSWORD = "pppp-pppp-pppp-pppp";

/** The bounds the fake-duplex sessions run under, copied from `test/service.test.ts`. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The mail diagnostic: a tool that awaits the principal before any socket. */
const MAIL_DIAGNOSTIC = "mail_imap_diagnose";

/** The account tool from plan 12-03. It opens no socket at all. */
const ACCOUNT_TOOL = "account_whoami";

/** The DAV diagnostic. Like the mail one, exempt from the pause (WR-04). */
const DAV_DIAGNOSTIC = "dav_diagnose";

/** An ordinary mail tool: it opens a socket, and the pause is what stops it. */
const MAIL_TOOL = "mail_list_folders";

/** An ordinary DAV tool: it sends a DAV request, and the pause stops that too. */
const CALENDAR_TOOL = "calendar_list_calendars";

/** The door as production builds it, with no injected tools. */
const door = createMcpApiHandler();

/**
 * A principal for this file's identity, straight from the real constructor.
 *
 * UN-ARMED. This is the shape the login page has, and the whole structural
 * defence of LIFE-04 is that a principal in this shape reports nothing.
 */
function unarmedPrincipal(): Promise<Principal> {
  return principalFromProps({
    v: 1,
    appleId: PAUSED_APPLE_ID,
    appPassword: PAUSED_APP_PASSWORD,
  });
}

/** The same principal, ARMED, exactly as the door arms one. */
function armedPrincipal(): Promise<Principal> {
  return guardAgainstPause(unarmedPrincipal(), entryEnv().OAUTH_KV);
}

/** One address's user id, derived by the real function. Never hashed here (D-12). */
async function userIdFor(appleId: string): Promise<string> {
  const userId = await userIdOf(appleId);
  expect(userId).not.toBeNull();
  return userId as string;
}

/** The marker's real key, built from the exported prefix and the real id. */
async function markerKey(appleId: string = PAUSED_APPLE_ID): Promise<string> {
  return `${PASSWORD_PAUSE_KEY_PREFIX}${await userIdFor(appleId)}`;
}

/** What the marker currently is: its value, and the expiry the store reports. */
async function readMarker(appleId: string = PAUSED_APPLE_ID): Promise<{
  value: string | null;
  expiration: number | null;
}> {
  const kv = entryEnv().OAUTH_KV;
  const key = await markerKey(appleId);
  const value = await kv.get(key);
  const listed = await kv.list({ prefix: key });
  const found = listed.keys.find((one) => one.name === key);
  return { value, expiration: found?.expiration ?? null };
}

/** Put the marker where the guard will find it, exactly as the report does. */
async function setMarker(appleId: string = PAUSED_APPLE_ID): Promise<void> {
  await entryEnv().OAUTH_KV.put(await markerKey(appleId), "1", {
    expirationTtl: PASSWORD_PAUSE_SECONDS,
  });
}

/** Hygiene rule 1. Called in a `finally` by every case that could have written one. */
async function forgetMarker(
  appleId: string = PAUSED_APPLE_ID,
): Promise<void> {
  await entryEnv().OAUTH_KV.delete(await markerKey(appleId));
}

/** A DAV target on the shape of host iCloud's discovery resolves to. */
const DAV_TARGET = "https://p42-caldav.icloud.com/1234567890/calendars/";

/** A stubbed global fetch that records what it was asked for. */
interface FetchStub {
  /** Every URL the stub was called with, in order. Its LENGTH is the assertion. */
  readonly calls: string[];
  readonly fetch: typeof globalThis.fetch;
}

/** Always answers with one status, whatever is asked, and records the call. */
function statusStub(status: number): FetchStub {
  const calls: string[] = [];
  return {
    calls,
    fetch: (async (input: RequestInfo | URL) => {
      calls.push(
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url,
      );
      return new Response(status === 204 ? null : "<multistatus/>", { status });
    }) as typeof globalThis.fetch,
  };
}

/** A transport that never answers at all, for the DAV connection-fault row. */
function failingStub(): FetchStub {
  const calls: string[] = [];
  return {
    calls,
    fetch: (async (input: RequestInfo | URL) => {
      calls.push(
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url,
      );
      throw new Error("the stubbed transport refused the connection");
    }) as typeof globalThis.fetch,
  };
}

/** What a call threw, as a value. Null when it did not throw. */
async function raise(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
    return null;
  } catch (err) {
    return err;
  }
}

/** Everything the login handler did to its stubs, in the order it did it. */
interface LoginRecorder {
  /** Store writes and provider calls on ONE list, so ordering is readable. */
  readonly calls: string[];
  /** Keys the handler asked the store to write. */
  readonly puts: string[];
  /** Keys the handler asked the store to delete. */
  readonly deletes: string[];
}

function loginRecorder(): LoginRecorder {
  return { calls: [], puts: [], deletes: [] };
}

/**
 * An env whose store RECORDS and whose provider records, for the login page.
 *
 * Hygiene rule 2. Nothing here touches the pool's real store, so a refused
 * sign-in writes no failure record that a sibling suite then has to live with —
 * and the recording store is what lets a case assert that NO pause key was
 * written, which a listing could never tell from a request that never arrived.
 *
 * Both limiters allow, because no case here is about a limiter.
 */
function loginStubEnv(
  record: LoginRecorder,
  appleId: string,
): Env & LoginGateSecret {
  return {
    OAUTH_KV: {
      async get(): Promise<string | null> {
        return null;
      },
      async put(key: string): Promise<void> {
        record.calls.push(`put:${key}`);
        record.puts.push(key);
      },
      async delete(key: string): Promise<void> {
        record.calls.push(`delete:${key}`);
        record.deletes.push(key);
      },
    },
    LOGIN_IP_LIMITER: {
      async limit(_options: { key: string }): Promise<{ success: boolean }> {
        return { success: true };
      },
    },
    LOGIN_ID_LIMITER: {
      async limit(_options: { key: string }): Promise<{ success: boolean }> {
        return { success: true };
      },
    },
    ALLOWED_APPLE_IDS_SEED: JSON.stringify([appleId]),
    ALLOW_LIST_KV: {
      async get(): Promise<string | null> {
        return null;
      },
    },
    OAUTH_PROVIDER: {
      parseAuthRequest: async () => ({
        responseType: "code",
        clientId: "stub-client",
        redirectUri: STUB_REDIRECT,
        scope: ["mcp"],
        state: "",
      }),
      lookupClient: async () => ({
        clientId: "stub-client",
        clientName: "Stub Client",
      }),
      completeAuthorization: async () => {
        record.calls.push("completeAuthorization");
        return { redirectTo: `${STUB_REDIRECT}?code=stub-code` };
      },
    },
  } as unknown as Env & LoginGateSecret;
}

/** Where the stub provider says the code would go. On an allowed origin. */
const STUB_REDIRECT = "https://claude.ai/cb";

/** The floor injected small: twenty refusals at three seconds each is a minute. */
const TEST_FLOOR_MS = 120;

/** A sign-in POST the stub provider is happy to parse. */
function loginPost(appleId: string): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: PAUSED_APP_PASSWORD,
      oauth_request: "response_type=code&client_id=stub-client",
    }).toString(),
  });
}

/**
 * The proof the login page actually runs, over a duplex that refuses.
 *
 * It calls the REAL `withMailSessionOver` — the same function every mail tool
 * goes through, and the same line that reports a refusal. That is what makes
 * "the login page cannot set the pause" a claim about production rather than
 * about a stub: the report line runs, and finds the principal un-armed.
 *
 * `oneAttemptPerGuess` is what the production proof passes, so the script
 * answers one attempt and never a fallback.
 */
const refusingProof: LoginProof = async (principal, gate) => {
  await withMailSessionOver(
    refusedAuth(AUTH_REJECTED_TEXT),
    principal,
    gate,
    null,
    null,
    async () => undefined,
    { ...FAST_BOUNDS, oneAttemptPerGuess: true },
  );
};

/** A proof Apple accepted, for the cases about what happens afterwards. */
const acceptingProof: LoginProof = async () => {};

// ---------------------------------------------------------------------------
// The pool-backed half: the REAL provider, the REAL store, and the fixture's
// injected proof. One case uses these, and it is the one that shows the clear
// happening in production wiring rather than against a stub. The helpers are
// COPIED from `test/grant-lifetime.test.ts` rather than imported, which is this
// repository's habit for test helpers.
// ---------------------------------------------------------------------------

/** The PKCE verifier this file redeems its one code with. Copied, not guessed. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";

/** `BASE64URL(SHA256(ASCII(CODE_VERIFIER)))`. See the source file it came from. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

/** Where Claude on the web asks the code to be sent. */
const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** A rate-limit binding stub that always lets the request through. */
function allowAllLimiter() {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success: true };
    },
  };
}

/**
 * The pool's environment with both limiters replaced, as a COPY.
 *
 * A spread, never a write onto the object `entryEnv()` hands back — the
 * `env-assignment` scan rule refuses that, because the object is shared by every
 * test in a file. The real per-target binding refuses a fourth sign-in per
 * address per minute and nothing clears its windows between runs.
 */
function allowAllEnv(): EntryEnv {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: allowAllLimiter(),
    LOGIN_ID_LIMITER: allowAllLimiter(),
  } as unknown as EntryEnv;
}

/** Drive the fixture Worker through its real fetch, on a real execution context. */
async function callFixtureWorker(
  request: Request,
  env: EntryEnv,
): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Register a real public client through the real registration endpoint. */
async function register(
  env: EntryEnv,
  clientName: string,
  redirectUri: string,
): Promise<string> {
  const response = await callFixtureWorker(
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

/** Sign the LISTED address in through the real provider, and hand back the code. */
async function signInForReal(
  env: EntryEnv,
  clientId: string,
  redirectUri: string,
): Promise<string> {
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    state: "password-pause",
  }).toString();

  const response = await callFixtureWorker(
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

/** Redeem a code at the real token endpoint, for the grant id inside the token. */
async function grantIdFromCode(
  env: EntryEnv,
  clientId: string,
  redirectUri: string,
  code: string,
): Promise<string> {
  const response = await callFixtureWorker(
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
  const body = JSON.parse(text) as { access_token: string };
  const segments = body.access_token.split(":");
  expect(segments).toHaveLength(3);
  return segments[1] as string;
}

/**
 * Delete a grant, every token under it, and the client record (hygiene rule 4).
 *
 * Serial, one delete at a time. Grants no longer expire since plan 12-01, so
 * nothing sweeps them and a case that minted one has to clean up after itself.
 */
async function forgetGrant(
  userId: string,
  grantId: string,
  clientId: string,
): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  const listed = await kv.list({ prefix: `token:${userId}:${grantId}:` });
  for (const key of listed.keys) {
    await kv.delete(key.name);
  }
  await kv.delete(`grant:${userId}:${grantId}`);
  await kv.delete(`client:${clientId}`);
}

/** How many seconds from now the reported expiry is. Null when there is none. */
function secondsOut(expiration: number | null): number | null {
  if (expiration === null) return null;
  return expiration - Math.floor(Date.now() / 1000);
}

/**
 * A conversation that refuses the authentication attempts, as iCloud would.
 *
 * Copied from `test/service.test.ts`'s own helper rather than imported, which
 * is this repository's habit for test helpers. Leaving `fallbackText` out is
 * load-bearing there and here: a script that answered a second attempt anyway
 * would let an unwanted one pass on a reply the fixture happened to provide.
 */
function refusedAuth(firstText: string, fallbackText?: string): FakeDuplex {
  const fallback =
    fallbackText === undefined ? [] : [taggedNo("a3", fallbackText)];
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedNo("a2", firstText),
    ...fallback,
    logoutExchange(fallbackText === undefined ? "a3" : "a4"),
  ]);
}

/**
 * A conversation that answers both authentication attempts `BAD`.
 *
 * `taggedNo` is what `refusedAuth` scripts, and the status is exactly what
 * separates these two cases — so this cannot be a parameter on that helper
 * without the helper's name becoming a lie. Both attempts are answered, because
 * a tool call does not pass `oneAttemptPerGuess` and a script that ran out of
 * turns would fail on the read timeout rather than on the classification.
 */
function badAuth(text = "syntax error"): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedBad("a2", text),
    taggedBad("a3", text),
    logoutExchange("a4"),
  ]);
}

/** The session shape a tool call takes: authenticated state only, no mailbox. */
function proveOver(duplex: FakeDuplex, principal: Principal): Promise<string> {
  return withMailSessionOver(
    duplex,
    principal,
    createSessionGate(),
    null,
    null,
    async () => "unreached",
    FAST_BOUNDS,
  );
}

/** A fully well-formed 2026-07-28 `tools/call`, as `test/door.test.ts` builds one. */
function toolCall(name: string): Request {
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: DEPLOYED_HOSTNAME,
      "Mcp-Method": "tools/call",
      "Mcp-Name": name,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: {},
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/** One tool answer, read off the door's response. */
interface ToolAnswer {
  readonly status: number;
  readonly isError: boolean;
  readonly body: Record<string, unknown>;
}

/**
 * Call one tool through the REAL door, carrying this file's grant.
 *
 * The props go onto the pool's own execution context, the way
 * `test/door.test.ts` does it, so the handler downstream sees the very context
 * the door saw. No OAuth grant is completed, so nothing here revokes anything.
 */
async function callTool(name: string): Promise<ToolAnswer> {
  const ctx = createExecutionContext();
  Object.defineProperty(ctx, "props", {
    value: {
      v: 1,
      appleId: PAUSED_APPLE_ID,
      appPassword: PAUSED_APP_PASSWORD,
    },
    enumerable: true,
  });
  const response = await door.fetch(toolCall(name), entryEnv(), ctx);
  await waitOnExecutionContext(ctx);

  const text = await response.text();
  const trimmed = text.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());

  let message: Record<string, unknown> | null = null;
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        message = parsed as Record<string, unknown>;
        break;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  expect(message, "the response holds no JSON-RPC message").not.toBeNull();

  const result = (message as Record<string, unknown>).result as
    | { isError?: boolean; content?: { text?: string }[] }
    | undefined;
  expect(result, "the tool call has no result").toBeDefined();

  const parsedBody: unknown = JSON.parse(result?.content?.[0]?.text ?? "null");
  return {
    status: response.status,
    isError: result?.isError === true,
    body:
      typeof parsedBody === "object" &&
      parsedBody !== null &&
      !Array.isArray(parsedBody)
        ? (parsedBody as Record<string, unknown>)
        : {},
  };
}

describe("LIFE-04: the dead-password pause", () => {
  // Titled so `-t "LIFE-04"` matches. 12-VALIDATION.md ships that filter, and a
  // name filter that matches nothing passes SILENTLY — which would leave the
  // row looking covered while measuring nothing.

  // The DAV cases replace the global fetch. Restoring it after every case,
  // rather than after the block, is what keeps a stub from answering a
  // neighbour's request — the tool-layer cases below it call the real door.
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("the guard at the door", () => {
    it("is fifteen minutes, which is over the store's minimum TTL", () => {
      // CONTEXT chose the top of the roadmap's ten-to-fifteen range, because
      // Apple's lockout threshold is unpublished and waiting costs less than a
      // locked account. Pinned here so a later change to the constant is a
      // decision rather than an edit.
      expect(PASSWORD_PAUSE_SECONDS).toBe(900);
      expect(PASSWORD_PAUSE_SECONDS).toBeGreaterThanOrEqual(60);
    });

    it("hands back the very object the promise resolved to when nothing is paused", async () => {
      // Never a spread and never a clone: the password reader answers only the
      // object the constructor built (D-16).
      const promise = unarmedPrincipal();
      const original = await promise;
      const guarded = await guardAgainstPause(promise, entryEnv().OAUTH_KV);
      expect(guarded).toBe(original);
    });

    it("rejects with the auth error while a marker exists", async () => {
      try {
        await setMarker();
        await expect(
          guardAgainstPause(unarmedPrincipal(), entryEnv().OAUTH_KV),
        ).rejects.toBeInstanceOf(ImapAuthError);
      } finally {
        await forgetMarker();
      }
    });

    it("carries on when the store's read THROWS (fail open)", async () => {
      // The OPPOSITE of the allow-list read, deliberately. The pause is a brake
      // on attempts at Apple, not access control, so a store fault must not
      // turn into every tool saying the password was refused.
      const kv = {
        get(): never {
          throw new Error("the store is unreachable");
        },
        async put(): Promise<void> {},
        async delete(): Promise<void> {},
      } as unknown as KVNamespace;

      const promise = unarmedPrincipal();
      const original = await promise;
      expect(await guardAgainstPause(promise, kv)).toBe(original);
    });

    it("carries on when the store's read REJECTS (fail open)", async () => {
      const kv = {
        async get(): Promise<string | null> {
          throw new Error("the store is unreachable");
        },
        async put(): Promise<void> {},
        async delete(): Promise<void> {},
      } as unknown as KVNamespace;

      const promise = unarmedPrincipal();
      const original = await promise;
      expect(await guardAgainstPause(promise, kv)).toBe(original);
    });
  });

  describe("sets the pause", () => {
    it("when Apple refuses an ARMED principal's saved password on the mail path", async () => {
      try {
        const principal = await armedPrincipal();
        await expect(
          proveOver(
            refusedAuth(AUTH_REJECTED_LEGACY_TEXT, AUTH_REJECTED_TEXT),
            principal,
          ),
        ).rejects.toBeInstanceOf(ImapAuthError);

        const marker = await readMarker();
        expect(marker.value, "Apple refused and no marker was written").toBe("1");
        const out = secondsOut(marker.expiration);
        expect(out).not.toBeNull();
        expect(out as number).toBeGreaterThan(880);
        expect(out as number).toBeLessThan(920);
      } finally {
        await forgetMarker();
      }
    });

    it("when iCloud answers a DAV request 401 for an ARMED principal", async () => {
      try {
        vi.stubGlobal("fetch", statusStub(401).fetch);
        const davFetch = createDavFetch(armedPrincipal());

        expect(await raise(() => davFetch(DAV_TARGET))).toBeInstanceOf(
          DavAuthError,
        );
        expect((await readMarker()).value).toBe("1");
      } finally {
        await forgetMarker();
      }
    });

    it("when Apple refuses an ARMED principal inside the mail diagnostic", async () => {
      try {
        const principal = await armedPrincipal();
        const { failed, error } = await runDiagnosticOver(
          refusedAuth(AUTH_REJECTED_LEGACY_TEXT, AUTH_REJECTED_TEXT),
          principal,
          1,
        );

        expect(failed).toBe(true);
        expect(error).toBeInstanceOf(ImapAuthError);
        expect((await readMarker()).value).toBe("1");
      } finally {
        await forgetMarker();
      }
    });

    it.each([
      ["prose only, in the wording a real server uses", AUTH_REFUSED_PROSE_TEXT],
      ["prose that never mentions the credential at all", AUTH_UNCLASSIFIED_TEXT],
    ])("when Apple refuses with %s and no bracketed code", async (_l, text) => {
      // WR-02, and the reversal of iteration 1. Owner decision, 2026-09-22.
      // Classification is by EXCLUSION, so a refusal carrying no response code
      // is a dead password. The allow-list version answered false to both of
      // these rows, which — if that is what `imap.mail.me.com` actually sends —
      // left LIFE-04's mail-path brake never firing in production at all, and
      // every tool call spending another attempt at an unpublished lockout
      // threshold. The second row is deliberately availability-flavoured: this
      // must not pass because the prose happened to say "authentication".
      try {
        const principal = await armedPrincipal();
        await expect(
          proveOver(refusedAuth(text, text), principal),
        ).rejects.toBeInstanceOf(ImapAuthError);

        expect(
          (await readMarker()).value,
          "a code-less refusal left the account retrying against Apple",
        ).toBe("1");
      } finally {
        await forgetMarker();
      }
    });

    it.each([
      ["the FIRST", AUTH_REJECTED_TEXT, AUTH_SERVER_FAULT_TEXT],
      ["the SECOND", AUTH_SERVER_FAULT_TEXT, AUTH_REJECTED_TEXT],
    ])(
      "when only %s attempt names a credential condition",
      async (_which, first, second) => {
        // IN-03. `credentialRefused` is `refusal(login) || refusal(sasl)`, and
        // until these two rows existed both positive cases carried the same
        // text twice — so either operand could be deleted and the suite stayed
        // green. Each row here reds a different deletion, which is the only
        // reason the comment at that line is worth believing.
        try {
          const principal = await armedPrincipal();
          await expect(
            proveOver(refusedAuth(first, second), principal),
          ).rejects.toBeInstanceOf(ImapAuthError);

          expect(
            (await readMarker()).value,
            "one attempt named the credential and the other reply won",
          ).toBe("1");
        } finally {
          await forgetMarker();
        }
      },
    );

    it("never, for an UN-ARMED principal refused the same way", async () => {
      // The login page's shape. This is the whole defence against a stranger
      // who knows a listed address pausing that person's working apps: only a
      // principal the DOOR built is armed, and arming is an object identity in
      // a private WeakMap rather than a flag anybody can set.
      try {
        const principal = await unarmedPrincipal();
        await expect(
          proveOver(
            refusedAuth(AUTH_REJECTED_LEGACY_TEXT, AUTH_REJECTED_TEXT),
            principal,
          ),
        ).rejects.toBeInstanceOf(ImapAuthError);

        expect(
          (await readMarker()).value,
          "an un-armed refusal wrote a marker",
        ).toBeNull();
      } finally {
        await forgetMarker();
      }
    });
  });

  describe("a paused call never reaches Apple", () => {
    it("answers the reconnect message from the account tool, which opens no socket", async () => {
      try {
        await setMarker();
        const answer = await callTool(ACCOUNT_TOOL);

        // Not a 401. The address is still listed and the grant is still
        // well-formed; the tool is what tells the client, not a challenge.
        expect(answer.status).toBe(200);
        expect(answer.isError, "the tool did not report a failure").toBe(true);
        expect(answer.body.category).toBe("auth_failed");
        // The message half of LIFE-04, already shipped in Phase 11. It says to
        // reconnect and that retrying will not help.
        expect(answer.body.message).toBe(SAFE_MESSAGES.auth_failed);
        expect(answer.body.signedInAs).toBeUndefined();
      } finally {
        await forgetMarker();
      }
    });

    it("answers a mail tool with the reconnect message, so no socket opened", async () => {
      // The mail tools are the reason the pause exists: each one opens a socket
      // and spends an attempt at Apple. A paused one answers before that. The
      // mail DIAGNOSTIC is deliberately not the tool used here — it is exempt
      // from the pause (WR-04, owner decision 2026-09-22) and has its own block
      // below.
      try {
        await setMarker();
        const answer = await callTool(MAIL_TOOL);

        expect(answer.status).toBe(200);
        expect(answer.isError).toBe(true);
        expect(answer.body.category).toBe("auth_failed");
        expect(answer.body.message).toBe(SAFE_MESSAGES.auth_failed);
        // A mail tool's answer carries the folder listing on success. Its
        // absence is what says the session never ran.
        expect(answer.body.folders).toBeUndefined();
      } finally {
        await forgetMarker();
      }
    });

    it("leaves the expiry alone, so retrying never extends the pause", async () => {
      try {
        await setMarker();
        const before = (await readMarker()).expiration;
        expect(before).not.toBeNull();

        await callTool(ACCOUNT_TOOL);
        await callTool(MAIL_TOOL);

        expect((await readMarker()).expiration).toBe(before);
      } finally {
        await forgetMarker();
      }
    });

    it("the control: with no marker, the account tool answers the masked address", async () => {
      // Without this the three cases above are vacuous: a door that refused
      // every request would pass all of them.
      await forgetMarker();
      const answer = await callTool(ACCOUNT_TOOL);

      expect(answer.status).toBe(200);
      expect(answer.isError, "the control was refused").toBe(false);
      expect(answer.body.signedInAs).toBe(maskAppleId(PAUSED_APPLE_ID));
      // The standing rule still holds on this path: the full address never
      // appears in a tool answer.
      expect(JSON.stringify(answer.body)).not.toContain(PAUSED_APPLE_ID);
    });

    it("sends ZERO DAV requests while paused, against one in the control", async () => {
      // The sharpest form of "never reaches Apple" this file can take: a count
      // of calls at the transport seam, not an inference from a status code.
      try {
        await setMarker();
        const pausedStub = statusStub(207);
        vi.stubGlobal("fetch", pausedStub.fetch);

        expect(
          await raise(() => createDavFetch(armedPrincipal())(DAV_TARGET)),
        ).toBeInstanceOf(DavAuthError);
        expect(
          pausedStub.calls.length,
          "a paused DAV call still reached the network",
        ).toBe(0);

        // The control, with the marker gone. Without it a stub that was never
        // installed would pass the assertion above.
        await forgetMarker();
        const openStub = statusStub(207);
        vi.stubGlobal("fetch", openStub.fetch);

        const response = await createDavFetch(armedPrincipal())(DAV_TARGET);
        expect(response.status).toBe(207);
        expect(openStub.calls).toHaveLength(1);
      } finally {
        await forgetMarker();
      }
    });
  });

  describe("the two diagnostics answer THROUGH a pause", () => {
    // WR-04, and an owner decision of 2026-09-22 that reverses
    // `12-02-SUMMARY.md`'s "`account_whoami` does not bypass the pause. Same
    // principal, same answer, same recovery." It does not bypass it and still
    // does not; the two DIAGNOSTICS do, because a user who is told to reconnect
    // must have some way of finding out whether reconnecting is the answer.
    //
    // The mail diagnostic is not driven end to end anywhere in this block, and
    // that is deliberate rather than an omission: past the exemption it calls
    // the real `connectImap()`, and no automated job in this repository may open
    // a socket to Apple (D-09). What is driven instead is the exemption itself,
    // which is the entire behavioural difference for that tool — its first line
    // is `await principal` — plus a source-text assertion that it is one of the
    // two registrations wired to it. `dav_diagnose` IS driven end to end through
    // the real door, over a stubbed transport, so the mechanism has a full
    // behavioural proof at the far end of the same wire.

    it("hands the diagnostics the very principal the guarded promise refuses", async () => {
      try {
        await setMarker();
        const source = unarmedPrincipal();
        const guarded = guardAgainstPause(source, entryEnv().OAUTH_KV);

        // The refusal every other tool gets, unchanged.
        expect(await raise(() => guarded)).toBeInstanceOf(ImapAuthError);

        // The same object, not a copy. `src/principal.ts`'s password reader
        // answers only the one object a constructor returned (D-16), so a clone
        // here would reach no credential at all.
        expect(await answersDuringPause(guarded)).toBe(await source);
      } finally {
        await forgetMarker();
      }
    });

    it("exempts ONLY the promise the guard itself returned", async () => {
      // The fail-closed half. The exemption is keyed by the very promise object
      // the guard handed back, so there is no value a caller can construct that
      // buys one — it can only hand back something it was given. Anything else
      // comes back unchanged, which means still guarded.
      try {
        await setMarker();
        const guarded = guardAgainstPause(
          unarmedPrincipal(),
          entryEnv().OAUTH_KV,
        );

        // A promise DERIVED from the guarded one is a different object, and a
        // look-alike is not a key. It gets itself back, so it still rejects.
        const derived = guarded.then((actor) => actor);
        expect(answersDuringPause(derived)).toBe(derived);
        expect(await raise(() => derived)).toBeInstanceOf(ImapAuthError);

        // And a promise that never went near the guard is handed straight back.
        const never = unarmedPrincipal();
        expect(answersDuringPause(never)).toBe(never);
      } finally {
        await forgetMarker();
      }
    });

    it("still ARMS the exempt principal, so a diagnostic refusal keeps the pause", async () => {
      // The exemption removes the refusal, not the arming. A diagnostic that
      // reaches Apple and is refused still reports — otherwise a user could hold
      // a dead password open indefinitely by running a diagnostic.
      try {
        const exempt = await answersDuringPause(armedPrincipal());
        const { failed, error } = await runDiagnosticOver(
          refusedAuth(AUTH_REJECTED_LEGACY_TEXT, AUTH_REJECTED_TEXT),
          exempt,
          1,
        );

        expect(failed).toBe(true);
        expect(error).toBeInstanceOf(ImapAuthError);
        expect(
          (await readMarker()).value,
          "an exempt principal reported nothing, so the pause never starts",
        ).toBe("1");
      } finally {
        await forgetMarker();
      }
    });

    it("lets dav_diagnose reach the network while every other DAV tool cannot", async () => {
      // The end-to-end half, through the REAL door with a live marker. The
      // assertion is a COUNT at the transport seam, which is the mirror image of
      // "sends ZERO DAV requests while paused" above — and the two together are
      // what say the exemption is narrow rather than a hole.
      try {
        await setMarker();
        const stub = statusStub(207);
        vi.stubGlobal("fetch", stub.fetch);

        const diagnosed = await callTool(DAV_DIAGNOSTIC);
        expect(
          stub.calls.length,
          "the pause silenced the tool that would explain the pause",
        ).toBeGreaterThan(0);
        // It got past the door's gate; what the stubbed transport then makes of
        // the discovery is not this file's business. What IS this file's
        // business is that the answer is not the pause's own refusal.
        expect(diagnosed.body.category).not.toBe("auth_failed");

        const reached = stub.calls.length;
        const refused = await callTool(CALENDAR_TOOL);

        expect(refused.isError, "a paused calendar call was served").toBe(true);
        expect(refused.body.category).toBe("auth_failed");
        expect(refused.body.message).toBe(SAFE_MESSAGES.auth_failed);
        expect(
          stub.calls.length,
          "a paused calendar call still reached the network",
        ).toBe(reached);
      } finally {
        await forgetMarker();
      }
    });

    it("the control: the account tool is still refused by the same marker", async () => {
      // Without this the case above is vacuous in the direction that matters —
      // a door that had stopped checking the pause at all would pass it. This is
      // also the decision itself, pinned: `account_whoami` names an account, it
      // does not explain a failure, so it is NOT exempt.
      try {
        await setMarker();
        const answer = await callTool(ACCOUNT_TOOL);

        expect(answer.isError).toBe(true);
        expect(answer.body.category).toBe("auth_failed");
        expect(answer.body.signedInAs).toBeUndefined();
      } finally {
        await forgetMarker();
      }
    });

    it("wires the exemption to exactly the two diagnostics and nothing else", () => {
      // The mail diagnostic's half of the proof, in the idiom `test/door.test.ts`
      // uses for a claim about wiring that cannot be driven — see the block
      // comment above for why driving it would open a socket to Apple.
      expect(
        SERVER_SOURCE.length,
        "the ?raw import of src/mcp/server.ts loaded nothing",
      ).toBeGreaterThan(1000);
      expect(SERVER_SOURCE).toContain("createServerFactory");

      // Granted once, from the guarded promise, and by the only function that
      // can grant it.
      const grants = SERVER_SOURCE.match(/answersDuringPause\(/g) ?? [];
      expect(
        grants.length,
        "the exemption is granted somewhere other than the one derivation",
      ).toBe(1);
      expect(SERVER_SOURCE).toContain(
        "const unpaused = answersDuringPause(principal);",
      );

      // Every registration that receives it, by name. A registrar added to this
      // list is a tool that answers while a user is paused, which is a change to
      // the safety boundary rather than a refactor.
      expect(SERVER_SOURCE).toContain("registerDiagnoseTool(server, unpaused)");
      expect(SERVER_SOURCE).toContain(
        "registerDavDiagnoseTool(server, davFetch, unpaused)",
      );
      // The shared DAV fetch takes it too, because one queue per request is
      // deliberate and a second fetch would be a second queue.
      expect(SERVER_SOURCE).toContain("createDavFetch(unpaused)");

      // And the count, which is what catches a THIRD tool quietly acquiring it.
      // Comments are stripped first: the file discusses `unpaused` at length
      // above the code, and a prose mention is not a registration.
      const code = SERVER_SOURCE.split("\n")
        .filter((line) => !line.trim().startsWith("//"))
        .join("\n");
      const uses = code.match(/\bunpaused\b/g) ?? [];
      expect(
        uses.length,
        "a tool other than the two diagnostics and their shared DAV fetch takes the unpaused principal",
      ).toBe(4);
    });
  });

  describe("never sets the pause", () => {
    // Every case here runs with an ARMED principal, so the only thing standing
    // between the failure and a marker is WHERE the report is called. A case
    // that used an un-armed principal would pass whatever the report sites did.

    it("on a connection-limit reply, which is a throttle and not a refusal", async () => {
      try {
        const principal = await armedPrincipal();
        expect(
          await raise(() =>
            proveOver(refusedAuth(CONNECTION_LIMIT_TEXT), principal),
          ),
        ).toBeInstanceOf(ImapThrottleError);

        expect(
          (await readMarker()).value,
          "a briefly busy server paused a working account",
        ).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it.each([
      ["a [SERVERBUG] fault, which is Apple's problem and not the password", AUTH_SERVER_FAULT_TEXT],
      ["a [CONTACTADMIN] fault, which needs a human at Apple and not a new password", AUTH_CONTACTADMIN_TEXT],
    ])("on %s", async (_label, text) => {
      // CR-02, kept and narrowed by WR-02. Authentication does NOT succeed on
      // either of these replies, so both land in the same `authenticated: false`
      // branch a real credential refusal lands in. These two are the ENTIRE
      // exclusion list now — a reply carrying no code at all pauses, and the
      // matching rows in `sets the pause` above are what stop this list being
      // widened back out to swallow a genuine refusal.
      try {
        const principal = await armedPrincipal();
        expect(
          await raise(() => proveOver(refusedAuth(text, text), principal)),
        ).toBeInstanceOf(ImapAuthError);

        expect(
          (await readMarker()).value,
          "a fault at Apple's end paused a working account",
        ).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a BAD, which is a protocol error of our own making", async () => {
      // WR-02's other exclusion, and the one that is not about Apple at all. A
      // `BAD` says this client sent something the server could not parse. The
      // password is not the subject, and pausing on it would turn one of our own
      // bugs into fifteen minutes of telling the user to reconnect.
      try {
        const principal = await armedPrincipal();
        expect(
          await raise(() => proveOver(badAuth(), principal)),
        ).toBeInstanceOf(ImapAuthError);

        expect(
          (await readMarker()).value,
          "a protocol error told the user their password was dead",
        ).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a server fault inside the mail diagnostic either", async () => {
      try {
        const principal = await armedPrincipal();
        const { failed, error } = await runDiagnosticOver(
          refusedAuth(AUTH_SERVER_FAULT_TEXT, AUTH_SERVER_FAULT_TEXT),
          principal,
          1,
        );

        expect(failed).toBe(true);
        expect(error).toBeInstanceOf(ImapAuthError);
        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("and the diagnostic is still REACHABLE after a server-error reply", async () => {
      // The cost of getting CR-02 wrong, stated as a behaviour rather than as
      // an absent key. The pause rides in the principal promise the door hands
      // every tool, so a marker written by the mail path above would make
      // `armedPrincipal()` reject and the diagnostic would never open its
      // socket. That it produces a report at all — with Apple's own reply text
      // in it — is the assertion that the tool which explains this failure was
      // not silenced by it.
      try {
        const principal = await armedPrincipal();
        expect(
          await raise(() =>
            proveOver(
              refusedAuth(AUTH_SERVER_FAULT_TEXT, AUTH_SERVER_FAULT_TEXT),
              principal,
            ),
          ),
        ).toBeInstanceOf(ImapAuthError);

        // A SECOND call, through the same gate the door puts in front of every
        // tool. Under the old behaviour this line rejects before any socket.
        const second = await armedPrincipal();
        const { failed, report } = await runDiagnosticOver(
          refusedAuth(AUTH_SERVER_FAULT_TEXT, AUTH_SERVER_FAULT_TEXT),
          second,
          1,
        );

        expect(failed).toBe(true);
        expect(
          report.tlsEstablished,
          "the diagnostic never reached the server, so the pause silenced it",
        ).toBe(true);
        expect(report.authFailureDetail).toContain("SERVERBUG");
        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a transport that never establishes", async () => {
      try {
        const principal = await armedPrincipal();
        expect(
          await raise(() => proveOver(createFailingDuplex(), principal)),
        ).toBeInstanceOf(ImapConnectError);

        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a DAV 403, which can be a write to a read-only shared calendar", async () => {
      // The status mapping folds 401 and 403 into one error on purpose, so the
      // report cannot live inside it. This is the case that holds that apart.
      try {
        vi.stubGlobal("fetch", statusStub(403).fetch);
        expect(
          await raise(() => createDavFetch(armedPrincipal())(DAV_TARGET)),
        ).toBeInstanceOf(DavAuthError);

        expect(
          (await readMarker()).value,
          "a 403 paused the account, so a read-only calendar write would too",
        ).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it.each([429, 503])("on a DAV %i, which is a throttle", async (status) => {
      try {
        vi.stubGlobal("fetch", statusStub(status).fetch);
        expect(
          await raise(() => createDavFetch(armedPrincipal())(DAV_TARGET)),
        ).toBeInstanceOf(DavThrottleError);

        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a DAV transport failure, which carries no status at all", async () => {
      try {
        vi.stubGlobal("fetch", failingStub().fetch);
        expect(
          await raise(() => createDavFetch(armedPrincipal())(DAV_TARGET)),
        ).toBeInstanceOf(DavConnectError);

        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a credential THIS SERVER refused, before Apple was asked", async () => {
      // A password holding a control character. `principalFromProps` refuses it
      // (D-19), so no principal exists to arm and no socket ever opens. It
      // raises the very same auth error Apple's refusal raises, which is exactly
      // why the report cannot key on the error type.
      const ctx = createExecutionContext();
      Object.defineProperty(ctx, "props", {
        value: {
          v: 1,
          appleId: PAUSED_APPLE_ID,
          appPassword: `pppp-pppp\u000d-pppp`,
        },
        enumerable: true,
      });

      try {
        const response = await door.fetch(
          toolCall(MAIL_DIAGNOSTIC),
          entryEnv(),
          ctx,
        );
        await waitOnExecutionContext(ctx);
        expect(response.status).toBe(200);

        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a staging secret that was never provisioned", async () => {
      // `mintUploadUrl` raises the auth error for an absent binding, and it
      // takes a user id rather than a principal — so there is nothing armed for
      // it to report through, by construction. Pinned anyway: the shape a later
      // phase would reach for is passing the principal down here.
      const userId = await userIdFor(PAUSED_APPLE_ID);
      const env = {
        ...entryEnv(),
        R2_ACCOUNT_ID: undefined,
        R2_ACCESS_KEY_ID: undefined,
        R2_SECRET_ACCESS_KEY: undefined,
      } as unknown as Env;

      try {
        expect(
          await raise(() =>
            mintUploadUrl(env, userId, {
              key: `staging/${userId}/probe`,
              contentType: "text/plain",
              contentLength: 1,
              filename: "probe.txt",
            }),
          ),
        ).toBeInstanceOf(ImapAuthError);

        expect((await readMarker()).value).toBeNull();
      } finally {
        await forgetMarker();
      }
    });

    it("on a REFUSED SIGN-IN, so a stranger cannot pause somebody's working apps", async () => {
      // T-12-02-01. The proof here is the real mail session over a refusing
      // duplex, which runs the very report line the mail path runs. The login
      // page's principal is never armed, so the report finds nothing — and that
      // is structural rather than a flag anybody could set.
      const record = loginRecorder();
      const response = await createLoginHandler(
        refusingProof,
        TEST_FLOOR_MS,
      ).fetch(loginPost(PAUSED_APPLE_ID), loginStubEnv(record, PAUSED_APPLE_ID));

      // The refusal the login page answers a bad credential with: the form
      // again, at 401. Asserted so a case that passed because the request was
      // refused for some earlier reason — an unlisted address, a limiter trip —
      // cannot look like the one being measured.
      expect(response.status).toBe(401);
      expect(record.calls).not.toContain("completeAuthorization");
      // Not "no marker in the store" — no WRITE was even attempted. A listing
      // could not tell that from a request that never reached the store.
      expect(
        record.puts.filter((key) => key.startsWith(PASSWORD_PAUSE_KEY_PREFIX)),
        "a refused sign-in asked the store to write a pause key",
      ).toHaveLength(0);
    });
  });

  describe("clears the pause", () => {
    it("on a sign-in Apple accepted, BEFORE the authorization is completed", async () => {
      // Without the clear, someone who has just made a fresh app-specific
      // password still waits out the pause and reasonably concludes the fix did
      // not work. The ordering is read off one shared list, so "before" is
      // observed rather than assumed.
      const record = loginRecorder();
      const response = await createLoginHandler(
        acceptingProof,
        TEST_FLOOR_MS,
      ).fetch(loginPost(PAUSED_APPLE_ID), loginStubEnv(record, PAUSED_APPLE_ID));

      expect(response.status).toBe(302);

      const key = await markerKey(PAUSED_APPLE_ID);
      expect(record.deletes, "the pause was never cleared").toContain(key);

      const clearedAt = record.calls.indexOf(`delete:${key}`);
      const completedAt = record.calls.indexOf("completeAuthorization");
      expect(clearedAt).toBeGreaterThanOrEqual(0);
      expect(completedAt).toBeGreaterThanOrEqual(0);
      expect(
        clearedAt,
        "the pause was cleared after the ceremony rather than before it",
      ).toBeLessThan(completedAt);
    });

    it("through the REAL provider and the REAL store, on a good sign-in", async () => {
      // The one case in this file that touches the pool's own store with the
      // listed address, and it is a GOOD sign-in — which writes no failure
      // record, so it spends nothing a sibling suite has to live with.
      const env = allowAllEnv();
      const userId = await userIdFor(LISTED_APPLE_ID);
      let clientId: string | null = null;
      let grantId: string | null = null;

      try {
        await setMarker(LISTED_APPLE_ID);
        expect((await readMarker(LISTED_APPLE_ID)).value).toBe("1");

        clientId = await register(
          env,
          "password-pause probe",
          CLAUDE_WEB_REDIRECT,
        );
        const code = await signInForReal(env, clientId, CLAUDE_WEB_REDIRECT);
        grantId = await grantIdFromCode(
          env,
          clientId,
          CLAUDE_WEB_REDIRECT,
          code,
        );

        expect(
          (await readMarker(LISTED_APPLE_ID)).value,
          "a good sign-in through the real wiring left the pause in place",
        ).toBeNull();
      } finally {
        await forgetMarker(LISTED_APPLE_ID);
        if (clientId !== null && grantId !== null) {
          await forgetGrant(userId, grantId, clientId);
        } else if (clientId !== null) {
          await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
        }
      }
    });
  });
});
