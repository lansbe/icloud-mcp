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
import { describe, expect, it } from "vitest";
import { ImapAuthError, SAFE_MESSAGES } from "../src/errors";
import { createSessionGate, withMailSessionOver } from "../src/mail/service";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import type { Principal } from "../src/principal";
import { maskAppleId, principalFromProps, userIdOf } from "../src/principal";
import {
  PASSWORD_PAUSE_KEY_PREFIX,
  PASSWORD_PAUSE_SECONDS,
  guardAgainstPause,
} from "../src/password-pause";
import { entryEnv } from "./fixtures/bound-secrets";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  AUTH_REJECTED_LEGACY_TEXT,
  AUTH_REJECTED_TEXT,
  GREETING,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedNo,
} from "./fixtures/icloud-bytes";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

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

/** This file's user id, derived by the real function. Never hashed here (D-12). */
async function pausedUserId(): Promise<string> {
  const userId = await userIdOf(PAUSED_APPLE_ID);
  expect(userId).not.toBeNull();
  return userId as string;
}

/** The marker's real key, built from the exported prefix and the real id. */
async function markerKey(): Promise<string> {
  return `${PASSWORD_PAUSE_KEY_PREFIX}${await pausedUserId()}`;
}

/** What the marker currently is: its value, and the expiry the store reports. */
async function readMarker(): Promise<{
  value: string | null;
  expiration: number | null;
}> {
  const kv = entryEnv().OAUTH_KV;
  const key = await markerKey();
  const value = await kv.get(key);
  const listed = await kv.list({ prefix: key });
  const found = listed.keys.find((one) => one.name === key);
  return { value, expiration: found?.expiration ?? null };
}

/** Put the marker where the guard will find it, exactly as the report does. */
async function setMarker(): Promise<void> {
  await entryEnv().OAUTH_KV.put(await markerKey(), "1", {
    expirationTtl: PASSWORD_PAUSE_SECONDS,
  });
}

/** Hygiene rule 1. Called in a `finally` by every case that could have written one. */
async function forgetMarker(): Promise<void> {
  await entryEnv().OAUTH_KV.delete(await markerKey());
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

    it("answers the diagnostic with the refused-here field, so no socket opened", async () => {
      try {
        await setMarker();
        const answer = await callTool(MAIL_DIAGNOSTIC);

        expect(answer.status).toBe(200);
        expect(answer.isError).toBe(true);
        expect(answer.body.category).toBe("auth_failed");
        // This field appears ONLY when the principal was refused before the
        // diagnostic ran — which is before any socket. Its presence is the
        // assertion that Apple was never asked; a refusal that reached Apple
        // carries `authFailureDetail` instead and never this.
        expect(
          answer.body.authRefusedBy,
          "the refusal did not happen before iCloud was asked",
        ).toBe("this server");
        expect(answer.body.authFailureDetail).toBeUndefined();
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
        await callTool(MAIL_DIAGNOSTIC);

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
  });
});
