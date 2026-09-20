// Two test users, A and B, and the cheapest honest way to be one of them today.
//
// **This file holds no real value.** Both addresses sit under `example.invalid`,
// a name reserved so that it can never resolve, and both passwords are plainly
// fake. They are shaped like app-specific passwords only so the fixture keeps
// working once a later phase starts checking that shape at the login page.
//
// **There are two carriers of "which user" while Phase 9 is under way.**
//
// - `envFor(user)` is the old one. Every exported function at the tool layer
//   that has not been moved yet takes the environment object as its first
//   argument and reads the account from it, so handing a function a copy with
//   B's two values in it IS being user B, as far as that code can tell. It
//   returns a NEW object and never assigns to the ambient one. Assigning would
//   leak B into every later test in the file, and a scan rule rejects it
//   outright.
// - `testPrincipal(user)` is the new one. It is a real principal, built by the
//   real props constructor (Phase 9 D-17).
//
// **Phase 9 swaps `envFor` for the principal, one chain at a time.** The mail
// chain moves in plan 09-04 and the DAV chain in plan 09-05. Each changes one
// line of `toolsFor` below. What the cross-user tests ASSERT does not change,
// which is the point of writing them against the old signatures (D-05).
//
// A and B both differ from the pool's own ambient identity, on purpose. A test
// user that happened to match it could pass by accident. No test may read,
// report or assert on the ambient identity: a local override file may hold a
// live value there.
//
// The user ids are COPIED from the vectors file and never computed. No
// fingerprinting code may exist in a test helper (D-12).

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { createDavFetch } from "../../src/dav/transport";
import type { Env } from "../../src/env";
import { createSessionGate } from "../../src/mail/service";
import { registerCalendarTools } from "../../src/mcp/tools/calendar";
import { registerMailTools } from "../../src/mcp/tools/mail";
import type { Principal } from "../../src/principal";
import { principalFromProps } from "../../src/principal";
import { USER_A_VECTOR, USER_B_VECTOR } from "./user-id-vectors";

/** One test user: who they are, and the user id the spec gives them. */
export interface TestUser {
  readonly label: "A" | "B";
  readonly appleId: string;
  readonly appPassword: string;
  readonly userId: string;
}

/** The user who owns the thing under test. */
export const USER_A: TestUser = {
  label: "A",
  appleId: USER_A_VECTOR.input,
  appPassword: "aaaa-aaaa-aaaa-aaaa",
  userId: USER_A_VECTOR.expected,
};

/** A second, legitimate, signed-in user who has got hold of one of A's values. */
export const USER_B: TestUser = {
  label: "B",
  appleId: USER_B_VECTOR.input,
  appPassword: "bbbb-bbbb-bbbb-bbbb",
  userId: USER_B_VECTOR.expected,
};

/**
 * The environment as `user` would have it: every real binding, and that user's
 * two account values in place of the ambient ones.
 *
 * Both values are overridden, never one. A copy carrying B's address and the
 * ambient password would be a third identity nobody meant to test.
 */
export function envFor(user: TestUser): Env {
  return {
    ...(env as Env),
    APPLE_ID: user.appleId,
    APPLE_APP_PASSWORD: user.appPassword,
  };
}

/**
 * A real principal for `user`, as a promise (D-17).
 *
 * It returns exactly what the REAL props constructor returns, given the one
 * shape that constructor accepts: three keys, `v` set to 1, the Apple ID and
 * the app password. There is no hand-built principal, no test-only export from
 * the principal module and no test-only way into the password store. So the
 * password reader answers for this object for the same reason it answers in
 * production: the real constructor built it.
 *
 * **Never spread or clone what this resolves to (D-16).** The password reader
 * answers only the very object the constructor returned. A copy has the same
 * two fields and gets the auth error. Pass the promise on as it is, or await it
 * and pass that one object on.
 *
 * `envFor` is still the carrier of "which user" for the DAV side. It stays
 * until plan 09-05 moves the DAV fetch onto the principal.
 */
export function testPrincipal(user: TestUser): Promise<Principal> {
  return principalFromProps({
    v: 1,
    appleId: user.appleId,
    appPassword: user.appPassword,
  });
}

/** What one attempt came to: a value, or a refusal. Never a throw. */
export type Attempt<T> =
  | { readonly refused: false; readonly value: T }
  | { readonly refused: true };

/**
 * Run B's action and hand back what happened AS A VALUE.
 *
 * This never throws and never rethrows, and that is the whole reason it exists.
 * The runner turns ANY failure inside an expected-fail body into a pass and
 * discards the error. So once a fix makes B's call throw, a body that let the
 * throw escape would keep "failing as expected" for ever, and the fix would
 * never be noticed. Turning the throw into `refused: true` leaves the leak
 * assertion as the only thing in the body that can fail.
 *
 * The caught value is deliberately never bound and never read: a refusal is a
 * refusal, and nothing about an error object belongs in a test report.
 */
export async function attempt<T>(run: () => Promise<T>): Promise<Attempt<T>> {
  try {
    return { refused: false, value: await run() };
  } catch {
    return { refused: true };
  }
}

/**
 * A tool result exactly as a callback in `src/` hands it back.
 *
 * `isError` is optional here because it is optional there. An error result sets
 * it to true. No tool ever sets it to false, so a success result does not carry
 * the field at all. Read it through `readToolResult`, never off this shape.
 */
export interface RecordedToolResult {
  readonly isError?: boolean;
  readonly content: readonly { readonly text: string }[];
}

/** A tool result with both halves parsed, and a yes-or-no answer for failure. */
export interface ParsedToolResult {
  /** Always a boolean, never missing. See `readToolResult` for why. */
  readonly isError: boolean;
  /** The first block, parsed. Null when it would not parse. */
  readonly trusted: Record<string, unknown> | null;
  /** The JSON object inside the fenced second block. Null when it would not parse. */
  readonly untrusted: Record<string, unknown> | null;
}

/** One recorded tool callback. It may return, throw, or reject. */
type RecordedCallback = (
  args: Record<string, unknown>,
) => RecordedToolResult | Promise<RecordedToolResult>;

/**
 * Extra tools for one `toolsFor` call, for tests only.
 *
 * The function is handed a small `register(name, callback)`. It mirrors the
 * extra-tools parameter `createServerFactory` already has in
 * `src/mcp/server.ts`. It exists so a test can register a callback that throws
 * and show that `call` gives null for it. No production tool is registered this
 * way.
 */
export type ExtraTools = (
  register: (name: string, callback: RecordedCallback) => void,
) => void;

/** The registered tools, as one named user would reach them. */
export interface UserTools {
  /** Every recorded tool name, in registration order. */
  readonly names: readonly string[];
  /**
   * Call one tool. Resolves to its result, or to null. Never throws and never
   * rejects.
   */
  call(
    name: string,
    args: Record<string, unknown>,
  ): Promise<RecordedToolResult | null>;
}

/**
 * The registered mail and calendar tool callbacks, for `user`.
 *
 * The repo never builds a real MCP server to call a tool. It hands the
 * registrars a small object that records what they register, in the same
 * three-argument shape `test/dav-tools.test.ts` uses, and then calls the
 * recorded callback. Registration opens no socket and sends no request.
 *
 * **What "for `user`" honestly means today, which is not much (D-05).**
 *
 * - The MAIL callbacks ignore the user completely. `registerMailTools` takes a
 *   server and a gate, and its callbacks read the ambient environment that
 *   `src/mcp/tools/mail.ts` imports for itself. So `toolsFor(USER_A)` and
 *   `toolsFor(USER_B)` make the very same mail call. That is not a flaw in this
 *   fixture. It is the thing the cross-user tests record: the tool layer has no
 *   idea who is calling.
 * - The CALENDAR callbacks carry the user's Basic header, because they send
 *   through the `davFetch` built here from `envFor(user)`. But they still key
 *   the DAV cache by the ambient identity, not by this user.
 *
 * **Phase 9 changes only this function.** When the registrars start taking a
 * signed-in user, this is where that user's principal gets passed in. What the
 * tests ASSERT does not change.
 *
 * **Why `call` never throws.** Inside an expected-fail body the runner counts a
 * throw from ANYWHERE as the expected failure and throws the error away. It is
 * true that today's callbacks catch their own errors and return a result. Do
 * not lean on that. Phase 9 rewires this function, and a callback that started
 * throwing would keep a leak test "failing as expected" for the wrong reason,
 * so the real fix in Phase 10 would go unnoticed. With null instead, the leak
 * test returns early, its body passes, the expected fail turns red, and someone
 * looks.
 *
 * `call` gives null in two cases: no tool has that name, or the callback threw
 * or rejected. `names` tells them apart. A name that is listed and still gives
 * null means the callback threw.
 *
 * The caught value is never bound and never read, for the same reason as in
 * `attempt`: nothing about an error object belongs in a test report.
 */
export function toolsFor(user: TestUser, extra?: ExtraTools): UserTools {
  const recorded: { name: string; callback: RecordedCallback }[] = [];

  const server = {
    registerTool(
      name: string,
      _options: Record<string, unknown>,
      callback: RecordedCallback,
    ): void {
      recorded.push({ name, callback });
    },
  } as unknown as McpServer;

  // **Building the tools must not throw either**, for the same reason `call`
  // must not. A leak test writes `toolsFor(USER_B).call(...)` inside its
  // expected-fail body, so a throw from a registrar would land in that body and
  // count as the expected failure. A registrar that throws leaves whatever was
  // recorded before it. `call` then gives null for a tool that never made it
  // onto the list, the leak test returns early, and the controls and the
  // fixture pins, which assert on `names` and on a real result, go red.
  try {
    registerMailTools(server, createSessionGate());
    registerCalendarTools(server, createDavFetch(envFor(user)));

    // After the real registrations, onto the same list, so an extra tool is
    // reached through the very same `call` path as a real one.
    if (extra !== undefined) {
      extra((name, callback) => {
        recorded.push({ name, callback });
      });
    }
  } catch {
    // Deliberately empty. See the comment above.
  }

  return {
    names: recorded.map((one) => one.name),
    async call(name, args) {
      const tool = recorded.find((one) => one.name === name);
      if (tool === undefined) return null;
      try {
        return await tool.callback(args);
      } catch {
        return null;
      }
    },
  };
}

/** The JSON object in `text`, from its first brace to its last. Null if none. */
function parseObject(text: unknown): Record<string, unknown> | null {
  try {
    if (typeof text !== "string") return null;
    const from = text.indexOf("{");
    const to = text.lastIndexOf("}");
    if (from < 0 || to < from) return null;
    const parsed: unknown = JSON.parse(text.slice(from, to + 1));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Read a tool result into its two parsed halves. Never throws.
 *
 * The first block is the server's own JSON. The second is a fenced block with a
 * notice around a JSON object, so it is read from its outermost brace to its
 * outermost brace. A block that is missing or will not parse comes back as null.
 *
 * **`isError` is compared with true, never passed through.** The field is
 * optional in `src/mcp/untrusted.ts`. Error results set it to true, and no tool
 * ever sets it to false, so a success result has no such field. Passing the raw
 * field through would hand back `undefined` for every success, and then every
 * check that it is false would fail, leak or no leak. Comparing with true makes
 * the answer a real boolean: true only when the raw field is exactly true, and
 * false in every other case, a missing field included.
 */
export function readToolResult(result: RecordedToolResult): ParsedToolResult {
  let trustedText: unknown = null;
  let untrustedText: unknown = null;
  let isError = false;
  try {
    isError = result.isError === true;
    trustedText = result.content[0]?.text;
    untrustedText = result.content[1]?.text;
  } catch {
    // A result with no readable content. Both halves stay null.
  }
  return {
    isError,
    trusted: parseObject(trustedText),
    untrusted: parseObject(untrustedText),
  };
}
