// "Which Apple ID is this connection signed in as?" (LIFE-06, D4).
//
// **What this file proves.** The one masking rule, held to a table of inputs and
// answers, over the same spec rows the folding rule is held to.
//
// The answer a user gets is deliberately MASKED: the first character, three
// bullets, and the domain. It answers the shared-laptop question — which account
// is this connection on — without putting a full address into a response the
// model reads and may quote back into a draft, an event or a later message. That
// exception to the standing rule is recorded in `.claude/CLAUDE.md` § 4.
//
// **The expectations here are this file's own literals.** Nothing below imports
// the masked form from the module under test and compares it with itself. The
// three bullets are written as escapes, and the escape is checked against the
// code point it claims to be, because three bullets, three middle dots and three
// full stops are hard to tell apart in a diff and one of those is not a mask.
//
// **No real value appears here.** Every address is user A's fake from the
// two-user fixture or a row from the spec vectors.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { EntryEnv } from "../src/env";
import { SAFE_MESSAGES } from "../src/errors";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import { signedInAsResult } from "../src/mcp/tools/account";
import { maskAppleId } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";
import { USER_A, testPrincipal } from "./fixtures/two-users";
import { REFUSED, USER_ID_VECTORS } from "./fixtures/user-id-vectors";

/**
 * The mask body: three U+2022 BULLET characters, written as escapes.
 *
 * This file's own constant, never imported from the module under test. Two
 * literals that must agree prove something; one literal compared with itself
 * proves nothing.
 */
const BULLETS = "\u2022\u2022\u2022";

/** What a refused input gets back. The body alone, with nothing around it. */
const REFUSED_MASK = BULLETS;

/** One row: an input, and exactly what must come out. */
interface MaskRow {
  readonly name: string;
  readonly input: unknown;
  readonly expected: string;
}

const MASK_ROWS: readonly MaskRow[] = [
  {
    name: "user A's address",
    input: "user-a@example.invalid",
    expected: `u${BULLETS}@example.invalid`,
  },
  {
    name: "padded and mixed case: the folding runs first",
    input: "  User-A@Example.Invalid ",
    expected: `u${BULLETS}@example.invalid`,
  },
  {
    name: "a one-character local part",
    input: "a@example.invalid",
    expected: `a${BULLETS}@example.invalid`,
  },
  {
    name: "a `+tag` address: the tag goes with the rest of the local part",
    input: "user-a+tag@example.invalid",
    expected: `u${BULLETS}@example.invalid`,
  },
  {
    name: "a different domain is kept as it is",
    input: "someone@icloud.com",
    expected: `s${BULLETS}@icloud.com`,
  },
  { name: "an empty string", input: "", expected: REFUSED_MASK },
  { name: "white space only", input: "   ", expected: REFUSED_MASK },
  { name: "no at sign", input: "no-at-sign", expected: REFUSED_MASK },
  { name: "two at signs", input: "user-a@example@invalid", expected: REFUSED_MASK },
  { name: "an empty local part", input: "@example.invalid", expected: REFUSED_MASK },
  { name: "an empty domain", input: "user-a@", expected: REFUSED_MASK },
  {
    name: "a character outside printable ASCII",
    input: "caf\u00e9@example.invalid",
    expected: REFUSED_MASK,
  },
  {
    name: "255 typed characters, one over the cap",
    input: `${"a".repeat(239)}@example.invalid`,
    expected: REFUSED_MASK,
  },
  { name: "a number", input: 42, expected: REFUSED_MASK },
  { name: "null", input: null, expected: REFUSED_MASK },
  { name: "undefined", input: undefined, expected: REFUSED_MASK },
];

describe("maskAppleId: the one masking rule (LIFE-06, D4)", () => {
  it("masks with three U+2022 bullets, and this file says which character that is", () => {
    // The escape above, checked against the code point it claims. A row that
    // expected three middle dots or three full stops would still read as a
    // mask in a diff, and one of those is not the mask this rule builds.
    expect(BULLETS.length).toBe(3);
    for (const character of BULLETS) {
      expect(character.codePointAt(0)).toBe(0x2022);
    }
  });

  it.each(MASK_ROWS)("$name", ({ input, expected }) => {
    expect(maskAppleId(input)).toBe(expected);
  });

  it("gives exactly three bullets for every input the folding rule refuses", () => {
    const refused = USER_ID_VECTORS.filter((row) => row.expected === REFUSED);
    // A guard on the fixture itself: a table with no refused rows would make
    // the loop below vacuous.
    expect(refused.length, "the spec holds no refused rows").toBeGreaterThan(10);

    for (const row of refused) {
      expect(maskAppleId(row.input), `refused row ${row.name}`).toBe(REFUSED_MASK);
    }
  });

  it("never gives back the local part of an address it accepted", () => {
    const accepted = USER_ID_VECTORS.filter((row) => row.expected !== REFUSED);
    expect(accepted.length, "the spec holds no accepted rows").toBeGreaterThan(5);

    for (const row of accepted) {
      const masked = maskAppleId(row.input);
      const folded = row.input.trim().toLowerCase();
      const localPart = folded.slice(0, folded.indexOf("@"));
      // Every accepted row in the spec has a local part longer than one
      // character, so the first character it keeps cannot be the whole thing.
      expect(localPart.length, `row ${row.name} has a one-character local part`)
        .toBeGreaterThan(1);
      expect(masked, `row ${row.name} leaked its local part`).not.toContain(
        localPart,
      );
      expect(masked, `row ${row.name} came back unchanged`).not.toBe(row.input);
      expect(masked, `row ${row.name} came back as the folded address`).not.toBe(
        folded,
      );
    }
  });

  it("never throws, whatever it is handed", () => {
    const hostile: unknown[] = [
      undefined,
      null,
      0,
      Number.NaN,
      true,
      Symbol("address"),
      {},
      [],
      () => "user-a@example.invalid",
      { toString: () => "user-a@example.invalid" },
      new Date(),
      BigInt(1),
    ];

    for (const value of hostile) {
      expect(() => maskAppleId(value)).not.toThrow();
      expect(maskAppleId(value)).toBe(REFUSED_MASK);
    }
  });
});

// ---------------------------------------------------------------------------
// The tool, through the real door.
//
// The block below drives `createMcpApiHandler()` — the very handler the Worker
// serves — with the props a stored grant carries. No fake server, no recorded
// callback: the claim is that a signed-in person asking this question over the
// real transport gets the masked answer back, and that the address does not
// appear anywhere in the response body.
//
// The helpers are copied from `test/door.test.ts` rather than exported from it,
// which is how every other suite here drives the door.
// ---------------------------------------------------------------------------

const HOSTNAME = DEPLOYED_HOSTNAME;
const ORIGIN = `https://${HOSTNAME}`;

/** The tool under test. */
const ACCOUNT_TOOL = "account_whoami";

/** The door, with nothing injected. Exactly what production builds. */
const door = createMcpApiHandler();

/** Props for one case. `absent` means the context carries no props at all. */
type CaseProps = { absent: true } | { absent: false; props: unknown };

/**
 * The grant the login page mints for someone on the allow list.
 *
 * User A's address is bound into `ALLOWED_APPLE_IDS_SEED` in `vitest.config.ts`
 * precisely so a served case can exist. Both values are user A's fakes from the
 * two-user fixture; no real credential appears in this file.
 */
const LISTED: CaseProps = {
  absent: false,
  props: {
    v: 1,
    appleId: USER_A.appleId,
    appPassword: USER_A.appPassword,
  },
};

/**
 * A listed grant whose stored password this server itself refuses (D-19).
 *
 * The password holds a NUL, written as an escape. `principalFromProps` turns it
 * away before any socket exists, so this case reaches no network either. The
 * door serves it: the door checks the address and never the password.
 */
const REFUSED_CREDENTIAL: CaseProps = {
  absent: false,
  props: {
    v: 1,
    appleId: USER_A.appleId,
    appPassword: "aaaa-aaaa\u0000aaaa-aaaa",
  },
};

/**
 * Drive the door with a context that carries the props under test.
 *
 * Copied from `test/door.test.ts`. The pool's execution context has no props
 * field of its own and the installed type marks it read-only, so the value is
 * defined onto the real context and the MCP handler downstream sees the very
 * same context the door saw.
 */
async function callDoor(
  request: Request,
  caseProps: CaseProps,
  withEnv: EntryEnv = entryEnv(),
): Promise<Response> {
  const ctx = createExecutionContext();
  if (!caseProps.absent) {
    Object.defineProperty(ctx, "props", {
      value: caseProps.props,
      enumerable: true,
    });
  }
  const response = await door.fetch(request, withEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** A fully well-formed 2026-07-28 `tools/call`. */
function toolCall(path: string, name: string = ACCOUNT_TOOL): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
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

/** A well-formed 2026-07-28 `tools/list`. It calls no tool at all. */
function toolsList(path: string): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
      "Mcp-Method": "tools/list",
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

/**
 * The JSON-RPC message in a response body, on either lane.
 *
 * The modern lane answers with a JSON body. Null when the body holds no message.
 */
function rpcMessageIn(bodyText: string): Record<string, unknown> | null {
  const trimmed = bodyText.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  return null;
}

/** The one text item a tool result carries, or null. */
function firstText(message: Record<string, unknown> | null): string | null {
  const result = message?.result as
    | { isError?: boolean; content?: { text?: string }[] }
    | undefined;
  return result?.content?.[0]?.text ?? null;
}

describe("account_whoami: the shaper (LIFE-06)", () => {
  it("answers exactly one field, holding the masked address", async () => {
    const principal = await testPrincipal(USER_A);
    const result = signedInAsResult(principal);

    expect(result.isError, "a success result carries no error flag").toBeUndefined();
    expect(result.content.length, "more than one content item").toBe(1);
    expect(result.content[0]?.type).toBe("text");

    const answer: unknown = JSON.parse(result.content[0]?.text ?? "null");
    expect(answer).toEqual({ signedInAs: `u${BULLETS}@example.invalid` });
  });

  it("carries the address nowhere in its serialized form", async () => {
    const principal = await testPrincipal(USER_A);
    const serialized = JSON.stringify(signedInAsResult(principal));

    // The whole result, not just the field this test named above. A second
    // field added later that happened to hold the address would fail here.
    expect(serialized).not.toContain(USER_A.appleId);
    expect(serialized).toContain(`u${BULLETS}@example.invalid`);
  });

  it("carries no user id, and no field but the one", async () => {
    const principal = await testPrincipal(USER_A);
    const answer = JSON.parse(
      signedInAsResult(principal).content[0]?.text ?? "null",
    ) as Record<string, unknown>;

    expect(Object.keys(answer)).toEqual(["signedInAs"]);
    expect(JSON.stringify(answer)).not.toContain(USER_A.userId);
  });
});

describe("account_whoami: through the real door (LIFE-06)", () => {
  it("is listed on the tool list a signed-in client asks for", async () => {
    const response = await callDoor(toolsList("/mcp"), LISTED);

    expect(response.status).toBe(200);
    const message = rpcMessageIn(await response.text());
    const result = message?.result as { tools?: { name: string }[] } | undefined;
    expect(
      result?.tools?.some((tool) => tool.name === ACCOUNT_TOOL),
      "the tools/list answer does not list the account tool",
    ).toBe(true);
  });

  it("answers the masked address, and the body never holds the real one", async () => {
    const response = await callDoor(toolCall("/mcp"), LISTED);

    expect(response.status, "a listed grant was not served").toBe(200);
    expect(
      response.headers.get("WWW-Authenticate"),
      "a listed grant was sent a challenge",
    ).toBeNull();

    const body = await response.text();
    const message = rpcMessageIn(body);
    expect(message, "the response holds no JSON-RPC message").not.toBeNull();

    const result = message?.result as { isError?: boolean } | undefined;
    expect(result, "the tool call has no result").toBeDefined();
    expect(result?.isError, "the tool reported a failure").not.toBe(true);

    const answer: unknown = JSON.parse(firstText(message) ?? "null");
    expect(answer).toEqual({ signedInAs: `u${BULLETS}@example.invalid` });

    // The end-to-end claim. Not the field, not the result — the WHOLE body the
    // client receives, headers' worth of envelope included.
    expect(body, "the response body holds the full address").not.toContain(
      USER_A.appleId,
    );
    expect(body, "the response body does not hold the mask").toContain(
      `u${BULLETS}@example.invalid`,
    );
  });

  it("answers auth_failed when this server refuses the stored credential", async () => {
    const response = await callDoor(toolCall("/mcp"), REFUSED_CREDENTIAL);

    // The door serves it. It checks the address, never the password, because it
    // cannot know whether Apple would accept one without asking Apple.
    expect(response.status).toBe(200);

    const body = await response.text();
    const message = rpcMessageIn(body);
    const result = message?.result as { isError?: boolean } | undefined;
    expect(result?.isError, "a refused credential did not report a failure").toBe(
      true,
    );

    const answer = JSON.parse(firstText(message) ?? "null") as {
      category?: string;
      message?: string;
    } | null;
    expect(answer?.category).toBe("auth_failed");
    expect(answer?.message).toBe(SAFE_MESSAGES.auth_failed);

    expect(body, "a refusal echoed the address").not.toContain(USER_A.appleId);
    expect(body, "a refusal echoed a mask it should not have built").not.toContain(
      BULLETS,
    );
  });
});
