// "Which Apple ID is this connection signed in as?" (LIFE-06, D4).
//
// **Two independent claims live in this file, and they no longer share a
// caller.** Since the owner reversed D4 on 2026-09-23 the tool answers with the
// WHOLE address, and `maskAppleId` serves the owner's grants listing instead. So:
//
// - The first block pins the one masking rule, held to a table of inputs and
//   answers over the same spec rows the folding rule is held to. It is the grants
//   listing's mask now. It is kept here, and kept whole, because a function whose
//   only remaining caller is a script is exactly the kind of thing a later
//   session deletes as dead.
// - The second and third blocks pin the tool, whose answer is the address as the
//   grant stored it — no mask, no fold, no trim.
//
// Neither block can now make the other pass. Reverting the tool to the mask
// leaves the table green and turns the tool blocks red; deleting the table leaves
// the tool blocks green. That separation is the point.
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
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";
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
    // WR-05. Keeping "the first character" of a one-character local part keeps
    // all of it, and `a•••@example.invalid` is the whole address
    // plus decoration. Two sites claim this function never hands back a whole
    // address — its docstring and `.claude/CLAUDE.md` § 4 — so this shape keeps no
    // character at all. It was three until 2026-09-23, when the tool stopped
    // calling this function and stopped making the claim.
    name: "a one-character local part keeps NO character",
    input: "a@example.invalid",
    expected: `${BULLETS}@example.invalid`,
  },
  {
    // The same edge after folding, so the rule is measured on the folded length
    // rather than on what was typed.
    name: "a one-character local part, padded and upper case",
    input: "  A@Example.Invalid ",
    expected: `${BULLETS}@example.invalid`,
  },
  {
    // The boundary on the other side: two characters keeps one, which is the
    // ordinary rule. Without this row the branch above could be widened to swallow
    // short local parts generally and nothing would fail.
    name: "a two-character local part keeps its first character",
    input: "ab@example.invalid",
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

describe("maskAppleId: the one masking rule, for the grants listing (LIFE-06)", () => {
  it("masks with three U+2022 bullets, and this file says which character that is", () => {
    // The escape above, checked against the code point it claims. A row that
    // expected three middle dots or three full stops would still read as a
    // mask in a diff, and one of those is not the mask this rule builds.
    expect(BULLETS.length).toBe(3);
    for (const character of BULLETS) {
      expect(character.codePointAt(0)).toBe(0x2022);
    }
  });

  it("has a table with rows in it, in both directions", () => {
    // **A guard on the table itself, in the idiom the two loops below already
    // use.** Without it `MASK_ROWS` can be emptied and this whole block still
    // reports green: `it.each([])` registers nothing and fails nothing, so the
    // table is the one assertion here that cannot notice its own deletion. That
    // was measured on 2026-09-23 — emptying the array left the file passing — and
    // it matters more now than it did while the tool shared this function, because
    // the grants listing is the mask's only remaining caller and this table is its
    // only remaining proof.
    //
    // Both counts, not just the total. A table that had lost every refusal row, or
    // every accepted one, would be half a rule while still looking populated.
    expect(MASK_ROWS.length, "the mask table is empty").toBeGreaterThan(15);
    expect(
      MASK_ROWS.filter((row) => row.expected === REFUSED_MASK).length,
      "the mask table holds no refused rows",
    ).toBeGreaterThan(5);
    expect(
      MASK_ROWS.filter((row) => row.expected !== REFUSED_MASK).length,
      "the mask table holds no accepted rows",
    ).toBeGreaterThan(5);
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
      // Compared against the masked LOCAL PART rather than the whole masked
      // string, which is what lets this run over a one-character local part at
      // all: `example.invalid` contains an `a`, so a whole-string search would
      // report the domain as a leak. It is also the stronger assertion — a leak
      // the domain happened to spell would previously have hidden in it.
      //
      // WR-05 removed the guard that used to sit here excluding one-character
      // rows from this loop. Those rows now keep no character, so there is
      // nothing to exclude.
      const maskedLocal = masked.slice(0, masked.indexOf("@"));
      expect(maskedLocal, `row ${row.name} leaked its local part`).not.toContain(
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
 * The OTHER address on the allow-list seed, as a second listed grant.
 *
 * `vitest.config.ts` seeds two addresses. This one exists so the provenance claim
 * can be made by DIFFERENCE: two grants go through the same door, the same
 * handler and the same tool, and each gets its own address back. An answer built
 * from anything ambient — a Worker secret, a module-scope value, a remembered
 * first caller — would give both grants the same one and fail.
 *
 * Deliberately NOT the environment's `APPLE_ID`. A local override file may bind a
 * live value there, and no test in this repository may read or assert on the
 * ambient identity. A second fake under the reserved `.invalid` domain tells the
 * two sources apart without touching it.
 */
const OTHER_LISTED: CaseProps = {
  absent: false,
  props: {
    v: 1,
    appleId: "listed-user@example.invalid",
    appPassword: "cccc-cccc-cccc-cccc",
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

describe("account_whoami: the shaper (LIFE-06, D4 reversed 2026-09-23)", () => {
  it("answers exactly one field, holding the WHOLE address", async () => {
    const principal = await testPrincipal(USER_A);
    const result = signedInAsResult(principal);

    expect(result.isError, "a success result carries no error flag").toBeUndefined();
    expect(result.content.length, "more than one content item").toBe(1);
    expect(result.content[0]?.type).toBe("text");

    const answer: unknown = JSON.parse(result.content[0]?.text ?? "null");
    expect(answer).toEqual({ signedInAs: USER_A.appleId });
  });

  it("carries the address, and no mask anywhere in its serialized form", async () => {
    const principal = await testPrincipal(USER_A);
    const serialized = JSON.stringify(signedInAsResult(principal));

    // The whole result, not just the field this test named above. The inverse of
    // what this test asserted until 2026-09-23: the owner reversed D4 because the
    // mask made the model unable to name the account. A tool that quietly went
    // back to masking fails here.
    expect(serialized).toContain(USER_A.appleId);
    expect(serialized, "the answer still holds a mask").not.toContain(BULLETS);
  });

  it("reads the principal it was given, and nothing ambient", async () => {
    // The provenance claim, at the shaper: the answer follows the PRINCIPAL. Two
    // different principals give two different answers, so nothing about this
    // result can be coming from a module-scope value, the environment, or a
    // remembered first caller.
    const a = signedInAsResult(await testPrincipal(USER_A));
    const b = signedInAsResult(await testPrincipal(USER_B));

    expect(JSON.parse(a.content[0]?.text ?? "null")).toEqual({
      signedInAs: USER_A.appleId,
    });
    expect(JSON.parse(b.content[0]?.text ?? "null")).toEqual({
      signedInAs: USER_B.appleId,
    });
    expect(
      b.content[0]?.text,
      "the second answer holds the first user's address",
    ).not.toContain(USER_A.appleId);
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

  it("answers the grant's address, and holds no mask", async () => {
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
    expect(answer).toEqual({ signedInAs: USER_A.appleId });

    // The end-to-end claim about the mask. Not the field, not the result — the
    // WHOLE body the client receives, headers' worth of envelope included.
    expect(body, "the response body does not hold the address").toContain(
      USER_A.appleId,
    );
    expect(body, "the response body still holds a mask").not.toContain(BULLETS);
  });

  it("gives two different grants two different answers", async () => {
    // The provenance claim, end to end and by difference. The same door, the same
    // handler, the same tool — and each grant gets the address ITS OWN props
    // carry. Without this case a tool rewired to read a Worker secret, or to
    // remember the first principal it saw, would still pass every assertion above.
    // Serial, not a concurrent combinator. Nothing here opens a socket, but § 3's
    // habit is worth keeping in a file that drives the real door.
    const first = await callDoor(toolCall("/mcp"), LISTED);
    const second = await callDoor(toolCall("/mcp"), OTHER_LISTED);

    expect(first.status, "user A's grant was not served").toBe(200);
    expect(second.status, "the second listed grant was not served").toBe(200);

    const firstAnswer: unknown = JSON.parse(
      firstText(rpcMessageIn(await first.text())) ?? "null",
    );
    const secondAnswer: unknown = JSON.parse(
      firstText(rpcMessageIn(await second.text())) ?? "null",
    );

    // A guard on the fixture: two grants carrying one address would make the pair
    // below vacuous.
    expect(
      (OTHER_LISTED as { props: { appleId: string } }).props.appleId,
      "the two listed grants carry the same address",
    ).not.toBe(USER_A.appleId);

    expect(firstAnswer).toEqual({ signedInAs: USER_A.appleId });
    expect(secondAnswer).toEqual({
      signedInAs: (OTHER_LISTED as { props: { appleId: string } }).props.appleId,
    });
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
