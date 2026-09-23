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

import { describe, expect, it } from "vitest";
import { maskAppleId } from "../src/principal";
import { REFUSED, USER_ID_VECTORS } from "./fixtures/user-id-vectors";

/**
 * The mask body: three U+2022 BULLET characters, written as escapes.
 *
 * This file's own constant, never imported from the module under test. Two
 * literals that must agree prove something; one literal compared with itself
 * proves nothing.
 */
const BULLETS = "•••";

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
    input: "rüssell@example.invalid",
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
