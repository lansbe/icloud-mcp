// The one function that turns an Apple ID into a user id, run over the spec.
//
// **What this file proves.** `test/fixtures/user-id-vectors.ts` is the user id
// spec, written as rows. This file runs the one function over every row. An
// accepted row must come out as exactly the hex beside it. A refused row must
// come out as `null`. That closes the half the vectors test cannot: it holds
// the rows to their own rules, but it may not check a hex value, because no
// fingerprinting code may exist in a test.
//
// **What this file cannot prove, and why.** It cannot show that a hex value in
// the vectors file is right. It only shows that the function and the file
// agree. The values were computed once, by hand, outside the repository, and
// the vectors file's own header says how. Nothing here computes a fingerprint:
// every comparison is between a result of the one function and a literal from
// the vectors file, or between two results of the one function.
//
// **What would make it pass for the wrong reason.** Two things. A filter that
// matched no rows, so a walk ran zero cases and reported green: the first test
// asserts a floor on both groups before anything walks them. And a missing
// `await`: the function returns a Promise, so a call that is not awaited
// compares a Promise with a string, and a not-equal check then passes for
// ever. Every call below is awaited inside an async body.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID. Every address sits under `example.invalid`.

import { describe, expect, it } from "vitest";
import { userIdOf } from "../src/principal";
import { REFUSED, USER_ID_VECTORS } from "./fixtures/user-id-vectors";

/** The rows the spec accepts. */
const HEX_ROWS = USER_ID_VECTORS.filter((row) => row.expected !== REFUSED);

/** The rows the spec turns away. */
const REFUSED_ROWS = USER_ID_VECTORS.filter((row) => row.expected === REFUSED);

describe("the walk sees rows at all, so an empty filter cannot pass", () => {
  it("holds at least 12 accepted rows and at least 18 refused rows", () => {
    // THE discriminating case for both walks below. Asserted first.
    expect(
      HEX_ROWS.length,
      "too few accepted rows: the filter matched nothing, or rows were removed",
    ).toBeGreaterThanOrEqual(12);
    expect(
      REFUSED_ROWS.length,
      "too few refused rows: the filter matched nothing, or rows were removed",
    ).toBeGreaterThanOrEqual(18);
  });
});

describe("every accepted row becomes exactly its user id", () => {
  it.each(HEX_ROWS.map((row) => [row.name, row] as const))(
    "%s gives the hex beside it",
    async (_name, row) => {
      expect(await userIdOf(row.input)).toBe(row.expected);
    },
  );
});

describe("every refused row is turned away with a plain no", () => {
  it.each(REFUSED_ROWS.map((row) => [row.name, row] as const))(
    "%s gives null",
    async (_name, row) => {
      expect(await userIdOf(row.input)).toBeNull();
    },
  );
});
