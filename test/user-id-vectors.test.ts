// Fixture integrity for `test/fixtures/user-id-vectors.ts`.
//
// **What this file proves.** The vectors file is the user id spec, typed by
// hand. Bytes someone typed are only as correct as the assertions holding them
// to it, so these cases hold the rows to the rules the spec itself states: the
// shape of every expected value, which rows must MEET (every spelling of A is
// A), which rows must STAY APART (a `+tag` address and the three Apple domains
// are each their own person), that every decision has a row pinning it, and
// that the two test users are copied from their rows and not typed twice.
//
// **What this file cannot prove, and why.** It cannot check that any hex value
// is the right one for its input. Checking that needs code that turns an
// address into a fingerprint, and no such code may exist in a test or a test
// helper (D-12): Phase 8's function must stay the only one in the repository,
// because a second copy written here would agree with a first copy written the
// same way and prove nothing about either. So every comparison below is between
// literals already in the vectors file. Phase 8's own function test, which runs
// that one function over every row, is what closes that half.
//
// **What would make it pass for the wrong reason.** A filter that matched no
// rows. Every row walk below would then run zero cases and report green. The
// first describe block exists only to stop that: it asserts a floor on the hex
// rows and on the refused rows before anything walks them.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09).

import { describe, expect, it } from "vitest";
import { USER_A, USER_B } from "./fixtures/two-users";
import {
  REFUSED,
  USER_A_VECTOR,
  USER_B_VECTOR,
  USER_ID_VECTORS,
} from "./fixtures/user-id-vectors";
import type { UserIdVector } from "./fixtures/user-id-vectors";

/** What an accepted row's expected value must look like. */
const FULL_HEX = /^[0-9a-f]{64}$/;

/** The rows the spec accepts. */
const HEX_ROWS = USER_ID_VECTORS.filter((row) => row.expected !== REFUSED);

/** The rows the spec turns away. */
const REFUSED_ROWS = USER_ID_VECTORS.filter((row) => row.expected === REFUSED);

/** One row by name. A missing name is a broken spec, so it fails loudly. */
function row(name: string): UserIdVector {
  const found = USER_ID_VECTORS.filter((one) => one.name === name);
  expect(found.length, `the spec must hold exactly one row named ${name}`).toBe(1);
  return found[0]!;
}

describe("the walk sees rows at all, so an empty filter cannot pass", () => {
  it("holds at least 11 accepted rows and at least 16 refused rows", () => {
    // THE discriminating case for every walk in this file. Asserted first.
    expect(
      HEX_ROWS.length,
      "too few accepted rows: the filter matched nothing, or rows were removed",
    ).toBeGreaterThanOrEqual(11);
    expect(
      REFUSED_ROWS.length,
      "too few refused rows: the filter matched nothing, or rows were removed",
    ).toBeGreaterThanOrEqual(16);
  });

  it("sorts every row into exactly one of the two groups", () => {
    expect(
      HEX_ROWS.length + REFUSED_ROWS.length,
      "a row is in neither group, or in both",
    ).toBe(USER_ID_VECTORS.length);
  });
});

describe("every row is well formed", () => {
  it.each(USER_ID_VECTORS.map((one) => [one.name, one] as const))(
    "%s expects 64 lowercase hex characters, or a refusal",
    (_name, one) => {
      expect(
        one.expected === REFUSED || FULL_HEX.test(one.expected),
        "expected must be the full 64-character lowercase hex, or the refused marker",
      ).toBe(true);
    },
  );

  it.each(USER_ID_VECTORS.map((one) => [one.name, one] as const))(
    "%s says which decision it pins",
    (_name, one) => {
      expect(one.name.length, "a row needs a name").toBeGreaterThan(0);
      expect(
        one.pins.length,
        "a row must say which decision it holds in place",
      ).toBeGreaterThan(0);
    },
  );

  it("gives every row its own name", () => {
    const names = USER_ID_VECTORS.map((one) => one.name);
    expect(new Set(names).size, "two rows share a name").toBe(names.length);
  });

  it("gives every row its own input", () => {
    const inputs = USER_ID_VECTORS.map((one) => one.input);
    expect(new Set(inputs).size, "two rows share an input").toBe(inputs.length);
  });
});

describe("values that mean the same thing meet", () => {
  it.each(["a-padded-mixed-case", "a-nbsp-padded", "a-bom-prefixed"])(
    "%s is user A",
    (name) => {
      expect(
        row(name).expected,
        `${name} is a spelling of A and must get A's user id`,
      ).toBe(row("user-a").expected);
    },
  );

  it.each(["a-padded-mixed-case", "a-nbsp-padded", "a-bom-prefixed"])(
    "%s is a different input from the plain address",
    (name) => {
      // Otherwise the row above would be comparing A with A.
      expect(
        row(name).input,
        `${name} must not be typed the same as the plain address`,
      ).not.toBe(row("user-a").input);
    },
  );
});

describe("values that only just differ stay apart", () => {
  it("keeps A and B apart", () => {
    expect(
      row("user-a").expected,
      "A and B share a user id: two people would be one user",
    ).not.toBe(row("user-b").expected);
  });

  it("does not fold a +tag address into the plain one", () => {
    expect(FULL_HEX.test(row("plus-tag").expected), "plus-tag must be accepted").toBe(
      true,
    );
    expect(
      row("plus-tag").expected,
      "the +tag address was folded into A",
    ).not.toBe(row("user-a").expected);
  });

  it("does not fold the three Apple domains together", () => {
    const domains = ["domain-icloud", "domain-me", "domain-mac"].map(
      (name) => row(name).expected,
    );
    for (const value of domains) {
      expect(FULL_HEX.test(value), "each Apple-domain row must be accepted").toBe(
        true,
      );
    }
    expect(
      new Set(domains).size,
      "two Apple domains share a user id: two people would be one user",
    ).toBe(3);
  });

  it("gives every distinct accepted person a distinct user id", () => {
    // The three spellings of A are the only rows allowed to repeat a value.
    const meeting = new Set([
      "a-padded-mixed-case",
      "a-nbsp-padded",
      "a-bom-prefixed",
    ]);
    const people = HEX_ROWS.filter((one) => !meeting.has(one.name));
    expect(
      new Set(people.map((one) => one.expected)).size,
      "two different accepted inputs share a user id",
    ).toBe(people.length);
  });
});

describe("the length cap is pinned where it is measured", () => {
  it("accepts an input of exactly 254 characters", () => {
    expect(row("max-length-254").input.length).toBe(254);
    expect(
      FULL_HEX.test(row("max-length-254").expected),
      "the longest allowed input must be accepted",
    ).toBe(true);
  });

  it("refuses an address of 255 characters", () => {
    expect(row("too-long-255").input.length).toBe(255);
    expect(row("too-long-255").expected, "255 characters must be refused").toBe(
      REFUSED,
    );
  });

  it("counts the input as typed, before the trim", () => {
    // D-18, settled by the owner: a 254-character address plus one trailing
    // space is 255 as typed, and is refused even though the trim would bring it
    // back to 254.
    const padded = row("padded-to-255");
    expect(padded.input.length, "the row must be 255 as typed").toBe(255);
    expect(padded.input.trim(), "the row must trim to the 254 row").toBe(
      row("max-length-254").input,
    );
    expect(padded.expected, "the cap is measured before the trim").toBe(REFUSED);
  });
});

describe("every decision has a row holding it in place", () => {
  it.each(["D-09", "D-10", "D-11", "D-17", "D-18"])(
    "%s is pinned by at least one row",
    (decision) => {
      expect(
        USER_ID_VECTORS.filter((one) => one.pins.includes(decision)).length,
        `no row names ${decision}, so nothing would notice it being dropped`,
      ).toBeGreaterThanOrEqual(1);
    },
  );

  it("refuses the empty and the spaces-only input", () => {
    expect(row("empty").input, "the empty row must be empty").toBe("");
    expect(row("empty").expected).toBe(REFUSED);
    expect(row("spaces-only").input.trim(), "the row must be spaces only").toBe("");
    expect(row("spaces-only").expected).toBe(REFUSED);
  });
});

describe("the two test users are copied from their rows", () => {
  it("takes A's address and user id from the user-a row", () => {
    expect(USER_A_VECTOR, "the named export must be the row in the list").toBe(
      row("user-a"),
    );
    expect(USER_A.appleId, "A's address was typed twice").toBe(row("user-a").input);
    expect(USER_A.userId, "A's user id was typed twice").toBe(
      row("user-a").expected,
    );
  });

  it("takes B's address and user id from the user-b row", () => {
    expect(USER_B_VECTOR, "the named export must be the row in the list").toBe(
      row("user-b"),
    );
    expect(USER_B.appleId, "B's address was typed twice").toBe(row("user-b").input);
    expect(USER_B.userId, "B's user id was typed twice").toBe(
      row("user-b").expected,
    );
  });

  it("makes A and B differ in address, password and user id", () => {
    expect(USER_A.appleId, "A and B share an address").not.toBe(USER_B.appleId);
    expect(USER_A.appPassword, "A and B share a password").not.toBe(
      USER_B.appPassword,
    );
    expect(USER_A.userId, "A and B share a user id").not.toBe(USER_B.userId);
  });

  it("keeps both users off the pool's own ambient identity", () => {
    // Compared against the literal, never against the bound value: a local
    // override file may hold a live address there, and no test may read it.
    const ambient = "test@example.invalid";
    expect(USER_A.appleId, "A matches the pool's identity").not.toBe(ambient);
    expect(USER_B.appleId, "B matches the pool's identity").not.toBe(ambient);
  });
});
