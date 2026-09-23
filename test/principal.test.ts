// The principal module: the one user id function run over the spec, the
// password holder, and the two constructors that build a principal.
//
// **What this file proves.** Six things.
//
// 1. `test/fixtures/user-id-vectors.ts` is the user id spec, written as rows.
//    This file runs the one function over every row. An accepted row must come
//    out as exactly the hex beside it. A refused row must come out as `null`.
//    That closes the half the vectors test cannot: it holds the rows to their
//    own rules, but it may not check a hex value, because no fingerprinting
//    code may exist in a test.
// 2. The cases the rows cannot show. A value that is not a string is a plain
//    `null` and not a throw. No row makes the promise reject. An accepted id
//    never holds the address. And the length cap counts UTF-16 code units, not
//    bytes: the rows pin 254 and 255 with ASCII only, where the two units
//    agree, so one case here uses a two-byte character to tell them apart.
// 3. (Retired in Phase 9.) This used to show that nothing under `src/` imports
//    the principal module. The door in `src/mcp/api-handler.ts` is now the
//    first importer, so that test is gone (Phase 9 D-03). Who may read a
//    password and who may read the grant's props are count rules in the scan.
// 4. The password does not travel with the principal. A built principal is a
//    frozen object with two fields, and neither is a secret. Turning it into
//    JSON, spreading it, cloning it or turning it into a string gives no
//    password. The one password reader answers only the very object that was
//    built. A copy with the same two fields gets the auth error.
// 5. The props constructor fails closed. It accepts exactly one shape: `v` as
//    the number 1, an Apple ID and an app password, and no other key. Every
//    other shape in the table below is refused with the existing auth error,
//    the old owner grant included. The refusal carries nothing from the input:
//    not in the message, not in the stack, not in a property. It takes one
//    argument, so there is no second place for a credential to come from.
// 6. The env constructor gives user A and user B the ids the vectors file
//    gives them, and refuses a missing or empty secret. For both users the two
//    constructors and the one function agree on the id.
//
// **What this file cannot prove, and why.** It cannot show that a hex value in
// the vectors file is right. It only shows that the function and the file
// agree. The values were computed once, by hand, outside the repository, and
// the vectors file's own header says how. Nothing here computes a fingerprint:
// every comparison is between a result of the one function and a literal from
// the vectors file, or between two results of the one function.
//
// **What would make it pass for the wrong reason.** Two things. A filter
// that matched no rows, so a walk ran zero cases and reported green: the first
// test asserts a floor on both groups before anything walks them. A missing
// `await`: the function returns a Promise, so a call that is not awaited
// compares a Promise with a string, and a not-equal check then passes for
// ever. Every call below is awaited inside an async body.
//
// Four more for the holder and the constructors. A props constructor that
// refused everything would pass the whole bad-props table: the good shape is
// shown to resolve, for A and for B, before the table runs. A leak check on an
// input that held no values would find none: each leak check first asserts
// that the input it sends really holds the address and the password. A copy
// that differed from the original would be refused for the wrong reason: each
// copy is first shown to be equal to the original, field for field, so only
// its identity is different. And two test users with the same password would
// make "A never answers B's password" empty: the two are shown to differ.
//
// Refusals are checked by error TYPE and by category. The one message compared
// is the fixed label, and only to show that nothing was added to it.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID. Every address sits under `example.invalid`.

import { describe, expect, it } from "vitest";
import type { OwnerMailSecrets } from "../src/env";
import { ImapAuthError, toErrorCategory } from "../src/errors";
import * as principalModule from "../src/principal";
import {
  passwordOf,
  principalFromEnv,
  principalFromProps,
  userIdOf,
} from "../src/principal";
import { USER_A, USER_B, envFor, testPrincipal } from "./fixtures/two-users";
import type { TestUser } from "./fixtures/two-users";
import { REFUSED, USER_ID_VECTORS } from "./fixtures/user-id-vectors";

/** What a user id must look like. */
const FULL_HEX = /^[0-9a-f]{64}$/;

/** The rows the spec accepts. */
const HEX_ROWS = USER_ID_VECTORS.filter((row) => row.expected !== REFUSED);

/** The rows the spec turns away. */
const REFUSED_ROWS = USER_ID_VECTORS.filter((row) => row.expected === REFUSED);

/**
 * A minimal environment carrying only the two account bindings.
 *
 * Built in one expression, and nothing is written onto it afterwards. Both
 * parameters admit `undefined` because a Workers Secret binding does: an unset
 * or deleted Secret arrives absent, and the refusal cases have to be able to
 * say so.
 */
function fakeEnv(
  appleId: string | undefined,
  password: string | undefined,
): OwnerMailSecrets {
  return {
    APPLE_ID: appleId,
    APPLE_APP_PASSWORD: password,
  };
}

/** The one props shape that is accepted, for `user`. A fresh object each call. */
function goodPropsFor(user: TestUser): {
  v: number;
  appleId: string;
  appPassword: string;
} {
  return { v: 1, appleId: user.appleId, appPassword: user.appPassword };
}

/** `base` with one more own key, a symbol. Its enumerable string keys do not change. */
function withSymbolKey(base: object): object {
  return { ...base, [Symbol("extra")]: 1 };
}

/** `base` with one more own key that is not enumerable, so a key listing skips it. */
function withHiddenKey(base: object, key: string, value: unknown): object {
  const copy = { ...base };
  Object.defineProperty(copy, key, { value, enumerable: false });
  return copy;
}

/** A made-up password for the rows that need one. Not a real credential. */
const ROW_PASSWORD = "cccc-cccc-cccc-cccc";

/** An address with one letter outside ASCII, built by number and never typed. */
const NON_ASCII_ADDRESS = `us${String.fromCharCode(0xe9)}r@example.invalid`;

/** An address one character over the cap: 239 letters and the 16 of the domain. */
const TOO_LONG_ADDRESS = `${"a".repeat(239)}@example.invalid`;

// White space for the untrimmed-address rows (D-18). Each is built from its
// number and never typed, so nothing that rewrites this file can change it.
const SPACE = String.fromCharCode(0x20);
const LINE_FEED = String.fromCharCode(0x0a);
const CARRIAGE_RETURN = String.fromCharCode(0x0d);
const NO_BREAK_SPACE = String.fromCharCode(0xa0);

/**
 * User A's address with white space at an end, by name (D-18, code review WR-06).
 *
 * The id function trims its own copy and ACCEPTS every one of these, as user A.
 * So each is refused by the props constructor's own trim check and by nothing
 * else, and a test below shows that before the table runs.
 */
const UNTRIMMED_ADDRESSES: ReadonlyArray<readonly [string, string]> = [
  ["an appleId with a leading space", SPACE + USER_A.appleId],
  ["an appleId with a trailing space", USER_A.appleId + SPACE],
  ["an appleId with a trailing line feed", USER_A.appleId + LINE_FEED],
  [
    "an appleId with a trailing carriage return and line feed",
    USER_A.appleId + CARRIAGE_RETURN + LINE_FEED,
  ],
  [
    "an appleId padded with no-break spaces",
    NO_BREAK_SPACE + USER_A.appleId + NO_BREAK_SPACE,
  ],
];

// Control characters for the unusable-password rows (D-19). Built from their
// numbers and never typed, for the same reason as the white space above.
const NUL = String.fromCharCode(0x00);
const TAB = String.fromCharCode(0x09);
const UNIT_SEPARATOR = String.fromCharCode(0x1f);
const DELETE = String.fromCharCode(0x7f);

/**
 * Every password both constructors must refuse, by name (D-19, code review WR-07).
 *
 * Each one is a non-empty string, so the older "is it set" check lets every one
 * of them through, and a test below shows that before the tables run. The line
 * endings are the rows that matter: a login is one command line, and a line
 * ending inside the password would end it early.
 */
const UNUSABLE_PASSWORDS: ReadonlyArray<readonly [string, string]> = [
  ["a password that is only spaces", SPACE + SPACE + SPACE],
  ["a password that is only no-break spaces", NO_BREAK_SPACE + NO_BREAK_SPACE],
  ["a password with an embedded carriage return", `cccc-cccc${CARRIAGE_RETURN}cccc-cccc`],
  ["a password with an embedded line feed", `cccc-cccc${LINE_FEED}cccc-cccc`],
  [
    "a password with a trailing carriage return and line feed",
    ROW_PASSWORD + CARRIAGE_RETURN + LINE_FEED,
  ],
  ["a password with an embedded NUL", `cccc-cccc${NUL}cccc-cccc`],
  ["a password with an embedded tab", `cccc-cccc${TAB}cccc-cccc`],
  ["a password with the last control character below the space", `cccc-cccc${UNIT_SEPARATOR}cccc-cccc`],
  ["a password with an embedded delete character", `cccc-cccc${DELETE}cccc-cccc`],
];

/**
 * Passwords that hold no control character and must still be accepted (D-19).
 *
 * The check is NOT a shape check: the four-groups-of-four rule belongs to the
 * login page in Phase 11. So anything that is not white-space-only and holds no
 * control character passes, a space in the middle and the two printable ends of
 * ASCII included. These are the near side of each boundary the rows above pin.
 */
const USABLE_PASSWORDS: ReadonlyArray<readonly [string, string]> = [
  ["the usual four groups of four", "cccc-cccc-cccc-cccc"],
  ["one with a space in the middle, the first code unit that is allowed", `cccc${SPACE}cccc`],
  ["one with spaces at the ends around real text", `${SPACE}cccc-cccc${SPACE}`],
  ["one holding the last printable ASCII character", `cccc${String.fromCharCode(0x7e)}cccc`],
  ["one that fits no app-password shape at all", "not the four-by-four shape!"],
];

/**
 * Every shape the props constructor must refuse, by name.
 *
 * One row per refusal in the plan's behaviour list. The old owner grant and
 * the extra-key shape are the two that matter most: the first is what every
 * grant stored before this milestone looks like, and the second is how a user
 * id supplied from outside would arrive.
 */
const BAD_PROPS: ReadonlyArray<readonly [string, unknown]> = [
  ["null", null],
  ["undefined", undefined],
  ["a string", "user-a@example.invalid"],
  ["a number", 1],
  ["an array", [1, USER_A.appleId, USER_A.appPassword]],
  ["an empty object", {}],
  ["the old owner grant", { userId: "owner" }],
  ["v 1 alone", { v: 1 }],
  ["v 2 with both fields", { ...goodPropsFor(USER_A), v: 2 }],
  ["v as the string 1 with both fields", { ...goodPropsFor(USER_A), v: "1" }],
  ["appleId empty", { v: 1, appleId: "", appPassword: ROW_PASSWORD }],
  ["appleId a number", { v: 1, appleId: 42, appPassword: ROW_PASSWORD }],
  ["appleId missing", { v: 1, appPassword: ROW_PASSWORD }],
  ["appPassword empty", { v: 1, appleId: USER_A.appleId, appPassword: "" }],
  ["appPassword a number", { v: 1, appleId: USER_A.appleId, appPassword: 42 }],
  ["appPassword missing", { v: 1, appleId: USER_A.appleId }],
  [
    "an appleId with no at sign",
    { v: 1, appleId: "user-a.example.invalid", appPassword: ROW_PASSWORD },
  ],
  [
    "an appleId holding a non-ASCII letter",
    { v: 1, appleId: NON_ASCII_ADDRESS, appPassword: ROW_PASSWORD },
  ],
  [
    "an appleId of 255 characters",
    { v: 1, appleId: TOO_LONG_ADDRESS, appPassword: ROW_PASSWORD },
  ],
  [
    "a good shape with one extra key, a user id supplied from outside",
    { ...goodPropsFor(USER_A), userId: USER_B.userId },
  ],
  // Code review WR-05. The module says a fourth key "of any kind, a hidden one
  // or a symbol included" is refused, and that the three fields must be the
  // object's own. Each claim rests on one clause, and before these rows no test
  // held any of them: the clause could be deleted with the suite green.
  //
  // The first two are seen ONLY by the own-keys count. The enumerable key list
  // of each is exactly the three good names.
  ["a good shape with one extra symbol key", withSymbolKey(goodPropsFor(USER_A))],
  [
    "a good shape with one extra hidden key, a user id supplied from outside",
    withHiddenKey(goodPropsFor(USER_A), "userId", USER_B.userId),
  ],
  // Every `in` check passes for these two, because `in` looks up the prototype
  // chain. They are refused because the fields are not the object's OWN.
  ["all three fields carried only on the prototype", Object.create(goodPropsFor(USER_A))],
  [
    "the password carried only on the prototype",
    Object.assign(Object.create({ appPassword: USER_A.appPassword }), {
      v: 1,
      appleId: USER_A.appleId,
    }),
  ],
  // D-18, code review WR-06. A good shape whose address the trim would change.
  ...UNTRIMMED_ADDRESSES.map(
    ([name, appleId]) =>
      [name, { v: 1, appleId, appPassword: USER_A.appPassword }] as const,
  ),
  // D-19, code review WR-07. A good shape whose password may not be stored.
  ...UNUSABLE_PASSWORDS.map(
    ([name, appPassword]) =>
      [name, { v: 1, appleId: USER_A.appleId, appPassword }] as const,
  ),
];

/** What a refusal is allowed to show: its message, its stack, its property names and values. */
function everythingOn(raised: unknown): string {
  const own = Object.getOwnPropertyNames(raised as object);
  return JSON.stringify({
    message: (raised as Error).message,
    stack: (raised as Error).stack,
    own,
    values: own.map((name) => String((raised as Record<string, unknown>)[name])),
  });
}

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

describe("a value that is not a string is a plain no, not a throw", () => {
  // The type says string. A caller reading a form field or a stored grant can
  // still hand over anything at runtime, and the answer must be the same `null`
  // every other refusal gets. Each value is cast through `unknown`, which is
  // the only way to get it past the compiler.
  it("gives null for undefined", async () => {
    expect(await userIdOf(undefined as unknown as string)).toBeNull();
  });

  it("gives null for null", async () => {
    expect(await userIdOf(null as unknown as string)).toBeNull();
  });

  it("gives null for a number", async () => {
    expect(await userIdOf(42 as unknown as string)).toBeNull();
  });

  it("gives null for an object", async () => {
    expect(await userIdOf({} as unknown as string)).toBeNull();
  });
});

describe("no input makes the function throw", () => {
  it("resolves for every one of the rows, accepted or refused", async () => {
    expect(
      USER_ID_VECTORS.length,
      "too few rows: this walk would prove nothing",
    ).toBeGreaterThanOrEqual(30);

    for (const row of USER_ID_VECTORS) {
      // The `resolves` form, so a rejection fails loudly and names the row. A
      // refusal is a value. It is never a throw, so there is never an error
      // for the typed address to ride out on.
      await expect(
        userIdOf(row.input),
        `${row.name} made the promise reject`,
      ).resolves.toSatisfy(
        (value: unknown) => value === null || typeof value === "string",
      );
    }
  });
});

describe("the Apple ID never appears in a user id", () => {
  it.each(HEX_ROWS.map((row) => [row.name, row] as const))(
    "%s gives 64 lowercase hex characters that hold no address",
    async (_name, row) => {
      const id = await userIdOf(row.input);
      expect(id, "an accepted row must give an id").not.toBeNull();
      expect(FULL_HEX.test(id!), "the id is not 64 lowercase hex").toBe(true);
      expect(id!.includes("@"), "the id holds an at sign").toBe(false);
      expect(
        id!.includes(row.input.trim().toLowerCase()),
        "the id holds the address it was made from",
      ).toBe(false);
    },
  );
});

describe("the length cap counts UTF-16 code units, not bytes", () => {
  // THE case that tells code units from bytes. The rows cannot: they pin 254
  // and 255 with ASCII only, where code units, code points and UTF-8 bytes are
  // all the same number. An NBSP is one code unit and two bytes. It is also
  // removed by the trim, so it changes the typed length and nothing else.
  //
  // The NBSP is built from its number, never typed, so nothing that rewrites
  // this file can change what is being measured.
  const NBSP = String.fromCharCode(0xa0);
  const ADDRESS = `${"a".repeat(237)}@example.invalid`;

  it("accepts 254 code units that are 255 bytes, as the same user", async () => {
    const padded = ADDRESS + NBSP;
    // Asserted before the call, so the test cannot drift off the boundary.
    expect(ADDRESS.length, "the clean address must be 253 long").toBe(253);
    expect(padded.length, "the padded input must be 254 code units").toBe(254);

    // One function called twice, not a second hash. The first result is held
    // to the id shape, so two refusals cannot pass as "the same user".
    const clean = await userIdOf(ADDRESS);
    expect(clean, "the clean address must be accepted").not.toBeNull();
    expect(FULL_HEX.test(clean!), "the id is not 64 lowercase hex").toBe(true);
    expect(
      await userIdOf(padded),
      "a cap counted in bytes would refuse this input: it is 255 bytes",
    ).toBe(clean);
  });

  it("refuses 255 code units, even though the trim would bring it back", async () => {
    const padded = ADDRESS + NBSP + NBSP;
    expect(padded.length, "the padded input must be 255 code units").toBe(255);
    expect(padded.trim(), "the input must trim to the clean address").toBe(ADDRESS);
    expect(await userIdOf(padded)).toBeNull();
  });
});

describe("module shape", () => {
  it("exports the two halves of the id rule, the one mask, the one password reader and the two constructors, nothing else", () => {
    // The design made checkable. There is no export that hands out the holder
    // itself.
    //
    // `normaliseAppleId` joined this list in Phase 11, and it is an ADDITION to
    // the id rule rather than a second copy of it: `userIdOf` calls it and
    // repeats not one of its steps, so there is still exactly one place the
    // folding is written down. It is exported because the door needs the
    // comparison synchronously and Web Crypto has no synchronous digest. A
    // list that quietly grew a second FOLDING function would be the drift this
    // assertion is here to catch.
    //
    // `maskAppleId` joined it in Phase 12 (LIFE-06), on exactly the same terms.
    // It is an addition BESIDE the folding rule, not a second copy of it: it
    // calls `normaliseAppleId` and repeats not one of its steps. It is here
    // because the "which account is this connection on" tool and the owner's
    // grants script must both build the same masked form, and a list that
    // quietly grew a second MASKING function would be that drift — two masks
    // that agree until the day one of them stops masking.
    expect(Object.keys(principalModule).sort()).toEqual([
      "maskAppleId",
      "normaliseAppleId",
      "passwordOf",
      "principalFromEnv",
      "principalFromProps",
      "userIdOf",
    ]);
  });

  it("exports only functions", () => {
    for (const value of Object.values(principalModule)) {
      expect(typeof value).toBe("function");
    }
  });
});

describe("the holder: the principal travels and the password does not (D-01, D-16)", () => {
  it("has two test users whose passwords differ, so the checks below mean something", () => {
    expect(USER_A.appPassword.length).toBeGreaterThan(0);
    expect(USER_B.appPassword.length).toBeGreaterThan(0);
    expect(USER_A.appPassword).not.toBe(USER_B.appPassword);
    expect(USER_A.userId).not.toBe(USER_B.userId);
  });

  it("builds a frozen object with exactly two fields, and neither is a secret", async () => {
    const principal = await principalFromProps(goodPropsFor(USER_A));

    expect(Object.keys(principal).sort()).toEqual(["appleId", "userId"]);
    expect(Reflect.ownKeys(principal).length, "a hidden or symbol key").toBe(2);
    expect(principal.userId).toBe(USER_A.userId);
    expect(principal.appleId).toBe(USER_A.appleId);
    expect(Object.isFrozen(principal)).toBe(true);
  });

  it("answers each user's password for that user's own principal, and only that", async () => {
    const a = await principalFromProps(goodPropsFor(USER_A));
    const b = await principalFromProps(goodPropsFor(USER_B));

    expect(passwordOf(a)).toBe(USER_A.appPassword);
    expect(passwordOf(b)).toBe(USER_B.appPassword);
    expect(passwordOf(a)).not.toBe(USER_B.appPassword);
    expect(passwordOf(b)).not.toBe(USER_A.appPassword);
  });

  it("reads the password without a promise", async () => {
    // The two constructors are async because the id function is. The reader
    // is not, and the callers in Phase 9 write it straight into a command.
    const principal = await principalFromProps(goodPropsFor(USER_A));
    expect(typeof passwordOf(principal)).toBe("string");
  });

  it("holds no password in any form a copy or a string could carry", async () => {
    const principal = await principalFromProps(goodPropsFor(USER_A));
    const password = USER_A.appPassword;

    const forms = [
      JSON.stringify(principal),
      JSON.stringify({ ...principal }),
      JSON.stringify(structuredClone(principal)),
      String(principal),
      `${principal as unknown as string}`,
      JSON.stringify(Object.getOwnPropertyNames(principal)),
      JSON.stringify(Object.values(principal)),
      JSON.stringify(Object.getOwnPropertyDescriptors(principal)),
    ];
    for (const form of forms) {
      expect(form.includes(password), `a form held the password: ${form}`).toBe(
        false,
      );
    }
    // The control. The same walk DOES find a value the object really holds, so
    // "not found" above is not the walk being blind.
    expect(forms.some((form) => form.includes(USER_A.appleId))).toBe(true);
    expect(Object.getOwnPropertySymbols(principal)).toEqual([]);
  });

  it("refuses a spread copy, which is equal in every field", async () => {
    const principal = await principalFromProps(goodPropsFor(USER_A));
    const copy = { ...principal };

    expect(copy, "the copy must equal the original").toEqual(principal);
    expect(copy === principal, "the copy must be another object").toBe(false);
    expect(() => passwordOf(copy)).toThrow(ImapAuthError);
    // And the original still answers, so the refusal is about identity.
    expect(passwordOf(principal)).toBe(USER_A.appPassword);
  });

  it("refuses a structured clone, which is equal in every field", async () => {
    const principal = await principalFromProps(goodPropsFor(USER_A));
    const copy = structuredClone(principal);

    expect(copy, "the clone must equal the original").toEqual(principal);
    expect(copy === principal, "the clone must be another object").toBe(false);
    expect(() => passwordOf(copy)).toThrow(ImapAuthError);
  });

  it("refuses an object made by hand with the right two fields", () => {
    const forged = Object.freeze({
      userId: USER_A.userId,
      appleId: USER_A.appleId,
    });
    expect(() => passwordOf(forged)).toThrow(ImapAuthError);
  });

  it("gives the auth category for a refused copy, and the fixed label", async () => {
    const principal = await principalFromProps(goodPropsFor(USER_A));
    let raised: unknown = null;
    try {
      passwordOf({ ...principal });
    } catch (err: unknown) {
      raised = err;
    }

    expect(raised).toBeInstanceOf(ImapAuthError);
    expect(toErrorCategory(raised).category).toBe("auth_failed");
    expect(everythingOn(raised)).not.toContain(USER_A.appPassword);
    expect(everythingOn(raised)).not.toContain(USER_A.appleId);
    expect((raised as Error).message).toBe("imap-credentials-rejected");
  });

  it("builds a new principal each time, so nothing is shared between two sign-ins", async () => {
    // Two grants for the same person are two objects. A table keyed by the
    // address would hand back the first one, and with it the first password.
    const first = await principalFromProps(goodPropsFor(USER_A));
    const second = await principalFromProps({
      ...goodPropsFor(USER_A),
      appPassword: ROW_PASSWORD,
    });

    expect(first === second).toBe(false);
    expect(first.userId).toBe(second.userId);
    expect(passwordOf(first)).toBe(USER_A.appPassword);
    expect(passwordOf(second)).toBe(ROW_PASSWORD);
  });

  it("keeps the password it was given, whatever happens to the props afterwards", async () => {
    const props = goodPropsFor(USER_A);
    const principal = await principalFromProps(props);
    props.appPassword = ROW_PASSWORD;
    props.appleId = USER_B.appleId;

    expect(passwordOf(principal)).toBe(USER_A.appPassword);
    expect(principal.appleId).toBe(USER_A.appleId);
    expect(principal.userId).toBe(USER_A.userId);
  });

  it("carries the Apple ID exactly as given, and still gives the same user id", async () => {
    // Asserted first, so the capital spelling below really is a different
    // string for the same person. No padding here: since D-18 the props
    // constructor refuses an address the trim would change, and the bad-props
    // table holds that. Letter case is still carried as given.
    expect(USER_A.appleId).toBe(USER_A.appleId.trim().toLowerCase());
    const typed = USER_A.appleId.toUpperCase();
    expect(typed).not.toBe(USER_A.appleId);
    expect(typed).toBe(typed.trim());

    const principal = await principalFromProps({
      ...goodPropsFor(USER_A),
      appleId: typed,
    });

    expect(principal.appleId, "no lowercasing").toBe(typed);
    expect(principal.userId).toBe(USER_A.userId);
  });
});

describe("the props constructor fails closed (D-02, D-04)", () => {
  it("accepts the one good shape, for A and for B, so the table below is not a function that refuses everything", async () => {
    await expect(
      principalFromProps(goodPropsFor(USER_A)),
    ).resolves.toMatchObject({ userId: USER_A.userId });
    await expect(
      principalFromProps(goodPropsFor(USER_B)),
    ).resolves.toMatchObject({ userId: USER_B.userId });
  });

  it("holds every refusal the plan lists, each under its own name", () => {
    expect(BAD_PROPS.length).toBeGreaterThanOrEqual(20);
    const names = BAD_PROPS.map(([name]) => name);
    expect(new Set(names).size, "two rows share a name").toBe(names.length);
    expect(names).toContain("the old owner grant");
    expect(
      names.some((name) => name.includes("one extra key")),
      "the extra-key row is missing",
    ).toBe(true);
  });

  it("builds the two awkward addresses the way the rows say", () => {
    expect(TOO_LONG_ADDRESS.length).toBe(255);
    expect(NON_ASCII_ADDRESS.charCodeAt(2)).toBe(0xe9);
  });

  it("builds the hidden-key, symbol-key and prototype rows the way their names say", () => {
    // Code review WR-05. Each of these rows is meant to get past every check
    // but one. If a row were refused for a plainer reason, such as a missing
    // field, it would hold nothing in place. So each is shown to look exactly
    // like the good shape to the checks it is meant to get past.
    const goodKeys = ["appPassword", "appleId", "v"];
    const row = (name: string): object => {
      const found = BAD_PROPS.find(([rowName]) => rowName === name);
      expect(found, `the row "${name}" is missing`).toBeDefined();
      return found![1] as object;
    };

    for (const name of [
      "a good shape with one extra symbol key",
      "a good shape with one extra hidden key, a user id supplied from outside",
    ]) {
      const value = row(name);
      expect(Object.keys(value).sort(), `${name}: the key listing`).toEqual(goodKeys);
      expect(Reflect.ownKeys(value).length, `${name}: the own-key count`).toBe(4);
      const fields = value as Record<string, unknown>;
      expect(fields.v, `${name}: v`).toBe(1);
      expect(fields.appleId, `${name}: the address`).toBe(USER_A.appleId);
      expect(fields.appPassword, `${name}: the password`).toBe(USER_A.appPassword);
    }

    for (const name of [
      "all three fields carried only on the prototype",
      "the password carried only on the prototype",
    ]) {
      const value = row(name) as Record<string, unknown>;
      for (const key of goodKeys) {
        expect(key in value, `${name}: ${key} must be reachable`).toBe(true);
      }
      expect(value.v).toBe(1);
      expect(value.appleId).toBe(USER_A.appleId);
      expect(value.appPassword).toBe(USER_A.appPassword);
      expect(
        Object.prototype.hasOwnProperty.call(value, "appPassword"),
        `${name}: the password must not be an own field`,
      ).toBe(false);
    }
  });

  it("builds the untrimmed addresses so that only the trim check can refuse them (D-18)", async () => {
    // Code review WR-06. If the id function turned one of these away, its row
    // in the table would pass with the trim check deleted, and hold nothing.
    // So each is shown to differ from its trimmed form, to trim back to user
    // A's clean address, and to be ACCEPTED by the id function as user A.
    expect(UNTRIMMED_ADDRESSES.length).toBe(5);
    for (const [name, address] of UNTRIMMED_ADDRESSES) {
      expect(address, `${name}: must differ from its trimmed form`).not.toBe(address.trim());
      expect(address.trim(), `${name}: must trim to the clean address`).toBe(USER_A.appleId);
      expect(await userIdOf(address), `${name}: the id function must accept it`).toBe(
        USER_A.userId,
      );
      expect(
        BAD_PROPS.some(([rowName]) => rowName === name),
        `${name}: missing from the bad-props table`,
      ).toBe(true);
    }
    // Built from numbers, so check the numbers.
    expect(UNTRIMMED_ADDRESSES[0]![1].charCodeAt(0)).toBe(0x20);
    expect(UNTRIMMED_ADDRESSES[2]![1].endsWith(String.fromCharCode(0x0a))).toBe(true);
    expect(UNTRIMMED_ADDRESSES[3]![1].endsWith(String.fromCharCode(0x0d, 0x0a))).toBe(true);
    expect(UNTRIMMED_ADDRESSES[4]![1].charCodeAt(0)).toBe(0xa0);
  });

  it.each(UNTRIMMED_ADDRESSES)(
    "leaves the env constructor alone: it still accepts %s, untouched (D-18)",
    async (_name, address) => {
      // D-18 changes the props path only. The env constructor must carry the
      // binding exactly as before, so today's wire bytes do not change.
      const principal = await principalFromEnv(fakeEnv(address, ROW_PASSWORD));
      expect(principal.appleId).toBe(address);
      expect(principal.userId).toBe(USER_A.userId);
    },
  );

  it("builds the unusable passwords so that only the password check can refuse them (D-19)", () => {
    // Code review WR-07. Each is a non-empty string, which is all the older
    // "is it set" check asks for. So a row here passes that check, and is
    // refused by the new one or by nothing.
    expect(UNUSABLE_PASSWORDS.length).toBe(9);
    const names = UNUSABLE_PASSWORDS.map(([name]) => name);
    expect(new Set(names).size, "two rows share a name").toBe(names.length);
    for (const [name, password] of UNUSABLE_PASSWORDS) {
      expect(typeof password, name).toBe("string");
      expect(password.length, `${name}: must not be empty`).toBeGreaterThan(0);
      expect(
        BAD_PROPS.some(([rowName]) => rowName === name),
        `${name}: missing from the bad-props table`,
      ).toBe(true);
    }

    // Built from numbers, so check the numbers. One control character each,
    // at the place the row's name says.
    const controlsIn = (text: string): number[] =>
      Array.from(text, (ch) => ch.charCodeAt(0)).filter((code) => code < 0x20 || code === 0x7f);
    const byName = new Map(UNUSABLE_PASSWORDS);
    expect(controlsIn(byName.get("a password with an embedded carriage return")!)).toEqual([0x0d]);
    expect(controlsIn(byName.get("a password with an embedded line feed")!)).toEqual([0x0a]);
    expect(
      controlsIn(byName.get("a password with a trailing carriage return and line feed")!),
    ).toEqual([0x0d, 0x0a]);
    expect(controlsIn(byName.get("a password with an embedded NUL")!)).toEqual([0x00]);
    expect(controlsIn(byName.get("a password with an embedded tab")!)).toEqual([0x09]);
    expect(
      controlsIn(byName.get("a password with the last control character below the space")!),
    ).toEqual([0x1f]);
    expect(controlsIn(byName.get("a password with an embedded delete character")!)).toEqual([0x7f]);
    // The two white-space-only rows hold no control character at all, so they
    // are refused by the white-space half of the check and not the other half.
    expect(controlsIn(byName.get("a password that is only spaces")!)).toEqual([]);
    expect(controlsIn(byName.get("a password that is only no-break spaces")!)).toEqual([]);

    // And the accepted passwords hold none either.
    for (const [name, password] of USABLE_PASSWORDS) {
      expect(controlsIn(password), `${name}: holds a control character`).toEqual([]);
      expect(password.trim().length, `${name}: is only white space`).toBeGreaterThan(0);
    }
  });

  it.each(USABLE_PASSWORDS)(
    "still accepts %s, and hands it back unchanged (D-19)",
    async (_name, password) => {
      // The other side of the check. A rule that refused every password would
      // pass the whole table above. It is not a shape check either: that one
      // belongs to the login page.
      const principal = await principalFromProps({
        v: 1,
        appleId: USER_A.appleId,
        appPassword: password,
      });
      expect(principal.userId).toBe(USER_A.userId);
      expect(passwordOf(principal)).toBe(password);
    },
  );

  it("carries no fragment of a refused password that held a line ending", async () => {
    const head = "leaky-control-head";
    const tail = "leaky-control-tail";
    const address = "leaky-control@example.invalid";
    const password = head + CARRIAGE_RETURN + LINE_FEED + tail;
    // The address is a good one, so the password is the only reason to refuse.
    expect(await userIdOf(address)).not.toBeNull();

    const raised = await principalFromProps({ v: 1, appleId: address, appPassword: password }).then(
      () => null,
      (err: unknown) => err,
    );

    expect(raised).toBeInstanceOf(ImapAuthError);
    expect(toErrorCategory(raised).category).toBe("auth_failed");
    const shown = everythingOn(raised);
    expect(shown).not.toContain(head);
    expect(shown).not.toContain(tail);
    expect(shown).not.toContain(address);
    expect((raised as Error).message).toBe("imap-credentials-rejected");
  });

  it.each(BAD_PROPS)("refuses %s with the auth error", async (_name, value) => {
    const raised = await principalFromProps(value).then(
      () => null,
      (err: unknown) => err,
    );
    expect(raised).toBeInstanceOf(ImapAuthError);
    expect(toErrorCategory(raised).category).toBe("auth_failed");
  });

  it("reads each field once, so a getter that changes its answer changes nothing", async () => {
    // Code review WR-05. The module says each field is read once into a local
    // and only the locals are used after the checks. This is the row that
    // holds it. Each getter answers with user A's value the first time and
    // user B's every time after. Code that checked one read and used another
    // would check A and then sign in as B.
    let addressReads = 0;
    let passwordReads = 0;
    const shifting = Object.defineProperties(
      { v: 1 },
      {
        appleId: {
          enumerable: true,
          get: () => {
            addressReads += 1;
            return addressReads === 1 ? USER_A.appleId : USER_B.appleId;
          },
        },
        appPassword: {
          enumerable: true,
          get: () => {
            passwordReads += 1;
            return passwordReads === 1 ? USER_A.appPassword : USER_B.appPassword;
          },
        },
      },
    );
    // The object passes the shape checks: three own enumerable keys.
    expect(Object.keys(shifting).sort()).toEqual(["appPassword", "appleId", "v"]);
    expect(Reflect.ownKeys(shifting).length).toBe(3);

    const principal = await principalFromProps(shifting);

    expect(addressReads, "the address was read more than once").toBe(1);
    expect(passwordReads, "the password was read more than once").toBe(1);
    expect(principal.appleId).toBe(USER_A.appleId);
    expect(principal.userId).toBe(USER_A.userId);
    expect(passwordOf(principal)).toBe(USER_A.appPassword);

    // The control. The getters really do change their answer, so "A came out"
    // above is the code reading once and not the getters standing still.
    expect((shifting as unknown as { appleId: string }).appleId).toBe(USER_B.appleId);
    expect((shifting as unknown as { appPassword: string }).appPassword).toBe(
      USER_B.appPassword,
    );
  });

  it("takes exactly one argument, so there is no second place for a credential to come from", () => {
    expect(principalFromProps.length).toBe(1);
  });

  const LEAKY_PASSWORD = "leaky-password-value";
  const LEAKY_SHAPES: ReadonlyArray<readonly [string, string, unknown]> = [
    [
      "a wrong v",
      "leaky-wrong-v@example.invalid",
      { v: 2, appleId: "leaky-wrong-v@example.invalid", appPassword: LEAKY_PASSWORD },
    ],
    [
      "an extra key",
      "leaky-extra-key@example.invalid",
      {
        v: 1,
        appleId: "leaky-extra-key@example.invalid",
        appPassword: LEAKY_PASSWORD,
        note: "anything",
      },
    ],
    [
      "an address the id function turns away",
      "leaky-no-at-sign.example.invalid",
      { v: 1, appleId: "leaky-no-at-sign.example.invalid", appPassword: LEAKY_PASSWORD },
    ],
  ];

  it.each(LEAKY_SHAPES)(
    "carries no fragment of the address or the password when it refuses %s",
    async (_name, address, shape) => {
      // The input really holds both values. Without this the check below
      // could pass on an input that had nothing to leak.
      expect(JSON.stringify(shape)).toContain(address);
      expect(JSON.stringify(shape)).toContain(LEAKY_PASSWORD);

      const raised = await principalFromProps(shape).then(
        () => null,
        (err: unknown) => err,
      );

      expect(raised).toBeInstanceOf(ImapAuthError);
      expect(toErrorCategory(raised).category).toBe("auth_failed");
      const shown = everythingOn(raised);
      expect(shown).not.toContain(address);
      expect(shown).not.toContain(LEAKY_PASSWORD);
      // Nor a length or a field name, which would be an oracle of its own.
      expect((raised as Error).message).toBe("imap-credentials-rejected");
    },
  );
});

describe("the env constructor, temporary until the secrets are removed (D-03)", () => {
  it.each([USER_A, USER_B].map((user) => [user.label, user] as const))(
    "gives user %s the id the vectors file gives them, and their own password",
    async (_label, user) => {
      const principal = await principalFromEnv(envFor(user));

      expect(principal.userId).toBe(user.userId);
      expect(principal.appleId).toBe(user.appleId);
      expect(passwordOf(principal)).toBe(user.appPassword);
      expect(Object.isFrozen(principal)).toBe(true);
      expect(Object.keys(principal).sort()).toEqual(["appleId", "userId"]);
    },
  );

  it("carries the Apple ID binding untouched, so no byte changes on the wire", async () => {
    const typed = ` ${USER_A.appleId.toUpperCase()}  `;
    const principal = await principalFromEnv(fakeEnv(typed, ROW_PASSWORD));

    expect(principal.appleId).toBe(typed);
    expect(principal.userId).toBe(USER_A.userId);
  });

  it.each([
    ["the Apple ID is not set", undefined, ROW_PASSWORD],
    ["the password is not set", USER_A.appleId, undefined],
    ["neither is set", undefined, undefined],
    ["the Apple ID is empty", "", ROW_PASSWORD],
    ["the password is empty", USER_A.appleId, ""],
    ["the Apple ID has no at sign", "user-a.example.invalid", ROW_PASSWORD],
    ["the Apple ID holds a non-ASCII letter", NON_ASCII_ADDRESS, ROW_PASSWORD],
  ] as const)("refuses with the auth error when %s", async (_name, appleId, password) => {
    await expect(
      principalFromEnv(fakeEnv(appleId, password)),
    ).rejects.toBeInstanceOf(ImapAuthError);
  });

  it.each(UNUSABLE_PASSWORDS)(
    "refuses %s with the auth error, the same as the props constructor (D-19)",
    async (_name, password) => {
      // The Apple ID is user A's good one, so the password is the only reason.
      const raised = await principalFromEnv(fakeEnv(USER_A.appleId, password)).then(
        () => null,
        (err: unknown) => err,
      );
      expect(raised).toBeInstanceOf(ImapAuthError);
      expect(toErrorCategory(raised).category).toBe("auth_failed");
    },
  );

  it.each(USABLE_PASSWORDS)(
    "still accepts %s, and hands it back unchanged (D-19)",
    async (_name, password) => {
      const principal = await principalFromEnv(fakeEnv(USER_A.appleId, password));
      expect(principal.userId).toBe(USER_A.userId);
      expect(passwordOf(principal)).toBe(password);
    },
  );

  it("carries no fragment of either binding when it refuses", async () => {
    const address = "leaky-binding.example.invalid";
    const password = "leaky-binding-password";

    const raised = await principalFromEnv(fakeEnv(address, password)).then(
      () => null,
      (err: unknown) => err,
    );

    expect(raised).toBeInstanceOf(ImapAuthError);
    expect(toErrorCategory(raised).category).toBe("auth_failed");
    expect(everythingOn(raised)).not.toContain(address);
    expect(everythingOn(raised)).not.toContain(password);
    expect((raised as Error).message).toBe("imap-credentials-rejected");
  });
});

describe("the invariant: three ways to an id, one answer", () => {
  it.each([USER_A, USER_B].map((user) => [user.label, user] as const))(
    "user %s gets the id from the vectors file, whichever way it is asked for",
    async (_label, user) => {
      // Every value compared here is a result of the one function, reached by
      // three roads, held against a literal from the vectors file. There is no
      // second fingerprint anywhere in this test.
      const fromEnv = await principalFromEnv(envFor(user));
      const fromProps = await principalFromProps(goodPropsFor(user));
      const direct = await userIdOf(user.appleId);

      expect(FULL_HEX.test(user.userId), "the vectors id is not 64 hex").toBe(true);
      expect(fromEnv.userId).toBe(user.userId);
      expect(fromProps.userId).toBe(user.userId);
      expect(direct).toBe(user.userId);
    },
  );
});

describe("test principals are built by the real constructor (Phase 9 D-17)", () => {
  it("has two test users whose ids and passwords differ, so the cases below mean something", () => {
    expect(USER_A.userId).not.toBe(USER_B.userId);
    expect(USER_A.appPassword).not.toBe(USER_B.appPassword);
    expect(USER_A.appPassword.length).toBeGreaterThan(0);
    expect(USER_B.appPassword.length).toBeGreaterThan(0);
  });

  it.each([USER_A, USER_B].map((user) => [user.label, user] as const))(
    "testPrincipal gives user %s a real principal, with that user's id and password",
    async (_label, user) => {
      // The passwords compared here are the fixture's fakes. The password
      // reader answering at all is the proof the real constructor built this
      // object: it answers for nothing else.
      const principal = await testPrincipal(user);

      expect(principal.userId).toBe(user.userId);
      expect(principal.appleId).toBe(user.appleId);
      expect(passwordOf(principal)).toBe(user.appPassword);
    },
  );

  it("gives A and B different principals, and neither answers the other's password", async () => {
    const forA = await testPrincipal(USER_A);
    const forB = await testPrincipal(USER_B);

    expect(forA.userId).not.toBe(forB.userId);
    expect(passwordOf(forA)).not.toBe(passwordOf(forB));
  });

  it("refuses a spread copy of a test principal with the auth error (D-16)", async () => {
    const principal = await testPrincipal(USER_A);
    const copy = { ...principal };

    // The copy is equal field for field, so only its identity differs.
    expect(copy).toEqual(principal);
    // And the original does answer, so the refusal below is about the copy.
    expect(passwordOf(principal)).toBe(USER_A.appPassword);

    let raised: unknown = null;
    try {
      passwordOf(copy);
    } catch (err) {
      raised = err;
    }
    expect(raised, "a spread copy was given a password").toBeInstanceOf(ImapAuthError);
    expect(toErrorCategory(raised).category).toBe("auth_failed");
  });
});
