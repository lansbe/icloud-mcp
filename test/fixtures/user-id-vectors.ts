// The user id spec, written as rows: an input, and what must come out.
//
// PROVENANCE — read this before treating any hex here as evidence.
//
// Every 64-character value in this file was computed ONCE, BY HAND, in a shell,
// with `printf '%s' "<address>" | shasum -a 256`, and then cross-checked a
// second way. Never with `echo`: `echo` appends a newline, the newline is
// hashed along with the address, and the result is a perfectly well-formed
// 64-character value that is simply wrong. A wrong value here would not fail
// loudly. It would become the spec.
//
// NO FINGERPRINTING CODE MAY APPEAR IN THIS FILE, IN ANY TEST, OR IN ANY TEST
// HELPER (D-12). Not to "double-check" a row, not to build a row, not behind a
// helper with a harmless name. The whole value of this file is that Phase 8's
// function is the ONLY place in the repository that turns an address into a
// user id. A second one in a test would agree with the first by construction,
// and two copies that agree by construction prove nothing about either. That is
// why every expected value below is a literal, and why this file imports
// nothing at all.
//
// PHASE 8'S ONE FUNCTION MUST PASS EVERY ROW. An accepted row must produce
// exactly the hex beside it. A refused row must produce the function's "no"
// value, without throwing, and without the typed address appearing in any
// message (D-11).
//
// Invisible and non-ASCII code points are written as escapes, never as the raw
// character. A raw NBSP or BOM in source is indistinguishable from a space or
// from nothing in most editors and most diffs, so a row could be silently
// changed by a formatter and nobody reviewing the change would see it.
//
// Changing a row that is already ACCEPTED is costly: the user id is the key of
// every per-user store, so a changed rule re-keys every store for every user
// the old rule accepted. Refusing more is the safe direction; accepting more,
// or accepting differently, is not (D-09, D-17, D-18, D-19).
//
// The order of the steps is part of the spec. The length cap is measured on
// the input as typed (D-18). Then trim, then refuse anything that is not
// printable ASCII, and only then lowercase (D-19). The kelvin-sign row is the
// one row that tells that last order from the other one.

/** What `expected` holds when the input must be turned away. */
export const REFUSED = "refused";

/** One row of the spec. */
export interface UserIdVector {
  /** A stable handle for the row, used in test names. Unique. */
  readonly name: string;
  /** The Apple ID exactly as typed. Unique. */
  readonly input: string;
  /** 64 lowercase hex characters, or `REFUSED`. */
  readonly expected: string;
  /** Which decision or requirement this row exists to hold in place. */
  readonly pins: string;
}

/** Test user A. `two-users.ts` copies its address and user id from here. */
export const USER_A_VECTOR: UserIdVector = {
  name: "user-a",
  input: "user-a@example.invalid",
  expected: "cf601486d21cb8446e95e8b5b3842c12fd604e94b10f052fc481ec17b4d68455",
  pins: "D-12 user A",
};

/** Test user B. Differs from A by one character, and must not meet A. */
export const USER_B_VECTOR: UserIdVector = {
  name: "user-b",
  input: "user-b@example.invalid",
  expected: "597af2e31f1cf1022bce26c7e3d250e319991cca81fdb83b233560384659a4de",
  pins: "D-12 user B",
};

/** The longest local part that still fits: 238 + 16 = 254 characters. */
const LOCAL_PART_238 = "a".repeat(238);

/** One character too many: 239 + 16 = 255 characters. */
const LOCAL_PART_239 = "a".repeat(239);

/**
 * Every row, in the order the spec was written.
 *
 * Read the accepted rows in two groups. Some must MEET: the padded, the
 * NBSP-padded and the BOM-prefixed spellings of A are all A. Others must STAY
 * APART: a `+tag` address and the three Apple domains are each their own
 * person. Folding any of those together would make two people one user.
 */
export const USER_ID_VECTORS: readonly UserIdVector[] = [
  USER_A_VECTOR,
  USER_B_VECTOR,
  {
    name: "a-padded-mixed-case",
    input: "  User-A@Example.INVALID  ",
    expected: USER_A_VECTOR.expected,
    pins: "D-10 trim ends, ISO-05 lowercase",
  },
  {
    name: "ascii-capital-i",
    input: "USER-I@EXAMPLE.INVALID",
    expected: "47718e90d373789fd68cd89a8ae8d56e5df00b78d6290f94bada74605738a1d7",
    pins: "ISO-05 plain toLowerCase, guards the locale trap",
  },
  {
    name: "plus-tag",
    input: "user-a+tag@example.invalid",
    expected: "710023ee399268e7abdb81f1a2109a28e43ae06fca8f1ce23feabec3fcecf7f7",
    pins: "ISO-05 no +tag folding",
  },
  {
    name: "domain-icloud",
    input: "someone@icloud.com",
    expected: "b5960fefee2142fb38bad61069d16aff7a5dbcd7dc00e8b299b68919a13f18e9",
    pins: "ISO-05 no domain folding",
  },
  {
    name: "domain-me",
    input: "someone@me.com",
    expected: "074a793de657667cbf52d585d45bde313f226a7828e22520019b62cc18659afb",
    pins: "ISO-05 no domain folding",
  },
  {
    name: "domain-mac",
    input: "someone@mac.com",
    expected: "e64ed1b1a6cd66b0510dd70db04829166a527c20487803f3f62002a74c95e988",
    pins: "ISO-05 no domain folding",
  },
  {
    name: "a-nbsp-padded",
    input: "\u00a0user-a@example.invalid\u00a0",
    expected: USER_A_VECTOR.expected,
    pins: "D-18 NBSP removed by trim",
  },
  {
    name: "a-bom-prefixed",
    input: "\ufeffuser-a@example.invalid",
    expected: USER_A_VECTOR.expected,
    pins: "D-18 BOM removed by trim",
  },
  {
    name: "max-length-254",
    input: `${LOCAL_PART_238}@example.invalid`,
    expected: "68c1388e82a845c684acbd4e4fa2ea8b60c419782e138437866f291d357361ab",
    pins: "D-18 longest accepted input",
  },
  {
    name: "empty",
    input: "",
    expected: REFUSED,
    pins: "D-11",
  },
  {
    name: "spaces-only",
    input: "   ",
    expected: REFUSED,
    pins: "D-11",
  },
  {
    name: "no-at-sign",
    input: "no-at-sign",
    expected: REFUSED,
    pins: "D-11, D-17",
  },
  {
    name: "inner-space",
    input: "user a@example.invalid",
    expected: REFUSED,
    pins: "D-10, D-18 space is 0x20",
  },
  {
    name: "inner-tab",
    input: "user\ta@example.invalid",
    expected: REFUSED,
    pins: "D-10 inner control character",
  },
  {
    name: "capital-i-with-dot",
    input: "\u0130user@example.invalid",
    expected: REFUSED,
    pins: "D-09 lowercases to i plus U+0307",
  },
  {
    name: "kelvin-sign",
    input: "\u212aelvin@example.invalid",
    expected: REFUSED,
    pins: "D-09, D-19 checked before lowercase, U+212A lowercases to ASCII k",
  },
  {
    name: "nul-prefixed",
    input: "\u0000user-a@example.invalid",
    expected: REFUSED,
    pins: "D-09, D-10 trim does not remove NUL",
  },
  {
    name: "double-at",
    input: "a@@b",
    expected: REFUSED,
    pins: "D-17",
  },
  {
    name: "empty-local-part",
    input: "@b",
    expected: REFUSED,
    pins: "D-17",
  },
  {
    name: "empty-domain",
    input: "a@",
    expected: REFUSED,
    pins: "D-17",
  },
  {
    name: "two-at-signs",
    input: "user-a@example@invalid",
    expected: REFUSED,
    pins: "D-17 exactly one at sign",
  },
  {
    name: "too-long-255",
    input: `${LOCAL_PART_239}@example.invalid`,
    expected: REFUSED,
    pins: "D-18",
  },
  {
    name: "padded-to-255",
    input: `${LOCAL_PART_238}@example.invalid `,
    expected: REFUSED,
    pins: "D-18, cap measured on the input as typed",
  },
  {
    name: "non-ascii-latin",
    input: "r\u00fcssell@example.invalid",
    expected: REFUSED,
    pins: "D-09",
  },
  {
    name: "inner-del",
    input: "user\u007fa@example.invalid",
    expected: REFUSED,
    pins: "D-18 printable ASCII ends at 0x7E",
  },
  {
    name: "inner-nbsp",
    input: "user\u00a0a@example.invalid",
    expected: REFUSED,
    pins: "D-18 only leading and trailing NBSP is removed",
  },
];
