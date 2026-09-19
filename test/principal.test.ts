// The one function that turns an Apple ID into a user id, run over the spec.
//
// **What this file proves.** Three things.
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
// 3. Nothing under `src/` imports the principal module yet. Phase 8 is
//    groundwork, and "nothing that ships today calls it" is how the phase
//    shows it changed no behaviour.
//
// **What this file cannot prove, and why.** It cannot show that a hex value in
// the vectors file is right. It only shows that the function and the file
// agree. The values were computed once, by hand, outside the repository, and
// the vectors file's own header says how. Nothing here computes a fingerprint:
// every comparison is between a result of the one function and a literal from
// the vectors file, or between two results of the one function.
//
// The no-importer test reads source text. It sees a `from` clause, a dynamic
// import and a bare side-effect import whose quoted path ends in the module's
// name. It cannot see a path built at runtime, and it does not look outside
// `src/`. Tests may import the module. That is how it gets tested.
//
// **What would make it pass for the wrong reason.** Three things. A filter
// that matched no rows, so a walk ran zero cases and reported green: the first
// test asserts a floor on both groups before anything walks them. A missing
// `await`: the function returns a Promise, so a call that is not awaited
// compares a Promise with a string, and a not-equal check then passes for
// ever. Every call below is awaited inside an async body. And a source glob
// that loaded nothing, so "no file imports it" was true of an empty set: the
// glob's size and two named members are asserted before the offender list,
// and the matcher is shown to match a real import line.
//
// **The no-importer test goes red on purpose in Phase 9.** Phase 9 adds the
// first real importer. When it does, this test fails, and that is the signal
// it was built to give. Phase 9 replaces it with a count rule in the scan,
// which says exactly which files may import the module. Do not loosen the
// matcher to get past it.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID. Every address sits under `example.invalid`.

import { describe, expect, it } from "vitest";
import { userIdOf } from "../src/principal";
import { REFUSED, USER_ID_VECTORS } from "./fixtures/user-id-vectors";

/** What a user id must look like. */
const FULL_HEX = /^[0-9a-f]{64}$/;

/** The rows the spec accepts. */
const HEX_ROWS = USER_ID_VECTORS.filter((row) => row.expected !== REFUSED);

/** The rows the spec turns away. */
const REFUSED_ROWS = USER_ID_VECTORS.filter((row) => row.expected === REFUSED);

/** The directory the no-importer test owns. Every key in `SOURCES` begins with it. */
const SRC_DIR = "src/";

/** The module nobody may import yet. It is the one file the test skips. */
const PRINCIPAL = "src/principal.ts";

// This project carries no Node type package and a Workers isolate has no
// filesystem, so the sources are read with Vite's build-time glob, as
// `test/dav-home-containment.test.ts` does. The one suppression is proven
// non-vacuous by `tsc` itself, which errors on one that suppresses nothing.
// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see above.
const GLOBBED: Record<string, string> = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/**
 * A glob key as a repository-relative path.
 *
 * Sliced from `src/` rather than stripped of a leading `../`, because the exact
 * prefix of a glob key belongs to the bundler. A key that does not contain the
 * directory at all is returned unchanged, and the non-vacuity test then reports
 * it rather than this function hiding it behind a silent rename.
 */
function repoPathOf(globKey: string): string {
  const index = globKey.indexOf(SRC_DIR);
  return index === -1 ? globKey : globKey.slice(index);
}

/** The whole source tree as text, typed on the way in so nothing is `any`. */
const SOURCES: Record<string, string> = Object.fromEntries(
  Object.entries(GLOBBED).map(([key, text]) => [repoPathOf(key), text]),
);

/**
 * Matches an import of the principal module, and never the bare word.
 *
 * The word `from` or the word `import`, optional white space, an optional
 * opening parenthesis, a quote, any path text, then a slash, the module's name
 * and the closing quote. That covers a `from` clause (a type-only one
 * included), a dynamic import and a bare side-effect import. A file extension
 * before the closing quote is allowed for, so spelling the path with one is not
 * a way past.
 *
 * It must match the import specifier and not the word: several files under
 * `src/` already hold that word inside DAV names, and none of them imports
 * this module.
 */
const IMPORTS_THE_PRINCIPAL =
  /\b(?:from|import)\s*\(?\s*["'][^"'\n]*\/principal(?:\.[cm]?[jt]s)?["']/;

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

describe("nothing that ships today imports the principal module", () => {
  it("loaded the whole src/ tree as text", () => {
    // Non-vacuity before anything else. A glob that matched nothing, a glob
    // that did not recurse, and a raw import that came back empty would each
    // leave the offender list below empty for the wrong reason.
    expect(
      Object.keys(SOURCES).length,
      "the src/ glob loaded too few files: it matched nothing, or it did not recurse into the subdirectories",
    ).toBeGreaterThan(30);

    for (const [file, source] of Object.entries(SOURCES)) {
      expect(
        file.startsWith(SRC_DIR) && file.endsWith(".ts"),
        `${file} is not a src/ TypeScript path`,
      ).toBe(true);
      expect(typeof source, `${file} did not load as text`).toBe("string");
      expect(source.length, `${file} loaded empty`).toBeGreaterThan(0);
    }

    // One file at the root and proof the module itself was read. The second
    // also shows the skip below is skipping something real.
    expect(Object.keys(SOURCES), "the glob missed the module itself").toContain(
      PRINCIPAL,
    );
    expect(Object.keys(SOURCES), "the glob missed the root of src/").toContain(
      "src/index.ts",
    );
    // And one file two directories down, so a glob that stopped at the first
    // level cannot pass for a recursive one.
    expect(
      Object.keys(SOURCES).some((file) => file.startsWith("src/mcp/tools/")),
      "the glob did not reach src/mcp/tools/",
    ).toBe(true);
  });

  it("matches an import of the module, in each of its three forms", () => {
    // The matcher's own control. If it cannot match these, an empty offender
    // list below means nothing.
    const fromClause = 'import { userIdOf } from "./principal";';
    const typeOnly = "import type { Principal } from '../principal';";
    const dynamic = 'const loaded = await import("../principal");';
    const sideEffect = 'import "./principal";';
    for (const line of [fromClause, typeOnly, dynamic, sideEffect]) {
      expect(IMPORTS_THE_PRINCIPAL.test(line), `did not match: ${line}`).toBe(true);
    }
  });

  it("does not match the bare word inside a DAV name", () => {
    expect(IMPORTS_THE_PRINCIPAL.test("principalUrl")).toBe(false);
    expect(
      IMPORTS_THE_PRINCIPAL.test('import { principalUrl } from "./discovery";'),
    ).toBe(false);
    expect(IMPORTS_THE_PRINCIPAL.test('from "./principal-url"')).toBe(false);
  });

  it("finds no file under src/ that imports it", () => {
    const importers = Object.entries(SOURCES)
      .filter(([file]) => file !== PRINCIPAL)
      .filter(([, source]) => IMPORTS_THE_PRINCIPAL.test(source))
      .map(([file]) => file)
      .sort();

    expect(
      importers,
      "a file under src/ imports the principal module. Phase 8 lands it with no caller. If this is Phase 9 adding the first one, replace this test with the count rule in the scan.",
    ).toEqual([]);
  });
});
