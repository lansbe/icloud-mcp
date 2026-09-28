// The per-person object never reaches mail code or the recall driver (Phase 26,
// D-21).
//
// The object holds the person's connection lease, their recall ledger and their
// recall state, and it never opens a socket (Phase 24 D-03). An open socket
// keeps a Durable Object resident and billed, and escapes the deadline that
// bounds every mail conversation in the Worker request.
//
// Phase 26 put code that reaches mail under `src/recall/`: the step, the IMAP
// page source and the driver that runs the step after a mail call. The object
// already imports from `src/recall/` (the store, the lifecycle, the retention
// numbers), so that directory is where a careless import would first cross.
// The scan's object-imports rule only sees the object module's OWN imports, and
// only of the mail, DAV, tool, auth, staging and feed trees. This test follows
// the imports all the way down. It also keeps the object from reaching the
// driver: an object that could reach the driver could build an index from its
// alarm, which the owner ruled out on 2026-09-27.
//
// WHAT COUNTS AS AN IMPORT. Every relative specifier in a static import, a
// side-effect import, a static re-export, or a dynamic import. Only the two
// statement forms the compiler erases are skipped: `import type ... from` and
// `export type ... from`. An import whose braces hold only `type` members is
// NOT skipped, because tsconfig sets `verbatimModuleSyntax`, and under it that
// statement is kept as a bare import and the module is loaded at run time.
// Package specifiers (`cloudflare:workers`, npm packages) are not followed.
//
// A relative specifier that resolves to no file fails the test rather than
// being dropped, so an edge cannot leave the closure by being mis-resolved.
//
// Static, under Node: it reads source text and runs nothing. The text comes in
// through Vite's `?raw` glob, as test/forbidden-tokens.test.ts does, because
// this project carries no Node type package.

import { describe, expect, it } from "vitest";

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see test/forbidden-tokens.test.ts.
const GLOBBED: Record<string, string> = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/** Every source file under src/, keyed by its repo-relative path. */
const SOURCES: Record<string, string> = Object.fromEntries(
  Object.entries(GLOBBED).map(([key, text]) => [key.replace(/^\.\.\//, ""), text]),
);

/** Where the walk starts. */
const OBJECT_MODULE = "src/agent/user-agent.ts";

/** What the object's closure must never reach. */
const FORBIDDEN = [
  "src/mail/service.ts",
  "src/mail/socket.ts",
  "src/recall/sync.ts",
  "src/recall/mail-source.ts",
  "src/recall/drive.ts",
];

/** Blank block and line comments, so an import quoted in prose is not an edge.
 *  Strings are not parsed: a `//` inside a string is rare in import position,
 *  and blanking too much can only drop an edge from a comment-shaped string. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");
}

/**
 * The relative specifiers `text` loads at run time.
 *
 * The middle of a static import or re-export is held to names, braces, commas,
 * `*` and whitespace, so a match cannot run across a function body to a
 * `from` somewhere later in the file.
 */
function valueSpecifiers(text: string): string[] {
  const code = withoutComments(text);
  const found: string[] = [];
  const staticForm = /\b(import|export)\s+(type\s+)?[\w$\s{},*]*?\bfrom\s*["']([^"']+)["']/g;
  for (const match of code.matchAll(staticForm)) {
    if (match[2] !== undefined) continue;
    found.push(match[3]!);
  }
  for (const match of code.matchAll(/\bimport\s*["']([^"']+)["']/g)) found.push(match[1]!);
  for (const match of code.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) found.push(match[1]!);
  return found.filter((specifier) => specifier.startsWith("./") || specifier.startsWith("../"));
}

/** Resolve a relative specifier from `fromFile` against `sources`, or null. */
function resolveSpecifier(
  fromFile: string,
  specifier: string,
  sources: Record<string, string>,
): string | null {
  const parts = fromFile.split("/").slice(0, -1);
  for (const segment of specifier.split("/")) {
    if (segment === "." || segment === "") continue;
    if (segment === "..") parts.pop();
    else parts.push(segment);
  }
  const base = parts.join("/");
  const stem = base.replace(/\.(?:js|ts)$/, "");
  for (const candidate of [`${stem}.ts`, `${base}/index.ts`]) {
    if (Object.hasOwn(sources, candidate)) return candidate;
  }
  return null;
}

/**
 * Every file `start` loads at run time, itself included, breadth first.
 * Throws on a relative specifier that resolves to nothing.
 */
function valueClosure(start: string, sources: Record<string, string>): Set<string> {
  const seen = new Set<string>([start]);
  const queue = [start];
  while (queue.length > 0) {
    const file = queue.shift()!;
    const text = sources[file];
    if (text === undefined) throw new Error(`no source for ${file}`);
    for (const specifier of valueSpecifiers(text)) {
      const target = resolveSpecifier(file, specifier, sources);
      if (target === null) throw new Error(`${file} imports ${specifier}, which resolves to no file`);
      if (seen.has(target)) continue;
      seen.add(target);
      queue.push(target);
    }
  }
  return seen;
}

describe("the per-person object's import closure (Phase 26, D-21)", () => {
  it("globbed the source tree, including every file it walks from and forbids", () => {
    for (const file of [OBJECT_MODULE, "src/mcp/server.ts", ...FORBIDDEN]) {
      expect(Object.hasOwn(SOURCES, file), `${file} was not globbed`).toBe(true);
    }
  });

  it("never reaches mail code, the step, the page source or the driver", () => {
    const closure = valueClosure(OBJECT_MODULE, SOURCES);
    expect(closure.size).toBeGreaterThan(1);
    const reached = FORBIDDEN.filter((file) => closure.has(file));
    expect(reached, `the object's closure: ${[...closure].sort().join(", ")}`).toEqual([]);
  });

  it("the walker is real: from the tool factory it reaches the driver and the step", () => {
    // A positive control. A walker that found nothing would pass the case
    // above by accident; this one must find the path the factory really takes.
    const closure = valueClosure("src/mcp/server.ts", SOURCES);
    expect(closure.has("src/recall/drive.ts")).toBe(true);
    expect(closure.has("src/recall/sync.ts")).toBe(true);
    expect(closure.has("src/mail/service.ts")).toBe(true);
  });

  it("skips only the erased type-only forms, and follows every value form", () => {
    const sources = {
      "src/a.ts": [
        'import type { T } from "./erased-import";',
        'export type { U } from "./erased-export";',
        'import { type V } from "./kept-inline-type";',
        'import { w } from "./named";',
        'import * as x from "./namespace";',
        'import "./side-effect";',
        'export * from "./star";',
        'export {\n  y,\n  z,\n} from "./multi-line";',
        'const later = await import("./dynamic");',
        '// import { q } from "./commented";',
        'import { cloud } from "cloudflare:workers";',
      ].join("\n"),
      "src/erased-import.ts": "",
      "src/erased-export.ts": "",
      "src/kept-inline-type.ts": "",
      "src/named.ts": "",
      "src/namespace.ts": "",
      "src/side-effect.ts": "",
      "src/star.ts": "",
      "src/multi-line.ts": "",
      "src/dynamic.ts": "",
      "src/commented.ts": "",
    };
    expect([...valueClosure("src/a.ts", sources)].sort()).toEqual(
      [
        "src/a.ts",
        "src/dynamic.ts",
        "src/kept-inline-type.ts",
        "src/multi-line.ts",
        "src/named.ts",
        "src/namespace.ts",
        "src/side-effect.ts",
        "src/star.ts",
      ].sort(),
    );
  });

  it("resolves a directory to its index, and follows an edge through a middle module", () => {
    const sources = {
      "src/agent/o.ts": 'import { m } from "./middle";',
      "src/agent/middle.ts": 'import { s } from "../recall";',
      "src/recall/index.ts": 'export { s } from "./sync.js";',
      "src/recall/sync.ts": "",
    };
    expect(valueClosure("src/agent/o.ts", sources).has("src/recall/sync.ts")).toBe(true);
  });

  it("fails loudly on a relative import that resolves to no file", () => {
    expect(() => valueClosure("src/a.ts", { "src/a.ts": 'import { m } from "./missing";' })).toThrow(
      /resolves to no file/,
    );
  });
});
