// ARCHITECTURE.md's module map, held to the files under src/ (BND-04).
//
// The map names every source file once, in a table per directory. This test
// fails when a file is added under src/ with no row, and when a row names a
// file that does not exist. It checks names only. What each row says about
// its file is still read by a person.
//
// How a row is read: each "### " heading in the map names one directory in
// backticks, and the rows under it are written relative to that directory.
// "### `mail/` — IMAP" with a row `service.ts` means src/mail/service.ts. The
// heading "### Root (`src/`)" means src/ itself.

import { describe, expect, it } from "vitest";

// A Workers isolate has no filesystem, so files are read with Vite's
// build-time glob, as the other source-reading tests do.
// @ts-expect-error -- Vite's `import.meta.glob` has no ambient declaration here.
const ARCH_GLOB: Record<string, string> = import.meta.glob("../ARCHITECTURE.md", {
  query: "?raw",
  import: "default",
  eager: true,
});
const ARCHITECTURE: string = Object.values(ARCH_GLOB)[0] ?? "";

// @ts-expect-error -- Vite's `import.meta.glob` has no ambient declaration here.
const SRC_GLOB: Record<string, string> = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/** Every file under src/, as a path relative to src/ ("mail/service.ts"). */
const SRC_FILES: string[] = Object.keys(SRC_GLOB)
  .map((key) => key.replace(/^\.\.\/src\//, ""))
  .sort();

/** The module map section: from its heading to the next "## " heading. */
function moduleMapSection(text: string): string {
  const start = text.indexOf("\n## Module map");
  if (start === -1) return "";
  const end = text.indexOf("\n## ", start + 1);
  return end === -1 ? text.slice(start) : text.slice(start, end);
}

/** Every file the map names, as a path relative to src/. */
function mappedFiles(section: string): string[] {
  const files: string[] = [];
  let dir: string | null = null;
  for (const line of section.split("\n")) {
    if (line.startsWith("### ")) {
      const named = line.match(/`([^`]+\/)`/);
      if (!named) throw new Error(`module map heading names no directory: ${line}`);
      dir = named[1] === "src/" ? "" : named[1];
      continue;
    }
    const row = line.match(/^\|\s*`([^`]+)`\s*\|/);
    if (!row) continue;
    if (dir === null) throw new Error(`module map row before any directory heading: ${line}`);
    files.push(dir + row[1]);
  }
  return files.sort();
}

describe("ARCHITECTURE.md module map", () => {
  const section = moduleMapSection(ARCHITECTURE);
  const mapped = mappedFiles(section);

  it("reads something from both sides", () => {
    // Non-vacuity: an empty read on either side would make both checks below pass.
    expect(ARCHITECTURE.length, "the ?raw import of ARCHITECTURE.md loaded nothing").toBeGreaterThan(0);
    expect(section.length, "ARCHITECTURE.md has no '## Module map' section").toBeGreaterThan(0);
    expect(SRC_FILES, "the glob over src/ found fewer files than it should").toContain("index.ts");
    expect(SRC_FILES.length).toBeGreaterThan(50);
    expect(mapped.length, "the module map has no file rows").toBeGreaterThan(50);
  });

  it("names every file under src/", () => {
    const missing = SRC_FILES.filter((file) => !mapped.includes(file));
    expect(
      missing,
      `add a row to ARCHITECTURE.md's module map for: ${missing.map((f) => "src/" + f).join(", ")}`,
    ).toEqual([]);
  });

  it("names no file that does not exist", () => {
    const stale = mapped.filter((file) => !SRC_FILES.includes(file));
    expect(
      stale,
      `ARCHITECTURE.md's module map names files that are not under src/: ${stale.map((f) => "src/" + f).join(", ")}`,
    ).toEqual([]);
  });

  it("names each file once", () => {
    const twice = mapped.filter((file, i) => mapped.indexOf(file) !== i);
    expect(twice, `ARCHITECTURE.md's module map names these twice: ${twice.join(", ")}`).toEqual([]);
  });
});
