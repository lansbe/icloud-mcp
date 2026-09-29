// SECURITY.md's numbers, held to the constants in the code (BND-04).
//
// SECURITY.md's recall section ends by saying "a check keeps this section equal
// to them". This file is that check. It reads SECURITY.md as text and asserts
// that the recall section and the autonomous rules section state each number
// exactly as the code has it. Each expected phrase is built from its constant,
// never typed, so changing a constant turns this red until the text changes too.
//
// Text is compared with runs of whitespace collapsed to one space, because the
// file wraps its lines and a phrase can cross a line break.

import { describe, expect, it } from "vitest";

import { JOB_CADENCE_MS } from "../src/agent/cadence";
import { MAX_DRAFTS_PER_DAY, MAX_DRAFTS_PER_RUN, MAX_FLAGS_PER_RUN } from "../src/agent/job";
import { RECALL_PAGE_PAUSE_MS } from "../src/agent/recall-ledger";
import { MAX_RULES } from "../src/agent/rules";
import { LEASE_TTL_MS } from "../src/agent/user-agent";
import {
  RECALL_BACKFILL_MAX_PAGES_PER_DAY,
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
  RECALL_TTL_MS,
} from "../src/recall/retention";
import { RECALL_BACKFILL_MAX_PAGES } from "../src/recall/sync";

// A Workers isolate has no filesystem, so the file is read with Vite's
// build-time glob, as the other source-reading tests do.
// @ts-expect-error -- Vite's `import.meta.glob` has no ambient declaration here.
const SECURITY_GLOB: Record<string, string> = import.meta.glob("../SECURITY.md", {
  query: "?raw",
  import: "default",
  eager: true,
});
const SECURITY: string = Object.values(SECURITY_GLOB)[0] ?? "";

/** One "### " section, from its heading to the next heading, whitespace collapsed. */
function section(heading: string): string {
  const start = SECURITY.indexOf(`\n### ${heading}\n`);
  if (start === -1) return "";
  const rest = SECURITY.slice(start + 1);
  const end = rest.search(/\n##+ /);
  return (end === -1 ? rest : rest.slice(0, end)).replace(/\s+/g, " ");
}

/** A count as SECURITY.md writes it: with a thousands separator. */
function count(n: number): string {
  return n.toLocaleString("en-US");
}

const DAY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;

const RECALL = section("Recall keeps a searchable copy of your recent mail");
const RULES = section("Autonomous rules");
const CONNECTIONS = section("One connection per request");

describe("SECURITY.md's numbers equal the constants in the code", () => {
  it("read SECURITY.md and found every section it checks", () => {
    expect(SECURITY.length).toBeGreaterThan(10000);
    expect(RECALL.length).toBeGreaterThan(500);
    expect(RULES.length).toBeGreaterThan(500);
    expect(CONNECTIONS.length).toBeGreaterThan(200);
  });

  it("the recall section states the retention window, page size and pace", () => {
    const days = RECALL_TTL_MS / DAY_MS;
    expect(Number.isInteger(days)).toBe(true);
    expect(RECALL).toContain(`from the last ${days} days`);
    expect(RECALL).toContain(`Each entry expires ${days} days after its message's date.`);
    expect(RECALL).toContain(`one page of ${RECALL_PAGE_SIZE} messages at a time`);
    // The pause is written as "one page a minute"; any other pause needs new words.
    expect(RECALL_PAGE_PAUSE_MS).toBe(MINUTE_MS);
    expect(RECALL).toContain("at most one page a minute");
  });

  it("the recall section states the backfill's pages per call", () => {
    expect(RECALL).toContain(`Each call reads up to ${RECALL_BACKFILL_MAX_PAGES} pages`);
  });

  it("the recall section states the ceilings", () => {
    expect(RECALL).toContain(`Each person holds at most ${count(RECALL_MAX_VECTORS)} entries.`);
    expect(RECALL).toContain(
      `Ordinary calls read at most ${count(RECALL_MAX_PAGES_PER_DAY)} pages for one person in one day.`,
    );
    expect(RECALL).toContain(
      `They read at most ${count(RECALL_BACKFILL_MAX_PAGES_PER_DAY)} pages for one person in one day`,
    );
    // "which is enough to fill 10,000 entries once"
    expect(RECALL_BACKFILL_MAX_PAGES_PER_DAY * RECALL_PAGE_SIZE).toBeGreaterThanOrEqual(RECALL_MAX_VECTORS);
    expect(RECALL).toContain(`enough to fill ${count(RECALL_MAX_VECTORS)} entries once`);
  });

  it("the recall section states the lease length", () => {
    expect(LEASE_TTL_MS % 1000).toBe(0);
    expect(RECALL).toContain(`outlast its ${LEASE_TTL_MS / 1000}-second lease`);
  });

  it("the recall section names every file its numbers come from", () => {
    for (const file of ["src/recall/retention.ts", "src/recall/sync.ts", "src/agent/recall-ledger.ts"]) {
      expect(RECALL).toContain(`\`${file}\``);
    }
  });

  it("the autonomous rules section states the cadence and the limits", () => {
    const minutes = JOB_CADENCE_MS / MINUTE_MS;
    expect(Number.isInteger(minutes)).toBe(true);
    expect(RULES).toContain(`every ${minutes} minutes`);
    expect(RULES).toContain(
      `Limits: ${MAX_FLAGS_PER_RUN} flags and ${MAX_DRAFTS_PER_RUN} replies a run, ` +
        `${MAX_DRAFTS_PER_DAY} replies a day, ${MAX_RULES} rules.`,
    );
  });

  it("the connection section states the lease length", () => {
    expect(CONNECTIONS).toContain(`the lease ends on its own after ${LEASE_TTL_MS / 1000} seconds`);
  });
});
