// README's tool block, held to the real server (BND-04).
//
// scripts/tool-table-core.mjs renders README's tool count and tables from one
// row per tool. Three things are checked here, against three sources:
//
//   1. The names read from the registrars' source text equal the names the
//      real server answers in tools/list. Reading source text can miss a tool
//      registered through a helper or a loop; this is what catches that.
//   2. The rows' names equal the live names, each once. A new tool with no
//      README line fails here.
//   3. README's block is exactly what the core renders. A hand edit between
//      the markers, a wrong count or a stale row fails here.
//   4. Each number a tool line states equals the constant the code enforces.
//      The expected phrase is built from the constant, never typed, as
//      test/security-numbers.test.ts does for SECURITY.md. Checks 1 to 3 compare
//      names and layout only, so without this a changed constant would leave
//      README stale with every check green.
//
// The server is driven the way test/instructions.test.ts drives it: the real
// per-request factory, raw JSON-RPC over an in-memory pair. No tool is called
// and no socket opens.

import { InMemoryTransport } from "@modelcontextprotocol/server";
import type { JSONRPCMessage } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import {
  FINDING_KINDS,
  START_MARKER,
  TOOL_GROUPS,
  checkReadme,
  registeredNames,
  rowNames,
  withBlock,
} from "../scripts/tool-table-core.mjs";
import type { ToolGroup } from "../scripts/tool-table-core.mjs";
import { JOB_CADENCE_MS } from "../src/agent/cadence";
import { MAX_CHANGE_FOLDERS } from "../src/change-marker";
import { MOVE_SET_CAP } from "../src/mail/triage";
import { createServerFactory } from "../src/mcp/server";
import { RECALL_PAGE_SIZE } from "../src/recall/retention";
import { RECALL_BACKFILL_BUDGET_MS, RECALL_BACKFILL_MAX_PAGES } from "../src/recall/sync";
import { SAVE_LINK_TTL_MS } from "../src/save/link";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// A Workers isolate has no filesystem, so files are read with Vite's
// build-time glob, as the other source-reading tests do.
// @ts-expect-error -- Vite's `import.meta.glob` has no ambient declaration here.
const TOOL_SOURCES: Record<string, string> = import.meta.glob("../src/mcp/tools/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

// @ts-expect-error -- Vite's `import.meta.glob` has no ambient declaration here.
const README_GLOB: Record<string, string> = import.meta.glob("../README.md", {
  query: "?raw",
  import: "default",
  eager: true,
});
const README: string = Object.values(README_GLOB)[0] ?? "";

/** The names the real server lists, sorted. */
async function liveToolNames(): Promise<string[]> {
  const server = await createServerFactory(ownerPrincipal())({ era: "modern" });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const received: Record<string, unknown>[] = [];
  clientSide.onmessage = (message) => {
    received.push(message as unknown as Record<string, unknown>);
  };
  await clientSide.start();
  await server.connect(serverSide);
  const requests: JSONRPCMessage[] = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2026-07-28",
        capabilities: {},
        clientInfo: { name: "tool-table-gate", version: "0" },
      },
    },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ];
  for (const request of requests) await clientSide.send(request);
  // Wait for the tools/list answer itself, not a fixed number of ticks, so a
  // slower handler does not make this flaky. Two seconds is far past any real
  // wait; the checks below report a missing answer by name.
  const deadline = Date.now() + 2000;
  while (!received.some((message) => message.id === 2) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  await server.close();

  const answer = received.find((message) => message.id === 2);
  expect(answer, "tools/list got no answer").toBeDefined();
  expect(answer?.error, "tools/list answered with an error").toBeUndefined();
  const tools = (answer?.result as { tools?: { name: string }[] } | undefined)?.tools;
  expect(tools, "tools/list answered with no tools array").toBeDefined();
  return tools!.map((tool) => tool.name).sort();
}

describe("README's tool block matches the running server", () => {
  it("reads something from every source it compares", async () => {
    // Non-vacuity: an empty glob or an empty list would make every set
    // comparison below a comparison of two empty things.
    expect(Object.keys(TOOL_SOURCES).length).toBeGreaterThan(5);
    expect(README.length).toBeGreaterThan(1000);
    expect((await liveToolNames()).length).toBeGreaterThan(0);
  });

  it("finds in the registrars' source exactly the tools the server lists", async () => {
    expect(registeredNames(TOOL_SOURCES)).toEqual(await liveToolNames());
  });

  it("has one row for each registered tool, and no other rows", async () => {
    const rows = rowNames(TOOL_GROUPS);
    expect(new Set(rows).size, "a tool has more than one row").toBe(rows.length);
    expect([...rows].sort()).toEqual(await liveToolNames());
  });

  it("finds nothing wrong with the real README", async () => {
    expect(checkReadme(README, TOOL_GROUPS, await liveToolNames())).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The numbers in the tool lines equal the constants
// ---------------------------------------------------------------------------

const MINUTE_MS = 60 * 1000;
const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];

/** A small count as README writes it: as a word. */
function word(n: number): string {
  const one = WORDS[n];
  expect(one, `${n} has no word; the README line needs new words`).toBeDefined();
  return one!;
}

/** One tool's README line, whitespace collapsed. */
function line(name: string): string {
  const row = TOOL_GROUPS.flatMap((one) => one.rows).find((one) => one.name === name);
  expect(row, `no row for ${name}`).toBeDefined();
  return row!.line.replace(/\s+/g, " ");
}

/**
 * The rules test's message count. It is a private constant in its registrar, so
 * it is read from that file's text rather than imported.
 */
function rulesTestMessages(): number {
  const text = Object.entries(TOOL_SOURCES).find(([path]) => path.endsWith("/rules.ts"))?.[1];
  expect(text, "the rules registrar was not read").toBeDefined();
  const found = /\bconst TEST_MESSAGES = (\d+);/.exec(text!);
  expect(found, "src/mcp/tools/rules.ts has no `const TEST_MESSAGES = <n>;`").not.toBeNull();
  return Number(found![1]);
}

describe("each number in a README tool line equals its constant", () => {
  it("mail_recall_backfill states the pages, page size and time limit", () => {
    const backfill = line("mail_recall_backfill");
    expect(backfill).toContain(
      `up to ${RECALL_BACKFILL_MAX_PAGES} pages of ${RECALL_PAGE_SIZE} messages`,
    );
    expect(RECALL_BACKFILL_BUDGET_MS % 1000).toBe(0);
    expect(backfill).toContain(`A ${RECALL_BACKFILL_BUDGET_MS / 1000}-second time limit`);
    // "4 or 5 pages" is a measurement (29.1.1 UAT), not a constant. The message
    // count that follows it is that measurement times the page size.
    expect(backfill).toContain(
      `after 4 or 5 pages, about ${4 * RECALL_PAGE_SIZE} to ${5 * RECALL_PAGE_SIZE} messages`,
    );
  });

  it("the move, archive and Trash previews state the move cap", () => {
    for (const name of ["mail_move", "mail_archive", "mail_trash"]) {
      expect(line(name)).toContain(`up to ${MOVE_SET_CAP} messages`);
    }
  });

  it("mail_save_attachment states the link's lifetime", () => {
    expect(SAVE_LINK_TTL_MS % MINUTE_MS).toBe(0);
    expect(line("mail_save_attachment")).toContain(
      `valid ${word(SAVE_LINK_TTL_MS / MINUTE_MS)} minutes`,
    );
  });

  it("changes_since states the folder cap", () => {
    expect(line("changes_since")).toContain(`up to ${word(MAX_CHANGE_FOLDERS)} folders you name`);
  });

  it("rules_test states how many messages it tries", () => {
    expect(line("rules_test")).toContain(`newest ${rulesTestMessages()} inbox messages`);
  });

  it("the Rules intro states the job's cadence", () => {
    const intro = TOOL_GROUPS.find((one) => one.heading === "Rules")?.intro;
    expect(intro, "the Rules group has no intro").toBeTruthy();
    expect(JOB_CADENCE_MS % MINUTE_MS).toBe(0);
    expect(intro!.replace(/\s+/g, " ")).toContain(`every ${JOB_CADENCE_MS / MINUTE_MS} minutes`);
  });
});

// ---------------------------------------------------------------------------
// Every drift is caught
// ---------------------------------------------------------------------------
//
// Each case starts from the real README and the real rows, makes one change,
// and asserts the exact kinds reported. The last case checks that these cases
// between them trigger every kind the core declares, so no kind exists that
// nothing can trigger (the same guarantee test/forbidden-tokens.test.ts gives
// its rules). It runs every case itself rather than reading what the other
// cases left behind, so it holds when run alone or in any order.

/** The distinct kinds `checkReadme` reports for this README and these rows, sorted. */
function kindsOf(readme: string, groups: readonly ToolGroup[]): string[] {
  const kinds = checkReadme(readme, groups, registeredNames(TOOL_SOURCES)).map(
    (finding) => finding.kind,
  );
  return [...new Set(kinds)].sort();
}

/** The real groups, with `change` applied to a copy of one group's rows. */
function changeRows(
  heading: string,
  change: (rows: ToolGroup["rows"][number][]) => ToolGroup["rows"][number][],
): ToolGroup[] {
  const found = TOOL_GROUPS.some((one) => one.heading === heading);
  expect(found, `no group headed ${heading}`).toBe(true);
  return TOOL_GROUPS.map((one) =>
    one.heading === heading ? { ...one, rows: change([...one.rows]) } : one,
  );
}

/** One drift: a name, the kinds it must report, and a function that makes it. */
interface Drift {
  readonly name: string;
  readonly expected: readonly string[];
  readonly make: () => { readme: string; groups: readonly ToolGroup[] };
}

const DRIFTS: readonly Drift[] = [
  {
    name: "a row removed from README's block",
    expected: ["block-differs"],
    make: () => {
      const row = "| `mail_flag` |";
      const line = README.split("\n").find((one) => one.startsWith(row));
      expect(line, "README has no mail_flag row to remove").toBeDefined();
      const edited = README.replace(`${line}\n`, "");
      expect(edited).not.toBe(README);
      return { readme: edited, groups: TOOL_GROUPS };
    },
  },
  {
    name: "a registered tool with no row",
    expected: ["missing-row"],
    make: () => {
      const groups = changeRows("Contacts", (rows) =>
        rows.filter((row) => row.name !== "contacts_commit"),
      );
      return { readme: withBlock(README, groups), groups };
    },
  },
  {
    name: "a row for a tool that is not registered",
    expected: ["unregistered-row"],
    make: () => {
      const groups = changeRows("Mail", (rows) => [
        ...rows,
        { name: "mail_not_a_tool", line: "Nothing." },
      ]);
      return { readme: withBlock(README, groups), groups };
    },
  },
  {
    name: "one tool in two groups",
    expected: ["duplicate-row"],
    make: () => {
      const groups = changeRows("Rules", (rows) => [
        ...rows,
        { name: "mail_flag", line: "Flag one message." },
      ]);
      return { readme: withBlock(README, groups), groups };
    },
  },
  {
    name: "README without the markers",
    expected: ["markers-missing"],
    make: () => {
      expect(README).toContain(START_MARKER);
      return { readme: README.replace(START_MARKER, ""), groups: TOOL_GROUPS };
    },
  },
  {
    name: "a wrong count line",
    expected: ["block-differs"],
    make: () => {
      const edited = README.replace(/^\d+ tools in /m, "44 tools in ");
      expect(edited, "the count was already 44, so this case changes nothing").not.toBe(README);
      return { readme: edited, groups: TOOL_GROUPS };
    },
  },
];

describe("every way the tool block can drift is reported", () => {
  for (const drift of DRIFTS) {
    it(drift.name, () => {
      const { readme, groups } = drift.make();
      expect(kindsOf(readme, groups)).toEqual([...drift.expected]);
    });
  }

  it("between them, the cases above trigger every declared kind", () => {
    const produced = new Set<string>();
    for (const drift of DRIFTS) {
      const { readme, groups } = drift.make();
      for (const kind of kindsOf(readme, groups)) produced.add(kind);
    }
    expect([...produced].sort()).toEqual([...FINDING_KINDS].sort());
  });
});

describe("the registrar reader", () => {
  it("resolves a tool named by a same-file constant", () => {
    const source =
      'export const X_TOOL_NAME = "x_tool";\n' +
      "server.registerTool(\n  X_TOOL_NAME,\n  {},\n);\n" +
      'server.registerTool("y_tool", {});\n';
    expect(registeredNames({ "a.ts": source })).toEqual(["x_tool", "y_tool"]);
  });

  it("refuses a tool named by something it cannot resolve, rather than skipping it", () => {
    const source = "server.registerTool(nameFromSomewhere, {});\n";
    expect(() => registeredNames({ "a.ts": source })).toThrow(/nameFromSomewhere/);
  });
});
