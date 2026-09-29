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
import { createServerFactory } from "../src/mcp/server";
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
  await new Promise((resolve) => setTimeout(resolve, 0));
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
// Every drift is caught
// ---------------------------------------------------------------------------
//
// Each case starts from the real README and the real rows, makes one change,
// and asserts the exact kinds reported. The last case checks that these cases
// between them trigger every kind the core declares, so no kind exists that
// nothing can trigger (the same guarantee test/forbidden-tokens.test.ts gives
// its rules).

/** Kinds produced by the cases below, for the set-equality case at the end. */
const produced = new Set<string>();

function kindsOf(readme: string, groups: readonly ToolGroup[]): string[] {
  const kinds = checkReadme(readme, groups, registeredNames(TOOL_SOURCES)).map(
    (finding) => finding.kind,
  );
  for (const kind of kinds) produced.add(kind);
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

describe("every way the tool block can drift is reported", () => {
  it("a row removed from README's block", () => {
    const row = "| `mail_flag` |";
    const line = README.split("\n").find((one) => one.startsWith(row));
    expect(line, "README has no mail_flag row to remove").toBeDefined();
    const edited = README.replace(`${line}\n`, "");
    expect(edited).not.toBe(README);
    expect(kindsOf(edited, TOOL_GROUPS)).toEqual(["block-differs"]);
  });

  it("a registered tool with no row", () => {
    const groups = changeRows("Contacts", (rows) =>
      rows.filter((row) => row.name !== "contacts_commit"),
    );
    expect(kindsOf(withBlock(README, groups), groups)).toEqual(["missing-row"]);
  });

  it("a row for a tool that is not registered", () => {
    const groups = changeRows("Mail", (rows) => [
      ...rows,
      { name: "mail_not_a_tool", line: "Nothing." },
    ]);
    expect(kindsOf(withBlock(README, groups), groups)).toEqual(["unregistered-row"]);
  });

  it("one tool in two groups", () => {
    const groups = changeRows("Rules", (rows) => [
      ...rows,
      { name: "mail_flag", line: "Flag one message." },
    ]);
    expect(kindsOf(withBlock(README, groups), groups)).toEqual(["duplicate-row"]);
  });

  it("README without the markers", () => {
    expect(README).toContain(START_MARKER);
    const edited = README.replace(START_MARKER, "");
    expect(kindsOf(edited, TOOL_GROUPS)).toEqual(["markers-missing"]);
  });

  it("a wrong count line", () => {
    const edited = README.replace(/^\d+ tools in /m, "44 tools in ");
    expect(edited, "the count was already 44, so this case changes nothing").not.toBe(README);
    expect(kindsOf(edited, TOOL_GROUPS)).toEqual(["block-differs"]);
  });

  it("between them, the cases above trigger every declared kind", () => {
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
