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
  TOOL_GROUPS,
  checkReadme,
  registeredNames,
  rowNames,
} from "../scripts/tool-table-core.mjs";
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
