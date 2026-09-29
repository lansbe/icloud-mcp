// The seam that drives the recall build (Phase 26, RCLL-08; D-26, D-28, D-35).
//
// The seam is under test here, not the step. `recallStep` is replaced by a
// recorder for this file only, so each case can see whether a step ran, when,
// and with what. The real step after a real tool call is in
// test/recall-drive-live.test.ts.
//
// Three halves:
// - the seam's rules, over a small fake server and fake callbacks;
// - which tools are driven, read from the REAL factory by watching what it
//   registers, with a set-equality check, so a new tool must get a row;
// - a text probe on src/mcp/server.ts, so the classification is also pinned
//   where a reader looks for it.

import { McpServer } from "@modelcontextprotocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/recall/sync", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/recall/sync")>()),
  recallStep: vi.fn(async () => "idle"),
  productionStepDeps: vi.fn((leased: unknown) => ({ builtFrom: leased })),
}));

import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import type { LeasedMail } from "../src/agent/lease";
import { createServerFactory } from "../src/mcp/server";
import type { Principal } from "../src/principal";
import { RECALL_DRIVEN, runRecallStep, withRecallStep } from "../src/recall/drive";
import { productionStepDeps, recallStep } from "../src/recall/sync";
import { ownerPrincipal } from "./fixtures/bound-secrets";

type Answer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (...args: unknown[]) => Promise<Answer>;

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// test/lease-coverage.test.ts carries the same comment.
const SERVER_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/server.ts",
  { query: "?raw", import: "default", eager: true },
);
const SERVER_SOURCE: string = Object.values(SERVER_SOURCE_GLOB)[0] ?? "";

/** A leased runner the seam only passes along. It is never called here. */
const MAIL = { withConnectionLease: vi.fn() } as unknown as LeasedMail;

/** An ordinary client id: anything that is not the autonomy client. */
const ORDINARY = "ordinary-client";

function ok(text = "done"): Answer {
  return { content: [{ type: "text", text }] };
}

function failed(): Answer {
  return { isError: true, content: [{ type: "text", text: "{\"category\":\"x\"}" }] };
}

/**
 * A small fake server: `registerTool` keeps each callback, and one data
 * property and one method let a case check the proxy answers them from the
 * real object.
 */
class FakeServer {
  readonly callbacks = new Map<string, Callback>();
  readonly configs = new Map<string, unknown>();
  readonly label = "the real server";
  registerTool(name: string, config: unknown, callback: Callback): string {
    this.configs.set(name, config);
    this.callbacks.set(name, callback);
    return `registered ${name}`;
  }
  whoAmI(): string {
    return this.label;
  }
}

/** Wrap a fake server and register one tool through it; answer its wrapped callback. */
function drivenCallback(
  original: Callback,
  grantClient: () => Promise<string | null> = async () => ORDINARY,
  principal: Promise<Principal> = ownerPrincipal(),
): Callback {
  const fake = new FakeServer();
  const driven = withRecallStep(fake as unknown as McpServer, principal, MAIL, grantClient);
  driven.registerTool("probe", { description: "probe" }, original as never);
  return fake.callbacks.get("probe")!;
}

beforeEach(() => {
  vi.mocked(recallStep).mockReset();
  vi.mocked(recallStep).mockImplementation(async () => "idle");
  vi.mocked(productionStepDeps).mockClear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// The seam's rules
// ---------------------------------------------------------------------------

describe("a wrapped callback (D-26, D-28)", () => {
  it("runs one step after a successful answer, and returns the very same answer object", async () => {
    const answer = ok();
    const wrapped = drivenCallback(async () => answer);

    const returned = await wrapped({ a: 1 });

    expect(returned).toBe(answer);
    expect(recallStep).toHaveBeenCalledTimes(1);
  });

  it("runs the step only after the callback's promise has resolved", async () => {
    let resolve: (answer: Answer) => void = () => {};
    const pending = new Promise<Answer>((settle) => {
      resolve = settle;
    });
    const wrapped = drivenCallback(() => pending);

    const call = wrapped({});
    // Let every microtask the wrapper could run settle.
    await new Promise((settle) => setTimeout(settle, 10));
    expect(recallStep).not.toHaveBeenCalled();

    const answer = ok();
    resolve(answer);
    expect(await call).toBe(answer);
    expect(recallStep).toHaveBeenCalledTimes(1);
  });

  it("the answer does not come back until the step has finished", async () => {
    const order: string[] = [];
    vi.mocked(recallStep).mockImplementation(async () => {
      await new Promise((settle) => setTimeout(settle, 10));
      order.push("step");
      return "idle";
    });
    const wrapped = drivenCallback(async () => {
      order.push("tool");
      return ok();
    });

    await wrapped({});
    order.push("answered");

    expect(order).toEqual(["tool", "step", "answered"]);
  });

  it("passes the same arguments to the original callback", async () => {
    const original = vi.fn(async () => ok());
    const wrapped = drivenCallback(original);
    const args = { query: "x" };
    const extra = { signal: "extra" };

    await wrapped(args, extra);

    expect(original).toHaveBeenCalledWith(args, extra);
  });

  it("runs no step after an error answer", async () => {
    const answer = failed();
    const wrapped = drivenCallback(async () => answer);

    expect(await wrapped({})).toBe(answer);
    expect(recallStep).not.toHaveBeenCalled();
  });

  it("returns the same answer, and throws nothing, when the step rejects", async () => {
    vi.mocked(recallStep).mockRejectedValue(new Error("step failed"));
    const answer = ok();
    const wrapped = drivenCallback(async () => answer);

    const returned = await wrapped({});

    expect(returned).toBe(answer);
    expect(returned.isError).toBeUndefined();
    expect(recallStep).toHaveBeenCalledTimes(1);
  });

  it("rethrows the same value when the callback throws, and runs no step", async () => {
    const thrown = new Error("the callback's own");
    const wrapped = drivenCallback(async () => {
      throw thrown;
    });

    await expect(wrapped({})).rejects.toBe(thrown);
    expect(recallStep).not.toHaveBeenCalled();
  });

  it("carries the driven mark as a non-enumerable property", () => {
    const wrapped = drivenCallback(async () => ok());

    expect((wrapped as unknown as Record<symbol, unknown>)[RECALL_DRIVEN]).toBe(true);
    expect(Object.keys(wrapped)).toEqual([]);
    expect(Object.getOwnPropertyDescriptor(wrapped, RECALL_DRIVEN)?.enumerable).toBe(false);
  });

  it("registers the same name and config on the real server", () => {
    const fake = new FakeServer();
    const driven = withRecallStep(
      fake as unknown as McpServer,
      ownerPrincipal(),
      MAIL,
      async () => ORDINARY,
    );
    const config = { description: "probe" };

    const returned = driven.registerTool("probe", config as never, (async () => ok()) as never);

    expect(fake.configs.get("probe")).toBe(config);
    expect(returned).toBe("registered probe");
  });

  it("answers every other property from the real server, bound to it", () => {
    const fake = new FakeServer();
    const driven = withRecallStep(
      fake as unknown as McpServer,
      ownerPrincipal(),
      MAIL,
      async () => ORDINARY,
    ) as unknown as FakeServer;

    expect(driven.label).toBe("the real server");
    expect(driven.callbacks).toBe(fake.callbacks);
    // Detached from the proxy, a method still reads the real server.
    const { whoAmI } = driven;
    expect(whoAmI()).toBe("the real server");
  });
});

describe("whose grant the request came in on (D-35)", () => {
  const cases: ReadonlyArray<{ name: string; client: () => Promise<string | null> }> = [
    { name: "null", client: async () => null },
    { name: "a rejection", client: async () => Promise.reject(new Error("store down")) },
    { name: "the autonomy client", client: async () => AUTONOMY_CLIENT_ID },
    { name: "an empty string", client: async () => "" },
  ];

  for (const { name, client } of cases) {
    it(`${name}: no step, and the same answer`, async () => {
      const answer = ok();
      const wrapped = drivenCallback(async () => answer, client);

      expect(await wrapped({})).toBe(answer);
      expect(recallStep).not.toHaveBeenCalled();
    });
  }

  it("an ordinary client: the step runs, for the principal, over the request's leased runner", async () => {
    const principal = ownerPrincipal();
    const wrapped = drivenCallback(async () => ok(), async () => ORDINARY, principal);

    await wrapped({});

    expect(recallStep).toHaveBeenCalledTimes(1);
    const [actor, deps] = vi.mocked(recallStep).mock.calls[0]!;
    expect(actor).toBe(await principal);
    expect(productionStepDeps).toHaveBeenCalledWith(MAIL);
    expect(deps).toEqual({ builtFrom: MAIL });
  });

  it("the grant client is not asked after an error answer", async () => {
    const client = vi.fn(async () => ORDINARY);
    const wrapped = drivenCallback(async () => failed(), client);

    await wrapped({});

    expect(client).not.toHaveBeenCalled();
  });
});

describe("runRecallStep never throws", () => {
  it("a principal that rejects: no step, nothing thrown", async () => {
    const refused = Promise.reject(new Error("refused"));
    refused.catch(() => {});

    await expect(runRecallStep(refused, MAIL, async () => ORDINARY)).resolves.toBeUndefined();
    expect(recallStep).not.toHaveBeenCalled();
  });

  it("a wrapped callback over a principal that rejects: same answer, no step", async () => {
    const refused = Promise.reject(new Error("refused")) as Promise<Principal>;
    refused.catch(() => {});
    const answer = ok();
    const wrapped = drivenCallback(async () => answer, async () => ORDINARY, refused);

    expect(await wrapped({})).toBe(answer);
    expect(recallStep).not.toHaveBeenCalled();
  });

  it("a step that throws synchronously is caught too", async () => {
    vi.mocked(recallStep).mockImplementation(() => {
      throw new Error("sync throw");
    });

    await expect(
      runRecallStep(ownerPrincipal(), MAIL, async () => ORDINARY),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Which tools the real factory drives
// ---------------------------------------------------------------------------

/**
 * Every tool the REAL factory registers, by name, with the callback the real
 * server was handed.
 */
function realTools(): Map<string, Callback> {
  const spy = vi.spyOn(McpServer.prototype, "registerTool");
  try {
    createServerFactory(ownerPrincipal())({ era: "modern" } as never);
    const tools = new Map<string, Callback>();
    for (const call of spy.mock.calls as unknown as [string, unknown, Callback][]) {
      const [name, , callback] = call;
      expect(tools.has(name), `${name} registered twice`).toBe(false);
      tools.set(name, callback);
    }
    return tools;
  } finally {
    spy.mockRestore();
  }
}

/**
 * Every tool that runs a step after a successful answer: every tool
 * `registerMailTools` registers, `mail_recall`, and `changes_since`.
 */
const DRIVEN: readonly string[] = [
  // registerMailTools
  "mail_get_message",
  "mail_list_folders",
  "mail_list_messages",
  "mail_find",
  "mail_list_unread",
  "mail_compose_new",
  "mail_compose_reply",
  "mail_get_attachment",
  "mail_stage_attachment",
  "mail_confirm_upload",
  "mail_mark_read",
  "mail_flag",
  "mail_move",
  "mail_archive",
  "mail_trash",
  "mail_delete_draft",
  "mail_commit",
  // registerRecallTools
  "mail_recall",
  // registerChangesTool
  "changes_since",
];

const NOT_MAIL = "not mail: calendar, contacts and DAV tools never run a recall step (D-28)";

/** Every other tool, with the reason it runs no step. */
const NOT_DRIVEN: ReadonlyArray<{ name: string; reason: string }> = [
  {
    name: "mail_imap_diagnose",
    reason:
      "runs on the pause-exempt principal; a step must never sign in for a person whose password Apple just refused",
  },
  { name: "account_whoami", reason: "not mail: it reads the signed-in principal only" },
  { name: "dav_diagnose", reason: NOT_MAIL },
  { name: "calendar_list_calendars", reason: NOT_MAIL },
  { name: "calendar_create_calendar", reason: NOT_MAIL },
  { name: "calendar_update_calendar", reason: NOT_MAIL },
  { name: "calendar_list_events", reason: NOT_MAIL },
  { name: "calendar_get_event", reason: NOT_MAIL },
  { name: "calendar_search", reason: NOT_MAIL },
  { name: "calendar_find_free_slots", reason: NOT_MAIL },
  { name: "calendar_create_event", reason: NOT_MAIL },
  { name: "calendar_update_event", reason: NOT_MAIL },
  { name: "calendar_respond_to_invitation", reason: NOT_MAIL },
  { name: "calendar_delete_event", reason: NOT_MAIL },
  { name: "calendar_delete_calendar", reason: NOT_MAIL },
  { name: "calendar_commit", reason: NOT_MAIL },
  { name: "contacts_search", reason: NOT_MAIL },
  { name: "contacts_get", reason: NOT_MAIL },
  { name: "contacts_create", reason: NOT_MAIL },
  { name: "contacts_update", reason: NOT_MAIL },
  { name: "contacts_commit", reason: NOT_MAIL },
  // Phase 28, decided by Claude (owner may revise): the rules tools manage the
  // person's own rules in their own object. Four open no mail session at all.
  // `rules_test` reads the newest 25 inbox headers once to try a rule, and a
  // recall step after it would be a second iCloud session nobody asked for.
  { name: "rules_list", reason: "not mail: it reads the person's own rules and the job's record only" },
  { name: "rules_add", reason: "not mail: a preview that reads and writes nothing" },
  { name: "rules_commit", reason: "not mail: it adds a rule to the person's own object" },
  { name: "rules_remove", reason: "not mail: it removes a rule from the person's own object" },
  {
    name: "rules_test",
    reason: "tries a rule on 25 inbox headers and writes nothing; a recall step would add a second session",
  },
  // Phase 29.1.1: the backfill the person asks for, on the plain server.
  {
    name: "mail_recall_backfill",
    reason:
      "it is the build itself; a recall step after it would be a second build pass in the same request",
  },
  {
    name: "mail_save_attachment",
    reason:
      "answers with five-minute links and runs one long session; a recall step after it would delay the links (29.1)",
  },
];

function isDriven(callback: Callback): boolean {
  return (callback as unknown as Record<symbol, unknown>)[RECALL_DRIVEN] === true;
}

describe("every registered tool is driven or not driven (D-28)", () => {
  it("the driven and not-driven rows are exactly the tools the real factory registers", () => {
    const registered = [...realTools().keys()].sort();
    const rows = [...DRIVEN, ...NOT_DRIVEN.map((row) => row.name)];

    expect(new Set(rows).size, "a tool has two rows").toBe(rows.length);
    expect([...rows].sort()).toEqual(registered);
  });

  it("the tools carrying the driven mark are exactly the driven rows", () => {
    const tools = realTools();
    const marked = [...tools].filter(([, callback]) => isDriven(callback)).map(([name]) => name);

    expect(marked.sort()).toEqual([...DRIVEN].sort());
  });

  it("every not-driven row states a reason", () => {
    for (const row of NOT_DRIVEN) {
      expect(row.reason.length, row.name).toBeGreaterThan(10);
    }
  });
});

describe("src/mcp/server.ts hands the driven server to the mail registrars only", () => {
  const code = SERVER_SOURCE.split("\n")
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join("\n");

  /** The body of the function the driven server is handed to. */
  function drivenBlock(): string {
    const start = code.indexOf("const registerMailRegistrars = (server: McpServer): void => {");
    const end = code.indexOf("registerMailRegistrars(driven);");
    expect(start, "the driven registrars' function").toBeGreaterThan(-1);
    expect(end, "the driven server handed in").toBeGreaterThan(start);
    return code.slice(start, end);
  }

  it("reads the real source", () => {
    expect(SERVER_SOURCE).toContain("export function createServerFactory(");
  });

  it("the driven server is built once, from the plain one", () => {
    expect(code).toContain(
      "const driven = withRecallStep(server, principal, leasedMail, grantClient);",
    );
    expect((code.match(/withRecallStep\(/g) ?? []).length).toBe(1);
    expect((code.match(/registerMailRegistrars\(driven\);/g) ?? []).length).toBe(1);
  });

  it("registerMailTools, registerRecallTools and registerChangesTool get the driven server", () => {
    const block = drivenBlock();
    expect(block).toContain("registerMailTools(server, leasedMail, principal);");
    expect(block).toContain("registerRecallTools(server, principal);");
    expect(block).toContain("registerChangesTool(server, leasedMail, principal, davFetch);");
    // And each of them is registered nowhere else.
    for (const name of ["registerMailTools(", "registerRecallTools(", "registerChangesTool("]) {
      expect(code.split(name).length - 1, name).toBe(1);
    }
  });

  it("every other registrar gets the plain server, outside the driven block", () => {
    const block = drivenBlock();
    const plain = [
      "registerDiagnoseTool(server, leasedMail, unpaused);",
      "registerAccountTool(server, principal);",
      "registerDavDiagnoseTool(server, davFetch, unpaused);",
      "registerCalendarTools(server, davFetch, principal);",
      "registerContactsTools(server, davFetch, principal);",
    ];
    for (const call of plain) {
      expect(code, call).toContain(call);
      expect(block, call).not.toContain(call);
    }
    expect(code).not.toMatch(/register\w*\(\s*driven\s*,/);
  });

  it("the backfill is registered exactly once, on the plain server, outside the driven block", () => {
    const call = "registerRecallBackfillTool(server, leasedMail, principal, grantClient);";
    const block = drivenBlock();
    expect(code.split(call).length - 1).toBe(1);
    expect((code.match(/registerRecallBackfillTool\(/g) ?? []).length).toBe(1);
    expect(block).not.toContain("registerRecallBackfillTool(");
    // After the driven server is handed in, so it cannot be inside that call.
    expect(code.indexOf(call)).toBeGreaterThan(code.indexOf("registerMailRegistrars(driven);"));
  });
});
