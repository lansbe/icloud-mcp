// Every tool the server registers, checked against the connection lease
// (Phase 24, DOBJ-02, DOBJ-03, DOBJ-04, D-07).
//
// **A new mail tool must get a row here.** The tool set is not typed out in
// this file. It is read from the REAL server factory, `createServerFactory`,
// by watching what it registers. So a tool added to the factory later, by any
// phase, is inside the set without anyone editing this file, and the
// set-equality case fails until the tool has a row: leased, or not leased with
// a reason.
//
// Two halves, on purpose:
// - behaviour: with the person's lease held by another request, every leased
//   tool answers `connection_busy` and opens no socket, and every tool at all
//   opens no socket;
// - structure: no registrar in src/mcp/server.ts is handed the raw gate.
//
// Each leased row asserts `connection_busy` SPECIFICALLY, never just "an
// error". A row whose arguments were refused for some other reason (a bad id,
// a missing field) would fail, not pass quietly. A vacuous row is the failure
// this file exists to prevent.
//
// The socket module is mocked for this file only, so no network connection is
// opened and nothing signs in to a real Apple ID. The DAV side's `fetch` is
// stubbed to fail, so no DAV request leaves the test either. The object is the
// real `UserAgent` in the pool, seeded through `runInDurableObject`.

import { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import type { UserAgent } from "../src/agent/user-agent";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  mailMoveChangeHashOf,
  mintConfirmation,
  reserveConfirmation,
} from "../src/confirm";
import {
  encodeAddressBookId,
  encodeCalendarId,
  encodeContactId,
  encodeEventId,
} from "../src/dav/ids";
import { SAFE_MESSAGES } from "../src/errors";
import {
  encodeAttachmentId,
  encodeFolderId,
  encodeMessageId,
  encodeUploadId,
} from "../src/mail/ids";
import { connectImap } from "../src/mail/socket";
import { createServerFactory } from "../src/mcp/server";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createHeldFirstReadDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>, extra?: unknown) => Promise<ToolAnswer>;

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// test/password-pause.test.ts carries the same comment. `?raw` inlines the
// file's text at build time, which is how a Workers isolate reads source.
const SERVER_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/server.ts",
  { query: "?raw", import: "default", eager: true },
);
const SERVER_SOURCE: string = Object.values(SERVER_SOURCE_GLOB)[0] ?? "";

/**
 * Every tool the REAL factory registers, by name, with its callback.
 *
 * One factory call is one request: every callback here shares that request's
 * one gate and one leased runner, exactly as in production.
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

// ---------------------------------------------------------------------------
// The person's object
// ---------------------------------------------------------------------------

type StoredLease = { token: string; expiresAt: number };

async function ownerObject() {
  return env.USER_AGENT.getByName((await ownerPrincipal()).userId);
}

async function readLease(): Promise<StoredLease | undefined> {
  return runInDurableObject(await ownerObject(), (_instance, state) =>
    state.storage.kv.get<StoredLease>("lease"),
  );
}

async function seedLease(record: StoredLease): Promise<void> {
  await runInDurableObject(await ownerObject(), (_instance, state) => {
    state.storage.kv.put("lease", record);
  });
}

async function clearLease(): Promise<void> {
  await runInDurableObject(await ownerObject(), (_instance, state) => {
    state.storage.kv.delete("lease");
  });
}

/** Another request's live lease, far from expiry. */
function heldByAnotherRequest(): StoredLease {
  return { token: "another-request", expiresAt: Date.now() + 60000 };
}

// ---------------------------------------------------------------------------
// Arguments that pass every cheap check
// ---------------------------------------------------------------------------

const MESSAGE_ID = encodeMessageId({ mailbox: "INBOX", uidValidity: 7, uid: 42 });
const FOLDER_ID = encodeFolderId({ mailbox: "Receipts" });
const ATTACHMENT_ID = encodeAttachmentId({
  mailbox: "INBOX",
  uidValidity: 7,
  uid: 42,
  path: "2",
});

const DAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";
const CALENDAR_URL = `${DAV_HOME}work/`;
const CALENDAR_ID = encodeCalendarId({ collectionUrl: CALENDAR_URL });
const EVENT_ID = encodeEventId({
  calendarUrl: CALENDAR_URL,
  objectUrl: `${CALENDAR_URL}event-1.ics`,
  recurrenceId: null,
});
const BOOK_URL = "https://p42-contacts.icloud.com/1234567890/carddavhome/card/";
const ADDRESS_BOOK_ID = encodeAddressBookId({ collectionUrl: BOOK_URL });
const CONTACT_ID = encodeContactId({
  addressBookUrl: BOOK_URL,
  objectUrl: `${BOOK_URL}contact-1.vcf`,
});

const MOVE_CHANGE = { op: "move" as const, ids: [MESSAGE_ID], destination: FOLDER_ID };

/** A real, unspent mail move confirmation for MOVE_CHANGE, and its slot id. */
async function mintedMove(): Promise<{ confirmToken: string; jti: string; expiry: number }> {
  const actor = await ownerPrincipal();
  const jti = crypto.randomUUID();
  const expiry = Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS;
  const confirmToken = await mintConfirmation(
    {
      v: CONFIRM_VERSION,
      t: "mail",
      k: "move",
      j: jti,
      m: encodeFolderId({ mailbox: "INBOX" }),
      uv: 7,
      q: FOLDER_ID,
      qr: null,
      l: [{ i: 42, z: 1200, d: 1790000000, n: "9001" }],
      h: await mailMoveChangeHashOf(MOVE_CHANGE),
      x: expiry,
      u: actor.userId,
    },
    env.CONFIRM_SECRET,
  );
  return { confirmToken, jti, expiry };
}

type Args = Record<string, unknown> | (() => Promise<Record<string, unknown>>);

async function argsOf(args: Args): Promise<Record<string, unknown>> {
  return typeof args === "function" ? args() : args;
}

/**
 * Every tool that can open an iCloud mail connection. Each must take the lease
 * before any socket, so with the lease held it answers connection_busy.
 */
const LEASED: ReadonlyArray<{ name: string; args: Args }> = [
  { name: "mail_get_message", args: { id: MESSAGE_ID } },
  { name: "mail_list_folders", args: {} },
  { name: "mail_list_messages", args: { folderId: FOLDER_ID } },
  { name: "mail_search", args: { keyword: "invoice" } },
  { name: "mail_list_unread", args: {} },
  {
    name: "mail_compose_new",
    args: { to: ["someone@example.invalid"], subject: "Hello", text: "Hi." },
  },
  {
    name: "mail_compose_reply",
    args: { parentId: MESSAGE_ID, replyAll: false, text: "Thanks." },
  },
  { name: "mail_get_attachment", args: { id: ATTACHMENT_ID } },
  { name: "mail_stage_attachment", args: { source: "message", attachmentId: ATTACHMENT_ID } },
  { name: "mail_mark_read", args: { id: MESSAGE_ID, read: true } },
  { name: "mail_flag", args: { id: MESSAGE_ID, flagged: true } },
  { name: "mail_move", args: { ids: [MESSAGE_ID], destination: FOLDER_ID } },
  { name: "mail_archive", args: { ids: [MESSAGE_ID] } },
  { name: "mail_trash", args: { ids: [MESSAGE_ID] } },
  {
    name: "mail_commit",
    args: async () => ({ confirmToken: (await mintedMove()).confirmToken, change: MOVE_CHANGE }),
  },
  { name: "mail_imap_diagnose", args: {} },
  { name: "changes_since", args: {} },
];

/** Why a calendar or contacts tool takes no lease. */
const DAV_REASON =
  "DAV over HTTPS, not the IMAP connection ceiling the lease guards (D-07)";

/** Every other tool, with the reason it takes no lease. */
const NOT_LEASED: ReadonlyArray<{ name: string; reason: string; args: Args }> = [
  {
    name: "account_whoami",
    reason: "reads the signed-in principal only; no socket, no DAV",
    args: {},
  },
  {
    name: "mail_confirm_upload",
    reason: "one storage read and one delete in R2; never opens a mail session",
    args: {
      uploadId: encodeUploadId({ key: "staged/lease-coverage", expiresAt: Date.now() + 600000 }),
      sizeBytes: 10,
    },
  },
  { name: "dav_diagnose", reason: "DAV over HTTPS (D-07)", args: {} },
  { name: "calendar_list_calendars", reason: DAV_REASON, args: {} },
  {
    name: "calendar_create_calendar",
    reason: DAV_REASON,
    args: { displayName: "Lease", color: "#FF0000" },
  },
  {
    name: "calendar_update_calendar",
    reason: DAV_REASON,
    args: { calendarId: CALENDAR_ID, displayName: "Renamed" },
  },
  {
    name: "calendar_list_events",
    reason: DAV_REASON,
    args: { calendarId: CALENDAR_ID, start: "2026-09-01", end: "2026-09-30" },
  },
  { name: "calendar_get_event", reason: DAV_REASON, args: { id: EVENT_ID } },
  {
    name: "calendar_search",
    reason: DAV_REASON,
    args: { calendarId: CALENDAR_ID, start: "2026-09-01", end: "2026-09-30", keyword: "x" },
  },
  {
    name: "calendar_find_free_slots",
    reason: DAV_REASON,
    args: {
      start: "2026-09-01",
      end: "2026-09-02",
      durationMinutes: 30,
      tzid: "America/Los_Angeles",
    },
  },
  {
    name: "calendar_create_event",
    reason: DAV_REASON,
    args: {
      calendarId: CALENDAR_ID,
      summary: "Lease check",
      startLocal: "2026-09-10T09:00:00",
      endLocal: "2026-09-10T09:30:00",
      tzid: "America/Los_Angeles",
    },
  },
  {
    name: "calendar_update_event",
    reason: DAV_REASON,
    args: { id: EVENT_ID, summary: "Renamed" },
  },
  {
    name: "calendar_respond_to_invitation",
    reason: DAV_REASON,
    args: { id: EVENT_ID, answer: "accepted" },
  },
  { name: "calendar_delete_event", reason: DAV_REASON, args: { id: EVENT_ID } },
  {
    name: "calendar_delete_calendar",
    reason: DAV_REASON,
    args: { calendarId: CALENDAR_ID },
  },
  {
    name: "calendar_commit",
    reason: DAV_REASON,
    args: { confirmToken: "not-a-confirmation", change: { op: "delete", id: EVENT_ID } },
  },
  { name: "contacts_search", reason: DAV_REASON, args: { term: "Ann" } },
  { name: "contacts_get", reason: DAV_REASON, args: { id: CONTACT_ID } },
  {
    name: "contacts_create",
    reason: DAV_REASON,
    args: { addressBookId: ADDRESS_BOOK_ID, change: { name: { given: "Ann" } } },
  },
  {
    name: "contacts_update",
    reason: DAV_REASON,
    args: { id: CONTACT_ID, change: { name: { given: "Ann" } } },
  },
  {
    name: "contacts_commit",
    reason: DAV_REASON,
    args: { confirmToken: "not-a-confirmation", change: { op: "update", id: CONTACT_ID } },
  },
];

/** The fixed answer every leased tool gives while another request holds the lease. */
const BUSY = { category: "connection_busy", message: SAFE_MESSAGES.connection_busy };

function bodyOf(answer: ToolAnswer): Record<string, unknown> | null {
  try {
    return JSON.parse(answer.content[0]?.text ?? "") as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Every DAV request fails at once, and is counted. */
const davFetch = vi.fn(async () => {
  throw new Error("no network in this test");
});

beforeEach(async () => {
  vi.mocked(connectImap).mockReset();
  davFetch.mockClear();
  vi.stubGlobal("fetch", davFetch);
  await clearLease();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await clearLease();
});

describe("every registered tool has a row (DOBJ-03)", () => {
  it("the leased and not-leased rows are exactly the tools the real factory registers", () => {
    const registered = [...realTools().keys()].sort();
    const rows = [...LEASED.map((row) => row.name), ...NOT_LEASED.map((row) => row.name)];

    // No tool filed twice, in one table or across both.
    expect(new Set(rows).size, "a tool has two rows").toBe(rows.length);
    expect(rows.sort()).toEqual(registered);
  });

  it("every not-leased row states a reason", () => {
    for (const row of NOT_LEASED) {
      expect(row.reason.length, row.name).toBeGreaterThan(10);
    }
  });
});

describe("with the lease held by another request (DOBJ-02, DOBJ-03)", () => {
  for (const row of LEASED) {
    it(`${row.name} answers connection_busy and opens no socket`, async () => {
      const tools = realTools();
      const args = await argsOf(row.args);
      const held = heldByAnotherRequest();
      await seedLease(held);

      const answer = await tools.get(row.name)!(args);

      expect(answer.isError, row.name).toBe(true);
      expect(bodyOf(answer), row.name).toEqual(BUSY);
      expect(connectImap, row.name).not.toHaveBeenCalled();
      // The refusal changed nothing in the object.
      expect(await readLease(), row.name).toEqual(held);
    });
  }

  for (const row of NOT_LEASED) {
    it(`${row.name} opens no mail socket and is not refused by the lease`, async () => {
      const tools = realTools();
      const args = await argsOf(row.args);
      const held = heldByAnotherRequest();
      await seedLease(held);

      const answer = await tools.get(row.name)!(args);

      expect(connectImap, row.name).not.toHaveBeenCalled();
      expect(bodyOf(answer)?.category, row.name).not.toBe("connection_busy");
      expect(await readLease(), row.name).toEqual(held);
    });
  }

  it("mail_commit refused as busy does not spend the confirmation", async () => {
    const tools = realTools();
    const { confirmToken, jti, expiry } = await mintedMove();
    await seedLease(heldByAnotherRequest());

    const answer = await tools.get("mail_commit")!({ confirmToken, change: MOVE_CHANGE });

    expect(bodyOf(answer)).toEqual(BUSY);
    // The one-time slot is still free: claiming it now succeeds. Had the busy
    // refusal spent it, this would throw.
    const { userId } = await ownerPrincipal();
    await expect(
      reserveConfirmation(env.CONFIRM_KV, userId, jti, expiry),
    ).resolves.toBeUndefined();
  });
});

describe("the calendar and contacts tools never take the lease (D-07)", () => {
  it("a calendar call and a contacts call reach DAV while the mail lease is held", async () => {
    const tools = realTools();
    await seedLease(heldByAnotherRequest());

    const calendar = await tools.get("calendar_list_calendars")!({});
    expect(bodyOf(calendar)?.category).not.toBe("connection_busy");
    // It got past everything the lease could have refused, to a DAV request.
    expect(davFetch).toHaveBeenCalled();

    davFetch.mockClear();
    const contacts = await tools.get("contacts_search")!({ term: "Ann" });
    expect(bodyOf(contacts)?.category).not.toBe("connection_busy");
    expect(davFetch).toHaveBeenCalled();
    expect(connectImap).not.toHaveBeenCalled();
  });
});

describe("no registrar is handed the raw gate (structural half)", () => {
  // Comment lines are removed first: the file explains the gate at length, and
  // prose is not a call.
  const code = SERVER_SOURCE.split("\n")
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join("\n");

  it("reads the real source", () => {
    expect(SERVER_SOURCE).toContain("export function createServerFactory(");
  });

  it("no register call takes `gate`; `gate` is named only where it is built and wrapped", () => {
    const calls = code.match(/register\w*\([^;]*\);/g) ?? [];
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.filter((call) => /\bgate\b/.test(call))).toEqual([]);

    expect(code).toContain("const gate = createSessionGate();");
    expect(code).toContain("const leasedMail = createLeasedMail(gate);");
    expect((code.match(/\bgate\b/g) ?? []).length).toBe(2);
  });

  it("every registrar that can open a mail session is handed the leased mail", () => {
    expect(code).toContain("registerMailTools(server, leasedMail, principal);");
    expect(code).toContain("registerDiagnoseTool(server, leasedMail, unpaused);");
    expect(code).toContain("registerChangesTool(server, leasedMail, principal, davFetch);");
  });
});

// ---------------------------------------------------------------------------
// The gate stands on its own (DOBJ-04)
// ---------------------------------------------------------------------------

/** A server that signs in and answers the folder listing. */
function folderListingScript(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 172 UNSEEN 4)',
      "a4 OK LIST completed",
    ),
    logoutExchange("a5"),
  ];
}

describe("a broken object cannot remove the per-request gate (DOBJ-04)", () => {
  // This is the case PITFALLS #52 names. If the object ever grants a lease it
  // should have refused, the per-request gate is still there, and still
  // refuses a second session inside one request. The lease is added to the
  // gate; it never replaced it.
  it("with every acquire forced to grant, the gate refuses the second session and one socket opens", async () => {
    await runInDurableObject(await ownerObject(), (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      vi.spyOn(prototype, "acquire").mockImplementation(() => ({
        held: true,
        token: crypto.randomUUID(),
      }));
    });
    const parked = createHeldFirstReadDuplex(folderListingScript());
    vi.mocked(connectImap).mockReturnValueOnce(parked.duplex as never);
    // One factory call: both callbacks share one request's gate and lease.
    const tools = realTools();
    const listFolders = tools.get("mail_list_folders")!;

    const first = listFolders({});
    // The first session holds the gate and is parked at the greeting.
    await vi.waitFor(() => expect(connectImap).toHaveBeenCalledTimes(1));

    const second = await listFolders({});

    expect(second.isError).toBe(true);
    expect(bodyOf(second)).toEqual({
      category: "rate_limited",
      message: SAFE_MESSAGES.rate_limited,
    });
    expect(connectImap).toHaveBeenCalledTimes(1);

    parked.release();
    const answer = await first;
    expect(answer.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
  });
});
