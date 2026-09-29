// The recall backfill through the REAL factory, on the IMAP wire, and one
// call's measured cost (Phase 29.1.1, RCLL-14; LD-4, LD-6, LD-7 in
// 29.1.1-01-PLAN.md).
//
// Everything here is real except the socket and the two bindings the pool
// cannot reach: the real server factory, the real `mail_recall_backfill`
// callback, the real engine loop, the real page source over the real mail
// service, the real person's object and the real connection lease. The socket
// module is mocked for this file only and hands out scripted conversations, so
// nothing signs in to a real Apple ID. `recallDeps` is mocked so the tool's own
// default deps reach the fake store and the fake model, as
// test/recall-dead-ref.test.ts does.
//
// What is proved, read back from each socket's own written lines:
// - every page session opens its mailbox with the read-only open, every fetch
//   item is the peeking form, and no command outside the read vocabulary is
//   sent (no flag change, no copy, no placing a message, no removal);
// - each socket's logout is written before the next socket is handed out, and
//   no more than one socket is ever open;
// - the autonomy grant, and a factory that does not know the grant, open no
//   socket and make no recall call to the object.
//
// The mutating open's keyword is never written at the start of a string here
// (CLAUDE.md §5; the scan counts it). The command check is an allow-list of the
// read vocabulary instead, which catches that open and every write without
// spelling any of them.
//
// THE MEASUREMENT (2026-09-28). One call that reads RECALL_BACKFILL_MAX_PAGES
// (10) pages of an INBOX already at build costs, in this pool:
//   sockets 10; object calls 64 (recallSyncState 12, recallProgress 2,
//   recallBeginPage 10, recallEndPage 10, recallRecord 10, recallSetSync 0,
//   acquire 10, release 10); model calls 10; store calls 10; grant reads 1.
//   Total 95, bound 200. At most one socket open at once.
// recallSyncState is 12: one read before anything, one per pass that pages,
// and the tool's one read after the run. A page mid-build writes no sync row;
// the cursor rides on the page slot.
// The case below asserts the bound and the socket count, so a change that
// multiplies the cost turns it red. CPU time and real per-page seconds cannot
// be measured here: performance timers do not advance during CPU work in
// workerd, and the page source's peer is scripted. Plan 04 measures both on
// the owner's first live run.

import { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

const current: { deps: RecallDeps | null } = { deps: null };

vi.mock("../src/recall/pipeline", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/recall/pipeline")>()),
  recallDeps: vi.fn(() => {
    if (current.deps === null) throw new Error("no fake recall deps for this case");
    return current.deps;
  }),
}));

import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import type { SyncRow } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import type { FolderState } from "../src/change-marker";
import { connectImap } from "../src/mail/socket";
import { BACKFILL_REFUSED, RECALL_BACKFILL_TOOL_NAME } from "../src/mcp/tools/recall";
import { createServerFactory } from "../src/mcp/server";
import type { Principal } from "../src/principal";
import { createEmbedder } from "../src/recall/embed";
import { createRecallStore } from "../src/recall/index";
import type { RecallDeps } from "../src/recall/pipeline";
import { RECALL_PAGE_SIZE } from "../src/recall/retention";
import { RECALL_BACKFILL_MAX_PAGES } from "../src/recall/sync";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeAi, type FakeAi } from "./fixtures/fake-embedder";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  statusResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

type Answer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>, extra?: unknown) => Promise<Answer>;

const ORDINARY = "ordinary-client";
const INBOX = "INBOX";
const DAY_MS = 24 * 60 * 60 * 1000;
const ENCODER = new TextEncoder();
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

/** The read vocabulary: every command word a backfill may send. */
const READ_COMMANDS = new Set([
  "CAPABILITY",
  "LOGIN",
  "LIST",
  "STATUS",
  "EXAMINE",
  "UID SEARCH",
  "UID FETCH",
  "LOGOUT",
]);

/** The object's methods a backfill call reaches, counted through its prototype. */
const OBJECT_METHODS = [
  "recallSyncState",
  "recallProgress",
  "recallBeginPage",
  "recallEndPage",
  "recallRecord",
  "recallSetSync",
  "acquire",
  "release",
] as const;

/** The per-call bound LD-7 states: far under 1,000 internal calls and 10,000 subrequests. */
const PER_CALL_BOUND = 200;

// ---------------------------------------------------------------------------
// The person's object
// ---------------------------------------------------------------------------

async function ownerObject(): Promise<DurableObjectStub<UserAgent>> {
  return env.USER_AGENT.getByName((await ownerPrincipal()).userId);
}

async function resetOwner(): Promise<void> {
  await runInDurableObject(await ownerObject(), (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    state.storage.kv.delete("lease");
  });
}

async function readLease(): Promise<unknown> {
  return runInDurableObject(await ownerObject(), (_instance, state) => state.storage.kv.get("lease"));
}

/** The folder list [INBOX], and INBOX at build, as a seed leaves it. */
async function seedInboxAtBuild(uidNext: number): Promise<void> {
  const stub = await ownerObject();
  expect(await stub.recallSetFolders([INBOX])).toEqual({ ok: true });
  const state: FolderState = {
    mailbox: INBOX,
    uidValidity: INBOX_UIDVALIDITY,
    uidNext,
    highestModseq: "7",
  };
  const row: SyncRow = {
    stage: "build",
    state,
    checkedAt: Date.now(),
    reconciledAt: null,
    due: null,
    seen: null,
    failedAt: null,
    failures: 0,
  };
  expect(await stub.recallSetSync(INBOX, row)).toEqual({ ok: true });
}

/** Spy every object method a backfill reaches, through the prototype. */
async function spyObject() {
  return runInDurableObject(await ownerObject(), (instance: UserAgent) => {
    const prototype = Object.getPrototypeOf(instance) as UserAgent;
    return Object.fromEntries(
      OBJECT_METHODS.map((name) => [name, vi.spyOn(prototype, name)]),
    ) as unknown as Record<(typeof OBJECT_METHODS)[number], { mock: { calls: unknown[] } }>;
  });
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** Two days ago, as an INTERNALDATE. */
function recentInternalDate(): string {
  const at = new Date(Date.now() - 2 * DAY_MS);
  const day = String(at.getUTCDate()).padStart(2, "0");
  return `${day}-${MONTHS[at.getUTCMonth()]}-${at.getUTCFullYear()} 10:15:02 +0000`;
}

function examineReply(tag: string): Uint8Array {
  return wire(
    "* 300 EXISTS",
    "* 0 RECENT",
    `* OK [UIDVALIDITY ${INBOX_UIDVALIDITY}] UIDs valid`,
    "* OK [UIDNEXT 301] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  );
}

function searchReply(tag: string, uids: readonly number[]): Uint8Array {
  if (uids.length === 0) return wire(`${tag} OK SEARCH completed`);
  return wire(`* SEARCH ${uids.join(" ")}`, `${tag} OK SEARCH completed`);
}

function metadataReply(tag: string, uids: readonly number[]): Uint8Array {
  const date = recentInternalDate();
  const chunks: Uint8Array[] = [];
  for (const uid of uids) {
    chunks.push(
      ENCODER.encode(
        `* ${uid} FETCH (UID ${uid} FLAGS () INTERNALDATE "${date}" ` +
          `RFC822.SIZE ${12000 + uid} BODYSTRUCTURE ${PLAIN_STRUCTURE} `,
      ),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]",
        [
          `Subject: Subject for ${uid}`,
          `From: "Sender ${uid}" <s${uid}@example.invalid>`,
          "Date: Thu, 13 Aug 2026 09:14:02 -0700",
          `Message-ID: <m${uid}@example.invalid>`,
          "",
          "",
        ].join("\r\n"),
      ),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

function snippetReply(tag: string, uids: readonly number[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const uid of uids) {
    chunks.push(
      ENCODER.encode(`* ${uid} FETCH (UID ${uid} `),
      literalItem("BODY[1]<0>", `Preview of message ${uid}.`),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/**
 * The scripted page `k` of an INBOX holding UIDs 1..`total`: the search finds
 * every UID below the previous page, and the page is the newest 25 of them.
 */
function pageSession(k: number, total: number): FakeDuplex {
  const top = total - k * RECALL_PAGE_SIZE;
  const searched = Array.from({ length: top }, (_, i) => i + 1);
  const page = searched.slice(-RECALL_PAGE_SIZE).reverse();
  return createFakeDuplex([
    ...authPrefix(),
    examineReply("a4"),
    searchReply("a5", searched),
    metadataReply("a6", page),
    snippetReply("a7", page),
    logoutExchange("a8"),
  ]);
}

/** The folder listing for a fresh person: INBOX and a sent folder, no archive. */
function listingSession(): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 30 UNSEEN 4)',
      '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
      '* STATUS "Sent Messages" (MESSAGES 40 UNSEEN 0)',
      "a4 OK LIST completed",
    ),
    logoutExchange("a5"),
  ]);
}

/** The seed's status check for INBOX: a session that opens no mailbox. */
function seedSession(total: number): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    statusResponse("a4", INBOX, INBOX_UIDVALIDITY, total + 1, total, "7"),
    logoutExchange("a5"),
  ]);
}

/** Each written line's command word, and nothing else: never the arguments. */
function commandsOf(duplex: FakeDuplex): string[] {
  return duplex.writtenLines().map((line) => {
    const words = line.split(" ");
    const verb = words[1] ?? "";
    return verb === "UID" ? `UID ${words[2] ?? ""}` : verb;
  });
}

function sentLogout(duplex: FakeDuplex): boolean {
  return duplex.writtenLines().some((line) => /^a\d+ LOGOUT$/.test(line));
}

function closed(duplex: FakeDuplex): boolean {
  return duplex.firstIndexOf("close") !== -1;
}

/**
 * Hand out `scripts` in order, one per socket. At each hand-out, record whether
 * every earlier socket had written its logout, and how many were still open.
 */
function handOut(scripts: FakeDuplex[]) {
  const handed: FakeDuplex[] = [];
  const log = { loggedOutBeforeNext: [] as boolean[], maxOpen: 0 };
  vi.mocked(connectImap).mockImplementation(() => {
    const previous = handed[handed.length - 1];
    if (previous !== undefined) log.loggedOutBeforeNext.push(sentLogout(previous));
    const next = scripts[handed.length];
    if (next === undefined) throw new Error("recall-backfill-wire: more sockets than scripted");
    handed.push(next);
    const open = handed.filter((one) => !closed(one)).length;
    log.maxOpen = Math.max(log.maxOpen, open);
    return next as never;
  });
  return { handed, log };
}

/** The backfill callback from the REAL factory, built with this grant reader. */
function realBackfill(grantClient?: () => Promise<string | null>): Callback {
  const spy = vi.spyOn(McpServer.prototype, "registerTool");
  try {
    createServerFactory(ownerPrincipal() as Promise<Principal>, [], grantClient)({
      era: "modern",
    } as never);
    const found = (spy.mock.calls as unknown as [string, unknown, Callback][]).find(
      ([name]) => name === RECALL_BACKFILL_TOOL_NAME,
    );
    expect(found, `${RECALL_BACKFILL_TOOL_NAME} is not registered`).toBeDefined();
    return found![2];
  } finally {
    spy.mockRestore();
  }
}

/** Every page socket's read-only open, peeking fetches and read-only vocabulary. */
function expectReadOnlyPage(duplex: FakeDuplex): void {
  const commands = commandsOf(duplex);
  expect(commands.filter((word) => !READ_COMMANDS.has(word))).toEqual([]);
  expect(duplex.writtenLines()).toContain(`a4 EXAMINE "${INBOX}"`);
  const fetches = duplex.writtenLines().filter((line) => line.includes(" UID FETCH "));
  expect(fetches).toHaveLength(2);
  for (const line of fetches) {
    expect(line.replace(/BODY\.PEEK\[/g, "")).not.toMatch(/BODY\[|RFC822(?!\.SIZE)/);
  }
  expect(sentLogout(duplex)).toBe(true);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let ai: FakeAi;
let index: FakeVectorize;

beforeEach(async () => {
  vi.mocked(connectImap).mockReset();
  await resetOwner();
  ai = createFakeAi();
  index = createFakeVectorize();
  current.deps = { store: createRecallStore(index), embedder: createEmbedder(ai) };
});

afterEach(async () => {
  vi.restoreAllMocks();
  current.deps = null;
  await resetOwner();
});

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

describe("one backfill call through the real factory, on the wire (LD-4, LD-6)", () => {
  it("reads RECALL_BACKFILL_MAX_PAGES pages, each on its own read-only socket, one at a time", async () => {
    const total = 300;
    await seedInboxAtBuild(total + 1);
    const scripts = Array.from({ length: RECALL_BACKFILL_MAX_PAGES }, (_, k) => pageSession(k, total));
    const { handed, log } = handOut(scripts);

    const answer = await realBackfill(async () => ORDINARY)({});

    expect(answer.isError).not.toBe(true);
    const parsed = JSON.parse(answer.content[0]!.text) as {
      stopped: string;
      thisCall: { pages: number; messages: number };
    };
    expect(parsed.stopped).toBe("budget");
    expect(parsed.thisCall.pages).toBe(RECALL_BACKFILL_MAX_PAGES);
    expect(parsed.thisCall.messages).toBe(RECALL_BACKFILL_MAX_PAGES * RECALL_PAGE_SIZE);
    expect(connectImap).toHaveBeenCalledTimes(RECALL_BACKFILL_MAX_PAGES);
    expect(handed).toHaveLength(RECALL_BACKFILL_MAX_PAGES);

    for (const duplex of handed) expectReadOnlyPage(duplex);
    expect(log.loggedOutBeforeNext).toEqual(
      Array.from({ length: RECALL_BACKFILL_MAX_PAGES - 1 }, () => true),
    );
    expect(log.maxOpen).toBe(1);
    expect(handed.every(closed)).toBe(true);
    // The lease is free at the end.
    expect(await readLease()).toBeUndefined();
  });

  it("a fresh person: the folder listing, the seed's status check, then the pages, in that order", async () => {
    const total = 30;
    const listing = listingSession();
    const seed = seedSession(total);
    const pages = [pageSession(0, total), pageSession(1, total)];
    const { handed, log } = handOut([listing, seed, ...pages]);

    const answer = await realBackfill(async () => ORDINARY)({});

    const parsed = JSON.parse(answer.content[0]!.text) as { stopped: string; index: string };
    expect(parsed.stopped).toBe("built");
    expect(parsed.index).toBe("built");
    expect(handed).toEqual([listing, seed, ...pages]);

    expect(commandsOf(listing)).toContain("LIST");
    expect(commandsOf(listing)).not.toContain("EXAMINE");
    // The seed opens no mailbox: a status check and nothing else.
    expect(commandsOf(seed)).toContain("STATUS");
    expect(commandsOf(seed)).not.toContain("EXAMINE");
    for (const duplex of [listing, seed]) {
      expect(commandsOf(duplex).filter((word) => !READ_COMMANDS.has(word))).toEqual([]);
      expect(sentLogout(duplex)).toBe(true);
    }
    for (const duplex of pages) expectReadOnlyPage(duplex);
    expect(log.loggedOutBeforeNext).toEqual([true, true, true]);
    expect(log.maxOpen).toBe(1);
  });
});

describe("no socket and no recall call on the autonomy grant, or on an unknown one (LD-2, LD-3)", () => {
  const refused: [string, (() => Promise<string | null>) | undefined][] = [
    ["the autonomy client", async () => AUTONOMY_CLIENT_ID],
    ["the factory's default reader (null)", undefined],
  ];

  it.each(refused)("%s: the fixed refusal, zero sockets, zero recall calls", async (_label, reader) => {
    await seedInboxAtBuild(301);
    handOut([pageSession(0, 300)]);
    const spies = await spyObject();

    const answer = await realBackfill(reader)({});

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual({ message: BACKFILL_REFUSED });
    expect(connectImap).not.toHaveBeenCalled();
    for (const name of OBJECT_METHODS) {
      expect(spies[name].mock.calls, name).toHaveLength(0);
    }
  });
});

describe("one call's measured cost (LD-7)", () => {
  it("a 10-page call stays within the per-call bound, with one socket open at a time", async () => {
    const total = 300;
    await seedInboxAtBuild(total + 1);
    const { log } = handOut(
      Array.from({ length: RECALL_BACKFILL_MAX_PAGES }, (_, k) => pageSession(k, total)),
    );
    const spies = await spyObject();
    let grantReads = 0;

    const answer = await realBackfill(async () => {
      grantReads += 1;
      return ORDINARY;
    })({});

    expect(answer.isError).not.toBe(true);
    const sockets = vi.mocked(connectImap).mock.calls.length;
    const objectCalls = Object.fromEntries(
      OBJECT_METHODS.map((name) => [name, spies[name].mock.calls.length]),
    ) as Record<(typeof OBJECT_METHODS)[number], number>;
    const objectTotal = Object.values(objectCalls).reduce((sum, n) => sum + n, 0);
    const modelCalls = ai.calls.length;
    const storeCalls = index.calls.length;
    const sum = sockets + objectTotal + modelCalls + storeCalls + grantReads;

    expect(sockets).toBe(RECALL_BACKFILL_MAX_PAGES);
    expect(grantReads).toBe(1);
    expect(log.maxOpen).toBe(1);
    // The recorded measurement. A change to any of these is a change to the
    // cost of one call, and belongs in the comment by RECALL_BACKFILL_MAX_PAGES.
    expect({ objectCalls, modelCalls, storeCalls, sum }).toEqual({
      objectCalls: {
        recallSyncState: 12,
        recallProgress: 2,
        recallBeginPage: 10,
        recallEndPage: 10,
        recallRecord: 10,
        recallSetSync: 0,
        acquire: 10,
        release: 10,
      },
      modelCalls: 10,
      storeCalls: 10,
      sum: 95,
    });
    expect(sum).toBeLessThanOrEqual(PER_CALL_BOUND);
  });
});
