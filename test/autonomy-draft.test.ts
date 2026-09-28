// The rules job's reply, its caps, the marker's gap rule and its bounded
// records (Phase 28, plan 28-02 Task 2; AUTO-09, AUTO-12, AUTO-15; D-05 as
// revised, D-08, D-15, D-18, D-26, D-29, D-30).
//
// Two layers.
//
// THE REAL DOOR. A person signs in through the login-proof worker, which arms
// their key. The object's seam to this Worker is pointed back at it, so the
// job's calls go through the real redemption, the real door, the real
// `changes_since`, the real `account_whoami` and the real `mail_compose_reply`,
// over the fake duplex. The draft is then read back from the bytes the write
// session was sent. That is the point of these cases: the job's reply IS the
// reply tool's reply, built by its own subject rule and threading builder, so
// they are checked at the byte level and never modelled by hand.
//
// THE JOB, DRIVEN DIRECTLY. The caps, the skips, the marker's gap rule, a new
// sign-in and the expiry are about what the job decides, so they drive
// `runAutonomyJob` with a recording `call` whose answers come from the REAL
// tool-side builders (the change answer, the sign-in answer, the flag answer,
// the compose answer). The job reads those exactly as it reads a real answer.
//
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID (D-09, D-13).

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { ACTIVITY_KEY, type ActivityEntry } from "../src/agent/activity";
import { AUTONOMY_KEY } from "../src/agent/autonomy";
import { AUTONOMY_TOOLS } from "../src/agent/autonomy-client";
import {
  JOB_DRAFT_DAY_KEY,
  JOB_MARKER_KEY,
  JOB_NEXT_AT_KEY,
  type JobDeps,
  RULES_KEY,
  runAutonomyJob,
} from "../src/agent/job";
import type { Rule } from "../src/agent/rules";
import type { CallAnswer } from "../src/agent/tool-call";
import type { UserAgent } from "../src/agent/user-agent";
import { encodeMessageId } from "../src/mail/ids";
import type { NewMailRow } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { signedInAsResult } from "../src/mcp/tools/account";
import { type ChangesAnswer, changesResult } from "../src/mcp/tools/changes";
import { composeToolResult, flagStateToolResult } from "../src/mcp/tools/mail";
import type { Principal } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import {
  INBOX_UIDVALIDITY,
  examineResponse,
  logoutExchange,
  selectResponse,
  flagEcho,
  wire,
} from "./fixtures/icloud-bytes";
import {
  type Armed,
  type SelfCall,
  authPrefix,
  concatBytes,
  directToolCall,
  headerFetchReply,
  makeJobDue,
  routeSelfCalls,
  signInArmed,
  statusSession,
  type Stub,
} from "./fixtures/rules-job";
import { LISTED_APPLE_ID } from "./fixtures/worker-with-login-proof";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** The words every draft rule here carries. */
const RULE_TEXT = "Thank you for your note. I will reply properly soon.";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

// ===================================================================== the door

/** The one sender the byte-level rule names, and the address a redirect names. */
const SENDER = "recruiter@example.invalid";
const REDIRECT = "desk@elsewhere.invalid";
const PARENT_UID = 4393;

/** The original's own threading headers. */
const PARENT_MESSAGE_ID = "<offer@example.invalid>";
const PARENT_REFERENCES = ["<one@example.invalid>", "<two@example.invalid>"];

/** The parent's six-field header block, with or without a redirect header. */
function parentHeaderBlock(redirect: boolean): string {
  return [
    `Message-ID: ${PARENT_MESSAGE_ID}`,
    `References: ${PARENT_REFERENCES[0]}`,
    ` ${PARENT_REFERENCES[1]}`,
    ...(redirect ? [`Reply-To: Front Desk <${REDIRECT}>`] : []),
    `From: "Jane Recruiter" <${SENDER}>`,
    `To: ${LISTED_APPLE_ID}`,
    "",
    "",
  ].join("\r\n");
}

/** The parent as a whole message, for the quoted original. */
function parentRaw(redirect: boolean): string {
  return [
    `From: "Jane Recruiter" <${SENDER}>`,
    ...(redirect ? [`Reply-To: Front Desk <${REDIRECT}>`] : []),
    `To: ${LISTED_APPLE_ID}`,
    "Subject: RE: Re: Offer",
    "Date: Wed, 19 Aug 2026 09:14:02 +0000",
    `Message-ID: ${PARENT_MESSAGE_ID}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "The original words.",
    "",
  ].join("\r\n");
}

/** One FETCH reply keyed by a section, count derived from the payload. */
function sectionReply(tag: string, uid: number, key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${uid} ${key} {${bytes.byteLength}}\r\n`),
    bytes,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The whole parent read, in the order the reply tool performs it. Copied from test/append.test.ts. */
function parentSession(uid: number, redirect: boolean): FakeDuplex {
  const raw = parentRaw(redirect);
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    sectionReply("a5", uid, "BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES REPLY-TO FROM TO CC)]", parentHeaderBlock(redirect)),
    wire(
      `* 1 FETCH (UID ${uid} FLAGS () INTERNALDATE "19-Aug-2026 09:14:02 +0000" ` +
        `RFC822.SIZE ${ENCODER.encode(raw).byteLength} ` +
        `BODYSTRUCTURE ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 21 1))`,
      "a6 OK UID FETCH completed",
    ),
    sectionReply("a7", uid, "BODY[]", raw),
    logoutExchange("a8"),
  ]);
}

/** The draft write: the folder listing, the go-ahead, the completion. Copied from test/append.test.ts. */
function writeSession(): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* LIST (\\HasNoChildren) "/" "Drafts"',
      '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
      '* LIST (\\HasNoChildren \\Trash) "/" "Deleted Messages"',
      "a4 OK LIST completed",
    ),
    wire("+ Ready for literal data"),
    wire("a5 OK [APPENDUID 1237268096 92] APPEND completed"),
    logoutExchange("a6"),
  ]);
}

/** The change check's new-mail read: open, search, header fetch. */
function newMailSession(at: number, rows: Parameters<typeof headerFetchReply>[2]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    wire(`* SEARCH ${rows.map((row) => row.uid).join(" ")}`, "a5 OK SEARCH completed"),
    headerFetchReply("a6", at, rows),
    logoutExchange("a7"),
  ]);
}

/** A flag change on one message. */
function flagSession(uid: number): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    selectResponse("a4", "[READ-WRITE]"),
    flagEcho("a5", 17, uid, "\\Flagged"),
    logoutExchange("a6"),
  ]);
}

/** Every duplex handed out, in order, and the queue of ones still to hand out. */
const handedOut: FakeDuplex[] = [];
let queued: (() => FakeDuplex)[] = [];

beforeEach(() => {
  handedOut.length = 0;
  queued = [];
  vi.mocked(connectImap).mockReset();
  vi.mocked(connectImap).mockImplementation((() => {
    const next = queued.shift();
    if (next === undefined) throw new Error("the test queued no more sessions");
    const duplex = next();
    handedOut.push(duplex);
    return duplex;
  }) as never);
  vi.stubGlobal("fetch", async () => new Response(null, { status: 500 }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The message bytes a write session was sent: the literal the APPEND line declared. */
function writtenDraft(duplex: FakeDuplex): string {
  const line = duplex.writtenLines().find((one) => /\bAPPEND\b/.test(one));
  expect(line, "no draft write in this session").toBeDefined();
  const count = Number(/\{(\d+)\}$/.exec(line as string)?.[1]);
  const chunk = duplex.writes.find((one) => one.byteLength === count);
  expect(chunk, "the declared literal was never written").toBeDefined();
  return DECODER.decode(chunk);
}

/** A message's header lines, unfolded, and its body. */
function splitMessage(message: string): { headers: string[]; body: string } {
  const at = message.indexOf("\r\n\r\n");
  const head = message.slice(0, at).replace(/\r\n[ \t]+/g, " ");
  return { headers: head.split("\r\n"), body: message.slice(at + 4) };
}

/** The first header line whose name is `name`, or undefined. */
function header(headers: string[], name: string): string | undefined {
  const prefix = `${name.toLowerCase()}:`;
  return headers.find((line) => line.toLowerCase().startsWith(prefix));
}

/** The plain-text part's decoded text. */
function plainText(message: string): string {
  const { headers, body } = splitMessage(message);
  const type = header(headers, "Content-Type") ?? "";
  const boundary = /boundary="([^"]+)"/.exec(type)?.[1];
  if (boundary !== undefined) {
    for (const part of body.split(`--${boundary}`)) {
      const trimmed = part.replace(/^\r\n/, "");
      if (/content-type: text\/plain/i.test(trimmed)) return plainText(trimmed);
    }
    throw new Error("no plain-text part");
  }
  const encoding = header(headers, "Content-Transfer-Encoding") ?? "";
  if (/base64/i.test(encoding)) {
    const binary = atob(body.replace(/\s+/g, ""));
    return DECODER.decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  }
  return body;
}

/** The draft with its Date, Message-ID and boundary values blanked. */
function normalised(message: string): string {
  let out = message
    .replace(/^Date: .*$/m, "Date: <date>")
    .replace(/^Message-ID: .*$/im, "Message-ID: <id>");
  const boundaries = [...out.matchAll(/boundary="([^"]+)"/g)].map((m) => m[1] as string);
  for (const boundary of boundaries) out = out.split(boundary).join("<boundary>");
  return out;
}

/** The object's stored keys and values with the given prefix. */
function stored(stub: Stub, prefix: string): Promise<[string, unknown][]> {
  return runInDurableObject(stub, (_i, state) => [...state.storage.kv.list({ prefix })]);
}

/** Every recall row the object holds, which the index-build step would write. */
function recallRows(stub: Stub): Promise<{ vectors: number; state: number }> {
  return runInDurableObject(stub, (_i, state) => {
    const sql = state.storage.sql;
    const tables = sql
      .exec<{ name: string }>("select name from sqlite_master where type = 'table'")
      .toArray()
      .map((row) => row.name);
    const count = (table: string) =>
      tables.includes(table) ? sql.exec<{ n: number }>(`select count(*) as n from ${table}`).one().n : 0;
    return { vectors: count("recall_vectors"), state: count("recall_state") };
  });
}

/** Sign in, route the calls, add one rule, and run the starting point. */
async function armedWithRule(
  then: Record<string, unknown>,
): Promise<{ armed: Armed; calls: SelfCall[]; ruleId: string }> {
  const armed = await signInArmed();
  try {
    const calls = await routeSelfCalls(armed);
    const added = await armed.stub.addRule({ when: { fromAddresses: [SENDER] }, then });
    expect(added.ok).toBe(true);
    queued.push(() => statusSession(4393, "118"));
    expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
    expect(queued).toHaveLength(0);
    calls.splice(0);
    handedOut.length = 0;
    vi.mocked(connectImap).mockClear();
    await makeJobDue(armed.stub);
    return { armed, calls, ruleId: added.ok ? added.id : "" };
  } catch (error) {
    await armed.cleanup();
    throw error;
  }
}

/** The recorded tool calls, by name, in order. */
function toolsOf(calls: SelfCall[]): (string | null)[] {
  return calls.filter((call) => call.path === "/mcp").map((call) => call.tool);
}

describe("a reply through the real door and the real reply tool (D-05 as revised, D-29)", () => {
  it("one parent read and one draft write, To only the From address, Re: subject, threaded, in the rule's words; and byte-equal to a direct reply", async () => {
    const { armed, calls } = await armedWithRule({ draft: { text: RULE_TEXT } });
    try {
      const received = Date.now() + MIN;
      queued.push(
        () => statusSession(4394, "120"),
        () =>
          newMailSession(received, [
            { uid: PARENT_UID, subject: "RE: Re: Offer", from: `"Jane Recruiter" <${SENDER}>` },
          ]),
        () => parentSession(PARENT_UID, false),
        () => writeSession(),
      );
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
      expect(queued).toHaveLength(0);

      // The calls: the change check, the sign-in check, then the reply.
      expect(toolsOf(calls)).toEqual(["changes_since", "account_whoami", "mail_compose_reply"]);
      const allowed: readonly string[] = AUTONOMY_TOOLS;
      for (const tool of toolsOf(calls)) expect(allowed).toContain(tool);
      const reply = calls.find((call) => call.tool === "mail_compose_reply") as SelfCall;
      const parentId = encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid: PARENT_UID });
      expect(Object.keys(reply.args ?? {}).sort()).toEqual(["parentId", "text", "to"]);
      expect(reply.args).toEqual({ parentId, text: RULE_TEXT, to: [SENDER] });

      // The sessions: status, new mail, the parent read, the write. Nothing else.
      expect(handedOut).toHaveLength(4);
      const parentLines = (handedOut[2] as FakeDuplex).writtenLines();
      expect(parentLines.some((line) => /\bEXAMINE\b/.test(line))).toBe(true);
      expect(parentLines.some((line) => /\bSELECT\b/.test(line))).toBe(false);
      expect(parentLines.some((line) => line.includes("BODY.PEEK[HEADER.FIELDS (MESSAGE-ID"))).toBe(true);
      for (const line of parentLines.filter((one) => /\bFETCH\b/.test(one))) {
        expect(line).not.toMatch(/\bBODY\[/);
        expect(line).not.toMatch(/\bRFC822(?:\.TEXT)?(?![.A-Z])/);
      }
      const writeLines = (handedOut[3] as FakeDuplex).writtenLines();
      const appends = handedOut.flatMap((duplex) => duplex.writtenLines()).filter((line) => /\bAPPEND\b/.test(line));
      expect(appends).toHaveLength(1);
      expect(appends[0]).toContain('"Drafts"');
      expect(writeLines.some((line) => /\bAPPEND\b/.test(line))).toBe(true);

      // The draft, read back from the bytes.
      const draft = writtenDraft(handedOut[3] as FakeDuplex);
      const { headers } = splitMessage(draft);
      expect(header(headers, "To")).toBe(`To: ${SENDER}`);
      expect(header(headers, "Cc")).toBeUndefined();
      expect(header(headers, "Bcc")).toBeUndefined();
      expect(header(headers, "Subject")).toBe("Subject: Re: Offer");
      expect(header(headers, "In-Reply-To")).toBe(`In-Reply-To: ${PARENT_MESSAGE_ID}`);
      expect(header(headers, "References")?.replace(/\s+/g, " ")).toBe(
        `References: ${[...PARENT_REFERENCES, PARENT_MESSAGE_ID].join(" ")}`,
      );
      const text = plainText(draft);
      expect(text.startsWith(RULE_TEXT)).toBe(true);
      expect(text).toContain("The original words.");

      // The same three arguments through a direct call on the person's own
      // connection, over a second identical exchange, write the same draft.
      handedOut.length = 0;
      queued.push(
        () => parentSession(PARENT_UID, false),
        () => writeSession(),
      );
      const direct = await directToolCall(armed, "mail_compose_reply", reply.args as Record<string, unknown>);
      expect(direct.status).toBe(200);
      const directDraft = writtenDraft(handedOut[1] as FakeDuplex);
      expect(normalised(draft)).toBe(normalised(directDraft));
      expect(draft).not.toBe(directDraft);

      // The job's acted record and activity.
      const acted = await stored(armed.stub, "acted:");
      expect(acted.map(([, value]) => (value as { state: string }).state)).toEqual(["placed"]);
      const view = await runInDurableObject(armed.stub, (instance: UserAgent) => instance.rulesView());
      expect(view.activity.slice(0, 2)).toMatchObject([
        { kind: "run", outcome: "done" },
        { kind: "draft", outcome: "placed", messageId: parentId },
      ]);
    } finally {
      await armed.cleanup();
    }
  });

  it("a redirect header naming another address: the reply still goes to From, and the other address is in no header and no argument", async () => {
    const { armed, calls } = await armedWithRule({ draft: { text: RULE_TEXT } });
    try {
      queued.push(
        () => statusSession(4394, "120"),
        () => newMailSession(Date.now() + MIN, [{ uid: PARENT_UID, subject: "RE: Re: Offer", from: SENDER }]),
        () => parentSession(PARENT_UID, true),
        () => writeSession(),
      );
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
      expect(queued).toHaveLength(0);

      const draft = writtenDraft(handedOut[3] as FakeDuplex);
      const { headers } = splitMessage(draft);
      expect(header(headers, "To")).toBe(`To: ${SENDER}`);
      for (const line of headers) expect(line).not.toContain(REDIRECT);
      for (const call of calls) expect(JSON.stringify(call.args ?? {})).not.toContain(REDIRECT);
    } finally {
      await armed.cleanup();
    }
  });

  it("a flag-and-draft rule over one message: one flag, one reply, two acted records, two activity entries, and no index-build write", async () => {
    const { armed, calls } = await armedWithRule({ flag: true, draft: { text: RULE_TEXT } });
    try {
      queued.push(
        () => statusSession(4394, "120"),
        () => newMailSession(Date.now() + MIN, [{ uid: PARENT_UID, subject: "Offer", from: SENDER }]),
        () => flagSession(PARENT_UID),
        () => parentSession(PARENT_UID, false),
        () => writeSession(),
      );
      expect(await runDurableObjectAlarm(armed.stub)).toBe(true);
      expect(queued).toHaveLength(0);
      expect(handedOut).toHaveLength(5);

      expect(toolsOf(calls)).toEqual(["changes_since", "account_whoami", "mail_flag", "mail_compose_reply"]);
      const lines = handedOut.flatMap((duplex) => duplex.writtenLines());
      expect(lines.filter((line) => /UID STORE/.test(line))).toEqual([`a5 UID STORE ${PARENT_UID} +FLAGS (\\Flagged)`]);
      expect(lines.filter((line) => /\bAPPEND\b/.test(line))).toHaveLength(1);

      const acted = await stored(armed.stub, "acted:");
      expect(acted.map(([, value]) => (value as { state: string }).state).sort()).toEqual(["flagged", "placed"]);
      const view = await runInDurableObject(armed.stub, (instance: UserAgent) => instance.rulesView());
      expect(view.activity.slice(0, 3)).toMatchObject([
        { kind: "run", outcome: "done" },
        { kind: "draft", outcome: "placed" },
        { kind: "flag", outcome: "flagged" },
      ]);

      // Phase 26's index-build step skips the autonomy grant: nothing was
      // recorded, and no session beyond the five above was asked for.
      expect(await recallRows(armed.stub)).toEqual({ vectors: 0, state: 0 });
      expect(vi.mocked(connectImap)).toHaveBeenCalledTimes(5);
    } finally {
      await armed.cleanup();
    }
  });
});

// ============================================================ the job, directly

/** The account's own address in the direct cases. */
const SELF = "me@icloud.com";

/** The time of the first direct run: 10:00 UTC on a fixed day. */
const T0 = Date.UTC(2026, 8, 28, 10, 0, 0);

/** A user id for the direct cases. */
const NAME = "a".repeat(64);

/** A stored rule matching every row whose subject holds "role". */
function rule(id: string, then: Rule["then"], when: Rule["when"] = { subjectContains: ["role"] }): Rule {
  return { v: 1, id, createdAt: 0, when, then };
}

const DRAFT: Rule["then"] = { draft: { text: RULE_TEXT } };
const FLAG: Rule["then"] = { flag: true };

/** A new-mail row as the change check builds it. */
function newRow(i: number, over: Partial<NewMailRow> = {}): NewMailRow {
  return {
    id: `INBOX-msg-${i}`,
    uid: 5000 + i,
    unread: true,
    receivedAt: "13-Aug-2026 09:14:02 -0700",
    fromName: "A Sender",
    fromAddress: `sender${i}@example.com`,
    subject: "About the role",
    mailingList: false,
    ...over,
  };
}

/** A key-value store in memory, in the shape the job uses. */
function memoryStorage(seed: Record<string, unknown> = {}) {
  const map = new Map<string, unknown>(Object.entries(seed));
  return {
    map,
    get<T = unknown>(key: string): T | undefined {
      return map.get(key) as T | undefined;
    },
    put<T>(key: string, value: T): void {
      map.set(key, value);
    },
    delete(key: string): boolean {
      return map.delete(key);
    },
    *list<T = unknown>(options: { prefix?: string } = {}): Iterable<[string, T]> {
      for (const [key, value] of [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
        if (options.prefix === undefined || key.startsWith(options.prefix)) yield [key, value as T];
      }
    },
  };
}
type Memory = ReturnType<typeof memoryStorage>;

/** Storage for an armed person with these rules and a fresh stored marker. */
function armedStorage(rules: Rule[], markerAt = T0 - HOUR): Memory {
  return memoryStorage({
    [AUTONOMY_KEY]: { v: 1, grantId: "grant-1", generation: 1 },
    [RULES_KEY]: rules,
    [JOB_MARKER_KEY]: { marker: "marker-0", at: markerAt },
  });
}

/** What the fake tools answer. Every answer comes from the real builder. */
interface Script {
  rows: NewMailRow[];
  /** The inbox count; the row count when absent. */
  count?: number;
  whoami?: () => CallAnswer;
  compose?: (args: Record<string, unknown>) => CallAnswer;
}

/** The change answer for the inbox alone, as the real tool builds it. */
function changesAnswerFor(script: Script, sentMarker: boolean, marker: string): ChangesAnswer {
  return {
    mail: [
      {
        folder: "INBOX",
        state: sentMarker ? "changes" : "started",
        newMessages: sentMarker ? (script.count ?? script.rows.length) : null,
        otherActivity: null,
        mechanism: "status-uidnext",
        rows: sentMarker ? script.rows : [],
      },
    ],
    calendar: { calendars: [], notCovered: [], gone: 0, unchecked: null },
    carried: [],
    since: null,
    marker,
  } as unknown as ChangesAnswer;
}

/** A successful compose answer, as the real tool builds it. */
function placedAnswer(args: Record<string, unknown>): CallAnswer {
  return {
    kind: "ok",
    result: composeToolResult({
      appended: true,
      id: "Drafts-id",
      role: "drafts",
      roleSource: "name",
      sizeBytes: 900,
      refusal: null,
      limitBytes: null,
      parentMessageId: "<p@example.com>",
      referencesCount: 1,
      attachedCount: 0,
      attachedBytes: 0,
      consumedStagedIds: [],
      subject: "Re: About the role",
      to: (args.to as string[]) ?? [],
      cc: [],
    } as never),
  };
}

/** One recorded call. */
interface Recorded {
  readonly tool: string;
  readonly args: Record<string, unknown>;
}

let runCounter = 0;

/**
 * Run the job once at `now` over `script`, with the stored next wake forgotten
 * so the run is due. Answers the outcome and the calls.
 */
async function runOnce(
  storage: Memory,
  script: Script,
  now = T0,
): Promise<{ outcome: string; calls: Recorded[] }> {
  storage.delete(JOB_NEXT_AT_KEY);
  runCounter += 1;
  const fresh = `marker-${runCounter}`;
  const calls: Recorded[] = [];
  const answer = (tool: string, args: Record<string, unknown>): CallAnswer => {
    if (tool === "changes_since") {
      return { kind: "ok", result: changesResult(changesAnswerFor(script, typeof args.marker === "string", fresh)) };
    }
    if (tool === "account_whoami") {
      return script.whoami?.() ?? { kind: "ok", result: signedInAsResult({ appleId: SELF } as unknown as Principal) };
    }
    if (tool === "mail_flag") {
      return {
        kind: "ok",
        result: flagStateToolResult(args.id as string, true, { applied: true, flagged: true, source: "store-echo" }),
      };
    }
    if (tool === "mail_compose_reply") return script.compose?.(args) ?? placedAnswer(args);
    return { kind: "failed" };
  };
  const deps: JobDeps = {
    storage,
    name: NAME,
    now: () => now,
    isRetry: false,
    requestWake: async () => {},
    withSession: async (use) => ({
      kind: "ok",
      value: await use(async (tool, args) => {
        calls.push({ tool, args });
        return answer(tool, args);
      }),
    }),
    disarm: async () => {},
  };
  return { outcome: await runAutonomyJob(deps), calls };
}

/** The action calls only. */
function actions(calls: Recorded[]): Recorded[] {
  return calls.filter((call) => call.tool === "mail_flag" || call.tool === "mail_compose_reply");
}

/** Every acted record's state. */
function actedStates(storage: Memory): string[] {
  return [...storage.list<{ state: string }>({ prefix: "acted:" })].map(([, value]) => value.state);
}

/** The ring, oldest first. */
function ring(storage: Memory): ActivityEntry[] {
  return (storage.get<ActivityEntry[]>(ACTIVITY_KEY) ?? []).slice();
}

/** The action entries in the ring, oldest first. */
function actionEntries(storage: Memory, kind: "flag" | "draft"): ActivityEntry[] {
  return ring(storage).filter((entry) => entry.kind === kind);
}

describe("the sign-in check: once, and only in a run with a reply to place (D-30, D-16)", () => {
  it("a run with a draft verdict asks it exactly once, before its first write", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const { outcome, calls } = await runOnce(storage, { rows: [newRow(1), newRow(2)] });
    expect(outcome).toBe("done");
    expect(calls.map((call) => call.tool)).toEqual([
      "changes_since",
      "account_whoami",
      "mail_compose_reply",
      "mail_compose_reply",
    ]);
  });

  it("a run with only flag verdicts never asks it", async () => {
    const storage = armedStorage([rule("r1", FLAG)]);
    const { calls } = await runOnce(storage, { rows: [newRow(1)] });
    expect(calls.map((call) => call.tool)).toEqual(["changes_since", "mail_flag"]);
  });

  // An auth_failed answer is no longer unreadable: plan 28-03 counts it as the
  // auth failure it is (D-16 as revised), and test/autonomy-failures.test.ts
  // pins the count. The run still stops before any action.
  const unreadable: Array<[string, () => CallAnswer, string]> = [
    ["a failed call", () => ({ kind: "failed" }), "own_address_unreadable"],
    [
      "an auth error answer",
      () => ({
        kind: "ok",
        result: { isError: true, content: [{ type: "text", text: '{"category":"auth_failed","message":"x"}' }] },
      }),
      "auth_failed",
    ],
    [
      "another error answer",
      () => ({
        kind: "ok",
        result: { isError: true, content: [{ type: "text", text: '{"category":"connection_failed","message":"x"}' }] },
      }),
      "own_address_unreadable",
    ],
    [
      "an answer with no signedInAs",
      () => ({ kind: "ok", result: { content: [{ type: "text", text: "{}" }] } }),
      "own_address_unreadable",
    ],
  ];
  for (const [name, whoami, expected] of unreadable) {
    it(`${name}: the run stops before any action as ${expected}, keeps the marker, and records one entry`, async () => {
      const storage = armedStorage([rule("r1", { flag: true, draft: { text: RULE_TEXT } })]);
      const before = storage.get(JOB_MARKER_KEY);
      const { outcome, calls } = await runOnce(storage, { rows: [newRow(1)], whoami });
      expect(outcome).toBe(expected);
      expect(actions(calls)).toEqual([]);
      expect(storage.get(JOB_MARKER_KEY)).toEqual(before);
      expect(actedStates(storage)).toEqual([]);
      expect(ring(storage)).toEqual([expect.objectContaining({ kind: "run", outcome: expected })]);
    });
  }
});

describe("replies that are never placed (D-30)", () => {
  it("the account's own address, in upper case, or at another Apple domain: no reply, recorded, and the flag still applies", async () => {
    const storage = armedStorage([rule("r1", { flag: true, draft: { text: RULE_TEXT } })]);
    const rows = [
      newRow(1, { fromAddress: "ME@ICLOUD.COM" }),
      newRow(2, { fromAddress: "me@me.com" }),
      newRow(3, { fromAddress: "Me@Mac.com" }),
    ];
    const { outcome, calls } = await runOnce(storage, { rows });
    expect(outcome).toBe("done");
    expect(calls.filter((call) => call.tool === "mail_compose_reply")).toEqual([]);
    expect(calls.filter((call) => call.tool === "mail_flag")).toHaveLength(3);
    expect(actionEntries(storage, "draft").map((entry) => entry.outcome)).toEqual([
      "skipped_own_address",
      "skipped_own_address",
      "skipped_own_address",
    ]);
    expect(actedStates(storage).filter((state) => state === "skipped_own_address")).toHaveLength(3);
  });

  it("a row from a mailing list: no reply, the list skip recorded, the flag still applies", async () => {
    const storage = armedStorage([rule("r1", { flag: true, draft: { text: RULE_TEXT } })]);
    const { calls } = await runOnce(storage, { rows: [newRow(1, { mailingList: true })] });
    expect(actions(calls).map((call) => call.tool)).toEqual(["mail_flag"]);
    expect(actionEntries(storage, "draft").map((entry) => entry.outcome)).toEqual(["skipped_mailing_list"]);
  });

  it("a row whose From has no usable address: no reply, the no-address skip recorded", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const rows = [newRow(1, { fromAddress: null }), newRow(2, { fromAddress: "Jane <jane@example.com>" })];
    const { calls } = await runOnce(storage, { rows });
    expect(actions(calls)).toEqual([]);
    expect(actionEntries(storage, "draft").map((entry) => entry.outcome)).toEqual([
      "skipped_no_address",
      "skipped_no_address",
    ]);
  });

  it("two draft rules matching one message: one reply, from the first rule; the second is a duplicate skip", async () => {
    const storage = armedStorage([rule("first", DRAFT), rule("second", DRAFT)]);
    const { calls } = await runOnce(storage, { rows: [newRow(1)] });
    expect(actions(calls)).toHaveLength(1);
    expect(actionEntries(storage, "draft").map((entry) => [entry.ruleId, entry.outcome])).toEqual([
      ["first", "placed"],
      ["second", "skipped_duplicate"],
    ]);
  });

  it("skipped replies do not count toward the cap: 3 own-address messages and 3 good ones give 3 replies", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const rows = [
      newRow(1, { fromAddress: SELF }),
      newRow(2, { fromAddress: SELF }),
      newRow(3, { fromAddress: SELF }),
      newRow(4),
      newRow(5),
      newRow(6),
    ];
    const { calls } = await runOnce(storage, { rows });
    expect(actions(calls).map((call) => call.args.parentId)).toEqual(["INBOX-msg-4", "INBOX-msg-5", "INBOX-msg-6"]);
    expect(actionEntries(storage, "draft").map((entry) => entry.outcome)).not.toContain("skipped_cap");
  });

  it("a refused reply (appended false) is recorded as refused and never retried", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const refused = (args: Record<string, unknown>): CallAnswer => ({
      kind: "ok",
      result: composeToolResult({
        appended: false,
        id: null,
        role: null,
        roleSource: null,
        sizeBytes: 99_999_999,
        refusal: "message-too-large",
        limitBytes: 1,
        parentMessageId: null,
        referencesCount: null,
        attachedCount: 0,
        attachedBytes: 0,
        consumedStagedIds: [],
        subject: "Re: x",
        to: args.to as string[],
        cc: [],
      } as never),
    });
    const first = await runOnce(storage, { rows: [newRow(1)], compose: refused });
    expect(actions(first.calls)).toHaveLength(1);
    expect(actedStates(storage)).toEqual(["refused"]);
    const second = await runOnce(storage, { rows: [newRow(1)] }, T0 + 15 * MIN);
    expect(actions(second.calls)).toEqual([]);
  });

  it("every reply call carries exactly parentId, text and to, with to the one From address", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const { calls } = await runOnce(storage, { rows: [newRow(1, { fromName: "boss@example.com" })] });
    const [reply] = actions(calls);
    expect(Object.keys(reply?.args ?? {}).sort()).toEqual(["parentId", "text", "to"]);
    expect(reply?.args).toEqual({ parentId: "INBOX-msg-1", text: RULE_TEXT, to: ["sender1@example.com"] });
  });
});

describe("the caps (D-08)", () => {
  it("12 matching messages for a flag rule: 10 flags, 2 skipped_cap entries, 12 acted records; the next run makes no action call", async () => {
    const storage = armedStorage([rule("r1", FLAG)]);
    const rows = Array.from({ length: 12 }, (_v, i) => newRow(i + 1));
    const first = await runOnce(storage, { rows });
    expect(actions(first.calls)).toHaveLength(10);
    const outcomes = actionEntries(storage, "flag").map((entry) => entry.outcome);
    expect(outcomes.filter((one) => one === "flagged")).toHaveLength(10);
    expect(outcomes.filter((one) => one === "skipped_cap")).toHaveLength(2);
    expect(actedStates(storage)).toHaveLength(12);
    const second = await runOnce(storage, { rows }, T0 + 15 * MIN);
    expect(actions(second.calls)).toEqual([]);
  });

  it("5 matching messages for a draft rule: 3 replies this run, 2 skipped_cap", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    const rows = Array.from({ length: 5 }, (_v, i) => newRow(i + 1));
    const { calls } = await runOnce(storage, { rows });
    expect(actions(calls)).toHaveLength(3);
    expect(actionEntries(storage, "draft").map((entry) => entry.outcome)).toEqual([
      "placed",
      "placed",
      "placed",
      "skipped_cap",
      "skipped_cap",
    ]);
  });

  it("across runs in one UTC day the 11th reply is skipped_cap; the first after UTC midnight is placed", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    let n = 0;
    const three = () => Array.from({ length: 3 }, () => newRow((n += 1)));
    for (let run = 0; run < 3; run += 1) {
      const { calls } = await runOnce(storage, { rows: three() }, T0 + run * 15 * MIN);
      expect(actions(calls)).toHaveLength(3);
    }
    const fourth = await runOnce(storage, { rows: three() }, T0 + 3 * 15 * MIN);
    expect(actions(fourth.calls)).toHaveLength(1);
    expect(actionEntries(storage, "draft").slice(-3).map((entry) => entry.outcome)).toEqual([
      "placed",
      "skipped_cap",
      "skipped_cap",
    ]);
    const midnight = Date.UTC(2026, 8, 29, 0, 5, 0);
    const next = await runOnce(storage, { rows: [newRow((n += 1))] }, midnight);
    expect(actions(next.calls)).toHaveLength(1);
    expect(actionEntries(storage, "draft").at(-1)?.outcome).toBe("placed");
    expect(storage.get(JOB_DRAFT_DAY_KEY)).toEqual({ day: "2026-09-29", count: 1 });
  });
});

describe("the marker's gap rule and a new sign-in (D-26)", () => {
  it("a stored marker 25 hours old is not sent: a starting point that acts on nothing and stores the fresh marker", async () => {
    const storage = armedStorage([rule("r1", FLAG)], T0 - 25 * HOUR);
    const { outcome, calls } = await runOnce(storage, { rows: [newRow(1)] });
    expect(calls[0]).toEqual({ tool: "changes_since", args: {} });
    expect(outcome).toBe("started");
    expect(actions(calls)).toEqual([]);
    expect(storage.get(JOB_MARKER_KEY)).toEqual({ marker: `marker-${runCounter}`, at: T0 });
  });

  it("a stored marker 23 hours old is sent", async () => {
    const storage = armedStorage([rule("r1", FLAG)], T0 - 23 * HOUR);
    const { outcome, calls } = await runOnce(storage, { rows: [newRow(1)] });
    expect(calls[0]).toEqual({ tool: "changes_since", args: { marker: "marker-0" } });
    expect(outcome).toBe("done");
    expect(actions(calls)).toHaveLength(1);
  });

  it("a new sign-in between runs changes nothing: the stored marker is sent and the day's count stands", async () => {
    const storage = armedStorage([rule("r1", DRAFT)]);
    await runOnce(storage, { rows: [newRow(1), newRow(2)] });
    const dayBefore = storage.get(JOB_DRAFT_DAY_KEY);
    const markerBefore = storage.get<{ marker: string }>(JOB_MARKER_KEY)?.marker;
    expect(dayBefore).toEqual({ day: "2026-09-28", count: 2 });

    // The sign-in: a new grant id and a generation two higher (the Claude
    // client submits the form twice).
    storage.put(AUTONOMY_KEY, { v: 1, grantId: "grant-2", generation: 3 });
    expect(storage.get(JOB_DRAFT_DAY_KEY)).toEqual(dayBefore);

    const { calls } = await runOnce(storage, { rows: [newRow(3)] }, T0 + 15 * MIN);
    expect(calls[0]).toEqual({ tool: "changes_since", args: { marker: markerBefore } });
    expect(actions(calls)).toHaveLength(1);
    expect(storage.get(JOB_DRAFT_DAY_KEY)).toEqual({ day: "2026-09-28", count: 3 });
  });

  it("an answer counting 30 new messages with 25 rows records 5 not seen", async () => {
    const storage = armedStorage([rule("r1", FLAG, { subjectContains: ["nothing matches this"] })]);
    const rows = Array.from({ length: 25 }, (_v, i) => newRow(i + 1));
    await runOnce(storage, { rows, count: 30 });
    expect(ring(storage)).toContainEqual(expect.objectContaining({ kind: "run", outcome: "not_seen", count: 5 }));
  });
});

describe("bounded records (D-15)", () => {
  it("acted records dated 15 days ago are removed at the end of a run; 13 days ago remain", async () => {
    const storage = armedStorage([rule("r1", FLAG)]);
    storage.put("acted:old:flag:1", { state: "flagged", at: T0 - 15 * DAY });
    storage.put("acted:recent:flag:2", { state: "flagged", at: T0 - 13 * DAY });
    await runOnce(storage, { rows: [] });
    expect(storage.get("acted:old:flag:1")).toBeUndefined();
    expect(storage.get("acted:recent:flag:2")).toEqual({ state: "flagged", at: T0 - 13 * DAY });
  });

  it("with 700 old records one run removes 500", async () => {
    const storage = armedStorage([rule("r1", FLAG)]);
    for (let i = 0; i < 700; i += 1) {
      storage.put(`acted:old:flag:${String(i).padStart(4, "0")}`, { state: "flagged", at: T0 - 20 * DAY });
    }
    await runOnce(storage, { rows: [] });
    expect([...storage.list({ prefix: "acted:" })]).toHaveLength(200);
  });

  it("a verdict whose record exists in any state is never retried, reserved and skipped_cap included", async () => {
    const storage = armedStorage([rule("r1", { flag: true, draft: { text: RULE_TEXT } })]);
    await runOnce(storage, { rows: [newRow(1)] });
    const keys = [...storage.list<{ state: string; at: number }>({ prefix: "acted:" })].map(([key]) => key);
    expect(keys).toHaveLength(2);
    for (const state of ["reserved", "skipped_cap"]) {
      for (const key of keys) storage.put(key, { state, at: T0 });
      const { calls } = await runOnce(storage, { rows: [newRow(1)] }, T0 + 15 * MIN);
      expect(actions(calls)).toEqual([]);
      expect(calls.map((call) => call.tool)).toEqual(["changes_since"]);
    }
  });
});

// ======================================================== the object's methods

describe("what the person can read back, and the rule cap (AUTO-15, D-18, D-08)", () => {
  function freshObject(): { stub: Stub; userId: string } {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const userId = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return { stub: entryEnv().USER_AGENT.getByName(userId), userId };
  }

  async function clear(stub: Stub): Promise<void> {
    await runInDurableObject(stub, async (_i, state) => {
      for (const [key] of state.storage.kv.list()) state.storage.kv.delete(key);
      await state.storage.deleteAlarm();
    });
  }

  it("rulesView gives the newest 50 entries, newest first, each of a closed kind and with no subject, address or text", async () => {
    const { stub } = freshObject();
    try {
      await runInDurableObject(stub, (_i, state) => {
        const entries: ActivityEntry[] = Array.from({ length: 100 }, (_v, i) => ({
          at: T0 + i,
          runId: `run-${i}`,
          kind: (["run", "flag", "draft"] as const)[i % 3] as ActivityEntry["kind"],
          ruleId: i % 3 === 0 ? null : "r1",
          messageId: i % 3 === 0 ? null : `INBOX-msg-${i}`,
          outcome: "done",
        }));
        state.storage.kv.put(ACTIVITY_KEY, entries);
      });
      const view = await stub.rulesView();
      expect(view.activity).toHaveLength(50);
      expect(view.activity.map((entry) => entry.at)).toEqual(Array.from({ length: 50 }, (_v, i) => T0 + 99 - i));
      for (const entry of view.activity) {
        expect(["run", "flag", "draft"]).toContain(entry.kind);
        for (const key of Object.keys(entry)) {
          expect(["at", "runId", "kind", "ruleId", "messageId", "outcome", "count"]).toContain(key);
        }
      }
    } finally {
      await clear(stub);
    }
  });

  it("the 21st addRule is refused and nothing more is stored", async () => {
    const { stub } = freshObject();
    try {
      for (let i = 0; i < 20; i += 1) {
        const added = await stub.addRule({ when: { fromAddresses: [`p${i}@example.com`] }, then: { flag: true } });
        expect(added.ok).toBe(true);
      }
      const before = await runInDurableObject(stub, (_i, state) => state.storage.kv.get(RULES_KEY));
      const refused = await stub.addRule({ when: { fromAddresses: ["p20@example.com"] }, then: { flag: true } });
      expect(refused).toMatchObject({ ok: false, refusal: "too-many-rules" });
      expect(await runInDurableObject(stub, (_i, state) => state.storage.kv.get(RULES_KEY))).toEqual(before);
      expect(before as unknown[]).toHaveLength(20);
    } finally {
      await clear(stub);
    }
  });
});
