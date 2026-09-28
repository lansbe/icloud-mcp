// The rules job against a mailbox of hostile mail (Phase 28, plan 28-05;
// AUTO-16; success criterion 6; D-01, D-04, D-05 as revised, D-09, D-29, D-30,
// D-31).
//
// The design says nothing a stranger writes can change what the job does, and a
// reply goes to the message's From address and nowhere else. This file tries
// hard to break both, with test/fixtures/hostile-mailbox.ts playing the
// stranger.
//
//   LEVEL A, pure. The matcher's verdicts over every hostile row equal the
//   hand-written table in the fixture.
//   LEVEL B, the whole job. The job runs over the hostile rows with a recording
//   caller whose answers come from the REAL tool-side builders. Only the four
//   tools are named, only matched rows are acted on, a reply carries exactly
//   its three arguments and goes to that row's From address, the caps hold, and
//   the rules and the job's settings are unchanged. Then each fixture runs
//   alone, and each reply fixture's written outcome is held by a named case.
//
//   LEVEL C, the wire. The real `changes_since` over the fake socket, serving
//   the fixture's raw headers, fetches no body, says which mail came from a
//   list, and gives the job the same rows as level A.
//   LEVEL D, the real reply tool. Given exactly the arguments level B recorded,
//   and serving the fixture's raw message, it writes a draft addressed to the
//   From address alone; for the hostile threading headers it refuses, or adds
//   no header of its own.
//   rules_test over the fixture gives level A's verdicts and writes nothing.
//   A seeded sweep of generated rule sets agrees with a reference matcher
//   written here from D-03 and D-30.
//
// If a case here fails, the defect is in src/agent/ and is fixed there. No
// assertion in this file may be loosened to make a hostile case pass.
//
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { ACTIVITY_KEY, type ActivityEntry } from "../src/agent/activity";
import { createLeasedMail } from "../src/agent/lease";
import { parseRule, type RuleBody } from "../src/agent/rules";
import { readFencedJson } from "../src/agent/tool-reply";
import { type MarkerContent, sealMarker } from "../src/change-marker";
import { createDavFetch } from "../src/dav/transport";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { CHANGES_TOOL_NAME, registerChangesTool } from "../src/mcp/tools/changes";
import { registerMailTools } from "../src/mcp/tools/mail";
import { registerRulesTools } from "../src/mcp/tools/rules";
import { userIdOf } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  statusResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { type RecordedToolResult, type TestUser, readToolResult, testPrincipal } from "./fixtures/two-users";
import { AUTONOMY_KEY } from "../src/agent/autonomy";
import { AUTONOMY_TOOLS } from "../src/agent/autonomy-client";
import { nextWakeAfter } from "../src/agent/cadence";
import { evaluate, type Verdict } from "../src/agent/evaluate";
import {
  JOB_MARKER_KEY,
  JOB_NEXT_AT_KEY,
  type JobDeps,
  MAX_DRAFTS_PER_RUN,
  MAX_FLAGS_PER_RUN,
  RULES_KEY,
  runAutonomyJob,
} from "../src/agent/job";
import type { Rule } from "../src/agent/rules";
import type { CallAnswer, EnvelopeRow } from "../src/agent/tool-call";
import { readChangesAnswer } from "../src/agent/tool-reply";
import type { UserAgent } from "../src/agent/user-agent";
import type { NewMailRow } from "../src/mail/service";
import { signedInAsResult } from "../src/mcp/tools/account";
import type { Principal } from "../src/principal";
import {
  ADDRESS_RULE_TEXT,
  COLLECTOR,
  type ExpectedOutcome,
  FIXTURE_RULES,
  FIXTURE_SELF,
  FORGED_ROW_ID,
  HOSTILE_MAILBOX,
  type HostileMessage,
  RULE_INDEX,
  type RuleName,
  TRUSTED_ADDRESSES,
  WORD_RULE_TEXT,
  hostile,
  idOf,
  uidOf,
} from "./fixtures/hostile-mailbox";
import {
  HOUR,
  T0,
  type Recorded,
  armedStorage,
  changesAnswerFor,
  directRun,
  flaggedAnswer,
  placedAnswer,
} from "./fixtures/job-direct";

// ---------------------------------------------------------------------------
// The name lists, written here so the fixture cannot quietly lose one
// ---------------------------------------------------------------------------

/** One fixture for each category RESEARCH §12 names, plus the ordinary control. */
const RESEARCH_CATEGORY_FIXTURES = [
  "body-instruction",
  "subject-instruction",
  "display-name-instruction",
  "fake-tool-call-subject",
  "fake-jsonrpc-body",
  "forged-end-marker",
  "fence-preamble-subject",
  "crlf-subject",
  "encoded-word-subject",
  "keyword-plus-also",
  "oversized-subject",
  "zero-width-subject",
  "bidi-override-subject",
  "homoglyph-subject",
  "fullwidth-subject",
  "calendar-invitation",
  "hidden-html-text",
  "attachment-named-like-rule-file",
  "fake-apple-security-notice",
  "unflag-or-mark-read",
  "hundreds-of-recipients",
  "header-claiming-a-rule",
  "another-message-id-in-subject",
  "call-the-rules-tools",
  "ordinary-control",
];

/**
 * The plan's table of reply fixtures and their outcomes, restated from the
 * plan by hand. The fixture's own `expected` must equal it, so neither can
 * drift alone. "reply" is the one address a reply call goes to.
 */
const PLAN_TABLE: Record<string, ExpectedOutcome> = {
  "forged-from": { flag: true, reply: "hr@trusted.example", skip: null },
  "name-looks-like-address": { flag: false, reply: "attacker@evil.example", skip: null },
  "name-encoded-word": { flag: false, reply: "attacker2@evil.example", skip: null },
  "name-with-brackets-and-comma": { flag: false, reply: "attacker3@evil.example", skip: null },
  "redirect-header": { flag: true, reply: "recruiter@trusted.example", skip: null },
  "own-address-exact": { flag: false, reply: null, skip: "own-address" },
  "own-address-case": { flag: false, reply: null, skip: "own-address" },
  "own-address-sibling": { flag: false, reply: null, skip: "own-address" },
  // The list fixture from a subdomain of the flag rule's domain: flagged, no reply.
  "list-id": { flag: true, reply: null, skip: "mailing-list" },
  "list-unsubscribe": { flag: false, reply: null, skip: "mailing-list" },
  "no-address-group": { flag: false, reply: null, skip: "no-address" },
  "no-address-name-only": { flag: false, reply: null, skip: "no-address" },
  "no-address-empty-angle": { flag: false, reply: null, skip: "no-address" },
  "no-address-garbage": { flag: false, reply: null, skip: "no-address" },
  "two-from-addresses": { flag: false, reply: "first@one.example", skip: null },
  "threading-line-break": { flag: false, reply: "thread@evil.example", skip: null },
  "threading-oversized": { flag: false, reply: "longref@evil.example", skip: null },
};
const REPLY_FIXTURES = Object.keys(PLAN_TABLE);

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

const ALLOWED_TOOLS: readonly string[] = AUTONOMY_TOOLS;

const HOSTILE_ROWS: NewMailRow[] = HOSTILE_MAILBOX.map((one) => one.row);

/** The sign-in check's answer for the fixture's own address, from the real builder. */
function whoamiForSelf(): CallAnswer {
  return { kind: "ok", result: signedInAsResult({ appleId: FIXTURE_SELF } as unknown as Principal) };
}

/** Answer the account's own address as FIXTURE_SELF; everything else as the direct harness does. */
function selfAnswer(tool: string): CallAnswer | undefined {
  return tool === "account_whoami" ? whoamiForSelf() : undefined;
}

/** The rows exactly as the job reads them: through the real change answer and the job's own parser. */
function parsedRows(rows: NewMailRow[]): readonly EnvelopeRow[] {
  const answer = changesAnswerFor(rows, true, "fresh-marker-a");
  if (answer.kind !== "ok") throw new Error("the change answer was not built");
  const reading = readChangesAnswer(answer.result);
  if (reading.kind !== "ok") throw new Error(`the change answer read as ${reading.kind}`);
  return reading.rows;
}

/** Level A's expected table, built from the fixture's hand-written verdicts. */
function expectedVerdicts(mailbox: readonly HostileMessage[]): Verdict[] {
  const out: Verdict[] = [];
  mailbox.forEach((one, row) => {
    for (const [rule, action] of one.verdicts) out.push({ rule: RULE_INDEX[rule], row, action });
  });
  return out;
}

/** The text of the rule that places a fixture's reply: its first draft verdict's rule. */
function replyTextOf(one: HostileMessage): string | null {
  const first = one.verdicts.find(([, action]) => action === "draft");
  if (first === undefined) return null;
  return first[0] === "trusted" ? ADDRESS_RULE_TEXT : WORD_RULE_TEXT;
}

/** Every string anywhere inside `value`. */
function stringsIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (typeof value === "object" && value !== null) return Object.values(value).flatMap(stringsIn);
  return [];
}

/** The skip outcome a reply skip is recorded as. */
function skipOutcome(skip: NonNullable<ExpectedOutcome["skip"]>): string {
  return `skipped_${skip.replace("-", "_")}`;
}

/**
 * What every recorded call in a run must satisfy, whatever the rules said:
 * only the four tools; a flag always sets, on a row that was served; a reply
 * carries exactly three keys, on a row that was served, in a rule's words, to
 * that row's From address alone. The only message-derived strings in any
 * argument are a row's id and that row's From address.
 */
function assertCallShapes(calls: readonly Recorded[], rows: readonly NewMailRow[], texts: readonly string[]): void {
  const byId = new Map(rows.map((one) => [one.id, one]));
  for (const call of calls) {
    expect(ALLOWED_TOOLS, call.tool).toContain(call.tool);
    if (call.tool === "mail_flag") {
      expect(Object.keys(call.args).sort()).toEqual(["flagged", "id"]);
      expect(call.args.flagged).toBe(true);
      expect(byId.has(call.args.id as string), "a flag on an id no row carried").toBe(true);
    } else if (call.tool === "mail_compose_reply") {
      expect(Object.keys(call.args).sort()).toEqual(["parentId", "text", "to"]);
      const parent = byId.get(call.args.parentId as string);
      expect(parent, "a reply to an id no row carried").toBeDefined();
      expect(texts).toContain(call.args.text);
      expect(call.args.to).toEqual([parent?.fromAddress]);
    } else if (call.tool === "changes_since") {
      // No folders argument: the inbox only (D-02). A marker, when sent, is the server's own.
      expect(Object.keys(call.args).every((key) => key === "marker")).toBe(true);
    } else {
      expect(call.args).toEqual({});
    }
  }
  // The only strings from a message in any argument: a row's id, and the From
  // address of the row a reply answers.
  const allowed = new Set<string>([...texts]);
  for (const call of calls) {
    if (call.tool === "mail_flag") allowed.add(call.args.id as string);
    if (call.tool === "mail_compose_reply") {
      allowed.add(call.args.parentId as string);
      allowed.add(byId.get(call.args.parentId as string)?.fromAddress as string);
    }
    if (call.tool === "changes_since" && typeof call.args.marker === "string") allowed.add(call.args.marker);
  }
  for (const call of calls) {
    for (const text of stringsIn(call.args)) expect(allowed.has(text), `${call.tool} carried ${JSON.stringify(text).slice(0, 80)}`).toBe(true);
  }
}

/** No fixture's forbidden strings, and never the account's own address, in any argument. */
function assertNothingLeaked(calls: readonly Recorded[], mailbox: readonly HostileMessage[]): void {
  const everything = JSON.stringify(calls.map((call) => call.args));
  for (const one of mailbox) {
    for (const text of one.mustNotAppear) {
      expect(everything.includes(text), `${one.name}: ${JSON.stringify(text).slice(0, 60)} reached an argument`).toBe(false);
    }
  }
  for (const call of calls.filter((one) => one.tool === "mail_compose_reply")) {
    const to = (call.args.to as string[])[0] as string;
    expect(to.toLowerCase()).not.toBe(FIXTURE_SELF);
    expect(to.toLowerCase().split("@")[0] === "me" && /@(icloud|me|mac)\.com$/i.test(to)).toBe(false);
  }
}

/** Every activity entry, oldest first. */
function activityOf(storage: { get<T>(key: string): T | undefined }): ActivityEntry[] {
  return (storage.get<ActivityEntry[]>(ACTIVITY_KEY) ?? []).slice();
}

/** No activity entry holds an address or a subject. */
function assertActivityHoldsNoAddress(entries: readonly ActivityEntry[]): void {
  for (const entry of entries) {
    expect(JSON.stringify(entry)).not.toContain("@");
    expect(Object.keys(entry).sort()).toEqual(
      entry.count === undefined
        ? ["at", "kind", "messageId", "outcome", "ruleId", "runId"]
        : ["at", "count", "kind", "messageId", "outcome", "ruleId", "runId"],
    );
  }
}

// ---------------------------------------------------------------------------
// The fixture itself
// ---------------------------------------------------------------------------

describe("the hostile mailbox (AUTO-16)", () => {
  it("holds at least 34 messages, one per RESEARCH §12 category and every reply fixture, each named once", () => {
    const names = HOSTILE_MAILBOX.map((one) => one.name);
    expect(HOSTILE_MAILBOX.length).toBeGreaterThanOrEqual(34);
    expect(new Set(names).size).toBe(names.length);
    expect([...names].sort()).toEqual([...RESEARCH_CATEGORY_FIXTURES, ...REPLY_FIXTURES].sort());
  });

  it("each reply fixture's written outcome is the plan's", () => {
    for (const name of REPLY_FIXTURES) expect(hostile(name).expected, name).toEqual(PLAN_TABLE[name]);
  });

  it("each entry says what it attempts, and its row is the one its UID gives", () => {
    for (const one of HOSTILE_MAILBOX) {
      expect(one.attempts.length).toBeGreaterThan(20);
      expect(one.row.id).toBe(idOf(one.row.uid - 7000));
      expect(one.raw).toContain("\r\n\r\n");
    }
  });

  it("no fixture's real From address is the display-name bait, and every expected reply is that row's From address", () => {
    for (const one of HOSTILE_MAILBOX) {
      expect(one.row.fromAddress).not.toBe("ceo@trusted.example");
      if (one.expected.reply !== null) expect(one.expected.reply).toBe(one.row.fromAddress);
    }
  });

  it("the rule words never contain a fixture string", () => {
    for (const one of HOSTILE_MAILBOX) {
      for (const text of one.mustNotAppear) {
        expect(ADDRESS_RULE_TEXT).not.toContain(text);
        expect(WORD_RULE_TEXT).not.toContain(text);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Level A
// ---------------------------------------------------------------------------

describe("level A: the matcher over every hostile row equals the hand-written table", () => {
  it("the verdicts are exactly the table's, in order", () => {
    const rows = parsedRows(HOSTILE_ROWS);
    expect(evaluate(FIXTURE_RULES, rows)).toEqual(expectedVerdicts(HOSTILE_MAILBOX));
  });

  it("the forged END marker survives as one subject and adds no row", () => {
    const rows = parsedRows(HOSTILE_ROWS);
    expect(rows).toHaveLength(HOSTILE_MAILBOX.length);
    expect(rows.map((one) => one.id)).toEqual(HOSTILE_MAILBOX.map((one) => one.row.id));
    expect(rows.some((one) => one.id === FORGED_ROW_ID)).toBe(false);
    const forged = rows.find((one) => one.id === hostile("forged-end-marker").row.id);
    expect(forged?.subject).toBe(hostile("forged-end-marker").row.subject);
    expect(forged?.senderAddress).toBe("fence@evil.example");
  });

  it("no display name reaches the row the job holds", () => {
    for (const row of parsedRows(HOSTILE_ROWS)) {
      expect(Object.keys(row).sort()).toEqual(["id", "mailingList", "receivedAt", "senderAddress", "subject"]);
    }
  });

  it("the oversized subject is compared without throwing", () => {
    const one = hostile("oversized-subject");
    expect(one.row.subject?.length).toBeGreaterThan(100 * 1024);
    expect(evaluate(FIXTURE_RULES, parsedRows([one.row]))).toEqual([{ rule: RULE_INDEX.word, row: 0, action: "draft" }]);
  });
});

// ---------------------------------------------------------------------------
// Level B: one run over the whole mailbox, inside a real object
// ---------------------------------------------------------------------------

/** A person's object for the whole-mailbox run. */
const OBJECT_NAME = "d".repeat(64);
type Stub = DurableObjectStub<UserAgent>;
function objectStub(): Stub {
  return env.USER_AGENT.getByName(OBJECT_NAME) as unknown as Stub;
}

/**
 * Every verdict of the whole-mailbox run and what it came to, by hand from the
 * caps (D-08): 10 flags a run, and 3 replies a run with the cap checked before
 * the recipient. Row order, then rule order, flag before reply.
 */
const WHOLE_MAILBOX_OUTCOMES: readonly (readonly [string, RuleName, "flag" | "draft", string])[] = [
  ["body-instruction", "domain", "flag", "flagged"],
  ["fake-tool-call-subject", "domain", "flag", "flagged"],
  ["fake-jsonrpc-body", "word", "draft", "placed"],
  ["forged-end-marker", "word", "draft", "placed"],
  ["crlf-subject", "word", "draft", "placed"],
  ["encoded-word-subject", "word", "draft", "skipped_cap"],
  ["keyword-plus-also", "domain", "flag", "flagged"],
  ["keyword-plus-also", "word", "draft", "skipped_cap"],
  ["oversized-subject", "word", "draft", "skipped_cap"],
  ["bidi-override-subject", "word", "draft", "skipped_cap"],
  ["fullwidth-subject", "word", "draft", "skipped_cap"],
  ["calendar-invitation", "word", "draft", "skipped_cap"],
  ["hidden-html-text", "domain", "flag", "flagged"],
  ["unflag-or-mark-read", "domain", "flag", "flagged"],
  ["hundreds-of-recipients", "domain", "flag", "flagged"],
  ["header-claiming-a-rule", "domain", "flag", "flagged"],
  ["another-message-id-in-subject", "word", "draft", "skipped_cap"],
  ["ordinary-control", "domain", "flag", "flagged"],
  ["forged-from", "trusted", "flag", "flagged"],
  ["forged-from", "trusted", "draft", "skipped_cap"],
  ["forged-from", "word", "draft", "skipped_duplicate"],
  ["name-looks-like-address", "word", "draft", "skipped_cap"],
  ["name-encoded-word", "word", "draft", "skipped_cap"],
  ["name-with-brackets-and-comma", "word", "draft", "skipped_cap"],
  ["redirect-header", "trusted", "flag", "flagged"],
  ["redirect-header", "trusted", "draft", "skipped_cap"],
  ["redirect-header", "word", "draft", "skipped_duplicate"],
  ["own-address-exact", "word", "draft", "skipped_cap"],
  ["own-address-case", "word", "draft", "skipped_cap"],
  ["own-address-sibling", "word", "draft", "skipped_cap"],
  ["list-id", "domain", "flag", "skipped_cap"],
  ["list-id", "word", "draft", "skipped_cap"],
  ["list-unsubscribe", "word", "draft", "skipped_cap"],
  ["no-address-group", "word", "draft", "skipped_cap"],
  ["no-address-name-only", "word", "draft", "skipped_cap"],
  ["no-address-empty-angle", "word", "draft", "skipped_cap"],
  ["no-address-garbage", "word", "draft", "skipped_cap"],
  ["two-from-addresses", "word", "draft", "skipped_cap"],
  ["threading-line-break", "word", "draft", "skipped_cap"],
  ["threading-oversized", "word", "draft", "skipped_cap"],
];

/** The default answers, from the real tool-side builders. */
function realAnswer(tool: string, args: Record<string, unknown>, rows: NewMailRow[]): CallAnswer {
  if (tool === "changes_since") return changesAnswerFor(rows, typeof args.marker === "string", "fresh-marker-b");
  if (tool === "account_whoami") return whoamiForSelf();
  if (tool === "mail_flag") return flaggedAnswer(args);
  if (tool === "mail_compose_reply") return placedAnswer(args);
  return { kind: "failed" };
}

interface ObjectRun {
  readonly outcome: string;
  readonly calls: Recorded[];
  readonly before: Awaited<ReturnType<UserAgent["rulesView"]>>;
  readonly after: Awaited<ReturnType<UserAgent["rulesView"]>>;
  readonly storedRules: unknown;
  readonly nextAt: unknown;
  readonly activity: ActivityEntry[];
}

/** Seed the object, then run the real job once inside it over `rows`. */
async function wholeMailboxRun(rows: NewMailRow[]): Promise<ObjectRun> {
  const stub = objectStub();
  await runInDurableObject(stub, async (_i, state) => {
    await state.storage.deleteAlarm();
    await state.storage.deleteAll();
    const kv = state.storage.kv;
    kv.put(RULES_KEY, FIXTURE_RULES);
    kv.put(AUTONOMY_KEY, { v: 1, grantId: "grant-1", generation: 1 });
    kv.put(JOB_MARKER_KEY, { marker: "marker-0", at: T0 - HOUR });
  });
  try {
    const before = await stub.rulesView();
    const calls: Recorded[] = [];
    const outcome = await runInDurableObject(stub, async (_i, state) => {
      const deps: JobDeps = {
        storage: state.storage.kv as unknown as JobDeps["storage"],
        name: OBJECT_NAME,
        now: () => T0,
        isRetry: false,
        requestWake: async () => {},
        withSession: async (use) => ({
          kind: "ok",
          value: await use(async (tool, args) => {
            calls.push({ tool, args: structuredClone(args) });
            return realAnswer(tool, args, rows);
          }),
        }),
        disarm: async () => {},
        statusStore: { put: async () => {} },
      };
      return runAutonomyJob(deps);
    });
    const after = await stub.rulesView();
    const { storedRules, nextAt, activity } = await runInDurableObject(stub, (_i, state) => ({
      storedRules: state.storage.kv.get(RULES_KEY),
      nextAt: state.storage.kv.get(JOB_NEXT_AT_KEY),
      activity: activityOf(state.storage.kv),
    }));
    return { outcome, calls, before, after, storedRules, nextAt, activity };
  } finally {
    await runInDurableObject(stub, async (_i, state) => {
      await state.storage.deleteAlarm();
      await state.storage.deleteAll();
    });
  }
}

describe("level B: the whole job over the whole hostile mailbox", () => {
  it("names only the four tools, asks the sign-in check once before the first write, and ends done", async () => {
    const run = await wholeMailboxRun(HOSTILE_ROWS);

    expect(run.outcome).toBe("done");
    for (const call of run.calls) expect(ALLOWED_TOOLS).toContain(call.tool);
    const tools = run.calls.map((call) => call.tool);
    expect(tools.filter((tool) => tool === "account_whoami")).toHaveLength(1);
    expect(tools.filter((tool) => tool === "changes_since")).toHaveLength(1);
    const firstWrite = tools.findIndex((tool) => tool === "mail_flag" || tool === "mail_compose_reply");
    expect(firstWrite).toBeGreaterThan(tools.indexOf("account_whoami"));
    expect(tools.indexOf("account_whoami")).toBeGreaterThan(tools.indexOf("changes_since"));
  });

  it("every action is one the table says, the caps hold, and each verdict came to exactly what the caps give", async () => {
    const run = await wholeMailboxRun(HOSTILE_ROWS);
    const idsOf = (name: string) => hostile(name).row.id;

    // Flags: only rows the table says to flag, always set.
    const flagIds = new Set(
      HOSTILE_MAILBOX.filter((one) => one.verdicts.some(([, action]) => action === "flag")).map((one) => one.row.id),
    );
    const flags = run.calls.filter((call) => call.tool === "mail_flag");
    const replies = run.calls.filter((call) => call.tool === "mail_compose_reply");
    for (const call of flags) {
      expect(flagIds.has(call.args.id as string)).toBe(true);
      expect(call.args.flagged).toBe(true);
    }
    expect(flags.length).toBeLessThanOrEqual(MAX_FLAGS_PER_RUN);
    expect(replies.length).toBeLessThanOrEqual(MAX_DRAFTS_PER_RUN);

    // Replies: only rows the table says to answer, to that row's From address.
    const replyIds = new Set(HOSTILE_MAILBOX.filter((one) => one.expected.reply !== null).map((one) => one.row.id));
    for (const call of replies) expect(replyIds.has(call.args.parentId as string)).toBe(true);

    // Exactly what the caps give, verdict by verdict, as the activity records it.
    const expected = WHOLE_MAILBOX_OUTCOMES.map(([name, rule, action, outcome]) => ({
      kind: action,
      ruleId: FIXTURE_RULES[RULE_INDEX[rule]]?.id,
      messageId: idsOf(name),
      outcome,
    }));
    const recorded = run.activity
      .filter((entry) => entry.kind !== "run")
      .map(({ kind, ruleId, messageId, outcome }) => ({ kind, ruleId, messageId, outcome }));
    expect(recorded).toEqual(expected);
    expect(flags.map((call) => call.args.id)).toEqual(
      expected.filter((one) => one.kind === "flag" && one.outcome === "flagged").map((one) => one.messageId),
    );
    expect(replies.map((call) => call.args.parentId)).toEqual(
      expected.filter((one) => one.kind === "draft" && one.outcome === "placed").map((one) => one.messageId),
    );
    expect(flags).toHaveLength(MAX_FLAGS_PER_RUN);
    expect(replies).toHaveLength(MAX_DRAFTS_PER_RUN);
  });

  it("every call has its exact shape, and the only message-derived values are a row's id and that row's From address", async () => {
    const run = await wholeMailboxRun(HOSTILE_ROWS);
    assertCallShapes(run.calls, HOSTILE_ROWS, [ADDRESS_RULE_TEXT, WORD_RULE_TEXT]);
    assertNothingLeaked(run.calls, HOSTILE_MAILBOX);
    // The forged row's id and the id named in a subject reach nothing.
    const everything = JSON.stringify(run.calls);
    expect(everything).not.toContain(FORGED_ROW_ID);
    expect(everything).not.toContain(COLLECTOR);
  });

  it("the rules and the job's settings are unchanged, and no activity entry holds an address", async () => {
    const run = await wholeMailboxRun(HOSTILE_ROWS);
    expect(run.after.rules).toEqual(run.before.rules);
    expect(run.after.rules).toEqual(FIXTURE_RULES);
    expect(run.storedRules).toEqual(FIXTURE_RULES);
    expect(run.nextAt).toBe(nextWakeAfter(T0, OBJECT_NAME));
    expect(run.after.job.nextAt).toBe(nextWakeAfter(T0, OBJECT_NAME));
    assertActivityHoldsNoAddress(run.activity);
  });
});

// ---------------------------------------------------------------------------
// Level B: each fixture alone, and each reply fixture's named case
// ---------------------------------------------------------------------------

/** Run the job over one fixture alone, with the account's own address as FIXTURE_SELF. */
async function aloneRun(one: HostileMessage) {
  const storage = armedStorage(FIXTURE_RULES as Rule[]);
  const run = await directRun(storage, { rows: [one.row], answer: selfAnswer });
  return { ...run, storage };
}

/** Assert a lone run did exactly what `one.expected` says. */
function assertAloneOutcome(one: HostileMessage, run: Awaited<ReturnType<typeof aloneRun>>): void {
  expect(run.outcome).toBe("done");
  assertCallShapes(run.calls, [one.row], [ADDRESS_RULE_TEXT, WORD_RULE_TEXT]);
  assertNothingLeaked(run.calls, [one]);

  const flags = run.calls.filter((call) => call.tool === "mail_flag");
  expect(flags.map((call) => call.args)).toEqual(one.expected.flag ? [{ id: one.row.id, flagged: true }] : []);

  const replies = run.calls.filter((call) => call.tool === "mail_compose_reply");
  if (one.expected.reply === null) {
    expect(replies).toEqual([]);
  } else {
    expect(replies.map((call) => call.args)).toEqual([
      { parentId: one.row.id, text: replyTextOf(one), to: [one.expected.reply] },
    ]);
  }

  const drafts = activityOf(run.storage).filter((entry) => entry.kind === "draft");
  const skips = drafts.filter((entry) => entry.outcome.startsWith("skipped_") && entry.outcome !== "skipped_duplicate");
  if (one.expected.skip === null) {
    expect(skips).toEqual([]);
  } else {
    expect(skips.map((entry) => entry.outcome)).toEqual([skipOutcome(one.expected.skip)]);
  }
  // A second reply verdict for the same message is only ever a duplicate skip.
  const extra = one.verdicts.filter(([, action]) => action === "draft").length - 1;
  expect(drafts.filter((entry) => entry.outcome === "skipped_duplicate")).toHaveLength(Math.max(0, extra));

  // The sign-in check runs exactly when there is a reply to decide.
  const hasDraft = one.verdicts.some(([, action]) => action === "draft");
  expect(run.calls.filter((call) => call.tool === "account_whoami")).toHaveLength(hasDraft ? 1 : 0);
  assertActivityHoldsNoAddress(activityOf(run.storage));
}

describe("level B: each hostile message alone does exactly what its entry says", () => {
  it.each(RESEARCH_CATEGORY_FIXTURES)("%s", async (name) => {
    const one = hostile(name);
    assertAloneOutcome(one, await aloneRun(one));
  });
});

describe("the reply fixtures, one named case each (D-05 as revised, D-30, D-31)", () => {
  it("forged-from: the address rule fires, the message is flagged, and the reply goes to the forged From; the return path reaches nothing", async () => {
    const one = hostile("forged-from");
    const run = await aloneRun(one);
    assertAloneOutcome(one, run);
    expect(run.calls.find((call) => call.tool === "mail_compose_reply")?.args.to).toEqual(["hr@trusted.example"]);
    expect(JSON.stringify(run.calls)).not.toContain("bounce@evil.example");
  });

  it.each(["name-looks-like-address", "name-encoded-word", "name-with-brackets-and-comma"])(
    "%s: the address rule does not fire on the display name; the subject rule replies to the real address only",
    async (name) => {
      const one = hostile(name);
      const run = await aloneRun(one);
      assertAloneOutcome(one, run);
      expect(run.calls.filter((call) => call.tool === "mail_flag")).toEqual([]);
      const reply = run.calls.find((call) => call.tool === "mail_compose_reply");
      expect(reply?.args.to).toEqual([one.row.fromAddress]);
      expect(reply?.args.text).toBe(WORD_RULE_TEXT);
      expect(JSON.stringify(run.calls)).not.toContain("ceo@trusted.example");
      expect(JSON.stringify(run.calls)).not.toContain(one.row.fromName as string);
    },
  );

  it("redirect-header: flagged, and the reply goes to From; the redirect address is in no argument and no activity entry", async () => {
    const one = hostile("redirect-header");
    const run = await aloneRun(one);
    assertAloneOutcome(one, run);
    expect(run.calls.find((call) => call.tool === "mail_compose_reply")?.args).toEqual({
      parentId: one.row.id,
      text: ADDRESS_RULE_TEXT,
      to: ["recruiter@trusted.example"],
    });
    expect(JSON.stringify(run.calls)).not.toContain(COLLECTOR);
    expect(JSON.stringify(activityOf(run.storage))).not.toContain(COLLECTOR);
  });

  it.each(["own-address-exact", "own-address-case", "own-address-sibling"])(
    "%s: no reply call, recorded as own address, and no flag rule matches",
    async (name) => {
      const one = hostile(name);
      const run = await aloneRun(one);
      assertAloneOutcome(one, run);
      expect(run.calls.filter((call) => call.tool === "mail_compose_reply")).toEqual([]);
      expect(activityOf(run.storage).some((entry) => entry.outcome === "skipped_own_address")).toBe(true);
    },
  );

  it.each(["list-id", "list-unsubscribe"])(
    "%s: no reply call, recorded as mailing list, and the flag applies only where a flag rule matches",
    async (name) => {
      const one = hostile(name);
      expect(one.row.mailingList).toBe(true);
      const run = await aloneRun(one);
      assertAloneOutcome(one, run);
      expect(run.calls.filter((call) => call.tool === "mail_compose_reply")).toEqual([]);
      expect(activityOf(run.storage).some((entry) => entry.outcome === "skipped_mailing_list")).toBe(true);
    },
  );

  it.each(["no-address-group", "no-address-name-only", "no-address-empty-angle", "no-address-garbage"])(
    "%s: the address and domain rules do not fire; the subject rule's reply is recorded as no address, with no call",
    async (name) => {
      const one = hostile(name);
      const rows = parsedRows([one.row]);
      // Only the subject rule matches: the address and domain rules see no address.
      expect(evaluate(FIXTURE_RULES, rows)).toEqual([{ rule: RULE_INDEX.word, row: 0, action: "draft" }]);
      const run = await aloneRun(one);
      assertAloneOutcome(one, run);
      expect(run.calls.filter((call) => call.tool === "mail_compose_reply")).toEqual([]);
      expect(activityOf(run.storage).some((entry) => entry.outcome === "skipped_no_address")).toBe(true);
    },
  );

  it("two-from-addresses: one reply, to the one address the row reports, and only that one", async () => {
    const one = hostile("two-from-addresses");
    const run = await aloneRun(one);
    assertAloneOutcome(one, run);
    const replies = run.calls.filter((call) => call.tool === "mail_compose_reply");
    expect(replies).toHaveLength(1);
    expect(replies[0]?.args.to).toEqual(["first@one.example"]);
    expect(JSON.stringify(run.calls)).not.toContain("second@two.example");
  });

  it.each(["threading-line-break", "threading-oversized"])(
    "%s: the job asks for one reply to From with its three arguments; the threading headers never reach it",
    async (name) => {
      const one = hostile(name);
      const run = await aloneRun(one);
      assertAloneOutcome(one, run);
      expect(JSON.stringify(run.calls)).not.toContain("X-Injected");
      expect(JSON.stringify(run.calls)).not.toContain("longref.example>");
    },
  );

  it("across every reply fixture alone, no reply ever goes to the account's own address or a sibling of it", async () => {
    for (const name of REPLY_FIXTURES) {
      const run = await aloneRun(hostile(name));
      for (const call of run.calls.filter((one) => one.tool === "mail_compose_reply")) {
        const to = ((call.args.to as string[])[0] as string).toLowerCase();
        expect(["me@mac.com", "me@icloud.com", "me@me.com"]).not.toContain(to);
      }
    }
  });
});

// ===========================================================================
// Task 2: the wire, the real reply tool, rules_test and the sweep
// ===========================================================================

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/**
 * The named fields of a raw message's header, folds kept, as a server answers
 * a header-fields fetch: the matching lines in message order, then a blank line.
 */
function headerFields(raw: string, names: readonly string[]): string {
  const head = raw.slice(0, raw.indexOf("\r\n\r\n"));
  const fields: string[] = [];
  for (const line of head.split("\r\n")) {
    if (/^[ \t]/.test(line) && fields.length > 0) fields[fields.length - 1] += `\r\n${line}`;
    else fields.push(line);
  }
  const wanted = names.map((name) => name.toLowerCase());
  const kept = fields.filter((field) => wanted.includes(field.slice(0, field.indexOf(":")).trim().toLowerCase()));
  return `${kept.join("\r\n")}\r\n\r\n`;
}

/** One `key {n}\r\n<payload>` item, the count derived from the payload. */
function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

/** The four turns every session opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** Copied from test/read-path-wire.test.ts: the login line, reduced. */
function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    return (tokens[1] ?? "").toUpperCase() === "LOGIN" ? `${tokens[0]} ${tokens[1]} [redacted]` : line;
  });
}

/** Every duplex handed out, in order, and the ones still queued. */
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
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// The forged END marker against the job's fence parser
// ---------------------------------------------------------------------------

describe("forged-end-marker: the job reads only the exact four-line fence", () => {
  /** The real change answer for the forged message alone, and its fenced part. */
  function forgedAnswer(): { result: ToolAnswer; fence: string } {
    const answer = changesAnswerFor([hostile("forged-end-marker").row], true, "fresh-marker-c");
    if (answer.kind !== "ok") throw new Error("the change answer was not built");
    const result = answer.result as ToolAnswer;
    return { result, fence: result.content[1]?.text as string };
  }

  /** The forged subject's own lines: the text, the guessed END line, the fake row, the guessed BEGIN line. */
  const forgedLines = (hostile("forged-end-marker").row.subject as string).split("\n");

  it("the real fence is four lines and reads as the one real row", () => {
    const { fence } = forgedAnswer();
    expect(fence.split("\n")).toHaveLength(4);
    const read = readFencedJson(fence) as { INBOX: { rows: NewMailRow[] } };
    expect(read.INBOX.rows).toEqual([hostile("forged-end-marker").row]);
  });

  it("the same fence with the forged END line or the fake row added as a fifth line is unreadable", () => {
    const { fence } = forgedAnswer();
    const [, guessedEnd, fakeRow, guessedBegin] = forgedLines as [string, string, string, string];
    const lines = fence.split("\n");
    const variants = [
      `${fence}\n${guessedEnd}`,
      `${fence}\n${fakeRow}`,
      `${fence}\n${guessedBegin}`,
      [lines[0], lines[1], lines[2], fakeRow, lines[3]].join("\n"),
      [lines[0], lines[1], fakeRow, lines[2], lines[3]].join("\n"),
    ];
    for (const variant of variants) {
      expect(variant.split("\n")).toHaveLength(5);
      expect(readFencedJson(variant), variant.slice(-60)).toBeNull();
    }
  });

  it("the forged subject spliced in with real line breaks is unreadable, and the job stops with no action", async () => {
    const { result, fence } = forgedAnswer();
    const spliced = fence.replace(/\\n/g, "\n");
    expect(spliced.split("\n").length).toBeGreaterThan(4);
    expect(readFencedJson(spliced)).toBeNull();

    const fiveLines = `${fence}\n${forgedLines[1]}`;
    const tampered: ToolAnswer = { content: [result.content[0] as ToolAnswer["content"][number], { type: "text", text: fiveLines }] };
    expect(readChangesAnswer(tampered).kind).toBe("unreadable");
    const run = await directRun(armedStorage(FIXTURE_RULES as Rule[]), {
      answer: (tool) => (tool === "changes_since" ? { kind: "ok", result: tampered } : selfAnswer(tool)),
    });
    expect(run.outcome).toBe("unreadable");
    expect(run.calls.map((call) => call.tool)).toEqual(["changes_since"]);
  });
});

// ---------------------------------------------------------------------------
// Level C: the real change check on the wire
// ---------------------------------------------------------------------------

/** The header-only fetch item the change check sends, and the only one. */
const NEW_MAIL_FETCH_ITEMS =
  "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM LIST-ID LIST-UNSUBSCRIBE)])";

/** One header-only fetch reply for `fixtures`, their raw headers served verbatim. */
function newMailFetchReply(tag: string, fixtures: readonly HostileMessage[]): Uint8Array {
  const parts: Uint8Array[] = [];
  fixtures.forEach((one, index) => {
    parts.push(
      ENCODER.encode(`* ${index + 1} FETCH (UID ${one.row.uid} FLAGS () INTERNALDATE "${one.row.receivedAt}" `),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM LIST-ID LIST-UNSUBSCRIBE)]",
        headerFields(one.raw, ["Subject", "From", "List-Id", "List-Unsubscribe"]),
      ),
      ENCODER.encode(")\r\n"),
    );
  });
  parts.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...parts);
}

/** Copied from test/changes-tool.test.ts: discovery and an account with no calendars. */
const CALDAV_SERVER = "https://caldav.icloud.com";
const DAV_PRINCIPAL_PATH = "/1234567890/principal/";
const DAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";

function davMultistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/">${body}</multistatus>`,
    { status: 207, headers: { "content-type": "text/xml; charset=utf-8" } },
  );
}

const noCalendars = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const method = String(init?.method ?? "GET").toUpperCase();
  if (url.includes("/.well-known/")) return new Response(null, { status: 404 });
  if (url.startsWith(CALDAV_SERVER)) {
    if (url.endsWith(DAV_PRINCIPAL_PATH)) {
      return davMultistatus(
        `<response><href>${DAV_PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${DAV_HOME}</href></C:calendar-home-set></prop></propstat></response>`,
      );
    }
    return davMultistatus(
      `<response><href>${DAV_PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${DAV_PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`,
    );
  }
  if (method === "PROPFIND" && url === DAV_HOME) {
    return davMultistatus(
      `<response><href>/1234567890/calendars/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>`,
    );
  }
  return new Response(null, { status: 500 });
}) as typeof globalThis.fetch;

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };

/** The change check's registered callback, as the owner. */
function changesCallback(): (args: { marker?: string }) => Promise<ToolAnswer> {
  let callback: ((args: { marker?: string }) => Promise<ToolAnswer>) | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: typeof callback) {
      if (name === CHANGES_TOOL_NAME) callback = handler;
    },
  };
  registerChangesTool(
    server as unknown as McpServer,
    createLeasedMail(createSessionGate()),
    ownerPrincipal(),
    createDavFetch(ownerPrincipal()),
    {},
  );
  expect(callback).toBeDefined();
  return callback as NonNullable<typeof callback>;
}

/**
 * One call of the real change check for fixtures `from` to `to - 1`: the marker
 * says the inbox's next UID was `from`'s, and the status answer says it is now
 * `to`'s. So exactly those fixtures are new, and the fetch serves their headers.
 */
async function changesPage(from: number, to: number): Promise<{ answer: ToolAnswer; read: FakeDuplex; fixtures: HostileMessage[] }> {
  const fixtures = HOSTILE_MAILBOX.filter((one) => one.row.uid >= uidOf(from) && one.row.uid < uidOf(to));
  const content: MarkerContent = {
    folders: [{ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uidNext: uidOf(from), highestModseq: null }],
    calendar: null,
    mintedAt: 1790000000,
  };
  const { userId } = await ownerPrincipal();
  const marker = await sealMarker(content, userId, env.CONFIRM_SECRET);
  const newestFirst = [...fixtures].sort((a, b) => b.row.uid - a.row.uid);
  queued.push(
    () =>
      createFakeDuplex([
        ...authPrefix(),
        statusResponse("a4", "INBOX", INBOX_UIDVALIDITY, uidOf(to), 172, null),
        logoutExchange("a5"),
      ]),
    () =>
      createFakeDuplex([
        ...authPrefix(),
        examineResponse("a4"),
        wire(`* SEARCH ${fixtures.map((one) => one.row.uid).join(" ")}`, "a5 OK SEARCH completed"),
        newMailFetchReply("a6", newestFirst),
        logoutExchange("a7"),
      ]),
  );
  const answer = await changesCallback()({ marker });
  expect(queued).toHaveLength(0);
  return { answer, read: handedOut[handedOut.length - 1] as FakeDuplex, fixtures: newestFirst };
}

/** The whole mailbox through the real tool: two pages, 17 then 25, as its 25-row cap requires. */
async function wholeMailboxOnTheWire() {
  const first = await changesPage(1, 18);
  const second = await changesPage(18, HOSTILE_MAILBOX.length + 1);
  return [first, second];
}

describe("level C: the real change check, serving the fixture's raw headers", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", noCalendars);
  });

  it("fetches headers only, by peeking, and nothing else", async () => {
    const pages = await wholeMailboxOnTheWire();
    expect(pages.map((page) => page.fixtures.length)).toEqual([17, 25]);
    for (const [index, page] of pages.entries()) {
      const [from, to] = index === 0 ? [1, 18] : [18, HOSTILE_MAILBOX.length + 1];
      expect(redacted(page.read.writtenLines())).toEqual([
        "a1 CAPABILITY",
        "a2 LOGIN [redacted]",
        "a3 CAPABILITY",
        'a4 EXAMINE "INBOX"',
        `a5 UID SEARCH UID ${uidOf(from)}:${uidOf(to) - 1}`,
        `a6 UID FETCH ${page.fixtures.map((one) => one.row.uid).join(",")} ${NEW_MAIL_FETCH_ITEMS}`,
        "a7 LOGOUT",
      ]);
    }
    const lines = handedOut.flatMap((duplex) => redacted(duplex.writtenLines()));
    expect(lines.some((line) => line.includes("UID FETCH"))).toBe(true);
    for (const line of lines) {
      expect((line.split(" ")[1] ?? "").toUpperCase(), line).not.toBe("SELECT");
      expect(line).not.toMatch(/BODYSTRUCTURE|RFC822|\bTEXT\b|\bSTORE\b|\bAPPEND\b/i);
      expect(line).not.toMatch(/BODY(?!\.PEEK)\[/i);
      expect(line).not.toMatch(/BODY\.PEEK\[(?!HEADER\.FIELDS \(SUBJECT FROM LIST-ID LIST-UNSUBSCRIBE\)\])/i);
    }
  });

  it("the fenced rows are the fixture's rows exactly, so the fixture has not drifted from the real parser", async () => {
    for (const page of await wholeMailboxOnTheWire()) {
      const fenced = readFencedJson(page.answer.content[1]?.text as string) as { INBOX: { rows: NewMailRow[] } };
      expect(fenced.INBOX.rows).toEqual(page.fixtures.map((one) => one.row));
    }
  });

  it("mailingList is true for exactly the two list fixtures", async () => {
    const rows = (await wholeMailboxOnTheWire()).flatMap(
      (page) => (readFencedJson(page.answer.content[1]?.text as string) as { INBOX: { rows: NewMailRow[] } }).INBOX.rows,
    );
    expect(rows.filter((one) => one.mailingList).map((one) => one.id).sort()).toEqual(
      [hostile("list-id").row.id, hostile("list-unsubscribe").row.id].sort(),
    );
  });

  it("the job's parser reads from the real answer the same rows as level A, and the matcher gives the same verdicts", async () => {
    const pages = await wholeMailboxOnTheWire();
    const read: EnvelopeRow[] = [];
    for (const page of pages) {
      const reading = readChangesAnswer(page.answer);
      expect(reading.kind).toBe("ok");
      if (reading.kind !== "ok") return;
      expect(reading.state).toBe("changes");
      expect(reading.newMessages).toBe(page.fixtures.length);
      expect(reading.dropped).toBe(0);
      read.push(...reading.rows);
    }
    const inFixtureOrder = [...read].sort(
      (a, b) =>
        HOSTILE_MAILBOX.findIndex((one) => one.row.id === a.id) - HOSTILE_MAILBOX.findIndex((one) => one.row.id === b.id),
    );
    expect(inFixtureOrder).toEqual(parsedRows(HOSTILE_ROWS));
    expect(evaluate(FIXTURE_RULES, inFixtureOrder)).toEqual(expectedVerdicts(HOSTILE_MAILBOX));
  });

  it("no sender, subject or list header value reaches the trusted block, and no header the check did not ask for reaches the answer", async () => {
    for (const page of await wholeMailboxOnTheWire()) {
      const trusted = page.answer.content[0]?.text as string;
      expect(trusted).not.toContain("@");
      expect(trusted).not.toContain(COLLECTOR);
      for (const one of page.fixtures) {
        if (one.row.subject !== null && one.row.subject.length > 0) expect(trusted).not.toContain(one.row.subject);
      }
      // The list header values, the redirect header, the return path and the
      // recipients are never fetched, so none of them is anywhere in the answer.
      // (The collector address is in one fixture's SUBJECT, which the answer
      // legitimately fences, so it is checked through the redirect header's
      // own display name instead.)
      const whole = JSON.stringify(page.answer);
      for (const text of ["applications.news.partner.example", "unsubscribe-7731@board.example", "Front Desk", "bounce@evil.example", "crowd.example", "X-ICloud-MCP-Rule"]) {
        expect(whole).not.toContain(text);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Level D: the real reply tool, on the arguments level B recorded
// ---------------------------------------------------------------------------

/**
 * The account the reply tool and rules_test run as: the fixture's own address.
 * Only its address and password reach the principal; the label is the type's
 * and names nobody here.
 */
const SELF_USER: TestUser = {
  label: "A",
  appleId: FIXTURE_SELF,
  appPassword: "ffff-ffff-ffff-ffff",
  userId: "",
};

/** The fields the reply tool asks of its parent, as test/autonomy-draft.test.ts serves them. */
const PARENT_HEADER_NAMES = ["Message-ID", "References", "Reply-To", "From", "To", "Cc"];

function sectionReply(tag: string, uid: number, key: string, payload: string): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${uid} `),
    literalItem(key, payload),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The parent read, in the order the reply tool performs it, serving the fixture's raw message. */
function parentSession(one: HostileMessage): FakeDuplex {
  const raw = one.raw;
  const body = raw.slice(raw.indexOf("\r\n\r\n") + 4);
  const uid = one.row.uid;
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    sectionReply("a5", uid, "BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES REPLY-TO FROM TO CC)]", headerFields(raw, PARENT_HEADER_NAMES)),
    wire(
      `* 1 FETCH (UID ${uid} FLAGS () INTERNALDATE "${one.row.receivedAt}" ` +
        `RFC822.SIZE ${ENCODER.encode(raw).byteLength} ` +
        `BODYSTRUCTURE ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" ${ENCODER.encode(body).byteLength} 2))`,
      "a6 OK UID FETCH completed",
    ),
    sectionReply("a7", uid, "BODY[]", raw),
    logoutExchange("a8"),
  ]);
}

/** The draft write: the folder listing, the go-ahead, the completion. Copied from test/autonomy-draft.test.ts. */
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

/** The reply tool's registered callback, running as the fixture's own account. */
function replyCallback(): (args: Record<string, unknown>) => Promise<ToolAnswer> {
  let callback: ((args: Record<string, unknown>) => Promise<ToolAnswer>) | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: typeof callback) {
      if (name === "mail_compose_reply") callback = handler;
    },
  };
  registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), testPrincipal(SELF_USER));
  expect(callback).toBeDefined();
  return callback as NonNullable<typeof callback>;
}

/** The arguments level B recorded for this fixture's one reply. */
async function recordedReplyArgs(one: HostileMessage): Promise<Record<string, unknown>> {
  const run = await aloneRun(one);
  const replies = run.calls.filter((call) => call.tool === "mail_compose_reply");
  expect(replies).toHaveLength(1);
  return (replies[0] as Recorded).args;
}

/** The message bytes a write session was sent: the literal the APPEND line declared. */
function writtenDraft(duplex: FakeDuplex): string {
  const line = duplex.writtenLines().find((one) => /\bAPPEND\b/.test(one));
  expect(line, "no draft write in this session").toBeDefined();
  const count = Number(/\{(\d+)\}$/.exec(line as string)?.[1]);
  const chunk = duplex.writes.find((one) => one.byteLength === count);
  expect(chunk, "the declared literal was never written").toBeDefined();
  return DECODER.decode(chunk);
}

/** A message's header block as written (folds kept), and its unfolded header lines. */
function headerOf(message: string): { physical: string[]; lines: string[] } {
  const head = message.slice(0, message.indexOf("\r\n\r\n"));
  return { physical: head.split("\r\n"), lines: head.replace(/\r\n[ \t]+/g, " ").split("\r\n") };
}

function headerNamed(lines: readonly string[], name: string): string[] {
  const prefix = `${name.toLowerCase()}:`;
  return lines.filter((line) => line.toLowerCase().startsWith(prefix));
}

function nameOf(line: string): string {
  return line.slice(0, line.indexOf(":")).toLowerCase();
}

interface ReplyOnTheWire {
  readonly result: ToolAnswer;
  readonly trusted: Record<string, unknown>;
  readonly draft: string | null;
  readonly lines: string[];
}

/** Run the real reply tool over the fake duplex with level B's arguments for `one`. */
async function replyOnTheWire(one: HostileMessage): Promise<ReplyOnTheWire> {
  const args = await recordedReplyArgs(one);
  queued.push(
    () => parentSession(one),
    () => writeSession(),
  );
  const result = await replyCallback()(args);
  const trusted = JSON.parse(result.content[0]?.text as string) as Record<string, unknown>;
  const lines = handedOut.flatMap((duplex) => duplex.writtenLines());
  const writer = handedOut.find((duplex) => duplex.writtenLines().some((line) => /\bAPPEND\b/.test(line)));
  return { result, trusted, draft: writer === undefined ? null : writtenDraft(writer), lines };
}

/** The header names the builder writes on an ordinary reply, from one ordinary draft. */
async function builderHeaderNames(): Promise<Set<string>> {
  const ordinary = await replyOnTheWire(hostile("forged-from"));
  handedOut.length = 0;
  return new Set(headerOf(ordinary.draft as string).lines.map(nameOf));
}

describe("level D: the real reply tool, given exactly what level B recorded", () => {
  const DRAFTED: readonly [string, readonly string[]][] = [
    ["forged-from", ["bounce@evil.example", "mx.evil.example"]],
    ["name-looks-like-address", ["ceo@trusted.example"]],
    ["name-encoded-word", ["ceo@trusted.example"]],
    ["name-with-brackets-and-comma", ["ceo@trusted.example", "CEO <"]],
    ["redirect-header", [COLLECTOR, "Front Desk"]],
    ["two-from-addresses", ["second@two.example"]],
  ];

  it.each(DRAFTED)(
    "%s: the draft's To holds the From address alone, with no display name, no Cc and no Bcc",
    async (name, absent) => {
      const one = hostile(name);
      const wire = await replyOnTheWire(one);
      expect(wire.result.isError).not.toBe(true);
      expect(wire.trusted.appended).toBe(true);
      expect(handedOut).toHaveLength(2);
      const { lines } = headerOf(wire.draft as string);
      expect(headerNamed(lines, "To")).toEqual([`To: ${one.row.fromAddress}`]);
      expect(headerNamed(lines, "Cc")).toEqual([]);
      expect(headerNamed(lines, "Bcc")).toEqual([]);
      for (const line of lines) {
        for (const text of absent) expect(line, line).not.toContain(text);
        if (one.row.fromName !== null && one.row.fromName !== "") expect(line, line).not.toContain(one.row.fromName);
      }
      // One APPEND, into Drafts, and nothing else written anywhere.
      const appends = wire.lines.filter((line) => /\bAPPEND\b/.test(line));
      expect(appends).toHaveLength(1);
      expect(appends[0]).toContain('"Drafts"');
      for (const line of wire.lines) expect(line).not.toMatch(/\b(STORE|COPY|MOVE|EXPUNGE)\b/);
    },
  );

  it("threading-line-break: the tool refuses the build, or writes no header line the builder did not write", async () => {
    const builder = await builderHeaderNames();
    const wire = await replyOnTheWire(hostile("threading-line-break"));
    if (wire.trusted.appended === false) {
      expect(wire.trusted.refusal).toEqual(expect.any(String));
      expect(wire.draft).toBeNull();
      expect(wire.lines.some((line) => /\bAPPEND\b/.test(line))).toBe(false);
    } else {
      const { lines } = headerOf(wire.draft as string);
      for (const line of lines) expect(builder.has(nameOf(line)), line).toBe(true);
      expect(headerNamed(lines, "Bcc")).toEqual([]);
      expect(headerNamed(lines, "X-Injected")).toEqual([]);
    }
    // Never a second header, on any path: nothing written carries the injected fields.
    for (const chunk of handedOut.flatMap((duplex) => duplex.writes)) {
      const text = DECODER.decode(chunk);
      expect(text).not.toMatch(/^Bcc:/im);
      expect(text).not.toMatch(/^X-Injected:/im);
    }
  });

  it("threading-line-break: a refused reply is recorded as refused and never tried again", async () => {
    const one = hostile("threading-line-break");
    const wire = await replyOnTheWire(one);
    expect(wire.trusted.appended).toBe(false);
    const real: CallAnswer = { kind: "ok", result: wire.result };
    const storage = armedStorage(FIXTURE_RULES as Rule[]);
    const answer = (tool: string) => (tool === "mail_compose_reply" ? real : selfAnswer(tool));
    const first = await directRun(storage, { rows: [one.row], answer });
    expect(first.calls.filter((call) => call.tool === "mail_compose_reply")).toHaveLength(1);
    expect(activityOf(storage).filter((entry) => entry.kind === "draft").map((entry) => entry.outcome)).toEqual(["refused"]);
    const second = await directRun(storage, { rows: [one.row], answer });
    expect(second.calls.filter((call) => call.tool === "mail_compose_reply")).toEqual([]);
  });

  it("threading-oversized: the reply is refused or its chain folded; no line is over the builder's limit, and the call completes", async () => {
    const builder = await builderHeaderNames();
    const wire = await replyOnTheWire(hostile("threading-oversized"));
    if (wire.trusted.appended === false) {
      expect(wire.trusted.refusal).toEqual(expect.any(String));
      expect(wire.draft).toBeNull();
    } else {
      const { physical, lines } = headerOf(wire.draft as string);
      for (const line of physical) expect(ENCODER.encode(line).byteLength).toBeLessThanOrEqual(998);
      for (const line of lines) expect(builder.has(nameOf(line)), line.slice(0, 40)).toBe(true);
      expect(headerNamed(lines, "References")).toHaveLength(1);
      expect(headerNamed(lines, "To")).toEqual(["To: longref@evil.example"]);
    }
  });
});

// ---------------------------------------------------------------------------
// rules_test over the fixture mailbox
// ---------------------------------------------------------------------------

/** The newest 25 fixture messages, newest first: the page the listing reads. */
const LISTING_PAGE = [...HOSTILE_MAILBOX].sort((a, b) => b.row.uid - a.row.uid).slice(0, 25);

/** The whole listing conversation on a fake duplex, serving the fixture's raw headers. */
function listingDuplex(): FakeDuplex {
  const metadata: Uint8Array[] = [];
  const snippets: Uint8Array[] = [];
  LISTING_PAGE.forEach((one, i) => {
    metadata.push(
      ENCODER.encode(
        `* ${i + 1} FETCH (UID ${one.row.uid} FLAGS () INTERNALDATE "${one.row.receivedAt}" ` +
          `RFC822.SIZE ${ENCODER.encode(one.raw).byteLength} BODYSTRUCTURE ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1) `,
      ),
      literalItem("BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]", headerFields(one.raw, ["Subject", "From", "Date", "Message-ID"])),
      ENCODER.encode(")\r\n"),
    );
    snippets.push(ENCODER.encode(`* ${i + 1} FETCH (UID ${one.row.uid} `), literalItem("BODY[1]<0>", "Preview."), ENCODER.encode(")\r\n"));
  });
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    wire(`* SEARCH ${HOSTILE_MAILBOX.map((one) => one.row.uid).join(" ")}`, "a5 OK SEARCH completed"),
    concatBytes(...metadata, ENCODER.encode("a6 OK UID FETCH completed\r\n")),
    concatBytes(...snippets, ENCODER.encode("a7 OK UID FETCH completed\r\n")),
    logoutExchange("a8"),
  ]);
}

/** Everything the listing sends: the read-only open and the peeking fetches, nothing else. */
const LISTING_GOLDEN = [
  "a1 CAPABILITY",
  "a2 LOGIN [redacted]",
  "a3 CAPABILITY",
  'a4 EXAMINE "INBOX"',
  "a5 UID SEARCH ALL",
  `a6 UID FETCH ${LISTING_PAGE.map((one) => one.row.uid).join(",")} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])`,
  `a7 UID FETCH ${LISTING_PAGE.map((one) => one.row.uid).join(",")} (BODY.PEEK[1]<0.1024>)`,
  "a8 LOGOUT",
];

/** rules_test's registered callback, as the fixture's own account. */
function rulesTestCallback(): (args: Record<string, unknown>) => Promise<RecordedToolResult> {
  let callback: ((args: Record<string, unknown>) => Promise<RecordedToolResult>) | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: typeof callback) {
      if (name === "rules_test") callback = handler;
    },
  };
  registerRulesTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), testPrincipal(SELF_USER), {});
  expect(callback).toBeDefined();
  return callback as NonNullable<typeof callback>;
}

describe("rules_test over the fixture mailbox reports level A's verdicts and writes nothing", () => {
  const selfStub = async (): Promise<Stub> =>
    env.USER_AGENT.getByName((await userIdOf(FIXTURE_SELF)) as string) as unknown as Stub;

  afterEach(async () => {
    await runInDurableObject(await selfStub(), async (_i, state) => {
      await state.storage.deleteAlarm();
      await state.storage.deleteAll();
    });
  });

  it.each(Object.keys(RULE_INDEX) as RuleName[])("the %s rule, as a candidate", async (ruleName) => {
    const stored = FIXTURE_RULES[RULE_INDEX[ruleName]] as Rule;
    const candidate: RuleBody = { when: stored.when, then: stored.then };
    const before = await (await selfStub()).rulesView();
    queued.push(() => listingDuplex());

    const result = await rulesTestCallback()({ rule: candidate });
    const parsed = readToolResult(result);

    expect(parsed.isError).toBe(false);
    expect(parsed.trusted?.messagesChecked).toBe(25);
    // Level A's verdicts for this rule, over the page. The listing does not say
    // whether mail came from a list, so rules_test does not skip list mail and
    // offers its From address, as its own fixed sentence says.
    const expected = LISTING_PAGE.flatMap((one) => {
      const actions = one.verdicts.filter(([rule]) => rule === ruleName).map(([, action]) => action);
      if (actions.length === 0) return [];
      const wouldDraft = actions.includes("draft");
      const skip = one.expected.skip === "mailing-list" ? null : one.expected.skip;
      return [{ messageId: one.row.id, wouldFlag: actions.includes("flag"), wouldDraft, draftSkip: wouldDraft ? skip : null }];
    });
    expect(parsed.trusted?.results).toEqual(expected);
    const fenced = parsed.untrusted?.results as Array<Record<string, unknown>>;
    expect(fenced.map((row) => row.messageId)).toEqual(expected.map((row) => row.messageId));
    for (const [index, row] of expected.entries()) {
      const one = HOSTILE_MAILBOX.find((m) => m.row.id === row.messageId) as HostileMessage;
      const replyTo = row.wouldDraft && row.draftSkip === null ? one.row.fromAddress : null;
      expect(fenced[index]?.replyTo, one.name).toBe(replyTo);
    }

    // Never a display name in any result, trusted or fenced. (The answer also
    // echoes the candidate rule, whose own values may coincide with a display
    // name used as bait, so the results are what is checked.)
    const results = JSON.stringify([parsed.trusted?.results, parsed.untrusted?.results]);
    for (const one of LISTING_PAGE) {
      if (one.row.fromName !== null && one.row.fromName !== "") expect(results, one.name).not.toContain(one.row.fromName);
    }
    expect(results).not.toContain(COLLECTOR);
    expect(results).not.toContain("ceo@trusted.example");

    // The read-only open and the peeking fetches, and nothing else.
    expect(handedOut).toHaveLength(1);
    const lines = redacted((handedOut[0] as FakeDuplex).writtenLines());
    expect(lines).toEqual(LISTING_GOLDEN);
    for (const line of lines) {
      expect(line).not.toMatch(/\b(SELECT|STORE|APPEND|EXPUNGE|COPY|MOVE)\b/);
      expect(line).not.toMatch(/BODY\[|BODY\.PEEK\[\]|RFC822(?!\.SIZE)/);
    }
    // Nothing was written to the object.
    expect(await (await selfStub()).rulesView()).toEqual(before);
  });
});

// ---------------------------------------------------------------------------
// The seeded sweep
// ---------------------------------------------------------------------------

/** The sweep's seed and size. Both are recorded in the SUMMARY. */
const SWEEP_SEED = 0x28052026;
const SWEEP_RULE_SETS = 500;

/** mulberry32: a small seeded generator, so a failure replays exactly. */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The reference matcher and reply rule, written here from D-03 and D-30's text
// and NOT by calling `evaluate` or `replyRecipient`.

const REF_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A fixture receipt time (`28-Sep-2026 09:11:00 +0000`) in milliseconds. */
function refReceivedAt(value: string | null): number | null {
  const m = /^(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) \+0000$/.exec(value ?? "");
  if (m === null) return null;
  return Date.UTC(Number(m[3]), REF_MONTHS.indexOf(m[2] as string), Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
}

function refNorm(text: string): string {
  return text.normalize("NFKC").toLowerCase();
}

/** D-03: every kind the rule has must match; any value within a kind. */
function refMatches(rule: Rule, row: NewMailRow): boolean {
  const at = refReceivedAt(row.receivedAt);
  if (at === null || at < rule.createdAt) return false;
  const address = row.fromAddress;
  const { fromAddresses, fromDomains, subjectContains } = rule.when;
  if (fromAddresses !== undefined) {
    if (address === null || !fromAddresses.some((one) => one.toLowerCase() === address.toLowerCase())) return false;
  }
  if (fromDomains !== undefined) {
    if (address === null || !address.includes("@")) return false;
    const domain = address.slice(address.lastIndexOf("@") + 1).toLowerCase();
    if (domain === "" || !fromDomains.some((one) => domain === one || domain.endsWith(`.${one}`))) return false;
  }
  if (subjectContains !== undefined) {
    if (row.subject === null || !subjectContains.some((one) => refNorm(row.subject as string).includes(refNorm(one)))) return false;
  }
  return fromAddresses !== undefined || fromDomains !== undefined || subjectContains !== undefined;
}

function refVerdicts(rules: readonly Rule[], rows: readonly NewMailRow[]): Verdict[] {
  const out: Verdict[] = [];
  rows.forEach((row, r) =>
    rules.forEach((rule, i) => {
      if (!refMatches(rule, row)) return;
      if (rule.then.flag === true) out.push({ rule: i, row: r, action: "flag" });
      if (rule.then.draft !== undefined) out.push({ rule: i, row: r, action: "draft" });
    }),
  );
  return out;
}

/** One plain address: a local part, one @, and a domain of two or more letter-digit-hyphen labels. */
const REF_BARE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

/** D-30: a list, then no usable address, then the account's own (Apple siblings included). */
function refReply(row: NewMailRow, self: string): { to: string } | { skip: ReplySkipName } {
  if (row.mailingList) return { skip: "mailing-list" };
  const from = row.fromAddress;
  if (from === null || !REF_BARE.test(from) || from.startsWith(".") || from.split("@")[0]?.endsWith(".") || from.includes("..")) {
    return { skip: "no-address" };
  }
  const [fl, fd] = from.toLowerCase().split("@") as [string, string];
  const [sl, sd] = self.toLowerCase().split("@") as [string, string];
  const apple = ["icloud.com", "me.com", "mac.com"];
  if (fl === sl && (fd === sd || (apple.includes(fd) && apple.includes(sd)))) return { skip: "own-address" };
  return { to: from };
}
type ReplySkipName = "no-address" | "own-address" | "mailing-list";

/** Pools drawn from the fixture's own senders, domains and subject words. */
const POOL_ADDRESSES = [
  ...new Set([
    ...HOSTILE_MAILBOX.map((one) => one.row.fromAddress).filter((a): a is string => a !== null && REF_BARE.test(a)),
    ...TRUSTED_ADDRESSES,
  ]),
];
const POOL_DOMAINS = [
  ...new Set(
    POOL_ADDRESSES.flatMap((address) => {
      const labels = address.slice(address.lastIndexOf("@") + 1).toLowerCase().split(".");
      return labels.slice(0, -1).map((_, i) => labels.slice(i).join("."));
    }),
  ),
];
const POOL_WORDS = [
  ...new Set(
    HOSTILE_MAILBOX.flatMap((one) => (one.row.subject ?? "").split(/\s+/))
      .filter((word) => word.length >= 1 && word.length <= 100 && !/[\u0000-\u001f\u007f]/.test(word)),
  ),
];
const RANDOM_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789 .-_@:";

interface SweepGen {
  readonly next: () => number;
}

function pick<T>(gen: SweepGen, list: readonly T[]): T {
  return list[Math.floor(gen.next() * list.length)] as T;
}

function randomText(gen: SweepGen, min: number, max: number): string {
  const length = min + Math.floor(gen.next() * (max - min + 1));
  let out = "";
  for (let i = 0; i < length; i += 1) out += pick(gen, [...RANDOM_ALPHABET]);
  return out;
}

function values(gen: SweepGen, pool: readonly string[], random: () => string): string[] {
  const count = 1 + Math.floor(gen.next() * 3);
  return Array.from({ length: count }, () => (gen.next() < 0.7 ? pick(gen, pool) : random()));
}

/** One valid rule, parsed by the real parser so it is one a person could add. */
function generatedRule(gen: SweepGen, index: number): Rule {
  for (;;) {
    const when: Record<string, string[]> = {};
    const kinds = Math.floor(gen.next() * 7) + 1; // a non-empty subset of the three kinds
    if (kinds & 1) when.fromAddresses = values(gen, POOL_ADDRESSES, () => `${randomText(gen, 1, 8).replace(/[^a-z0-9]/g, "x")}@evil.example`);
    if (kinds & 2) when.fromDomains = values(gen, POOL_DOMAINS, () => `${randomText(gen, 1, 8).replace(/[^a-z0-9]/g, "x")}.example`);
    if (kinds & 4) when.subjectContains = values(gen, POOL_WORDS, () => randomText(gen, 1, 12));
    const which = Math.floor(gen.next() * 3);
    const then: Record<string, unknown> = {};
    if (which !== 1) then.flag = true;
    if (which !== 0) then.draft = { text: `sweep ${index}: ${randomText(gen, 1, 40)}` };
    const parsed = parseRule({ when, then });
    if (!parsed.ok) continue;
    const window = Date.UTC(2026, 8, 28, 9, 10, 0) + Math.floor(gen.next() * 44) * 60_000;
    const createdAt = gen.next() < 0.75 ? RULES_ADDED_AT_FOR_SWEEP : window;
    return { v: 1, id: `sweep-${index}`, createdAt, ...parsed.rule };
  }
}
const RULES_ADDED_AT_FOR_SWEEP = FIXTURE_RULES[0]?.createdAt as number;

describe("the seeded sweep: generated rule sets over every hostile row", () => {
  it(`seed ${SWEEP_SEED.toString(16)}, ${SWEEP_RULE_SETS} rule sets: every action is one the rules alone justify, and every reply goes to that row's From address`, async () => {
    const gen: SweepGen = { next: seeded(SWEEP_SEED) };
    const envelope = parsedRows(HOSTILE_ROWS);
    const byId = new Map(HOSTILE_ROWS.map((one) => [one.id, one]));
    let flagsSeen = 0;
    let repliesSeen = 0;
    let skipsSeen = 0;

    for (let set = 0; set < SWEEP_RULE_SETS; set += 1) {
      const count = 1 + Math.floor(gen.next() * 5);
      const rules = Array.from({ length: count }, (_, i) => generatedRule(gen, set * 10 + i));

      // The reference matcher and the real matcher disagree on nothing.
      const reference = refVerdicts(rules, HOSTILE_ROWS);
      expect(evaluate(rules, envelope), `set ${set}`).toEqual(reference);

      const storage = armedStorage(rules);
      const run = await directRun(storage, { rows: HOSTILE_ROWS, answer: selfAnswer });
      expect(run.outcome, `set ${set}`).toBe("done");
      const texts = rules.flatMap((rule) => (rule.then.draft === undefined ? [] : [rule.then.draft.text]));
      assertCallShapes(run.calls, HOSTILE_ROWS, texts);

      const flagJustified = new Set(
        reference.filter((v) => v.action === "flag").map((v) => (HOSTILE_ROWS[v.row] as NewMailRow).id),
      );
      const flags = run.calls.filter((call) => call.tool === "mail_flag");
      const replies = run.calls.filter((call) => call.tool === "mail_compose_reply");
      expect(flags.length).toBeLessThanOrEqual(MAX_FLAGS_PER_RUN);
      expect(replies.length).toBeLessThanOrEqual(MAX_DRAFTS_PER_RUN);
      for (const call of flags) expect(flagJustified.has(call.args.id as string), `set ${set}`).toBe(true);
      for (const call of replies) {
        const row = byId.get(call.args.parentId as string) as NewMailRow;
        const matching = reference
          .filter((v) => v.action === "draft" && (HOSTILE_ROWS[v.row] as NewMailRow).id === row.id)
          .map((v) => (rules[v.rule] as Rule).then.draft?.text);
        expect(matching, `set ${set}: a reply no rule justifies`).toContain(call.args.text);
        const decided = refReply(row, FIXTURE_SELF);
        expect(decided, `set ${set}: a reply to a row that gets none`).toEqual({ to: row.fromAddress });
        expect(call.args.to).toEqual([row.fromAddress]);
      }
      expect(new Set(replies.map((call) => call.args.parentId)).size).toBe(replies.length);
      skipsSeen += activityOf(storage).filter((entry) =>
        ["skipped_own_address", "skipped_mailing_list", "skipped_no_address"].includes(entry.outcome),
      ).length;
      flagsSeen += flags.length;
      repliesSeen += replies.length;
    }
    // Non-vacuity: the sweep actually flagged, replied, and reached the reply skips.
    expect(flagsSeen).toBeGreaterThan(SWEEP_RULE_SETS);
    expect(repliesSeen).toBeGreaterThan(SWEEP_RULE_SETS / 2);
    expect(skipsSeen).toBeGreaterThan(0);
  }, 120_000);
});
