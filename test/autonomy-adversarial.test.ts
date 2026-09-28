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
// Levels C and D, the rules_test case and the sweep follow below.
//
// If a case here fails, the defect is in src/agent/ and is fixed there. No
// assertion in this file may be loosened to make a hostile case pass.
//
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { ACTIVITY_KEY, type ActivityEntry } from "../src/agent/activity";
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
  WORD_RULE_TEXT,
  hostile,
  idOf,
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
