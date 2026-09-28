// The rules tools (Phase 28, plan 28-04): list, add, commit, remove, test.
//
// Every tool is called through its registered callback, with a real principal
// from the real props constructor and the person's real object. The socket
// module is mocked for this file only, so a tool that opened an iCloud mail
// connection would reach the mock, and the cases that must open none assert
// the mock was never called. Nothing here signs in to a real Apple ID.
//
// The object outlives a test case, so every case starts by clearing both test
// users' objects.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { ACTIVITY_KEY } from "../src/agent/activity";
import { AUTONOMY_KEY } from "../src/agent/autonomy";
import {
  JOB_AUTH_FAILURES_KEY,
  JOB_LAST_RUN_KEY,
  JOB_NEXT_AT_KEY,
  JOB_STATE_KEY,
  RULES_KEY,
  runAutonomyJob,
} from "../src/agent/job";
import type { JobDeps } from "../src/agent/job";
import { createLeasedMail } from "../src/agent/lease";
import type { Rule } from "../src/agent/rules";
import type { CallAnswer } from "../src/agent/tool-call";
import type { UserAgent } from "../src/agent/user-agent";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  ConfirmationInvalidError,
  mintConfirmation,
  verifyConfirmation,
} from "../src/confirm";
import type { ConfirmPayload } from "../src/confirm";
import type { DavFetch } from "../src/dav/transport";
import type { MailSessionOptions, NewMailRow } from "../src/mail/service";
import { createSessionGate } from "../src/mail/service";
import { encodeMessageId } from "../src/mail/ids";
import { connectImap } from "../src/mail/socket";
import { signedInAsResult } from "../src/mcp/tools/account";
import { type ChangesAnswer, changesResult } from "../src/mcp/tools/changes";
import { registerContactsWriteTools } from "../src/mcp/tools/contacts-write";
import { composeToolResult, flagStateToolResult } from "../src/mcp/tools/mail";
import { registerRulesTools } from "../src/mcp/tools/rules";
import type { Principal } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import {
  type RecordedToolResult,
  type TestUser,
  USER_A,
  USER_B,
  readToolResult,
  testPrincipal,
} from "./fixtures/two-users";

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

type Callback = (args: Record<string, unknown>) => Promise<RecordedToolResult>;

interface Registered {
  readonly options: { description?: unknown; inputSchema?: unknown };
  readonly callback: Callback;
}

/** The five names, as D-10 fixed them. */
const RULES_TOOLS = ["rules_list", "rules_add", "rules_commit", "rules_remove", "rules_test"];

/** Every tool the rules registrar registers, for `user`. */
function registered(user: TestUser, options: MailSessionOptions = {}): Map<string, Registered> {
  const tools = new Map<string, Registered>();
  const server = {
    registerTool(name: string, toolOptions: Registered["options"], callback: Callback) {
      tools.set(name, { options: toolOptions, callback });
    },
  };
  const principal = testPrincipal(user);
  principal.catch(() => {});
  registerRulesTools(
    server as unknown as McpServer,
    createLeasedMail(createSessionGate()),
    principal,
    options,
  );
  return tools;
}

/** Call one rules tool as `user`. */
async function call(
  user: TestUser,
  name: string,
  args: Record<string, unknown> = {},
  options: MailSessionOptions = {},
): Promise<RecordedToolResult> {
  const tool = registered(user, options).get(name);
  expect(tool, `${name} is not registered`).toBeDefined();
  return tool!.callback(args);
}

/** Every text block of a result, joined. */
function textOf(result: RecordedToolResult): string {
  return result.content.map((block) => block.text).join("\n");
}

type Stub = DurableObjectStub<UserAgent>;

function stubFor(user: TestUser): Stub {
  return env.USER_AGENT.getByName(user.userId) as unknown as Stub;
}

/** Clear one person's object. */
async function clear(user: TestUser): Promise<void> {
  await runInDurableObject(stubFor(user), async (_instance, state) => {
    await state.storage.deleteAlarm();
    await state.storage.deleteAll();
  });
}

/** Put one value into a person's object's key-value storage. */
async function seed(user: TestUser, key: string, value: unknown): Promise<void> {
  await runInDurableObject(stubFor(user), (_instance, state) => {
    state.storage.kv.put(key, value);
  });
}

/** The rules stored in a person's object. */
async function storedRules(user: TestUser): Promise<Rule[]> {
  return (await stubFor(user).rulesView()).rules as Rule[];
}

const SECRET = (): string | undefined => entryEnv().CONFIRM_SECRET;

// ---------------------------------------------------------------------------
// The rules used below
// ---------------------------------------------------------------------------

/** A flag rule with all three condition kinds, written with mixed case. */
const FLAG_RULE = {
  when: {
    fromAddresses: ["Recruiter@Example.com"],
    fromDomains: ["Jobs.Example.org"],
    subjectContains: ["Interview"],
  },
  then: { flag: true },
};

/** `FLAG_RULE` as the parser normalises it. */
const FLAG_RULE_NORMALISED = {
  when: {
    fromAddresses: ["recruiter@example.com"],
    fromDomains: ["jobs.example.org"],
    subjectContains: ["interview"],
  },
  then: { flag: true },
};

/** The flag rule's preview sentence, whole. */
const FLAG_RULE_LINE =
  "Adding a rule that runs on its own every 15 minutes, with nobody present, for as long as you stay signed in. " +
  "It matches new inbox mail that meets all of these: sent from 'recruiter@example.com'; " +
  "sent from an address at 'jobs.example.org', or at any subdomain of it; with 'interview' in the subject. " +
  "Mail that arrived before the rule was added never matches it. " +
  "For each match it flags the message. " +
  "Removing the rule with rules_remove stops it at once.";

/** The draft's own words. Never in a sentence and never in a trusted block. */
const DRAFT_TEXT = "Thank you for writing. I will reply properly within a day.";

/** A draft rule with one sender address. */
const DRAFT_RULE = {
  when: { fromAddresses: ["hr@example.com"] },
  then: { flag: true, draft: { text: DRAFT_TEXT } },
};

/** The fixed words a draft rule's sentence must carry (D-11 as revised again). */
const DRAFT_FRAGMENTS = [
  "places a draft reply to that message's sender",
  "in the rule's own words",
  'with the subject "Re: " and the original subject',
  "Each reply goes only to the address in the matching message's From line.",
  "That address comes from the message, and a sender can fake it, so a reply may be addressed to someone who did not write the message.",
  "No reply goes to your own address, to mailing-list mail, or when the From line has no usable address.",
  "Nothing is sent",
];

/** Preview a rule as `user`, and answer its token, its rule and its line. */
async function preview(
  user: TestUser,
  rule: unknown,
): Promise<{ token: string; rule: unknown; line: string }> {
  const parsed = readToolResult(await call(user, "rules_add", { rule }));
  expect(parsed.isError).toBe(false);
  const token = parsed.trusted?.confirmToken;
  expect(typeof token).toBe("string");
  return {
    token: token as string,
    rule: parsed.untrusted?.rule,
    line: parsed.untrusted?.confirmationLine as string,
  };
}

/** Preview, then commit, as `user`. Answers the stored rule's id. */
async function addRule(user: TestUser, rule: unknown): Promise<string> {
  const shown = await preview(user, rule);
  const parsed = readToolResult(
    await call(user, "rules_commit", { confirmToken: shown.token, rule: shown.rule }),
  );
  expect(parsed.isError).toBe(false);
  expect(parsed.trusted?.added).toBe(true);
  return parsed.trusted?.ruleId as string;
}

/** A stored rule value, as the object writes one. */
function storedRule(i: number): Rule {
  return {
    v: 1,
    id: `seeded-${i}`,
    createdAt: 1,
    when: { fromAddresses: [`s${i}@example.com`] },
    then: { flag: true },
  };
}

beforeEach(async () => {
  vi.mocked(connectImap).mockReset();
  await clear(USER_A);
  await clear(USER_B);
});

afterEach(() => {
  vi.mocked(connectImap).mockReset();
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe("the five rules tools", () => {
  it("are registered under D-10's names, and nothing else", () => {
    expect([...registered(USER_A).keys()].sort()).toEqual([...RULES_TOOLS].sort());
  });

  it("each description says these are this server's rules, not iCloud Mail's, within the ceiling", () => {
    for (const [name, tool] of registered(USER_A)) {
      const description = String(tool.options.description);
      expect(description, name).toMatch(/^This server's own autonomy rules, not iCloud Mail's rules\./);
      expect(description.length, name).toBeLessThan(280);
    }
  });

  it("no input schema has a key naming a user, an object, a time or a cadence", () => {
    const banned = /user|object|agent|owner|account|principal|time|date|cadence|interval|schedule|minute|hour|delay|wake|expir/i;
    for (const [name, tool] of registered(USER_A)) {
      const keys: string[] = [];
      const walk = (node: unknown): void => {
        if (typeof node !== "object" || node === null) return;
        const record = node as Record<string, unknown>;
        if (typeof record.properties === "object" && record.properties !== null) {
          for (const [key, child] of Object.entries(record.properties)) {
            keys.push(key);
            walk(child);
          }
        }
        for (const child of Object.values(record)) walk(child);
      };
      walk(z.toJSONSchema(tool.options.inputSchema as z.ZodType));
      expect(keys.filter((key) => banned.test(key)), name).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// rules_add
// ---------------------------------------------------------------------------

describe("rules_add previews and writes nothing", () => {
  it("a flag rule: the normalised rule, the whole sentence, a confirmation, and nothing stored", async () => {
    const parsed = readToolResult(await call(USER_A, "rules_add", { rule: FLAG_RULE }));

    expect(parsed.isError).toBe(false);
    expect(typeof parsed.trusted?.confirmToken).toBe("string");
    expect(parsed.untrusted?.rule).toEqual(FLAG_RULE_NORMALISED);
    expect(parsed.untrusted?.confirmationLine).toBe(FLAG_RULE_LINE);
    expect(await storedRules(USER_A)).toEqual([]);
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("a draft rule: the sentence says who the reply goes to, that From can be faked, what gets none, and that nothing is sent", async () => {
    const shown = await preview(USER_A, DRAFT_RULE);

    for (const fragment of DRAFT_FRAGMENTS) expect(shown.line).toContain(fragment);
    expect(shown.line).toContain("'hr@example.com'");
    expect(shown.line).toContain("flags the message and places a draft reply");
    expect(shown.line).toContain(
      "runs on its own every 15 minutes, with nobody present, for as long as you stay signed in",
    );
    expect(await storedRules(USER_A)).toEqual([]);
  });

  it("a draft rule: its words are in the fenced block, never in the sentence or the trusted block", async () => {
    const result = await call(USER_A, "rules_add", { rule: DRAFT_RULE });
    const parsed = readToolResult(result);

    expect((parsed.untrusted?.rule as typeof DRAFT_RULE).then.draft.text).toBe(DRAFT_TEXT);
    expect(parsed.untrusted?.confirmationLine).not.toContain(DRAFT_TEXT);
    expect(result.content[0]!.text).not.toContain(DRAFT_TEXT);
    expect(result.content[0]!.text).not.toContain("hr@example.com");
  });

  for (const key of ["to", "subject", "cc", "bcc", "html"]) {
    it(`a draft carrying ${key} is refused: a rule's draft is always a reply to the sender and takes only text`, async () => {
      const rule = {
        when: { fromAddresses: ["hr@example.com"] },
        then: { draft: { text: DRAFT_TEXT, [key]: key === "html" ? "<p>x</p>" : ["x@example.com"] } },
      };
      const result = await call(USER_A, "rules_add", { rule });
      const parsed = readToolResult(result);

      expect(parsed.isError).toBe(false);
      expect(parsed.trusted?.refused).toBe(true);
      expect(parsed.trusted?.reason).toContain("always a reply to the sender of the matching message");
      expect(parsed.trusted?.reason).toContain("takes only text");
      expect(textOf(result)).not.toContain("confirmToken");
      expect(await storedRules(USER_A)).toEqual([]);
    });
  }

  it("the registered schema keeps a draft's extra keys, so the refusal is reached through the real input path", () => {
    const schema = registered(USER_A).get("rules_add")!.options.inputSchema as z.ZodType;
    const args = schema.parse({
      rule: { when: { fromAddresses: ["hr@example.com"] }, then: { draft: { text: "x", to: ["y@example.com"] } } },
    }) as { rule: { then: { draft: Record<string, unknown> } } };

    expect(args.rule.then.draft.to).toEqual(["y@example.com"]);
  });

  it("an invalid rule is refused on the success arm, naming the limit, with no confirmation", async () => {
    const addresses = Array.from({ length: 11 }, (_, i) => `a${i}@example.com`);
    const result = await call(USER_A, "rules_add", {
      rule: { when: { fromAddresses: addresses }, then: { flag: true } },
    });
    const parsed = readToolResult(result);

    expect(parsed.isError).toBe(false);
    expect(parsed.trusted?.refused).toBe(true);
    expect(parsed.trusted?.reason).toBe("Each condition holds between 1 and 10 values.");
    expect(textOf(result)).not.toContain("confirmToken");
  });
});

// ---------------------------------------------------------------------------
// rules_commit
// ---------------------------------------------------------------------------

/** A payload of another arm, for `user`, sealed with the real secret. */
async function foreignToken(user: TestUser, arm: "contact" | "calendar" | "collection" | "mail"): Promise<string> {
  const base = {
    v: CONFIRM_VERSION,
    j: crypto.randomUUID(),
    h: "AAAA",
    x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
    u: user.userId,
  };
  const payloads: Record<typeof arm, ConfirmPayload> = {
    contact: { ...base, k: "create", t: "dav", c: "/ab/", o: "/ab/x.vcf", r: null, e: null, s: null, f: [] },
    calendar: { ...base, k: "update", t: "dav", c: "/cal/", o: "/cal/x.ics", r: null, e: '"1"', s: null, f: [] },
    collection: { ...base, k: "delete", t: "col", c: "/cal/", o: "/cal/", g: 0, b: "tag" },
    mail: { ...base, k: "move", t: "mail", m: "folder", uv: 1, q: "dest", qr: null, l: [{ i: 1, z: 1, d: 1, n: "1" }] },
  } as unknown as Record<typeof arm, ConfirmPayload>;
  return mintConfirmation(payloads[arm], SECRET());
}

describe("the rule arm and every other arm refuse each other", () => {
  /** A rule payload for USER_A. */
  function rulePayload(): Record<string, unknown> {
    return {
      v: CONFIRM_VERSION,
      k: "rule",
      t: "rule",
      j: crypto.randomUUID(),
      h: "AAAA",
      x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
      u: USER_A.userId,
    };
  }

  it("a rule payload verifies as a rule, and only as a rule", async () => {
    const built = rulePayload();
    const token = await mintConfirmation(built as unknown as ConfirmPayload, SECRET());

    expect(await verifyConfirmation(token, SECRET(), USER_A.userId, "rule")).toEqual(built);
    for (const other of ["dav", "col", "mail"] as const) {
      await expect(verifyConfirmation(token, SECRET(), USER_A.userId, other)).rejects.toBeInstanceOf(
        ConfirmationInvalidError,
      );
    }
  });

  it("a rule payload relabelled as another arm, and another arm's kind under the rule arm, are refused", async () => {
    for (const other of ["dav", "col", "mail"] as const) {
      const relabelled = { ...rulePayload(), t: other };
      const token = await mintConfirmation(relabelled as unknown as ConfirmPayload, SECRET());
      await expect(verifyConfirmation(token, SECRET(), USER_A.userId, other)).rejects.toBeInstanceOf(
        ConfirmationInvalidError,
      );
    }
    for (const kind of ["create", "update", "delete", "reply", "move"]) {
      const token = await mintConfirmation({ ...rulePayload(), k: kind } as unknown as ConfirmPayload, SECRET());
      await expect(verifyConfirmation(token, SECRET(), USER_A.userId, "rule")).rejects.toBeInstanceOf(
        ConfirmationInvalidError,
      );
    }
  });

  it("every other arm's field set, relabelled as a rule, is refused", async () => {
    for (const arm of ["contact", "calendar", "collection", "mail"] as const) {
      const token = await foreignToken(USER_A, arm);
      const payload = JSON.parse(atob(token.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"))) as Record<
        string,
        unknown
      >;
      for (const relabel of [{ t: "rule" }, { t: "rule", k: "rule" }]) {
        const sealed = await mintConfirmation({ ...payload, ...relabel } as unknown as ConfirmPayload, SECRET());
        await expect(verifyConfirmation(sealed, SECRET(), USER_A.userId, "rule")).rejects.toBeInstanceOf(
          ConfirmationInvalidError,
        );
      }
    }
  });
});

describe("rules_commit stores exactly the previewed rule, or nothing", () => {
  it("stores the rule once, and repeats the sentence in the past tense", async () => {
    const shown = await preview(USER_A, DRAFT_RULE);
    const parsed = readToolResult(
      await call(USER_A, "rules_commit", { confirmToken: shown.token, rule: shown.rule }),
    );

    expect(parsed.isError).toBe(false);
    expect(parsed.trusted?.added).toBe(true);
    const rules = await storedRules(USER_A);
    expect(rules).toHaveLength(1);
    expect(rules[0]!.id).toBe(parsed.trusted?.ruleId);
    expect({ when: rules[0]!.when, then: rules[0]!.then }).toEqual(shown.rule);
    expect(parsed.untrusted?.confirmationLine).toBe(shown.line.replace(/^Adding /, "Added "));
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("one changed character in the draft text is refused, and nothing is stored", async () => {
    const shown = await preview(USER_A, DRAFT_RULE);
    const changed = structuredClone(shown.rule) as typeof DRAFT_RULE;
    changed.then.draft.text = `${DRAFT_TEXT.slice(0, -1)}!`;
    const parsed = readToolResult(
      await call(USER_A, "rules_commit", { confirmToken: shown.token, rule: changed }),
    );

    expect(parsed.isError).toBe(true);
    expect(parsed.trusted?.category).toBe("confirmation_invalid");
    expect(await storedRules(USER_A)).toEqual([]);
  });

  it("the same confirmation twice: the second is refused", async () => {
    const shown = await preview(USER_A, FLAG_RULE);
    const args = { confirmToken: shown.token, rule: shown.rule };

    expect(readToolResult(await call(USER_A, "rules_commit", args)).isError).toBe(false);
    const second = readToolResult(await call(USER_A, "rules_commit", args));

    expect(second.isError).toBe(true);
    expect(second.trusted?.category).toBe("confirmation_invalid");
    expect(await storedRules(USER_A)).toHaveLength(1);
  });

  it("person B commits person A's confirmation: refused, nothing stored for either, and A's is not spent", async () => {
    const shown = await preview(USER_A, FLAG_RULE);
    const args = { confirmToken: shown.token, rule: shown.rule };

    const byB = readToolResult(await call(USER_B, "rules_commit", args));
    expect(byB.isError).toBe(true);
    expect(byB.trusted?.category).toBe("confirmation_invalid");
    expect(await storedRules(USER_A)).toEqual([]);
    expect(await storedRules(USER_B)).toEqual([]);

    expect(readToolResult(await call(USER_A, "rules_commit", args)).isError).toBe(false);
    expect(await storedRules(USER_A)).toHaveLength(1);
    expect(await storedRules(USER_B)).toEqual([]);
  });

  for (const arm of ["contact", "calendar", "collection", "mail"] as const) {
    it(`a ${arm} confirmation given to rules_commit is refused before anything is stored`, async () => {
      const parsed = readToolResult(
        await call(USER_A, "rules_commit", {
          confirmToken: await foreignToken(USER_A, arm),
          rule: FLAG_RULE_NORMALISED,
        }),
      );

      expect(parsed.isError).toBe(true);
      expect(parsed.trusted?.category).toBe("confirmation_invalid");
      expect(await storedRules(USER_A)).toEqual([]);
    });
  }

  it("a rule confirmation given to contacts_commit is refused before any request is sent", async () => {
    const shown = await preview(USER_A, FLAG_RULE);
    const davFetch = vi.fn();
    let commit: Callback | undefined;
    const server = {
      registerTool(name: string, _options: unknown, callback: Callback) {
        if (name === "contacts_commit") commit = callback;
      },
    };
    const principal = testPrincipal(USER_A);
    registerContactsWriteTools(server as unknown as McpServer, davFetch as unknown as DavFetch, principal);
    expect(commit).toBeDefined();

    const parsed = readToolResult(
      await commit!({ confirmToken: shown.token, change: { kind: "create", formattedName: "Somebody" } }),
    );

    expect(parsed.isError).toBe(true);
    expect(parsed.trusted?.category).toBe("confirmation_invalid");
    expect(davFetch).not.toHaveBeenCalled();

    // Not spent either: the rule's own commit still takes it.
    expect(
      readToolResult(await call(USER_A, "rules_commit", { confirmToken: shown.token, rule: shown.rule }))
        .isError,
    ).toBe(false);
  });

  it("at 20 rules: refused on the success arm, the confirmation spent, nothing stored", async () => {
    const shown = await preview(USER_A, FLAG_RULE);
    await seed(USER_A, RULES_KEY, Array.from({ length: 20 }, (_, i) => storedRule(i)));
    const args = { confirmToken: shown.token, rule: shown.rule };

    const first = readToolResult(await call(USER_A, "rules_commit", args));
    expect(first.isError).toBe(false);
    expect(first.trusted?.added).toBe(false);
    expect(first.trusted?.reason).toBe("A person can hold at most 20 rules. Remove one first.");
    expect(await storedRules(USER_A)).toHaveLength(20);

    const again = readToolResult(await call(USER_A, "rules_commit", args));
    expect(again.isError).toBe(true);
    expect(again.trusted?.category).toBe("confirmation_invalid");
  });
});

// ---------------------------------------------------------------------------
// rules_remove
// ---------------------------------------------------------------------------

describe("rules_remove removes at once, and only the caller's own rule", () => {
  it("removes an existing rule and says so", async () => {
    const id = await addRule(USER_A, FLAG_RULE);
    const parsed = readToolResult(await call(USER_A, "rules_remove", { ruleId: id }));

    expect(parsed.isError).toBe(false);
    expect(parsed.trusted?.removed).toBe(true);
    expect(parsed.trusted?.sentence).toBe("Removed the rule. It no longer acts on any mail.");
    expect(await storedRules(USER_A)).toEqual([]);
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("an unknown id: says there was none", async () => {
    const parsed = readToolResult(await call(USER_A, "rules_remove", { ruleId: "no-such-rule" }));

    expect(parsed.isError).toBe(false);
    expect(parsed.trusted?.removed).toBe(false);
    expect(parsed.trusted?.sentence).toBe("You have no rule with that id. Nothing was changed.");
  });

  it("another person's rule id: says there was none, and their rule remains", async () => {
    const id = await addRule(USER_A, FLAG_RULE);
    const parsed = readToolResult(await call(USER_B, "rules_remove", { ruleId: id }));

    expect(parsed.trusted?.removed).toBe(false);
    expect((await storedRules(USER_A)).map((rule) => rule.id)).toEqual([id]);
  });
});

// ---------------------------------------------------------------------------
// rules_list
// ---------------------------------------------------------------------------

/** The fixed sentence for signing in again, as every no-key status carries it. */
const SIGN_IN_AGAIN = "Signing in again (reconnecting iCloud MCP in a Claude app) makes a new";

interface Status {
  running: boolean;
  holdsAutonomyKey: boolean;
  nextWakeAt: string | null;
  consecutiveAuthFailures: number;
  lastRun: { at: string; outcome: string } | null;
  sentence: string;
}

describe("rules_list shows the rules, the job's status and what it did", () => {
  it("no rules: an empty list and one sentence saying nothing runs; no connection and no lease", async () => {
    // The lease is held for the whole call. A tool that took it would answer
    // connection_busy; one that opened a connection would reach the mock.
    const held = await stubFor(USER_A).acquire();
    expect(held.held).toBe(true);
    try {
      const parsed = readToolResult(await call(USER_A, "rules_list"));

      expect(parsed.isError).toBe(false);
      expect(parsed.trusted?.rules).toEqual([]);
      expect((parsed.trusted?.status as Status).sentence).toBe(
        "You have no rules, so the rules job does nothing for you.",
      );
      expect(connectImap).not.toHaveBeenCalled();
    } finally {
      if (held.held) await stubFor(USER_A).release(held.token);
    }
  });

  it("rules and no autonomy key: the job is not running, and signing in again makes a new key", async () => {
    await addRule(USER_A, FLAG_RULE);
    const status = readToolResult(await call(USER_A, "rules_list")).trusted?.status as Status;

    expect(status.running).toBe(false);
    expect(status.holdsAutonomyKey).toBe(false);
    expect(status.sentence).toContain("The rules job is not running for you");
    expect(status.sentence).toContain(SIGN_IN_AGAIN);
  });

  it("after two refused sign-ins: the job stopped because iCloud refused the sign-in twice", async () => {
    await addRule(USER_A, FLAG_RULE);
    await seed(USER_A, JOB_STATE_KEY, "off_auth");
    await seed(USER_A, JOB_AUTH_FAILURES_KEY, 0);
    await seed(USER_A, JOB_LAST_RUN_KEY, { at: Date.now(), outcome: "off_auth" });
    const status = readToolResult(await call(USER_A, "rules_list")).trusted?.status as Status;

    expect(status.running).toBe(false);
    expect(status.sentence).toContain("iCloud refused the sign-in twice in a row");
    expect(status.sentence).toContain(SIGN_IN_AGAIN);
  });

  it("holding a key: running, with the next wake, the failure count and the last run", async () => {
    await addRule(USER_A, FLAG_RULE);
    const next = Date.UTC(2026, 8, 28, 12, 0, 0);
    const last = Date.UTC(2026, 8, 28, 11, 45, 0);
    await seed(USER_A, AUTONOMY_KEY, { held: true });
    await seed(USER_A, JOB_NEXT_AT_KEY, next);
    await seed(USER_A, JOB_AUTH_FAILURES_KEY, 1);
    await seed(USER_A, JOB_LAST_RUN_KEY, { at: last, outcome: "done" });
    const status = readToolResult(await call(USER_A, "rules_list")).trusted?.status as Status;

    expect(status.running).toBe(true);
    expect(status.holdsAutonomyKey).toBe(true);
    expect(status.nextWakeAt).toBe(new Date(next).toISOString());
    expect(status.consecutiveAuthFailures).toBe(1);
    expect(status.lastRun).toEqual({ at: new Date(last).toISOString(), outcome: "done" });
    expect(status.sentence).toBe(
      "The rules job runs on its own every 15 minutes, with nobody present, and acts on new inbox mail your rules match.",
    );
  });

  it("no rules answer names a renewal, an expiry or a lifetime for the key", async () => {
    const texts: string[] = [];
    texts.push(textOf(await call(USER_A, "rules_list")));
    const shown = await preview(USER_A, DRAFT_RULE);
    texts.push(textOf(await call(USER_A, "rules_add", { rule: DRAFT_RULE })));
    const committed = await call(USER_A, "rules_commit", { confirmToken: shown.token, rule: shown.rule });
    texts.push(textOf(committed));
    texts.push(textOf(await call(USER_A, "rules_list")));
    await seed(USER_A, JOB_STATE_KEY, "off_auth");
    texts.push(textOf(await call(USER_A, "rules_list")));
    await seed(USER_A, AUTONOMY_KEY, { held: true });
    await seed(USER_A, JOB_STATE_KEY, null);
    texts.push(textOf(await call(USER_A, "rules_list")));
    const id = readToolResult(committed).trusted?.ruleId as string;
    texts.push(textOf(await call(USER_A, "rules_remove", { ruleId: id })));

    for (const text of texts) {
      expect(text).not.toMatch(/renew|expir|lifetime|\buntil\b/i);
      expect(text).not.toMatch(/\b\d+\s*(day|week|month|year)s?\b/i);
    }
  });
});

// ---------------------------------------------------------------------------
// rules_list after the job ran
// ---------------------------------------------------------------------------

const SUBJECT_MARK = "Offer-7f3c-subject-mark";
const SENDER = "hr@example.com";
const SELF = "self@example.com";

/** An INTERNALDATE for `ms`, in the protocol's own form, in UTC. */
function internalDate(ms: number): string {
  const d = new Date(ms);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const two = (n: number) => String(n).padStart(2, "0");
  return (
    `${two(d.getUTCDate())}-${months[d.getUTCMonth()]}-${d.getUTCFullYear()} ` +
    `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} +0000`
  );
}

/** Run the real job twice in the person's object: a start, then one matching message. */
async function runJobTwice(user: TestUser): Promise<void> {
  const row: NewMailRow = {
    id: "INBOX-msg-1",
    uid: 5001,
    unread: true,
    receivedAt: internalDate(Date.now() + 3_600_000),
    fromName: "Hiring Team",
    fromAddress: SENDER,
    subject: SUBJECT_MARK,
    mailingList: false,
  };
  const answerFor = (sentMarker: boolean, marker: string): ChangesAnswer =>
    ({
      mail: [
        {
          folder: "INBOX",
          state: sentMarker ? "changes" : "started",
          newMessages: sentMarker ? 1 : null,
          otherActivity: null,
          mechanism: "status-uidnext",
          rows: sentMarker ? [row] : [],
        },
      ],
      calendar: { calendars: [], notCovered: [], gone: 0, unchecked: null },
      carried: [],
      since: null,
      marker,
    }) as unknown as ChangesAnswer;

  for (const marker of ["marker-1", "marker-2"]) {
    await runInDurableObject(stubFor(user), async (_instance, state) => {
      const storage = state.storage.kv;
      storage.delete(JOB_NEXT_AT_KEY);
      const answer = (tool: string, args: Record<string, unknown>): CallAnswer => {
        if (tool === "changes_since") {
          return { kind: "ok", result: changesResult(answerFor(typeof args.marker === "string", marker)) };
        }
        if (tool === "account_whoami") {
          return { kind: "ok", result: signedInAsResult({ appleId: SELF } as unknown as Principal) };
        }
        if (tool === "mail_flag") {
          return {
            kind: "ok",
            result: flagStateToolResult(args.id as string, true, {
              applied: true,
              flagged: true,
              source: "store-echo",
            }),
          };
        }
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
            subject: `Re: ${SUBJECT_MARK}`,
            to: (args.to as string[]) ?? [],
            cc: [],
          } as never),
        };
      };
      const deps: JobDeps = {
        storage: storage as unknown as JobDeps["storage"],
        name: user.userId,
        now: () => Date.now(),
        isRetry: false,
        requestWake: async () => {},
        withSession: async (use) => ({
          kind: "ok",
          value: await use(async (tool, args) => answer(tool, args)),
        }),
        disarm: async () => {},
      };
      await runAutonomyJob(deps);
    });
  }
}

describe("rules_list after the job ran", () => {
  it("ids, times, kinds and the status are trusted; every rule value and draft word is fenced; activity holds no subject or address", async () => {
    const id = await addRule(USER_A, DRAFT_RULE);
    await seed(USER_A, AUTONOMY_KEY, { held: true });
    await runJobTwice(USER_A);

    const result = await call(USER_A, "rules_list");
    const parsed = readToolResult(result);
    const trustedText = result.content[0]!.text;

    // The job acted: one flag and one draft entry for the rule, beside the runs.
    const activity = parsed.trusted?.activity as Array<Record<string, unknown>>;
    expect(activity.map((entry) => entry.kind).sort()).toEqual(["draft", "flag", "run", "run"]);
    expect(activity.filter((entry) => entry.kind !== "run").every((entry) => entry.ruleId === id)).toBe(true);
    for (const entry of activity) {
      expect(Object.keys(entry).sort()).toEqual(
        entry.count === undefined
          ? ["at", "kind", "messageId", "outcome", "ruleId", "runId"]
          : ["at", "count", "kind", "messageId", "outcome", "ruleId", "runId"],
      );
      expect(typeof entry.at).toBe("string");
    }

    // The trusted block: the rule's id and kinds, no value and no draft word.
    expect(parsed.trusted?.rules).toEqual([
      expect.objectContaining({ id, actions: ["flag", "draft"], conditionKinds: ["fromAddresses"] }),
    ]);
    for (const value of [SENDER, DRAFT_TEXT, SUBJECT_MARK, SELF, "@"]) {
      expect(trustedText).not.toContain(value);
    }

    // The fenced block: every rule value and the draft's words.
    expect(parsed.untrusted?.rules).toEqual([{ id, when: DRAFT_RULE.when, then: DRAFT_RULE.then }]);
    // No mail content anywhere in the answer.
    expect(textOf(result)).not.toContain(SUBJECT_MARK);
  });

  it("one person's rules and activity are invisible to another person's list", async () => {
    await addRule(USER_A, DRAFT_RULE);
    await seed(USER_A, ACTIVITY_KEY, [
      { at: 1, runId: "r", kind: "run", ruleId: null, messageId: null, outcome: "done" },
    ]);
    const parsed = readToolResult(await call(USER_B, "rules_list"));

    expect(parsed.trusted?.rules).toEqual([]);
    expect(parsed.trusted?.activity).toEqual([]);
    expect(parsed.untrusted?.rules).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// rules_test
// ---------------------------------------------------------------------------

const ENCODER = new TextEncoder();

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

/** One `key {n}\r\n<payload>` pair, the count derived from the payload. */
function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

/** The inbox holds 30 messages; the newest 25 are the page. */
const ALL_UIDS = Array.from({ length: 30 }, (_, i) => 4801 + i);
const PAGE_UIDS = [...ALL_UIDS].reverse().slice(0, 25);

/** The one display name that looks like an address. It must never be offered. */
const LOOKALIKE_NAME = "boss@company.example";

/** The From and Subject lines of each row on the page. Filler unless named. */
function headersOf(uid: number): { from: string; subject: string } {
  if (uid === 4830) return { from: '"Hiring" <hr@example.com>', subject: "Your interview" };
  if (uid === 4829) return { from: `"${LOOKALIKE_NAME}" <attacker@evil.example>`, subject: "Interview slot" };
  if (uid === 4828) return { from: `<${USER_A.appleId}>`, subject: "My interview notes" };
  if (uid === 4827) return { from: "undisclosed-recipients:;", subject: "interview?" };
  return { from: `"Filler" <filler${uid}@example.net>`, subject: `Newsletter ${uid}` };
}

/** The search reply, the metadata reply and the snippet reply for the page. */
function listingTurns(): Uint8Array[] {
  const metadata: Uint8Array[] = [];
  const snippets: Uint8Array[] = [];
  PAGE_UIDS.forEach((uid, i) => {
    const { from, subject } = headersOf(uid);
    metadata.push(
      ENCODER.encode(
        `* ${i + 1} FETCH (UID ${uid} FLAGS () INTERNALDATE "01-Jan-2026 00:00:00 +0000" ` +
          `RFC822.SIZE ${12000 + uid} BODYSTRUCTURE ${PLAIN_STRUCTURE} `,
      ),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]",
        [`Subject: ${subject}`, `From: ${from}`, "Date: Thu, 1 Jan 2026 00:00:00 +0000", `Message-ID: <m${uid}@example.net>`, "", ""].join(
          "\r\n",
        ),
      ),
      ENCODER.encode(")\r\n"),
    );
    snippets.push(
      ENCODER.encode(`* ${i + 1} FETCH (UID ${uid} `),
      literalItem("BODY[1]<0>", `Preview of message ${uid}.`),
      ENCODER.encode(")\r\n"),
    );
  });
  return [
    wire(`* SEARCH ${ALL_UIDS.join(" ")}`, "a5 OK SEARCH completed"),
    concatBytes(...metadata, ENCODER.encode("a6 OK UID FETCH completed\r\n")),
    concatBytes(...snippets, ENCODER.encode("a7 OK UID FETCH completed\r\n")),
  ];
}

/** One whole listing conversation on a fake duplex. */
function listingDuplex(): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4"),
    ...listingTurns(),
    logoutExchange("a8"),
  ]);
}

/** Every duplex the socket mock handed out, in order. */
function queueListing(): FakeDuplex[] {
  const handed: FakeDuplex[] = [];
  vi.mocked(connectImap).mockImplementation(() => {
    const duplex = listingDuplex();
    handed.push(duplex);
    return duplex as never;
  });
  return handed;
}

/** The login line, reduced, as test/read-path-wire.test.ts reduces it. */
function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    return (tokens[1] ?? "").toUpperCase() === "LOGIN" ? `${tokens[0]} ${tokens[1]} [redacted]` : line;
  });
}

/** Everything the listing sends: the read-only open and the peeking fetches, nothing else. */
const LISTING_GOLDEN = [
  "a1 CAPABILITY",
  "a2 LOGIN [redacted]",
  "a3 CAPABILITY",
  'a4 EXAMINE "INBOX"',
  "a5 UID SEARCH ALL",
  `a6 UID FETCH ${PAGE_UIDS.join(",")} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])`,
  `a7 UID FETCH ${PAGE_UIDS.join(",")} (BODY.PEEK[1]<0.1024>)`,
  "a8 LOGOUT",
];

function idOf(uid: number): string {
  return encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid });
}

/** A rule that matches a subject word and places a reply. */
const INTERVIEW_RULE = {
  when: { subjectContains: ["interview"] },
  then: { draft: { text: DRAFT_TEXT } },
};

/** The fixed sentences every test answer carries. */
const IGNORES_DATE =
  "This test ignores when the rule was added, so it also shows what the rule would do to mail that arrived before it. The rules job itself never acts on that mail.";
const NO_LIST_CHECK =
  "This test does not check whether a message came from a mailing list, because the listing it reads does not say. The rules job itself never replies to mailing-list mail.";

interface TestRow {
  messageId: string;
  wouldFlag: boolean;
  wouldDraft: boolean;
  draftSkip: string | null;
}

describe("rules_test tries a rule on recent mail and writes nothing", () => {
  it("with a stored rule id: reads the newest 25 inbox messages once, and says per message what it would do", async () => {
    const id = await addRule(USER_A, DRAFT_RULE);
    const before = await stubFor(USER_A).rulesView();
    const handed = queueListing();

    const result = await call(USER_A, "rules_test", { ruleId: id });
    const parsed = readToolResult(result);

    expect(parsed.isError).toBe(false);
    expect(handed).toHaveLength(1);
    expect(parsed.trusted?.messagesChecked).toBe(25);
    expect(parsed.trusted?.results).toEqual([
      { messageId: idOf(4830), wouldFlag: true, wouldDraft: true, draftSkip: null },
    ]);
    expect(parsed.untrusted?.results).toEqual([
      { messageId: idOf(4830), from: "hr@example.com", subject: "Your interview", replyTo: "hr@example.com" },
    ]);
    // Senders and subjects are fenced, never trusted.
    expect(result.content[0]!.text).not.toContain("@");
    expect(result.content[0]!.text).not.toContain("Your interview");
    // Nothing was written to the object.
    expect(await stubFor(USER_A).rulesView()).toEqual(before);
  });

  it("for each draft verdict: who the reply would go to, or which skip applies, and that the list rule is not checked", async () => {
    queueListing();
    const parsed = readToolResult(await call(USER_A, "rules_test", { rule: INTERVIEW_RULE }));

    expect(parsed.trusted?.results).toEqual([
      { messageId: idOf(4830), wouldFlag: false, wouldDraft: true, draftSkip: null },
      { messageId: idOf(4829), wouldFlag: false, wouldDraft: true, draftSkip: null },
      { messageId: idOf(4828), wouldFlag: false, wouldDraft: true, draftSkip: "own-address" },
      { messageId: idOf(4827), wouldFlag: false, wouldDraft: true, draftSkip: "no-address" },
    ]);
    const fenced = parsed.untrusted?.results as Array<Record<string, unknown>>;
    expect(fenced.map((row) => row.replyTo)).toEqual(["hr@example.com", "attacker@evil.example", null, null]);
    expect(parsed.trusted?.sentences).toContain(NO_LIST_CHECK);
  });

  it("a display name that looks like an address is never offered as a recipient", async () => {
    queueListing();
    const result = await call(USER_A, "rules_test", { rule: INTERVIEW_RULE });
    const fenced = readToolResult(result).untrusted?.results as Array<Record<string, unknown>>;

    expect(fenced.find((row) => row.messageId === idOf(4829))?.replyTo).toBe("attacker@evil.example");
    expect(textOf(result)).not.toContain(LOOKALIKE_NAME);
  });

  it("a candidate rule: the same answer, with nothing stored and no confirmation minted", async () => {
    queueListing();
    const result = await call(USER_A, "rules_test", { rule: INTERVIEW_RULE });

    expect(readToolResult(result).isError).toBe(false);
    expect(textOf(result)).not.toContain("confirmToken");
    expect(await storedRules(USER_A)).toEqual([]);
  });

  it("both, neither, an unknown id or an invalid candidate: a plain refusal before any socket", async () => {
    const id = await addRule(USER_A, FLAG_RULE);
    const cases: Record<string, unknown>[] = [
      { ruleId: id, rule: FLAG_RULE },
      {},
      { ruleId: "no-such-rule" },
      { rule: { when: {}, then: { flag: true } } },
    ];
    for (const args of cases) {
      const parsed = readToolResult(await call(USER_A, "rules_test", args));
      expect(parsed.isError).toBe(false);
      expect(parsed.trusted?.refused).toBe(true);
      expect(typeof parsed.trusted?.reason).toBe("string");
    }
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("the recorded lines are the read-only open and the listing's peeking fetches, and nothing else", async () => {
    const handed = queueListing();
    await call(USER_A, "rules_test", { rule: DRAFT_RULE });

    const lines = redacted(handed[0]!.writtenLines());
    expect(lines).toEqual(LISTING_GOLDEN);
    for (const line of lines) {
      expect(line).not.toMatch(/\b(SELECT|STORE|APPEND|EXPUNGE|COPY|MOVE)\b/);
      expect(line).not.toMatch(/BODY\[|BODY\.PEEK\[\]|RFC822(?!\.SIZE)/);
    }
  });

  it("says it ignores when the rule was added, and applies to older mail", async () => {
    // The rule is added now; every scripted message arrived on 1 January 2026.
    const id = await addRule(USER_A, DRAFT_RULE);
    queueListing();
    const parsed = readToolResult(await call(USER_A, "rules_test", { ruleId: id }));

    expect((parsed.trusted?.results as TestRow[]).map((row) => row.messageId)).toEqual([idOf(4830)]);
    expect(parsed.trusted?.sentences).toContain(IGNORES_DATE);
  });

  it("with the lease held by another request: connection_busy, and nothing read", async () => {
    const held = await stubFor(USER_A).acquire();
    expect(held.held).toBe(true);
    try {
      const parsed = readToolResult(await call(USER_A, "rules_test", { rule: FLAG_RULE }));
      expect(parsed.isError).toBe(true);
      expect(parsed.trusted?.category).toBe("connection_busy");
      expect(connectImap).not.toHaveBeenCalled();
    } finally {
      if (held.held) await stubFor(USER_A).release(held.token);
    }
  });
});
