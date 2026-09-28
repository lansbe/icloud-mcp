// The rules tools (Phase 28, D-10 to D-13, D-18, D-25, D-28 to D-30).
//
// A person's autonomy rules are THIS SERVER's rules, not iCloud Mail's own. A
// rule runs on its own every 15 minutes, with nobody present, and can only flag
// a matching message or place a draft reply to its sender. These tools let the
// person list their rules and what the job did, add one after a preview, remove
// one, and try one on recent mail without waiting for the job.
//
// WHY ADDING IS PREVIEWED (D-11). The model reads mail strangers wrote, so a
// message can ask it to add a rule. A rule is a standing instruction that acts
// with nobody looking, so adding one goes through the same confirm gate as every
// other write here: `rules_add` writes nothing and returns one sentence this
// server wrote, naming every condition value and the action, plus a signed
// confirmation. Only `rules_commit`, handed that confirmation and the rule back
// unaltered, adds it. That call is the only place under `src/` that adds a rule
// to the object.
//
// WHAT REACHES WHAT (D-25). `rules_list`, `rules_add`, `rules_commit` and
// `rules_remove` reach the person's own object and nothing else: no iCloud
// connection and no lease. Only `rules_test` reads mail, through the ordinary
// inbox listing, under the lease. The object is always named from the principal
// through `agentFor`, and no tool takes a user id, an object id or a time.
//
// WHAT IS TRUSTED. Ids, times, closed words and counts are this server's, and go
// in the first block. Rule values, draft words, and every sender and subject go
// in the fenced block. Every sentence is fixed text with values filled in, and
// no sentence ever carries mail content.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import { type LeasedMail, agentFor } from "../../agent/lease";
import { MAX_RULES, type Rule, type RuleBody, parseRule } from "../../agent/rules";
import type { RulesView } from "../../agent/user-agent";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  ConfirmationInvalidError,
  changeHashMatches,
  composeConfirmationLine,
  mintConfirmation,
  reserveConfirmation,
  ruleChangeHashOf,
  verifyConfirmation,
} from "../../confirm";
import type {
  ConfirmationTense,
  NormalizedRuleChange,
  RuleConfirmPayload,
} from "../../confirm";
import { MailConfirmationError } from "../../errors";
import type { MailSessionOptions } from "../../mail/service";
import type { Principal } from "../../principal";
import type { ToolResult } from "../untrusted";
import { untrustedToolResult } from "../untrusted";
import { mailErrorResult } from "./mail";

/** How every rules tool description begins (D-10). */
const RULES_PREFIX = "This server's own autonomy rules, not iCloud Mail's rules.";

/** The status sentence when the person has no rules (D-25). */
const NO_RULES_SENTENCE = "You have no rules, so the rules job does nothing for you.";

/** The status sentence when the job runs for the person. */
const RUNNING_SENTENCE =
  "The rules job runs on its own every 15 minutes, with nobody present, and acts on new inbox mail your rules match.";

/**
 * The status sentence when the person holds no autonomy key (D-18 as revised).
 * It names no lifetime and no renewal (D-28): the key has none.
 */
const NO_KEY_SENTENCE =
  "The rules job is not running for you, because this account holds no autonomy key right now. " +
  "Signing in again (reconnecting iCloud MCP in a Claude app) makes a new one.";

/** The status sentence after iCloud refused the sign-in twice (D-16, D-18). */
const OFF_AUTH_SENTENCE =
  "The rules job stopped because iCloud refused the sign-in twice in a row. " +
  "Signing in again (reconnecting iCloud MCP in a Claude app) makes a new key, and the job then starts again on its own.";

/** The answer to removing a rule, and to finding none. */
const REMOVED_SENTENCE = "Removed the rule. It no longer acts on any mail.";
const NOT_FOUND_SENTENCE = "You have no rule with that id. Nothing was changed.";

/** A time this server holds, in milliseconds, as an ISO string, or null. */
function isoOf(ms: unknown): string | null {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** A plain answer with one block: this server's own words and values only. */
function plainResult(value: Record<string, unknown>): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

/** A refusal on the success arm: a fixed sentence, nothing written. */
function refusalResult(reason: string): ToolResult {
  return plainResult({ refused: true, reason });
}

/** The two actions a rule takes, in a fixed order. Closed words. */
function actionsOf(rule: RuleBody): ("flag" | "draft")[] {
  const actions: ("flag" | "draft")[] = [];
  if (rule.then.flag === true) actions.push("flag");
  if (rule.then.draft !== undefined) actions.push("draft");
  return actions;
}

/** The condition kinds a rule has, in a fixed order. Closed words. */
function conditionKindsOf(rule: RuleBody): string[] {
  const kinds: string[] = [];
  if (rule.when.fromAddresses !== undefined) kinds.push("fromAddresses");
  if (rule.when.fromDomains !== undefined) kinds.push("fromDomains");
  if (rule.when.subjectContains !== undefined) kinds.push("subjectContains");
  return kinds;
}

/** The rule as the person sees it: its conditions and actions, nothing else. */
function publishedRule(rule: RuleBody): RuleBody {
  return { when: rule.when, then: rule.then };
}

/** What the confirmation's hash is taken over. See `canonicalRuleChange`. */
function changeOf(rule: RuleBody): NormalizedRuleChange {
  return {
    fromAddresses: rule.when.fromAddresses ?? null,
    fromDomains: rule.when.fromDomains ?? null,
    subjectContains: rule.when.subjectContains ?? null,
    flag: rule.then.flag === true,
    draftText: rule.then.draft?.text ?? null,
  };
}

/** The sentence for a rule being added, or added (D-11). */
function ruleLine(rule: RuleBody, tense: ConfirmationTense): string {
  return composeConfirmationLine(
    {
      kind: "rule",
      fromAddresses: rule.when.fromAddresses ?? [],
      fromDomains: rule.when.fromDomains ?? [],
      subjectWords: rule.when.subjectContains ?? [],
      flag: rule.then.flag === true,
      draft: rule.then.draft !== undefined,
    },
    tense,
  );
}

/**
 * Turn the neutral confirmation refusal into the mail one, so the answer is
 * `confirmation_invalid` rather than a connection diagnosis. Nothing is read
 * off the caught value.
 */
function answerFor(err: unknown): ToolResult {
  if (err instanceof ConfirmationInvalidError) return mailErrorResult(new MailConfirmationError());
  return mailErrorResult(err);
}

/** Preview adding a rule: parse it, mint a confirmation, write nothing. */
async function previewRule(actor: Principal, supplied: unknown): Promise<ToolResult> {
  const parsed = parseRule(supplied);
  if (!parsed.ok) return refusalResult(parsed.reason);
  const rule = parsed.rule;

  const payload: RuleConfirmPayload = {
    v: CONFIRM_VERSION,
    k: "rule",
    t: "rule",
    j: crypto.randomUUID(),
    h: await ruleChangeHashOf(changeOf(rule)),
    x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
    u: actor.userId,
  };
  const confirmToken = await mintConfirmation(payload, env.CONFIRM_SECRET);

  return untrustedToolResult(
    {
      confirmToken,
      confirmWithinSeconds: CONFIRM_TTL_SECONDS,
      actions: actionsOf(rule),
      conditionKinds: conditionKindsOf(rule),
    },
    { rule: publishedRule(rule), confirmationLine: ruleLine(rule, "would") },
  );
}

/**
 * Add exactly the previewed rule, or refuse having added nothing.
 *
 * The order is `applyContactCommit`'s: verify the seal, the version, the target,
 * the user and the expiry; the kind; the supplied rule parses; its hash matches
 * the signed one; claim the one-time slot; and only then add. Nothing before
 * the slot is claimed reaches the object, so a refused commit costs the person
 * nothing. The object's own refusals (20 rules already) come after the slot, so
 * that confirmation is spent.
 */
async function commitRule(
  actor: Principal,
  confirmToken: string,
  supplied: unknown,
): Promise<ToolResult> {
  const payload = await verifyConfirmation(confirmToken, env.CONFIRM_SECRET, actor.userId, "rule");
  if (payload.k !== "rule") throw new ConfirmationInvalidError();

  const parsed = parseRule(supplied);
  if (!parsed.ok) throw new ConfirmationInvalidError();
  const rule = parsed.rule;
  if (!(await changeHashMatches(await ruleChangeHashOf(changeOf(rule)), payload.h))) {
    throw new ConfirmationInvalidError();
  }

  await reserveConfirmation(env.CONFIRM_KV, actor.userId, payload.j, payload.x);

  // THE ONE CALL SITE under `src/` that adds a rule to the object.
  const added = await agentFor(actor).addRule(rule);
  if (!added.ok) return plainResult({ added: false, reason: added.reason });

  return untrustedToolResult(
    { added: true, ruleId: added.id, addedAt: isoOf(added.createdAt) },
    { rule: publishedRule(rule), confirmationLine: ruleLine(rule, "did") },
  );
}

/** The job's status, from the view, per D-18 as revised. */
function statusOf(view: RulesView): Record<string, unknown> {
  const hasRules = view.rules.length > 0;
  const running = hasRules && view.armed;
  const sentence = !hasRules
    ? NO_RULES_SENTENCE
    : view.armed
      ? RUNNING_SENTENCE
      : view.job.offAuth
        ? OFF_AUTH_SENTENCE
        : NO_KEY_SENTENCE;
  const lastRun = view.job.lastRun;
  return {
    running,
    holdsAutonomyKey: view.armed,
    nextWakeAt: running ? isoOf(view.job.nextAt) : null,
    consecutiveAuthFailures: view.job.authFailures,
    lastRun:
      lastRun === null ? null : { at: isoOf(lastRun.at), outcome: lastRun.outcome },
    sentence,
  };
}

/** The list answer: trusted status, ids, times, kinds and activity; rule values fenced. */
function listResult(view: RulesView): ToolResult {
  const rules = view.rules as Rule[];
  return untrustedToolResult(
    {
      status: statusOf(view),
      ruleCount: rules.length,
      maxRules: MAX_RULES,
      rules: rules.map((rule) => ({
        id: rule.id,
        addedAt: isoOf(rule.createdAt),
        actions: actionsOf(rule),
        conditionKinds: conditionKindsOf(rule),
      })),
      activity: view.activity.map((entry) => {
        const out: Record<string, unknown> = {
          at: isoOf(entry.at),
          runId: entry.runId,
          kind: entry.kind,
          ruleId: entry.ruleId,
          messageId: entry.messageId,
          outcome: entry.outcome,
        };
        if (typeof entry.count === "number") out.count = entry.count;
        return out;
      }),
    },
    { rules: rules.map((rule) => ({ id: rule.id, ...publishedRule(rule) })) },
  );
}

/**
 * The rule's input shape.
 *
 * Every object is LOOSE on purpose: a key the schema does not name is passed
 * through to `parseRule`, which refuses it by name. A strict-stripping schema
 * would drop a draft's `to` silently and preview a rule the person did not
 * write; the parser is the one place a rule's shape is decided (D-29).
 */
function ruleSchema(what: string) {
  return z
    .looseObject({
      when: z
        .looseObject({
          fromAddresses: z
            .array(z.string())
            .optional()
            .describe("Whole sender addresses, 1 to 10. Any one matches."),
          fromDomains: z
            .array(z.string())
            .optional()
            .describe("Sender domains, 1 to 10. A subdomain matches too."),
          subjectContains: z
            .array(z.string())
            .optional()
            .describe("Words in the subject, 1 to 10, each up to 100 characters. Any one matches."),
        })
        .describe("What a new inbox message must match. Every kind given must match."),
      then: z
        .looseObject({
          flag: z.boolean().optional().describe("true to flag each matching message."),
          draft: z
            .looseObject({
              text: z.string().optional().describe("The reply's words, 1 to 2000 characters."),
            })
            .optional()
            .describe(
              "A draft reply to each matching message's sender, in these words. Takes only text: " +
                "no recipients, subject, copies or HTML. Never sent.",
            ),
        })
        .describe("What the rule does: flag, draft, or both."),
    })
    .describe(what);
}

/**
 * Register the rules tools (D-10).
 *
 * `mail` is the request's leased runner; only the test tool reaches it.
 * `options` is the test seam for the mail session's bounds, as
 * `registerChangesTool` has; production passes nothing.
 */
export function registerRulesTools(
  server: McpServer,
  _mail: LeasedMail,
  principal: Promise<Principal>,
  _options: MailSessionOptions = {},
): void {
  server.registerTool(
    "rules_list",
    {
      description:
        `${RULES_PREFIX} Lists your rules, whether the rules job is running for you, ` +
        "and what it did recently. Reads no mail.",
      inputSchema: z.object({}),
    },
    async () => {
      try {
        const actor = await principal;
        return listResult(await agentFor(actor).rulesView());
      } catch (err) {
        return answerFor(err);
      }
    },
  );

  server.registerTool(
    "rules_add",
    {
      description:
        `${RULES_PREFIX} Previews adding one; writes nothing. A rule runs every 15 minutes ` +
        "with nobody present. Show the user confirmationLine word for word, then commit with rules_commit.",
      inputSchema: z.object({
        rule: ruleSchema("The rule to add. Pass the rule this returns back to rules_commit unaltered."),
      }),
    },
    async ({ rule }) => {
      try {
        const actor = await principal;
        return await previewRule(actor, rule);
      } catch (err) {
        return answerFor(err);
      }
    },
  );

  server.registerTool(
    "rules_commit",
    {
      description:
        `${RULES_PREFIX} Adds the rule rules_add previewed. Pass its confirmToken and its rule ` +
        "back unaltered.",
      inputSchema: z.object({
        confirmToken: z
          .string()
          .describe(
            "The confirmToken from rules_add, unaltered. Before you pass this back, the user must " +
              "have seen the preview's confirmationLine word for word. It can be spent only once.",
          ),
        rule: ruleSchema(
          "The rule rules_add returned, passed back unaltered. Altering any value is refused.",
        ),
      }),
    },
    async ({ confirmToken, rule }) => {
      try {
        const actor = await principal;
        return await commitRule(actor, confirmToken, rule);
      } catch (err) {
        return answerFor(err);
      }
    },
  );

  server.registerTool(
    "rules_remove",
    {
      description: `${RULES_PREFIX} Removes one of your rules at once, by its id from rules_list.`,
      inputSchema: z.object({
        ruleId: z.string().describe("The rule's id from rules_list."),
      }),
    },
    async ({ ruleId }) => {
      try {
        const actor = await principal;
        const answer = await agentFor(actor).removeRule(ruleId);
        return plainResult(
          answer.removed
            ? { removed: true, sentence: REMOVED_SENTENCE }
            : { removed: false, sentence: NOT_FOUND_SENTENCE },
        );
      } catch (err) {
        return answerFor(err);
      }
    },
  );
}
