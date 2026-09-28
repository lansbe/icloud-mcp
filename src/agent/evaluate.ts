// The matcher (Phase 28, D-01, D-03, D-04).
//
// It runs a person's rules over the new inbox messages and says which rule
// matched which message, and what to do: flag, or draft. That is all it says.
//
// WHY NO IDENTIFIER LEAVES IT (PITFALLS #41). A verdict is two integer indices
// and one of two words. The code that acts takes the message id from the row it
// already holds, the draft's words from the rule it already holds, and the
// reply's one recipient from the row through `replyRecipient`. So nothing a
// stranger wrote can reach an action by way of this function's answer: a
// subject that says "flag message X" or "reply to Y" is compared, never read,
// and the answer has no field it could land in.
//
// It is synchronous, and this module has no runtime import. Both are checked:
// the answer is not a promise, and only type imports appear here. There is no
// model anywhere in it (D-01).

import type { Rule } from "./rules";
import type { EnvelopeRow } from "./tool-call";

/** The two things a rule can do. */
export type VerdictAction = "flag" | "draft";

/** One match: which rule, which message, and which action. Indices only. */
export interface Verdict {
  readonly rule: number;
  readonly row: number;
  readonly action: VerdictAction;
}

/** Whether the row's sender is one of the addresses, compared without case. */
function fromAddressMatches(values: readonly string[], row: EnvelopeRow): boolean {
  const sender = row.senderAddress;
  if (sender === null) return false;
  const lower = sender.toLowerCase();
  return values.some((value) => value.toLowerCase() === lower);
}

/**
 * Whether the row's sender is at one of the domains, or a subdomain of one.
 * The domain is the part after the address's last `@`. A lookalike suffix
 * (`evilexample.com` for `example.com`) does not match: a subdomain must meet
 * the domain at a dot.
 */
function fromDomainMatches(values: readonly string[], row: EnvelopeRow): boolean {
  const sender = row.senderAddress;
  if (sender === null) return false;
  const at = sender.lastIndexOf("@");
  if (at < 0) return false;
  const domain = sender.slice(at + 1).toLowerCase();
  if (domain.length === 0) return false;
  return values.some((value) => {
    const wanted = value.toLowerCase();
    return domain === wanted || domain.endsWith(`.${wanted}`);
  });
}

/**
 * Text as a subject is compared: NFKC, then lower case. The same two steps the
 * parser applies to a rule's words, repeated here because this module has no
 * runtime import.
 */
function comparable(text: string): string {
  return text.normalize("NFKC").toLowerCase();
}

/** Whether the row's subject contains one of the words. */
function subjectMatches(values: readonly string[], row: EnvelopeRow): boolean {
  if (row.subject === null) return false;
  const subject = comparable(row.subject);
  return values.some((value) => subject.includes(comparable(value)));
}

/** Whether every condition kind the rule has matches the row. */
function ruleMatches(rule: Rule, row: EnvelopeRow): boolean {
  // A message received before the rule was added never matches it, and a
  // message whose time would not parse matches nothing (D-03).
  if (row.receivedAt === null || row.receivedAt < rule.createdAt) return false;
  const { when } = rule;
  let kinds = 0;
  if (when.fromAddresses !== undefined) {
    kinds += 1;
    if (!fromAddressMatches(when.fromAddresses, row)) return false;
  }
  if (when.fromDomains !== undefined) {
    kinds += 1;
    if (!fromDomainMatches(when.fromDomains, row)) return false;
  }
  if (when.subjectContains !== undefined) {
    kinds += 1;
    if (!subjectMatches(when.subjectContains, row)) return false;
  }
  // A rule with no condition matches nothing. The parser refuses one anyway.
  return kinds > 0;
}

/**
 * Every verdict, in row order and then rule order; a rule with both actions
 * gives the flag first, then the draft. The answer is frozen.
 */
export function evaluate(rules: readonly Rule[], rows: readonly EnvelopeRow[]): readonly Verdict[] {
  const verdicts: Verdict[] = [];
  rows.forEach((row, rowIndex) => {
    rules.forEach((rule, ruleIndex) => {
      if (!ruleMatches(rule, row)) return;
      if (rule.then.flag === true) {
        verdicts.push(Object.freeze({ rule: ruleIndex, row: rowIndex, action: "flag" }));
      }
      if (rule.then.draft !== undefined) {
        verdicts.push(Object.freeze({ rule: ruleIndex, row: rowIndex, action: "draft" }));
      }
    });
  });
  return Object.freeze(verdicts);
}
