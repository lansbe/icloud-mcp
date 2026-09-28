// A person's autonomy rules: the shape, the limits and the one parser (Phase
// 28, D-03, D-05 as revised, D-08, D-29).
//
// A rule says "when a new inbox message looks like this, flag it, or place a
// draft reply to its sender in these words". It matches only on the sender's
// address, the sender's domain and words in the subject. Nothing in a message
// is ever read as an instruction, because nothing here interprets text: it is
// plain comparison (PITFALLS #41).
//
// THE PARSER IS STRICT. An unknown key anywhere is refused, never ignored. A
// rule type with an open action field is how a rule set grows a third action
// without anyone deciding it (PITFALLS #42). The action list is closed at two:
// the flag, and the draft reply.
//
// A RULE'S DRAFT TAKES ONLY TEXT (D-29). It is always a reply to the matching
// message's sender, so it has no recipient, no subject, no copy and no HTML of
// its own. Each of those keys gets its own refusal that says so, rather than the
// general unknown-key one, because a person who writes one of them has a
// reasonable idea of what a draft is and deserves to be told the real shape.
//
// No runtime import, on purpose: the object, the job and the rules tool all read
// this file, and it must stay a leaf.

/** The version of the stored rule shape. */
export const RULE_VERSION = 1;

/** The most rules one person may hold (D-08). */
export const MAX_RULES = 20;

/** The most values in one condition kind, and the fewest (D-03). */
export const MAX_VALUES_PER_KIND = 10;

/** The most characters of one address, per RFC 5321's path limit. */
export const MAX_ADDRESS_CHARS = 254;

/** The most characters of one subject word, and the fewest is one (D-03). */
export const MAX_SUBJECT_WORD_CHARS = 100;

/** The most characters of a draft's text, and the fewest is one (D-05 as revised). */
export const MAX_DRAFT_TEXT_CHARS = 2000;

/** A rule's draft: the rule's own words, and nothing else (D-05 as revised, D-29). */
export interface RuleDraft {
  readonly text: string;
}

/**
 * What a rule matches on. Every kind present must match; any value within a
 * kind. `fromAddresses` are whole addresses, lower-cased. `fromDomains` match
 * the domain or any subdomain of it, lower-cased. `subjectContains` are words
 * found anywhere in the subject, compared after NFKC and lower-casing.
 */
export interface RuleWhen {
  readonly fromAddresses?: readonly string[];
  readonly fromDomains?: readonly string[];
  readonly subjectContains?: readonly string[];
}

/** What a rule does. At least one of the two. */
export interface RuleThen {
  readonly flag?: true;
  readonly draft?: RuleDraft;
}

/** A rule as a caller writes it, before the object stamps it. */
export interface RuleBody {
  readonly when: RuleWhen;
  readonly then: RuleThen;
}

/**
 * A stored rule. `id` and `createdAt` are the object's, never a caller's:
 * `createdAt` is the object's clock when it stored the rule, in milliseconds,
 * and a message received before it never matches the rule (D-03).
 */
export interface Rule extends RuleBody {
  readonly v: typeof RULE_VERSION;
  readonly id: string;
  readonly createdAt: number;
}

/** Why a rule was refused. A closed list. */
export type RuleRefusal =
  | "not-an-object"
  | "unknown-key"
  | "no-condition"
  | "bad-values"
  | "bad-address"
  | "bad-domain"
  | "bad-subject-word"
  | "no-action"
  | "bad-flag"
  | "draft-not-reply"
  | "bad-draft-text";

/** The fixed sentence each refusal answers with. Plain words, no value from the input. */
const REFUSAL_REASONS: Readonly<Record<RuleRefusal, string>> = Object.freeze({
  "not-an-object": "A rule is an object with a when part and a then part.",
  "unknown-key":
    "The rule has a field this server does not know. Only the listed fields are accepted.",
  "no-condition": "A rule needs at least one condition in its when part.",
  "bad-values": `Each condition holds between 1 and ${MAX_VALUES_PER_KIND} values.`,
  "bad-address": "Each sender address must be one plain address, like name@example.com.",
  "bad-domain": "Each sender domain must be a plain domain, like example.com.",
  "bad-subject-word": `Each subject word is between 1 and ${MAX_SUBJECT_WORD_CHARS} characters, on one line.`,
  "no-action": "A rule must flag the message, place a draft reply, or both.",
  "bad-flag": "The flag, when given, can only be true. A rule never clears a flag.",
  "draft-not-reply":
    "A rule's draft is always a reply to the sender of the matching message, and takes only text. It has no recipients, subject, copies or HTML of its own.",
  "bad-draft-text": `A draft's text is between 1 and ${MAX_DRAFT_TEXT_CHARS} characters, with no invisible, direction-changing or control characters except line breaks.`,
});

/** The keys a draft may not carry, each refused with the reply sentence (D-29). */
const NOT_REPLY_KEYS: readonly string[] = Object.freeze(["to", "subject", "cc", "bcc", "html"]);

/** What `parseRule` answers. */
export type RuleParse =
  | { readonly ok: true; readonly rule: RuleBody }
  | { readonly ok: false; readonly refusal: RuleRefusal; readonly reason: string };

/** Characters an address may never hold: controls, spaces and the header specials. */
const NOT_IN_ADDRESS = /[\u0000- \u007f()<>[\]:;@\\,"]/;

/**
 * Characters that change how an address LOOKS without being seen (28-REVIEW
 * WR-07): every "other" character (controls, format characters such as the
 * bidi embeddings, overrides, isolates and marks, the zero-width characters and
 * the byte-order mark, surrogates, private use, unassigned), every separator
 * (the no-break and ideographic spaces, the line and paragraph separators),
 * and every default-ignorable one (the combining grapheme joiner, the Hangul
 * fillers and the rest).
 *
 * The safety case for replying to the From address is that the person sees the
 * address before sending. A right-to-left override in the local part reverses
 * how the rest of the address is shown, domain included, so a stranger could
 * make their own address look like a trusted one in the draft. The domain is
 * already letters, digits and hyphens only. A letter from another script is
 * still allowed: it is visible, and refusing it would refuse real people.
 */
const HIDDEN_IN_ADDRESS = /[\p{C}\p{Z}\p{Default_Ignorable_Code_Point}]/u;

/**
 * Characters a draft's text may not hold (28-REVIEW-2 IN-01): every control
 * character but the line break, every format character (the direction marks,
 * embeddings, overrides and isolates, the zero-width space, the word joiner,
 * the invisible operators, the soft hyphen, the byte-order mark, the tag
 * characters), private use, surrogates, unassigned code points, the line and
 * paragraph separators, and every other default-ignorable one (the Hangul
 * fillers, the combining grapheme joiner).
 *
 * WHY. The rule's confirmation line says "Each reply says, in full: '...'",
 * and the line drops exactly these characters before it quotes the words
 * (`foldedForSentence` in `src/confirm.ts`), because they can reorder the rest
 * of the sentence or hide inside it. The draft is built from the text as
 * stored. So a text holding one read one way in the line the person approved
 * and another way in the draft that goes out under their name. Refused here,
 * the line and the draft carry the same characters; the line's fold is then a
 * second guard, not the thing that makes them differ.
 *
 * KEPT, on purpose: the line break (it folds to a space in the line and stays
 * a line break in the draft, and every word is still shown), the zero-width
 * non-joiner and joiner (Persian, Arabic and the Indic scripts spell with them,
 * emoji sequences are built with them, and they neither move nor hide text),
 * and the variation selectors (they pick a character's glyph, such as an
 * emoji's colour form). Decided by Claude, owner may revise.
 */
const HIDDEN_IN_TEXT =
  /(?![\n\r\u200c\u200d\u180b-\u180d\u180f\ufe00-\ufe0f\u{e0100}-\u{e01ef}])[\p{Control}\p{Format}\p{Private_Use}\p{Surrogate}\p{Unassigned}\p{Line_Separator}\p{Paragraph_Separator}\p{Default_Ignorable_Code_Point}]/u;

/** One domain label: letters, digits and inner hyphens, 1 to 63 characters. */
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** Whether `value` is a domain of two or more labels. */
function isDomain(value: string): boolean {
  const labels = value.split(".");
  return labels.length >= 2 && labels.every((label) => LABEL.test(label));
}

/**
 * Whether `value` is ONE bare address: a local part, one `@`, and a domain of
 * two or more labels. No display name, no angle brackets, no spaces, no line
 * breaks, no second `@`, and no character that changes how the address looks
 * without being seen (28-REVIEW WR-07).
 *
 * The one check both a rule's sender addresses and a reply's recipient go
 * through (D-30), so what a rule may name and what a reply may be sent to are
 * the same set.
 */
export function isBareAddress(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length < 3 || value.length > MAX_ADDRESS_CHARS) return false;
  const at = value.indexOf("@");
  if (at < 1 || at !== value.lastIndexOf("@")) return false;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.length > 64 || NOT_IN_ADDRESS.test(local) || HIDDEN_IN_ADDRESS.test(local)) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return false;
  return isDomain(domain);
}

/** Whether `value` is a plain object, not an array and not null. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Whether `value` holds only keys from `allowed`. */
function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

class Refused {
  constructor(readonly refusal: RuleRefusal) {}
}

/**
 * A list of 1 to 10 values, each checked and normalised by `each`, which
 * answers null for a value it refuses; that value is refused as `bad`.
 */
function valuesOf(
  value: unknown,
  each: (one: unknown) => string | null,
  bad: RuleRefusal,
): string[] {
  if (!Array.isArray(value)) throw new Refused("bad-values");
  if (value.length < 1 || value.length > MAX_VALUES_PER_KIND) throw new Refused("bad-values");
  return value.map((one) => {
    const out = each(one);
    if (out === null) throw new Refused(bad);
    return out;
  });
}

/** A sender address, lower-cased, or null. */
function addressValue(one: unknown): string | null {
  return isBareAddress(one) ? one.toLowerCase() : null;
}

/** A sender domain, lower-cased, or null. */
function domainValue(one: unknown): string | null {
  if (typeof one !== "string" || one.length > MAX_ADDRESS_CHARS) return null;
  return isDomain(one) ? one.toLowerCase() : null;
}

/** Any control character, a line break among them. */
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * Text as the matcher compares it: NFKC, then lower case. The matcher applies
 * the same two steps to the subject, and has its own copy because it may not
 * import at run time; the parser's tables pin the pair.
 */
function comparableText(text: string): string {
  return text.normalize("NFKC").toLowerCase();
}

/** A subject word, normalised, or null. One line, 1 to 100 characters. */
function subjectWordValue(one: unknown): string | null {
  if (typeof one !== "string" || CONTROL.test(one)) return null;
  const word = comparableText(one);
  return word.length >= 1 && word.length <= MAX_SUBJECT_WORD_CHARS ? word : null;
}

function whenOf(value: unknown): RuleWhen {
  if (!isPlainObject(value)) throw new Refused("no-condition");
  if (!onlyKeys(value, ["fromAddresses", "fromDomains", "subjectContains"])) {
    throw new Refused("unknown-key");
  }
  const when: { fromAddresses?: string[]; fromDomains?: string[]; subjectContains?: string[] } = {};
  if (value.fromAddresses !== undefined) {
    when.fromAddresses = valuesOf(value.fromAddresses, addressValue, "bad-address");
  }
  if (value.fromDomains !== undefined) {
    when.fromDomains = valuesOf(value.fromDomains, domainValue, "bad-domain");
  }
  if (value.subjectContains !== undefined) {
    when.subjectContains = valuesOf(value.subjectContains, subjectWordValue, "bad-subject-word");
  }
  if (Object.keys(when).length === 0) throw new Refused("no-condition");
  return when;
}

function draftOf(value: unknown): RuleDraft {
  if (!isPlainObject(value)) throw new Refused("bad-draft-text");
  if (Object.keys(value).some((key) => NOT_REPLY_KEYS.includes(key))) {
    throw new Refused("draft-not-reply");
  }
  if (!onlyKeys(value, ["text"])) throw new Refused("unknown-key");
  const text = value.text;
  if (typeof text !== "string" || text.length < 1 || text.length > MAX_DRAFT_TEXT_CHARS) {
    throw new Refused("bad-draft-text");
  }
  if (HIDDEN_IN_TEXT.test(text)) throw new Refused("bad-draft-text");
  return { text };
}

function thenOf(value: unknown): RuleThen {
  if (!isPlainObject(value)) throw new Refused("no-action");
  if (value.draft !== undefined && isPlainObject(value.draft)) {
    // The reply refusal outranks an unknown key beside it, so its sentence is
    // the one a person who wrote a recipient actually reads.
    if (Object.keys(value.draft).some((key) => NOT_REPLY_KEYS.includes(key))) {
      throw new Refused("draft-not-reply");
    }
  }
  if (!onlyKeys(value, ["flag", "draft"])) throw new Refused("unknown-key");
  const then: { flag?: true; draft?: RuleDraft } = {};
  if (value.flag !== undefined) {
    if (value.flag !== true) throw new Refused("bad-flag");
    then.flag = true;
  }
  if (value.draft !== undefined) then.draft = draftOf(value.draft);
  if (then.flag === undefined && then.draft === undefined) throw new Refused("no-action");
  return then;
}

/**
 * Parse a rule a caller wrote: `{ when, then }` and nothing else (D-03).
 *
 * Answers the normalised rule (addresses lower-cased) or one refusal from a
 * closed list, with a fixed sentence. A caller never supplies `v`, `id` or
 * `createdAt`: the object stamps those, so a caller cannot choose a rule's age
 * and reach mail from before it existed. Never throws.
 */
export function parseRule(input: unknown): RuleParse {
  try {
    if (!isPlainObject(input)) throw new Refused("not-an-object");
    if (!onlyKeys(input, ["when", "then"])) throw new Refused("unknown-key");
    const when = whenOf(input.when);
    const then = thenOf(input.then);
    return { ok: true, rule: { when, then } };
  } catch (err) {
    const refusal = err instanceof Refused ? err.refusal : "not-an-object";
    return { ok: false, refusal, reason: REFUSAL_REASONS[refusal] };
  }
}

/**
 * A stored value as a rule, or null when it is not exactly one.
 *
 * The object reads its stored rules through this, so a value that no longer
 * parses (an older shape, a hand edit) is dropped rather than acted on.
 */
export function storedRuleOf(value: unknown): Rule | null {
  if (!isPlainObject(value)) return null;
  if (!onlyKeys(value, ["v", "id", "createdAt", "when", "then"])) return null;
  if (value.v !== RULE_VERSION) return null;
  if (typeof value.id !== "string" || value.id.length < 1 || value.id.length > 64) return null;
  if (typeof value.createdAt !== "number" || !Number.isFinite(value.createdAt)) return null;
  const parsed = parseRule({ when: value.when, then: value.then });
  if (!parsed.ok) return null;
  return { v: RULE_VERSION, id: value.id, createdAt: value.createdAt, ...parsed.rule };
}
