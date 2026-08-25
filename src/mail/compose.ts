// The message builder: inputs in, RFC 5322 bytes out. Pure and socket-free.
//
// The inverse of `./mime.ts`, and structured to match it. That module turns raw
// bytes into a decoded message; this one turns a caller's fields into the raw
// bytes a mailbox stores. It imports nothing from `./service`, `./socket` or
// `./imap-session`, so like `./imap-parser.ts` and `./mime.ts` it unit-tests
// against literal values with nothing stood up — which is where the coverage in
// this phase belongs, because the protocol has no local emulator on this stack.
//
// The one place in this project where hand-rolling beats a library, and the
// reason is recorded rather than assumed: every candidate builder on npm drags
// in a Node-era dependency tree (a polyfill bundle, a media-type data table, or
// an unmaintained parser stack) to avoid a few hundred lines of mechanical
// string templating. The mitigation for hand-rolling is this module's purity —
// see 04-RESEARCH.md § 3.6 for the costed comparison.
//
// **The central hazard is that every way of getting this wrong still succeeds.**
// PITFALLS #8's defining property is that a missing draft flag, a blank message
// id, a bare newline, or a byte count taken off a string's `.length` all produce
// a message the server accepts without complaint and a client renders wrong.
// Nothing here can be validated by "it worked" — hence the returned-refusal
// shape below, and hence a test file that reads its own output back through the
// parser rather than eyeballing a byte dump.
//
// Decisions this module implements: D-71 (the quoted original under an
// attribution line), D-73 (a stranger's markup passes through unmodified, which
// is what makes the boundary check adversarial rather than probabilistic), D-74
// (the caller authors both body halves; nothing derives one from the other),
// D-75 (either half alone is legal, or both).
//
// The ONE import, and it is deliberate: `htmlToText` from `./mime.ts`. The
// plain half of a quoted original has to render a stranger's markup as text,
// and that converter already ships — it is `HTMLRewriter`-based, it was probed
// rather than assumed, and it has been exercised against 239 KB, 78 KB and
// 64 KB of real stranger-authored markup. A second converter written here would
// be a second set of the same edge cases, diverging quietly. Nothing else is
// imported: this module still opens no socket and still knows nothing about a
// session.
//
// This module contains no logging calls of any kind and must never acquire any.

import { htmlToText } from "./mime";

const ENCODER = new TextEncoder();

/** The one line ending this module emits. Never a bare newline, anywhere. */
const CRLF = "\r\n";

/**
 * The characters that cannot appear inside a header value at all.
 *
 * The same three `./credentials.ts` refuses one layer over, refused here for a
 * transposition of the same reason: CR or LF terminates the header line early
 * and injects a SECOND header built from the caller's own bytes, and NUL has no
 * representation in the grammar at all. On this path the injected header is
 * `Bcc:` — a caller-authored recipient on a message the user will later send —
 * which is the highest-consequence version of the failure in this codebase.
 *
 * Refusing beats escaping for the reason `./credentials.ts` and
 * `../dav/transport.ts` both give: escaping produces a value the peer rejects,
 * and the user is then told something false about which part was wrong.
 */
const ILLEGAL_IN_HEADER_VALUE = /[\r\n\x00]/;

/**
 * The same three, plus the space, for the address itself.
 *
 * An addr-spec is `local@domain` and has no space in it, so a value carrying one
 * is not an address that needs escaping — it is a different thing being passed
 * in the address position, most likely the display-name form `Jane <j@x>`.
 * Parsing that apart would be repair, and repair is what this module does not
 * do; refusing names the real problem and the caller can supply a bare address.
 * `../dav/transport.ts` refuses the space in a header value on the same footing.
 */
const ILLEGAL_IN_ADDRESS = /[\r\n\x00 ]/;

/** Whether a value is pure printable US-ASCII and so needs no encoding. */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** Whether a value carries any byte outside US-ASCII. */
const NON_ASCII = /[^\x00-\x7f]/;

/**
 * The RFC 5322 `specials`, which force a display name into a quoted string.
 *
 * A name containing any of these is not a bare `atom` sequence, so emitting it
 * unquoted produces a field the peer parses as something other than a name —
 * `Doe, Jane <j@x>` reads as two addresses, one of which does not exist.
 */
const RFC5322_SPECIALS = /[()<>@,;:\\".[\]]/;

/**
 * The assembled-message ceiling, above which the build refuses.
 *
 * **CALIBRATED, NOT MEASURED**, and that sentence is first for the reason
 * `MAX_WIRE_MESSAGE_BYTES` in `./service.ts` gives for its own: a reader who
 * believes this number was measured against real messages will never revisit
 * it, and it has not been. It is derived from two things this project does
 * know and from nothing else.
 *
 * The arithmetic. Apple's published per-message limit for iCloud Mail is 20 MB,
 * read off the support page and transcribed in `04-UAT.md` rather than
 * search-derived. Wrapped base64 inflates a source file by a measured 1.3684 —
 * the often-quoted "~33%" is the UNWRAPPED figure, and the wrapping adds
 * another 2.7 points to what actually goes on the wire. So 20 MB ÷ 1.3684 is
 * roughly 14.6 MB of source before headers and before the quoted original a
 * reply carries. Twelve mebibytes sits under that with room for two attachments
 * and a long quoted thread.
 *
 * **What the number buys is WHERE the failure lands.** Without a ceiling here,
 * an oversized draft is accepted, stored, and rejected by Apple at send time —
 * in the user's mail client, hours later, with nothing connecting it back to
 * the tool call that built it. With one, the refusal arrives in the same
 * response as the request, carrying both numbers.
 *
 * On trip it REFUSES and never raises. Adding a fifth error category for "too
 * big" was considered and rejected: FND-05 closed the vocabulary at four values
 * and phases 3 through 6 all inherit it. See `BuildResult` for the shipped
 * precedent this refusal shape copies.
 */
export const MAX_APPEND_LITERAL_BYTES = 12 * 1024 * 1024;

/**
 * The longest line this module will emit without reaching for base64.
 *
 * RFC 5322's hard limit is 998 octets. The margin below it is deliberate rather
 * than superstitious: the check runs on a part's content, and a part is
 * rendered under a header block whose own lines are counted separately, so a
 * value sitting exactly at the limit has no room for the encoder to be wrong.
 */
const MAX_LINE_OCTETS = 990;

/** How many characters of base64 go on one line. RFC 2045's own figure. */
const BASE64_LINE_LENGTH = 76;

/**
 * How many source bytes the encoder converts per call into the binary string.
 *
 * `./credentials.ts` builds its binary string one character at a time, which is
 * correct and entirely fine for a forty-byte credential and quadratic-ish for a
 * megabyte body. **Do not copy that loop here.** A spread call over the whole
 * array is the other wrong answer: it blows the argument-count limit on a large
 * body. Chunked subarrays are the shape that is neither.
 */
const BASE64_CHUNK_BYTES = 0x8000;

/**
 * The most source bytes one encoded-word may carry.
 *
 * RFC 2047 §2 caps an encoded-word at 75 characters INCLUDING its delimiters.
 * The delimiters here are twelve characters, and base64 emits four characters
 * per three source bytes — so fifteen whole groups is 45 source bytes, 60
 * characters of base64, and 72 characters in total. Sixteen groups would be 76
 * and over the line.
 *
 * Counting whole groups rather than dividing and hoping is what keeps the
 * padding from pushing a word over: a partial group still costs four
 * characters.
 */
const ENCODED_WORD_SOURCE_BYTES = 45;

/** The boundary prefix. The leading hyphens make a delimiter line unmistakable. */
const BOUNDARY_PREFIX = "----=_iCloudMCP_";

/**
 * The characters RFC 5987 lets an extended parameter value carry unencoded.
 *
 * `attr-char` from that grammar, exactly: the alphanumerics plus a fixed
 * punctuation set. Everything outside it — the space and the percent sign
 * included — is percent-encoded, which is what makes the encoder's output
 * unambiguous to the decoder `./mime.ts` already ships.
 */
const ATTR_CHAR = /^[A-Za-z0-9!#$&+\-.^_`|~]$/;

/**
 * The characters the PLAIN parameter's quoted string may carry unchanged.
 *
 * Printable US-ASCII minus the double quote and the backslash, which end and
 * escape a `quoted-string` respectively. Anything outside becomes an
 * underscore — see `contentDispositionParams` for why that substitution is not
 * a lossy repair.
 */
const QUOTABLE_ASCII = /^[\x20-\x21\x23-\x5b\x5d-\x7e]$/;

/**
 * A conservative media type: two tokens either side of one slash.
 *
 * The same shape `../staging/r2.ts` uses for the type it writes into a stored
 * header, and here for the same reason one layer over: an attachment's declared
 * type is sender-authored on the from-message path, and it lands in a header of
 * a message the user will send.
 */
const MEDIA_TYPE =
  /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;

/** What an unusable declared type becomes. Says nothing about the bytes. */
const DEFAULT_MEDIA_TYPE = "application/octet-stream";

/**
 * The shape a `msg-id` has to have before it may reach a threading header.
 *
 * `<` then at least one character that is neither an angle bracket nor
 * whitespace, then `>`. Deliberately narrower than RFC 5322's own `msg-id`
 * production, which admits comments, folding whitespace and quoted local parts:
 * this pattern is a GATE on a stranger-authored value, not a parser for one, and
 * the narrow shape is what makes a token that passes it unable to carry a
 * sentence — there is nowhere in it for a space.
 *
 * That property is load-bearing twice over. It is why a token that passes may be
 * emitted into a header of a message the user will send, and it is why the
 * parent's id may be reported in the TRUSTED half of the compose response:
 * a value with no whitespace in it cannot carry an instruction.
 */
const REFERENCE_TOKEN = /^<[^<>\s]+>$/;

/**
 * RFC 5322's hard per-line ceiling, in octets, including the CRLF's absence.
 *
 * Unlike `MAX_LINE_OCTETS` above there is no margin here, because this bound is
 * applied to a header the folder controls completely: it knows the field name's
 * width, it knows each token's width, and it inserts the fold itself. A margin
 * would be a guess standing in for arithmetic that is available.
 *
 * **"Controls completely" is true only because a token too wide to fold is
 * DROPPED.** The folder chooses where the folds go; it does not choose how wide
 * a stranger's message id is, and inserting a fold inside one would corrupt it.
 * See `MAX_REFERENCE_TOKEN_OCTETS`, which is what makes the sentence above hold
 * rather than nearly hold.
 */
const MAX_HEADER_LINE_OCTETS = 998;

/** The field name whose folding budget the folder has to account for. */
const REFERENCES_FIELD = "References";

/**
 * The widest a single `msg-id` may be and still be foldable.
 *
 * The FIRST line's budget, which is the tighter of the two: it pays for the
 * field name and the `: ` after it, where a continuation line pays only for the
 * single space that marks it as one. Measuring against the tighter number gives
 * one invariant that holds everywhere — a token that survives this fits on any
 * line the folder can start — which is what makes both of the folder's
 * "start a new line with this token" branches safe without a check of their own.
 *
 * Deliberately conservative by the eleven octets between the two budgets. A
 * message id in that band is not a case anyone will meet, and one bound that is
 * true everywhere is worth more than two that are each true somewhere.
 */
const MAX_REFERENCE_TOKEN_OCTETS =
  MAX_HEADER_LINE_OCTETS - REFERENCES_FIELD.length - 2;

/**
 * A leading run of the ASCII reply prefix family, in any casing.
 *
 * Covers `Re:`, `RE:`, `re:`, a bracketed counter (`Re[2]:`), stray spacing on
 * either side of the colon, and any number of them stacked. Exported so the rule
 * itself is inspectable rather than only its effect.
 *
 * **Nothing localised is in it and nothing localised should be added.** See
 * `replySubject` for why that is a decision rather than an omission.
 */
export const RE_PREFIX = /^(?:\s*[Rr][Ee](?:\[\d+\])?\s*:\s*)+/;

/** Day names, in a fixed English table. Never a locale-aware formatter. */
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** Month names, same table, same reason. */
const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/**
 * One file travelling with a draft.
 *
 * **Assembled, not merely declared.** An earlier slice wired this field and
 * validated the filename while nothing could supply one; the `multipart/mixed`
 * outer wrap around whichever of the three body trees below was built now
 * exists, and `../mcp/tools/mail.ts` fills this from the staging bucket.
 *
 * **Every field here is untrusted on the from-message path.** The filename and
 * the declared media type were both chosen by whoever sent the message the file
 * was copied out of, and both land in headers of a message the user will send.
 * The filename is refused outright for CR, LF and NUL and otherwise emitted in
 * the two parameter forms `contentDispositionParams` builds; the media type is
 * metadata rather than a gate, so an unusable one is replaced with a neutral
 * value rather than refusing the whole draft.
 */
export interface DraftAttachment {
  /** The name the file is offered under. Refused, never repaired. */
  filename: string;
  /** The declared media type. Never verified against the bytes. */
  mimeType: string;
  /** The decoded file, exactly as it will be base64-encoded. */
  content: Uint8Array;
}

/**
 * The parent, in the shape a reply needs to quote it.
 *
 * Structurally a subset of `ParsedMessage` in `./mime.ts`, on purpose: the fetch
 * that produced the parent already returns exactly these fields, so the caller
 * hands the parsed message straight in rather than copying it field by field
 * into a second shape that can drift from the first.
 *
 * **Every string here is stranger-authored**, which is the same sentence
 * `ParsedMessage` carries and it is repeated rather than referenced because this
 * is where those values stop being something the user reads and start being
 * something the user SENDS.
 */
export interface QuotedSource {
  /** The parent's own `Date` header, as the parser rendered it. */
  date: string | null;
  /** The sender's display name, exactly as they chose it. */
  fromName: string | null;
  /** The sender's address, as the message declares it. */
  fromAddress: string | null;
  /** The parent's readable body. */
  text: string;
  /** The parent's raw HTML part, when it had one. */
  html: string | null;
  /** Which part `text` came from, or `null` when no part was chosen. */
  bodySource: "text/plain" | "text/html" | null;
}

/**
 * The quoted original, resolved: one attribution line and two renditions.
 *
 * Separated from `QuotedSource` because resolving it is ASYNCHRONOUS — the plain
 * rendition of an HTML parent runs through `HTMLRewriter` — while `buildDraft`
 * is synchronous and stays that way. Splitting the two keeps every byte-level
 * assertion in this module against a function that takes literal values and
 * returns literal bytes.
 */
export interface QuotedOriginal {
  /** `On {date}, {name} wrote:` — authored HERE, from values a stranger chose. */
  attribution: string;
  /** The parent as plain text, converted if its chosen part was markup. */
  text: string;
  /** The parent's raw markup, or `null`. Emitted UNMODIFIED (D-73). */
  html: string | null;
}

/** Everything one draft is built from. */
export interface DraftInput {
  /**
   * The authoring identity.
   *
   * Resolved from the environment by `draftFromAddress` in `./credentials.ts`
   * and never caller-supplied: a caller-supplied `From` is a caller-supplied
   * identity, on a message that will be sent under the user's own name.
   */
  from: string;
  /** Primary recipients, as bare addresses. Caller-authored. */
  to: string[];
  /** Copied recipients. Empty means the header is omitted entirely. */
  cc: string[];
  /** The subject line, encoded only if it needs to be. Caller-authored. */
  subject: string;
  /**
   * The plain-text half, or `null`.
   *
   * D-74: the caller authors both halves and nothing derives one from the
   * other. **Nothing enforces that the two say the same thing** — that is the
   * decision's stated and accepted cost, not an omission here.
   */
  text: string | null;
  /** The markup half, or `null`. Same authorship rule as `text`. */
  html: string | null;
  /** The parent's message id. Wired here; supplied by plan 04-04. */
  inReplyTo: string | null;
  /** The thread's reference chain. Wired here; supplied by plan 04-04. */
  references: string[];
  /** Files to travel with the draft. See `DraftAttachment`. */
  attachments: DraftAttachment[];
  /**
   * The original this draft replies to, or `null` for a new message.
   *
   * D-71. It goes into BOTH body halves, under the attribution line, and it is
   * what makes the draft the thing Mail.app would have produced had the user hit
   * Reply themselves — a reply without it is one the user has to notice and fix
   * before sending.
   *
   * **Its accepted cost is size.** The append literal grows by the whole quoted
   * thread, and D-36 keeps quoted history verbatim, so a long chain compounds
   * with every round. `MAX_APPEND_LITERAL_BYTES` is what bounds it, and the
   * refusal it produces hands back both numbers rather than a sentence.
   */
  quoted: QuotedOriginal | null;
  /**
   * The instant the draft is dated.
   *
   * **Injected, never read inside**, so the output is deterministic under test
   * and cannot vary with the host's own clock or zone. This is `IMAP_MONTHS`'s
   * fixed-English-table rule in `./service.ts` applied one field over, and it
   * sidesteps the host-timezone hazard `src/dav/` carries a whole scan rule
   * about: there, the failure is not an exception but silently wrong times.
   */
  now: Date;
}

/**
 * Why a build produced no bytes. Every value names a caller-fixable cause.
 *
 * **`no-recipients` is a distinct member rather than a reuse of
 * `recipient-illegal-characters`**, because the two ask the caller for
 * different things: one says a recipient you gave me cannot travel, the other
 * says you gave me none and none could be derived. On the reply path the second
 * is not a caller mistake at all — it is a parent whose sender the parser could
 * not read — and telling the model its addresses contain illegal characters
 * when it supplied no addresses is a wrong statement it cannot act on.
 *
 * This union is this builder's OWN and is not `ErrorCategory`. D-35 closed the
 * error vocabulary at four values and that is untouched here: a refusal is a
 * field on a successful call, which is the whole reason this type exists.
 */
export type BuildRefusal =
  | "message-too-large"
  | "no-recipients"
  | "recipient-illegal-characters"
  | "references-illegal-characters"
  | "filename-illegal-characters";

/**
 * What a build produced: bytes, or a stated reason there are none.
 *
 * **A discriminated result rather than a raise**, and this is the shipped
 * `unsupportedCharset` precedent applied to a write path. `searchPage` in
 * `./service.ts:1765-1770` reports a charset rejection rather than raising it,
 * with the argument that "the search RAN; the server declined the encoding;
 * none of the four categories in the closed vocabulary describes that." The
 * same holds here: the build ran and produced a stated answer, and neither
 * `not_found` nor `connection_failed` describes an oversized message or an
 * address carrying a carriage return.
 *
 * D-35's rejection of a fifth error category is unchanged by this and is not
 * being worked around. A refusal is a FIELD on a successful call, which is what
 * hands the model the two numbers it needs to explain the problem rather than a
 * sentence it has to parse.
 */
export type BuildResult =
  | {
      built: true;
      bytes: Uint8Array;
      /**
       * The id this draft actually threads under, or `null`.
       *
       * What was EMITTED, not what was asked for: a parent id that was absent
       * or malformed yields `null` here even though one was supplied. On a path
       * where every failure mode returns a successful write, the difference
       * between "you asked me to thread this" and "it threads" is the whole
       * answer, so the builder reports the second.
       */
      inReplyTo: string | null;
      /** How many tokens the emitted `References` carried. Zero when none was. */
      referencesCount: number;
    }
  | {
      built: false;
      refusal: BuildRefusal;
      /** The assembled size, on a size refusal only. */
      sizeBytes?: number;
      /** The ceiling it exceeded, on a size refusal only. */
      limitBytes?: number;
    };

/** One MIME entity: its own headers, and its already-encoded body. */
interface MimeEntity {
  /** Content headers, without the blank line that follows them. */
  headers: string[];
  /** The body as it will appear on the wire, transfer-encoding applied. */
  body: string;
}

/** Two digits, zero-padded. */
function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/**
 * Base64 over raw bytes, chunked.
 *
 * The runtime's built-in is used rather than a hand-rolled alphabet table, for
 * the reason `./credentials.ts` states: an alphabet table is a thing to get
 * wrong for no gain. What differs from that module is only the loop — see
 * `BASE64_CHUNK_BYTES`.
 *
 * Takes bytes rather than a string, so the caller is forced to decide the
 * encoding before reaching here. Handing a JavaScript string to the runtime's
 * primitive encodes UTF-16 code units, which is wrong for every non-ASCII byte
 * and is the same class of bug as measuring a wire length in code units.
 */
function base64Of(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += BASE64_CHUNK_BYTES) {
    binary += String.fromCharCode(
      ...bytes.subarray(index, index + BASE64_CHUNK_BYTES),
    );
  }
  return btoa(binary);
}

/** Break a base64 run into wire-length lines. */
function wrapBase64(encoded: string): string {
  const lines: string[] = [];
  for (
    let index = 0;
    index < encoded.length;
    index += BASE64_LINE_LENGTH
  ) {
    lines.push(encoded.slice(index, index + BASE64_LINE_LENGTH));
  }
  return lines.join(CRLF);
}

/**
 * Reduce every line ending to CRLF.
 *
 * Applied to a part's content before anything is counted or encoded. PITFALLS
 * #8 names this as "a classic bug source when message construction happens in a
 * JS/TS environment that defaults to `\n`", and the structural defence is that
 * this module never concatenates a bare newline anywhere: line lists are joined
 * with `CRLF`, and caller-authored content passes through here.
 */
function toCrlf(value: string): string {
  return value.replace(/\r\n|\r|\n/g, CRLF);
}

/**
 * Whether a part's content must be base64 rather than `7bit`.
 *
 * **The line length is the binding constraint, not the character set**, and
 * that ordering is the reason there is no quoted-printable implementation in
 * this module at all. D-73 passes a stranger's markup through unmodified, and
 * real marketing HTML routinely carries single lines in the tens of kilobytes;
 * `7bit` on such a part produces a message some servers reject outright and
 * some clients render wrong, whatever its character set.
 *
 * The three reasons quoted-printable was declined, recorded so the decision
 * does not read as an oversight:
 *
 * 1. It does not solve the binding constraint any better than base64 does,
 *    while base64 wraps at a fixed column unconditionally and makes the whole
 *    class disappear.
 * 2. It is four independent ways to be silently wrong — the soft line break,
 *    the trailing-whitespace rule, the escape set, and the rule against
 *    splitting an escape triplet across a soft break.
 * 3. Its only advantage is that a raw dump of the message stays readable, which
 *    matters to exactly one developer and to zero end users.
 */
function needsBase64(content: string): boolean {
  if (NON_ASCII.test(content)) return true;
  for (const line of content.split(CRLF)) {
    if (line.length > MAX_LINE_OCTETS) return true;
  }
  return false;
}

/** One encoded-word over a run of source characters. */
function encodedWord(source: string): string {
  return `=?UTF-8?B?${base64Of(ENCODER.encode(source))}?=`;
}

/**
 * Encode one header's text, if it needs encoding at all.
 *
 * **Raw when the value is pure printable US-ASCII.** That is not an
 * optimisation: it keeps the common case legible in a raw dump of the message,
 * which is the difference between a debuggable write path and an undebuggable
 * one on a path whose failures are otherwise silent.
 *
 * **B-encoding rather than Q**, and the reason is surface area. B reuses the
 * one base64 primitive the attachment path needs anyway. Q needs a per-character
 * escape table with distinct variants for the phrase and comment contexts,
 * which is precisely the shape `./mime.ts` declines to reimplement on the read
 * side.
 *
 * **The split runs on CHARACTER boundaries, before the encoding.** Splitting
 * the encoded output at a byte boundary cuts a multi-byte sequence in half and
 * produces mojibake in every client — and it only reproduces for values long
 * enough to need a second word, so it survives every short test. Iterating the
 * string with `for…of` walks code POINTS, so an astral character stays whole
 * where a code-unit walk would halve its surrogate pair.
 *
 * Words are joined with a single space. RFC 2047 requires linear whitespace
 * between adjacent encoded-words and specifies that a decoder drops it, which
 * the read side's own `decodeWords` was confirmed to do before this shape was
 * chosen.
 */
export function encodeHeaderText(value: string): string {
  if (PRINTABLE_ASCII.test(value)) return value;

  const words: string[] = [];
  let pending = "";
  let pendingBytes = 0;

  for (const character of value) {
    const size = ENCODER.encode(character).byteLength;
    if (pendingBytes + size > ENCODED_WORD_SOURCE_BYTES) {
      words.push(encodedWord(pending));
      pending = "";
      pendingBytes = 0;
    }
    pending += character;
    pendingBytes += size;
  }
  if (pending.length > 0) words.push(encodedWord(pending));

  return words.join(" ");
}

/**
 * One address field value, or `null` when the inputs cannot make one.
 *
 * The two halves are treated differently on purpose. An encoded-word is legal
 * in the display-name position and **illegal inside the address itself**, so a
 * non-ASCII name is encoded while a non-ASCII address is simply carried — this
 * project's own address is ASCII, and inventing an encoding for the addr-spec
 * would be inventing something the grammar does not have.
 *
 * `null` rather than a raise, so the caller reports which field was wrong.
 */
export function addressField(
  address: string,
  displayName: string | null,
): string | null {
  if (ILLEGAL_IN_ADDRESS.test(address) || address.length === 0) return null;
  if (displayName === null || displayName.length === 0) return address;
  if (ILLEGAL_IN_HEADER_VALUE.test(displayName)) return null;

  if (!PRINTABLE_ASCII.test(displayName)) {
    return `${encodeHeaderText(displayName)} <${address}>`;
  }
  if (RFC5322_SPECIALS.test(displayName)) {
    const quoted = displayName
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"');
    return `"${quoted}" <${address}>`;
  }
  return `${displayName} <${address}>`;
}

/**
 * The `Date` header, in RFC 5322 form and always in UTC.
 *
 * Built from the fixed English tables above and the instant's UTC components,
 * never through a locale-aware formatter and never through a host-zone
 * conversion. `src/dav/` carries a scan rule against exactly the latter, and
 * its rationale transfers unchanged: the failure is not an exception but
 * silently wrong times, so it passes the suite on a developer's machine and is
 * wrong for the user in production.
 */
export function rfc5322Date(now: Date): string {
  const day = DAY_NAMES[now.getUTCDay()];
  const month = MONTH_NAMES[now.getUTCMonth()];

  return (
    `${day}, ${pad2(now.getUTCDate())} ${month} ${now.getUTCFullYear()} ` +
    `${pad2(now.getUTCHours())}:${pad2(now.getUTCMinutes())}:` +
    `${pad2(now.getUTCSeconds())} +0000`
  );
}

/**
 * The `References` chain, folded across as many lines as it needs.
 *
 * **Truncating is the tempting wrong answer, and it is the one that looks like
 * success.** RFC 5322 §3.6.4 permits an implementation to drop tokens from the
 * MIDDLE of a long chain; a client that drops from the END instead breaks the
 * thread for every message that follows, and the append still returns OK. So the
 * chain is never shortened here — it is folded, which is the mechanism the
 * grammar actually provides for a header longer than a line.
 *
 * The fold is `CRLF` then a single space, and the budget is arithmetic rather
 * than a guess: the first line has to carry `References: ` as well, so it gets
 * that much less of the 998-octet ceiling, and every continuation line spends
 * one octet on its leading space. Widths are counted in OCTETS through the
 * encoder, because the ceiling is an octet ceiling and a message id is not
 * guaranteed to be ASCII.
 *
 * **Two dispositions for a bad token, and which one applies is decided by order
 * rather than by shape.** Every token is checked for CR, LF and NUL FIRST, and
 * one carrying any of them refuses the whole header — `null`, which the caller
 * turns into a build refusal. Only then is the angle-bracket shape checked, and
 * a token failing that is dropped.
 *
 * The ordering is the whole subtlety. A token carrying a CR also fails the shape
 * check, so a shape-first implementation would silently DROP it — a repair, and
 * repair is what this module does not do. And the refusal is the right shape
 * here for the reason `quoteMailbox()` gives one layer over: the parent's
 * `References` is stranger-authored, and a CR in a header value terminates the
 * line early and injects a second header — on this path, into a message the user
 * will send under their own name. Stripping it would send a message built partly
 * from an attacker's intent while reporting success.
 */
export function foldReferences(tokens: string[]): string | null {
  const kept: string[] = [];
  for (const token of tokens) {
    if (ILLEGAL_IN_HEADER_VALUE.test(token)) return null;
    if (!REFERENCE_TOKEN.test(token)) continue;
    // **Dropped on the same footing a shape-failing token is dropped, and for
    // a stronger reason: it cannot be folded at all.** `REFERENCE_TOKEN` places
    // no length bound on what sits between the angle brackets, and the parent's
    // `References` is stranger-authored — `parseParentHeaders` splits it on
    // whitespace and nothing else, so a single 2,000-character message id
    // arrives as one token. The loop below starts a fresh line for a token that
    // will not fit beside the previous one, but a token wider than a whole line
    // has nowhere to go, and emitting it breaks RFC 5322's hard 998-octet
    // ceiling on a message the user will SEND. Some MTAs reject an over-long
    // header line outright, which is the same "Apple rejects it hours later in
    // Mail.app" failure the size ceiling exists to avoid.
    //
    // A drop rather than a refusal, because that is what this function already
    // does with a token it cannot emit. The refusal arm is reserved for CR, LF
    // and NUL, where the token is not merely unusable but hostile.
    if (ENCODER.encode(token).byteLength > MAX_REFERENCE_TOKEN_OCTETS) continue;
    kept.push(token);
  }

  const lines: string[] = [];
  let current = "";
  let octets = 0;
  // Every kept token fits within this, which is what lets the two branches
  // below open a line with one unconditionally.
  let budget = MAX_REFERENCE_TOKEN_OCTETS;

  for (const token of kept) {
    const width = ENCODER.encode(token).byteLength;
    if (current.length === 0) {
      current = token;
      octets = width;
      continue;
    }
    if (octets + 1 + width > budget) {
      lines.push(current);
      current = token;
      octets = width;
      // A continuation line spends one octet on the space that marks it as one.
      budget = MAX_HEADER_LINE_OCTETS - 1;
      continue;
    }
    current += ` ${token}`;
    octets += 1 + width;
  }
  if (current.length > 0) lines.push(current);

  return lines.join(`${CRLF} `);
}

/**
 * The four address fields a reply derives its own recipients from.
 *
 * Structurally the address half of `ParentHeaders` in `./service.ts`, declared
 * here rather than imported so this module keeps importing nothing from the
 * session layer. Every list is bare addresses: display names are not carried,
 * because nothing on this path needs one and each would be a second copy of a
 * stranger-authored string.
 */
export interface ReplyAddresses {
  replyTo: string[];
  from: string[];
  to: string[];
  cc: string[];
}

/** What the caller may vary about a reply's recipients. */
export interface ReplyRecipientOptions {
  /** The account's own address, resolved from the binding. Never Cc'd itself. */
  self: string;
  /** D-68. False adds nobody; the reply goes to the sender alone. */
  replyAll: boolean;
  /** D-67's override for `To`. REPLACES the derivation; never adds to it. */
  to?: string[];
  /** D-67's override for `Cc`. Same rule, including under reply-all. */
  cc?: string[];
}

/** One address, in the form two of them are compared by. */
function foldAddress(address: string): string {
  return address.trim().toLowerCase();
}

/**
 * Who a reply goes to (D-67), and who else hears about it (D-68).
 *
 * **`To` is the parent's `Reply-To`, falling back to its `From`.** That is what
 * `Reply-To` is for — a sender who set one is asking to be answered somewhere
 * else, and a client that ignored it would send the reply to an address the
 * sender deliberately routed away from.
 *
 * **An explicit `to` or `cc` REPLACES the derived value rather than adding to
 * it**, and this is the precedence the tool description has to state: two ways
 * of filling one field is the thing that goes wrong here. Replacing rather than
 * merging is what makes "reply just to the recruiter, not the whole chain"
 * expressible at all — a merge would make the escape hatch unable to narrow.
 *
 * **Reply-all adds the parent's `To` and `Cc` to the draft's `Cc`, minus the
 * account's own address.** Three exclusions, and only the first is D-68's:
 *
 * - The account's own address, or the user is Cc'd on their own reply. Compared
 *   case-insensitively on the ADDRESS and never on the display name, so a
 *   spoofed name cannot smuggle the address back in, and a mailbox differing
 *   only in case is recognised as the same mailbox.
 * - Anyone already in `To`, who would otherwise receive the reply twice.
 * - A repeat of an address the parent itself listed twice.
 *
 * Reply-all is where deriving beats the model reconstructing a recipient list by
 * hand, and it is the case where a mistake is most visible, because it reaches
 * strangers rather than staying in the user's own Drafts folder.
 */
export function replyRecipients(
  parent: ReplyAddresses,
  options: ReplyRecipientOptions,
): { to: string[]; cc: string[] } {
  const derived = parent.replyTo.length > 0 ? parent.replyTo : parent.from;
  const to = options.to ?? derived;

  if (options.cc !== undefined) return { to, cc: options.cc };
  if (!options.replyAll) return { to, cc: [] };

  const seen = new Set([options.self, ...to].map(foldAddress));
  const cc: string[] = [];
  for (const address of [...parent.to, ...parent.cc]) {
    const key = foldAddress(address);
    if (seen.has(key)) continue;
    seen.add(key);
    cc.push(address);
  }
  return { to, cc };
}

/**
 * The reply's subject: exactly one ASCII prefix, whatever the parent carried.
 *
 * Strips a leading run of the ASCII reply family — any casing, an optional
 * bracketed counter, stray spacing — and prepends one. A parent already carrying
 * three stacked prefixes yields one, not four.
 *
 * **A localised prefix is left alone, and that is the decision rather than the
 * gap.** `Aw:`, `Antw:`, `SV:` and their kin stay where they are and gain an
 * ASCII prefix in front of them. Stripping a prefix you do not recognise is how
 * a subject loses a word that was actually part of it — a mail whose subject
 * genuinely begins `SV: the quarterly numbers` is not hypothetical — and a fixed
 * table of foreign prefixes is a table that is wrong for the next language. The
 * recommendation this implements is deliberately "do the least".
 *
 * **What Apple's own client does with a localised prefix is ASSUMED, not
 * measured.** It is believed to produce the same stacked form this does. That
 * belief is not load-bearing: doing the least is defensible whether or not the
 * assumption holds, which is why the assumption was not worth a round trip to
 * settle.
 *
 * A null or empty parent subject still yields the bare prefix. Odd, but honest —
 * and an absent `Subject` header on a draft is worse than an odd one.
 */
export function replySubject(parentSubject: string | null): string {
  return `Re: ${(parentSubject ?? "").replace(RE_PREFIX, "")}`;
}

/**
 * The five characters that must not reach markup this module authors.
 *
 * **This is not a departure from D-73 and must not be read as the beginning of
 * one.** D-73 is about the parent's CONTENT, which passes through untouched a
 * few lines below. This escapes the ATTRIBUTION LINE — a sentence this builder
 * writes, wrapped around a display name a stranger chose. Left raw, that name
 * could carry markup landing OUTSIDE the blockquote, where a reader reads it as
 * the user's own words rather than as quoted material.
 *
 * It is also what renders a plain-text parent into the HTML half, where the
 * parent supplied no markup of its own and so there is nothing to preserve.
 */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * The parent's `Date`, normalised — or nothing, if it cannot be read.
 *
 * Re-rendered through `rfc5322Date` rather than echoed, so the attribution line
 * carries a date in one fixed form built from UTC components, whatever spelling
 * the parent's client chose. An unparseable value yields `null` and the
 * attribution simply drops its date clause: a date is a nicety on that line, and
 * printing a stranger's unparsed string there would put arbitrary text in the
 * position a reader trusts to be a timestamp.
 */
function attributionDate(value: string | null): string | null {
  if (value === null) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return rfc5322Date(parsed);
}

/**
 * Resolve a parent into the attribution line and its two renditions (D-71).
 *
 * Asynchronous for exactly one reason: an HTML parent's plain rendition runs
 * through the shipped `htmlToText`, which is `HTMLRewriter`-based. Everything
 * else here is string work. Keeping it out of `buildDraft` is what lets that
 * function stay synchronous and testable byte for byte.
 *
 * Links are EMITTED rather than omitted in the plain rendition. A quoted
 * original is the one place a bare URL matters — the recipient of the reply sees
 * the quote and may need what it pointed at — where a listing snippet, which
 * omits them, is trying to be short.
 *
 * **The HTML rendition is the parent's own bytes, unchanged (D-73), and this is
 * the paragraph a later reviewer is meant to find before "fixing" it.** No
 * sanitiser, no allowlist, no stripping. The outgoing HTML part therefore
 * contains bytes a stranger wrote, including any remote images or tracking
 * pixels, and those re-transmit when the user sends. That cost was named and
 * accepted, on two grounds that were both weighed: it is exactly what Apple's
 * and Google's own clients do on reply, and the draft sits in Drafts for human
 * review before anything leaves — which Convention 2's ban on sending is what
 * makes load-bearing rather than notional.
 *
 * The two alternatives are named here so the next reader does not re-derive
 * them. Quoting the converted text as escaped content: no stranger markup ever
 * reaches an outgoing message, and the formatting of the original is lost. An
 * `HTMLRewriter` allowlist: highest fidelity, and a security-critical component
 * whose failures are silent and for which this project has no precedent. Both
 * were rejected. **Do not add a sanitiser.**
 *
 * One structural thing makes that safe rather than merely accepted, and it is
 * worth knowing which: the boundary scan-and-regenerate in `freshBoundary`. A
 * stranger who can choose part content is a stranger who could otherwise choose
 * a boundary and redraw the message's part structure at a point of their
 * choosing. That door is closed rather than narrowed, which is what leaves the
 * accepted cost bounded to what D-73 actually names.
 */
export async function quoteOriginal(
  source: QuotedSource,
): Promise<QuotedOriginal> {
  const who = source.fromName ?? source.fromAddress ?? "the sender";
  const when = attributionDate(source.date);

  return {
    attribution:
      when === null ? `${who} wrote:` : `On ${when}, ${who} wrote:`,
    text:
      source.bodySource === "text/html" && source.html !== null
        ? await htmlToText(source.html, "emit-links")
        : source.text,
    html: source.html,
  };
}

/**
 * A boundary that provably does not occur in any part's content.
 *
 * **The probability argument is not available here, and that is the whole
 * point.** D-73 passes a stranger's HTML through unmodified into an outgoing
 * message, so the one place a boundary collision could be CHOSEN rather than
 * stumbled into is the exact place this project decided not to sanitise. A
 * collision does not fail loudly: it silently redraws the part boundaries of a
 * message the user is about to send.
 *
 * Checking costs two string scans and regenerating is free, so the window is
 * closed rather than narrowed.
 */
export function freshBoundary(parts: string[]): string {
  for (;;) {
    const candidate = `${BOUNDARY_PREFIX}${crypto.randomUUID()}`;
    if (!parts.some((part) => part.includes(candidate))) return candidate;
  }
}

/**
 * One value in RFC 5987's extended form: UTF-8 bytes, percent-encoded.
 *
 * The inverse of `percentDecode` in `./mime.ts`, and that decoder is the
 * working reference this was written against rather than a second reading of
 * the grammar. Its T-02-22 note is the same mistake seen from the other
 * direction: a non-starred section must NOT be percent-decoded, because doing
 * so invents characters that never appeared on the wire. The symmetric rule
 * here is that only the STARRED parameter carries this encoding, and the plain
 * one carries literal text — so an implementation that percent-encoded both
 * would produce a plain fallback reading `Lebenslauf%20M%C3%BCller.pdf` in
 * every client that does not understand the extended form.
 *
 * Encoding runs over BYTES rather than characters, because the grammar is a
 * byte grammar: a multi-byte character becomes several percent triplets, and a
 * per-character encoder would emit a code point where an octet belongs.
 */
function rfc2231Value(name: string): string {
  let encoded = "";
  for (const byte of ENCODER.encode(name)) {
    const character = String.fromCharCode(byte);
    if (byte < 0x80 && ATTR_CHAR.test(character)) {
      encoded += character;
      continue;
    }
    encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

/**
 * The ASCII rendition of a name, safe inside a `quoted-string`.
 *
 * Walks code POINTS rather than code units, so an astral character becomes one
 * underscore rather than two — the same reason `encodeHeaderText` iterates with
 * `for…of`.
 *
 * The extension survives without being special-cased: a dot and the ASCII
 * letters that follow it are all inside the quotable class, so `résumé.pdf`
 * becomes `r_sum_.pdf` and still opens as a PDF.
 */
function asciiFilename(name: string): string {
  let rendered = "";
  for (const character of name) {
    rendered += QUOTABLE_ASCII.test(character) ? character : "_";
  }
  return rendered;
}

/**
 * The `Content-Disposition` parameters for one attachment, or a refusal.
 *
 * **The value this returns is the tail of a header in a message the user will
 * SEND, built from a name a stranger chose.** On the from-message staging path
 * the filename came off somebody else's message, and this is the point at which
 * it stops being something the user reads and starts being something the user
 * transmits under their own name. Three rules, in this order.
 *
 * **1. CR, LF and NUL refuse, and are never stripped.** `null` here becomes a
 * returned build refusal, never a raise. The reason transfers unchanged from
 * `quoteMailbox` and from `./credentials.ts`'s own assertion, both of which
 * refuse rather than repair: a control character in a header parameter
 * terminates the header early and injects a SECOND header built from the
 * stranger's own bytes. Stripping would send a message built partly from an
 * attacker's intent while reporting success, which is strictly worse than not
 * sending one.
 *
 * **2. Both forms when the plain one is lossy.** The plain parameter carries an
 * ASCII rendition inside a quoted string; the extended parameter carries the
 * name losslessly, UTF-8 percent-encoded, and takes precedence in a client that
 * understands it. The condition for emitting the second is exactly that the
 * first is not byte-identical to the name — which covers a non-ASCII name and
 * also covers an ASCII one carrying a quote or a backslash. That is why
 * replacing those two is not a lossy repair: the lossless copy always travels
 * beside the lossy one, and never instead of it.
 *
 * **3. No encoded-words.** RFC 2047 words are not valid in a parameter value.
 * Some senders put one in a `name=` parameter and clients tolerate it; matching
 * that is bug compatibility rather than correctness, and this server controls
 * both sides of what it writes. The extended parameter is the mechanism the
 * grammar actually provides for a parameter, and `encodeHeaderText` is the
 * mechanism for unstructured header text — conflating the two is the bug.
 *
 * **Whether Apple's client honours the extended form is ASSUMED, not
 * measured.** Every modern client is reported to. It is a UAT check with a
 * non-ASCII filename rather than a code question, and it is recorded as one in
 * `04-UAT.md`: the file opening at all is the pass, the name rendering
 * correctly is the bonus. Nothing structural depends on the assumption, because
 * the plain fallback keeps the extension whatever the client does.
 *
 * An empty name yields no parameter at all rather than `filename=""`. An empty
 * quoted string claims a name that does not exist, and absence is the true
 * statement; the caller supplies a default before reaching here.
 */
export function contentDispositionParams(filename: string): string | null {
  if (ILLEGAL_IN_HEADER_VALUE.test(filename)) return null;
  if (filename.length === 0) return "";

  const plain = asciiFilename(filename);
  const params = `; filename="${plain}"`;
  if (plain === filename) return params;

  // Folded onto a continuation line: the two parameters together routinely
  // exceed a comfortable line width, and the fold is the mechanism the grammar
  // provides for a header longer than one line.
  return `${params};${CRLF} filename*=UTF-8''${rfc2231Value(filename)}`;
}

/**
 * The message id, minted fresh for every draft and never left blank.
 *
 * PITFALLS #8 names a missing or malformed id first among the failures that
 * still return success: without one, a client may refuse to thread the draft or
 * may collide it with another message.
 *
 * **The credential-adjacency check, done explicitly because that is what this
 * project does.** The domain of the Apple ID is public and is already in the
 * message's own `From` header, so repeating it here discloses nothing new. The
 * LOCAL part is a different matter: it must appear nowhere except the address
 * fields, and the `local-part.timestamp@domain` form several clients use would
 * put it in a second place — including in a tool response that echoes the id
 * back to the model. A random identifier avoids that by construction rather
 * than by a rule someone has to remember.
 */
function messageId(from: string): string {
  const domain = from.slice(from.lastIndexOf("@") + 1);
  return `<${crypto.randomUUID()}@${domain}>`;
}

/** One text entity, with its transfer encoding decided from its content. */
function textEntity(mediaType: string, content: string): MimeEntity {
  const canonical = toCrlf(content);
  const contentType = `Content-Type: ${mediaType}; charset="UTF-8"`;

  if (needsBase64(canonical)) {
    return {
      headers: [contentType, "Content-Transfer-Encoding: base64"],
      body: wrapBase64(base64Of(ENCODER.encode(canonical))),
    };
  }
  return {
    headers: [contentType, "Content-Transfer-Encoding: 7bit"],
    body: canonical,
  };
}

/** An entity rendered as its own headers, a blank line, and its body. */
function renderEntity(entity: MimeEntity): string {
  return `${entity.headers.join(CRLF)}${CRLF}${CRLF}${entity.body}`;
}

/**
 * The body, as one of D-75's three trees.
 *
 * **A single part is NEVER wrapped in a one-child multipart.** That shape is
 * legal and is a different message: it is what makes a draft open as an
 * attachment-looking blob rather than as text in some clients, and it is the
 * kind of difference that only shows up on a device.
 *
 * **When both halves are present, the plain part comes FIRST.** RFC 2046
 * §5.1.4 orders the parts by increasing faithfulness and a client displays the
 * LAST one it can render, so the reverse order silently makes every rich client
 * show plain text — which reads as "the draft lost its formatting" rather than
 * as a structural bug.
 *
 * Returning an entity rather than a finished string is what lets plan 04-09 add
 * the `multipart/mixed` attachment wrap as an OUTER wrap rather than as a
 * restructure of this function.
 */
/**
 * The plain half: the caller's words, a blank line, the attribution, the quote.
 *
 * The quoted text carries no `>` prefix per line. That convention was not
 * specified by D-71 — which says the attribution line "then the parent's
 * content" — and adding it would mean rewriting every line of a rendition that
 * came out of the converter, on a body whose HTML half already carries the
 * structural `blockquote` a rich client renders. Doing the least, again.
 */
function plainHalf(input: DraftInput): string {
  const own = input.text ?? "";
  if (input.quoted === null) return own;
  return `${own}${CRLF}${CRLF}${input.quoted.attribution}${CRLF}${input.quoted.text}`;
}

/**
 * The rich half: the caller's markup, the attribution, then the quote nested.
 *
 * `blockquote type="cite"` is the element Apple's and Google's clients both
 * emit for quoted material, so a reply built here renders as a quote rather than
 * as a wall of the recipient's own prose.
 *
 * **The parent's markup goes in unchanged (D-73).** Only the attribution — and,
 * when the parent had no markup of its own, its plain text — passes through
 * `escapeHtml`. See `quoteOriginal` for the whole argument and the two rejected
 * alternatives.
 */
function htmlHalf(input: DraftInput): string {
  const own = input.html ?? "";
  if (input.quoted === null) return own;

  const quoted =
    input.quoted.html ??
    `<pre>${escapeHtml(input.quoted.text)}</pre>`;

  return (
    `${own}${CRLF}<div>${escapeHtml(input.quoted.attribution)}</div>${CRLF}` +
    `<blockquote type="cite">${CRLF}${quoted}${CRLF}</blockquote>`
  );
}

function bodyEntity(input: DraftInput): MimeEntity {
  if (input.text !== null && input.html !== null) {
    const plain = textEntity("text/plain", plainHalf(input));
    const rich = textEntity("text/html", htmlHalf(input));
    // Checked against the ENCODED bodies, because those are the bytes that go
    // between the delimiters. A base64 part cannot carry a boundary; a `7bit`
    // one carries exactly what the caller wrote.
    const boundary = freshBoundary([plain.body, rich.body]);

    const parts = [plain, rich]
      .map((part) => `${CRLF}--${boundary}${CRLF}${renderEntity(part)}`)
      .join("");

    return {
      // Quoted, because the boundary carries `=` and `_` and quoting is the
      // safe default for a parameter value that does.
      headers: [`Content-Type: multipart/alternative; boundary="${boundary}"`],
      body: `${parts}${CRLF}--${boundary}--`,
    };
  }

  if (input.html !== null) return textEntity("text/html", htmlHalf(input));
  return textEntity("text/plain", plainHalf(input));
}

/**
 * One attachment as its own entity: base64, unconditionally.
 *
 * **The encoding is not decided from the content, unlike a body part.** A
 * binary file has no other legal encoding, and deciding per type would make
 * `text/plain` an attachment travel differently from `application/pdf` one for
 * no gain — with the difference showing up only on whichever file happened to
 * be plain text. One rule, applied to every attachment.
 *
 * The declared media type is METADATA rather than a gate, exactly as
 * `../staging/r2.ts` treats it: nothing branches on it, this server does not
 * sniff the content to check it, and a wrong one costs a mislabelled part
 * rather than a wrong decision. What it must not do is carry bytes that are not
 * a media type into a header, so an unusable one is replaced with the neutral
 * default rather than refusing the whole draft. Replacing beats refusing here
 * and refusing beats replacing for the filename, and the difference is what
 * each value is FOR: a name is the user's own data and a wrong type is a label.
 *
 * `params` is `contentDispositionParams`'s already-checked output, passed in
 * rather than recomputed, so the refusal is decided once — before anything is
 * encoded — and this function has no failure branch at all.
 */
function attachmentEntity(
  attachment: DraftAttachment,
  params: string,
): MimeEntity {
  const mediaType = MEDIA_TYPE.test(attachment.mimeType)
    ? attachment.mimeType
    : DEFAULT_MEDIA_TYPE;

  return {
    headers: [
      `Content-Type: ${mediaType}`,
      "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment${params}`,
    ],
    body: wrapBase64(base64Of(attachment.content)),
  };
}

/**
 * The whole message entity: the body tree, wrapped when files travel with it.
 *
 * **D-72's nesting sentence, and it is an OUTER wrap rather than a
 * restructure.** With no attachments this returns exactly what `bodyEntity`
 * returned before attachments existed, byte for byte — asserted against a
 * committed fixture in `test/compose.test.ts` rather than trusted, because
 * "nothing changed" is the claim most easily believed and least often checked.
 * With attachments the body tree becomes the FIRST child of a
 * `multipart/mixed`, whichever of D-75's three trees it happens to be, and the
 * attachments follow as its siblings.
 *
 * **The outer boundary is scanned against the RENDERED children, headers
 * included, so it cannot collide with the inner one.** Scanning only the part
 * bodies would leave the inner boundary — which appears in the inner
 * `Content-Type` header and in every inner delimiter — outside the check, and a
 * collision there redraws the message's part structure silently. D-73 is what
 * makes this adversarial rather than probabilistic: a stranger's markup passes
 * through unmodified, so a colliding value can be CHOSEN.
 *
 * The delimiter syntax is spelled out here because an off-by-one in it is
 * silent: a CRLF, two hyphens and the boundary before each part, and a CRLF,
 * two hyphens, the boundary and two more hyphens after the last. The leading
 * CRLF belongs to the delimiter rather than to the part above it.
 */
function messageEntity(input: DraftInput, dispositions: string[]): MimeEntity {
  const body = bodyEntity(input);
  if (input.attachments.length === 0) return body;

  const rendered = [
    renderEntity(body),
    ...input.attachments.map((attachment, at) =>
      renderEntity(attachmentEntity(attachment, dispositions[at] as string)),
    ),
  ];

  const boundary = freshBoundary(rendered);
  const parts = rendered
    .map((part) => `${CRLF}--${boundary}${CRLF}${part}`)
    .join("");

  return {
    // Quoted for the reason the inner one is: the boundary carries `=` and `_`,
    // and quoting is the safe default for a parameter value that does.
    headers: [`Content-Type: multipart/mixed; boundary="${boundary}"`],
    body: `${parts}${CRLF}--${boundary}--`,
  };
}

/**
 * The two threading headers, or a statement that the build must refuse.
 *
 * RESEARCH § 2.2's four rules, each its own branch so a reader can find the one
 * they came for:
 *
 * 1. **No usable parent id means NEITHER header.** An `In-Reply-To` pointing at
 *    a fabricated id is worse than none: it creates an orphan reference that
 *    some clients render as a broken thread, and the append succeeds either way
 *    so nothing downstream notices. The case is reachable rather than
 *    theoretical — `ParsedMessage.messageId` is nullable, and plenty of real
 *    senders emit no `Message-ID` at all.
 * 2. **`In-Reply-To` is the parent's own id**, and nothing else.
 * 3. **`References` is the parent's `References` plus the parent's own id.**
 *    Never `In-Reply-To` alone: a client that skips `References` threads
 *    correctly against the immediate parent and loses the chain above it.
 * 4. **The parent's id is not repeated** when it already appears in the parent's
 *    `References`. RFC 5322 tolerates the duplicate; Mail.app's behaviour on it
 *    is unverified, so the chain is built the way the RFC describes building it.
 *
 * "Usable" in rule 1 covers malformed as well as absent, and that is a
 * deliberate widening: an id that is not an angle-bracket token cannot be
 * matched by any other client, so emitting it produces the same broken thread as
 * fabricating one, by a different route.
 *
 * The chain is validated even on the branch that will not emit it. Refusing a
 * poisoned token the caller handed over is honest; discarding it quietly because
 * the header happens not to be wanted is repair by omission, and it would leave
 * `foldReferences`'s refusal branch unreachable from here — a rule that silently
 * matches nothing, which this project treats as worse than no rule.
 */
interface Threading {
  /** The header lines to emit. Empty when the parent offered no usable id. */
  lines: string[];
  /** The id actually emitted, or `null`. */
  inReplyTo: string | null;
  /** How many tokens the emitted chain carried. */
  referencesCount: number;
}

function threadingHeaders(input: DraftInput): Threading | null {
  if (
    input.inReplyTo !== null &&
    ILLEGAL_IN_HEADER_VALUE.test(input.inReplyTo)
  ) {
    return null;
  }

  const parentId =
    input.inReplyTo !== null && REFERENCE_TOKEN.test(input.inReplyTo)
      ? input.inReplyTo
      : null;

  const chain =
    parentId === null || input.references.includes(parentId)
      ? input.references
      : [...input.references, parentId];

  const folded = foldReferences(chain);
  if (folded === null) return null;

  if (parentId === null) {
    return { lines: [], inReplyTo: null, referencesCount: 0 };
  }

  const emitted = folded.length === 0 ? [] : [`${REFERENCES_FIELD}: ${folded}`];
  return {
    lines: [`In-Reply-To: ${parentId}`, ...emitted],
    inReplyTo: parentId,
    // Counted off the FOLDED value, so the number describes what shipped rather
    // than what was handed in — a token dropped for its shape is not in it.
    referencesCount: folded.split(/\s+/).filter((one) => one.length > 0).length,
  };
}

/**
 * Every address field, or `null` if any one of them cannot be built.
 *
 * All-or-nothing rather than field-by-field: a message missing one recipient
 * because that recipient was quietly dropped is a worse outcome than a message
 * that was not built, and only one of the two is visible to the caller.
 */
function addressList(addresses: string[]): string | null {
  const fields: string[] = [];
  for (const address of addresses) {
    const field = addressField(address, null);
    if (field === null) return null;
    fields.push(field);
  }
  return fields.join(", ");
}

/**
 * Build one draft's bytes.
 *
 * The order of operations is load-bearing at exactly one point: the assembled
 * string is normalised to CRLF as the LAST step before encoding, and the size
 * is then taken off the resulting array. Building a string, measuring the
 * string, and encoding afterwards is the same off-by-one `searchKeys` in
 * `./service.ts` calls "silently catastrophic rather than merely wrong" — and
 * with more force here, because the payload is longer and carries bytes a
 * stranger may have chosen.
 */
export function buildDraft(input: DraftInput): BuildResult {
  // **Refused in the BUILDER, so both compose tools inherit it from one place.**
  // The new-message tool guards its recipients with `.min(1)` at the schema; the
  // reply tool cannot, because its `to` is legitimately omitted in the normal
  // case and derived from the parent instead. But the derivation can itself
  // yield nothing: it falls back to the parent's `From`, and `addressesOf`
  // returns an empty list for a sender the parser could not read — which is
  // ordinary for automated senders rather than hypothetical.
  //
  // `addressList([])` returns the empty string, and unlike `Cc` below an empty
  // `To` is not omitted, so the draft was emitted with a bare `To: ` line, the
  // write succeeded, and `appended: true` was reported for a draft the user
  // cannot send. That is the shape PITFALLS #8 is about: on this path every
  // failure mode returns a successful write, so a failure that is not refused
  // is a failure that is reported as success.
  if (input.to.length === 0) {
    return { built: false, refusal: "no-recipients" };
  }

  const from = addressField(input.from, null);
  const to = addressList(input.to);
  const cc = addressList(input.cc);
  if (from === null || to === null || cc === null) {
    return { built: false, refusal: "recipient-illegal-characters" };
  }

  const threading = threadingHeaders(input);
  if (threading === null) {
    return { built: false, refusal: "references-illegal-characters" };
  }

  // Every disposition decided BEFORE anything is encoded, and all-or-nothing.
  // A message missing one attachment because that attachment was quietly
  // dropped is a worse outcome than a message that was not built, and only one
  // of the two is visible to the caller — `addressList` above makes the same
  // trade for the same reason. Deciding first also means a hostile name costs
  // no base64 work and leaves no part carrying a truncated name.
  const dispositions: string[] = [];
  for (const attachment of input.attachments) {
    const params = contentDispositionParams(attachment.filename);
    if (params === null) {
      return { built: false, refusal: "filename-illegal-characters" };
    }
    dispositions.push(params);
  }

  const entity = messageEntity(input, dispositions);

  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    // Omitted entirely when empty. An empty header is not the same statement as
    // an absent one, and only the absent one is true.
    ...(cc.length === 0 ? [] : [`Cc: ${cc}`]),
    `Subject: ${encodeHeaderText(input.subject)}`,
    `Date: ${rfc5322Date(input.now)}`,
    `Message-ID: ${messageId(input.from)}`,
    ...threading.lines,
    "MIME-Version: 1.0",
    ...entity.headers,
  ];

  // One normalisation over the whole assembled message, then ONE encode, then
  // the count off the array. Never a count taken from the string.
  const message = toCrlf(
    `${headers.join(CRLF)}${CRLF}${CRLF}${entity.body}${CRLF}`,
  );
  const bytes = ENCODER.encode(message);

  if (bytes.byteLength > MAX_APPEND_LITERAL_BYTES) {
    return {
      built: false,
      refusal: "message-too-large",
      sizeBytes: bytes.byteLength,
      limitBytes: MAX_APPEND_LITERAL_BYTES,
    };
  }

  return {
    built: true,
    bytes,
    inReplyTo: threading.inReplyTo,
    referencesCount: threading.referencesCount,
  };
}
