// Raw RFC822 bytes in, a decoded message out. Pure and socket-free.
//
// Imports the MIME library and nothing from the transport modules, so it
// unit-tests against captured bytes with nothing stood up — the same shape
// `imap-parser.ts` keeps one layer down.
//
// Runtime-coupled but NOT socket-coupled: `htmlToText` below uses
// `HTMLRewriter`, a workerd global, and the test pool runs inside real workerd.
// That is a different thing from depending on a socket, and it is what lets the
// HTML path be measured rather than assumed.
//
// This module contains no logging calls of any kind and must never acquire any.

import PostalMime, { decodeWords } from "postal-mime";
import type { SExpr } from "./imap-parser";

/**
 * The ceiling on extracted text, applied to the ASSEMBLED string.
 *
 * **This is explicitly NOT a context cap.** The model asked for one specific
 * message and gets that message; deciding on the model's behalf that it wanted
 * less would be answering a different question than the one it asked (D-34).
 *
 * It exists because the isolate has a bounded heap and a bounded CPU budget,
 * while MIME parsing plus content decoding plus JSON serialisation multiplies
 * the peak — roughly three times the wire size on the common path. Two
 * megabytes of extracted text is far above any real piece of correspondence and
 * far below anything that threatens the isolate, and it matches
 * `MAX_LITERAL_OCTETS` because the two are the same failure seen from either
 * side of the transport.
 *
 * On trip it TRUNCATES and sets `truncated`. It never raises. Adding a fifth
 * error category for "too big" was considered and rejected: the caller can do
 * nothing differently, and the flag already says what happened.
 *
 * Applied once, to the finished string, copying `MAX_FAILURE_DETAIL`'s
 * reasoning in `imap-session.ts`: bounding each part instead would bound none
 * of the whole, and the real ceiling would then grow with the number of parts.
 */
export const MAX_EXTRACTED_TEXT_BYTES = 2 * 1024 * 1024;

/**
 * What is known about one attachment, without its contents.
 *
 * `sizeBytes` is the DECODED byte length — the length of the file as it would
 * land on disk. The library hands back decoded content, so the number comes
 * from that. The transfer-encoded octet count is roughly 1.37x the real file
 * for a base64 part and must never be reported as the size: a user told their
 * 4 MB PDF is 5.5 MB has been told something false about their own file.
 */
export interface AttachmentMeta {
  /** The sender's filename, or `null` when the part declared none. Untrusted. */
  filename: string | null;
  /** The declared media type. Sender-declared, so untrusted. */
  mimeType: string;
  /** Decoded size in bytes. Never the transfer-encoded octet count. */
  sizeBytes: number;
  /** `attachment`, `inline`, or `null` when the part declared none. */
  disposition: string | null;
  /**
   * The IMAP part path this row was derived from, or `null` when it was not
   * derived from a structure walk at all.
   *
   * Server-derived rather than sender-authored: the walk builds every segment
   * as `String(index + 1)`, so this is a statement about where in the message
   * the part sits, not a value a stranger chose. It never crosses the tool
   * boundary — the model holds the minted `id` instead, exactly as it holds a
   * folder token rather than a wire mailbox name (D-18).
   *
   * **A non-empty check on this field would be wrong IN GENERAL.**
   * `BodyPart.path`'s empty string is a legal value meaning "the top-level
   * multipart", and RFC 3501 §6.4.5 is explicit that such a container is not
   * itself numbered. It cannot arise on an attachment row because
   * `attachmentsFrom` skips multiparts — but that is a property of the
   * PREDICATE, not of the type, and the two are easy to confuse. `ids.ts`'s
   * `assertPartPath` refuses the empty string for the same reason from the
   * other side; the apparent contradiction between the two modules is
   * deliberate and is recorded in both.
   *
   * `null` on a row the MIME library produced, because the library has no
   * notion of a part path — see `extractMessage`.
   */
  path: string | null;
  /**
   * The opaque token naming this attachment, or `null` when none was minted.
   *
   * **Minted in `./service.ts`, not here, and that split is deliberate.** An
   * attachment id encodes the mailbox, the UIDVALIDITY, the UID and the path;
   * this module is pure and socket-free and knows only the last of those. So
   * the pure module stays pure, the identifier layer in `./ids.ts` stays the
   * one minting site, and the service — the one place holding a message
   * reference — is where the two meet.
   *
   * Every row this module produces therefore carries `null` here. A row that
   * reached a tool response with a null id would be an attachment the model
   * could see and not address, which is why the service populates it on every
   * structure-derived row rather than on some of them.
   */
  id: string | null;
}

// ---------------------------------------------------------------------------
// The BODYSTRUCTURE walk
//
// The parser library turns raw RFC822 bytes into a message. What it does not
// do, and cannot do, is speak IMAP: it has no notion of a PART PATH, and the
// part path is the address `BODY.PEEK[1.1]<0.1024>` needs for a snippet and
// `BODY.PEEK[2]` will need for an attachment. Deriving it from the server's
// own `BODYSTRUCTURE` is this project's work, not the library's.
// ---------------------------------------------------------------------------

/**
 * One part of a message, as the server's own `BODYSTRUCTURE` describes it.
 *
 * Every field here is server-reported but reflects ATTACKER-AUTHORED message
 * composition: arbitrary nesting, missing fields, and `NIL` where a list is
 * expected are all legal in the grammar and all reachable by a stranger who
 * composed the mail (T-02-21).
 */
export interface BodyPart {
  /**
   * The IMAP part path, e.g. `1`, `1.2`, `2.1`.
   *
   * The EMPTY STRING is a real value, and it means "the top-level multipart".
   * RFC 3501 §6.4.5 is explicit that a top-level multipart is not itself
   * numbered — its children start at 1 — so the empty path records that fact
   * rather than hiding it by omitting the node.
   */
  path: string;
  /** Lowercased media type. `multipart` for a container. */
  type: string;
  /** Lowercased media subtype. */
  subtype: string;
  /** `body-fld-param`, keys lowercased, values decoded. Stranger-authored. */
  params: Record<string, string>;
  /** Lowercased `body-fld-enc`. Empty for a multipart container. */
  encoding: string;
  /**
   * `body-fld-octets` — the ENCODED octet count, and named so nobody reads it
   * as a size. See `decodedSizeBytes` for why that distinction is load-bearing.
   */
  encodedOctets: number;
  /** Lowercased `body-fld-dsp` value (`attachment`, `inline`), or `null`. */
  disposition: string | null;
  /** The disposition's parameter list, keys lowercased, values decoded. */
  dispositionParams: Record<string, string>;
  /** Whether this part is a container rather than content. */
  isMultipart: boolean;
  /**
   * Whether this part lives INSIDE a `MESSAGE/RFC822` part.
   *
   * Carried rather than re-derived from the path because the primary-body
   * selection must never descend into forwarded mail, and a rule that
   * important should not depend on string-prefix arithmetic at each call site.
   */
  encapsulated: boolean;
}

const DECODER = new TextDecoder();

/** A parenthesised list, or `null` for anything else — including `NIL`. */
function asList(node: SExpr | undefined): SExpr[] | null {
  return Array.isArray(node) ? node : null;
}

/**
 * A string value, or `null`.
 *
 * A literal is accepted and decoded here because a server may legitimately
 * send a non-ASCII filename as `{n}` bytes rather than as a quoted string, and
 * the transport layer deliberately leaves literals undecoded.
 */
function asString(node: SExpr | undefined): string | null {
  if (typeof node === "string") return node;
  if (node instanceof Uint8Array) return DECODER.decode(node);
  return null;
}

/** A non-negative count, or 0 for a field that was absent or unparseable. */
function asCount(node: SExpr | undefined): number {
  const text = asString(node);
  if (text === null) return 0;
  const value = Number(text);
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

/**
 * Whether a parsed body node is a multipart.
 *
 * **This is the only non-obvious thing about the `BODYSTRUCTURE` grammar, and
 * it drives the entire walk.** From RFC 3501 §9:
 *
 * ```abnf
 * body            = "(" (body-type-1part / body-type-mpart) ")"
 * body-type-mpart = 1*body SP media-subtype [SP body-ext-mpart]
 * body-type-basic = media-basic SP body-fields
 * ```
 *
 * `body-type-mpart` begins with `1*body`, and `body` begins with an open
 * parenthesis. Every single-part alternative begins with a `media-*`
 * production, which begins with a string. So the first element decides it: a
 * LIST means multipart, a STRING means single-part. There is no subtype field
 * to consult and no count to check — the shape is the discriminator.
 */
function isMultipartNode(node: SExpr[]): boolean {
  return node.length > 0 && asList(node[0]) !== null;
}

/** How many leading elements of a multipart node are its children. */
function childCount(node: SExpr[]): number {
  let count = 0;
  while (count < node.length && asList(node[count]) !== null) count += 1;
  return count;
}

/**
 * Locate `body-fld-dsp` in a part's extension region by SHAPE, not by offset.
 *
 * The extension region (`body-ext-1part` / `body-ext-mpart`) is optional,
 * openly extensible, and the one place real servers genuinely differ. A fixed
 * index that is right for one server reads `body-fld-lang` as a disposition on
 * another, which silently turns a language tag into a filename.
 *
 * `body-fld-dsp = "(" string SP body-fld-param ")" / nil` — a two-element list
 * whose first element is a string and whose second is a list or `NIL`. That
 * shape distinguishes it from `body-fld-lang`, whose list form is strings all
 * the way down, so a two-element `("en" "fr")` is rejected by the second test.
 */
function dispositionFrom(
  node: SExpr[],
  from: number,
): { value: string | null; params: Record<string, string> } {
  for (let index = from; index < node.length; index += 1) {
    const candidate = asList(node[index]);
    if (candidate === null || candidate.length !== 2) continue;
    const value = asString(candidate[0]);
    if (value === null) continue;
    const params = candidate[1];
    if (params !== null && asList(params) === null) continue;
    return { value: value.toLowerCase(), params: paramsFrom(params) };
  }
  return { value: null, params: {} };
}

/**
 * Decode an RFC 2231 percent-encoded parameter section under its charset.
 *
 * Only sections whose name ends in `*` reach here. A plain `name*0=` section
 * is literal text, and decoding it would invent characters that never appeared
 * on the wire — turning `a%2F..%2Fetc` into a path traversal (T-02-22).
 */
function percentDecode(value: string, charset: string): string {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "%" && index + 2 < value.length) {
      const byte = Number.parseInt(value.slice(index + 1, index + 3), 16);
      if (Number.isFinite(byte)) {
        bytes.push(byte);
        index += 2;
        continue;
      }
    }
    bytes.push(value.charCodeAt(index) & 0xff);
  }
  return decoderFor(charset).decode(new Uint8Array(bytes));
}

/**
 * A `TextDecoder` for a sender-declared charset, falling back to UTF-8.
 *
 * The charset comes from the message, so it is stranger-authored: an unknown
 * or malformed label makes the constructor throw, and a throw here would turn
 * a cosmetic filename problem into a failed tool call.
 *
 * Exported for `./extract.ts` (plan 04-07), which faces the same question on an
 * attachment's own declared charset. A second copy of the try/fallback would be
 * a second place for the fallback to be forgotten, and forgetting it turns a
 * European name in a `text/plain` attachment into a failed tool call.
 */
export function decoderFor(charset: string | null): TextDecoder {
  if (charset === null || charset.length === 0) return new TextDecoder("utf-8");
  try {
    // Non-fatal is the default and is what is wanted: an undecodable byte
    // becomes U+FFFD rather than throwing partway through a filename.
    return new TextDecoder(charset);
  } catch {
    return new TextDecoder("utf-8");
  }
}

/** One RFC 2231 continuation section of a parameter value. */
interface ParamSection {
  index: number;
  value: string;
  extended: boolean;
}

/** Join and decode one parameter's continuation sections, in section order. */
function joinSections(sections: ParamSection[]): string {
  const ordered = [...sections].sort((a, b) => a.index - b.index);
  let charset: string | null = null;
  let result = "";
  let pending = "";

  for (const [position, section] of ordered.entries()) {
    let value = section.value;
    if (position === 0 && section.extended) {
      const header = /^([^']*)'[^']*'([\s\S]*)$/.exec(value);
      if (header !== null) {
        charset = header[1].length > 0 ? header[1] : null;
        value = header[2];
      }
    }
    if (section.extended) {
      // Adjacent encoded sections decode together: one multi-byte character
      // may be percent-encoded across a section boundary.
      pending += value;
      continue;
    }
    if (pending.length > 0) {
      result += percentDecode(pending, charset ?? "utf-8");
      pending = "";
    }
    result += value;
  }
  if (pending.length > 0) result += percentDecode(pending, charset ?? "utf-8");
  return result;
}

/**
 * A `body-fld-param` list as a decoded map with lowercased keys.
 *
 * `NIL` in this position is legal and common, and indexing into it is the
 * exact shape of throw this walk must not produce.
 *
 * RFC 2047 encoded words are decoded through the library's own `decodeWords`
 * rather than a hand-rolled decoder — that is precisely the ~60 lines
 * § Don't Hand-Roll warns against reimplementing. RFC 2231 continuations are
 * joined here because the library does not export its own joiner.
 */
function paramsFrom(node: SExpr | undefined): Record<string, string> {
  const list = asList(node);
  if (list === null) return {};

  const decoded: Record<string, string> = {};
  const continuations = new Map<string, ParamSection[]>();

  for (let index = 0; index + 1 < list.length; index += 2) {
    const key = asString(list[index]);
    const value = asString(list[index + 1]);
    if (key === null || value === null) continue;

    const lowered = key.toLowerCase();
    const match = /^(.+?)\*(\d+)?(\*)?$/.exec(lowered);
    if (match === null) {
      decoded[lowered] = decodeWords(value);
      continue;
    }
    const sections = continuations.get(match[1]) ?? [];
    sections.push({
      index: match[2] === undefined ? 0 : Number(match[2]),
      value,
      extended: match[3] === "*",
    });
    continuations.set(match[1], sections);
  }

  for (const [key, sections] of continuations) {
    decoded[key] = decodeWords(joinSections(sections));
  }
  return decoded;
}

/** Where a single-part node's extension region begins, by media type. */
function extensionStart(type: string, subtype: string): number {
  // body-type-text = media-text SP body-fields SP body-fld-lines
  if (type === "text") return 8;
  // body-type-msg = media-message SP body-fields SP envelope SP body
  //                 SP body-fld-lines
  if (type === "message" && subtype === "rfc822") return 10;
  // body-type-basic = media-basic SP body-fields
  return 7;
}

/** Emit the children of a multipart node, numbered under `prefix`. */
function collectChildren(
  node: SExpr[],
  prefix: string,
  encapsulated: boolean,
  out: BodyPart[],
): void {
  const children = childCount(node);
  for (let index = 0; index < children; index += 1) {
    // The path rule, stated once and in the code rather than in a comment: a
    // container contributes no segment when it has no path of its own (the
    // top level, and the body of an encapsulated message), and contributes
    // `prefix.` when it does.
    const path = prefix === "" ? String(index + 1) : `${prefix}.${index + 1}`;
    collectPart(node[index] as SExpr[], path, encapsulated, out);
  }
}

/** Emit `node` and everything beneath it, given the path `node` occupies. */
function collectPart(
  node: SExpr[],
  path: string,
  encapsulated: boolean,
  out: BodyPart[],
): void {
  if (!Array.isArray(node) || node.length === 0) return;

  if (isMultipartNode(node)) {
    const subtypeIndex = childCount(node);
    const subtype = asString(node[subtypeIndex]) ?? "";
    // body-ext-mpart = body-fld-param [SP body-fld-dsp …] — so the extension
    // region opens one past the subtype, and the disposition is found in it.
    const dsp = dispositionFrom(node, subtypeIndex + 2);
    out.push({
      path,
      type: "multipart",
      subtype: subtype.toLowerCase(),
      params: paramsFrom(node[subtypeIndex + 1]),
      encoding: "",
      encodedOctets: 0,
      disposition: dsp.value,
      dispositionParams: dsp.params,
      isMultipart: true,
      encapsulated,
    });
    collectChildren(node, path, encapsulated, out);
    return;
  }

  const rawType = asString(node[0]);
  const rawSubtype = asString(node[1]);
  // A part with no media type is not a part. Refuse it; do not invent one.
  if (rawType === null || rawSubtype === null) return;

  const type = rawType.toLowerCase();
  const subtype = rawSubtype.toLowerCase();
  const dsp = dispositionFrom(node, extensionStart(type, subtype));

  out.push({
    path,
    type,
    subtype,
    params: paramsFrom(node[2]),
    encoding: (asString(node[5]) ?? "").toLowerCase(),
    encodedOctets: asCount(node[6]),
    disposition: dsp.value,
    dispositionParams: dsp.params,
    isMultipart: false,
    encapsulated,
  });

  if (type !== "message" || subtype !== "rfc822") return;

  // RFC 3501 §6.4.5: "A part of type MESSAGE/RFC822 also has nested part
  // numbers, referring to parts of the MESSAGE part's body." The encapsulated
  // body is at index 8, after the envelope. Its own multipart container is
  // unnumbered for the same reason the top-level one is, so its children take
  // this part's path as their prefix.
  const inner = asList(node[8]);
  if (inner === null || inner.length === 0) return;
  if (isMultipartNode(inner)) {
    collectChildren(inner, path, true, out);
  } else {
    collectPart(inner, `${path}.1`, true, out);
  }
}

/**
 * Turn a parsed `BODYSTRUCTURE` into a flat list of parts with IMAP paths.
 *
 * Returns an EMPTY LIST for a tree it cannot make sense of, and never throws
 * (T-02-21). A malformed or truncated structure is attacker-reachable — a
 * stranger composes the message the server describes — so the failure has to
 * be a value the caller can handle, not an exception at the tool boundary.
 * Refuse, do not repair: nothing here invents a media type or a path.
 *
 * A structure that yields no content part at all is treated as unusable even
 * if it yielded containers, because a message made entirely of empty
 * containers describes nothing that can be fetched.
 */
export function walkBodystructure(node: SExpr[]): BodyPart[] {
  const parts: BodyPart[] = [];
  if (!Array.isArray(node) || node.length === 0) return parts;

  if (isMultipartNode(node)) {
    // The top-level container is unnumbered — RFC 3501 §6.4.5 — so it carries
    // the empty path and its children start at 1.
    collectPart(node, "", false, parts);
  } else {
    collectPart(node, "1", false, parts);
  }

  return parts.some((part) => !part.isMultipart) ? parts : [];
}

/** The parent path of a part path. `1.2` → `1`; `1` → `` (the top level). */
function parentPath(path: string): string {
  const separator = path.lastIndexOf(".");
  return separator === -1 ? "" : path.slice(0, separator);
}

/**
 * The parts directly beneath `path`, excluding anything inside a forwarded
 * message.
 *
 * The `encapsulated` filter is the SECOND of two independent mechanisms
 * keeping forwarded text out of the primary body — the first is that
 * `selectIn` never recurses through a single-part node, and a `MESSAGE/RFC822`
 * part is a single-part node. Two mechanisms for one property, the same shape
 * `EXAMINE` plus `BODY.PEEK` takes in `service.ts` (D-47).
 */
function childrenOf(parts: BodyPart[], path: string): BodyPart[] {
  return parts.filter(
    (part) =>
      part.path !== path && !part.encapsulated && parentPath(part.path) === path,
  );
}

/**
 * Whether a part's disposition marks it an attachment rather than content.
 *
 * An attached `.txt` file is an attachment, not the message, and
 * `body-fld-dsp` is the only field that says so. Without this test a message
 * carrying `notes.txt` can render the attachment's contents as the body.
 */
function isAttached(part: BodyPart): boolean {
  return part.disposition === "attachment";
}

/**
 * How many times an HTML half must outweigh its plain twin before the plain
 * one is read as UNAUTHORED rather than as short.
 *
 * **What this ratio measures, which is not size.** An authored `text/plain`
 * alternative is a serialisation of the same message as its HTML twin: it
 * contains the message's visible words. The HTML twin contains those same words
 * PLUS markup. So plain-to-HTML is really the HTML part's markup-to-content
 * weight, and a threshold of 100 says the plain part is under one percent of
 * the HTML part — which is not a claim about length in the abstract, it is the
 * statement that the plain part cannot be this message's text.
 *
 * **Lower bound, from the largest observed placeholder.** Three placeholder
 * shapes are on record against this account: a whitespace-only part (uid 184545,
 * uid 184504); a part reading `undefined` and a newline, 10 bytes against a
 * 123 978-byte message (uid 184746); and the largest, two messages from
 * Sleep-Insights@sleeptracker.com whose entire plain part reads `Your email
 * client does not support HTML email` — roughly 45 bytes. For the rule to fire
 * on that largest one the HTML part need only exceed ~4.5 KB, and an HTML part
 * that IS the message exceeds that on its preamble alone: G-02-9a records the
 * doctype/head/style head of real marketing mail as routinely several
 * kilobytes. 100 therefore fires on every placeholder observed.
 *
 * **Upper bound, from the authored pairs in hand.** The repository's alternative
 * fixtures declare 2.2x and 3x. 100 sits an order and a half above them, so no
 * existing pinned command assertion moves.
 *
 * **Why not a "does it contain words" gate.** This is the alternative the chosen
 * rule beat, and the Sleeptracker case is why: its plain part is eight real
 * English words. A prose-detection gate passes it and the user still cannot read
 * the message. The size relationship catches it; nothing about its contents
 * does.
 *
 * **Why not a string blocklist.** Several MGM/Cosmopolitan messages carry a
 * plain part reading `MGM RESORTS INTERNATIONAL | MGM Rewards ***** undefined
 * undefined Book Now https://...` — the same broken token, MID-BODY, in a part
 * that is otherwise legitimate and must be returned as written. A blocklist
 * would have to strip mid-text, which is D-36 territory, and it generalises to
 * nothing: the next sender's placeholder is `null` or an empty template tag.
 *
 * **Known risk, accepted by the developer on the record.** A terse-but-real
 * plain part beside a fat HTML signature block selects the HTML. The failure is
 * recoverable — the reader gets MORE text, not less — and the opposite failure
 * is not: an unreadable message has no recovery at all.
 *
 * **What would revise this number.** A real authored pair measured above 100, or
 * a real placeholder measured below it. Neither exists today. Recorded so a
 * later session revises on evidence rather than on taste.
 *
 * The rule this serves is G-02-9b's `decision:` block, decided by the developer
 * on 2026-08-16 with 02-17's refusal of a "guessed size threshold" raised as an
 * objection and the decision reaffirmed. That refusal was about a threshold
 * triggering a SECOND FETCH; this one triggers no fetch at all.
 */
export const UNAUTHORED_PLAIN_RATIO = 100;

/**
 * Whether an alternative's HTML half outweighs its plain half by that margin.
 *
 * Both sizes are already in hand at both call sites — from `BODYSTRUCTURE` on
 * the listing path, and from the parser's two halves on the full-fetch path —
 * so answering this question costs no round trip and D-20's cost model is
 * untouched.
 *
 * MULTIPLIES rather than divides, so a zero-length plain part cannot produce a
 * division by zero. A zero-length plain part is already handled upstream in any
 * case: by `hasReadableText` on the fetch path, and by the recovery pass on the
 * listing path. This predicate is for the parts those two miss — the ones that
 * carry real words and still cannot be the message.
 *
 * A zero-length HTML half answers `false`. There is nothing to prefer.
 */
export function htmlOutweighsPlain(
  plainBytes: number,
  htmlBytes: number,
): boolean {
  if (htmlBytes === 0) return false;
  return plainBytes * UNAUTHORED_PLAIN_RATIO < htmlBytes;
}

/** The selection rule, applied at one node of the tree. */
function selectIn(parts: BodyPart[], node: BodyPart): BodyPart | null {
  if (!node.isMultipart) {
    // Deliberately no recursion here, and that is what keeps the primary body
    // out of forwarded mail: a `MESSAGE/RFC822` part is single-part, so the
    // walk stops at it rather than descending into someone else's message.
    return node.type === "text" && !isAttached(node) ? node : null;
  }

  const children = childrenOf(parts, node.path);

  if (node.subtype === "alternative") {
    const readable = children.filter(
      (child) => !child.isMultipart && child.type === "text" && !isAttached(child),
    );
    const plain = readable.find((child) => child.subtype === "plain");
    // Falling back to the HTML half is the record that a conversion is owed:
    // the caller reads `subtype` and runs `htmlToText` (D-33).
    const html = readable.find((child) => child.subtype === "html");

    if (plain !== undefined) {
      // Measured through `decodedSizeBytes` on BOTH halves deliberately, not
      // off `encodedOctets` directly. A base64 HTML half beside a 7bit plain
      // half would otherwise be compared in different units, and the ratio
      // would carry base64's ~1.37x inflation as a silent bias.
      if (
        html !== undefined &&
        htmlOutweighsPlain(
          decodedSizeBytes(plain.encoding, plain.encodedOctets),
          decodedSizeBytes(html.encoding, html.encodedOctets),
        )
      ) {
        return html;
      }
      return plain;
    }
    if (html !== undefined) return html;
  }

  for (const child of children) {
    const chosen = selectIn(parts, child);
    if (chosen !== null) return chosen;
  }
  return null;
}

/**
 * Choose the part that IS this message's readable body, or `null`.
 *
 * Prefers `text/plain`, falls back to `text/html`, and otherwise takes the
 * first child of a container whose own selection succeeds, in document order.
 *
 * The same function serves the snippet path and the full-body path, so the two
 * cannot drift into disagreeing about which part a message's text lives in.
 *
 * `null` is an ordinary outcome, not an error: a message that is nothing but
 * an attachment has no body, and the caller renders an empty one.
 */
export function selectTextPart(parts: BodyPart[]): BodyPart | null {
  if (parts.length === 0) return null;
  return selectIn(parts, parts[0]);
}

/**
 * The `text/html` half of the `multipart/alternative` a resolved part sits in,
 * or `null`.
 *
 * **This exists because selection happens where content is invisible.**
 * `selectTextPart` reads `BODYSTRUCTURE`, in which no body bytes have been
 * fetched, so a blank `text/plain` placeholder — a slot filled without anything
 * put in it, which senders emit routinely — wins on presence over the populated
 * HTML part beside it. Observed live on two real messages (G-02-3b). Only a
 * caller holding the DECODED window can see that, and by then the selection is
 * already made; this is what such a caller reaches for to name the other half.
 *
 * **Deliberately does not change `selectTextPart`'s preference order.** Plain
 * still wins on presence for both consumers (D-33), and this helper is a
 * recovery the caller reaches for AFTER seeing a blank window.
 *
 * **An earlier version of this paragraph said a declared-size rule in `selectIn`
 * had been declined, full stop. That is now half wrong, and the half that is
 * still right is the one worth being precise about.** What was declined, and
 * remains declined, is an ABSOLUTE FLOOR — "a plain part under N bytes is not a
 * body". A floor cannot distinguish a whitespace placeholder from a genuinely
 * short reply, so it would silently read real correspondence from its HTML twin
 * (T-02-51). What was ADOPTED, in `selectIn` twenty lines above, is a RATIO
 * BETWEEN THE TWO HALVES of one alternative. A ratio is not a statement about
 * length at all: it says the plain half is too small to be a serialisation of
 * the same message as the HTML half beside it, which is evidence about
 * AUTHORSHIP rather than about brevity. "Approved." is a short reply and passes
 * a ratio comfortably whenever its HTML twin is also short. G-02-9b's
 * `decision:` block carries the reasoning, the accepted risk and the record of
 * the objection being raised and overruled.
 *
 * The two rules are complementary rather than one having eaten the other: the
 * ratio catches a plain half that carries words it should not, and this helper
 * still catches the whitespace half a ratio cannot see when the HTML twin is
 * itself modest.
 *
 * Resolved through `parentPath` and `childrenOf` rather than by path arithmetic
 * at the call site, which is the fragility those two exist to prevent — and the
 * `encapsulated` filter `childrenOf` carries is what keeps a forwarded
 * message's HTML from being offered as this message's body.
 *
 * `null` whenever there is nothing to recover from: a single-part message, a
 * container that is not an `ALTERNATIVE`, or an alternative carrying no HTML
 * child OTHER than the resolved part itself.
 *
 * **The resolved part is excluded by PATH, never by media type, and that
 * distinction is the contract rather than an implementation note.** A sender
 * who declares TWO `text/html` children under one alternative gets the other
 * one back here — being HTML already is not itself a reason to refuse, and an
 * earlier draft of this comment claimed otherwise (WR-04; the review's probe
 * resolved part `1` and was handed sibling `2`). What the exclusion actually
 * prevents is the helper offering a part the caller has already read, which is
 * a question about identity and is answered by the path.
 *
 * The answer is the FIRST HTML child in document order that is not the resolved
 * part, so it may sit BEFORE it as easily as after — there is no notion of "the
 * other half" here beyond "not the one you already have". A test pins both
 * directions, because the phrase "the HTML alternative" invites the positional
 * reading and the positional reading is wrong.
 *
 * The cost of the two-HTML shape is bounded and already accepted: the caller
 * spends one extra grouped `UID FETCH` on a second part inside the sender's own
 * message, and only when the first window came back blank. That is exactly
 * T-02-50's recorded posture — "a sender can direct the fallback at a part of
 * their choosing within their own message" — rather than a new surface.
 */
export function htmlAlternativeOf(
  parts: BodyPart[],
  part: BodyPart,
): BodyPart | null {
  const container = parts.find((one) => one.path === parentPath(part.path));
  if (container === undefined) return null;
  if (!container.isMultipart || container.subtype !== "alternative") return null;

  return (
    childrenOf(parts, container.path).find(
      (child) =>
        child.path !== part.path &&
        !child.isMultipart &&
        child.type === "text" &&
        child.subtype === "html" &&
        !isAttached(child),
    ) ?? null
  );
}

/**
 * The decoded byte length a part's content will have on disk.
 *
 * **`body-fld-octets` is the ENCODED size.** It sits exactly where a size
 * field would sit and it looks entirely plausible, which is what makes it
 * dangerous: base64 runs ~1.37x, so reporting it raw tells a user their 135 KB
 * PDF is 180 KB — a false statement about their own file, from a tool whose
 * only job is to report facts about their mail.
 *
 * Base64 emits 4 characters per 3 bytes, so the inverse is exact for the
 * payload and slightly generous for the line breaks MIME wraps it in. Every
 * other transfer encoding is byte-for-byte, so the declared count already IS
 * the byte count.
 */
export function decodedSizeBytes(encoding: string, encodedOctets: number): number {
  if (encoding.toLowerCase() !== "base64") return encodedOctets;
  return Math.floor(encodedOctets / 4) * 3;
}

/**
 * The sender's filename for a part, or `null`.
 *
 * `body-fld-dsp`'s `FILENAME` first, then `body-fld-param`'s `NAME` — older
 * senders (and Apple Mail itself, historically) put it there and omit the
 * disposition entirely. Both values are already RFC 2047- and RFC 2231-decoded
 * by `paramsFrom`.
 *
 * `null` when neither is present. Nothing here fabricates a name from the
 * media type: an invented `attachment.pdf` is a value the model would repeat
 * to the user as though the sender had chosen it.
 */
function filenameOf(part: BodyPart): string | null {
  return part.dispositionParams.filename ?? part.params.name ?? null;
}

/**
 * Attachment metadata for every part that is one, from the structure alone.
 *
 * This is ATT-01's "without downloading the attachment": every field below is
 * derived from `BODYSTRUCTURE`, and not one byte of any attachment is fetched.
 *
 * A part counts as an attachment when its disposition says so or when it
 * carries a filename. The selected body part is excluded by path, and so is
 * anything inside a forwarded message — a mail client lists the forward
 * itself, not the forward's own attachments, and listing both would report one
 * file twice under two different names.
 *
 * **That one predicate decides id-minting too, and no second one was added
 * (D-76).** The discretion question was whether an `inline` part should be
 * addressable. The fact that settles it is measured rather than argued: the one
 * real attachment this project has ever observed was a PDF with an INLINE
 * disposition, "which a fixture handling only attachment would have missed"
 * (02-VERIFICATION), so excluding inline parts would make the only attachment
 * this project has seen unaddressable. A second, different predicate for
 * minting would also give one message two attachment lists that can disagree.
 *
 * `path` is carried rather than discarded — the whole of D-76's seam — but the
 * `id` is left `null` here. See `AttachmentMeta.id` for why the mint happens
 * one layer up.
 *
 * Returns `[]` for a message with none. Never `null`.
 */
export function attachmentsFrom(parts: BodyPart[]): AttachmentMeta[] {
  const body = selectTextPart(parts);
  const attachments: AttachmentMeta[] = [];

  for (const part of parts) {
    if (part.isMultipart || part.encapsulated) continue;
    if (body !== null && part.path === body.path) continue;

    const filename = filenameOf(part);
    if (!isAttached(part) && filename === null) continue;

    attachments.push({
      filename,
      mimeType: `${part.type}/${part.subtype}`,
      sizeBytes: decodedSizeBytes(part.encoding, part.encodedOctets),
      disposition: part.disposition,
      path: part.path,
      id: null,
    });
  }
  return attachments;
}

// ---------------------------------------------------------------------------
// The snippet
//
// A list row carries a preview, and the preview comes from a PARTIAL fetch:
// `BODY.PEEK[1.1]<0.1024>`. RFC 3501 §6.4.5 is explicit that a partial fetch
// returns the first N octets of the part AS TRANSFERRED — still
// transfer-encoded. Every rule below exists because of that one sentence, and
// not one of them is visible against a short 7-bit test message.
// ---------------------------------------------------------------------------

/**
 * How many CHARACTERS of a message body a list row previews.
 *
 * Two hundred is the number D-20's cost/benefit assumed when it accepted
 * roughly two extra round trips per page for snippets: long enough to tell two
 * recruiter emails apart, short enough that a hundred-row page is still a list
 * rather than a wall of prose.
 *
 * A CHARACTER count, deliberately, and the one place in this module where a
 * length is not measured in bytes. This bound exists to shape what a reader
 * sees, and a reader sees characters — capping a CJK preview by bytes would
 * cut it to a third the length of an English one for no reason a user could
 * understand. The byte-measured bound is `MAX_EXTRACTED_TEXT_BYTES`, which is
 * a different bound protecting a different thing.
 */
export const SNIPPET_MAX_CHARS = 200;

/**
 * How many ENCODED octets to ask for when fetching a snippet.
 *
 * A kilobyte, which is what survives the two lossy trims below and still
 * yields the full character cap. Base64 gives 768 bytes after trimming, which
 * is ~256 characters of CJK at three bytes each; quoted-printable is close to
 * 1:1 for Latin text. A much smaller window would routinely produce a snippet
 * SHORTER than the cap for exactly the encoded content that needs it most —
 * the non-Latin and accented mail — which is the failure this number avoids.
 */
export const SNIPPET_FETCH_OCTETS = 1024;

/**
 * How many ENCODED octets to ask for when the part being previewed is HTML.
 *
 * A DIFFERENT question from the one `SNIPPET_FETCH_OCTETS` answers, which is
 * why this is a second constant rather than a revision of that one. That number
 * asks "how much encoded content yields the full character cap"; this one asks
 * "how far in does an HTML part's first sentence of prose actually begin". A
 * plain part's first octet is prose. An HTML part's first octets are a doctype,
 * a `<head>` and a `<style>` block, and the converter correctly gets nothing out
 * of them — measured on this account, 20 of 100 rows on an INBOX page previewed
 * as the empty string for exactly this reason, uid 184617 among them, whose full
 * fetch returns 64 KB of clean prose through the same converter on the same part
 * (G-02-9a).
 *
 * **Lower bound — it must clear the preamble.** G-02-9a characterises the head
 * of a real HTML part as a doctype, a `<head>` and a `<style>` block that
 * routinely runs to several kilobytes of media queries. 1024 octets does not
 * reach past that, which is the entire defect. 16 KiB clears "several kilobytes"
 * with room left for the first paragraph.
 *
 * Carry the ENCODING term through that bound rather than reasoning in flat
 * kilobytes, because `SNIPPET_FETCH_OCTETS` reasons that way and a later reader
 * revising one number against the other would otherwise be comparing two
 * different quantities. Both constants count ENCODED octets, so a base64 HTML
 * part yields roughly three quarters of its window after the transfer decode —
 * 1024 becomes ~768 bytes, and 16 384 becomes ~12 KiB of actual markup. The
 * conclusion survives the term (12 KiB still clears a several-kilobyte
 * preamble), but it is stated here so nobody later "corrects" 16 384 to 12 288
 * believing the number was decoded bytes all along.
 *
 * **Upper bound — one command's reply must stay bounded.** The worst case is a
 * full page at D-22's documented maximum of 100 rows — measured accepted and
 * returned in full at UAT check 2 — with every row resolving to HTML:
 * 100 x 16 384 = 1 638 400 bytes, inside the 2 MiB bound this project already
 * uses for a single message's wire size (`MAX_WIRE_MESSAGE_BYTES`) and for a
 * single literal (`MAX_LITERAL_OCTETS`). The next power of two puts that same
 * worst case at ~3.2 MB, outside it. 16 KiB is therefore the LARGEST escalation
 * that keeps a page's snippet reply inside the bound this phase already treats
 * as "one reply must not be unbounded" (T-02-59). This bound is on the WIRE, so
 * it is correctly computed in encoded octets and needs no decode adjustment.
 *
 * **What would change it**, so a later session revises this on evidence rather
 * than on taste: a real HTML part measured whose prose begins past 16 KiB, or a
 * page-size ceiling raised above 100 rows. Either one moves the number; nothing
 * else does.
 */
export const SNIPPET_HTML_FETCH_OCTETS = 16384;

/**
 * The snippet window a part's SUBTYPE earns it.
 *
 * One place, exported, because both snippet passes need this answer and a second
 * pass spelling its own rule is how the two quietly diverge — the same reasoning
 * that put `hasReadableText` and `htmlAlternativeOf` in this module rather than
 * at their call sites. It is keyed on the part being FETCHED, not on which pass
 * asked, so 02-17's recovery gets the escalated window whenever its target is an
 * HTML sibling.
 */
export function windowOctetsFor(part: BodyPart): number {
  return part.type === "text" && part.subtype === "html"
    ? SNIPPET_HTML_FETCH_OCTETS
    : SNIPPET_FETCH_OCTETS;
}

/** Everything outside the base64 alphabet, including the MIME line wrapping. */
const NON_BASE64 = /[^A-Za-z0-9+/=]/g;

/**
 * A transfer encoding's decoded bytes, trimmed so the decode cannot garble.
 *
 * **Exported for `mail_get_attachment` (plan 04-07), which hands it a WHOLE
 * part rather than a snippet window, and the trims stay correct for both.** The
 * quantum trim removes at most three characters from the tail of a complete
 * base64 body, and a complete body is a whole number of quanta, so it removes
 * nothing; the same is true of the quoted-printable escape trim against a
 * complete escape. Neither is a snippet-only heuristic — both are "do not decode
 * a fragment you were given only part of", and a whole part is the case where
 * there is no fragment.
 *
 * The `catch` returning an empty array is likewise unchanged and correct for the
 * new caller: a deliberately malformed part yields no text rather than failing
 * the tool call, which lands in `extract.ts` as an ordinary empty document.
 */
export function transferDecode(window: Uint8Array, encoding: string): Uint8Array {
  const normalised = encoding.toLowerCase();

  if (normalised === "base64") {
    // Base64 in MIME is line-wrapped, so the breaks come out before anything
    // is counted — otherwise the quantum arithmetic below counts CRLFs.
    const compact = DECODER.decode(window).replace(NON_BASE64, "");
    // Prevents: a window cut mid-quantum decoding to garbage. Four characters
    // carry three bytes, and a partial quantum carries no whole byte at all.
    const whole = compact.slice(0, compact.length - (compact.length % 4));
    try {
      const binary = atob(whole);
      const decoded = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        decoded[index] = binary.charCodeAt(index);
      }
      return decoded;
    } catch {
      // A deliberately malformed window yields a shorter snippet, never a
      // throw (T-02-23, accepted). The cost is a less useful preview.
      return new Uint8Array(0);
    }
  }

  if (normalised === "quoted-printable") {
    // Prevents: a stray `=` or `=C` fragment reaching the reader, because the
    // window's last escape was cut in half.
    const trimmed = DECODER.decode(window).replace(/=(?:[0-9a-fA-F]|\r)?$/, "");
    return decodeQuotedPrintable(trimmed);
  }

  // 7bit, 8bit, binary: already bytes.
  return window;
}

/**
 * Decode a quoted-printable body fragment to bytes.
 *
 * Exported for the save path's window decoder (`./stream-decode.ts`), which
 * feeds it one window at a time and carries an unfinished escape across the
 * cut. Unchanged by the export.
 */
export function decodeQuotedPrintable(text: string): Uint8Array {
  const decoded: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== "=") {
      decoded.push(text.charCodeAt(index) & 0xff);
      continue;
    }
    // A soft line break carries nothing.
    if (text[index + 1] === "\r" && text[index + 2] === "\n") {
      index += 2;
      continue;
    }
    if (text[index + 1] === "\n") {
      index += 1;
      continue;
    }
    const hex = text.slice(index + 1, index + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
      // Not an escape at all. Keep the `=` the sender wrote rather than
      // guessing what they meant.
      decoded.push(0x3d);
      continue;
    }
    decoded.push(Number.parseInt(hex, 16));
    index += 2;
  }
  return new Uint8Array(decoded);
}

/**
 * A partial-fetch window as a decoded string, and nothing else yet.
 *
 * The order below is not interchangeable: transfer-decode-safe trimming FIRST
 * (the window is still encoded), then the charset decode, then the trailing
 * replacement-character trim (the charset decode is what produces it).
 *
 * Deliberately stops short of presentation. Everything above this line is
 * about recovering the sender's characters from a window cut at an arbitrary
 * offset; what happens to those characters afterwards depends on the part's
 * subtype, and that is a decision only `snippetFromPart` holds.
 */
function decodeWindow(
  window: Uint8Array,
  encoding: string,
  charset: string | null,
): string {
  const decoded = transferDecode(window, encoding);

  return (
    decoderFor(charset)
      .decode(decoded)
      // Prevents: a lone U+FFFD hanging off the end because the window cut
      // through a multi-byte character. Only the TRAILING run is trimmed — one
      // in the middle is a genuine encoding problem in the message itself, and
      // hiding it would misreport what the sender sent.
      .replace(/�+$/, "")
  );
}

/**
 * A decoded string as a finished preview: one line, capped by code point.
 *
 * Runs LAST on every path, on text that is already in its final form. See
 * `snippetFromPart` for why that ordering is the whole point.
 */
function previewOf(text: string): string {
  // A preview is one line. Collapsing every whitespace run also removes the
  // leading blank lines many senders emit above their first paragraph.
  const collapsed = text.replace(/\s+/g, " ").trim();

  // Sliced by code point rather than by string index, so the cap cannot land
  // between the halves of a surrogate pair and emit a lone one.
  const characters = [...collapsed];
  return characters.length <= SNIPPET_MAX_CHARS
    ? collapsed
    : characters.slice(0, SNIPPET_MAX_CHARS).join("");
}

/**
 * The preview for a resolved body part — the ONE way to build a snippet.
 *
 * **Why this takes the part rather than the three values pulled off it.**
 * `selectTextPart` prefers a plain part and falls back to the HTML one, and the
 * comment at that fallback records what the fallback means: falling back to the
 * HTML half IS the record that a conversion is owed, and the caller is expected
 * to read the subtype and run it. That contract was stated and then not kept —
 * the full-body path honoured it and the page listing did not, because the
 * listing called a decoder that took the encoding and the charset as loose
 * scalars and never saw a subtype at all (G-02-3a). A shared selector cannot
 * catch that: both callers agreed about WHICH part held the text and disagreed
 * about what was owed on it. Taking the part closes the seam structurally —
 * there is no argument list from which the subtype can be omitted.
 *
 * **The conversion runs BEFORE the cap, and that order is the whole content of
 * this function.** Capping first would spend all two hundred characters on
 * markup — a doctype declaration and a style block are a routine preamble in
 * marketing mail — and then convert a preview that had already thrown the words
 * away. That is a subtler restatement of the bug being fixed, not a fix for it.
 *
 * **A non-HTML part is decoded for the PREVIEW ONLY, and the full body is left
 * byte-faithful. That asymmetry is a decision, not an oversight (G-02-9c).**
 * Senders emit preheader padding into the plain alternative as well as the HTML
 * one — uid 184735 opens with roughly 140 literal `&zwnj;` strings, which is the
 * entire two-hundred-character cap spent before the first real word, on 7 of 100
 * rows on the measured page.
 *
 * The question the gap was filed on is whether an entity reference in a
 * `text/plain` part is the sender's literal characters or padding to remove.
 * Both readings are defensible, which is exactly why this was a checkpoint
 * rather than a judgement call: a plain part is by definition what the sender
 * wrote, and that is why 02-15 confined its entity work to `htmlToText`.
 *
 * It was settled on the record in favour of decoding HERE and nowhere else. The
 * reason is that this function's output is ALREADY not what the sender wrote —
 * `previewOf` collapses every whitespace run and cuts at `SNIPPET_MAX_CHARS` —
 * so a presentation decision belongs at a layer that is admittedly a
 * presentation, and does not belong in `extractMessage`, whose entire contract
 * is fidelity (D-36). `mail_get_message` therefore returns the raw references
 * and this preview does not, and a test pins each half of that seam so neither
 * can drift into the other without a decision.
 *
 * The accepted cost is a sender who writes `&lt;` as literal text — a bug report
 * or a developer list — seeing it previewed as `<`. It is confined to two
 * hundred characters, and fetching the message still shows exactly what was
 * sent.
 *
 * Both steps run, in this order, and neither is optional: decoding alone turns
 * the padding into U+200C, which is invisible noise a reader still cannot see
 * and a model still pays for. 02-15 measured that on the HTML path, which is
 * why `htmlToText`'s tail spells the same pair the same way round. They are
 * REUSED rather than restated, so the `&amp;`-last ordering that keeps
 * `&amp;lt;` from collapsing to `<` holds on this path by construction.
 *
 * This is the ONLY exported way to build a preview, and it is exported alone on
 * purpose. A second entry point taking the encoding and the charset as loose
 * scalars is the seam the bug came through, still open and waiting for the next
 * consumer. There is no longer one to reach for.
 *
 * Returns `""` for a window that holds nothing readable. That is an outcome,
 * not an error: a snippet is a convenience, and no failure of one should cost
 * the caller a row.
 *
 * **That promise is STRUCTURAL on the HTML side, not a claim about the
 * converter.** The conversion runs inside a catch that answers `""`, because
 * the sentence above was true only for as long as every edit to `htmlToText`
 * and everything it calls stayed total — and it stopped being true exactly once
 * already: an unguarded `String.fromCodePoint` raised on a malformed numeric
 * reference and took down the entire listing page rather than one preview
 * (CR-01). The range guard fixes that specific raise; this makes the NEXT one
 * cost a preview instead of a page.
 *
 * The catch is silent, and that is CLAUDE.md §4 rather than an oversight: there
 * is no logging anywhere under `src/`, and the string being converted here is
 * an untrusted mail body. The evidence a reader gets is the empty preview
 * itself, which is the same evidence a genuinely blank window produces — and
 * the listing path already treats an empty preview as a fact to act on, since
 * that is what triggers the alternative-part recovery.
 */
export async function snippetFromPart(
  window: Uint8Array,
  part: BodyPart,
): Promise<string> {
  const text = decodeWindow(window, part.encoding, part.params.charset ?? null);

  if (part.type === "text" && part.subtype === "html") {
    try {
      // A preview gets no link targets. See `htmlToText`'s docstring for the
      // three reasons; the short one is that a snippet's two hundred characters
      // belong to prose, and one tracking URL can exceed that on its own.
      return previewOf(await htmlToText(text, "omit-links"));
    } catch {
      return "";
    }
  }
  // Preview only — see the docstring's G-02-9c paragraphs. `extractMessage`
  // deliberately does NOT do this to the same part.
  return previewOf(decodeEntities(text).replace(INVISIBLE_FORMATTING, ""));
}

/**
 * How many `References` tokens a fetched message reports alongside its count.
 *
 * Five, and the asymmetry behind that number is worth stating because a later
 * reader would otherwise flatten it.
 *
 * A forty-message thread's `References` is forty opaque angle-bracket ids the
 * model cannot act on — the payload shape PITFALLS #11 warns about, spent on
 * every fetch of every message in a long thread. What makes capping safe rather
 * than merely cheaper is D-69: the reply tool fetches the parent's headers
 * ITSELF, inside the compose call, because the opaque message id encodes the
 * mailbox, the UIDVALIDITY and the UID and not the parent's `Message-ID`. So
 * the full chain is load-bearing in exactly one place, and it is a place the
 * model never sees. `References` in a FETCH response is informational.
 *
 * That is the whole argument, and it does not survive being repeated as "five
 * is enough": five is enough for a human reading a transcript to recognise a
 * thread, and the full count travels alongside so nothing is hidden. If the
 * reply path ever stopped fetching its own parent, this cap would become a
 * correctness bug rather than a saving.
 */
export const REFERENCES_PREVIEW_LIMIT = 5;

/**
 * One address as a message declared it — never as it was verified.
 *
 * Both fields are stranger-authored. The display name is a string whoever sent
 * the message chose, and the address is what the message claims rather than
 * what any check confirmed, which is the same distinction `fromAddress` already
 * carries one field up.
 */
export interface MessageAddress {
  /** The display name, or `null` when the field carried only an address. */
  name: string | null;
  /** The bare address. */
  address: string | null;
}

/**
 * Every address in one parsed header field, groups flattened.
 *
 * A `group` — `Team: alice@x, bob@x;` — carries its members one level down, and
 * a reader that only looked at `.address` would silently drop every one of
 * them. On a recipient list that is a wrong answer reported as a right one, and
 * `./service.ts`'s `addressesOf` learned it the same way on the reply path.
 *
 * Returns `[]` for a field that was absent. Never `null`: the caller cannot
 * distinguish "no recipients" from "not asked", and a null would invite a check
 * at every call site that a stable empty array makes unnecessary.
 */
export function recipientsFrom(
  list: { name?: string; address?: string; group?: { name?: string; address: string }[] }[] | undefined,
): MessageAddress[] {
  const found: MessageAddress[] = [];
  for (const entry of list ?? []) {
    if (typeof entry.address === "string" && entry.address.length > 0) {
      found.push({
        name: entry.name !== undefined && entry.name.length > 0 ? entry.name : null,
        address: entry.address,
      });
      continue;
    }
    for (const member of entry.group ?? []) {
      if (member.address.length > 0) {
        found.push({
          name:
            member.name !== undefined && member.name.length > 0
              ? member.name
              : null,
          address: member.address,
        });
      }
    }
  }
  return found;
}

/**
 * The `References` chain, as tokens, in the order the header carried them.
 *
 * The library hands back the field's raw value with folds already merged, so
 * splitting on whitespace recovers the tokens a folded chain arrived as. Doing
 * it any other way — reading a physical line, say — reports a chain missing
 * every token past the first fold, which then looks like a short thread rather
 * than like a parse failure.
 *
 * Nothing here shape-checks a token or drops a malformed one. That is a
 * deliberate non-decision: this value is REPORTED, and a reported header should
 * say what the header said. The refuse-or-drop rules belong to `./compose.ts`,
 * which puts tokens back into a header of a message the user will send, and
 * applying them here would quietly change what a user is shown.
 */
export function referencesFrom(raw: string | undefined): string[] {
  return (raw ?? "").split(/\s+/).filter((token) => token.length > 0);
}

/** A decoded message. Every string field here is stranger-authored. */
export interface ParsedMessage {
  subject: string | null;
  /** The sender's display name, exactly as they chose it. */
  fromName: string | null;
  /** The sender's address, as the message declares it — not as it was verified. */
  fromAddress: string | null;
  /**
   * The `To` recipients, with the display names their sender chose (D-70).
   *
   * Always an array. A message addressed to nobody visible — a Bcc-only send —
   * yields `[]` rather than null, which is a fact about the message rather than
   * a missing value.
   */
  to: MessageAddress[];
  /** The `Cc` recipients, on the same terms as `to`. Always an array. */
  cc: MessageAddress[];
  /**
   * The most recent `REFERENCES_PREVIEW_LIMIT` tokens of the thread's chain.
   *
   * The TAIL rather than the head, because a `References` chain is ordered
   * oldest first: keeping the head would show where a thread began and hide
   * where it currently is. `referencesCount` reports the full length, so a
   * shorter array here is never mistaken for a shorter thread.
   */
  references: string[];
  /**
   * How many tokens the chain actually carried.
   *
   * The one field in this interface that is NOT stranger-authored: it is a
   * number this server derived by counting a parsed header. That is what puts
   * it in the trusted half of the tool response while `references` itself sits
   * inside the fence, the same split `attachmentCount` already makes against
   * the attachment rows it counts.
   */
  referencesCount: number;
  /** The `Date` header, ISO-formatted by the library. */
  date: string | null;
  /** The `Message-ID` header. */
  messageId: string | null;
  /** The readable body. Empty string when the message carried no body at all. */
  text: string;
  /** The raw HTML part, when one existed. */
  html: string | null;
  /**
   * Which part `text` came from, or `null` when no part was chosen.
   *
   * NOT a claim that `text` is non-empty. An HTML part that converts to
   * nothing — an image-only marketing half, say — is still the part that was
   * chosen, so `"text/html"` alongside an empty `text` is a real and correct
   * pair. `extractMessage` says why the two arms gate differently (WR-03).
   */
  bodySource: "text/plain" | "text/html" | null;
  /** Whether `text` hit `MAX_EXTRACTED_TEXT_BYTES` and was cut. */
  truncated: boolean;
  /** Always an array. A message with no attachments yields `[]`, never `null`. */
  attachments: AttachmentMeta[];
}

const ENCODER = new TextEncoder();

/**
 * Elements whose text is markup or metadata, never body content.
 *
 * `title` is in the list because its text is chrome rather than correspondence,
 * and `script`/`style` are in it because their text is code — see `htmlToText`
 * for why excluding them needs a counter rather than a flag.
 */
const NON_CONTENT_ELEMENTS = "script,style,head,noscript,title";

/**
 * The same tags as a set, for the inline-hidden handler's disjointness guard.
 *
 * DERIVED from the selector above rather than written out a second time, and
 * that is the whole point of it existing. A hand-copied list is a list that
 * drifts the first time someone adds a tag to one of them, and the drift is
 * silent: the two handlers would both claim the new tag, both register an
 * `onEndTag`, and — per probe P4, where the later registration REPLACES the
 * earlier — the counter would finish latched at +1 and blank the rest of the
 * body. Deriving it means adding a tag above extends the guard automatically.
 */
const NON_CONTENT_TAGS = new Set(NON_CONTENT_ELEMENTS.split(","));

/** Elements that imply a line break where they open. */
const BLOCK_ELEMENTS =
  "p,div,br,li,tr,h1,h2,h3,h4,h5,h6,blockquote,table";

/**
 * Named references worth decoding, plus the non-breaking space.
 *
 * The first six are the markup-critical set. The rest are what real mail
 * actually carries: typographic punctuation a marketing template emits by
 * default, the symbol trio a signature block ends with, and the invisible
 * formatting family a preheader is padded with — `&zwnj;` alone appeared
 * roughly 130 times at the head of one observed message (G-02-3c).
 *
 * `&amp;` is deliberately NOT a row here. See `decodeEntities` for why it can
 * only be handled after this table has run.
 *
 * Order within the table cannot matter, and this is the reason rather than an
 * assumption: every key ends with a semicolon and no key is a substring of
 * another, so no sequential replacement can consume a prefix of a later one.
 * Adding a row that breaks either property would make the iteration order of
 * this object load-bearing.
 */
const NAMED_ENTITIES: Record<string, string> = {
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&#39;": "'",
  "&nbsp;": " ",
  // The invisible three are written as escapes on purpose: a literal
  // zero-width character in source is a character no reader of this file can
  // see, no diff can show, and no review can check.
  "&zwnj;": "\u200C",
  "&zwj;": "\u200D",
  "&shy;": "\u00AD",
  "&hellip;": "…",
  "&mdash;": "—",
  "&ndash;": "–",
  "&rsquo;": "’",
  "&lsquo;": "‘",
  "&ldquo;": "“",
  "&rdquo;": "”",
  "&trade;": "™",
  "&reg;": "®",
  "&copy;": "©",
};

/**
 * Decode the entity references `HTMLRewriter` leaves alone.
 *
 * Plan 02-01's probe measured this rather than assuming it: `HTMLRewriter` is
 * built for byte-preserving transformation and delivers EVERY entity form
 * undecoded — named, non-breaking space, decimal numeric and hexadecimal
 * numeric alike. The measurement is recorded verbatim in `test/probes.test.ts`.
 *
 * `&amp;` is decoded LAST, deliberately. Decoding it first would turn
 * `&amp;lt;` — which a sender wrote to display the literal text `&lt;` — into
 * `&lt;` and then into `<`, silently changing what the sender wrote.
 *
 * The table is an ALLOWLIST, and a reference it does not cover is left exactly
 * as the sender wrote it rather than removed. Stripping unrecognised forms was
 * considered and rejected for G-02-3c: an accented, currency or mathematical
 * entity is in no table this project will ever write, and stripping deletes it
 * from correspondence a person is trying to read.
 */
function decodeEntities(text: string): string {
  let decoded = text;
  for (const [entity, character] of Object.entries(NAMED_ENTITIES)) {
    decoded = decoded.split(entity).join(character);
  }
  decoded = decoded.replace(/&#(\d+);/g, (match, code: string) =>
    safeCodePoint(Number(code)) ?? match,
  );
  decoded = decoded.replace(/&#[xX]([0-9a-fA-F]+);/g, (match, code: string) =>
    safeCodePoint(Number.parseInt(code, 16)) ?? match,
  );
  return decoded.split("&amp;").join("&");
}

/**
 * A code point this module can safely materialise, or `null`.
 *
 * **`String.fromCodePoint` RAISES, and both numeric branches above match values
 * it will not accept.** Anything above U+10FFFF throws `RangeError`, and the
 * digit runs those patterns match are unbounded — `&#1114112;`, `&#x110000;`
 * and a twenty-digit decimal all reach it. The input is stranger-authored HTML
 * from an email body, which is the most hostile surface this project has, and
 * the raise does not stop at the snippet: it travels out of `htmlToText`, out
 * of `snippetFromPart`, out of `pagePreviews` and out of `fetchPage`, so one
 * such message in a folder costs the caller the whole listing PAGE rather than
 * one preview (CR-01).
 *
 * A lone surrogate is refused for a different reason and deliberately in the
 * same place. It does not raise — U+D800 is inside the acceptable range — but
 * it is half of a character rather than a character, so it renders as nothing a
 * reader can see and is not valid UTF-8 on its own. A guard written only
 * against the raise would let it through, which is precisely what happened
 * before this existed.
 *
 * `null` means "leave the reference alone", and the caller does exactly that.
 * That is not a new policy invented for this case: the allowlist above already
 * leaves a reference it does not cover exactly as the sender wrote it, on the
 * ground that deleting it removes something from correspondence a person is
 * trying to read. A reference naming no character is such a reference.
 */
function safeCodePoint(value: number): string | null {
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff) return null;
  if (value >= 0xd800 && value <= 0xdfff) return null;
  return String.fromCodePoint(value);
}

/**
 * Formatting code points a browser renders as NOTHING, removed on the way out.
 *
 * This is a rendering decision, and it lives here rather than in
 * `decodeEntities` for that reason: the decoder stays a pure decoder, and
 * `htmlToText` is already the function that renders — it turns `&nbsp;` into an
 * ordinary space rather than preserving it, and it drops markup wholesale.
 *
 * Decoding `&zwnj;` without this step converts VISIBLE noise into INVISIBLE
 * noise. Preheader padding is near-universal in marketing mail and lands at the
 * top of the extracted text; one observed message carried roughly 130 sequences
 * ahead of its first real word (G-02-3c). The reader sees nothing either way,
 * and the model pays for it either way, so a decoder alone would have moved the
 * cost rather than removed it.
 *
 * Membership, and why each one:
 * - U+200B zero-width space, U+200C zero-width non-joiner — layout padding.
 * - U+FEFF zero-width no-break space, in its IN-TEXT role. As a leading byte
 *   order mark it is the encoding's business, not this function's; by the time
 *   a string reaches here it is text, and mid-text it renders as nothing.
 * - U+00AD soft hyphen — a hint about where a word MAY break, invisible unless
 *   the layout engine takes it up. There is no layout engine here.
 *
 * **U+200D zero-width JOINER is deliberately excluded, and must stay excluded.**
 * It is the one member of this family that carries meaning rather than layout:
 * inside an emoji sequence it is what fuses several code points into one glyph,
 * so removing it splits a family emoji into separate people. It is decoded by
 * `NAMED_ENTITIES` and then left alone. A test pins this, because the joiner
 * looks exactly like the rest of the family to anyone tidying this list up
 * later.
 *
 * This narrows a spoofing surface rather than widening one (T-02-41):
 * zero-width characters are a known way to split a string so that a reader — or
 * a filter — does not see what a model sees.
 */
const INVISIBLE_FORMATTING = /[\u200B\u200C\uFEFF\u00AD]/g;

/**
 * The non-breaking space, rendered as an ordinary space so the collapse folds it.
 *
 * Applied to the CHARACTER, which makes the raw form behave exactly as the
 * `&nbsp;` entity already did — the same inconsistency G-02-3c reported, seen
 * from the other side. Two spellings of one rendered result should not extract
 * differently.
 */
const NO_BREAK_SPACE = /\u00A0/g;

/**
 * Whether a conversion emits link targets. A REQUIRED argument, never defaulted.
 *
 * A default is exactly the seam that produced G-02-3a — a caller that never had
 * to say what it wanted, and therefore never noticed it was getting the wrong
 * thing. 02-16 closed that seam by PROMOTING the argument rather than fixing the
 * one call site that had it wrong, and this follows the same rule: every caller
 * states a policy, so every caller is a place the question was answered on
 * purpose.
 */
export type LinkPolicy = "emit-links" | "omit-links";

/**
 * The longest target emitted whole, in CODE POINTS.
 *
 * The question a target answers is "where does this actually go", and the
 * scheme, the host and the leading path answer it — all of which sit at the
 * FRONT. The tail of a 900-character tracking URL is campaign parameters, which
 * answer nothing a reader asked. 120 keeps a full host plus a substantial path
 * on every realistic link and cuts an absurd one to roughly a seventh.
 */
export const MAX_EMITTED_URL_CHARS = 120;

/**
 * Appended inside the brackets when the cap trips.
 *
 * Unmistakable by construction rather than by convention: RFC 3986 permits
 * neither U+2026 nor a space un-encoded in a URI, so a whole target can never
 * end in this and a truncated one can never be read as complete.
 */
export const URL_TRUNCATION_MARKER = "… truncated";

/**
 * Characters removed from a target before it is emitted.
 *
 * Every one is a character RFC 3986 excludes from a URI and which a legitimate
 * target must percent-encode, so removing them cannot change what a well-formed
 * target reads as. What removal prevents is the two ways a crafted target can
 * lie (T-02-54):
 *
 * - `>` would close the emitted bracket early, so the attacker's prose after it
 *   reads as document text rather than as part of the URL. `<` goes with it.
 * - A zero-width character splits a hostname, so `https://evil[U+200B].example`
 *   reads to a human as one host and resolves as another — T-02-41's shape,
 *   already a recorded concern in this module.
 *
 * `\s` is doing more work than it looks: JavaScript's whitespace class includes
 * U+00A0 and U+FEFF, both of which are in the same splitting family.
 *
 * **U+200D is stripped HERE even though `INVISIBLE_FORMATTING` deliberately
 * excludes it, and that is a third answer rather than an inconsistency.** This
 * module now asks about the zero-width joiner in three places and the answers
 * differ because the questions do. In body text it fuses an emoji sequence into
 * one glyph and must survive (`INVISIBLE_FORMATTING`). In the readability
 * predicate a string of nothing but joiners has nothing to join and is not
 * content (`hasReadableText`). In a URL it is not a glyph fuser at all — there
 * is no emoji sequence in a hostname — it is purely a splitting character, so
 * it goes.
 */
const URL_UNSAFE_CHARACTERS =
  /[\u0000-\u001F\u007F\s<>\u200B\u200C\u200D\u00AD]/g;

/**
 * Schemes whose target is emitted. An ALLOWLIST, and it must stay one.
 *
 * `mailto:` and `tel:` are the two the reported defect named, on the ground that
 * the address is already the label and repeating it is noise. An allowlist
 * delivers both and covers three more cases in one rule:
 *
 * - **`javascript:` and `data:` are a security exclusion, not an aesthetic one
 *   (T-02-55).** Emitting one would place attacker-authored script source
 *   directly into the extracted text handed to the model — reopening the exact
 *   hazard the skip counter above exists to close (T-02-13), through a door this
 *   feature would otherwise have built. Do not relax this to a denylist: a
 *   denylist is a list of the attacks already thought of.
 * - A relative href (`/unsubscribe`) and a bare fragment (`#`) name no reachable
 *   place at all, because a mail body has no base URL. Emitting them is noise.
 *
 * The allowlist also fails in the safe direction. An unfamiliar scheme emits
 * nothing, which loses information rather than inventing it.
 */
const EMITTED_SCHEMES = /^https?:\/\//;

/**
 * A raw `href` as the reader-visible target it names, or `null` to emit nothing.
 *
 * **The order of operations is the whole content of this function, and one step
 * of it deviates from the plan that specified it — deliberately, because the
 * specified order reopens T-02-54.**
 *
 * Probe P1 measured that `getAttribute` returns an attribute RAW, with entity
 * references intact, exactly as A4 measured for text. So the value arrives
 * needing one decode. The plan called for sanitising first and decoding second;
 * done in that order, a sender writing `&#62;` gets a literal `>` back AFTER the
 * sanitiser has already run, and closes the emitted bracket early — precisely
 * the attack the sanitiser exists to stop. Decoding first and sanitising second
 * makes the invariant hold on the string actually emitted, which is what the
 * angle-bracket delimiter argument rests on.
 *
 * One decode, never two. `decodeEntities` is a single non-recursive pass, so a
 * sender who wrote `&amp;#62;` — meaning the six visible characters `&#62;` —
 * gets those characters and not a `>`: the named table finds no key, the numeric
 * patterns find no `&#` sequence, and `&amp;` decodes last.
 *
 * Nothing after the sanitiser can reintroduce an unsafe character. The cap
 * slices code points, the marker is appended outside the URL by design, and the
 * ampersand re-escape at the call site produces only `&amp;` sequences the
 * wholesale pass turns back into `&`.
 *
 * Returns the UNCAPPED form. The cap belongs after the same-target comparison,
 * so a long naked-URL link is still recognised as naked.
 */
function linkTargetOf(href: string | null): string | null {
  if (href === null) return null;

  const target = decodeEntities(href).replace(URL_UNSAFE_CHARACTERS, "");
  if (target === "") return null;
  if (!EMITTED_SCHEMES.test(target.toLowerCase())) return null;

  return target;
}

/**
 * A target as it appears inside the brackets: capped, marked when cut.
 *
 * Sliced by code point with the spread-and-slice idiom `previewOf` uses, so the
 * cut cannot land between the halves of a surrogate pair.
 */
function boundedTarget(target: string): string {
  const characters = [...target];
  if (characters.length <= MAX_EMITTED_URL_CHARS) return target;
  return (
    characters.slice(0, MAX_EMITTED_URL_CHARS).join("") + URL_TRUNCATION_MARKER
  );
}

/**
 * Both sides of the same-target comparison, brought to one form.
 *
 * Applied to a throwaway string that is never pushed. The caller decodes the
 * LABEL before calling this and does not decode the target, because the target
 * has already been decoded exactly once by `linkTargetOf` — each side reaches
 * its decoded form by exactly one route.
 */
function compareForm(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "");
}

/**
 * Elements HTML gives no end tag, on which `onEndTag` must never be called.
 *
 * **Probe P2 measured that this is worse than a latch.** The question was
 * whether `onEndTag` silently never fires for a void element, which would leave
 * a counter opened on one latched open and blank the rest of the document.
 * It does not silently do anything: `element.onEndTag()` RAISES
 * `TypeError: Parser error: No end tag.` synchronously inside the element
 * handler, for `img` and `br` alike and for the bare and self-closing spellings
 * both. Uncaught, that propagates out of the `.text()` await, out of
 * `htmlToText`, and out of `extractMessage`, which has no catch — so a counter
 * opened on a tracking pixel does not merely lose the body, it fails the whole
 * message fetch.
 *
 * `<img style="display:none">` IS a tracking pixel, and it is the single most
 * common element in marketing mail, so this is the live case rather than a
 * corner one. Nothing is given up by the guard: a void element has no text
 * content to suppress, so there is never a reason to open the counter on one.
 */
const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input",
  "link", "meta", "param", "source", "track", "wbr",
]);

/**
 * The declarations that mean "this is not rendered", anchored at BOTH ends.
 *
 * Anchoring is the whole content of the rule, because this is string work on
 * attacker-authored input and the sender chooses every byte of it. A pattern
 * matching a SUBSTRING would let a sender delete arbitrary text from their own
 * message by embedding the literal somewhere harmless-looking (T-02-57), and
 * each anchor is what makes a specific false positive fail correctly:
 *
 * - `display:none-such` — the value is `none-such`, not `none`. The trailing
 *   anchor rejects it.
 * - `background-image:url(https://e.invalid/x?s=display:none)` — the
 *   declaration's property is `background-image`. The leading anchor rejects
 *   it, and the `;` split cannot help an attacker either: splitting a
 *   `url(data:image/svg+xml;base64,…)` value produces fragments, and no
 *   fragment can match because each pattern requires its own property name at
 *   position zero.
 * - `--custom:display:none` — a custom property, whose declaration starts with
 *   `--custom:`. Rejected for the same reason.
 * - `display : none`, `DISPLAY:NONE` and `display:none !important` all match,
 *   which is what the `\s*` and the caller's lowercasing are for.
 */
const HIDDEN_DECLARATIONS = [
  /^display\s*:\s*none\s*(?:!\s*important)?$/,
  /^visibility\s*:\s*hidden\s*(?:!\s*important)?$/,
];

/**
 * Whether an inline `style` attribute declares its element unrendered.
 *
 * **The failure direction is KEEPING text, and that is the entire safety
 * argument for how conservative this rule is.** A missed hidden block reads as
 * duplication — which is today's behaviour and exactly the defect being fixed,
 * so the cost of a miss is that this fix did not fire. A false positive
 * silently EATS real correspondence, which is the failure class D-36 declined
 * for quoted history and the one this project keeps refusing. When in doubt, do
 * not suppress.
 *
 * The attribute is matched RAW. Probe P1 measured that `getAttribute` returns
 * an attribute with its entity references intact, so a sender writing
 * `display:&#110;one` is not matched here. That is deliberately left alone
 * rather than decoded: it fails in the KEEPING direction, and a decode would
 * add a second way for a crafted value to reach the matcher.
 */
function declaresHidden(style: string | null): boolean {
  if (style === null) return false;

  return style.split(";").some((declaration) => {
    const normalised = declaration.trim().toLowerCase();
    return HIDDEN_DECLARATIONS.some((pattern) => pattern.test(normalised));
  });
}

/**
 * Extract readable text from an HTML body part.
 *
 * **The skip counter is a security control, not a tidiness measure (T-02-13).**
 * The published pattern this replaces guarded its text handler with
 * `Text.removed`, reasoning that a `<script>` dropped by an earlier element
 * handler would be marked removed by the time its text arrived. Plan 02-01
 * measured that inside real workerd and it is false: `removed` is `false` on
 * EVERY chunk, including text inside elements a prior handler removed.
 * `element.remove()` drops the element from the rewriter's OUTPUT and does not
 * suppress the text handler for content inside it, and `removed` reports only
 * whether that chunk was removed by an earlier TEXT handler. The guard never
 * fires and never could — so the published loop puts attacker-authored
 * JavaScript source, CSS and `<title>` text into the string handed to the
 * model. The measurement is in `test/probes.test.ts`; do not reintroduce the
 * `removed` check as the mechanism.
 *
 * The counter opens in `element()` and closes from `onEndTag()`, which the same
 * probe verified fires once per open (4 against 4) so the counter cannot latch
 * open and blank an entire body. If a malformed message did leave it latched,
 * the failure direction is losing text rather than leaking script source, which
 * is the right way round for this control.
 *
 * Consuming the transformed body is what runs the handlers — `.transform()` is
 * lazy, and without the `await` below nothing fires and the output stays empty.
 * The returned HTML is discarded; extraction happens in the handlers. Text also
 * arrives fragmented, which is why chunks are accumulated and joined once
 * rather than inspected individually.
 *
 * ## Link targets (G-02-3d)
 *
 * Under `"emit-links"` a link contributes its own text and then its target,
 * separated by one space and wrapped in angle brackets:
 *
 * ```
 * whole:      Click here <https://example.invalid/meet/abc>
 * truncated:  Click here <https://example.invalid/very/long/pre… truncated>
 * ```
 *
 * Before this, the converter collected text nodes only and never read an
 * attribute, so `<a href="https://real">Click here</a>` yielded `Click here` —
 * the model could not answer "what is the meeting link", and a link labelled
 * "Apple Support" pointing at some other host was not merely unverifiable but
 * invisible.
 *
 * **Angle brackets rather than parentheses, and the reason is provable rather
 * than stylistic.** RFC 3986 excludes `<` and `>` from a URI entirely, so after
 * `URL_UNSAFE_CHARACTERS` has run they cannot occur inside the target and the
 * delimiters are unambiguous. A parenthesis is a legal sub-delimiter and appears
 * in real URLs, so parentheses would be ambiguous on exactly the links people
 * share.
 *
 * The target is emitted from `onEndTag`, not from `element()`. The open-tag
 * handler fires before any text has arrived, so emitting there would put the URL
 * BEFORE its label. `onEndTag` is also what makes the label available at all:
 * `collected.slice(start)` between the two callbacks IS the link's visible text,
 * so no second buffer is needed. Probe P2 measured that an `<a>` closes cleanly
 * even when written self-closing or left unclosed, so this registration needs no
 * void guard of its own.
 *
 * **The scheme allowlist is a security control (T-02-55)** — see
 * `EMITTED_SCHEMES`. **The sanitiser is a spoofing control (T-02-54)** — see
 * `URL_UNSAFE_CHARACTERS`. Neither is an optimisation.
 *
 * **The ampersand round trip is exactly-once by construction, and the proof is
 * the reason no placeholder scheme is needed.** `linkTargetOf` decodes the raw
 * attribute once (probe P1 measured attributes arriving RAW). The target is then
 * re-escaped — every `&` becomes `&amp;` — before being pushed, so the single
 * wholesale `decodeEntities` pass at the bottom of this function restores it
 * exactly. Every entity reference begins with `&`, so escaping every `&` leaves
 * no residue of the target able to match a `NAMED_ENTITIES` key, a `&#\d+;` form
 * or a `&#x..;` form; the only thing the pass can find is what this step wrote,
 * and `&amp;` is decoded last by design. `?a=1&b=2` survives as `?a=1&b=2`, and a
 * literal `?q=&nbsp;` survives as `?q=&nbsp;` — in `&amp;nbsp;` the character
 * before `nbsp;` is a semicolon, and the table key requires an ampersand there.
 * A placeholder would be worse than the problem it solved: the attacker writes
 * the message body, and can therefore write the placeholder.
 *
 * **The same-target skip is deliberately conservative, and the failure direction
 * is stated because it is the whole point of the feature.** A link whose visible
 * text already IS its target emits the URL once, not twice; naked-URL links are
 * extremely common. The comparison is near-exact (case, surrounding whitespace,
 * a `http(s)://` prefix and trailing slashes are ignored) and is made BEFORE the
 * cap, so a long naked URL is still recognised as naked. A label that is a
 * truncated rendering of its URL is NOT equal, so the target is emitted — the
 * full URL is genuinely new information there. So a missed skip costs noise,
 * while an over-eager skip would suppress exactly the hidden destination this
 * feature exists to reveal. When in doubt, emit.
 *
 * **Links are omitted on the snippet path, and that is a decision rather than an
 * omission.** `snippetFromPart` passes `"omit-links"`; `extractMessage` passes
 * `"emit-links"`. Three reasons: a snippet is 200 CHARACTERS and one tracking
 * URL routinely exceeds that on its own, so a single link would consume an
 * entire preview — the exact failure shape G-02-3a was about, spending the cap
 * on something that is not prose; the question a target answers is asked of a
 * message, not of a listing row; and a test already asserts a snippet contains
 * no `<` and no `>`, so the constraint was pinned before it was written down.
 * The policy is a REQUIRED parameter for the reason `LinkPolicy` gives.
 *
 * Deduplicating repeated targets is deliberately NOT done. A marketing email may
 * link one URL thirty times and will emit it thirty times. Deduplication needs
 * state and is a stripping heuristic, which is the class D-36 declined; the cost
 * is bounded by `MAX_EMITTED_URL_CHARS` per target and by
 * `MAX_EXTRACTED_TEXT_BYTES` overall (T-02-58, accepted).
 *
 * ## Inline hidden declarations (G-02-3e)
 *
 * An element whose inline `style` attribute declares `display:none` or
 * `visibility:hidden` contributes no text. Marketing senders ship a desktop and
 * a mobile variant of the same content and hide one with CSS; because `<style>`
 * is stripped by the skip counter above, this converter could not know which
 * block was hidden and collected both, so the reader saw every sentence twice.
 *
 * **Why an inline declaration is admissible where the alternatives are not.** It
 * is an explicit sender statement that the content is not rendered — the same
 * CLASS of signal as skipping `<script>`, rather than an inference about what
 * the content means. That distinction is what keeps this out of the territory
 * D-36 declined. Three neighbouring things are therefore NOT done, and their
 * absence is a decision rather than an oversight:
 *
 * - **The `hidden` attribute and `aria-hidden="true"`.** `aria-hidden` in
 *   particular is an accessibility hint whose content is frequently still
 *   rendered, so honouring it would delete visible text.
 * - **Any `<style>`-block or `@media` evaluation.** Unanswerable without a
 *   viewport. `<style>` content stays suppressed by the control above and is
 *   never parsed.
 * - **Deduplicating the duplicate text itself.** That is a stripping heuristic,
 *   which is the class D-36 declined; this fix reads a declaration instead.
 *
 * The matching rule and its failure direction are in `declaresHidden`. The
 * suppression reuses the SAME skip counter rather than adding a second,
 * differently-shaped path — a parallel mechanism would not inherit the
 * measurement that says this one cannot latch.
 *
 * **Two guards keep that non-latching property true under the extension, and
 * each answers a measured behaviour rather than a supposed one.** The
 * disjointness guard (`NON_CONTENT_TAGS`) makes it unreachable for one element
 * to be counted by both handlers, because probe P4 measured that a second
 * `onEndTag` registration REPLACES the first. The void guard (`VOID_ELEMENTS`)
 * keeps the counter off elements that have no end tag, because probe P2
 * measured that `onEndTag` RAISES on one. A third case is handled by chain
 * ORDER rather than by a guard: an `<a>` that itself declares hidden is matched
 * by this handler and by the link handler both, and this handler sits ahead of
 * it, so the link handler sees a non-zero counter and returns before it can
 * register a replacing callback.
 *
 * An unclosed NON-void element — `<div style="display:none">` with no closing
 * tag — still latches, and that is accepted rather than fixed. It is the same
 * failure direction this module already documents for an unclosed `<script>`,
 * losing text rather than leaking it, and the void guard is what removes the
 * common case that would otherwise trigger it constantly.
 */
export async function htmlToText(
  html: string,
  links: LinkPolicy,
): Promise<string> {
  const collected: string[] = [];
  let skipDepth = 0;

  const transformed = new HTMLRewriter()
    .on(NON_CONTENT_ELEMENTS, {
      element(element) {
        skipDepth += 1;
        element.onEndTag(() => {
          skipDepth -= 1;
        });
      },
    })
    .on("*", {
      element(element) {
        const tag = element.tagName.toLowerCase();

        // The disjointness guard. An element can match BOTH rules —
        // `<style style="display:none">` is the obvious case, and any of
        // `head`, `noscript` or `title` carrying a style attribute is another.
        // The handler above has already claimed it and registered the only
        // `onEndTag` it may have; per probe P4 a second registration REPLACES
        // the first, so counting it twice here would finish latched at +1.
        // This guard does not make that double registration safe, it makes it
        // unreachable. Lowercased at the comparison site regardless of P5's
        // measurement, because a guard resting on an undocumented case
        // convention is a guard one runtime update from being wrong.
        if (NON_CONTENT_TAGS.has(tag)) return;
        if (VOID_ELEMENTS.has(tag)) return;
        if (!declaresHidden(element.getAttribute("style"))) return;

        skipDepth += 1;
        element.onEndTag(() => {
          skipDepth -= 1;
        });
      },
    })
    .on(BLOCK_ELEMENTS, {
      element() {
        if (skipDepth === 0) collected.push("\n");
      },
    })
    .on("a", {
      element(element) {
        if (links === "omit-links" || skipDepth > 0) return;

        const target = linkTargetOf(element.getAttribute("href"));
        if (target === null) return;

        // Captured per element by the closure rather than in a shared
        // variable, so a nested anchor — which the parser will not produce,
        // but which nothing here needs to rely on it not producing — cannot
        // make one link's label be measured from another link's start.
        const start = collected.length;

        element.onEndTag(() => {
          // Re-checked rather than assumed: the counter can have opened
          // between this link's start and end tags.
          if (skipDepth > 0) return;

          // The label is still raw HTML text at this point, hence the decode.
          // The target was decoded exactly once by `linkTargetOf` and is not
          // decoded again — each side reaches its comparable form by one route.
          const label = decodeEntities(collected.slice(start).join(""));
          if (compareForm(label) === compareForm(target)) return;

          collected.push(` <${boundedTarget(target).split("&").join("&amp;")}>`);
        });
      },
    })
    .on("*", {
      text(chunk) {
        if (skipDepth === 0 && chunk.text) collected.push(chunk.text);
      },
    })
    .transform(new Response(html));

  await transformed.text();

  return decodeEntities(collected.join(""))
    .replace(INVISIBLE_FORMATTING, "")
    .replace(NO_BREAK_SPACE, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** The decoded byte length of one attachment's content. */
function decodedSize(content: ArrayBuffer | Uint8Array | string): number {
  if (typeof content === "string") return ENCODER.encode(content).byteLength;
  return content.byteLength;
}

/**
 * Truncate to a byte ceiling without splitting a character in half.
 *
 * Slicing by character count would be wrong on every non-ASCII body, and
 * slicing raw bytes would be wrong at the boundary. Encoding, cutting, and
 * decoding non-fatally is what keeps the returned string valid — the one place
 * in this project where a U+FFFD substitution is the correct behaviour rather
 * than the bug, because here the input really was cut mid-character by us.
 *
 * Reports whether it cut rather than leaving the caller to compare two string
 * lengths afterwards. A comparison in JavaScript string units would agree with
 * the byte-measured bound for ASCII and disagree for everything else, which is
 * the exact class of bug this module measures in bytes to avoid.
 *
 * Exported for `./extract.ts` (plan 04-07), so an attachment's extracted text is
 * bounded by the same mechanism a body's is rather than by a second ceiling. The
 * argument for the disposition — truncate and flag, never raise — is in
 * `MAX_EXTRACTED_TEXT_BYTES`'s docstring and is unchanged by the second caller.
 */
export function truncateToBytes(
  text: string,
  limit: number,
): { text: string; truncated: boolean } {
  const bytes = ENCODER.encode(text);
  if (bytes.byteLength <= limit) return { text, truncated: false };
  return {
    text: new TextDecoder("utf-8").decode(bytes.subarray(0, limit)),
    truncated: true,
  };
}

/**
 * The joiner, removed for the READABILITY PREDICATE and nowhere else.
 *
 * Deliberately a second constant rather than a row added to
 * `INVISIBLE_FORMATTING`: that set is what `htmlToText` deletes from text a
 * reader will see, and the joiner must survive that deletion or every family
 * emoji in the user's mail comes apart. See `hasReadableText` below for why the
 * same character answers the two questions differently.
 */
const ZERO_WIDTH_JOINER = /\u200D/g;

/**
 * Whether a decoded part carries anything a reader would actually see.
 *
 * **A length test is not enough, and that is the whole reason this exists.** A
 * newline is one character long, so `"\n".length > 0` reports a body where
 * there is none — and senders emit a blank `text/plain` part routinely as a
 * `multipart/alternative` placeholder, filling the slot without putting
 * anything in it. Under a length test that empty placeholder wins over the
 * populated HTML part beside it, and a message with real content reads as one
 * newline. Confirmed live on two real messages: a 239 KB one whose entire body
 * decodes to `"\n"`, and another whose body is `"\n\n"` (G-02-3b).
 *
 * **`.trim()` alone is not enough either, and that is the second thing this
 * exists for.** JavaScript's whitespace set — `String.trim` and `\s` alike —
 * excludes U+200B, U+200C, U+200D and U+00AD, which are exactly the code points
 * `INVISIBLE_FORMATTING` above classifies as rendering to NOTHING. Without this
 * step the module holds two contradictory definitions of invisible: `htmlToText`
 * deletes those characters while this predicate counts them as content. The
 * consequence is the same G-02-3b failure in a different spelling — a plain
 * alternative padded with zero-width characters passes the gate, so the
 * populated HTML sibling beside it is never reached and the recovery pass on
 * the listing path never fires (WR-02).
 *
 * **U+200D is stripped HERE and must stay out of `INVISIBLE_FORMATTING`.** The
 * two are different questions and conflating them costs a real property: a
 * joiner BETWEEN emoji fuses several code points into one glyph and removing it
 * splits a family into separate people, so the renderer must keep it — but a
 * body consisting of nothing but joiners has nothing to join, so the predicate
 * must not call it content. Tests pin both directions.
 *
 * Nothing here edits what a sender wrote. This is a predicate; it answers a
 * question about a string and returns a boolean. The "a sender's literal bytes
 * are not ours to edit" decision from 02-15 is untouched.
 *
 * Exported for the listing path, which asks the same question of a finished
 * preview — the two places that decide "did this part contribute anything"
 * share one predicate rather than each spelling a length test its own way.
 */
export function hasReadableText(text: string): boolean {
  return (
    text.replace(INVISIBLE_FORMATTING, "").replace(ZERO_WIDTH_JOINER, "").trim()
      .length > 0
  );
}

/**
 * Turn raw RFC822 bytes into a decoded message.
 *
 * The raw bytes go straight to the library's parse entry point, which handles
 * RFC 2047 encoded words, quoted-printable, base64, flowed format, parameter
 * value continuations and charsets — all of them things § Don't Hand-Roll
 * specifically warns against reimplementing.
 *
 * The plain text part is preferred. When a message carries only HTML, the text
 * is extracted with `htmlToText` above rather than left empty: the tracer's
 * whole claim is that Claude gets the message's body back, and an HTML-only
 * message is ordinary correspondence rather than an exotic case.
 *
 * **The PLAIN arm is gated on readable content rather than on part presence.**
 * The preference order is untouched — `text/plain` still wins whenever it
 * carries readable text (D-33) — but a plain part that contributed nothing is
 * treated as ABSENT rather than as an empty body, so the alternative beside it
 * is reached. `bodySource`'s declared meaning is "which part `text` came from",
 * and naming a part that contributed nothing is a false statement in the one
 * field built to make the choice visible. When neither part passes,
 * `bodySource` stays `null` and the body stays empty: a whitespace-only body IS
 * no body.
 *
 * **The HTML arm is NOT content-gated, and the difference is deliberate.** It
 * tests the raw markup string, so any markup at all passes — an image-only HTML
 * half whose conversion yields nothing still sets `bodySource` to `"text/html"`
 * and returns an empty `text`. Gating it on the CONVERSION's output instead
 * would be a second, unplanned behaviour change, and 02-14 scoped it out rather
 * than slipping it in (WR-03). So the honest reading of `bodySource` is "which
 * part was chosen", and on the HTML side "chosen" means "was present as
 * markup". Making the two arms agree is a decision, not a refactor: it changes
 * which messages report a body source at all, and the caller that ranks a page
 * of rows would feel it.
 *
 * **The plain arm is ALSO refused when it is dwarfed by a readable HTML half
 * (G-02-9b).** The content gate above catches a plain half that says nothing;
 * it cannot catch one that says the wrong thing. uid 184746 returns
 * `bodySource: "text/plain"` and a 10-byte body of `undefined` for a
 * 123 978-byte message, and two Sleeptracker messages return 45 bytes reading
 * "Your email client does not support HTML email" — real words, so the gate
 * passes them, and the user cannot read the message at all. The margin is not a
 * claim about what the plain half SAYS; it is evidence the sender never
 * authored one. The predicate is shared with `selectIn` so the structure path
 * and this one cannot drift into two definitions of "drastically smaller".
 *
 * **One imprecision this site carries that the structure site does not, and it
 * is recorded rather than hidden.** The parser hands back a `text` and an `html`
 * half without stating they were the two children of one `ALTERNATIVE` — it
 * resolves them across the whole message. So this site applies the rule to
 * whatever the parser resolved as the two body halves, which is the closest
 * available proxy for the relationship `selectIn` reads directly off
 * `BODYSTRUCTURE`.
 *
 * **Quoted reply history is kept verbatim.** No heuristic stripping happens
 * here and none should be added (D-36). "Improving" this is a decision, not a
 * refactor: the quoted history is frequently the part a user actually wants
 * summarised, every stripping heuristic is wrong on some real thread, and the
 * ceiling above already bounds the cost of keeping it.
 */
export async function extractMessage(raw: Uint8Array): Promise<ParsedMessage> {
  const email = await PostalMime.parse(raw);

  const plain = email.text ?? "";
  const html = email.html ?? null;

  const plainReadable = hasReadableText(plain);
  const htmlReadable = html !== null && hasReadableText(html);

  // Measured in BYTES via the module's encoder, never in JavaScript string
  // units. A comparison in string units agrees with a byte-measured one for
  // ASCII and disagrees for everything else, which `truncateToBytes` names as
  // the exact class of bug this module measures in bytes to avoid. A ratio is
  // no exception.
  const plainBytes = ENCODER.encode(plain).byteLength;
  const htmlBytes = html === null ? 0 : ENCODER.encode(html).byteLength;

  let bodySource: ParsedMessage["bodySource"] = null;
  let assembled = "";
  // The ORDER of these two conditions is the load-bearing part. When the plain
  // half is dwarfed but the HTML half is NOT readable, the plain half must
  // still win: a rule that can leave the reader with nothing where they
  // previously had something is a worse failure than the one being fixed.
  if (plainReadable && !(htmlReadable && htmlOutweighsPlain(plainBytes, htmlBytes))) {
    bodySource = "text/plain";
    assembled = plain;
  } else if (html !== null && htmlReadable) {
    bodySource = "text/html";
    // The full-fetch path is where a link target is worth its characters: the
    // model has asked for this one message, and "where does this actually go"
    // is a question asked of a message rather than of a listing row.
    assembled = await htmlToText(html, "emit-links");
  }

  // The ceiling is applied at exactly ONE place, to the finished string. It
  // truncates and sets a flag; it never raises, and no fifth error category
  // appears (D-35, T-02-08).
  const bounded = truncateToBytes(assembled, MAX_EXTRACTED_TEXT_BYTES);

  return {
    subject: email.subject ?? null,
    fromName: email.from?.name ?? null,
    fromAddress: email.from?.address ?? null,
    date: email.date ?? null,
    messageId: email.messageId ?? null,
    to: recipientsFrom(email.to),
    cc: recipientsFrom(email.cc),
    // The full chain is counted before the preview is cut, so the count is the
    // header's own length rather than the length of what survived the cap.
    references: referencesFrom(email.references).slice(
      -REFERENCES_PREVIEW_LIMIT,
    ),
    referencesCount: referencesFrom(email.references).length,
    text: bounded.text,
    html,
    bodySource,
    truncated: bounded.truncated,
    attachments: email.attachments.map((attachment) => ({
      filename: attachment.filename ?? null,
      mimeType: attachment.mimeType,
      sizeBytes: decodedSize(attachment.content),
      disposition: attachment.disposition ?? null,
      // The library has no notion of a part path and cannot acquire one, so
      // neither field is derivable on this branch. The structure-derived list
      // is the one that reaches a response (`fetchOne` replaces this one with
      // it on every branch); this list exists to be COMPARED against that one,
      // and `attachmentsAgree` compares filename, type and size alone.
      path: null,
      id: null,
    })),
  };
}
