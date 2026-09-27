// Pure IMAP line parsing. No I/O, no sockets, no imports from this
// directory's transport modules.
//
// Split out precisely so it can be unit-tested against captured byte
// sequences with nothing attached to it. Plan 01-03 writes those tests, and
// Phase 2 extends this module with byte-counted literal handling rather than
// rewriting it.

/**
 * One logical IMAP response, with its literal payloads lifted out.
 *
 * IMAP's grammar is a hybrid: line framing punctuated by byte-counted,
 * binary-safe literals. `literal = "{" number "}" CRLF *CHAR8`. A single
 * logical response can therefore span many physical lines, and the byte
 * immediately after the last literal octet continues the SAME logical line —
 * there is no CRLF between them.
 *
 * `text` is the protocol text with each literal replaced by a placeholder, so
 * the structure stays parseable as a string. `literals` holds the payloads in
 * the order they appeared, as RAW BYTES that are never decoded at this layer:
 * a literal may carry base64, binary, or any charset, and a `TextDecoder` pass
 * here would replace invalid bytes with U+FFFD and make an attachment
 * irrecoverable.
 */
export interface ResponseLine {
  /** Protocol text, with each literal replaced by its placeholder. */
  text: string;
  /** Literal payloads in order, raw and undecoded. */
  literals: Uint8Array[];
}

/**
 * A literal count at the very end of a line, and nowhere it can be confused.
 *
 * End-anchoring is unambiguous rather than merely convenient, and the grammar
 * is what guarantees it: `{` cannot appear in an IMAP `atom`, and a quoted
 * string cannot contain CR or LF — so a quoted string that happened to end
 * `…{5}"` would have its closing `"` AFTER the `}` and would not match a
 * pattern anchored at end of line. Anchoring after CRLF stripping is therefore
 * sufficient.
 *
 * `\+?` accepts the non-synchronizing form on the RECEIVE side. That asymmetry
 * is deliberate: a server may send `{n+}` whenever it likes, while this client
 * may only send that form if the server advertised the capability. Accepting
 * both inbound costs one character and prevents a desync on a server that
 * volunteers it.
 *
 * Not a global regex, deliberately. `lastIndex` on a shared global regex is
 * state, and shared state is how a matcher starts skipping lines depending on
 * what it happened to be handed first.
 */
export const LITERAL_SUFFIX = /\{(\d+)\+?\}$/;

/** NUL, spelled once. */
const NUL = "\u0000";

/**
 * The placeholder standing in for literal `index` inside a `ResponseLine.text`.
 *
 * Built from NUL bytes, and that is what makes it unforgeable rather than
 * merely unlikely. Literal payloads never enter `text` at all; the only
 * message-derived bytes that reach `text` are inside quoted strings, and RFC
 * 3501's `QUOTED-CHAR` production excludes CR, LF and NUL outright —
 * `src/mail/credentials.ts` already relies on exactly that fact in the outbound
 * direction, where its `ILLEGAL_IN_QUOTED_STRING` refuses the same three.
 *
 * `stripNul` closes the last gap by construction rather than by argument: after
 * it runs, no content-derived byte in `text` can be NUL, so no content can
 * spell a placeholder even if a server violated the grammar.
 */
export function literalPlaceholder(index: number): string {
  return `${NUL}L${index}${NUL}`;
}

/**
 * Remove every NUL from a decoded protocol line.
 *
 * Runs on every line before it is appended to a `ResponseLine.text`. See
 * `literalPlaceholder` for why this is the step that makes the placeholder
 * unforgeable instead of merely improbable.
 */
export function stripNul(line: string): string {
  return line.includes(NUL) ? line.split(NUL).join("") : line;
}

/**
 * One node of a parsed IMAP response.
 *
 * - `string` — an atom, or the contents of a quoted string
 * - `null` — the unquoted `NIL` atom, which is a DISTINCT value from the
 *   quoted string of the same spelling (`nstring = string / nil`)
 * - `SExpr[]` — a parenthesised list, nesting arbitrarily
 * - `Uint8Array` — a literal payload, still undecoded
 */
export type SExpr = string | null | SExpr[] | Uint8Array;

/** Characters that end an atom. */
const ATOM_DELIMITERS = new Set([" ", "\t", "(", ")", '"', NUL]);

/**
 * Tokenize one logical response, resolving placeholders back to their bytes.
 *
 * Straight from the ABNF, and every rule below exists because omitting it
 * produces a tree that looks plausible and is wrong:
 *
 * - `"(" … ")"` nests arbitrarily. `body-type-mpart = 1*body SP media-subtype`
 *   and `body = "(" (body-type-1part / body-type-mpart) ")"`, so a multipart
 *   structure has no bounded depth.
 * - `nil = "NIL"` is a value, not the two-character string. Only the UNQUOTED
 *   atom becomes `null` here; a quoted `"NIL"` stays a string, because a
 *   subject or filename may legitimately be that text.
 * - `string = quoted / literal`, and a quoted string escapes `\"` and `\\`.
 * - A bracketed section specifier carries its own parenthesised list —
 *   `BODY[HEADER.FIELDS (SUBJECT FROM)]` — so brackets are matched BEFORE
 *   general tokenizing. Without that, the section's inner `(` unbalances the
 *   whole tree and every field after it lands at the wrong depth.
 *
 * Pure: it reads the `ResponseLine` it is handed and touches nothing else.
 */
export function parseSExpr(line: ResponseLine): SExpr[] {
  const text = line.text;
  let index = 0;

  const readQuoted = (): string => {
    index += 1; // the opening quote
    let value = "";
    while (index < text.length) {
      const char = text[index];
      if (char === "\\" && index + 1 < text.length) {
        value += text[index + 1];
        index += 2;
        continue;
      }
      if (char === '"') {
        index += 1;
        return value;
      }
      value += char;
      index += 1;
    }
    // Unterminated. Return what there was rather than throwing: the caller
    // decides whether a malformed response is fatal, and a parser that throws
    // on malformed input gives the caller a caught value to inspect, which is
    // the one thing the error discipline forbids.
    return value;
  };

  const readPlaceholder = (): Uint8Array | undefined => {
    const closing = text.indexOf(NUL, index + 1);
    if (closing === -1) return undefined;
    const body = text.slice(index + 1, closing);
    if (!/^L\d+$/.test(body)) return undefined;
    index = closing + 1;
    return line.literals[Number(body.slice(1))] ?? new Uint8Array(0);
  };

  const readAtom = (): string => {
    const start = index;
    while (index < text.length) {
      const char = text[index];
      if (char === "[") {
        let depth = 0;
        while (index < text.length) {
          if (text[index] === "[") depth += 1;
          else if (text[index] === "]") {
            depth -= 1;
            if (depth === 0) {
              index += 1;
              break;
            }
          }
          index += 1;
        }
        continue;
      }
      if (ATOM_DELIMITERS.has(char)) break;
      index += 1;
    }
    return text.slice(start, index);
  };

  const readSequence = (depth: number): SExpr[] => {
    const items: SExpr[] = [];
    for (;;) {
      while (index < text.length && (text[index] === " " || text[index] === "\t")) {
        index += 1;
      }
      if (index >= text.length) return items;

      const char = text[index];
      if (char === ")") {
        index += 1;
        // A close at depth 0 is unbalanced input. Skipping it beats throwing,
        // for the same reason the unterminated quoted string above does.
        if (depth > 0) return items;
        continue;
      }
      if (char === "(") {
        index += 1;
        items.push(readSequence(depth + 1));
        continue;
      }
      if (char === '"') {
        items.push(readQuoted());
        continue;
      }
      if (char === NUL) {
        const literal = readPlaceholder();
        if (literal !== undefined) {
          items.push(literal);
          continue;
        }
        // Not a well-formed placeholder. `stripNul` makes this unreachable for
        // content-derived bytes; step over it rather than looping forever.
        index += 1;
        continue;
      }

      const atom = readAtom();
      if (atom.length === 0) {
        index += 1;
        continue;
      }
      items.push(atom === "NIL" ? null : atom);
    }
  };

  return readSequence(0);
}

/**
 * The UIDVALIDITY carried by an untagged OK response code, or `null`.
 *
 * It arrives as a response code on an untagged `OK` — `* OK [UIDVALIDITY
 * 3857529045] UIDs valid` — and never as a field of the tagged completion.
 * Response codes are case-insensitive atoms, so the match is too.
 *
 * `null` means the code was ABSENT, and the RFC is explicit about what that
 * means: "If this is missing, the server does not support unique identifiers."
 * That is a fail-closed condition, not a reason to default to zero. Every UID a
 * session would hand out or accept under such a server is meaningless, so the
 * caller refuses rather than proceeding.
 *
 * The value is unsigned 32-bit, so it may legitimately exceed 2^31 — RFC 3501's
 * own worked example is 3857529045, and a signed-int assumption anywhere on
 * this path corrupts it into a negative silently.
 */
export function parseUidValidity(line: string): number | null {
  if (!/^\* +OK\b/i.test(line)) return null;
  const match = /\[UIDVALIDITY +(\d+)\]/i.exec(line);
  return match === null ? null : Number(match[1]);
}

/**
 * The flag list carried by an untagged `PERMANENTFLAGS` response code, or
 * `null`.
 *
 * It arrives on an untagged `OK` when a mailbox opens:
 * `* OK [PERMANENTFLAGS (\Answered \Seen \*)] Limited`. RFC 3501 §7.1 says a
 * flag missing from this list can be changed, but only for this session. The
 * change is gone when the session ends. So a mailbox can open read-write and
 * still not keep a read-state change.
 *
 * `null` means the code was ABSENT. RFC 3501 §6.3.1 says what that means: the
 * client should assume all flags can be changed permanently. That is the
 * opposite of `parseUidValidity`'s absent case, and it is the RFC's rule, not a
 * default picked here.
 *
 * The flags come back verbatim, in order, split on spaces. Flags are atoms,
 * which cannot hold a space or a parenthesis. Comparing them is the caller's
 * job, and it must ignore case. `\*` is returned like any other entry. It says
 * new keywords can be created. It does not say `\Seen` is kept, so a caller
 * must not read it as covering `\Seen`.
 */
export function parsePermanentFlags(line: string): string[] | null {
  if (!/^\* +OK\b/i.test(line)) return null;
  const match = /\[PERMANENTFLAGS +\(([^()]*)\)\]/i.exec(line);
  if (match === null) return null;
  return match[1].split(" ").filter((flag) => flag !== "");
}

/**
 * The message count carried by an untagged `EXISTS` response, or `null`.
 *
 * Not a response code but a counted untagged response — `* 172 EXISTS` — which
 * is why it needs its own tiny parser rather than sharing the bracket-matching
 * one above. It lives here for the same reason everything else in this file
 * does: nothing that reads bytes off a socket should also be deciding what a
 * line means.
 */
export function parseExists(line: string): number | null {
  const match = /^\* +(\d+) +EXISTS\b/i.exec(line);
  return match === null ? null : Number(match[1]);
}

/**
 * The access code on a mailbox open's tagged completion, or `null`.
 *
 * RFC 3501 §6.3.1 puts it there: `a4 OK [READ-WRITE] ... completed`. Only a
 * bracketed code IMMEDIATELY after an OK counts. A NO, a code further along in
 * the human text, and an untagged line are all `null`. Response codes are
 * case-insensitive atoms, so the match is too.
 *
 * Three answers, not two, and that is the point (PITFALLS #33). `null` means the
 * server did not say. A caller that read `null` as "writable" would go on to
 * change a mailbox the server never agreed to open for changing, so every
 * caller must treat `null` exactly as it treats `"read-only"`.
 */
export function parseAccessCode(
  taggedLine: string,
): "read-write" | "read-only" | null {
  const parsed = parseTaggedResponse(taggedLine);
  if (parsed === null || parsed.status !== "OK") return null;
  const match = /^\[(READ-WRITE|READ-ONLY)\]/i.exec(parsed.text);
  if (match === null) return null;
  return match[1].toUpperCase() === "READ-WRITE" ? "read-write" : "read-only";
}

/**
 * The response code on a tagged completion of any status, upper-cased, or
 * `null`.
 *
 * `a5 NO [NONEXISTENT] No such message` gives `NONEXISTENT`. Only a bracketed
 * code IMMEDIATELY after the status counts, as in `parseAccessCode`; the same
 * letters further along are prose the server chose to write. Only the code's
 * first atom is returned, never its arguments and never the human text, so no
 * server-chosen sentence travels any further than this function.
 *
 * `null` means the server gave no code, which is the common case.
 */
export function parseCompletionCode(taggedLine: string): string | null {
  const parsed = parseTaggedResponse(taggedLine);
  if (parsed === null) return null;
  const match = /^\[([A-Za-z0-9-]+)[\] ]/.exec(parsed.text);
  return match === null ? null : match[1].toUpperCase();
}

/**
 * Whether the FETCH reply for one UID says the message is seen, or `null`.
 *
 * Reads the untagged FETCH replies a command produced. It finds the reply whose
 * OWN UID item equals `uid`, and never goes by position or by the
 * sequence-number prefix. Those can name another message, and the answer would
 * then be about the wrong one while looking right. `fetchReplies` in
 * `./service.ts` records the same rule for the read path.
 *
 * When more than one reply names this UID, the LAST one wins. One command can
 * carry several: an unsolicited flag update (another device changed the
 * message) can arrive before the command's own reply. The server's final word
 * is the last one it sent, so an earlier one is stale.
 *
 * The seen flag is compared without regard to case. `null` means no reply for
 * this UID carried a flag list, which is how a message that no longer exists
 * shows up: the server answers OK and sends nothing about it.
 *
 * Pure: it reads the lines it is handed and touches nothing else.
 */
export function seenStateOf(
  untagged: readonly ResponseLine[],
  uid: number,
): boolean | null {
  let seen: boolean | null = null;
  for (const line of untagged) {
    const parsed = parseSExpr(line);
    if (parsed[0] !== "*") continue;
    if (typeof parsed[2] !== "string" || parsed[2].toUpperCase() !== "FETCH") {
      continue;
    }
    const list = parsed[3];
    if (!Array.isArray(list)) continue;

    let replyUid: string | null = null;
    let flags: SExpr | undefined;
    for (let index = 0; index + 1 < list.length; index += 2) {
      const key = list[index];
      if (typeof key !== "string") continue;
      const upper = key.toUpperCase();
      const value = list[index + 1];
      if (upper === "UID" && typeof value === "string") replyUid = value;
      if (upper === "FLAGS") flags = value;
    }

    if (replyUid === null || !/^[1-9]\d*$/.test(replyUid)) continue;
    if (Number(replyUid) !== uid) continue;
    if (!Array.isArray(flags)) continue;

    // Keep going: a later reply for the same UID replaces this one.
    seen = flags.some(
      (flag) => typeof flag === "string" && flag.toLowerCase() === "\\seen",
    );
  }
  return seen;
}

/**
 * Decoder for mailbox names that arrived as literals.
 *
 * Only ever applied to a mailbox NAME, never to a message payload. A mailbox
 * name is modified UTF-7 (RFC 3501 §5.1.3), which is seven-bit ASCII by
 * construction, so decoding it as UTF-8 is lossless — every byte it can
 * legitimately contain is its own code point. Message payloads take the
 * opposite path deliberately: `ResponseLine.literals` keeps them as raw bytes
 * precisely so a decode pass here cannot replace them with U+FFFD.
 */
const DECODER = new TextDecoder();

/** One `* LIST` (or `* LSUB`) reply, decomposed. */
export interface MailboxListLine {
  /**
   * The attribute list, VERBATIM — original order, original casing.
   *
   * See `parseListLine` for why nothing is normalised here.
   */
  attributes: string[];
  /** The hierarchy delimiter read from the wire, or `null` for a flat namespace. */
  delimiter: string | null;
  /** The mailbox name as it arrived, still modified-UTF-7 encoded. */
  name: string;
}

/** The counts a `* STATUS` reply carried for one mailbox. */
export interface MailboxStatus {
  /** The mailbox the counts belong to, as the server spelled it. */
  name: string;
  /**
   * Only the counts that actually arrived, keyed by uppercased attribute name.
   *
   * An absent count is ABSENT from this map. See `parseStatusLine`.
   */
  counts: Record<string, number>;
}

/** One folder, with the counts that named it — or `null` if none arrived. */
export interface FolderStatus {
  /** The mailbox-list line, as it arrived. */
  line: MailboxListLine;
  /** The correlated counts, or `null` when the server sent no status reply. */
  counts: Record<string, number> | null;
}

/**
 * A mailbox name node, whether it arrived as an atom, a quoted string, or a
 * literal.
 *
 * All three forms are legal for `mailbox` (`astring = 1*ASTRING-CHAR / string`,
 * `string = quoted / literal`) and a server picks freely between them. Reading
 * only the quoted form is the bug that makes a folder whose name needs a
 * literal simply vanish from a listing.
 *
 * `null` for the unquoted `NIL` atom, which is a value rather than a name.
 */
function mailboxName(node: SExpr): string | null {
  if (typeof node === "string") return node;
  if (node instanceof Uint8Array) return DECODER.decode(node);
  return null;
}

/**
 * Parse an untagged mailbox-list reply.
 *
 * `mailbox-list = "(" [mbx-list-flags] ")" SP (DQUOTE QUOTED-CHAR DQUOTE / nil)
 * SP mailbox` (RFC 3501 §9). Parsed through the S-expression tokenizer rather
 * than a bespoke regex, because a mailbox name may arrive quoted, as a bare
 * atom, or as a literal, and the tokenizer already resolves all three — a regex
 * would have to reimplement the quoting rules and would still be blind to the
 * literal, which does not appear in the protocol text at all.
 *
 * **The attributes are returned VERBATIM — no lowercasing, no sorting, no
 * normalisation.** That string is evidence, and the argument is the one
 * `parseCapabilityLine` already makes: a tidied copy is a summary of the
 * evidence rather than the evidence. It matters more here than there, because
 * the question it settles is open. This account's measured post-authentication
 * capability list advertises neither `SPECIAL-USE` nor `XLIST`, but RFC 6154 §2
 * says a server "MAY include any or all of the following attributes in responses
 * to the non-extended IMAP LIST command" and that "there is no capability string
 * related to" that — so their absence from the capability list proves nothing,
 * and the first real run is what answers it.
 *
 * **The delimiter is read from the second field and may legitimately be `NIL`.**
 * A flat namespace is legal, and indexing into a nil delimiter — `line[2][0]` —
 * is the specific crash this guards. Nothing here assumes `/`.
 *
 * `LSUB` is accepted alongside `LIST` because the grammar is literally the same
 * production; the two differ in which mailboxes they enumerate, not in shape.
 *
 * Returns `null` for anything that is not a mailbox-list reply, so a caller
 * mapping over every untagged line can simply keep reading.
 */
export function parseListLine(line: ResponseLine): MailboxListLine | null {
  const parsed = parseSExpr(line);
  if (parsed[0] !== "*") return null;

  const command = parsed[1];
  if (typeof command !== "string") return null;
  const upper = command.toUpperCase();
  if (upper !== "LIST" && upper !== "LSUB") return null;

  const attributeList = parsed[2];
  if (!Array.isArray(attributeList)) return null;
  const attributes: string[] = [];
  for (const attribute of attributeList) {
    if (typeof attribute === "string") attributes.push(attribute);
  }

  // A quoted single character, or `null` from the NIL atom. Anything else — a
  // literal in the delimiter position — is not a delimiter this can use.
  const node = parsed[3];
  const delimiter = typeof node === "string" ? node : null;

  const name = mailboxName(parsed[4]);
  if (name === null) return null;

  return { attributes, delimiter, name };
}

/**
 * Parse an untagged status reply.
 *
 * `"STATUS" SP mailbox SP "(" [status-att-list] ")"`, where `status-att-list =
 * status-att SP number *(SP status-att SP number)` (RFC 3501 §9).
 *
 * **Attribute names are matched case-insensitively and the map is keyed in upper
 * case.** Response atoms are case-insensitive in IMAP, so the case a server
 * happens to choose is not information — unlike the LIST attributes above, where
 * it is exactly the evidence in question. Uppercasing a lookup key is not the
 * same act as tidying a measurement.
 *
 * **Any attribute name is recorded, not only RFC 3501's five.** `CONDSTORE`
 * adds `HIGHESTMODSEQ` and this account's server advertises `CONDSTORE`, so a
 * fixed allow-list would silently drop a count the server volunteered. The
 * caller reads the keys it knows.
 *
 * **An absent count is ABSENT from the map, never defaulted to zero.** A folder
 * with no reported unseen count is a different fact from a folder with zero
 * unread, and only one of the two is true.
 *
 * Returns `null` for anything that is not a status reply.
 */
export function parseStatusLine(line: ResponseLine): MailboxStatus | null {
  const parsed = parseSExpr(line);
  if (parsed[0] !== "*") return null;

  const command = parsed[1];
  if (typeof command !== "string" || command.toUpperCase() !== "STATUS") {
    return null;
  }

  const name = mailboxName(parsed[2]);
  if (name === null) return null;

  const attributeList = parsed[3];
  if (!Array.isArray(attributeList)) return null;

  const counts: Record<string, number> = {};
  for (let index = 0; index + 1 < attributeList.length; index += 2) {
    const key = attributeList[index];
    const value = attributeList[index + 1];
    if (typeof key !== "string" || typeof value !== "string") continue;
    // `number` in the grammar. A non-numeric value is a malformed pair, and
    // coercing it would put `NaN` in a count the caller renders.
    if (!/^\d+$/.test(value)) continue;
    counts[key.toUpperCase()] = Number(value);
  }

  return { name, counts };
}

/**
 * Pair each mailbox-list line with the status reply that named it.
 *
 * **Correlated by mailbox NAME, never by position, and that is a correctness
 * requirement rather than a preference.** RFC 5819 §2 permits a server to omit
 * the status reply for a mailbox that cannot be selected — "the STATUS response
 * MUST NOT be returned and the LIST response MUST include the \NoSelect
 * attribute" — and separately permits dropping one "if the server runs into
 * unexpected problems", while still completing the command with a tagged `OK`.
 * Either omission shifts every later reply by one under positional pairing, so
 * the counts land on the wrong folder in exactly the case where a folder is
 * unusual, with nothing anywhere to indicate it happened.
 *
 * Matching is exact rather than case-insensitive. Two mailboxes differing only
 * in case are two different mailboxes in IMAP (`INBOX` alone is reserved), so a
 * case-insensitive match could merge a pair of real folders' counts. Both sides
 * of the comparison come off the same wire in the same command, so an exact
 * match is what the server itself means.
 *
 * A folder with no matching status yields `null` counts — that is an ordinary
 * folder listing, not an error. The same shape covers the plain-`LIST` fallback,
 * where no status reply arrives for any folder at all.
 */
export function correlateStatus(
  lists: MailboxListLine[],
  statuses: MailboxStatus[],
): FolderStatus[] {
  const byName = new Map<string, Record<string, number>>();
  for (const status of statuses) {
    // First wins. A repeated name is a server anomaly; taking the first keeps
    // the result a function of the reply order the server chose rather than of
    // whichever line happened to be read last.
    if (!byName.has(status.name)) byName.set(status.name, status.counts);
  }

  return lists.map((line) => ({
    line,
    counts: byName.get(line.name) ?? null,
  }));
}

/** What one `* STATUS` reply said about a folder, for the change check. */
export interface StatusSnapshot {
  /** The mailbox the reply named, exactly as the server spelled it. */
  name: string;
  uidValidity: number | null;
  uidNext: number | null;
  messages: number | null;
  /** The digits exactly as sent, or `null` when the server sent none. */
  highestModseq: string | null;
}

/** The largest mod-sequence RFC 7162 allows: a 63-bit value. */
const MAX_MODSEQ = 9223372036854775807n;

/** A 32-bit unsigned value from a digit string, or `null`. */
function uint32Of(value: string): number | null {
  if (!/^\d{1,10}$/.test(value)) return null;
  const number = Number(value);
  return number <= 0xffffffff ? number : null;
}

/**
 * Parse an untagged status reply into the four facts the change check reads.
 *
 * The same S-expression walk and the same mailbox-name handling as
 * `parseStatusLine`, so a name that arrives quoted, bare or as a literal is
 * read the same way on both paths.
 *
 * **The mod-sequence is kept as the digits the server sent, never as a
 * number.** It is a 63-bit value (RFC 7162), and a JS number holds 53 bits
 * exactly. Above that, two different mod-sequences can turn into the same
 * number, and "nothing else changed" would then be said about a folder where
 * something did. `parseStatusLine` converts every value with `Number`, which is
 * why this is its own reader. The digits are checked against the 63-bit limit
 * with `BigInt`.
 *
 * **Absent is `null`, never zero.** A folder whose reply left out a value is a
 * different fact from a folder whose value is zero.
 *
 * Returns `null` for anything that is not a status reply.
 */
export function parseStatusSnapshot(line: ResponseLine): StatusSnapshot | null {
  const parsed = parseSExpr(line);
  if (parsed[0] !== "*") return null;

  const command = parsed[1];
  if (typeof command !== "string" || command.toUpperCase() !== "STATUS") {
    return null;
  }

  const name = mailboxName(parsed[2]);
  if (name === null) return null;

  const attributeList = parsed[3];
  if (!Array.isArray(attributeList)) return null;

  const snapshot: StatusSnapshot = {
    name,
    uidValidity: null,
    uidNext: null,
    messages: null,
    highestModseq: null,
  };
  for (let index = 0; index + 1 < attributeList.length; index += 2) {
    const key = attributeList[index];
    const value = attributeList[index + 1];
    if (typeof key !== "string" || typeof value !== "string") continue;
    switch (key.toUpperCase()) {
      case "UIDVALIDITY":
        snapshot.uidValidity = uint32Of(value);
        break;
      case "UIDNEXT":
        snapshot.uidNext = uint32Of(value);
        break;
      case "MESSAGES":
        snapshot.messages = uint32Of(value);
        break;
      case "HIGHESTMODSEQ":
        snapshot.highestModseq =
          /^(?:0|[1-9]\d{0,18})$/.test(value) && BigInt(value) <= MAX_MODSEQ
            ? value
            : null;
        break;
    }
  }

  return snapshot;
}

/**
 * The modified base64 alphabet, with a comma in the sixty-third position.
 *
 * RFC 3501 §5.1.3: characters outside printable US-ASCII "are represented in
 * modified BASE64, with a further modification from [UTF-7] that ',' is used
 * instead of '/'." So `/` is NOT in this alphabet, and a run containing one is
 * malformed rather than a slash.
 */
const MODIFIED_BASE64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/**
 * Decode one shifted run into the characters it spells, or `null` if malformed.
 *
 * The decoded bit stream is big-endian UTF-16 CODE UNITS, not code points. Two
 * octets make one unit, and a surrogate pair makes one character — which JS
 * gets for free, because a JS string already is a UTF-16 sequence. Treating
 * each unit as a code point is the mistake that produces a name looking almost
 * right.
 *
 * A leftover of six or more bits means a whole base64 character's worth of data
 * produced no output — the run was truncated mid-character, and what came back
 * is a partial name. Fewer than six leftover bits are the encoder's padding and
 * are ignored even when they are not zero: those bits sit past the last complete
 * code unit, so they name no character, and refusing on them would hide a
 * perfectly readable folder name over a bit nobody can see.
 */
function decodeShiftedRun(run: string): string | null {
  let bits = 0;
  let held = 0;
  let decoded = "";

  for (const char of run) {
    const value = MODIFIED_BASE64.indexOf(char);
    if (value === -1) return null;

    bits = (bits << 6) | value;
    held += 6;
    if (held >= 16) {
      held -= 16;
      decoded += String.fromCharCode((bits >>> held) & 0xffff);
      // Drop the consumed bits. Without this the accumulator grows past 32 bits
      // and JavaScript's shift operators silently wrap it.
      bits &= (1 << held) - 1;
    }
  }

  return held >= 6 ? null : decoded;
}

/**
 * Decode a modified-UTF-7 mailbox name for DISPLAY.
 *
 * RFC 3501 §5.1.3, implemented directly:
 *
 * - printable US-ASCII except `&` represents itself;
 * - `&-` is a literal `&`;
 * - `&` shifts into modified base64 and `-` shifts back.
 *
 * **This project needs a decoder ONLY and must never grow an encoder.** The
 * opaque message id and the pagination cursor both carry the RAW WIRE name
 * (D-18, D-21), and that name is what goes back to the server, so the round
 * trip is byte-exact by construction — there is no re-encoding step that could
 * diverge from the server's own spelling of its own folder. An encoder
 * appearing here later would be a regression rather than an addition: it would
 * create a second spelling of a name the server has already spelled, and the two
 * would only have to disagree once to select the wrong mailbox.
 *
 * **A malformed shifted run returns the input UNCHANGED**, not a partial
 * decode. A folder name is an identifier as well as a label; a half-decoded name
 * is worse than an undecoded one, because an undecoded one is visibly encoded
 * and a half-decoded one merely looks wrong. Nothing downstream depends on this
 * succeeding — the decoded value is display-only.
 *
 * Easy to skip and expensive to skip: `Sent Messages` and `Deleted Messages` are
 * pure ASCII, so an English account never sees this run, and then a French
 * account's `Reçus` arrives as `Re&AOc-us`, is shown to the model verbatim, and
 * `resolveFolderRole`'s name ladder never matches it.
 */
export function decodeModifiedUtf7(wireName: string): string {
  // The overwhelmingly common case: an ASCII folder name with no shift at all.
  if (!wireName.includes("&")) return wireName;

  let decoded = "";
  let index = 0;

  while (index < wireName.length) {
    const char = wireName[index]!;
    if (char !== "&") {
      decoded += char;
      index += 1;
      continue;
    }

    if (wireName[index + 1] === "-") {
      decoded += "&";
      index += 2;
      continue;
    }

    const end = wireName.indexOf("-", index + 1);
    // Unterminated: the shift never shifts back, so there is no run to decode
    // and no way to know where the name resumes.
    if (end === -1) return wireName;

    const run = decodeShiftedRun(wireName.slice(index + 1, end));
    if (run === null) return wireName;

    decoded += run;
    index = end + 1;
  }

  return decoded;
}

/**
 * The role a folder plays for this account, or `null` for an ordinary folder.
 *
 * Lowercase and closed, matching the error vocabulary's style. **`null` for an
 * ordinary user folder is meaningfully different from an empty string**: a
 * folder with no role is a fact, not a missing value, and a caller that has to
 * distinguish `""` from `"inbox"` will eventually forget which it is looking at.
 *
 * Six roles, from D-31. They all arrive in the same listing reply, so resolving
 * six costs nothing more than resolving one, and it turns a single empirical
 * question into six answers.
 */
export type FolderRole =
  | "inbox"
  | "drafts"
  | "sent"
  | "trash"
  | "junk"
  | "archive"
  | null;

/**
 * How a role was resolved, or `null` when none was.
 *
 * **The whole purpose of reporting this is that the first real tool call becomes
 * legible evidence rather than a code read.** Criterion 1 requires the drafts
 * folder be discovered rather than guessed; `"special-use"` says the server
 * named it, `"name-match"` says this client recognised the name, and the
 * difference is visible in the response instead of buried in a branch. It is the
 * same move `parseCapabilityLine` makes by returning the capability string
 * verbatim — the measurement is the deliverable.
 *
 * It doubles as the signal for T-02-24. Any user or mail client can create a
 * folder named to resemble a role folder, and a name-based resolution is exactly
 * the case worth noticing.
 */
export type RoleSource = "special-use" | "name-match" | null;

/**
 * RFC 6154 §2's special-use attributes, lowercased for comparison.
 *
 * `\All` and `\Flagged` are deliberately absent. Both are defined by RFC 6154,
 * and neither is one of the six roles D-31 identifies — they name virtual
 * mailboxes rather than a destination this project ever writes to or reads as a
 * role. Adding them would put values in `FolderRole` that no caller can act on.
 *
 * The inbox is absent for a different reason: it has no attribute at all. Its
 * name is reserved by the protocol itself, so it resolves through the ladder.
 */
const SPECIAL_USE_ATTRIBUTES = new Map<string, FolderRole>([
  ["\\drafts", "drafts"],
  ["\\sent", "sent"],
  ["\\trash", "trash"],
  ["\\junk", "junk"],
  ["\\archive", "archive"],
]);

/**
 * The Apple-specific name ladder, lowercased, checked in order.
 *
 * **Apple-specific rather than generic, and that is the whole point.** This
 * account's server calls them `Sent Messages` and `Deleted Messages`; a ladder
 * carrying only `Sent` and `Trash` resolves NEITHER of the two folders a draft
 * workflow actually needs, and does so silently. PITFALLS.md #8 is the entry.
 *
 * The long forms are listed before the generic ones. That ordering is currently
 * unobservable — no name appears twice, so no name can match two entries — and
 * it is kept anyway, because the ladder is a table a later plan edits and the
 * intended precedence should be readable from the table rather than inferred
 * from the absence of a collision.
 *
 * `inbox` is here rather than in the attribute map because RFC 3501 reserves the
 * name itself. Reaching it by name is not a fallback or a guess; the name IS the
 * specification.
 */
const NAME_LADDER: ReadonlyArray<readonly [string, FolderRole]> = [
  ["inbox", "inbox"],
  ["drafts", "drafts"],
  ["sent messages", "sent"],
  ["sent", "sent"],
  ["deleted messages", "trash"],
  ["trash", "trash"],
  ["junk", "junk"],
  ["spam", "junk"],
  ["archive", "archive"],
];

/**
 * Whether a folder sits at the top of the hierarchy.
 *
 * Uses the delimiter READ FROM THE WIRE rather than an assumed separator (D-32).
 * A `null` delimiter means the server reported a flat namespace, in which case
 * every folder is top-level by definition.
 */
function isTopLevel(name: string, delimiter: string | null): boolean {
  if (delimiter === null || delimiter.length === 0) return true;
  return !name.includes(delimiter);
}

/**
 * Resolve a folder's role, and report which path resolved it.
 *
 * **Attributes first, then the Apple-specific name ladder, then nothing** —
 * D-29's order, and it is the one a naive implementation gets backwards. A name
 * is a claim: any user, and any mail client that ever touched this account, can
 * create a folder called `Drafts`. An attribute is the server's own answer about
 * its own mailbox. So when both are present the attribute wins, and the reported
 * source says which ran (T-02-24).
 *
 * **Neither resolving leaves the role `null`, never a guess.** Criterion 1
 * requires the drafts folder be discovered rather than guessed, and a guess that
 * happens to be right is still a guess.
 *
 * Two details decide whether this is correct or merely plausible:
 *
 * - The ladder matches the WHOLE name, so `Archive/2024` is a year of filed mail
 *   rather than the archive folder. `isTopLevel` states that rule against the
 *   wire delimiter instead of leaving it as an emergent property of the table.
 * - The comparison runs on the DECODED name (see `decodeModifiedUtf7`) and is
 *   case-insensitive. A wire-encoded name never matches an ASCII ladder entry,
 *   which is how a non-ASCII folder becomes comparable at all.
 *
 * The ladder is restricted to top-level folders; an ATTRIBUTE is not. The
 * asymmetry is deliberate — the ladder is a heuristic about names, while an
 * attribute is the server's statement about that specific mailbox and holds
 * wherever the mailbox lives.
 */
export function resolveFolderRole(
  attributes: string[],
  decodedName: string,
  delimiter: string | null,
): { role: FolderRole; source: RoleSource } {
  for (const attribute of attributes) {
    const role = SPECIAL_USE_ATTRIBUTES.get(attribute.toLowerCase());
    if (role !== undefined) return { role, source: "special-use" };
  }

  if (isTopLevel(decodedName, delimiter)) {
    const lowered = decodedName.toLowerCase();
    for (const [candidate, role] of NAME_LADDER) {
      if (lowered === candidate) return { role, source: "name-match" };
    }
  }

  return { role: null, source: null };
}

/**
 * Parse an untagged search reply into its identifiers.
 *
 * `mailbox-data = … "SEARCH" *(SP nz-number) …` (RFC 3501 §9) — a flat list of
 * space-separated non-zero integers, and the zero-identifier form is legal.
 *
 * **An empty reply yields an empty array, never `null`.** A search that matched
 * nothing ran perfectly; returning `null` there would make "no results"
 * indistinguishable from a parse failure, and the tool would report an error for
 * a call that worked. `null` means the line was not a search reply at all.
 *
 * Tokens that are not identifiers are skipped rather than coerced. RFC 4551
 * appends `(MODSEQ n)` to this response and this account's server advertises
 * `CONDSTORE`, so a parser that ran `Number()` over every token would put `NaN`
 * into the identifier list on an ordinary reply.
 *
 * **The line can be very long — thousands of identifiers on a large mailbox —
 * and that is fine.** The reader has no length cap, the numbers never reach the
 * model, and each page re-runs the search (D-25) precisely so nothing has to be
 * cached. T-02-27 accepts the proportional allocation: the reply comes from the
 * account's own server over an authenticated session, and the per-read and
 * per-call bounds already cap how long the read can take.
 */
export function parseSearchLine(line: ResponseLine): number[] | null {
  const parsed = parseSExpr(line);
  if (parsed[0] !== "*") return null;

  const command = parsed[1];
  if (typeof command !== "string" || command.toUpperCase() !== "SEARCH") {
    return null;
  }

  const identifiers: number[] = [];
  for (let index = 2; index < parsed.length; index += 1) {
    const token = parsed[index];
    if (typeof token !== "string") continue;
    if (!/^[1-9]\d*$/.test(token)) continue;
    identifiers.push(Number(token));
  }

  return identifiers;
}

/**
 * Wrap a raw wire mailbox name as an IMAP quoted string, or refuse it.
 *
 * Returns `null` for a name containing CR, LF or NUL. That is the same
 * refuse-don't-repair rule `src/mail/credentials.ts` applies on the credential
 * path, and for the same reason: those three have no escaped form in the
 * `QUOTED-CHAR` production, so escaping around them is not available, and
 * sending a value the server then rejects misdiagnoses the cause. A CR or LF
 * would additionally terminate the command line early and inject a SECOND
 * command whose tag comes from the mailbox name's own bytes.
 *
 * `\` and `"` DO have escaped forms and are escaped rather than refused —
 * they are legal in a mailbox name and refusing them would make real folders
 * unreachable.
 */
export function quoteMailbox(name: string): string | null {
  if (/[\r\n\u0000]/.test(name)) return null;
  return `"${name.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** A tagged IMAP response line, decomposed. */
export interface TaggedResponse {
  /** The command tag the server is answering, e.g. `a1`. */
  tag: string;
  /** The completion status. */
  status: "OK" | "NO" | "BAD";
  /** Everything after the status, verbatim and untrimmed of content. */
  text: string;
}

const TAGGED = /^([A-Za-z0-9][A-Za-z0-9._-]*) +(OK|NO|BAD)(?: +(.*))?$/;

/**
 * Parse a tagged response line.
 *
 * Returns `null` for anything that is not a tagged completion — untagged
 * lines, continuation requests, and malformed input all fall through, so a
 * caller reading until its own tag appears can simply keep reading.
 */
export function parseTaggedResponse(line: string): TaggedResponse | null {
  const match = TAGGED.exec(line);
  if (!match) return null;

  return {
    tag: match[1],
    status: match[2] as TaggedResponse["status"],
    // Group 3 is optional in the pattern, so it is genuinely absent for a
    // bare `a1 OK` even though the match array's type does not say so.
    text: match[3] ?? "",
  };
}

/**
 * Whether a line is an untagged server response (`* ...`).
 *
 * The server may emit any number of these before the tagged completion of
 * the command in flight, and also emits the connection greeting this way.
 */
export function isUntagged(line: string): boolean {
  return line.startsWith("* ") || line === "*";
}

/**
 * Extract the capability list from an untagged `* CAPABILITY ...` line.
 *
 * Returns the remainder VERBATIM — no normalisation, no sorting, no
 * uppercasing. That string is evidence: it is the first real measurement this
 * project takes of what Apple's server advertises, and Phase 4 reads it to
 * decide which literal form `APPEND` may use. A tidied copy would be a
 * summary of the evidence rather than the evidence.
 *
 * Returns `null` for any line that is not a capability response.
 */
export function parseCapabilityLine(line: string): string | null {
  const prefix = "* CAPABILITY ";
  if (!line.startsWith(prefix)) return null;

  const remainder = line.slice(prefix.length);
  return remainder.length > 0 ? remainder : null;
}

/**
 * Whether a capability string advertises non-synchronizing literals.
 *
 * Token match rather than substring match, and case-insensitive: IMAP
 * capability names are case-insensitive, and a substring test would also
 * match a hypothetical longer name that merely starts with the same letters.
 */
export function hasLiteralPlus(capabilityString: string): boolean {
  return capabilityString
    .split(/\s+/)
    .some((token) => token.toUpperCase() === "LITERAL+");
}

/**
 * IMAP response codes that name an authentication or authorization condition.
 *
 * Lowercase and bracketed, because the comparison is against a lowered line and
 * the brackets are what make these codes rather than ordinary words — an
 * unbracketed `authenticationfailed` could appear inside prose, and the
 * bracketed form is the one the protocol specifies.
 *
 * These outrank the prose list below, and the asymmetry is the whole point: a
 * response code is a specified, machine-readable signal the server chose from a
 * defined set, while a hint is a fragment of free-form text the server wrote for
 * a human. When both are present in one reply, the specified signal is the one
 * that carries meaning and the prose is decoration. So the code wins.
 *
 * The list is deliberately short. No live rejection has ever been observed from
 * `imap.mail.me.com` (01-IMAP-PROOF.md § 2 records a successful LOGIN), so every
 * code here is chosen from the specification rather than from evidence, and
 * adding a code on speculation would widen the one direction this function must
 * not get wrong — suppressing a genuine throttle.
 */
const AUTH_RESPONSE_CODES = [
  "[authenticationfailed]",
  "[authorizationfailed]",
  "[privacyrequired]",
];

/**
 * Wording servers use when refusing on connection count rather than on
 * credentials.
 *
 * Substring matching is the right shape here, unlike the capability test
 * above: these are prose fragments inside free-form server text, not tokens in
 * a specified list. Three of these — `try again later`, `temporarily
 * unavailable`, `[unavailable]` — are ordinary availability prose that a
 * credential rejection can perfectly well carry. That overlap is real and was
 * always real; what makes it harmless is the response-code guard above, not any
 * property of this list.
 *
 * A mailbox-quota fragment used to sit here and was removed. A quota condition
 * is neither a throttle nor a credential failure, and the four-value error
 * vocabulary has no category for it, so classifying it here told the caller to
 * wait for something waiting cannot change. It is left uncategorised on purpose:
 * `src/errors.ts` records that inventing a fifth category would put a value in
 * the model's vocabulary that no code path can reach.
 */
const CONNECTION_LIMIT_HINTS = [
  "too many",
  "connection limit",
  "try again later",
  "temporarily unavailable",
  "[unavailable]",
];

/**
 * Whether a tagged or untagged reply signals a connection-count refusal.
 *
 * Lives in the parser rather than in the session so there is exactly one place
 * to add a phrasing when the server surprises us, instead of an ad-hoc string
 * test at each site that needs to know.
 *
 * Structure is checked before prose, and the ordering is load-bearing rather
 * than stylistic. `authenticate` throws on a true result, and that throw exits
 * before the rejection detail is assembled — so a false positive here does not
 * merely mislabel the failure, it deletes the field that tells a wrong password
 * apart from a wrong username format.
 *
 * DEFERRED, deliberately: carrying that detail on the throttle path too, so
 * nothing is lost even on a true result. The guard above removes the case that
 * made it urgent — a credential rejection misclassified as a throttle, which was
 * the path that silently deleted the field — and what is left is a genuine
 * throttle, where the server's prose adds little the fixed safe message does not
 * already say. Doing it properly means widening the tool boundary's type gate
 * from a single error class to a second one and adding a field to a shipped
 * response shape for a category never once observed live. That is Phase 2
 * surface work, not a gap closure, and it is tracked in the defect ledger rather
 * than left to this comment.
 */
export function indicatesConnectionLimit(line: string): boolean {
  const lowered = line.toLowerCase();
  if (AUTH_RESPONSE_CODES.some((code) => lowered.includes(code))) return false;
  return CONNECTION_LIMIT_HINTS.some((hint) => lowered.includes(hint));
}

/**
 * Response codes that name a fault at the SERVER rather than a verdict on the
 * credential.
 *
 * Lowercase and bracketed for the same reason `AUTH_RESPONSE_CODES` is. These
 * are the two a server sends when it never got as far as checking the password:
 * `[SERVERBUG]` says the server broke, `[CONTACTADMIN]` says a human has to fix
 * something at their end. Neither is evidence about what is saved in the grant.
 *
 * This list is an EXCLUSION list, and that is the reverse of how
 * `AUTH_RESPONSE_CODES` is read one function down. Adding a code here makes the
 * pause fire LESS, so the risk of a wrong entry is a missed pause rather than a
 * false one — the same direction of caution, pointed the other way.
 */
const SERVER_FAULT_RESPONSE_CODES = ["[serverbug]", "[contactadmin]"];

/**
 * Whether a tagged reply is Apple refusing the password saved in the grant.
 *
 * **Classification is BY EXCLUSION, and that reverses iteration 1 of the phase
 * 12 code review. Owner decision, 2026-09-22.** A tagged `NO` to a login is
 * treated as a dead password unless it names one of the two conditions that are
 * demonstrably not about the password: a server fault response code above, or a
 * connection ceiling as `indicatesConnectionLimit` reads one. Everything else
 * pauses, including a refusal carrying no bracketed code at all.
 *
 * Why it was reversed. The allow-list version fired only on
 * `AUTH_RESPONSE_CODES`, and nothing in this repository has ever measured what
 * `imap.mail.me.com` actually replies to a wrong app-specific password — the
 * fixtures are labelled "Representative" and the live proof captured no refusal
 * at all. Plenty of IMAP servers answer a bad password as bare prose
 * (`a2 NO Authentication failed.`). If Apple is one of them, the allow-list
 * never fires in production and the account sits in the pre-LIFE-04 position:
 * every tool call opens a socket and spends another attempt against an
 * unpublished lockout threshold, which is the exact thing the pause exists to
 * stop and the thing that locks the user out of Mail.app on their own devices.
 * A missed pause is the expensive error here; a spurious one costs fifteen
 * minutes.
 *
 * **A `BAD` never pauses**, and neither does an `OK` or a line that is not a
 * tagged completion at all. `BAD` means this client sent something the server
 * could not parse — a protocol desync, our bug, and no statement about the
 * credential. That is why this reads the parsed status rather than the raw
 * string: the status is the one part of the line that is specified.
 *
 * **What the reversal costs, written down rather than left to be discovered.**
 * A server-side fault Apple spells with no response code now pauses a working
 * account for fifteen minutes. The compensation is the other half of the same
 * owner decision: `mail_imap_diagnose` and `dav_diagnose` answer THROUGH a
 * pause (see `answersDuringPause` in `src/password-pause.ts`), so the user can
 * always find out why they are paused and read Apple's own reply text while it
 * is in force. Without that exemption this widening would be the wrong trade.
 */
export function indicatesCredentialRefusal(line: string): boolean {
  // Only a tagged `NO`. An `OK`, a `BAD`, an untagged line and an unparseable
  // one all answer false — see the docstring for why `BAD` is deliberate.
  if (parseTaggedResponse(line)?.status !== "NO") return false;

  const lowered = line.toLowerCase();
  if (SERVER_FAULT_RESPONSE_CODES.some((code) => lowered.includes(code))) {
    return false;
  }
  // The throttle classification, reused rather than restated. `authenticate`
  // raises on a connection ceiling before it ever asks this question, so this
  // line is a second fence rather than the only one — but the two functions
  // must not be able to disagree about the same reply.
  return !indicatesConnectionLimit(line);
}
