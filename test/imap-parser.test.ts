// Pure parser units. No network, and no real socket anywhere.
//
// The line-level cases below are exactly what the header says: a string in, a
// decomposed value out. The mailbox-list, status and search cases are NOT, and
// the difference is deliberate rather than a drift in scope.
//
// Those three parsers take a `ResponseLine` — protocol text plus lifted literal
// payloads — and a `ResponseLine` is produced by the byte-counted reader, not by
// hand. Constructing one literally in a test would assert the parser against a
// shape this project's own reader might no longer produce, which is the kind of
// green suite 02-04 spent a whole task refusing. So every wire line in those
// cases is driven through the REAL reader path (`ImapChannel.readResponse` via
// `readUntilTag`, the same call production makes) over an in-memory duplex. A
// tokenizer or framing regression surfaces here as well as in
// `test/imap-literal.test.ts`, and the mailbox name that arrives as a LITERAL is
// only reachable this way at all.

import { describe, expect, it } from "vitest";
import * as imapParser from "../src/mail/imap-parser";
import type { ResponseLine } from "../src/mail/imap-parser";
import {
  correlateStatus,
  decodeModifiedUtf7,
  hasLiteralPlus,
  indicatesConnectionLimit,
  indicatesCredentialRefusal,
  isUntagged,
  parseAccessCode,
  parseCapabilityLine,
  parseCompletionCode,
  parseCopyUid,
  parseFingerprint,
  parseListLine,
  parseEsearchCount,
  parseModifiedUids,
  parsePermanentFlags,
  parseSearchLine,
  parseStatusLine,
  parseTaggedResponse,
  resolveFolderRole,
  seenStateOf,
  flagStateOf,
  keepsFlag,
} from "../src/mail/imap-parser";
import { ImapChannel, readUntilTag } from "../src/mail/imap-session";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  AUTH_CONTACTADMIN_TEXT,
  AUTH_REFUSED_PROSE_TEXT,
  AUTH_REJECTED_LEGACY_TEXT,
  AUTH_REJECTED_TEXT,
  AUTH_SERVER_FAULT_TEXT,
  AUTH_UNCLASSIFIED_TEXT,
  CONNECTION_LIMIT_TEXT,
  GREETING_LINE,
  MEASURED_ESEARCH_GONE_LINE,
  MEASURED_ESEARCH_PRESENT_LINE,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  UNTIDY_CAPABILITY_LINE,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

const ENCODER = new TextEncoder();

/** A read bound of a few milliseconds, so no case here costs wall time. */
const FAST_READ_MS = 40;

/** The tag every constructed exchange below completes with. */
const TAG = "a1";

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

/**
 * Drive constructed server lines through the real reader and return the
 * untagged responses.
 *
 * The tagged completion is appended here rather than by each caller, so no case
 * can accidentally assert against a read that never terminated.
 */
async function untaggedFrom(...lines: string[]): Promise<ResponseLine[]> {
  const channel = new ImapChannel(
    createFakeDuplex([wire(...lines), taggedOk(TAG, "completed")]),
    { readTimeoutMs: FAST_READ_MS },
  );
  return (await readUntilTag(channel, TAG)).untagged;
}

/** The same, for a turn that must carry raw bytes rather than lines. */
async function untaggedFromBytes(...turns: Uint8Array[]): Promise<ResponseLine[]> {
  const channel = new ImapChannel(
    createFakeDuplex([...turns, taggedOk(TAG, "completed")]),
    { readTimeoutMs: FAST_READ_MS },
  );
  return (await readUntilTag(channel, TAG)).untagged;
}

/**
 * A mailbox-list line whose NAME arrives as a literal.
 *
 * The declared octet count is DERIVED from the encoded name's byte length,
 * following `test/fixtures/hostile-bytes.ts`: a hand-written count silently
 * invalidates itself the moment anyone edits the name, and teaches the parser
 * the wrong framing in the direction of a green suite.
 *
 * Note where the CRLFs are. There is none between the last literal octet and
 * the end of the logical line, so the terminator that follows the payload is
 * the line's own — the same framing a real server produces.
 */
function listWithLiteralName(
  attributes: string,
  delimiter: string,
  name: string,
): Uint8Array {
  const bytes = ENCODER.encode(name);
  return concatBytes(
    ENCODER.encode(`* LIST (${attributes}) ${delimiter} {${bytes.byteLength}}\r\n`),
    bytes,
    ENCODER.encode("\r\n"),
  );
}

/** The first untagged line of a turn, parsed as a mailbox-list line. */
async function oneListLine(line: string) {
  const [first] = await untaggedFrom(line);
  return parseListLine(first!);
}

describe("parseTaggedResponse", () => {
  it("decomposes an OK completion", () => {
    expect(parseTaggedResponse("a1 OK CAPABILITY completed")).toEqual({
      tag: "a1",
      status: "OK",
      text: "CAPABILITY completed",
    });
  });

  it("decomposes a NO completion and keeps the server's text verbatim", () => {
    const parsed = parseTaggedResponse(
      "a2 NO [AUTHENTICATIONFAILED] Authentication failed",
    );
    expect(parsed?.status).toBe("NO");
    expect(parsed?.text).toBe("[AUTHENTICATIONFAILED] Authentication failed");
  });

  it("decomposes a BAD completion", () => {
    const parsed = parseTaggedResponse("a3 BAD syntax error");
    expect(parsed?.status).toBe("BAD");
    expect(parsed?.tag).toBe("a3");
  });

  it("returns an empty text for a bare completion rather than undefined", () => {
    expect(parseTaggedResponse("a9 OK")).toEqual({
      tag: "a9",
      status: "OK",
      text: "",
    });
  });

  it("returns null for untagged lines, continuations, and noise", () => {
    for (const line of [
      "* OK ready",
      "* CAPABILITY IMAP4rev1",
      "+ go ahead",
      "",
      "not a response at all",
      "a1 MAYBE something",
    ]) {
      expect(parseTaggedResponse(line)).toBeNull();
    }
  });

  it("matches the tagged reply even when several untagged lines precede it", () => {
    // The shape that breaks a reader which stops at the first line it can
    // parse. Only the last line here is a tagged completion.
    const conversation = [
      "* 3 EXISTS",
      "* 0 RECENT",
      "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
      "* OK [UIDVALIDITY 1] UIDs valid",
      "a4 OK completed",
    ];

    const parsed = conversation.map(parseTaggedResponse);
    expect(parsed.slice(0, 4).every((entry) => entry === null)).toBe(true);
    expect(parsed[4]).toEqual({ tag: "a4", status: "OK", text: "completed" });
  });

  it("does not confuse another command's tag with our own", () => {
    // A server may complete commands out of order. A reader waiting for `a5`
    // must not accept `a4`'s completion.
    const other = parseTaggedResponse("a4 OK completed");
    expect(other?.tag).not.toBe("a5");
  });
});

describe("isUntagged", () => {
  it("recognises the greeting and ordinary untagged responses", () => {
    expect(isUntagged(GREETING_LINE)).toBe(true);
    expect(isUntagged("* BYE Logging out")).toBe(true);
    expect(isUntagged("*")).toBe(true);
  });

  it("rejects tagged completions and continuation requests", () => {
    expect(isUntagged("a1 OK completed")).toBe(false);
    expect(isUntagged("+ go ahead")).toBe(false);
    expect(isUntagged("")).toBe(false);
  });
});

describe("parseCapabilityLine", () => {
  it("returns the pre-authentication list verbatim", () => {
    expect(parseCapabilityLine(`* CAPABILITY ${PRE_AUTH_CAPABILITY}`)).toBe(
      PRE_AUTH_CAPABILITY,
    );
  });

  it("returns the post-authentication list verbatim", () => {
    expect(parseCapabilityLine(`* CAPABILITY ${POST_AUTH_CAPABILITY}`)).toBe(
      POST_AUTH_CAPABILITY,
    );
  });

  it("preserves capitalisation and internal spacing exactly", () => {
    // The string is evidence. A normalised copy would be a summary of the
    // evidence, and the phase's whole job is to produce the evidence.
    const remainder = parseCapabilityLine(UNTIDY_CAPABILITY_LINE);
    expect(remainder).toBe(" IMAP4rev1   liTeRaL+ ");
    expect(remainder).toContain("liTeRaL+");
  });

  it("returns null for anything that is not a capability response", () => {
    expect(parseCapabilityLine(GREETING_LINE)).toBeNull();
    expect(parseCapabilityLine("a1 OK CAPABILITY completed")).toBeNull();
    expect(parseCapabilityLine("* CAPABILITY ")).toBeNull();
    expect(parseCapabilityLine("* BYE Logging out")).toBeNull();
  });
});

describe("hasLiteralPlus", () => {
  it("is false for the pre-authentication list", () => {
    expect(hasLiteralPlus(PRE_AUTH_CAPABILITY)).toBe(false);
  });

  it("is true for the post-authentication list", () => {
    expect(hasLiteralPlus(POST_AUTH_CAPABILITY)).toBe(true);
  });

  it("matches case-insensitively, as capability names are", () => {
    expect(hasLiteralPlus("IMAP4rev1 liTeRaL+ IDLE")).toBe(true);
  });

  it("matches whole tokens, not substrings", () => {
    // A longer name that merely starts with the same letters must not match.
    expect(hasLiteralPlus("IMAP4rev1 LITERAL+FOO IDLE")).toBe(false);
    expect(hasLiteralPlus("IMAP4rev1 LITERAL- IDLE")).toBe(false);
    expect(hasLiteralPlus("")).toBe(false);
  });
});

describe("indicatesConnectionLimit", () => {
  // Recognising a connection-count refusal is a parsing concern, not an ad-hoc
  // string test scattered through the session. It lives here so there is one
  // place to add a phrasing when the server surprises us.

  it("recognises a tagged refusal that names a connection ceiling", () => {
    expect(indicatesConnectionLimit(`a2 NO ${CONNECTION_LIMIT_TEXT}`)).toBe(
      true,
    );
  });

  it("recognises an untagged BYE that names a connection ceiling", () => {
    expect(
      indicatesConnectionLimit(
        "* BYE Too many simultaneous connections from this IP; try again later",
      ),
    ).toBe(true);
  });

  it("matches regardless of case", () => {
    expect(indicatesConnectionLimit("a2 NO TOO MANY CONNECTIONS")).toBe(true);
    expect(indicatesConnectionLimit("a2 NO too many connections")).toBe(true);
  });

  it("does not fire on an ordinary credential rejection", () => {
    // Misreading a wrong password as a throttle would tell the caller to wait
    // and retry, which is the one thing that definitely will not work.
    expect(indicatesConnectionLimit(`a2 NO ${AUTH_REJECTED_TEXT}`)).toBe(false);
    expect(
      indicatesConnectionLimit(`a2 NO ${AUTH_REJECTED_LEGACY_TEXT}`),
    ).toBe(false);
  });

  it("does not fire on a successful completion or an empty line", () => {
    expect(indicatesConnectionLimit("a1 OK CAPABILITY completed")).toBe(false);
    expect(indicatesConnectionLimit(GREETING_LINE)).toBe(false);
    expect(indicatesConnectionLimit("")).toBe(false);
  });

  it("still fires on an availability refusal that names no response code", () => {
    // The false-negative side of the boundary. Removing the prose match
    // entirely would be a cure worse than the disease: a genuine throttle
    // carrying only free-form text must still be recognised as one.
    expect(
      indicatesConnectionLimit(
        "a2 NO [ALERT] Account temporarily unavailable, please try again later.",
      ),
    ).toBe(true);
  });

  it("does not report a rejected password as a throttle when the prose says to retry", () => {
    // The failure this guard exists for. A throw on this path exits
    // `authenticate` before the rejection text is assembled, so the caller is
    // told to wait AND loses the one string that would have said the password
    // is wrong.
    expect(
      indicatesConnectionLimit(
        "a2 NO [AUTHENTICATIONFAILED] Account temporarily unavailable, please try again later.",
      ),
    ).toBe(false);
  });

  it("does not report a refused authorization as a throttle", () => {
    expect(
      indicatesConnectionLimit(
        "a2 NO [AUTHORIZATIONFAILED] Service temporarily unavailable, try again later",
      ),
    ).toBe(false);
  });

  it("does not report a privacy-required refusal as a throttle", () => {
    expect(
      indicatesConnectionLimit(
        "a2 NO [PRIVACYREQUIRED] Connection temporarily unavailable",
      ),
    ).toBe(false);
  });

  it("recognises the response code whatever case the server writes it in", () => {
    // Response codes are case-insensitive in IMAP, so a server writing one in
    // lower case must not slip past the guard and back onto the prose match.
    expect(
      indicatesConnectionLimit(
        "a2 no [authenticationfailed] too many failed attempts; try again later",
      ),
    ).toBe(false);
    expect(
      indicatesConnectionLimit(
        "A2 NO [AuthorizationFailed] TEMPORARILY UNAVAILABLE",
      ),
    ).toBe(false);
  });

  it("does not tell the caller to wait out a full mailbox", () => {
    // A quota condition is neither a throttle nor a credential failure, and
    // waiting does not empty a mailbox.
    expect(
      indicatesConnectionLimit("a2 NO [OVERQUOTA] Mailbox is over quota"),
    ).toBe(false);
    expect(
      indicatesConnectionLimit("A2 NO [OVERQUOTA] MAILBOX IS OVER QUOTA"),
    ).toBe(false);
  });
});

describe("indicatesCredentialRefusal", () => {
  // The question LIFE-04's pause is branched on: is this Apple saying the
  // password saved in the grant is dead? Classification is BY EXCLUSION per the
  // owner decision of 2026-09-22, which reversed the allow-list this function
  // shipped with — so the cases below come in two halves, and BOTH halves have
  // to stay populated. An exclusion list with every entry deleted answers true
  // to everything; an exclusion list widened to cover a real refusal answers
  // false to everything that matters.

  it("reads a bracketed authentication refusal as a dead password", () => {
    expect(indicatesCredentialRefusal(`a2 NO ${AUTH_REJECTED_TEXT}`)).toBe(true);
    expect(
      indicatesCredentialRefusal(`a2 NO ${AUTH_REJECTED_LEGACY_TEXT}`),
    ).toBe(true);
  });

  it("reads a PROSE-ONLY refusal as a dead password, which is the reversal", () => {
    // The case the allow-list missed, and the whole reason for the reversal.
    // Nothing in this repository has measured Apple's actual reply, and a server
    // that answers in prose left the pause never firing at all.
    expect(
      indicatesCredentialRefusal(`a2 NO ${AUTH_REFUSED_PROSE_TEXT}`),
    ).toBe(true);
  });

  it("reads a refusal whose prose never mentions the credential as one too", () => {
    // The classifier does not read the prose. This line says "Server busy" and
    // still pauses, because the alternative — guessing from free-form English —
    // is the allow-list problem in a different costume.
    expect(
      indicatesCredentialRefusal(`a2 NO ${AUTH_UNCLASSIFIED_TEXT}`),
    ).toBe(true);
  });

  it("does NOT read a server fault as a dead password", () => {
    expect(
      indicatesCredentialRefusal(`a2 NO ${AUTH_SERVER_FAULT_TEXT}`),
    ).toBe(false);
    expect(
      indicatesCredentialRefusal(`a2 NO ${AUTH_CONTACTADMIN_TEXT}`),
    ).toBe(false);
  });

  it("does not read a server fault as one whatever case the code is written in", () => {
    // Response codes are case-insensitive in IMAP. A server writing one in
    // lower case must not fall off the exclusion list and into a pause.
    expect(indicatesCredentialRefusal("a2 no [serverbug] internal error")).toBe(
      false,
    );
    expect(
      indicatesCredentialRefusal("A2 NO [ContactAdmin] ASK YOUR ADMIN"),
    ).toBe(false);
  });

  it("does NOT read a connection ceiling as a dead password", () => {
    // The classification `indicatesConnectionLimit` already makes, reused. Two
    // shapes: the bracketed one and a prose-only ceiling.
    expect(
      indicatesCredentialRefusal(`a2 NO ${CONNECTION_LIMIT_TEXT}`),
    ).toBe(false);
    expect(
      indicatesCredentialRefusal("a2 NO Too many simultaneous connections"),
    ).toBe(false);
  });

  it("still reads a refusal that names a code AND says to retry as a dead password", () => {
    // The overlap the throttle guard exists for, seen from this side. The
    // bracketed code outranks the availability prose, so this pauses.
    expect(
      indicatesCredentialRefusal(
        "a2 NO [AUTHENTICATIONFAILED] Account temporarily unavailable, try again later",
      ),
    ).toBe(true);
  });

  it("does NOT read a BAD as a dead password", () => {
    // A protocol error is this client sending something the server could not
    // parse — our bug, and no statement at all about the credential.
    expect(indicatesCredentialRefusal("a2 BAD syntax error")).toBe(false);
    expect(
      indicatesCredentialRefusal(`a2 BAD ${AUTH_REFUSED_PROSE_TEXT}`),
    ).toBe(false);
  });

  it("does not read a success, an untagged line or an empty line as one", () => {
    expect(indicatesCredentialRefusal("a1 OK LOGIN completed")).toBe(false);
    expect(indicatesCredentialRefusal(GREETING_LINE)).toBe(false);
    expect(indicatesCredentialRefusal("* NO something happened")).toBe(false);
    expect(indicatesCredentialRefusal("")).toBe(false);
  });
});

describe("parseListLine", () => {
  it("decomposes a mailbox-list into attributes, delimiter and name", async () => {
    const parsed = await oneListLine('* LIST (\\HasNoChildren \\Drafts) "/" "Drafts"');

    expect(parsed).toEqual({
      attributes: ["\\HasNoChildren", "\\Drafts"],
      delimiter: "/",
      name: "Drafts",
    });
  });

  it("returns the attributes byte-identically, casing included", async () => {
    // The attribute list is the evidence that settles whether this server emits
    // special-use attributes at all. A normalised copy would be a summary of the
    // evidence rather than the evidence — the same argument the capability
    // parser above makes, and it matters more here because the question is open.
    const parsed = await oneListLine('* LIST (\\noselect \\HASCHILDREN) "/" "Odd"');

    expect(parsed?.attributes).toEqual(["\\noselect", "\\HASCHILDREN"]);
    // Not lowercased, not uppercased, not sorted.
    expect(parsed?.attributes[0]).toBe("\\noselect");
    expect(parsed?.attributes[1]).toBe("\\HASCHILDREN");
  });

  it("yields a null delimiter for a flat namespace, and does not throw", async () => {
    // A NIL delimiter is legal — the grammar's second field is
    // `(DQUOTE QUOTED-CHAR DQUOTE / nil)`. Code that indexes into it throws,
    // which is the specific crash this case pins.
    const parsed = await oneListLine('* LIST (\\HasNoChildren) NIL "Flat"');

    expect(parsed?.delimiter).toBeNull();
    expect(parsed?.name).toBe("Flat");
  });

  it("yields an empty array for an empty attribute list", async () => {
    const parsed = await oneListLine('* LIST () "/" "Plain"');

    expect(parsed?.attributes).toEqual([]);
  });

  it("keeps a mailbox name containing a space intact when it arrives quoted", async () => {
    // `Sent Messages` is Apple's own name for the sent folder, so a parser that
    // split this on whitespace would break the ladder on the exact folder the
    // ladder exists for.
    const parsed = await oneListLine('* LIST (\\HasNoChildren) "/" "Sent Messages"');

    expect(parsed?.name).toBe("Sent Messages");
  });

  it("keeps a mailbox name intact when it arrives as a LITERAL", async () => {
    // Reachable only through the byte-counted reader: the name is lifted out of
    // the protocol text as bytes and referenced by placeholder, so the parser
    // has to resolve it back rather than read it out of the line.
    const [first] = await untaggedFromBytes(
      listWithLiteralName("\\HasNoChildren", '"/"', "Re&AOc-us"),
    );

    expect(first!.literals).toHaveLength(1);
    expect(parseListLine(first!)).toEqual({
      attributes: ["\\HasNoChildren"],
      delimiter: "/",
      name: "Re&AOc-us",
    });
  });

  it("returns null for a line that is not a mailbox-list", async () => {
    for (const line of [
      "* STATUS \"INBOX\" (MESSAGES 17)",
      "* SEARCH 1 2 3",
      "* 3 EXISTS",
      "* OK [UIDVALIDITY 1] UIDs valid",
      "* CAPABILITY IMAP4rev1",
    ]) {
      const [first] = await untaggedFrom(line);
      expect(parseListLine(first!)).toBeNull();
    }
  });
});

describe("parseStatusLine", () => {
  it("decomposes a status reply into its mailbox name and counts", async () => {
    const [first] = await untaggedFrom('* STATUS "INBOX" (MESSAGES 17 UNSEEN 16)');

    expect(parseStatusLine(first!)).toEqual({
      name: "INBOX",
      counts: { MESSAGES: 17, UNSEEN: 16 },
    });
  });

  it("reports only the counts that arrived, never defaulting the rest to zero", async () => {
    // A folder with no reported unseen count is a different fact from a folder
    // with zero unread, and only one of the two is true.
    const [first] = await untaggedFrom('* STATUS "Archive" (MESSAGES 4)');
    const parsed = parseStatusLine(first!);

    expect(parsed?.counts).toEqual({ MESSAGES: 4 });
    expect(parsed?.counts.UNSEEN).toBeUndefined();
    expect("UNSEEN" in parsed!.counts).toBe(false);
  });

  it("matches the count names case-insensitively, as response atoms are", async () => {
    const [first] = await untaggedFrom('* STATUS "INBOX" (messages 3 uNsEeN 1)');

    expect(parseStatusLine(first!)?.counts).toEqual({ MESSAGES: 3, UNSEEN: 1 });
  });

  it("reports a zero count that really arrived", async () => {
    const [first] = await untaggedFrom('* STATUS "Junk" (MESSAGES 0 UNSEEN 0)');

    expect(parseStatusLine(first!)?.counts).toEqual({ MESSAGES: 0, UNSEEN: 0 });
  });

  it("returns null for a line that is not a status reply", async () => {
    for (const line of [
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      "* SEARCH 1 2 3",
      "* 3 EXISTS",
    ]) {
      const [first] = await untaggedFrom(line);
      expect(parseStatusLine(first!)).toBeNull();
    }
  });
});

describe("correlateStatus", () => {
  /** The worked exchange from RFC 5819 §3, with one unselectable folder. */
  const LIST_LINES = [
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* LIST (\\HasNoChildren \\Drafts) "/" "Drafts"',
    '* LIST (\\Noselect \\HasChildren) "/" "Archive"',
  ];
  const STATUS_LINES = [
    '* STATUS "INBOX" (MESSAGES 17 UNSEEN 16)',
    '* STATUS "Drafts" (MESSAGES 2 UNSEEN 0)',
  ];

  async function parseBoth(lines: string[]) {
    const untagged = await untaggedFrom(...lines);
    const lists = untagged
      .map(parseListLine)
      .filter((entry) => entry !== null);
    const statuses = untagged
      .map(parseStatusLine)
      .filter((entry) => entry !== null);
    return { lists, statuses };
  }

  it("pairs each folder with the counts that named it", async () => {
    const { lists, statuses } = await parseBoth([
      LIST_LINES[0]!,
      STATUS_LINES[0]!,
      LIST_LINES[1]!,
      STATUS_LINES[1]!,
    ]);

    const correlated = correlateStatus(lists, statuses);

    expect(correlated.map((entry) => entry.line.name)).toEqual([
      "INBOX",
      "Drafts",
    ]);
    expect(correlated[0]!.counts).toEqual({ MESSAGES: 17, UNSEEN: 16 });
    expect(correlated[1]!.counts).toEqual({ MESSAGES: 2, UNSEEN: 0 });
  });

  it("yields null counts for a folder with no status reply", async () => {
    // RFC 5819 §2: a mailbox that cannot be selected gets no STATUS reply at
    // all, and the LIST response carries \Noselect instead. That is an ordinary
    // folder listing, not an error.
    const { lists, statuses } = await parseBoth([...LIST_LINES, ...STATUS_LINES]);

    const correlated = correlateStatus(lists, statuses);

    expect(correlated).toHaveLength(3);
    expect(correlated[2]!.line.name).toBe("Archive");
    expect(correlated[2]!.counts).toBeNull();
  });

  it("correlates by NAME, not by position", async () => {
    // THE discriminating case. Both reply sets are fed in DIFFERENT orders, so
    // a positional implementation attributes INBOX's 17 messages to Drafts and
    // still returns a plausible-looking result. The RFC permits a server to drop
    // a status reply for a mailbox it could not select, and to drop one on an
    // internal problem while still completing the command successfully — so
    // positional pairing misattributes counts in exactly the case where a folder
    // is unusual.
    const { lists } = await parseBoth(LIST_LINES);
    const { statuses } = await parseBoth([...STATUS_LINES].reverse());

    expect(statuses.map((entry) => entry.name)).toEqual(["Drafts", "INBOX"]);

    const correlated = correlateStatus(lists, statuses);

    expect(correlated[0]!.line.name).toBe("INBOX");
    expect(correlated[0]!.counts).toEqual({ MESSAGES: 17, UNSEEN: 16 });
    expect(correlated[1]!.line.name).toBe("Drafts");
    expect(correlated[1]!.counts).toEqual({ MESSAGES: 2, UNSEEN: 0 });
  });

  it("returns every folder even when no status reply arrived at all", async () => {
    // The plain-LIST fallback shape: iCloud may reject the LIST-STATUS return
    // clause outright, and the folder listing must still be a folder listing.
    const { lists } = await parseBoth(LIST_LINES);

    const correlated = correlateStatus(lists, []);

    expect(correlated).toHaveLength(3);
    expect(correlated.every((entry) => entry.counts === null)).toBe(true);
  });
});

describe("decodeModifiedUtf7", () => {
  // PROVENANCE of the wire strings below. Every one was computed from RFC 3501
  // §5.1.3's rules with an independent script and pasted in as a constant — NOT
  // produced by an encoder in this repository, which would make each assertion
  // a round trip through the author's own misunderstanding. There is no encoder
  // here to round-trip against, deliberately; see the decoder's own docstring.

  it("returns a pure-ASCII name unchanged", () => {
    // Apple's own folder names are all ASCII, which is exactly why this is easy
    // to skip: an English account never sees the decoder do anything.
    for (const name of [
      "INBOX",
      "Drafts",
      "Sent Messages",
      "Deleted Messages",
      "Archive/2024",
      "",
    ]) {
      expect(decodeModifiedUtf7(name)).toBe(name);
    }
  });

  it("decodes the escaped ampersand to a single ampersand", () => {
    expect(decodeModifiedUtf7("&-")).toBe("&");
    expect(decodeModifiedUtf7("R&-D")).toBe("R&D");
    expect(decodeModifiedUtf7("Rock &- Roll")).toBe("Rock & Roll");
  });

  it("decodes an accented Latin character", () => {
    // The failure Pitfall 6 names: a French account's `Reçus` arrives like this
    // and is shown to the model verbatim unless something decodes it.
    expect(decodeModifiedUtf7("Re&AOc-us")).toBe("Reçus");
    expect(decodeModifiedUtf7("Caf&AOk-")).toBe("Café");
  });

  it("decodes a character outside the basic multilingual plane", () => {
    // The decoded bytes are big-endian UTF-16 code UNITS, so this run is a
    // surrogate PAIR that must become one character. An implementation that
    // treats each unit as a code point produces two replacement characters and
    // a name that looks almost right.
    const decoded = decodeModifiedUtf7("&2D3eAA-");

    expect(decoded).toBe("\u{1F600}");
    expect(decoded.codePointAt(0)).toBe(0x1f600);
    expect([...decoded]).toHaveLength(1);
    expect(decoded.length).toBe(2);
  });

  it("uses the modified alphabet, where a comma replaces the sixty-third character", () => {
    // U+03F0 encodes to a run containing the sixty-third alphabet position. A
    // decoder that used the standard base64 table finds no comma in it and
    // rejects — or worse, silently maps it wrong.
    expect(decodeModifiedUtf7("&A,A-")).toBe("ϰ");
    // And the character the comma REPLACED is not in the alphabet at all.
    expect(decodeModifiedUtf7("&A/A-")).toBe("&A/A-");
  });

  it("decodes a shifted run immediately followed by more ASCII", () => {
    expect(decodeModifiedUtf7("&AOc-us")).toBe("çus");
    expect(decodeModifiedUtf7("&AOc-")).toBe("ç");
  });

  it("decodes two shifted runs in one name", () => {
    expect(decodeModifiedUtf7("A&AOc-B&AOk-C")).toBe("AçBéC");
    expect(decodeModifiedUtf7("&AOc-&AOk-")).toBe("çé");
    // Two characters in ONE run decode too, which is the other packing.
    expect(decodeModifiedUtf7("&AOcA6Q-")).toBe("çé");
  });

  it("returns the input unchanged when a shifted run is unterminated", () => {
    // A folder name is an identifier as well as a label. A half-decoded name is
    // worse than an undecoded one, and the raw wire name is what the opaque
    // token carries anyway, so nothing downstream depends on this succeeding.
    expect(decodeModifiedUtf7("Re&AOcus")).toBe("Re&AOcus");
    expect(decodeModifiedUtf7("Trailing&")).toBe("Trailing&");
    expect(decodeModifiedUtf7("&AOc-and&AOk")).toBe("&AOc-and&AOk");
  });

  it("returns the input unchanged when a shifted run holds a character outside the alphabet", () => {
    expect(decodeModifiedUtf7("Re&AO!c-us")).toBe("Re&AO!c-us");
    expect(decodeModifiedUtf7("&A B-")).toBe("&A B-");
  });

  it("returns the input unchanged when a shifted run is truncated mid-character", () => {
    // Two base64 characters carry twelve bits, and a UTF-16 code unit needs
    // sixteen. A whole character's worth of data went missing, which is the
    // truncation case rather than the padding case.
    expect(decodeModifiedUtf7("&AA-")).toBe("&AA-");
    expect(decodeModifiedUtf7("Re&AOcAO-us")).toBe("Re&AOcAO-us");
  });

  it("does not grow an encoder", () => {
    // Stated as a test as well as in the docstring, because this is a property
    // of the module rather than of any one function: the opaque token stores the
    // RAW wire name, so the round trip back to the server is byte-exact by
    // construction. An encoder appearing here later would be a regression, not
    // an addition — it would introduce a second spelling of a name the server
    // already spelled.
    const parser = imapParser as Record<string, unknown>;
    const encoders = Object.keys(parser).filter((name) =>
      /^encode/i.test(name),
    );
    expect(encoders).toEqual([]);
  });
});

describe("resolveFolderRole", () => {
  it("resolves each special-use attribute, and records the attribute path", () => {
    // Five of the six roles come from RFC 6154 attributes. Whether THIS server
    // emits any of them is the open question the source field exists to settle
    // on the first real run.
    const cases: Array<[string, string]> = [
      ["\\Drafts", "drafts"],
      ["\\Sent", "sent"],
      ["\\Trash", "trash"],
      ["\\Junk", "junk"],
      ["\\Archive", "archive"],
    ];

    for (const [attribute, role] of cases) {
      expect(resolveFolderRole([attribute], "Whatever The User Called It", "/")).toEqual({
        role,
        source: "special-use",
      });
    }
  });

  it("matches attributes case-insensitively, as response atoms are", () => {
    expect(resolveFolderRole(["\\HasNoChildren", "\\dRaFtS"], "Nonsense", "/")).toEqual({
      role: "drafts",
      source: "special-use",
    });
  });

  it("ignores the two RFC 6154 attributes this project names no role for", () => {
    // `\All` and `\Flagged` are virtual mailboxes rather than one of the six
    // roles D-31 identifies, and inventing a role for them would put a value in
    // the vocabulary that nothing downstream can act on.
    expect(resolveFolderRole(["\\All"], "All Mail", "/")).toEqual({
      role: null,
      source: null,
    });
    expect(resolveFolderRole(["\\Flagged"], "Flagged", "/")).toEqual({
      role: null,
      source: null,
    });
  });

  it("falls back to the name ladder, and records the name path", () => {
    expect(resolveFolderRole([], "Drafts", "/")).toEqual({
      role: "drafts",
      source: "name-match",
    });
    expect(resolveFolderRole(["\\HasNoChildren"], "Archive", "/")).toEqual({
      role: "archive",
      source: "name-match",
    });
  });

  it("lets the attribute WIN when both are present, and says so", () => {
    // The ordering a naive implementation gets backwards, and the reason it
    // matters: any user or mail client can create a folder named `Drafts`, so a
    // name is a claim and an attribute is the server's own answer. The reported
    // source is what makes the difference visible without reading code.
    expect(resolveFolderRole(["\\Sent"], "Drafts", "/")).toEqual({
      role: "sent",
      source: "special-use",
    });
  });

  it("knows Apple's own folder names, not only the generic ones", () => {
    // PITFALLS #8. A generic-only ladder resolves NEITHER of these, and this
    // account uses both.
    expect(resolveFolderRole([], "Sent Messages", "/")).toEqual({
      role: "sent",
      source: "name-match",
    });
    expect(resolveFolderRole([], "Deleted Messages", "/")).toEqual({
      role: "trash",
      source: "name-match",
    });
    // And the generic forms still resolve, for an account that uses those.
    expect(resolveFolderRole([], "Sent", "/").role).toBe("sent");
    expect(resolveFolderRole([], "Trash", "/").role).toBe("trash");
    expect(resolveFolderRole([], "Spam", "/").role).toBe("junk");
    expect(resolveFolderRole([], "Junk", "/").role).toBe("junk");
  });

  it("resolves the inbox from the protocol-reserved name, whatever case it arrives in", () => {
    for (const name of ["INBOX", "inbox", "InBoX"]) {
      expect(resolveFolderRole([], name, "/")).toEqual({
        role: "inbox",
        source: "name-match",
      });
    }
  });

  it("does not let a CHILD folder claim its parent's role", () => {
    // `Archive/2024` is a year's worth of filed mail, not the archive folder.
    // Refused with the delimiter READ FROM THE WIRE rather than an assumed
    // separator, and refused again by whole-name matching when no delimiter was
    // reported at all.
    expect(resolveFolderRole([], "Archive/2024", "/")).toEqual({
      role: null,
      source: null,
    });
    expect(resolveFolderRole([], "Archive/2024", null)).toEqual({
      role: null,
      source: null,
    });
    expect(resolveFolderRole([], "Sent Messages/2024", "/").role).toBeNull();
    expect(resolveFolderRole([], "INBOX/Drafts", "/").role).toBeNull();
    // A server using a different delimiter is refused on ITS delimiter, which
    // is the point of not hardcoding one.
    expect(resolveFolderRole([], "Archive.2024", ".").role).toBeNull();
  });

  it("still honours an ATTRIBUTE on a nested folder", () => {
    // The asymmetry is deliberate. The ladder is a heuristic about names, so it
    // is restricted to top-level folders; an attribute is the server's own
    // statement about that mailbox and holds wherever the mailbox lives.
    expect(resolveFolderRole(["\\Drafts"], "INBOX/Drafts", "/")).toEqual({
      role: "drafts",
      source: "special-use",
    });
  });

  it("compares names case-insensitively", () => {
    expect(resolveFolderRole([], "drafts", "/").role).toBe("drafts");
    expect(resolveFolderRole([], "SENT MESSAGES", "/").role).toBe("sent");
    expect(resolveFolderRole([], "dElEtEd mEsSaGeS", "/").role).toBe("trash");
  });

  it("compares against the DECODED name, so a wire-encoded name is comparable", () => {
    // `&AEQ-rafts` is a legal — if unusual — modified-UTF-7 spelling of
    // `Drafts`. It is used here because it makes the property observable with a
    // name the ladder actually knows: pass the wire form and nothing matches;
    // decode first and it does. Pitfall 6's real case is `Re&AOc-us`, where the
    // consequence is the same and the folder is simply never recognised.
    const wireName = "&AEQ-rafts";

    expect(decodeModifiedUtf7(wireName)).toBe("Drafts");
    expect(resolveFolderRole([], decodeModifiedUtf7(wireName), "/")).toEqual({
      role: "drafts",
      source: "name-match",
    });
    expect(resolveFolderRole([], wireName, "/")).toEqual({
      role: null,
      source: null,
    });
  });

  it("returns a null role AND a null source for an ordinary user folder", () => {
    // Never a guess. Criterion 1 requires the drafts folder be DISCOVERED
    // rather than guessed, and a guess that happens to be right is still a
    // guess. Both fields are null, so a caller cannot read a source and infer a
    // role that was never resolved.
    for (const name of ["Job Search", "Receipts", "Reçus", "Sent Items"]) {
      expect(resolveFolderRole([], name, "/")).toEqual({
        role: null,
        source: null,
      });
    }
  });
});

describe("parseSearchLine", () => {
  it("parses a flat list of identifiers", async () => {
    const [first] = await untaggedFrom("* SEARCH 4102 3871 3702");

    expect(parseSearchLine(first!)).toEqual([4102, 3871, 3702]);
  });

  it("yields an EMPTY array for a search that matched nothing", async () => {
    // `mailbox-data = … "SEARCH" *(SP nz-number)` — the zero-identifier form is
    // legal and ordinary. A parser returning null here makes "no results" look
    // like a parse failure, and the tool would report an error for a search
    // that ran perfectly.
    const [first] = await untaggedFrom("* SEARCH");

    expect(parseSearchLine(first!)).toEqual([]);
  });

  it("parses a reply carrying thousands of identifiers", async () => {
    // No length cap anywhere on this path. The reply comes from the account's
    // own server over an authenticated session, the identifiers never reach the
    // model, and the search is re-run per page precisely so nothing is cached.
    const uids = Array.from({ length: 5000 }, (_, index) => 90000 - index);
    const [first] = await untaggedFrom(`* SEARCH ${uids.join(" ")}`);

    const parsed = parseSearchLine(first!);

    expect(parsed).toHaveLength(5000);
    expect(parsed![0]).toBe(90000);
    expect(parsed![4999]).toBe(85001);
  });

  it("ignores a CONDSTORE MODSEQ trailer rather than choking on it", async () => {
    // RFC 4551 appends `(MODSEQ n)` to the SEARCH response, and this account's
    // server advertises CONDSTORE. A parser that coerced every token would put
    // NaN in the identifier list.
    const [first] = await untaggedFrom("* SEARCH 1 2 3 (MODSEQ 917162500)");

    expect(parseSearchLine(first!)).toEqual([1, 2, 3]);
  });

  it("returns null for a line that is not a search reply", async () => {
    for (const line of [
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 17)',
      "* 3 EXISTS",
      "* CAPABILITY IMAP4rev1",
    ]) {
      const [first] = await untaggedFrom(line);
      expect(parseSearchLine(first!)).toBeNull();
    }
  });
});

describe("parseEsearchCount", () => {
  // iCloud sends no untagged search line when a plain search matches nothing
  // (21-UAT.md, "Probe, 2026-09-27"), so a move's re-read asks for a count
  // instead. These are the two lines the probe recorded, then every way a line
  // can fail to be the answer to THIS command.
  async function countOf(line: string, tag: string): Promise<number | null> {
    const [first] = await untaggedFrom(line);
    return parseEsearchCount(first!, tag);
  }

  it.each<[string, string, string, number | null]>([
    ["iCloud's measured reply for a UID that is gone", MEASURED_ESEARCH_GONE_LINE, "a6", 0],
    ["iCloud's measured reply for a UID that is there", MEASURED_ESEARCH_PRESENT_LINE, "a7", 1],
    ["the gone reply read for another command's tag", MEASURED_ESEARCH_GONE_LINE, "a7", null],
    ["a tag that only starts the same", '* ESEARCH (TAG "a60") UID COUNT 0', "a6", null],
    ["no correlator at all", "* ESEARCH UID COUNT 0", "a6", null],
    ["a correlator with no tag value", "* ESEARCH (TAG) UID COUNT 0", "a6", null],
    ["no COUNT item", '* ESEARCH (TAG "a6") UID MIN 3', "a6", null],
    ["no return data at all", '* ESEARCH (TAG "a6") UID', "a6", null],
    ["COUNT with no number", '* ESEARCH (TAG "a6") UID COUNT', "a6", null],
    ["COUNT with a word for a number", '* ESEARCH (TAG "a6") UID COUNT none', "a6", null],
    ["COUNT with a negative number", '* ESEARCH (TAG "a6") UID COUNT -1', "a6", null],
    ["COUNT with a leading zero", '* ESEARCH (TAG "a6") UID COUNT 01', "a6", null],
    ["COUNT past the 32-bit range", '* ESEARCH (TAG "a6") UID COUNT 4294967296', "a6", null],
    ["COUNT twice", '* ESEARCH (TAG "a6") UID COUNT 0 COUNT 1', "a6", null],
    ["other items before COUNT", '* ESEARCH (TAG "a6") UID MIN 3 COUNT 1', "a6", 1],
    ["other items after COUNT", '* ESEARCH (TAG "a6") UID COUNT 2 MIN 3 MAX 9', "a6", 2],
    ["a set-valued item before COUNT", '* ESEARCH (TAG "a6") UID ALL 3:5,9 COUNT 4', "a6", 4],
    ["no UID marker", '* ESEARCH (TAG "a6") COUNT 0', "a6", 0],
    ["lowercase throughout", '* esearch (tag "a6") uid count 0', "a6", 0],
    ["a plain search line", "* SEARCH 4242", "a6", null],
    ["iCloud's empty plain search, were it ever sent", "* SEARCH", "a6", null],
    ["another untagged line", "* 3 EXISTS", "a6", null],
  ])("%s", async (_label, line, tag, expected) => {
    expect(await countOf(line, tag)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// The mutating path's two parsers (phase 20, plan 20-03)
// ---------------------------------------------------------------------------

describe("parseAccessCode", () => {
  it("reads read-write off an OK completion", () => {
    expect(parseAccessCode("a4 OK [READ-WRITE] SELECT completed")).toBe(
      "read-write",
    );
  });

  it("reads read-only off an OK completion", () => {
    expect(parseAccessCode("a4 OK [READ-ONLY] SELECT completed")).toBe(
      "read-only",
    );
  });

  it("matches the code in any case, as response codes are case-insensitive", () => {
    expect(parseAccessCode("a4 OK [read-write] SELECT completed")).toBe(
      "read-write",
    );
    expect(parseAccessCode("a4 OK [Read-Only] done")).toBe("read-only");
  });

  it("is null when the completion carries no access code", () => {
    // Absent is its own answer, not read-write (PITFALLS #33).
    expect(parseAccessCode("a4 OK SELECT completed")).toBeNull();
    expect(parseAccessCode("a4 OK")).toBeNull();
  });

  it("is null on a NO, even one carrying the code", () => {
    expect(parseAccessCode("a4 NO [READ-WRITE] no such mailbox")).toBeNull();
    expect(parseAccessCode("a4 BAD [READ-WRITE] syntax")).toBeNull();
  });

  it("is null when the code sits later in the human text", () => {
    // Only the bracketed code immediately after OK is a response code. The
    // same letters further along are prose the server chose to write.
    expect(
      parseAccessCode("a4 OK SELECT completed [READ-WRITE]"),
    ).toBeNull();
    expect(
      parseAccessCode("a4 OK [UIDVALIDITY 5] then [READ-WRITE]"),
    ).toBeNull();
  });

  it("is null on an untagged line", () => {
    expect(parseAccessCode("* OK [READ-WRITE] mailbox open")).toBeNull();
  });
});

describe("parseCompletionCode", () => {
  it("reads the code right after the status, on any status, upper-cased", () => {
    expect(parseCompletionCode("a5 NO [NONEXISTENT] No such message")).toBe("NONEXISTENT");
    expect(parseCompletionCode("a5 NO [unavailable] later")).toBe("UNAVAILABLE");
    expect(parseCompletionCode("a5 BAD [CLIENTBUG] odd")).toBe("CLIENTBUG");
    expect(parseCompletionCode("a4 OK [READ-WRITE] SELECT completed")).toBe("READ-WRITE");
  });

  it("returns the code's first atom only, never its arguments", () => {
    expect(parseCompletionCode("a4 OK [UIDVALIDITY 5] done")).toBe("UIDVALIDITY");
  });

  it("is null with no code, a code later in the text, or an untagged line", () => {
    expect(parseCompletionCode("a5 NO STORE failed")).toBeNull();
    expect(parseCompletionCode("a5 NO")).toBeNull();
    expect(parseCompletionCode("a5 NO failed [NONEXISTENT]")).toBeNull();
    expect(parseCompletionCode("* NO [NONEXISTENT] gone")).toBeNull();
  });
});

describe("parsePermanentFlags", () => {
  it("reads the list off the untagged OK, verbatim and in order", () => {
    expect(
      parsePermanentFlags(
        "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted",
      ),
    ).toEqual(["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft", "\\*"]);
  });

  it("reads an empty list as an empty array, not as absent", () => {
    // Empty means no flag is kept. Absent means every flag is. Mixing the two
    // up is the whole hazard.
    expect(parsePermanentFlags("* OK [PERMANENTFLAGS ()] No permanent flags")).toEqual([]);
  });

  it("matches the code in any case, and keeps the flags' own case", () => {
    expect(parsePermanentFlags("* ok [permanentflags (\\seen)] ok")).toEqual(["\\seen"]);
  });

  it("is null when the line carries no such code", () => {
    expect(parsePermanentFlags("* OK [UIDVALIDITY 5] UIDs valid")).toBeNull();
    expect(parsePermanentFlags("* FLAGS (\\Seen \\Draft)")).toBeNull();
    expect(parsePermanentFlags("* 172 EXISTS")).toBeNull();
  });

  it("is null on a tagged line or a NO, even one carrying the code", () => {
    expect(parsePermanentFlags("a4 OK [PERMANENTFLAGS (\\Seen)] done")).toBeNull();
    expect(parsePermanentFlags("* NO [PERMANENTFLAGS (\\Seen)] odd")).toBeNull();
  });
});

describe("seenStateOf", () => {
  it("finds the reply whose own UID matches, among several", async () => {
    const untagged = await untaggedFrom(
      "* 3 FETCH (UID 10 FLAGS ())",
      "* 4 FETCH (UID 11 FLAGS (\\Seen))",
      "* 5 FETCH (UID 12 FLAGS ())",
    );

    expect(seenStateOf(untagged, 11)).toBe(true);
    expect(seenStateOf(untagged, 10)).toBe(false);
    expect(seenStateOf(untagged, 12)).toBe(false);
  });

  it("keys on the UID item, never on the sequence-number prefix", async () => {
    // The prefix here is 11, and it names a different message. Reading it as
    // the UID would report another message's state as this one's.
    const untagged = await untaggedFrom("* 11 FETCH (UID 40 FLAGS (\\Seen))");

    expect(seenStateOf(untagged, 11)).toBeNull();
    expect(seenStateOf(untagged, 40)).toBe(true);
  });

  it("skips a reply with no UID item", async () => {
    const untagged = await untaggedFrom(
      "* 4 FETCH (FLAGS (\\Seen))",
      "* 5 FETCH (UID 11 FLAGS ())",
    );

    expect(seenStateOf(untagged, 11)).toBe(false);
    expect(seenStateOf(untagged, 4)).toBeNull();
  });

  it("takes the LAST reply for the UID when there are several (WR-02)", async () => {
    // An unsolicited flag update from another device can arrive before the
    // command's own reply. The server's final word is the last one, both ways.
    const seenLast = await untaggedFrom(
      "* 4 FETCH (UID 11 FLAGS ())",
      "* 4 FETCH (UID 11 FLAGS (\\Seen))",
    );
    const unseenLast = await untaggedFrom(
      "* 4 FETCH (UID 11 FLAGS (\\Seen))",
      "* 7 FETCH (UID 12 FLAGS (\\Seen))",
      "* 4 FETCH (UID 11 FLAGS (\\Flagged))",
    );

    expect(seenStateOf(seenLast, 11)).toBe(true);
    expect(seenStateOf(unseenLast, 11)).toBe(false);
  });

  it("keeps an earlier flag list when a later reply for the UID carries none", async () => {
    // A later reply with no flag list says nothing about the flag, so it
    // cannot replace a reply that did.
    const untagged = await untaggedFrom(
      "* 4 FETCH (UID 11 FLAGS (\\Seen))",
      "* 4 FETCH (UID 11 MODSEQ (124))",
    );

    expect(seenStateOf(untagged, 11)).toBe(true);
  });

  it("is null when the matching reply carries no flag list", async () => {
    const untagged = await untaggedFrom("* 4 FETCH (UID 11 MODSEQ (123))");

    expect(seenStateOf(untagged, 11)).toBeNull();
  });

  it("is null when there is no reply at all", () => {
    expect(seenStateOf([], 11)).toBeNull();
  });

  it("reads the seen flag in any case", async () => {
    const untagged = await untaggedFrom("* 4 FETCH (UID 11 FLAGS (\\SEEN \\Flagged))");

    expect(seenStateOf(untagged, 11)).toBe(true);
  });

  it("is false when the list holds other flags but not the seen flag", async () => {
    const untagged = await untaggedFrom("* 4 FETCH (UID 11 FLAGS (\\Flagged \\Answered))");

    expect(seenStateOf(untagged, 11)).toBe(false);
  });
});

// ===========================================================================
// The move path's parsers (Phase 21)
// ===========================================================================

/**
 * The destination's validity in every COPYUID row below.
 *
 * Different from every source validity in this file, and from the source UID,
 * so a parser that read the fields in the wrong order cannot pass (RFC 4315 §3
 * puts the DESTINATION's validity first; PITFALLS #35).
 */
const COPY_DESTINATION_VALIDITY = 1_700_000_001;

describe("parseCopyUid", () => {
  it("reads the destination's validity first, then the source set, then the destination set", () => {
    expect(parseCopyUid(`a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} 4242 91] Done`)).toEqual({
      uidValidity: COPY_DESTINATION_VALIDITY,
      source: [4242],
      destination: [91],
    });
  });

  it.each<[string, string, { uidValidity: number; source: number[]; destination: number[] }]>([
    ["a range written high to low equals low to high", "4:2 91:93", { uidValidity: COPY_DESTINATION_VALIDITY, source: [2, 3, 4], destination: [91, 92, 93] }],
    ["a range written low to high", "2:4 91:93", { uidValidity: COPY_DESTINATION_VALIDITY, source: [2, 3, 4], destination: [91, 92, 93] }],
    ["a list with a range expands in order", "1,3:4 91,92,93", { uidValidity: COPY_DESTINATION_VALIDITY, source: [1, 3, 4], destination: [91, 92, 93] }],
    ["exactly 100 UIDs", "1:100 201:300", { uidValidity: COPY_DESTINATION_VALIDITY, source: Array.from({ length: 100 }, (_u, i) => i + 1), destination: Array.from({ length: 100 }, (_u, i) => i + 201) }],
  ])("%s", (_label, sets, expected) => {
    expect(parseCopyUid(`a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} ${sets}] Done`)).toEqual(expected);
  });

  it.each<[string, string]>([
    ["unequal set lengths", `a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} 4242,4243 91] Done`],
    ["more than 100 UIDs", `a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} 1:101 201:301] Done`],
    ["a zero source UID", `a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} 0 91] Done`],
    ["a zero destination UID", `a6 OK [COPYUID ${COPY_DESTINATION_VALIDITY} 4242 0] Done`],
    ["a zero validity", "a6 OK [COPYUID 0 4242 91] Done"],
    ["a NO line", `a6 NO [COPYUID ${COPY_DESTINATION_VALIDITY} 4242 91] Done`],
    ["an untagged line", `* OK [COPYUID ${COPY_DESTINATION_VALIDITY} 4242 91] Done`],
    ["another code", `a6 OK [APPENDUID ${COPY_DESTINATION_VALIDITY} 91] Done`],
    ["the code later in the text", `a6 OK Done [COPYUID ${COPY_DESTINATION_VALIDITY} 4242 91]`],
  ])("%s is null", (_label, text) => {
    expect(parseCopyUid(text)).toBeNull();
  });
});

describe("parseModifiedUids", () => {
  it.each<[string, string, number[] | null]>([
    ["on OK", "a7 OK [MODIFIED 4242] Conditional STORE failed", [4242]],
    ["on NO", "a7 NO [MODIFIED 4242] Conditional STORE failed", [4242]],
    ["a range and a list", "a7 OK [MODIFIED 7,9:11] Conditional STORE failed", [7, 9, 10, 11]],
    ["absent", "a7 OK STORE completed", null],
    ["absent on NO", "a7 NO STORE failed", null],
  ])("%s", (_label, text, expected) => {
    expect(parseModifiedUids(text)).toEqual(expected);
  });
});

describe("parseFingerprint", () => {
  const DATE = '"13-Aug-2026 09:14:02 -0700"';
  const SECONDS = Date.UTC(2026, 7, 13, 16, 14, 2) / 1000;

  function reply(seq: number, uid: number, size: string, date: string, modSeq: string | null): string {
    const modSeqItem = modSeq === null ? "" : ` MODSEQ (${modSeq})`;
    return `* ${seq} FETCH (UID ${uid} FLAGS (\\Seen) RFC822.SIZE ${size} INTERNALDATE ${date}${modSeqItem})`;
  }

  it("finds the reply whose own UID matches, among several", async () => {
    const untagged = await untaggedFrom(
      reply(1, 4241, "10", DATE, "1"),
      reply(2, 4242, "18431", DATE, "742"),
      reply(3, 4243, "30", DATE, "3"),
    );

    expect(parseFingerprint(untagged, 4242)).toEqual({
      uid: 4242,
      flags: ["\\Seen"],
      size: 18_431,
      internalDate: SECONDS,
      modSeq: "742",
    });
  });

  it("takes the last of two replies for one UID", async () => {
    const untagged = await untaggedFrom(
      reply(2, 4242, "18431", DATE, "742"),
      reply(2, 4242, "18431", DATE, "743"),
    );

    expect(parseFingerprint(untagged, 4242)?.modSeq).toBe("743");
  });

  it("ignores the sequence number", async () => {
    // Sequence number 4242 names a different message; only the UID item counts.
    const untagged = await untaggedFrom(reply(4242, 7, "10", DATE, "1"));

    expect(parseFingerprint(untagged, 4242)).toBeNull();
    expect(parseFingerprint(untagged, 7)?.uid).toBe(7);
  });

  it.each<[string, string | null]>([
    ["no MODSEQ", null],
    ["a MODSEQ of 0", "0"],
    ["a MODSEQ with a leading zero", "07"],
    ["a 20-digit MODSEQ", "12345678901234567890"],
  ])("%s is null", async (_label, modSeq) => {
    const untagged = await untaggedFrom(reply(1, 4242, "18431", DATE, modSeq));

    expect(parseFingerprint(untagged, 4242)).toBeNull();
  });

  it("keeps a 19-digit MODSEQ exactly, as digits", async () => {
    const untagged = await untaggedFrom(reply(1, 4242, "18431", DATE, "9223372036854775807"));

    expect(parseFingerprint(untagged, 4242)?.modSeq).toBe("9223372036854775807");
  });

  it("reads a day padded with a space", async () => {
    const untagged = await untaggedFrom(reply(1, 4242, "18431", '" 3-Aug-2026 09:14:02 -0700"', "742"));

    expect(parseFingerprint(untagged, 4242)?.internalDate).toBe(
      Date.UTC(2026, 7, 3, 16, 14, 2) / 1000,
    );
  });

  it.each<[string, string, string]>([
    ["a day that does not exist", "18431", '"31-Feb-2026 09:14:02 -0700"'],
    ["an unknown month", "18431", '"13-Foo-2026 09:14:02 -0700"'],
    ["a size above the wire bound", "4294967296", DATE],
  ])("%s is null", async (_label, size, date) => {
    const untagged = await untaggedFrom(reply(1, 4242, size, date, "742"));

    expect(parseFingerprint(untagged, 4242)).toBeNull();
  });
});


describe("keepsFlag (D-08)", () => {
  const FLAGS = ["\\Seen", "\\Flagged", "\\Deleted"] as const;

  it("is true for every flag when the open sent no list (RFC 3501 §6.3.1)", () => {
    for (const flag of FLAGS) expect(keepsFlag(null, flag), flag).toBe(true);
  });

  it("is false for every flag on an empty list", () => {
    for (const flag of FLAGS) expect(keepsFlag([], flag), flag).toBe(false);
  });

  it.each(FLAGS)("finds %s when present, in any case, and not when absent", (flag) => {
    const others = FLAGS.filter((one) => one !== flag);
    expect(keepsFlag([flag], flag)).toBe(true);
    expect(keepsFlag(["\\Answered", flag.toUpperCase()], flag)).toBe(true);
    expect(keepsFlag([flag.toLowerCase()], flag)).toBe(true);
    expect(keepsFlag(others, flag)).toBe(false);
  });

  it.each(FLAGS)("does not count \\* alone for %s: it is about keywords", (flag) => {
    expect(keepsFlag(["\\*"], flag)).toBe(false);
  });
});

describe("flagStateOf", () => {
  it("finds the reply whose own UID matches, among several", async () => {
    const untagged = await untaggedFrom(
      "* 3 FETCH (UID 10 FLAGS (\\Seen))",
      "* 4 FETCH (UID 11 FLAGS (\\Flagged))",
      "* 5 FETCH (UID 12 FLAGS ())",
    );

    expect(flagStateOf(untagged, 11, "\\Flagged")).toBe(true);
    expect(flagStateOf(untagged, 10, "\\Flagged")).toBe(false);
    expect(flagStateOf(untagged, 12, "\\Flagged")).toBe(false);
    expect(flagStateOf(untagged, 10, "\\Seen")).toBe(true);
  });

  it("lets the last reply for the UID win", async () => {
    const flaggedLast = await untaggedFrom(
      "* 4 FETCH (UID 11 FLAGS ())",
      "* 4 FETCH (UID 11 FLAGS (\\flagged))",
    );
    const clearedLast = await untaggedFrom(
      "* 4 FETCH (UID 11 FLAGS (\\Flagged))",
      "* 4 FETCH (UID 11 FLAGS ())",
    );

    expect(flagStateOf(flaggedLast, 11, "\\Flagged")).toBe(true);
    expect(flagStateOf(clearedLast, 11, "\\Flagged")).toBe(false);
  });

  it("keys on the UID item, never on the sequence-number prefix", async () => {
    const untagged = await untaggedFrom("* 11 FETCH (UID 40 FLAGS (\\Flagged))");

    expect(flagStateOf(untagged, 11, "\\Flagged")).toBeNull();
    expect(flagStateOf(untagged, 40, "\\Flagged")).toBe(true);
  });

  it("is null when no reply for the UID carries a flag list", async () => {
    const untagged = await untaggedFrom("* 4 FETCH (UID 11 RFC822.SIZE 100)");

    expect(flagStateOf(untagged, 11, "\\Flagged")).toBeNull();
    expect(flagStateOf([], 11, "\\Flagged")).toBeNull();
  });

  it("does not read the other flag as this one", async () => {
    const untagged = await untaggedFrom("* 4 FETCH (UID 11 FLAGS (\\Seen))");

    expect(flagStateOf(untagged, 11, "\\Flagged")).toBe(false);
    expect(flagStateOf(untagged, 11, "\\Seen")).toBe(true);
  });
});
