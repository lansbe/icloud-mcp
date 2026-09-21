// The whole mail session, driven end to end with no socket.
//
// This is the tracer's own proof: a full IMAP conversation — greeting,
// capability, login, capability, read-only mailbox open, one UID fetch whose
// reply carries a literal body, logout — against an in-memory duplex, asserting
// the decoded body, the sender, the subject, the unread flag and the attachment
// list that come back out the other end.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID. The bytes below are CONSTRUCTED rather than captured, in the
// same spirit as `./fixtures/icloud-bytes.ts`: what they pin is the SHAPE of the
// exchange, and none of the assertions depends on a token only Apple could
// have produced.

import { beforeAll, describe, expect, it } from "vitest";
import {
  ImapAuthError,
  ImapConnectError,
  ImapNotFoundError,
  ImapThrottleError,
} from "../src/errors";
import {
  decodeCursor,
  decodeFolderId,
  encodeCursor,
  encodeMessageId,
} from "../src/mail/ids";
import {
  SNIPPET_FETCH_OCTETS,
  SNIPPET_HTML_FETCH_OCTETS,
  SNIPPET_MAX_CHARS,
} from "../src/mail/mime";
import type {
  FolderListing,
  FolderSummary,
  MailSessionOptions,
  SearchCriteria,
} from "../src/mail/service";
import {
  MAX_WIRE_MESSAGE_BYTES,
  PAGE_SIZE_DEFAULT,
  PAGE_SIZE_MAX,
  createSessionGate,
  getMessageOver,
  listFoldersOver,
  listMessagesOver,
  listUnreadOver,
  searchMessagesOver,
  withMailSessionOver,
} from "../src/mail/service";
import {
  AUTH_REJECTED_LEGACY_TEXT,
  AUTH_REJECTED_TEXT,
  CONNECTION_LIMIT_TEXT,
  GREETING,
  MUTF7_DISPLAY_NAME,
  MUTF7_WIRE_NAME,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  base64Bytes,
  capabilityResponse,
  logoutExchange,
  taggedBad,
  taggedNo,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import {
  createFakeDuplex,
  createStallingDuplex,
} from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();

/** The mailbox and validity every fixture below agrees on. */
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;
const UID = 4827;

/**
 * Bounds a few milliseconds wide, so no case here waits out a real timeout.
 *
 * D-51's whole point: the suite was spending ~20 s of wall time genuinely
 * waiting on production bounds. These stay discriminating — an implementation
 * that never returned would still hang the runner — at roughly 1% of the cost.
 */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/**
 * A message with a plain text part and one base64 attachment.
 *
 * CRLF throughout, because that is what arrives on the wire and because a
 * fixture using bare LF would quietly stop exercising the reassembly the reader
 * does across physical lines.
 */
const MESSAGE_SUBJECT = "Re: your interview on Thursday";
const MESSAGE_FROM_NAME = "Doe, Jane";
const MESSAGE_FROM_ADDRESS = "jane.doe@example.invalid";
const ATTACHMENT_FILENAME = "offer.pdf";

/** The attachment's base64 body, as the part carries it. */
const ATTACHMENT_BASE64 = "SGVsbG8sIFBERiE=";

/**
 * The decoded size, DERIVED from the body above rather than written beside it.
 *
 * It was a hand-written `11` with the base64 transcribed separately — the same
 * pair that invalidates itself the moment anyone edits one half, and in the
 * direction of a green suite. Deriving it is what plan 02-09 applied to
 * `icloud-bytes.ts`; this is the same hazard one file over.
 */
const ATTACHMENT_DECODED_BYTES = base64Bytes(ATTACHMENT_BASE64).byteLength;

const RAW_MESSAGE = [
  `From: "${MESSAGE_FROM_NAME}" <${MESSAGE_FROM_ADDRESS}>`,
  "To: russell@example.invalid",
  `Subject: ${MESSAGE_SUBJECT}`,
  "Date: Thu, 13 Aug 2026 09:14:02 -0700",
  "Message-ID: <a1b2c3@example.invalid>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="Apple-Mail-A1"',
  "",
  "--Apple-Mail-A1",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hi — following up on our conversation.",
  "",
  "Second paragraph, so the body is genuinely multi-line.",
  "",
  "--Apple-Mail-A1",
  "Content-Type: application/pdf",
  `Content-Disposition: attachment; filename="${ATTACHMENT_FILENAME}"`,
  "Content-Transfer-Encoding: base64",
  "",
  ATTACHMENT_BASE64,
  "",
  "--Apple-Mail-A1--",
  "",
].join("\r\n");

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
 * `RAW_MESSAGE`'s body structure, as the server would describe it.
 *
 * The field layout is the ABNF's, not a guess: a `TEXT` part carries
 * `body-fld-lines` after the octet count so its extension region opens one slot
 * later than a basic part's, and `body-fld-md5` (the `NIL` before the
 * disposition) is the slot a fixed-offset disposition reader gets wrong.
 *
 * The attachment's declared octet count is DERIVED from the base64 body the
 * message actually carries, so the structure and the message cannot drift into
 * describing different files — the same discipline plan 02-09 applied to
 * `icloud-bytes.ts`.
 */
const MIXED_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${ATTACHMENT_FILENAME}") NIL NIL "BASE64" ` +
  `${ATTACHMENT_BASE64.length} NIL ` +
  `("attachment" ("FILENAME" "${ATTACHMENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** A structure whose attachment names a DIFFERENT file than the message does. */
const DISAGREEING_STRUCTURE = MIXED_STRUCTURE.split(ATTACHMENT_FILENAME).join(
  "something-else.pdf",
);

/**
 * A structure whose attachment declares FEWER octets than the message carries.
 *
 * The direction that framing overhead cannot explain. `body-fld-octets` counts
 * the ENCODED bytes, so the structure-derived size is always an over-estimate
 * of the decoded length — a structure claiming LESS than the parse decoded is
 * one of the two derivations being wrong, at any magnitude.
 */
const UNDERSIZED_STRUCTURE = MIXED_STRUCTURE.replace(
  `"BASE64" ${ATTACHMENT_BASE64.length} NIL`,
  '"BASE64" 4 NIL',
);

/** A single-part text message: no attachment, one selectable body part. */
const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

/**
 * A message whose ONLY readable part is HTML — no plain alternative at all.
 *
 * The commonest shape marketing mail arrives in, and the one `selectTextPart`
 * has no choice about: there is nothing to prefer, so the resolved part is the
 * HTML one and a conversion is owed on it (G-02-3a).
 */
const HTML_ONLY_STRUCTURE = '("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 900 20)';

/** A structure with no text part at all — one image, nothing readable. */
const NO_TEXT_STRUCTURE =
  '(("IMAGE" "PNG" ("NAME" "shot.png") NIL NIL "BASE64" 400 NIL ' +
  '("attachment" ("FILENAME" "shot.png")) NIL)' +
  ' "MIXED" ("BOUNDARY" "b") NIL NIL)';

/**
 * Round trip ONE: the structure-and-size reply.
 *
 * No literal anywhere in it, which is the point of splitting the fetch — this
 * command's reply is a few hundred bytes whatever the message weighs, and it is
 * what the size branch below decides on.
 */
function structureReply(
  tag: string,
  options: {
    flags?: string;
    structure?: string;
    wireSize?: number;
    status?: string;
  } = {},
): Uint8Array {
  const size = options.wireSize ?? ENCODER.encode(RAW_MESSAGE).byteLength;
  return wire(
    `* 1 FETCH (UID ${UID} FLAGS (${options.flags ?? ""}) ` +
      `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
      `RFC822.SIZE ${size} BODYSTRUCTURE ${options.structure ?? MIXED_STRUCTURE})`,
    `${tag} ${options.status ?? "OK"} UID FETCH completed`,
  );
}

/**
 * Round trip TWO, common path: the whole message as one literal.
 *
 * The declared octet count is DERIVED from the payload's byte length rather
 * than written by hand. A hand-written count invalidates itself the moment
 * anyone edits the payload, and a fixture with a wrong count teaches the parser
 * the wrong framing — which is worse than having no fixture at all.
 *
 * Note where the CRLFs are and are not: there is none between the last literal
 * octet and the `)` that follows it, because that `)` continues the SAME
 * logical line the `* 1 FETCH (` opened.
 */
function contentReply(
  tag: string,
  options: { raw?: string } = {},
): Uint8Array {
  const payload = ENCODER.encode(options.raw ?? RAW_MESSAGE);
  const head = `* 1 FETCH (UID ${UID} BODY[] {${payload.byteLength}}\r\n`;

  return concatBytes(
    ENCODER.encode(head),
    payload,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** One `key {n}\r\n<payload>` pair, count derived from the payload. */
function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(
    ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`),
    bytes,
  );
}

/**
 * The body the ceiling path returns, with a quoted reply block inside it.
 *
 * Two levels of quoting, deliberately. D-36 keeps quoted history VERBATIM, and
 * every stripping heuristic anyone might later add reaches for exactly this
 * shape first.
 */
const QUOTED_HISTORY = [
  "Thanks — Thursday works.",
  "",
  "> On 12 Aug 2026, at 08:00, Someone wrote:",
  "> Are you free Thursday?",
  "> ",
  ">> and the layer beneath that one",
].join("\r\n");

/**
 * Round trip TWO, ceiling path: message headers, the part's own MIME headers,
 * and that part's body — three literals in ONE untagged reply.
 *
 * Three literals on one logical line is a framing shape nothing else in this
 * suite exercises, and it is the shape the over-ceiling branch depends on.
 */
function partScopedReply(
  tag: string,
  path: string,
  options: { headers?: string; mime?: string; body?: string } = {},
): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} `),
    literalItem(
      "BODY[HEADER]",
      options.headers ??
        [
          `From: "${MESSAGE_FROM_NAME}" <${MESSAGE_FROM_ADDRESS}>`,
          `Subject: ${MESSAGE_SUBJECT}`,
          "Date: Thu, 13 Aug 2026 09:14:02 -0700",
          "MIME-Version: 1.0",
          'Content-Type: multipart/mixed; boundary="Apple-Mail-A1"',
          "",
          "",
        ].join("\r\n"),
    ),
    ENCODER.encode(" "),
    literalItem(
      `BODY[${path}.MIME]`,
      options.mime ?? "Content-Type: text/plain; charset=utf-8\r\n",
    ),
    ENCODER.encode(" "),
    literalItem(`BODY[${path}]`, options.body ?? QUOTED_HISTORY),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The ceiling path's reply when the message has no readable part to ask for. */
function headerOnlyReply(tag: string, headers: string): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} `),
    literalItem("BODY[HEADER]", headers),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The untagged set `EXAMINE` returns, then its read-only completion. */
function examineReply(
  tag: string,
  options: { uidValidity?: number | null; exists?: number } = {},
): Uint8Array {
  const validity = options.uidValidity === undefined ? UIDVALIDITY : options.uidValidity;
  const lines = [
    `* ${options.exists ?? 172} EXISTS`,
    "* 0 RECENT",
    "* OK [UNSEEN 12] Message 12 is first unseen",
    ...(validity === null ? [] : [`* OK [UIDVALIDITY ${validity}] UIDs valid`]),
    "* OK [UIDNEXT 4392] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

/**
 * The full happy-path conversation, tags a1 through a7.
 *
 * SEVEN tags rather than six, and the extra one is this plan's whole subject: a
 * fetch is two round trips now — `a5` asks what the message IS, `a6` asks for
 * as much of it as the size warrants.
 */
function happyPathDuplex(
  fetchOptions: { flags?: string; raw?: string; structure?: string } = {},
): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineReply("a4"),
    structureReply("a5", {
      flags: fetchOptions.flags,
      structure: fetchOptions.structure,
      wireSize: fetchOptions.raw
        ? ENCODER.encode(fetchOptions.raw).byteLength
        : undefined,
    }),
    contentReply("a6", { raw: fetchOptions.raw }),
    logoutExchange("a7"),
  ]);
}

/**
 * A conversation whose message declares itself ABOVE the wire ceiling.
 *
 * The declared size is the ceiling plus one byte, expressed against the
 * exported constant rather than as a literal — a fixture carrying its own copy
 * of a safety number stops testing the branch the moment the constant moves.
 */
function overCeilingDuplex(
  options: {
    structure?: string;
    path?: string;
    /** A tagged BAD on the content command: the server refused the ITEM. */
    refuseParts?: boolean;
    /** A tagged NO on the content command: the server refused the MESSAGE. */
    refuseMessage?: boolean;
    body?: string;
  } = {},
): FakeDuplex {
  const content = options.refuseMessage
    ? [taggedNo("a6", "no such message")]
    : options.refuseParts
      ? [taggedBad("a6", "Invalid section specifier"), contentReply("a7")]
      : [partScopedReply("a6", options.path ?? "1", { body: options.body })];

  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineReply("a4"),
    structureReply("a5", {
      structure: options.structure,
      wireSize: MAX_WIRE_MESSAGE_BYTES + 1,
    }),
    ...content,
    logoutExchange(options.refuseParts ? "a8" : "a7"),
  ]);
}

/** Which tag the logout carries, given how many content commands ran. */
function logoutTagOf(duplex: FakeDuplex): string {
  return duplex.writtenLines().at(-1) ?? "";
}

/**
 * The IMAP verb of each written line, keeping `UID FETCH` whole.
 *
 * `commandWords` in `./imap-session.test.ts` takes only the second token, which
 * would render every UID command as the bare word `UID` — losing exactly the
 * distinction this file's ordering assertion is about.
 */
function commandVerbs(lines: string[]): string[] {
  return lines.map((line) => {
    const parts = line.split(" ");
    return parts[1] === "UID" ? `${parts[1]} ${parts[2]}` : (parts[1] ?? "");
  });
}

const REF = { mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: UID };

describe("mail_get_message, end to end over a full conversation", () => {
  it("returns the decoded body, sender, subject and attachments", async () => {
    const duplex = happyPathDuplex();

    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.subject).toBe(MESSAGE_SUBJECT);
    expect(detail.fromName).toBe(MESSAGE_FROM_NAME);
    expect(detail.fromAddress).toBe(MESSAGE_FROM_ADDRESS);
    expect(detail.text).toContain("following up on our conversation");
    expect(detail.text).toContain("Second paragraph");
    expect(detail.bodySource).toBe("text/plain");
    expect(detail.truncated).toBe(false);
    expect(detail.uid).toBe(UID);
    expect(detail.id).toBe(encodeMessageId(REF));
  });

  it("reports the attachment's DECODED size, not its transfer-encoded octets", async () => {
    // `SGVsbG8sIFBERiE=` is 16 transfer-encoded characters and 11 real bytes.
    // Reporting the wire count would tell a user something false about their
    // own file, and the two numbers are close enough that a wrong one looks
    // plausible.
    //
    // The figure now comes from the STRUCTURE fetch rather than from the parsed
    // attachment, which is what makes ATT-01's "without downloading it" true —
    // and it is why the assertion is a bounded range rather than an equality:
    // `body-fld-octets` counts the CRLFs MIME wraps a base64 body in, so the
    // structure-derived size sits a few bytes above the decoded length.
    const duplex = happyPathDuplex();

    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachments).toHaveLength(1);
    expect(detail.attachments[0]!.filename).toBe(ATTACHMENT_FILENAME);
    expect(detail.attachments[0]!.mimeType).toBe("application/pdf");
    expect(detail.attachments[0]!.sizeBytes).toBeGreaterThanOrEqual(
      ATTACHMENT_DECODED_BYTES,
    );
    expect(detail.attachments[0]!.sizeBytes).toBeLessThan(
      ATTACHMENT_BASE64.length,
    );
  });

  it("returns an empty attachment list rather than null when there are none", async () => {
    const plain = [
      `From: ${MESSAGE_FROM_ADDRESS}`,
      "Subject: no attachments here",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Just a body.",
      "",
    ].join("\r\n");

    const detail = await getMessageOver(
      happyPathDuplex({ raw: plain, structure: PLAIN_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachments).toEqual([]);
  });

  it("derives the unread flag from the flag list", async () => {
    const unread = await getMessageOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );
    const read = await getMessageOver(
      happyPathDuplex({ flags: "\\Seen" }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(unread.unread).toBe(true);
    expect(read.unread).toBe(false);
  });

  it("keeps the server's internal date apart from the sender's own header", async () => {
    // Only one of these two is a fact this server can vouch for, which is why
    // they travel in different halves of the tool response.
    const detail = await getMessageOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.internalDate).toBe("13-Aug-2026 09:14:02 -0700");
    expect(detail.date).not.toBe(detail.internalDate);
  });
});

describe("the commands actually written to the wire", () => {
  it("issues them in order, with distinct tags", async () => {
    const duplex = happyPathDuplex();

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    const lines = duplex.writtenLines();
    // An ordered comparison, not a set of `toContain` calls: a reader that
    // fetched before opening the mailbox, or opened it twice, would satisfy
    // every containment check and none of this one.
    expect(commandVerbs(lines)).toEqual([
      "CAPABILITY",
      "LOGIN",
      "CAPABILITY",
      "EXAMINE",
      "UID FETCH",
      "UID FETCH",
      "LOGOUT",
    ]);
    const tags = lines.map((line) => line.split(" ")[0]);
    expect(tags).toEqual(["a1", "a2", "a3", "a4", "a5", "a6", "a7"]);
  });

  it("opens the mailbox read-only and peeks at every body it fetches", async () => {
    // Two independent mechanisms for one property (D-47). EXAMINE makes \Seen
    // mutation refusable by Apple's server for the whole session; BODY.PEEK is
    // the call-site half. Losing either should fail here.
    const duplex = happyPathDuplex();

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    const lines = duplex.writtenLines();
    expect(lines.some((line) => line.includes("EXAMINE"))).toBe(true);
    expect(lines.some((line) => line.includes("SELECT"))).toBe(false);

    // Every fetch that asks for content asks for it the peeking way. The
    // structure command asks for no content at all, which is why it is checked
    // for the ABSENCE of a body item rather than for the peeking spelling.
    const fetches = lines.filter((line) => line.includes("FETCH"));
    expect(fetches).toHaveLength(2);
    for (const line of fetches) {
      expect(/BODY(?!\.PEEK)\[/.test(line)).toBe(false);
      expect(/\bRFC822(?!\.SIZE)\b/.test(line)).toBe(false);
    }
  });

  it("writes exactly TWO fetch commands, in the order structure-then-content", async () => {
    // The ordered comparison is the substance. An implementation that asked
    // for the content first and the structure afterwards would satisfy every
    // containment check here and none of this one — and it would have decided
    // how much to pull before it knew how much there was.
    const duplex = happyPathDuplex();

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    expect(fetches).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
      `a6 UID FETCH ${UID} BODY.PEEK[]`,
    ]);
  });

  it("asks a DIFFERENT second command above the ceiling, compared line for line", async () => {
    // Two whole command lines, each compared against its expected string.
    // `toContain("BODY.PEEK")` would pass against both branches at once, which
    // is precisely the distinction this case exists to make.
    const under = happyPathDuplex();
    const over = overCeilingDuplex();

    await getMessageOver(under, principal, createSessionGate(), REF, FAST_BOUNDS);
    await getMessageOver(over, principal, createSessionGate(), REF, FAST_BOUNDS);

    expect(under.writtenLines()[5]).toBe(`a6 UID FETCH ${UID} BODY.PEEK[]`);
    expect(over.writtenLines()[5]).toBe(
      `a6 UID FETCH ${UID} ` +
        "(BODY.PEEK[HEADER] BODY.PEEK[1.MIME] BODY.PEEK[1])",
    );
  });

  it("quotes the mailbox name it opens", async () => {
    const duplex = happyPathDuplex();

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    expect(duplex.writtenLines()[3]).toBe(`a4 EXAMINE "${MAILBOX}"`);
  });

  it("tears down in a finally, even when the fetch itself fails", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineReply("a4"),
      taggedNo("a5", "no such message"),
      logoutExchange("a6"),
    ]);

    await expect(
      getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toContain("a6 LOGOUT");
    expect(duplex.firstIndexOf("close")).toBeGreaterThan(
      duplex.firstIndexOf("readable-done"),
    );
  });
});

describe("the wire-size ceiling truncates, and never raises (D-35, T-02-06)", () => {
  it("returns a SUCCESSFUL result with the truncation flag set", async () => {
    // The whole point of the branch. An oversized message degrades to a
    // partial answer, not to a failure — the four-value error vocabulary was
    // closed deliberately and phases 3 through 6 all inherit it.
    const detail = await getMessageOver(
      overCeilingDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.truncated).toBe(true);
    expect(detail.fetchPath).toBe("part-scoped");
    expect(detail.text).toContain("Thursday works");
  });

  it("still lists the attachment, because the structure said so and no bytes were pulled", async () => {
    // ATT-01 exactly as written: the metadata comes from the structure fetch,
    // so it survives a branch that deliberately fetches no attachment content.
    const detail = await getMessageOver(
      overCeilingDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachments).toHaveLength(1);
    expect(detail.attachments[0]!.filename).toBe(ATTACHMENT_FILENAME);
    expect(detail.attachments[0]!.mimeType).toBe("application/pdf");
  });

  it("keeps the quoted reply history verbatim (D-36)", async () => {
    // No heuristic stripping, and this is the shape every stripping heuristic
    // reaches for first. Compared against the whole fixture payload rather than
    // by `toContain`, so a rule that dropped only the deepest layer fails.
    const detail = await getMessageOver(
      overCeilingDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    const normalise = (text: string) => text.replace(/\r\n/g, "\n").trimEnd();
    expect(normalise(detail.text)).toBe(normalise(QUOTED_HISTORY));
  });

  it("falls back to the whole message when the server refuses the part item", async () => {
    // Assumption A5: whether this server accepts a part-scoped MIME-headers
    // specifier is unverified, and a scripted fixture cannot settle it. What it
    // CAN pin is that a refusal degrades rather than fails, and that the answer
    // is recorded for the first real run to read.
    const duplex = overCeilingDuplex({ refuseParts: true });

    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.fetchPath).toBe("part-scoped-refused");
    expect(detail.truncated).toBe(true);
    expect(detail.text).toContain("following up on our conversation");
    expect(
      duplex.writtenLines().filter((line) => line.includes("FETCH")),
    ).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
      `a6 UID FETCH ${UID} (BODY.PEEK[HEADER] BODY.PEEK[1.MIME] BODY.PEEK[1])`,
      `a7 UID FETCH ${UID} BODY.PEEK[]`,
    ]);
  });

  it("does NOT fall back on a tagged NO, which is about the message not the syntax", async () => {
    // The same distinction `listAllFolders` draws, and it needs its own case
    // here: BAD means the request was malformed, so asking a simpler question
    // may work. NO means the server understood the request and refused it —
    // retrying the whole message would spend a command on an answer already
    // given, and would pull megabytes to be told the same thing again.
    const duplex = overCeilingDuplex({ refuseMessage: true });

    await expect(
      getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(
      duplex.writtenLines().filter((line) => line.includes("FETCH")),
    ).toHaveLength(2);
    expect(logoutTagOf(duplex)).toBe("a7 LOGOUT");
  });

  it("asks only for the headers when the structure offers no readable part", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineReply("a4"),
      structureReply("a5", {
        structure: NO_TEXT_STRUCTURE,
        wireSize: MAX_WIRE_MESSAGE_BYTES + 1,
      }),
      headerOnlyReply("a6", "Subject: just a picture\r\n\r\n"),
      logoutExchange("a7"),
    ]);

    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(duplex.writtenLines()[5]).toBe(
      `a6 UID FETCH ${UID} (BODY.PEEK[HEADER])`,
    );
    expect(detail.text).toBe("");
    expect(detail.bodySource).toBeNull();
  });

  it("does not fire on an ordinary message, which is what makes D-34 true in practice", async () => {
    const detail = await getMessageOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.truncated).toBe(false);
    expect(detail.fetchPath).toBe("whole-message");
  });
});

describe("a message with neither a text part nor an HTML part", () => {
  it("yields an empty body and a NULL body source, not an error", async () => {
    // An outcome, not a failure. A message that is nothing but an attachment
    // has no body, and reporting that as `not_found` would make "nothing to
    // read" indistinguishable from "the message is gone".
    const attachmentOnly = [
      `From: ${MESSAGE_FROM_ADDRESS}`,
      "Subject: just a picture",
      "MIME-Version: 1.0",
      'Content-Type: image/png; name="shot.png"',
      'Content-Disposition: attachment; filename="shot.png"',
      "Content-Transfer-Encoding: base64",
      "",
      "iVBORw0KGgo=",
      "",
    ].join("\r\n");

    const detail = await getMessageOver(
      happyPathDuplex({ raw: attachmentOnly, structure: NO_TEXT_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.text).toBe("");
    expect(detail.bodySource).toBeNull();
    expect(detail.truncated).toBe(false);
  });
});

describe("the raw-HTML option (D-33)", () => {
  /** `multipart/alternative`: a plain part and an HTML one. */
  const ALTERNATIVE_STRUCTURE =
    '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 20 1 NIL NIL NIL)' +
    '("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 60 2 NIL NIL NIL)' +
    ' "ALTERNATIVE" ("BOUNDARY" "alt-1") NIL NIL)';

  /** A single HTML part and nothing else — ordinary correspondence, not exotic. */
  const HTML_ONLY_STRUCTURE =
    '("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 60 2)';

  const HTML_ONLY = [
    `From: ${MESSAGE_FROM_ADDRESS}`,
    "Subject: html only",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<html><body><p>First paragraph.</p><p>Second paragraph.</p></body></html>",
    "",
  ].join("\r\n");

  const BOTH_PARTS = [
    `From: ${MESSAGE_FROM_ADDRESS}`,
    "Subject: both parts",
    "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt-1"',
    "",
    "--alt-1",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "The plain half.",
    "",
    "--alt-1",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<html><body><p>The markup half.</p></body></html>",
    "",
    "--alt-1--",
    "",
  ].join("\r\n");

  /**
   * The shape G-02-3b was confirmed on: a `multipart/alternative` whose plain
   * half is a placeholder and whose HTML half carries the message.
   *
   * The plain child declares two octets, because that is what it holds — the
   * lone CRLF a sender emits when they fill the alternative's plain slot with
   * nothing. A 239 KB Costco email and a BECU notice both arrived this way.
   */
  const BLANK_PLAIN_STRUCTURE =
    '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 2 1 NIL NIL NIL)' +
    '("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 120 3 NIL NIL NIL)' +
    ' "ALTERNATIVE" ("BOUNDARY" "alt-2") NIL NIL)';

  /**
   * The message those two real ones decode like.
   *
   * The plain part's body is exactly one CRLF: the blank line after its headers
   * ENDS the headers, the next one is the body, and the last belongs to the
   * boundary delimiter. A `length > 0` test reports a body here.
   */
  const BLANK_PLAIN_ALTERNATIVE = [
    `From: ${MESSAGE_FROM_ADDRESS}`,
    "Subject: blank plain half",
    "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="alt-2"',
    "",
    "--alt-2",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "",
    "",
    "--alt-2",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<html><body><p>Your membership renews in October.</p>",
    "<p>No action is needed today.</p></body></html>",
    "",
    "--alt-2--",
    "",
  ].join("\r\n");

  it("falls through to the HTML alternative when the plain part is only whitespace", async () => {
    // The generalized intent, asserted where a future presence test would break
    // it: the body comes from the part that carries readable CONTENT, not from
    // the part whose media type appears first in the structure.
    const detail = await getMessageOver(
      happyPathDuplex({
        raw: BLANK_PLAIN_ALTERNATIVE,
        structure: BLANK_PLAIN_STRUCTURE,
      }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.bodySource).toBe("text/html");
    expect(detail.text).toContain("Your membership renews in October.");
    expect(detail.text).toContain("No action is needed today.");
    // Converted, not handed over raw.
    expect(detail.text).not.toContain("<p>");
    // And emphatically not the newline the plain placeholder held.
    expect(detail.text.trim().length).toBeGreaterThan(0);
  });

  it("returns a NULL raw-HTML field without the flag", async () => {
    const detail = await getMessageOver(
      happyPathDuplex({ raw: HTML_ONLY, structure: HTML_ONLY_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.html).toBeNull();
    // And the readable text is still there — the flag governs the MARKUP, not
    // whether an HTML-only message is readable at all.
    expect(detail.text).toContain("First paragraph.");
  });

  it("returns the raw HTML part WITH the flag", async () => {
    const detail = await getMessageOver(
      happyPathDuplex({ raw: HTML_ONLY, structure: HTML_ONLY_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      { ...FAST_BOUNDS, includeHtml: true },
    );

    expect(detail.html).toContain("<p>First paragraph.</p>");
  });

  it("converts an HTML-only message to readable text, recording where it came from", async () => {
    const detail = await getMessageOver(
      happyPathDuplex({ raw: HTML_ONLY, structure: HTML_ONLY_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.bodySource).toBe("text/html");
    expect(detail.text).toContain("First paragraph.");
    expect(detail.text).toContain("Second paragraph.");
    // Converted, not handed over raw: no markup survives into the readable half.
    expect(detail.text).not.toContain("<p>");
  });

  it("prefers the PLAIN part when a message carries both", async () => {
    const detail = await getMessageOver(
      happyPathDuplex({ raw: BOTH_PARTS, structure: ALTERNATIVE_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.bodySource).toBe("text/plain");
    expect(detail.text).toContain("The plain half.");
    expect(detail.text).not.toContain("The markup half.");
  });

  it("costs the SAME number of round trips either way", async () => {
    // The flag governs what is REPORTED, not what is asked for. A version that
    // fetched the HTML part with a third command would still return the right
    // markup and would have doubled the cost of a common call.
    const without = happyPathDuplex({ raw: HTML_ONLY, structure: HTML_ONLY_STRUCTURE });
    const with_ = happyPathDuplex({ raw: HTML_ONLY, structure: HTML_ONLY_STRUCTURE });

    await getMessageOver(without, principal, createSessionGate(), REF, FAST_BOUNDS);
    await getMessageOver(with_, principal, createSessionGate(), REF, {
      ...FAST_BOUNDS,
      includeHtml: true,
    });

    expect(commandVerbs(with_.writtenLines())).toEqual(
      commandVerbs(without.writtenLines()),
    );
  });
});

describe("the attachment cross-check (T-02-22)", () => {
  it("agrees when the structure and the parse describe the same file", async () => {
    const detail = await getMessageOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachmentsDisagree).toBe(false);
    expect(detail.attachments[0]!.filename).toBe(ATTACHMENT_FILENAME);
  });

  it("SURFACES a disagreement rather than silently preferring one source", async () => {
    // Two independent derivations of the same facts, by different routes. The
    // two disagreeing says something real about the message — a structure that
    // does not describe the bytes that followed it — and resolving it silently
    // would throw that signal away.
    const detail = await getMessageOver(
      happyPathDuplex({ structure: DISAGREEING_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachmentsDisagree).toBe(true);
    // And the STRUCTURE-derived list is the one returned, because it is the one
    // that exists on both branches.
    expect(detail.attachments[0]!.filename).toBe("something-else.pdf");
  });

  it("calls a size BELOW the decoded length a disagreement, at any magnitude", async () => {
    // What makes the tolerance's DIRECTION half load-bearing rather than
    // decorative. Framing overhead can only ever push the structure-derived
    // figure UP, so a structure claiming less than the parse decoded is not a
    // rounding question — it is one of the two derivations being wrong.
    const detail = await getMessageOver(
      happyPathDuplex({ structure: UNDERSIZED_STRUCTURE }),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachmentsDisagree).toBe(true);
  });

  it("reports no disagreement above the ceiling, where only one derivation ran", async () => {
    // Not a claim that the two agree — a claim that only one of them exists.
    // Reporting `true` there would flag every oversized message as suspicious.
    const detail = await getMessageOver(
      overCeilingDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachmentsDisagree).toBe(false);
  });

  it("tolerates the base64 line-wrapping overhead without calling it a disagreement", async () => {
    // The trap this tolerance exists for: `body-fld-octets` counts the CRLFs
    // MIME wraps a base64 body in, so the structure-derived size is always
    // slightly ABOVE the decoded length. A strict equality here would fire on
    // every real attachment and the flag would become noise.
    const detail = await getMessageOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(detail.attachmentsDisagree).toBe(false);
    expect(detail.attachments[0]!.sizeBytes).toBeGreaterThanOrEqual(
      ATTACHMENT_DECODED_BYTES,
    );
    expect(detail.attachments[0]!.sizeBytes).toBeLessThan(
      ATTACHMENT_BASE64.length,
    );
  });
});

describe("the UIDVALIDITY gate (MAIL-06, T-02-12)", () => {
  it("runs BEFORE any fetch is written, and refuses a mismatch", async () => {
    // The ordering is the substance. A gate that ran after the fetch would
    // still return the right error while having already read a message the
    // caller was not entitled to address.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineReply("a4", { uidValidity: UIDVALIDITY + 1 }),
      logoutExchange("a5"),
    ]);

    await expect(
      getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(
      duplex.writtenLines().some((line) => line.includes("FETCH")),
    ).toBe(false);
  });

  it("refuses an ABSENT validity code identically to a mismatch", async () => {
    // The RFC defines a missing UIDVALIDITY as "the server does not support
    // unique identifiers". iCloud advertises UIDPLUS and will send it in
    // practice — but "will be present in practice" is not a check.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineReply("a4", { uidValidity: null }),
      logoutExchange("a5"),
    ]);

    await expect(
      getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
    expect(
      duplex.writtenLines().some((line) => line.includes("FETCH")),
    ).toBe(false);
  });

  it("carries a validity above 2^31 without corrupting it", async () => {
    // RFC 3501's own worked example exceeds 2^31; a signed-int assumption
    // anywhere on this path turns it negative silently.
    const session = await withMailSessionOver(
      createFakeDuplex([
        GREETING,
        capabilityResponse("a1", PRE_AUTH_CAPABILITY),
        taggedOk("a2", "LOGIN completed"),
        capabilityResponse("a3", POST_AUTH_CAPABILITY),
        examineReply("a4", { uidValidity: 4294967295, exists: 9 }),
        logoutExchange("a5"),
      ]),
      principal,
      createSessionGate(),
      MAILBOX,
      null,
      async (open) => ({ uidValidity: open.uidValidity, exists: open.exists }),
      FAST_BOUNDS,
    );

    expect(session.uidValidity).toBe(4294967295);
    expect(session.exists).toBe(9);
  });

  it("refuses a mailbox name carrying CR or LF rather than escaping around it", async () => {
    // Refuse-don't-repair, applied at the command-construction site. A name
    // with CR or LF terminates the command line early and injects a second
    // command built from the name's own bytes.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      logoutExchange("a4"),
    ]);

    await expect(
      withMailSessionOver(
        duplex,
        principal,
        createSessionGate(),
        "INBOX\r\na9 LOGOUT",
        null,
        async () => "unreachable",
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    // Nothing carrying the name reached the wire. Refusing after writing it
    // would already have injected the second command.
    expect(
      duplex.writtenLines().some((line) => line.includes("EXAMINE")),
    ).toBe(false);
  });
});

// This project carries no Node type package and a Workers isolate has no
// filesystem, so the source is read with Vite's build-time glob, as
// `test/dav-home-containment.test.ts` does. The one suppression is proven
// non-vacuous by `tsc` itself, which errors on one that suppresses nothing.
// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see above.
const SERVICE_SOURCE: Record<string, string> = import.meta.glob(
  "../src/mail/service.ts",
  { query: "?raw", import: "default", eager: true },
);

/** Drop block comments and line comments, so prose cannot count as code. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/**
 * The code of one function, from its `function` keyword up to `marker`.
 *
 * Comments are dropped BEFORE the marker is looked for. A comment that names
 * the marker would otherwise end the span early and hide an await behind it.
 * Null when the function or the marker is not there, so a rename turns the
 * test red rather than letting it pass on an empty span.
 */
function spanAheadOf(
  source: string,
  functionName: string,
  marker: string,
): string | null {
  const start = source.search(new RegExp(`\\bfunction\\s+${functionName}\\b`));
  if (start === -1) return null;
  const code = withoutComments(source.slice(start));
  const end = code.indexOf(marker);
  return end === -1 ? null : code.slice(0, end);
}

/** Whether anything awaits in that span. Null means the span was not found. */
function awaitsAheadOf(
  source: string,
  functionName: string,
  marker: string,
): boolean | null {
  const span = spanAheadOf(source, functionName, marker);
  return span === null ? null : /\bawait\b/.test(span);
}

// What this guards: the socket cap for a legacy batch. Part (c) of the long
// comment in `src/mcp/api-handler.ts` records that two tool calls in one legacy
// JSON-RPC batch share ONE server, so they share one gate and one principal.
// The gate check and the acquire are atomic only because nothing awaits
// between them. An await ahead of the socket open would let both calls pass
// the check, and both would open a socket. Nothing in the suite sends a real
// batch, so this text guard and the shared-gate test below are what hold it.
// The principal is awaited in the tool callback for exactly this reason
// (Phase 9 D-27).
describe("nothing awaits ahead of the gate", () => {
  const source = Object.values(SERVICE_SOURCE)[0] ?? "";

  it("loaded the real source, not an empty string", () => {
    expect(Object.keys(SERVICE_SOURCE)).toHaveLength(1);
    expect(source.length).toBeGreaterThan(10_000);
  });

  it("withMailSession holds no await ahead of the call that opens the socket", () => {
    const span = spanAheadOf(source, "withMailSession", "connectImap(");

    // Non-vacuity: this is the right function, and the span is real code.
    expect(span).not.toBeNull();
    expect(span).toContain("gate.held");
    expect(span).toContain("principal: Principal");
    expect(awaitsAheadOf(source, "withMailSession", "connectImap(")).toBe(false);
  });

  it("withMailSessionOver holds no await ahead of gate.acquire()", () => {
    const span = spanAheadOf(source, "withMailSessionOver", "gate.acquire(");

    expect(span).not.toBeNull();
    expect(span).toContain("duplex: DuplexLike");
    expect(span).toContain("principal: Principal");
    expect(awaitsAheadOf(source, "withMailSessionOver", "gate.acquire(")).toBe(
      false,
    );
  });

  it("does not mistake the longer name for the shorter one", () => {
    // `withMailSession` is a prefix of `withMailSessionOver`. The span for the
    // shorter name must be the socket wrapper, which takes no duplex.
    expect(spanAheadOf(source, "withMailSession", "connectImap(")).not.toContain(
      "duplex: DuplexLike",
    );
  });

  describe("the matcher can see an await (the control)", () => {
    const madeUp = [
      "export async function madeUp(principal, gate) {",
      "  if (gate.held) throw new Error();",
      "  const who = await principal;",
      "  const sock = connectImap();",
      "  return [who, sock];",
      "}",
    ].join("\n");

    it("says yes for a made-up function with an await ahead of the socket call", () => {
      expect(awaitsAheadOf(madeUp, "madeUp", "connectImap(")).toBe(true);
    });

    it("says no when the only await comes after the socket call", () => {
      const after = madeUp
        .replace("  const who = await principal;\n", "")
        .replace("return [who, sock]", "return await sock");
      expect(awaitsAheadOf(after, "madeUp", "connectImap(")).toBe(false);
    });

    it("says no when the word only appears in a comment", () => {
      const commented = madeUp.replace(
        "  const who = await principal;",
        "  // never await principal here\n  /* await nothing */",
      );
      expect(awaitsAheadOf(commented, "madeUp", "connectImap(")).toBe(false);
    });

    it("is not fooled by a comment that names the marker early", () => {
      const early = madeUp.replace(
        "  if (gate.held)",
        "  // connectImap() comes later\n  if (gate.held)",
      );
      expect(awaitsAheadOf(early, "madeUp", "connectImap(")).toBe(true);
    });

    it("says null, not no, when the function or the marker is missing", () => {
      expect(awaitsAheadOf(madeUp, "notThere", "connectImap(")).toBeNull();
      expect(awaitsAheadOf(madeUp, "madeUp", "notThere(")).toBeNull();
    });
  });
});

describe("the session gate is request-scoped (D-46)", () => {
  it("refuses a SECOND session against ONE gate, loudly", async () => {
    // A fan-out inside one request. Production allows six simultaneous
    // connections per Worker invocation and the OAuth provider's KV lookup has
    // already spent one before any mail code runs, so a second socket here is
    // not a performance question.
    const gate = createSessionGate();
    let releaseFirst: () => void = () => {};
    const firstIsHolding = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    // ONE principal too, the very same object for both callers. That is what
    // two tool calls in one legacy batch have: one server, so one gate and one
    // promise of the principal, which resolves to one object.
    const shared = principal;
    const firstDuplex = happyPathDuplex();

    // The gate is acquired synchronously at the top of the call, before any
    // await, so it is already held by the time the next line runs.
    const first = withMailSessionOver(
      firstDuplex,
      shared,
      gate,
      MAILBOX,
      null,
      async () => {
        await firstIsHolding;
        return "first";
      },
      FAST_BOUNDS,
    );

    const secondDuplex = happyPathDuplex();
    await expect(
      withMailSessionOver(
        secondDuplex,
        shared,
        gate,
        MAILBOX,
        null,
        async () => "second",
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapThrottleError);

    // A raised error, not a silent second socket: the refused session wrote
    // nothing at all to its duplex.
    expect(secondDuplex.writtenLines()).toEqual([]);

    releaseFirst();
    await expect(first).resolves.toBe("first");

    // The first caller logged in exactly once, and the refused one never did.
    // Only a COUNT is asserted. The login line carries the pool's ambient
    // credential, and a failed length check on the lines themselves would
    // print them.
    const loginLines = (lines: string[]): number =>
      lines.filter((line) => /^\S+ LOGIN /.test(line)).length;
    expect(loginLines(firstDuplex.writtenLines())).toBe(1);
    expect(loginLines(secondDuplex.writtenLines())).toBe(0);
  });

  it("lets TWO gates each run a session, because two requests are not a fan-out", async () => {
    // The case that catches the module-level-counter implementation. An
    // isolate-wide counter passes the test above and fails this one — refusing
    // a perfectly legitimate second REQUEST that happened to land in the same
    // isolate, which is a false failure on a correct call and a worse outcome
    // than the fan-out it was trying to prevent.
    const first = withMailSessionOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      MAILBOX,
      null,
      async () => "first",
      FAST_BOUNDS,
    );
    const second = withMailSessionOver(
      happyPathDuplex(),
      principal,
      createSessionGate(),
      MAILBOX,
      null,
      async () => "second",
      FAST_BOUNDS,
    );

    await expect(Promise.all([first, second])).resolves.toEqual([
      "first",
      "second",
    ]);
  });

  it("is free again after the session's work throws", async () => {
    // A failed call must not poison the rest of the request. The release lives
    // in the same `finally` as teardown for exactly this reason.
    const gate = createSessionGate();

    await expect(
      withMailSessionOver(
        happyPathDuplex(),
        principal,
        gate,
        MAILBOX,
        null,
        async () => {
          throw new Error("the work failed");
        },
        FAST_BOUNDS,
      ),
    ).rejects.toThrow("the work failed");

    expect(gate.held).toBe(false);
    // And the slot really is usable again, not merely reported free.
    await expect(
      withMailSessionOver(
        happyPathDuplex(),
        principal,
        gate,
        MAILBOX,
        null,
        async () => "reused",
        FAST_BOUNDS,
      ),
    ).resolves.toBe("reused");
  });

  it("releases the gate on the ordinary success path too", async () => {
    const gate = createSessionGate();

    await withMailSessionOver(
      happyPathDuplex(),
      principal,
      gate,
      MAILBOX,
      null,
      async () => "done",
      FAST_BOUNDS,
    );

    expect(gate.held).toBe(false);
  });
});

describe("the per-call deadline races the work, not the session (D-45)", () => {
  it("raises, tears down anyway, and frees the gate", async () => {
    // The close-observed assertion is the load-bearing one. An implementation
    // that raced the OUTER call would abandon teardown along with the work —
    // leaking exactly the connection the deadline exists to release — and would
    // still pass a test that only checked that the call raised.
    //
    // The read bound is deliberately LARGER than the call deadline here, so it
    // is genuinely the deadline that fires rather than a read timing out first.
    const duplex = createStallingDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineReply("a4"),
      // …and then the server stalls, without closing.
    ]);
    const gate = createSessionGate();

    const startedAt = Date.now();
    await expect(
      getMessageOver(duplex, principal, gate, REF, {
        readTimeoutMs: 300,
        drainTimeoutMs: 20,
        closeTimeoutMs: 20,
        callDeadlineMs: 50,
      }),
    ).rejects.toBeInstanceOf(ImapConnectError);

    // Teardown ran anyway: close() was called on the duplex.
    expect(duplex.firstIndexOf("close")).toBeGreaterThanOrEqual(0);
    expect(gate.held).toBe(false);
    expect(Date.now() - startedAt).toBeLessThan(1000);
  });

  it("does not fire on a call that finishes inside it", async () => {
    // The other direction. A deadline that fired on healthy traffic would be a
    // worse bug than no deadline, and a test asserting only the timeout case
    // would not notice.
    await expect(
      getMessageOver(happyPathDuplex(), principal, createSessionGate(), REF, {
        ...FAST_BOUNDS,
        callDeadlineMs: 2000,
      }),
    ).resolves.toMatchObject({ uid: UID });
  });
});

// ---------------------------------------------------------------------------
// The folder listing (MAIL-01, D-19, D-29 … D-32)
// ---------------------------------------------------------------------------

/** One folder as the server would announce it, plus the counts it may carry. */
interface ScriptedFolder {
  name: string;
  /** The attribute list's inner text, verbatim. */
  attributes?: string;
  /** The delimiter FIELD as it appears on the wire — `"/"` or the NIL atom. */
  delimiter?: string;
  /** The counts the server volunteers, or `null` for a folder it reports none for. */
  counts?: { messages: number; unseen: number } | null;
}

/**
 * One listing turn: an untagged reply per folder, then the tagged completion.
 *
 * A folder's `* STATUS` line is emitted immediately after its `* LIST` line,
 * which is the ordering RFC 5819 §2 describes and the one a POSITIONAL
 * correlation would also survive. The order-independence of the real
 * implementation is proven separately below, by a case that interleaves them
 * differently.
 */
function listTurn(
  tag: string,
  folders: ScriptedFolder[],
  completion = "LIST completed",
): Uint8Array {
  const lines: string[] = [];
  for (const folder of folders) {
    lines.push(
      `* LIST (${folder.attributes ?? "\\HasNoChildren"}) ` +
        `${folder.delimiter ?? '"/"'} "${folder.name}"`,
    );
    if (folder.counts) {
      lines.push(
        `* STATUS "${folder.name}" ` +
          `(MESSAGES ${folder.counts.messages} UNSEEN ${folder.counts.unseen})`,
      );
    }
  }
  lines.push(`${tag} OK ${completion}`);
  return wire(...lines);
}

/**
 * The four turns every conversation opens with, before the first real command.
 *
 * Named rather than repeated because the TAG SEQUENCE is load-bearing: plan
 * 02-07 found six scripts silently desynchronised by a command that reused a
 * tag and then read the LOGOUT exchange as its own success. Every script below
 * continues from `a4`.
 */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A server that accepts the extended form: one listing command, then logout. */
function extendedListingDuplex(folders: ScriptedFolder[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    listTurn("a4", folders),
    logoutExchange("a5"),
  ]);
}

/** A server that rejects the extended SYNTAX and answers the plain form. */
function fallbackListingDuplex(folders: ScriptedFolder[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    taggedBad("a4", "Invalid arguments to LIST"),
    listTurn("a5", folders.map(({ counts, ...rest }) => rest)),
    logoutExchange("a6"),
  ]);
}

/** The folders the ordinary cases script, in the order the server lists them. */
const SCRIPTED_FOLDERS: ScriptedFolder[] = [
  { name: "INBOX", counts: { messages: 172, unseen: 4 } },
  { name: "Drafts", counts: { messages: 3, unseen: 0 } },
  { name: "Sent Messages", counts: { messages: 91, unseen: 0 } },
  { name: "Deleted Messages", counts: { messages: 12, unseen: 0 } },
  { name: "Archive/2024", counts: { messages: 640, unseen: 0 } },
];

/** Look one folder up by its DECODED display name. */
function folderNamed(
  listing: FolderListing,
  displayName: string,
): FolderSummary {
  const found = listing.folders.find((one) => one.displayName === displayName);
  expect(found).toBeDefined();
  return found!;
}

describe("mail_list_folders, over a full conversation", () => {
  it("returns every folder with inline counts when the extended form is accepted", async () => {
    const listing = await listFoldersOver(
      extendedListingDuplex(SCRIPTED_FOLDERS),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.folders).toHaveLength(5);
    expect(listing.countsSource).toBe("list-status");
    expect(folderNamed(listing, "INBOX").totalCount).toBe(172);
    expect(folderNamed(listing, "INBOX").unreadCount).toBe(4);
    expect(folderNamed(listing, "Drafts").totalCount).toBe(3);
    expect(folderNamed(listing, "Drafts").unreadCount).toBe(0);
  });

  it("takes the hierarchy separator from the reply's own field", async () => {
    const listing = await listFoldersOver(
      extendedListingDuplex(SCRIPTED_FOLDERS),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.delimiter).toBe("/");
  });

  it("yields a null separator for a flat namespace without throwing", async () => {
    // `NIL` is legal in the delimiter position, and indexing into it —
    // `line[2][0]` — is the specific crash this pins.
    const listing = await listFoldersOver(
      extendedListingDuplex([
        { name: "INBOX", delimiter: "NIL", counts: { messages: 1, unseen: 0 } },
      ]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.delimiter).toBeNull();
    expect(listing.folders).toHaveLength(1);
  });

  it("returns the folders in the order the SERVER listed them, unsorted", async () => {
    // The listing order is itself information about how the account is
    // organised. An alphabetical re-sort would put `Archive/2024` first and
    // `INBOX` third, discarding that while adding nothing.
    const listing = await listFoldersOver(
      extendedListingDuplex(SCRIPTED_FOLDERS),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.folders.map((one) => one.displayName)).toEqual([
      "INBOX",
      "Drafts",
      "Sent Messages",
      "Deleted Messages",
      "Archive/2024",
    ]);
  });

  it("yields an EMPTY array for an account whose listing returns nothing", async () => {
    // A listing that matched nothing ran perfectly. Reporting it as an error
    // would make "no folders" indistinguishable from a failed command.
    const listing = await listFoldersOver(
      extendedListingDuplex([]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.folders).toEqual([]);
    expect(listing.countsSource).toBe("list-status");
  });

  it("yields NULL counts for an unselectable folder, never zero", async () => {
    // RFC 5819 §2: for a mailbox that cannot be selected "the STATUS response
    // MUST NOT be returned and the LIST response MUST include the \NoSelect
    // attribute". Zero would be a claim about an empty folder; null is the
    // truth, which is that nobody said.
    const listing = await listFoldersOver(
      extendedListingDuplex([
        { name: "INBOX", counts: { messages: 172, unseen: 4 } },
        { name: "Containers", attributes: "\\Noselect", counts: null },
        { name: "Notes", counts: { messages: 8, unseen: 1 } },
      ]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    const unselectable = folderNamed(listing, "Containers");
    expect(unselectable.totalCount).toBeNull();
    expect(unselectable.unreadCount).toBeNull();
    // And the folders on either side keep their OWN counts — the shift a
    // positional correlation would produce lands here.
    expect(folderNamed(listing, "INBOX").totalCount).toBe(172);
    expect(folderNamed(listing, "Notes").totalCount).toBe(8);
  });

  it("correlates counts by NAME, so a reordered status reply still lands right", async () => {
    // The hazard plan 02-06 reproduced live: positional pairing puts Drafts'
    // counts on INBOX, and the result still looks entirely plausible. Here the
    // status replies arrive in the OPPOSITE order to the listing replies.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      wire(
        '* LIST (\\HasNoChildren) "/" "INBOX"',
        '* LIST (\\HasNoChildren) "/" "Drafts"',
        '* STATUS "Drafts" (MESSAGES 2 UNSEEN 0)',
        '* STATUS "INBOX" (MESSAGES 17 UNSEEN 16)',
        "a4 OK LIST completed",
      ),
      logoutExchange("a5"),
    ]);

    const listing = await listFoldersOver(
      duplex,
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(folderNamed(listing, "INBOX").totalCount).toBe(17);
    expect(folderNamed(listing, "INBOX").unreadCount).toBe(16);
    expect(folderNamed(listing, "Drafts").totalCount).toBe(2);
  });

  it("carries both the raw wire name and the decoded display name", async () => {
    // The wire name is what round-trips back to the server; the decoded name is
    // display-only. Storing the decoded form would need an encoder this project
    // deliberately does not have.
    const listing = await listFoldersOver(
      extendedListingDuplex([{ name: MUTF7_WIRE_NAME, counts: null }]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.folders[0]!.wireName).toBe(MUTF7_WIRE_NAME);
    expect(listing.folders[0]!.displayName).toBe(MUTF7_DISPLAY_NAME);
    // And the opaque identity carries the WIRE name, byte-exact.
    expect(decodeFolderId(listing.folders[0]!.id).mailbox).toBe(MUTF7_WIRE_NAME);
  });

  it("carries each folder's role AND the path that resolved it", async () => {
    // D-30's whole point: `roleSource` makes criterion 1's "discovered rather
    // than guessed" auditable from one tool call instead of a code read.
    const listing = await listFoldersOver(
      extendedListingDuplex([
        { name: "INBOX", counts: null },
        { name: "Drafts", attributes: "\\Drafts \\HasNoChildren", counts: null },
        { name: "Sent Messages", counts: null },
        { name: "Archive/2024", counts: null },
      ]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(folderNamed(listing, "Drafts").role).toBe("drafts");
    expect(folderNamed(listing, "Drafts").roleSource).toBe("special-use");
    // Apple's own long form, resolved by the ladder rather than an attribute —
    // and reported as such, which is the signal a spoofed folder needs.
    expect(folderNamed(listing, "Sent Messages").role).toBe("sent");
    expect(folderNamed(listing, "Sent Messages").roleSource).toBe("name-match");
    expect(folderNamed(listing, "INBOX").role).toBe("inbox");
    // A child beneath a role folder claims no role, and says so with a null
    // SOURCE too rather than an empty string.
    expect(folderNamed(listing, "Archive/2024").role).toBeNull();
    expect(folderNamed(listing, "Archive/2024").roleSource).toBeNull();
  });

  it("keeps the attribute list VERBATIM, casing included", async () => {
    // That string is the evidence that settles whether this server emits
    // special-use attributes at all. A tidied copy is a summary of the evidence.
    const listing = await listFoldersOver(
      extendedListingDuplex([
        { name: "Drafts", attributes: "\\Drafts \\HasNoChildren", counts: null },
      ]),
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    expect(listing.folders[0]!.attributes).toEqual([
      "\\Drafts",
      "\\HasNoChildren",
    ]);
  });
});

describe("the commands a folder listing actually writes", () => {
  it("opens NO mailbox at all — the listing runs from the authenticated state", async () => {
    const duplex = extendedListingDuplex(SCRIPTED_FOLDERS);

    await listFoldersOver(duplex, principal, createSessionGate(), FAST_BOUNDS);

    const lines = duplex.writtenLines();
    expect(commandVerbs(lines)).toEqual([
      "CAPABILITY",
      "LOGIN",
      "CAPABILITY",
      "LIST",
      "LOGOUT",
    ]);
    expect(lines.some((line) => line.includes("EXAMINE"))).toBe(false);
    expect(lines.some((line) => line.includes("SELECT"))).toBe(false);
  });

  it("asks for the counts inline, recursively, from the namespace root", async () => {
    const duplex = extendedListingDuplex(SCRIPTED_FOLDERS);

    await listFoldersOver(duplex, principal, createSessionGate(), FAST_BOUNDS);

    expect(duplex.writtenLines()[3]).toBe(
      'a4 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
    );
  });

  it("falls back on a tagged BAD, writing exactly ONE extra command", async () => {
    // T-02-07. A per-folder status loop would satisfy every containment check
    // and none of this one: twenty folders on a single sequential connection is
    // the cost D-19 declined, and it would spend most of the call deadline.
    const duplex = fallbackListingDuplex(SCRIPTED_FOLDERS);

    const listing = await listFoldersOver(
      duplex,
      principal,
      createSessionGate(),
      FAST_BOUNDS,
    );

    // An ORDERED comparison of every command written, not a set of assertions
    // about what appears: exactly two listing commands, and no standalone
    // status command anywhere.
    expect(commandVerbs(duplex.writtenLines())).toEqual([
      "CAPABILITY",
      "LOGIN",
      "CAPABILITY",
      "LIST",
      "LIST",
      "LOGOUT",
    ]);
    expect(duplex.writtenLines()[4]).toBe('a5 LIST "" "*"');
    expect(listing.folders).toHaveLength(5);
    expect(listing.countsSource).toBe("unavailable");
    for (const folder of listing.folders) {
      expect(folder.totalCount).toBeNull();
      expect(folder.unreadCount).toBeNull();
    }
  });

  it("does NOT fall back on a tagged NO, which is about the mailbox not the syntax", async () => {
    // BAD means the request was malformed. NO means the server understood it
    // and refused. Retrying the plain form against a NO would be a second
    // command spent on a question already answered.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", "Mailbox does not exist"),
      logoutExchange("a5"),
    ]);

    await expect(
      listFoldersOver(duplex, principal, createSessionGate(), FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(commandVerbs(duplex.writtenLines())).toEqual([
      "CAPABILITY",
      "LOGIN",
      "CAPABILITY",
      "LIST",
      "LOGOUT",
    ]);
  });

  it("tears down in a finally when the listing itself fails", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", "Mailbox does not exist"),
      logoutExchange("a5"),
    ]);

    await expect(
      listFoldersOver(duplex, principal, createSessionGate(), FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toContain("a5 LOGOUT");
    expect(duplex.firstIndexOf("close")).toBeGreaterThan(
      duplex.firstIndexOf("readable-done"),
    );
  });
});

// ---------------------------------------------------------------------------
// The paginated listing (MAIL-02, criterion 2)
//
// The cost discipline is the subject here, not merely the fields. A page of any
// size costs one identifier command, one batched metadata command, and one
// snippet command per DISTINCT resolved part path — never one command per
// message, which at D-22's hundred-row maximum would be two hundred sequential
// round trips inside a twenty-second deadline (T-02-07).
// ---------------------------------------------------------------------------

/**
 * A structure whose readable part sits at `1.1` rather than at `1`.
 *
 * A `multipart/mixed` wrapping a `multipart/alternative`, which is the second
 * commonest shape real mail arrives in — and the one that makes the grouping
 * assertion below non-vacuous, because a page of these resolves to a different
 * path than a page of plain single-part messages.
 */
const NESTED_ALTERNATIVE_STRUCTURE =
  "(" +
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 90 3)' +
  '("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 200 5)' +
  ' "ALTERNATIVE" ("BOUNDARY" "inner") NIL NIL)' +
  '("APPLICATION" "PDF" ("NAME" "deck.pdf") NIL NIL "BASE64" 400 NIL' +
  ' ("attachment" ("FILENAME" "deck.pdf")) NIL)' +
  ' "MIXED" ("BOUNDARY" "outer") NIL NIL' +
  ")";

/**
 * The plain half's declared size in both structures below: the LARGEST
 * placeholder on record against this account.
 *
 * Two messages from Sleep-Insights@sleeptracker.com carry a `text/plain`
 * alternative whose entire contents are the sentence
 * `placeholderPlainWindowFor` returns — roughly 45 octets of real English words
 * (G-02-9b). It is the largest of the three observed placeholder shapes, and it
 * is deliberately the one both cases below are built on: the whitespace-only
 * shape 02-17 already recovers from proves nothing about a rule keyed on a
 * ratio, because it would reach the HTML half either way.
 */
const PLACEHOLDER_PLAIN_OCTETS = 45;

/** An HTML half that outweighs that placeholder by more than the ratio. */
const DWARFING_HTML_OCTETS = 60000;

/** An HTML half that does NOT — the same shape, on the other side of the line. */
const MODEST_HTML_OCTETS = 900;

/**
 * `NESTED_ALTERNATIVE_STRUCTURE`'s shape with both halves' sizes supplied.
 *
 * Built rather than pasted so the two constants below differ in exactly ONE
 * number, which is the property that makes the pair discriminating: any
 * implementation keyed on what the plain half SAYS cannot tell them apart,
 * because the plain window they are served is byte-identical.
 */
function alternativePairStructure(
  plainOctets: number,
  htmlOctets: number,
): string {
  return (
    "(" +
    `(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" ${plainOctets} 3)` +
    `("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" ${htmlOctets} 5)` +
    ' "ALTERNATIVE" ("BOUNDARY" "inner") NIL NIL)' +
    '("APPLICATION" "PDF" ("NAME" "deck.pdf") NIL NIL "BASE64" 400 NIL' +
    ' ("attachment" ("FILENAME" "deck.pdf")) NIL)' +
    ' "MIXED" ("BOUNDARY" "outer") NIL NIL' +
    ")"
  );
}

/** A plain half that cannot be this message: 45 octets against 60 000. */
const DWARFED_PLAIN_STRUCTURE = alternativePairStructure(
  PLACEHOLDER_PLAIN_OCTETS,
  DWARFING_HTML_OCTETS,
);

/** The same plain half beside an HTML half it is NOT dwarfed by. */
const MODEST_HTML_STRUCTURE = alternativePairStructure(
  PLACEHOLDER_PLAIN_OCTETS,
  MODEST_HTML_OCTETS,
);

/** The item list the batched metadata command asks for, spelled once. */
const PAGE_ITEM_LIST =
  "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE " +
  "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])";

/** The reply key the server returns that block under. */
const HEADER_BLOCK_KEY = "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]";

/**
 * The server's own receipt time, deliberately nothing like the `Date` header.
 *
 * A year and a month apart, so a summary reporting the sender's header instead
 * of the server's INTERNALDATE fails on the value rather than on formatting.
 */
const INTERNAL_DATE = "01-Jan-2026 00:00:00 +0000";

/** One row of a scripted page. */
interface PageRow {
  uid: number;
  /**
   * The SEQUENCE NUMBER prefix the untagged reply carries.
   *
   * Deliberately unrelated to the UID. RFC 3501 prefixes every untagged FETCH
   * with one even in reply to a UID FETCH, and MAIL-06 requires a UID-only
   * surface — a fixture whose sequence numbers happened to equal its UIDs could
   * not tell a correct client from one surfacing the prefix.
   */
  seq: number;
  flags?: string;
  structure?: string;
  subject?: string;
}

/** The header block one row's metadata reply carries as a literal. */
function headerBlockFor(row: PageRow): string {
  return [
    `Subject: ${row.subject ?? `Subject for ${row.uid}`}`,
    `From: "Sender ${row.uid}" <s${row.uid}@example.invalid>`,
    "Date: Thu, 13 Aug 2026 09:14:02 -0700",
    `Message-ID: <m${row.uid}@example.invalid>`,
    "",
    "",
  ].join("\r\n");
}

/** The wire size a row declares. Distinct from every sequence number in play. */
function wireSizeOf(row: PageRow): number {
  return 12000 + row.uid;
}

/** The batched metadata reply: one untagged line per row, then the completion. */
function pageMetadataReply(tag: string, rows: PageRow[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const row of rows) {
    chunks.push(
      ENCODER.encode(
        `* ${row.seq} FETCH (UID ${row.uid} FLAGS (${row.flags ?? ""}) ` +
          `INTERNALDATE "${INTERNAL_DATE}" ` +
          `RFC822.SIZE ${wireSizeOf(row)} ` +
          `BODYSTRUCTURE ${row.structure ?? PLAIN_STRUCTURE} `,
      ),
      literalItem(HEADER_BLOCK_KEY, headerBlockFor(row)),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** The text one row's snippet window carries. */
function snippetTextFor(uid: number): string {
  return `Preview of message ${uid} — following up on our conversation.`;
}

/** The prose an HTML row's markup window carries, once converted. */
function snippetProseFor(uid: number): string {
  return `Your briefing for message ${uid} is ready to read.`;
}

/**
 * The MARKUP an HTML-only row's snippet window carries.
 *
 * The preamble is longer than `SNIPPET_MAX_CHARS` on purpose, which is what
 * makes the assertion below non-vacuous: a preview built by capping the raw
 * window never reaches the first paragraph at all, so it cannot contain the
 * prose by accident.
 */
function snippetMarkupFor(uid: number): string {
  return (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" ' +
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' +
    "<html><head><title>Digest</title>" +
    "<style>body{margin:0;padding:0;background:#f4f4f4;font-family:Helvetica}" +
    ".wrapper{width:100%;max-width:600px;margin:0 auto}</style></head><body>" +
    `<p>${snippetProseFor(uid)}</p>` +
    "<p>Three new talks were added this week.</p></body></html>"
  );
}

/**
 * The MARKUP of an HTML row whose prose begins past the OLD snippet window.
 *
 * The shape G-02-9a was measured on, not a contrived one. Real marketing and
 * newsletter mail opens with a doctype, a `<head>`, a `<title>` and a `<style>`
 * block of media queries that routinely runs to several kilobytes before the
 * first paragraph — the TED newsletter at uid 184617 is the recorded example,
 * and it previewed as the empty string in a listing while its full fetch
 * returned 64 KB of clean prose through the same converter on the same part.
 * `snippetFromPart` was never wrong about that window; the window simply never
 * reached the prose.
 *
 * The style block is BUILT by repetition rather than pasted as a wall of literal
 * CSS, so the fixture's intent — "longer than `SNIPPET_FETCH_OCTETS`" — is
 * legible at a glance instead of buried in a kilobyte of declarations. The
 * length claim is asserted in the test rather than trusted here.
 */
function deepPreambleMarkupFor(uid: number): string {
  const mediaQuery =
    "@media only screen and (max-width:600px){" +
    ".wrapper{width:100%!important}.column{display:block!important}" +
    ".hide-on-mobile{display:none!important}}";
  return (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" ' +
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' +
    "<html><head><title>The Weekly Briefing</title>" +
    `<style>${mediaQuery.repeat(12)}</style></head><body>` +
    `<p>${snippetProseFor(uid)}</p>` +
    "<p>Three new talks were added this week.</p></body></html>"
  );
}

/**
 * The window a BLANK `text/plain` alternative sends back.
 *
 * Not a fabrication and not a degenerate edge case: G-02-3b recorded two real
 * messages on this account — uid 184545 and uid 184504 — whose entire plain
 * alternative decodes to whitespace, which is what made their listing previews
 * come back empty. Senders emit a blank plain part routinely as an
 * `ALTERNATIVE` placeholder, filling the slot without putting anything in it.
 *
 * A whitespace RUN rather than an empty literal, on purpose. An empty window
 * and a whitespace window reach the fallback by different routes — one is a
 * window the server sent that decodes to nothing, the other is a window that
 * never arrived — and the observed defect is the first.
 */
function blankPlainWindowFor(_uid: number): string {
  return "\r\n   \r\n";
}

/**
 * The window a plain alternative padded with ZERO-WIDTH characters sends back.
 *
 * The same blank-placeholder shape as above in the one spelling `.trim()`
 * cannot see (WR-02). JavaScript's whitespace set excludes U+200B, U+200C,
 * U+200D and U+00AD — precisely the family `INVISIBLE_FORMATTING` classifies as
 * rendering to nothing — so this window is "readable" to a trim-only predicate
 * and the recovery never fires for it. A preheader padded exactly like this is
 * near-universal in marketing mail: one observed message carried roughly 130
 * such sequences ahead of its first real word (G-02-3c).
 *
 * Escapes rather than literals, for the reason 02-15 gives: a literal
 * zero-width character in a fixture is one no reader, diff or review can see.
 */
function zeroWidthPlainWindowFor(_uid: number): string {
  return "\u200B\u200C\u200B\uFEFF\u00AD".repeat(8);
}

/**
 * The window an UNAUTHORED plain alternative sends back \u2014 made of real words.
 *
 * The Sleeptracker sentence, verbatim from the account (G-02-9b). This is the
 * fixture the whole ratio rule stands or falls on, and the reason is that it
 * passes every content test there is: eight real English words, no placeholder
 * token, nothing to blocklist, nothing whitespace about it. `hasReadableText`
 * returns true for it, so 02-17's recovery never fires \u2014 a row carrying this
 * costs one command and returns text the user cannot read the message from.
 *
 * The same string is served to BOTH cases below, so the only thing that can
 * separate them is the relationship between the two declared sizes.
 */
function placeholderPlainWindowFor(_uid: number): string {
  return "Your email client does not support HTML email";
}

/**
 * A grouped snippet reply, all rows for one resolved part path.
 *
 * `origin` writes the partial-fetch origin marker. RFC 3501: "A partial fetch
 * that starts at octet 0 is returned as a partial fetch, even if this truncation
 * happened" — so the marker is the NORMAL shape and its absence is the special
 * case, which is why it defaults to present here and one case flips it.
 *
 * `body` swaps what the window CARRIES without touching how it is framed. The
 * literal's byte count is the part of this helper that is easy to get wrong, so
 * a markup window reuses this framing rather than growing a second builder
 * beside it.
 */
function snippetReply(
  tag: string,
  path: string,
  rows: PageRow[],
  options: { origin?: boolean; body?: (uid: number) => string } = {},
): Uint8Array {
  const marker = options.origin === false ? "" : "<0>";
  const bodyFor = options.body ?? snippetTextFor;
  const chunks: Uint8Array[] = [];
  for (const row of rows) {
    chunks.push(
      ENCODER.encode(`* ${row.seq} FETCH (UID ${row.uid} `),
      literalItem(`BODY[${path}]${marker}`, bodyFor(row.uid)),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** The untagged search reply for a set of identifiers, in server order. */
function searchReply(tag: string, uids: number[]): Uint8Array {
  return wire(
    `* SEARCH${uids.map((uid) => ` ${uid}`).join("")}`,
    `${tag} OK SEARCH completed`,
  );
}

/** The four commands every mail session opens with, then the mailbox. */
function listingPrefix(
  options: { uidValidity?: number | null } = {},
): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineReply("a4", { uidValidity: options.uidValidity }),
  ];
}

/** Rows for a run of consecutive identifiers, all one structure. */
function rowsFor(uids: number[], structure?: string): PageRow[] {
  return uids.map((uid, index) => ({
    uid,
    // Sequence numbers run from 1 and are never the UID.
    seq: index + 1,
    structure,
  }));
}

/** Identifiers as the page will hold them: newest first, descending. */
function descending(uids: number[]): number[] {
  return [...uids].sort((a, b) => b - a);
}

/** A whole listing conversation: search, metadata, snippets, logout. */
function listingDuplex(turns: Uint8Array[], logoutTag: string): FakeDuplex {
  return createFakeDuplex([...listingPrefix(), ...turns, logoutExchange(logoutTag)]);
}

/** The commands a listing wrote, excluding the authentication preamble. */
function sessionCommands(duplex: FakeDuplex): string[] {
  return duplex.writtenLines().slice(3);
}

describe("the batched page fetch (MAIL-02, T-02-07)", () => {
  /** Twenty-five plain messages, which is D-22's default page. */
  const PAGE_UIDS = descending(
    Array.from({ length: 25 }, (_value, index) => 4801 + index),
  );
  const PAGE_ROWS = rowsFor(PAGE_UIDS);

  function fullPageDuplex(): FakeDuplex {
    return listingDuplex(
      [
        searchReply("a5", PAGE_UIDS),
        pageMetadataReply("a6", PAGE_ROWS),
        snippetReply("a7", "1", PAGE_ROWS),
      ],
      "a8",
    );
  }

  it("costs a handful of round trips for a whole page, not one per message", async () => {
    // T-02-07 stated as an ordered comparison rather than a count, so a failure
    // says WHICH command was extra rather than only that one was.
    const duplex = fullPageDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    expect(page.messages).toHaveLength(25);
    expect(commandVerbs(sessionCommands(duplex))).toEqual([
      "EXAMINE",
      "UID SEARCH",
      "UID FETCH",
      "UID FETCH",
      "LOGOUT",
    ]);
    // Five, against a per-message implementation's fifty for the same page.
    expect(sessionCommands(duplex).length).toBeLessThanOrEqual(6);
  });

  it("covers all twenty-five identifiers with ONE metadata command", async () => {
    // Compared against the whole expected line rather than by counting commas:
    // the identifier set, the item list and the peeking form are all part of the
    // same claim, and asserting them separately would let a correct-looking
    // command with the wrong item list through.
    const duplex = fullPageDuplex();

    await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    expect(duplex.writtenLines()[5]).toBe(
      `a6 UID FETCH ${PAGE_UIDS.join(",")} ${PAGE_ITEM_LIST}`,
    );
  });

  it("fetches one snippet command for a page resolving to a single path", async () => {
    const duplex = fullPageDuplex();

    await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    expect(duplex.writtenLines()[6]).toBe(
      `a7 UID FETCH ${PAGE_UIDS.join(",")} (BODY.PEEK[1]<0.${SNIPPET_FETCH_OCTETS}>)`,
    );
  });

  it("uses the PEEKING form on every fetch it writes (D-47, T-02-09)", async () => {
    // The snippet fetch touches every message on a page, so one slip here marks
    // a whole page read in a single call — a far worse failure than the same
    // slip on a single-message fetch.
    const duplex = fullPageDuplex();

    await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    expect(fetches).toHaveLength(2);
    for (const line of fetches) {
      expect(line).not.toMatch(/BODY(?!\.PEEK)[.\w]*\[/);
    }
  });

  it("returns every field criterion 2 names, and no body", async () => {
    const duplex = fullPageDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    const first = page.messages[0]!;
    expect(first.uid).toBe(PAGE_UIDS[0]);
    expect(first.id).toBe(
      encodeMessageId({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: PAGE_UIDS[0]! }),
    );
    expect(first.subject).toBe(`Subject for ${PAGE_UIDS[0]}`);
    expect(first.fromName).toBe(`Sender ${PAGE_UIDS[0]}`);
    expect(first.fromAddress).toBe(`s${PAGE_UIDS[0]}@example.invalid`);
    expect(first.snippet).toContain("following up on our conversation");
    expect(first.wireSizeBytes).toBe(12000 + PAGE_UIDS[0]!);
    expect(first.hasAttachments).toBe(false);
    // The structural half of criterion 2's "never full bodies": there is no
    // field on this type that could carry one.
    expect("text" in first).toBe(false);
    expect("html" in first).toBe(false);
  });

  it("reports the SERVER's internal date, never the sender's own header", async () => {
    const duplex = fullPageDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    expect(page.messages[0]!.internalDate).toBe(INTERNAL_DATE);
    // The sender's `Date` header is stranger-authored and is not a field here.
    expect("date" in page.messages[0]!).toBe(false);
  });

  it("derives read status from the presence of the seen flag", async () => {
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, flags: "\\Seen" },
      { uid: 4801, seq: 2, flags: "" },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1", rows),
      ],
      "a8",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages.map((one) => one.unread)).toEqual([false, true]);
  });

  it("discards the sequence-number prefix, which reaches no field (PITFALLS #5)", async () => {
    // MAIL-06 requires a UID-only surface, and this is the single place in the
    // phase where a sequence number is handed to the client unasked.
    const duplex = fullPageDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: PAGE_SIZE_DEFAULT,
    });

    const sequenceNumbers = new Set(PAGE_ROWS.map((row) => row.seq));
    expect(sequenceNumbers.size).toBe(25);
    for (const summary of page.messages) {
      for (const value of Object.values(summary)) {
        if (typeof value === "number") {
          expect(sequenceNumbers.has(value)).toBe(false);
        }
      }
    }
  });

  it("returns an empty page for an empty folder, not an error", async () => {
    const duplex = listingDuplex([searchReply("a5", [])], "a6");

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    // No metadata command and no snippet command: there was nothing to ask for.
    expect(commandVerbs(sessionCommands(duplex))).toEqual([
      "EXAMINE",
      "UID SEARCH",
      "LOGOUT",
    ]);
  });
});

describe("the grouped snippet fetches (D-20, T-02-09)", () => {
  const PLAIN_ROWS: PageRow[] = [
    { uid: 4805, seq: 1 },
    { uid: 4803, seq: 3 },
  ];
  const NESTED_ROWS: PageRow[] = [
    { uid: 4804, seq: 2, structure: NESTED_ALTERNATIVE_STRUCTURE },
    { uid: 4802, seq: 4, structure: NESTED_ALTERNATIVE_STRUCTURE },
  ];

  /** A page resolving to exactly two distinct paths, interleaved on the wire. */
  function twoPathDuplex(): FakeDuplex {
    const rows = [PLAIN_ROWS[0]!, NESTED_ROWS[0]!, PLAIN_ROWS[1]!, NESTED_ROWS[1]!];
    return listingDuplex(
      [
        searchReply("a5", [4802, 4803, 4804, 4805]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1", PLAIN_ROWS),
        snippetReply("a8", "1.1", NESTED_ROWS),
      ],
      "a9",
    );
  }

  it("issues exactly one command per DISTINCT resolved part path", async () => {
    const duplex = twoPathDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(4);
    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    // One metadata command plus two snippet commands — not four, and not one
    // per message.
    expect(fetches).toHaveLength(3);
    expect(fetches[1]).toBe(
      `a7 UID FETCH 4805,4803 (BODY.PEEK[1]<0.${SNIPPET_FETCH_OCTETS}>)`,
    );
    expect(fetches[2]).toBe(
      `a8 UID FETCH 4804,4802 (BODY.PEEK[1.1]<0.${SNIPPET_FETCH_OCTETS}>)`,
    );
  });

  it("gives every row its own snippet, correlated by UID rather than position", async () => {
    // The correlation hazard plan 02-06 reproduced one layer down, where
    // positional pairing put one folder's counts on another and still looked
    // entirely plausible. Here the two snippet replies arrive in a different
    // order from the metadata reply, so a positional client mixes them up.
    const duplex = twoPathDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    for (const summary of page.messages) {
      expect(summary.snippet).toBe(snippetTextFor(summary.uid));
    }
  });

  it("gives an HTML-only row a prose snippet rather than raw markup", async () => {
    // This case is the point of the fix, and it is at the LISTING level on
    // purpose. The root cause was never in the converter — it was a call site
    // that never asked for one, so a test exercising `htmlToText` or
    // `selectTextPart` directly would have stayed green through the whole bug.
    // Both consumers of the shared selector agreed about which part held the
    // text; they disagreed about what was owed on it (G-02-3a).
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: HTML_ONLY_STRUCTURE },
      { uid: 4801, seq: 2, structure: HTML_ONLY_STRUCTURE },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1", rows, { body: snippetMarkupFor }),
      ],
      "a8",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(2);
    for (const summary of page.messages) {
      // Non-vacuity, asserted rather than asserted-about: a preview built by
      // capping the markup stops inside the style block, so it cannot reach
      // this prose by accident.
      expect(
        snippetMarkupFor(summary.uid).indexOf(snippetProseFor(summary.uid)),
      ).toBeGreaterThan(SNIPPET_MAX_CHARS);

      expect(summary.snippet).toContain(snippetProseFor(summary.uid));
      expect(summary.snippet).not.toContain("<");
      expect(summary.snippet).not.toContain(">");
      expect(summary.snippet).not.toContain("DOCTYPE");
      expect(summary.snippet).not.toContain("#f4f4f4");
      expect([...summary.snippet].length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    }
  });

  /** Two HTML-only rows whose prose sits past the OLD 1024-octet window. */
  const DEEP_PREAMBLE_ROWS: PageRow[] = [
    { uid: 4802, seq: 1, structure: HTML_ONLY_STRUCTURE },
    { uid: 4801, seq: 2, structure: HTML_ONLY_STRUCTURE },
  ];

  function deepPreambleDuplex(): FakeDuplex {
    return listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", DEEP_PREAMBLE_ROWS),
        snippetReply("a7", "1", DEEP_PREAMBLE_ROWS, {
          body: deepPreambleMarkupFor,
        }),
      ],
      "a8",
    );
  }

  it("reaches past a multi-kilobyte HTML preamble to the first prose", async () => {
    // G-02-9a: 20 of 100 rows on a real INBOX page carried no snippet, because
    // the window was the first 1024 encoded octets of the resolved part and for
    // an HTML part those octets are the doctype, the head and a style block.
    // The converter was never the problem — it converted that window correctly
    // and correctly got nothing out of it.
    const duplex = deepPreambleDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    // The discrimination is this PAIR of assertions and NEITHER IS SUFFICIENT
    // ALONE. The scripted duplex answers with whatever it was scripted with
    // regardless of how large a window the client asked for, so no assertion on
    // the OUTCOME can show that the old window would have failed. Assertion one
    // proves the escalation reached the wire; assertion two proves the prose it
    // reached for was genuinely out of the old window's range. Deleting either
    // as redundant silently converts this case into a vacuous green.
    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    expect(fetches[1]).toBe(
      `a7 UID FETCH 4802,4801 (BODY.PEEK[1]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
    );

    // Measured in the SAME UNIT the constant is in. `SNIPPET_FETCH_OCTETS`
    // counts octets and `String.indexOf` counts UTF-16 code units; an indexOf
    // comparison would be sound here only because this fixture happens to be
    // ASCII, which is the exact class of silent unit error `truncateToBytes`
    // warns about. (The twin at `#gives an HTML-only row a prose snippet rather
    // than raw markup` compares against SNIPPET_MAX_CHARS, which IS a character
    // count, and is unit-correct as written — do not "align" it to this one.)
    const markup = deepPreambleMarkupFor(4802);
    const preamble = markup.slice(0, markup.indexOf(snippetProseFor(4802)));
    expect(ENCODER.encode(preamble).byteLength).toBeGreaterThan(
      SNIPPET_FETCH_OCTETS,
    );

    expect(page.messages).toHaveLength(2);
    for (const summary of page.messages) {
      expect(summary.snippet).toContain(snippetProseFor(summary.uid));
      expect(summary.snippet).not.toContain("<");
      expect(summary.snippet).not.toContain(">");
      expect(summary.snippet).not.toContain("DOCTYPE");
      expect(summary.snippet).not.toContain("max-width");
      expect([...summary.snippet].length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    }
  });

  it("costs one command for a page of HTML rows, not two", async () => {
    // The escalation is a LARGER first fetch, never a second pass. G-02-9a's
    // `missing:` list named both options and this phase declined the second,
    // because a recovery pass costs one command per page of affected rows
    // whereas a wider window costs none — the cost is bounded by the page's
    // SHAPE rather than by its length (D-20). This is the assertion that catches
    // someone re-implementing it as the option that was declined.
    const duplex = deepPreambleDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(2);
    expect(sessionCommands(duplex)).toEqual([
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      `a6 UID FETCH 4802,4801 ${PAGE_ITEM_LIST}`,
      `a7 UID FETCH 4802,4801 (BODY.PEEK[1]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
      "a8 LOGOUT",
    ]);
  });

  it("costs one command MORE when one path carries both subtypes", async () => {
    // THE CASE THE COST CLAIM RESTS ON. The window follows the resolved part's
    // SUBTYPE, and a single-part plain message and a single-part HTML message
    // both resolve to path `1` — so a page mixing them, which is the commonest
    // mixed shape there is and exactly what UAT check 2 measured at 20 HTML rows
    // among 100, shared ONE command before this change and takes TWO after it.
    //
    // Nothing in the repository exercised that page shape: the no-extra-command
    // guard below runs on `twoPathDuplex()`, whose four rows are all
    // plain-resolved. Without this case the increment is structurally
    // unfalsifiable. The honest claim it pins is: at most ONE additional command
    // per resolved path carrying both subtypes — bounded by the page's distinct
    // paths, never one per message. That is the claim D-20 tolerates, and it is
    // only a claim if this test exists.
    //
    // ONE interleaved array with explicit `seq` values, not two `rowsFor()`
    // calls. `rowsFor` restarts `seq` at 1 on every call, so the obvious two-call
    // construction emits duplicate sequence numbers and this case fails for a
    // reason with nothing to do with the change under test — the most expensive
    // kind of red, because it reads as the feature breaking. `twoPathDuplex()`
    // above already does exactly this for the same four identifiers.
    const PLAIN_SUBSET: PageRow[] = [
      { uid: 4805, seq: 1, structure: PLAIN_STRUCTURE },
      { uid: 4803, seq: 3, structure: PLAIN_STRUCTURE },
    ];
    const HTML_SUBSET: PageRow[] = [
      { uid: 4804, seq: 2, structure: HTML_ONLY_STRUCTURE },
      { uid: 4802, seq: 4, structure: HTML_ONLY_STRUCTURE },
    ];
    const rows = [
      PLAIN_SUBSET[0]!,
      HTML_SUBSET[0]!,
      PLAIN_SUBSET[1]!,
      HTML_SUBSET[1]!,
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4802, 4803, 4804, 4805]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1", PLAIN_SUBSET),
        snippetReply("a8", "1", HTML_SUBSET, { body: deepPreambleMarkupFor }),
      ],
      "a9",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(4);
    // Byte for byte, which pins the split, its grouping, its path/window pairing
    // AND its order: the group map's key order follows first appearance and the
    // page runs newest-first, so the plain pair leads.
    expect(sessionCommands(duplex)).toEqual([
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      `a6 UID FETCH 4805,4804,4803,4802 ${PAGE_ITEM_LIST}`,
      `a7 UID FETCH 4805,4803 (BODY.PEEK[1]<0.${SNIPPET_FETCH_OCTETS}>)`,
      `a8 UID FETCH 4804,4802 (BODY.PEEK[1]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
      "a9 LOGOUT",
    ]);

    for (const summary of page.messages) {
      if (summary.uid === 4805 || summary.uid === 4803) {
        expect(summary.snippet).toBe(snippetTextFor(summary.uid));
      } else {
        expect(summary.snippet).toContain(snippetProseFor(summary.uid));
        expect(summary.snippet).not.toContain("<");
      }
    }
  });

  it("refetches the HTML alternative when the plain window decodes to whitespace", async () => {
    // G-02-3b's other half, at the listing level. `selectTextPart` resolves the
    // readable part from `BODYSTRUCTURE`, where no body bytes have been fetched
    // and content is invisible — so a blank `text/plain` placeholder wins on
    // presence and the window really does decode to nothing. 02-14's content
    // gate cannot reach this: it lives in `extractMessage`, one layer up, where
    // decoded bytes already exist.
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: NESTED_ALTERNATIVE_STRUCTURE },
      { uid: 4801, seq: 2, structure: NESTED_ALTERNATIVE_STRUCTURE },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1.1", rows, { body: blankPlainWindowFor }),
        snippetReply("a8", "1.2", rows, { body: snippetMarkupFor }),
      ],
      "a9",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    // Non-vacuity, asserted rather than asserted-about: the first window really
    // carries nothing a reader would see, so a preview reaching the prose below
    // cannot have come from it.
    expect(blankPlainWindowFor(4802).trim()).toBe("");

    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    // One metadata command, one snippet command, and EXACTLY ONE fallback —
    // grouped by the sibling's path exactly as the first pass groups, not one
    // per message (T-02-49). Both rows fell back and both are on the one line.
    expect(fetches).toHaveLength(3);
    // The fallback target is the HTML child at `1.2`, so it is fetched at the
    // ESCALATED window (G-02-9a). The window follows the TARGET part's subtype
    // rather than the pass that asked for it, which is what gives 02-17's
    // recovery the same reach a directly-resolved HTML part gets.
    expect(fetches[2]).toBe(
      `a8 UID FETCH 4802,4801 (BODY.PEEK[1.2]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
    );

    expect(page.messages).toHaveLength(2);
    for (const summary of page.messages) {
      expect(summary.snippet).toContain(snippetProseFor(summary.uid));
      // The recovered window is markup, so the conversion is owed on it too.
      expect(summary.snippet).not.toContain("<");
      expect(summary.snippet).not.toContain("DOCTYPE");
      expect([...summary.snippet].length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    }
  });

  it("refetches the HTML alternative when the plain window is ZERO-WIDTH padding", async () => {
    // The same recovery, at the listing level, for the padding `.trim()` cannot
    // see (WR-02). This is G-02-3b reopening in a different spelling: the row's
    // preview is a run of characters a reader sees nothing of, `hasReadableText`
    // called it content, and so 02-17's recovery never fired for it — the model
    // received up to SNIPPET_MAX_CHARS of invisible characters in a page.
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: NESTED_ALTERNATIVE_STRUCTURE },
      { uid: 4801, seq: 2, structure: NESTED_ALTERNATIVE_STRUCTURE },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1.1", rows, { body: zeroWidthPlainWindowFor }),
        snippetReply("a8", "1.2", rows, { body: snippetMarkupFor }),
      ],
      "a9",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    // Non-vacuity, and it is the whole point of this case rather than a
    // formality: this window is NOT empty under `.trim()`, so it reaches the
    // recovery only if the predicate stopped using trim alone. The case beside
    // it, whose window is ordinary whitespace, passes either way.
    expect(zeroWidthPlainWindowFor(4802).trim()).not.toBe("");
    expect(zeroWidthPlainWindowFor(4802).length).toBeGreaterThan(0);

    const fetches = duplex.writtenLines().filter((line) => line.includes("FETCH"));
    expect(fetches).toHaveLength(3);
    // Escalated for the same reason as the case above: the target is HTML.
    expect(fetches[2]).toBe(
      `a8 UID FETCH 4802,4801 (BODY.PEEK[1.2]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
    );

    expect(page.messages).toHaveLength(2);
    for (const summary of page.messages) {
      expect(summary.snippet).toContain(snippetProseFor(summary.uid));
      expect(summary.snippet).not.toContain("<");
    }
  });

  it("reads the HTML half when the plain half cannot be this message", async () => {
    // G-02-9b. The plain half is 45 declared octets against 60 000 — not a
    // close call and not a claim about what it says, but evidence the sender
    // never authored a plain half at all, only a template that failed to
    // render. The rule fires on the STRUCTURE, before any body byte is
    // fetched, so this row resolves to `1.2` on the FIRST pass: 02-17's
    // recovery never runs and the page costs ONE snippet command.
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: DWARFED_PLAIN_STRUCTURE },
      { uid: 4801, seq: 2, structure: DWARFED_PLAIN_STRUCTURE },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1.2", rows, { body: snippetMarkupFor }),
      ],
      "a8",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(2);
    // Byte for byte, and the point of asserting the WHOLE list rather than one
    // line is the absence: there is no `a8` snippet command here. An
    // implementation that let the plain half win and then recovered from the
    // blank-ish window would show two, and would also be spending a round trip
    // on a serialised socket to reach a conclusion the structure already had.
    // The window is the escalated one because the resolved part is HTML — the
    // window follows the TARGET part's subtype (02-19).
    expect(sessionCommands(duplex)).toEqual([
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      `a6 UID FETCH 4802,4801 ${PAGE_ITEM_LIST}`,
      `a7 UID FETCH 4802,4801 (BODY.PEEK[1.2]<0.${SNIPPET_HTML_FETCH_OCTETS}>)`,
      "a8 LOGOUT",
    ]);

    for (const summary of page.messages) {
      expect(summary.snippet).toContain(snippetProseFor(summary.uid));
      expect(summary.snippet).not.toContain("<");
      expect(summary.snippet).not.toContain("DOCTYPE");
    }
  });

  it("reads the plain half when the same text sits beside a small HTML half", async () => {
    // THE CASE THAT DISCRIMINATES, and it exists to fail any implementation
    // keyed on the SENTENCE rather than on the ratio. The plain window here is
    // byte-identical to the one above — same helper, same eight English words —
    // and the outcome is the opposite one, because the only thing that changed
    // is the HTML half's declared size. A string blocklist passes the case
    // above and fails this one. So does a "does it contain words" gate, in the
    // other direction: it passes this one and fails the case above.
    //
    // Which is also why the rule cannot be keyed on contents at all. The plain
    // half of a real MGM message reads `MGM RESORTS INTERNATIONAL | MGM Rewards
    // ***** undefined undefined Book Now https://…` — the same broken token,
    // MID-BODY, in a part that is otherwise legitimate and must be returned as
    // written (D-36).
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: MODEST_HTML_STRUCTURE },
      { uid: 4801, seq: 2, structure: MODEST_HTML_STRUCTURE },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1.1", rows, { body: placeholderPlainWindowFor }),
      ],
      "a8",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(2);
    expect(sessionCommands(duplex)).toEqual([
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      `a6 UID FETCH 4802,4801 ${PAGE_ITEM_LIST}`,
      `a7 UID FETCH 4802,4801 (BODY.PEEK[1.1]<0.${SNIPPET_FETCH_OCTETS}>)`,
      "a8 LOGOUT",
    ]);

    for (const summary of page.messages) {
      expect(summary.snippet).toBe(placeholderPlainWindowFor(summary.uid));
    }
  });

  it("issues no extra command when every window carries text", async () => {
    // The guard on the case above, and the one that catches an over-eager
    // fallback. These rows resolve to `1.1` and an HTML sibling sits at `1.2`,
    // so a second pass that ran unconditionally WOULD have somewhere to go —
    // and this page must still cost exactly what it costs today, byte for byte,
    // because D-20's grouped-fetch cost model was decided rather than inherited.
    const duplex = twoPathDuplex();

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(4);
    expect(sessionCommands(duplex)).toEqual([
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      `a6 UID FETCH 4805,4804,4803,4802 ${PAGE_ITEM_LIST}`,
      `a7 UID FETCH 4805,4803 (BODY.PEEK[1]<0.${SNIPPET_FETCH_OCTETS}>)`,
      `a8 UID FETCH 4804,4802 (BODY.PEEK[1.1]<0.${SNIPPET_FETCH_OCTETS}>)`,
      "a9 LOGOUT",
    ]);
  });

  it("parses a reply carrying the partial-fetch origin marker identically", async () => {
    // RFC 3501: a window starting at octet 0 comes back as a partial fetch even
    // when nothing was truncated, so the key carries an origin the plain form
    // does not. Both spellings must land in the same place.
    const rows = rowsFor([4801]);
    const build = (origin: boolean) =>
      listingDuplex(
        [
          searchReply("a5", [4801]),
          pageMetadataReply("a6", rows),
          snippetReply("a7", "1", rows, { origin }),
        ],
        "a8",
      );

    const withMarker = await listMessagesOver(
      build(true),
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );
    const without = await listMessagesOver(
      build(false),
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );

    expect(withMarker.messages[0]!.snippet).toBe(snippetTextFor(4801));
    expect(without.messages[0]!.snippet).toBe(withMarker.messages[0]!.snippet);
  });

  it("keeps a message with no selectable text part, with an empty snippet", async () => {
    // A snippet is a convenience. A message that is nothing but an attachment
    // has no readable part, and dropping the row would cost the caller the
    // message rather than the preview.
    const rows: PageRow[] = [{ uid: 4801, seq: 1, structure: NO_TEXT_STRUCTURE }];
    const duplex = listingDuplex(
      [searchReply("a5", [4801]), pageMetadataReply("a6", rows)],
      "a7",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(1);
    expect(page.messages[0]!.snippet).toBe("");
    expect(page.messages[0]!.hasAttachments).toBe(true);
    // No snippet command at all: there was no path to name.
    expect(commandVerbs(sessionCommands(duplex))).toEqual([
      "EXAMINE",
      "UID SEARCH",
      "UID FETCH",
      "LOGOUT",
    ]);
  });

  it("reports attachment PRESENCE from the structure, having fetched no body", async () => {
    // ATT-01's discipline applied to the listing: the flag comes from the same
    // BODYSTRUCTURE the snippet path resolves against, and the only body item
    // on the wire is a bounded window of the TEXT part.
    const rows: PageRow[] = [
      { uid: 4802, seq: 1, structure: NESTED_ALTERNATIVE_STRUCTURE },
      { uid: 4801, seq: 2 },
    ];
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802]),
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1.1", [rows[0]!]),
        snippetReply("a8", "1", [rows[1]!]),
      ],
      "a9",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages.map((one) => one.hasAttachments)).toEqual([true, false]);
    for (const line of duplex.writtenLines()) {
      expect(line).not.toContain("BODY.PEEK[]");
    }
  });
});

// ---------------------------------------------------------------------------
// The cursor contract (D-21 … D-25, T-02-12)
// ---------------------------------------------------------------------------

/**
 * What a server would report for a search over `folder`, given a constraint.
 *
 * The fixture models the SERVER honestly — it answers with the identifiers that
 * genuinely match — rather than replaying whatever the client happened to ask
 * for. That is what leaves room for the client to ask the wrong question, which
 * is why each case below also asserts the exact search command written: a
 * fixture that echoed the request could not tell an off-by-one from a correct
 * range, because it would return the same rows either way.
 */
function matching(folder: number[], below: number | null): number[] {
  return folder.filter((uid) => below === null || uid < below);
}

/**
 * A whole conversation for one page, given what the search matched.
 *
 * A page that comes back empty writes no metadata command and no snippet
 * command, so its logout carries an earlier tag — scripted here rather than
 * asserted around, because a fixture whose tags drift desynchronises the reader
 * and reads as a parser bug (the failure plan 02-07 found six of).
 */
function pageConversation(matched: number[], pageSize: number): FakeDuplex {
  const page = descending(matched).slice(0, pageSize);
  if (page.length === 0) {
    return listingDuplex([searchReply("a5", matched)], "a6");
  }
  const rows = rowsFor(page);
  return listingDuplex(
    [
      searchReply("a5", matched),
      pageMetadataReply("a6", rows),
      snippetReply("a7", "1", rows),
    ],
    "a8",
  );
}

describe("the cursor contract (D-21, D-24, D-25)", () => {
  it("returns the NEWEST page first when given no cursor", async () => {
    const duplex = pageConversation([4801, 4802, 4803, 4804], 2);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 2,
    });

    expect(page.messages.map((one) => one.uid)).toEqual([4804, 4803]);
    expect(duplex.writtenLines()[4]).toBe("a5 UID SEARCH ALL");
  });

  it("signals more results with a cursor, as two separately named fields", async () => {
    const duplex = pageConversation([4801, 4802, 4803, 4804], 2);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 2,
    });

    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).not.toBeNull();
    // Minted from the page's LAST identifier, and carrying the mailbox and the
    // validity the session actually reported.
    expect(decodeCursor(page.nextCursor!)).toEqual({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      lastUid: 4803,
    });
  });

  it("returns NO cursor when nothing remains, so a reader stops on the flag", async () => {
    // D-24's substance: a model reading `hasMore: false` stops without having
    // to reason about what a null cursor means.
    const duplex = pageConversation([4801, 4802], 25);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
    });

    expect(page.messages).toHaveLength(2);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  it("constrains the next page's search to values BELOW the cursor", async () => {
    const cursor = encodeCursor({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      lastUid: 4805,
    });
    const duplex = pageConversation([4801, 4802, 4803, 4804], 25);

    await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      cursor,
    });

    // Strictly below, so the cursor's own identifier is never re-requested.
    expect(duplex.writtenLines()[4]).toBe("a5 UID SEARCH UID 1:4804");
  });

  it("pages a folder to exhaustion with no duplicate and no omission", async () => {
    // The boundary case, and the one worth the machinery: the folder's
    // identifiers straddle each cursor exactly, so an inclusive range repeats a
    // message and an over-eager exclusive one skips the next.
    const folder = [1, 2, 3, 4, 5, 6, 7];
    const collected: number[] = [];
    const searches: string[] = [];
    let cursor: string | undefined;

    for (let call = 0; call < folder.length; call += 1) {
      const below = cursor === undefined ? null : decodeCursor(cursor).lastUid;
      const duplex = pageConversation(matching(folder, below), 3);

      const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
        ...FAST_BOUNDS,
        pageSize: 3,
        cursor,
      });

      searches.push(duplex.writtenLines()[4]!);
      collected.push(...page.messages.map((one) => one.uid));
      if (!page.hasMore) {
        expect(page.nextCursor).toBeNull();
        break;
      }
      expect(page.nextCursor).not.toBeNull();
      cursor = page.nextCursor!;
    }

    expect(collected).toEqual([7, 6, 5, 4, 3, 2, 1]);
    expect(new Set(collected).size).toBe(folder.length);
    expect(searches).toEqual([
      "a5 UID SEARCH ALL",
      "a5 UID SEARCH UID 1:4",
      "a5 UID SEARCH UID 1:1",
    ]);
  });

  it("anchors the cursor to the last identifier SEARCHED, not the last row returned", async () => {
    // A message expunged between the search and the metadata fetch is an
    // ordinary race on a live mailbox: the row simply does not appear. But if
    // the cursor were anchored to the last row RETURNED, the next page's range
    // would start above the gap and the vanished identifier would sit inside
    // the range forever — re-requested on every subsequent page for as long as
    // the caller keeps paging.
    //
    // Added because mutation P8 — anchoring to the last row — left the suite
    // entirely green, which made the docstring explaining the choice a
    // decoration rather than a claim anything checked.
    const rows = rowsFor([4805, 4804]);
    const duplex = listingDuplex(
      [
        searchReply("a5", [4801, 4802, 4803, 4804, 4805]),
        // The command covers 4805, 4804 AND 4803; the server answers for two.
        pageMetadataReply("a6", rows),
        snippetReply("a7", "1", rows),
      ],
      "a8",
    );

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 3,
    });

    expect(duplex.writtenLines()[5]).toContain("UID FETCH 4805,4804,4803 ");
    expect(page.messages.map((one) => one.uid)).toEqual([4805, 4804]);
    expect(page.hasMore).toBe(true);
    expect(decodeCursor(page.nextCursor!).lastUid).toBe(4803);
  });

  it("returns an empty page for a cursor resting on the lowest identifier", async () => {
    // Nothing sits below UID 1, and `1:0` is not a range any server has to
    // accept — so the guard is about what does NOT reach the wire.
    const cursor = encodeCursor({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      lastUid: 1,
    });
    const duplex = createFakeDuplex([...listingPrefix(), logoutExchange("a5")]);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      cursor,
    });

    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    expect(duplex.writtenLines().some((line) => line.includes("SEARCH"))).toBe(
      false,
    );
  });

  it("clamps a page size above the maximum rather than refusing it", async () => {
    // A refusal costs a round trip and teaches nothing; a clamp gives the
    // caller a usable answer on the first call.
    const folder = Array.from({ length: 150 }, (_value, index) => 5000 + index);
    const duplex = pageConversation(folder, PAGE_SIZE_MAX);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 500,
    });

    expect(page.messages).toHaveLength(PAGE_SIZE_MAX);
    expect(page.hasMore).toBe(true);
  });

  it("clamps a page size below one to the DEFAULT, not to one row", async () => {
    const folder = Array.from({ length: 40 }, (_value, index) => 5000 + index);
    const duplex = pageConversation(folder, PAGE_SIZE_DEFAULT);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 0,
    });

    expect(page.messages).toHaveLength(PAGE_SIZE_DEFAULT);
  });

  it("refuses a cursor naming a DIFFERENT mailbox, before opening anything", async () => {
    const cursor = encodeCursor({
      mailbox: "Archive",
      uidValidity: UIDVALIDITY,
      lastUid: 4805,
    });
    const duplex = createFakeDuplex([]);

    await expect(
      listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
        ...FAST_BOUNDS,
        cursor,
      }),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    // Refused for free: no greeting was read and no byte was written.
    expect(duplex.writtenLines()).toEqual([]);
  });

  it("refuses a token that is not a cursor at all", async () => {
    // The codec's kind discriminator, reached through this path. A message id
    // handed where a cursor belongs names a single message, not a position.
    const duplex = createFakeDuplex([]);

    await expect(
      listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
        ...FAST_BOUNDS,
        cursor: encodeMessageId(REF),
      }),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });
});

describe("the listing's UIDVALIDITY gate (D-23, MAIL-06, T-02-12)", () => {
  /** A cursor minted when the mailbox still had its original validity. */
  const STALE_CURSOR = encodeCursor({
    mailbox: MAILBOX,
    uidValidity: UIDVALIDITY,
    lastUid: 4805,
  });

  it("refuses a validity CHANGE, and writes no fetch before doing so", async () => {
    // Refusing is the only shape that literally forces a re-list. Silently
    // restarting from page one answers a question the caller did not ask, and a
    // model that misses the change believes it is still paging.
    const duplex = createFakeDuplex([
      ...listingPrefix({ uidValidity: UIDVALIDITY + 1 }),
      logoutExchange("a5"),
    ]);

    await expect(
      listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
        ...FAST_BOUNDS,
        cursor: STALE_CURSOR,
      }),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(
      duplex.writtenLines().some((line) => line.includes("FETCH")),
    ).toBe(false);
    expect(
      duplex.writtenLines().some((line) => line.includes("SEARCH")),
    ).toBe(false);
    // The session still tore down, so the connection is not leaked.
    expect(duplex.writtenLines()).toContain("a5 LOGOUT");
  });

  it("refuses an ABSENT validity code identically to a mismatch", async () => {
    // Fail closed. The RFC defines a missing UIDVALIDITY as "the server does
    // not support unique identifiers", which makes every identifier this page
    // would return meaningless.
    const duplex = createFakeDuplex([
      ...listingPrefix({ uidValidity: null }),
      logoutExchange("a5"),
    ]);

    await expect(
      listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
        ...FAST_BOUNDS,
        cursor: STALE_CURSOR,
      }),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(
      duplex.writtenLines().some((line) => line.includes("SEARCH")),
    ).toBe(false);
  });

  it("mints page one's cursor from the validity the SERVER reported", async () => {
    // Page one carries no cursor to compare against, so nothing is refused —
    // but the cursor it hands back has to carry this session's validity, or the
    // next page's gate would compare against a number nobody stated.
    const duplex = pageConversation([4801, 4802, 4803], 2);

    const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 2,
    });

    expect(decodeCursor(page.nextCursor!).uidValidity).toBe(UIDVALIDITY);
  });
});

// ---------------------------------------------------------------------------
// Search (MAIL-04, D-25 … D-28, criterion 4)
//
// The date range is where the single most likely correctness bug in search
// lives: the two IMAP bounds are asymmetric — one inclusive, one exclusive —
// and nothing in their names says so. A search that quietly drops the last day
// of a range looks entirely plausible in a response, which is why the four
// boundary days each get their own case rather than sharing one.
// ---------------------------------------------------------------------------

/** The continuation the server sends before a synchronizing literal's octets. */
const CONTINUATION = wire("+ Ready for additional command text");

/** Five JavaScript characters, eight UTF-8 bytes. */
const ACCENTED_TERM = "café☕";

/** A search conversation whose only literal is the term, then a normal page. */
function literalSearchConversation(matched: number[]): FakeDuplex {
  const page = descending(matched);
  if (page.length === 0) {
    return createFakeDuplex([
      ...listingPrefix(),
      CONTINUATION,
      searchReply("a5", matched),
      logoutExchange("a6"),
    ]);
  }
  const rows = rowsFor(page);
  return createFakeDuplex([
    ...listingPrefix(),
    CONTINUATION,
    searchReply("a5", matched),
    pageMetadataReply("a6", rows),
    snippetReply("a7", "1", rows),
    logoutExchange("a8"),
  ]);
}

/**
 * The search command an implementation writes for one set of criteria.
 *
 * Captured against a server that finds nothing, so the conversation ends after
 * the search and the command is the only thing under test. This is the
 * assertion that actually pins the date semantics: `SINCE` and `BEFORE` are
 * evaluated on Apple's hardware, so the whole of this client's contribution to
 * an inclusive range is the two arguments it emits.
 */
async function searchCommandFor(
  criteria: SearchCriteria,
  options: { cursor?: string } = {},
): Promise<string> {
  const duplex = listingDuplex([searchReply("a5", [])], "a6");
  await searchMessagesOver(duplex, principal, createSessionGate(), MAILBOX, criteria, {
    ...FAST_BOUNDS,
    ...options,
  });
  // [0] is the mailbox open, [1] is the search.
  return sessionCommands(duplex)[1]!;
}

/** One fixture message, on one of the four days the range turns on. */
interface DayMessage {
  uid: number;
  /** The day its INTERNALDATE falls on, as `YYYY-MM-DD`. */
  day: string;
}

/**
 * A folder holding exactly one message on each of the four boundary days.
 *
 * The start and end below are 1 February and 28 February, so these are: the day
 * before the start, the start itself, the end itself, and the day after.
 */
const RANGE_START = "2026-02-01";
const RANGE_END = "2026-02-28";
const DAY_MESSAGES: DayMessage[] = [
  { uid: 5104, day: "2026-01-31" },
  { uid: 5103, day: "2026-02-01" },
  { uid: 5102, day: "2026-02-28" },
  { uid: 5101, day: "2026-03-01" },
];

const MONTH_NAMES = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/** Read a `d-Mmm-yyyy` argument back into the day it names, in UTC. */
function parseImapDate(text: string): number {
  const match = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/.exec(text);
  expect(match, `not an IMAP date: ${text}`).not.toBeNull();
  const month = MONTH_NAMES.indexOf(match![2]!);
  expect(month, `not an English three-letter month: ${match![2]}`).toBeGreaterThan(-1);
  return Date.UTC(Number(match![3]), month, Number(match![1]));
}

/**
 * Which identifiers an RFC-conformant server returns for a written command.
 *
 * **This is an oracle for APPLE's behaviour, not a copy of this client's.** RFC
 * 3501 §6.4.4: `SINCE` matches messages whose internal date "is within or later
 * than the specified date" and `BEFORE` matches those "earlier than the
 * specified date", both disregarding time and timezone. That is one `>=` and one
 * `<` over whole days, and it is the whole of the server side.
 *
 * Reading the bounds out of the command the implementation ACTUALLY WROTE is
 * what makes the boundary cases below discriminating: an off-by-one in the
 * emitted `BEFORE` shifts what this returns, and the case then fails against a
 * literal expected list written from the caller's inclusive intent.
 */
function serverWouldMatch(command: string, folder: DayMessage[]): number[] {
  const since = /\bSINCE (\S+)/.exec(command);
  const before = /\bBEFORE (\S+)/.exec(command);
  const lower = since === null ? -Infinity : parseImapDate(since[1]!);
  const upper = before === null ? Infinity : parseImapDate(before[1]!);

  return folder
    .filter((one) => {
      const day = Date.parse(`${one.day}T00:00:00Z`);
      return day >= lower && day < upper;
    })
    .map((one) => one.uid);
}

/**
 * Run a dated search twice: once to capture the command, once for real.
 *
 * Two passes because the fake duplex is scripted before the command exists. The
 * first pass answers every search with nothing and yields the command; the
 * oracle above turns that command into what a conformant server would return;
 * the second pass replays exactly that.
 */
async function datedSearch(
  criteria: SearchCriteria,
  folder: DayMessage[] = DAY_MESSAGES,
): Promise<number[]> {
  const command = await searchCommandFor(criteria);
  const matched = serverWouldMatch(command, folder);
  const duplex = pageConversation(matched, PAGE_SIZE_DEFAULT);

  const page = await searchMessagesOver(
    duplex,
    principal,
    createSessionGate(),
    MAILBOX,
    criteria,
    FAST_BOUNDS,
  );
  return page.messages.map((one) => one.uid);
}

describe("the search command this client writes", () => {
  it("takes the quoted path for a plain ASCII term, with no charset clause", async () => {
    // Compared against the whole line rather than by fragments: the absence of
    // the charset clause, the key spelling and the quoting are one claim, and
    // asserting them separately would let a correct-looking command through.
    expect(await searchCommandFor({ keyword: "recruiter" })).toBe(
      'a5 UID SEARCH TEXT "recruiter"',
    );
  });

  it("writes no continuation handshake at all on the ASCII path", async () => {
    // The fixture answers the search directly, with no continuation anywhere in
    // the script. An implementation that waited for one would read the search
    // reply as its continuation and desynchronise — so this passes only if no
    // wait happened.
    const duplex = listingDuplex([searchReply("a5", [])], "a6");

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: "recruiter" },
      FAST_BOUNDS,
    );

    expect(page.messages).toEqual([]);
    expect(commandVerbs(sessionCommands(duplex))).toEqual([
      "EXAMINE",
      "UID SEARCH",
      "LOGOUT",
    ]);
  });

  it("maps the sender to the envelope FROM key", async () => {
    expect(await searchCommandFor({ sender: "jane@example.invalid" })).toBe(
      'a5 UID SEARCH FROM "jane@example.invalid"',
    );
  });

  it("sends the ALL key when there are no criteria at all", async () => {
    // The grammar demands `1*(SP search-key)`, so a search with nothing to say
    // still has to say something.
    expect(await searchCommandFor({})).toBe("a5 UID SEARCH ALL");
  });

  it("composes several criteria by intersection, in ONE command", async () => {
    // "When multiple keys are specified, the result is the intersection (AND
    // function) of all the messages that match those keys" — so the whole
    // search is one round trip however many filters the caller gave.
    const command = await searchCommandFor({
      keyword: "offer",
      sender: "jane@example.invalid",
      startDate: RANGE_START,
      endDate: RANGE_END,
      unreadOnly: true,
    });

    expect(command).toBe(
      "a5 UID SEARCH UNSEEN SINCE 1-Feb-2026 BEFORE 1-Mar-2026 " +
        'FROM "jane@example.invalid" TEXT "offer"',
    );
  });

  it("matches on the SERVER's received date, never the sender's own header", async () => {
    // `SENTSINCE`/`SENTBEFORE` read the stranger-authored `Date:` header, which
    // can be arbitrarily wrong or missing. `SINCE`/`BEFORE` read INTERNALDATE —
    // what a person means by "mail from last week", and the field a listing row
    // already reports, so a search row and a listing row cannot disagree.
    const command = await searchCommandFor({
      startDate: RANGE_START,
      endDate: RANGE_END,
    });

    expect(command).toContain("SINCE 1-Feb-2026");
    expect(command).toContain("BEFORE 1-Mar-2026");
    expect(command).not.toContain("SENTSINCE");
    expect(command).not.toContain("SENTBEFORE");
  });

  it("sends the caller's inclusive end date as an EXCLUSIVE bound one day later", async () => {
    // Stated on its own because it is the one asymmetry the parameter names do
    // not signpost. A month end, so a naive `+1` on the day number would
    // produce `29-Feb-2026` — a day that does not exist in 2026.
    expect(
      await searchCommandFor({ startDate: "2026-02-01", endDate: "2026-02-28" }),
    ).toContain("BEFORE 1-Mar-2026");
    // And across a year boundary, where the same naive arithmetic overflows the
    // month as well as the day.
    expect(
      await searchCommandFor({ startDate: "2026-12-01", endDate: "2026-12-31" }),
    ).toContain("BEFORE 1-Jan-2027");
  });

  it("refuses a date that is not a day of its month, before writing anything", async () => {
    // Added after mutation M14: removing the round-trip check inside the date
    // parser left every case green, because no fixture used an impossible date.
    // The gap is real and it is silent — `Date.UTC(2026, 1, 31)` rolls happily
    // forward to 3 March, so the search would run over a range shifted by two
    // days and report a confident, wrong answer. The schema's pattern cannot
    // catch this: `2026-02-31` is a well-formed `YYYY-MM-DD`.
    const duplex = createFakeDuplex([]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { startDate: "2026-02-01", endDate: "2026-02-31" },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toEqual([]);
    // Non-vacuous: the same range with a real last day is accepted.
    expect(
      await searchCommandFor({ startDate: "2026-02-01", endDate: "2026-02-28" }),
    ).toContain("BEFORE 1-Mar-2026");
  });

  it("uses the fixed English three-letter month names, whatever the locale", async () => {
    // Poisoned rather than merely inspected. A locale-aware formatter under an
    // English runtime produces the same three letters, so asserting the output
    // alone cannot tell a fixed table from `toLocaleDateString`. Making those
    // APIs throw for the duration is what turns "looks right here" into "cannot
    // be locale-dependent anywhere".
    const realToLocaleDate = Date.prototype.toLocaleDateString;
    const realToLocaleString = Date.prototype.toLocaleString;
    const poison = function poisoned(): string {
      throw new Error("a locale-aware formatter reached the date path");
    };
    Date.prototype.toLocaleDateString = poison;
    Date.prototype.toLocaleString = poison;

    try {
      for (let month = 0; month < 12; month += 1) {
        const iso = `2026-${String(month + 1).padStart(2, "0")}-15`;
        const command = await searchCommandFor({ startDate: iso, endDate: iso });
        expect(command).toContain(`SINCE 15-${MONTH_NAMES[month]}-2026`);
      }
    } finally {
      Date.prototype.toLocaleDateString = realToLocaleDate;
      Date.prototype.toLocaleString = realToLocaleString;
    }
  });
});

describe("the four boundary days of an inclusive range (PITFALLS #5)", () => {
  const CRITERIA: SearchCriteria = {
    startDate: RANGE_START,
    endDate: RANGE_END,
  };

  it("INCLUDES the start day itself", async () => {
    expect(await datedSearch(CRITERIA)).toContain(5103);
  });

  it("EXCLUDES the day before the start", async () => {
    expect(await datedSearch(CRITERIA)).not.toContain(5104);
  });

  it("INCLUDES the end day itself", async () => {
    // The clause an off-by-one silently drops. A caller asking for "1 February
    // through 28 February" and receiving nothing from the 28th has been given a
    // plausible, wrong answer.
    expect(await datedSearch(CRITERIA)).toContain(5102);
  });

  it("EXCLUDES the day after the end", async () => {
    expect(await datedSearch(CRITERIA)).not.toContain(5101);
  });

  it("returns exactly the two in-range days, newest first", async () => {
    // The four cases above each fail for one reason; this one states the whole
    // set, so a change that fixed one boundary by breaking another is caught.
    expect(await datedSearch(CRITERIA)).toEqual([5103, 5102]);
  });
});

describe("a non-ASCII search term takes the literal path", () => {
  it("declares the term's UTF-8 BYTE count, not its string length", async () => {
    // The single worst failure available here: too small and the server parses
    // the tail of the term as a new command; too large and it waits forever for
    // octets that never come.
    expect(ACCENTED_TERM.length).toBe(5);
    expect(ENCODER.encode(ACCENTED_TERM).byteLength).toBe(8);

    const duplex = literalSearchConversation([]);

    await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM },
      FAST_BOUNDS,
    );

    expect(sessionCommands(duplex)[1]).toBe(
      "a5 UID SEARCH CHARSET UTF-8 TEXT {8}",
    );
    expect(sessionCommands(duplex)[1]).not.toContain("{5}");
  });

  it("writes exactly that many raw bytes, then the command terminator", async () => {
    const duplex = literalSearchConversation([]);

    await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM },
      FAST_BOUNDS,
    );

    // Four preamble writes (CAPABILITY, LOGIN, CAPABILITY, EXAMINE), then the
    // literal head, the payload, the terminator, and LOGOUT.
    const payload = duplex.writes[5]!;
    expect(Array.from(payload)).toEqual(Array.from(ENCODER.encode(ACCENTED_TERM)));
    expect(payload.byteLength).toBe(8);
    expect(new TextDecoder().decode(duplex.writes[6]!)).toBe("\r\n");
  });

  it("carries the charset clause BEFORE the first key", async () => {
    const duplex = literalSearchConversation([]);

    await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM, unreadOnly: true },
      FAST_BOUNDS,
    );

    expect(sessionCommands(duplex)[1]).toBe(
      "a5 UID SEARCH CHARSET UTF-8 UNSEEN TEXT {8}",
    );
  });

  it("returns the page the server answered with, after the handshake", async () => {
    const duplex = literalSearchConversation([4802, 4801]);

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM },
      FAST_BOUNDS,
    );

    expect(page.messages.map((one) => one.uid)).toEqual([4802, 4801]);
    expect(page.unsupportedCharset).toBe(false);
  });

  it("takes the literal path for a term carrying a quoting hazard", async () => {
    // A double quote has no escaped form this client will construct: the
    // literal path length-prefixes the bytes, so the term cannot be
    // reinterpreted as command syntax at all (T-02-11).
    const duplex = literalSearchConversation([]);

    await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: 'the "offer" letter' },
      FAST_BOUNDS,
    );

    expect(sessionCommands(duplex)[1]).toBe(
      "a5 UID SEARCH CHARSET UTF-8 TEXT {18}",
    );
  });
});

describe("a null byte in a search term", () => {
  it("is refused before a single command is written", async () => {
    // `CHAR8 = %x01-ff` excludes it, so a NUL is not representable in a literal
    // at all. Refused at the boundary rather than at the wire, so the caller
    // gets a real answer instead of a protocol error — and refused before the
    // socket conversation starts, so it costs nothing.
    const duplex = createFakeDuplex([]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { keyword: "offer\u0000letter" },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toEqual([]);
  });

  it("is refused in the sender term too", async () => {
    const duplex = createFakeDuplex([]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { sender: "jane\u0000@example.invalid" },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toEqual([]);
  });
});

describe("a search that matched nothing", () => {
  it("is a SUCCESSFUL call returning zero rows", async () => {
    const duplex = listingDuplex([searchReply("a5", [])], "a6");

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: "nothing matches this" },
      FAST_BOUNDS,
    );

    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    expect(page.unsupportedCharset).toBe(false);
  });
});

describe("a charset rejection (T-02-37)", () => {
  /** The tagged NO the RFC specifies — explicitly not a BAD. */
  function badCharsetConversation(): FakeDuplex {
    return createFakeDuplex([
      ...listingPrefix(),
      CONTINUATION,
      taggedNo("a5", "[BADCHARSET (US-ASCII)] Unsupported charset"),
      logoutExchange("a6"),
    ]);
  }

  it("is a successful call with zero rows and an explicit field", async () => {
    // The search RAN; the server declined the encoding. No category in the
    // closed four-value vocabulary describes that: `not_found` would tell the
    // model the mailbox does not exist, and `connection_failed` would tell it to
    // retry something that will fail identically every time.
    const page = await searchMessagesOver(
      badCharsetConversation(),
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM },
      FAST_BOUNDS,
    );

    expect(page.unsupportedCharset).toBe(true);
    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  it("issues no metadata fetch after it, because there is nothing to fetch", async () => {
    const duplex = badCharsetConversation();

    await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: ACCENTED_TERM },
      FAST_BOUNDS,
    );

    expect(duplex.writtenLines().some((line) => line.includes("FETCH"))).toBe(
      false,
    );
    // The session still tore down cleanly rather than being abandoned.
    expect(duplex.writtenLines()).toContain("a6 LOGOUT");
  });

  it("still refuses a tagged NO that carries no such response code", async () => {
    // Added after mutation M11: widening the check to ANY tagged NO left every
    // case green, because no fixture carried a NO without the code. The gap is
    // real and it is the worse direction of the two — a server saying "no" for
    // its own reasons would be reported to the model as "your charset is
    // unsupported and there are no results", which is a plausible, wrong answer
    // that hides a genuine failure rather than surfacing it.
    const duplex = createFakeDuplex([
      ...listingPrefix(),
      CONTINUATION,
      taggedNo("a5", "Server unavailable, try again later"),
      logoutExchange("a6"),
    ]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { keyword: ACCENTED_TERM },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });

  it("still refuses a rejection that is NOT about the charset", async () => {
    // A `BAD` means the command was malformed, which is a real failure and must
    // not be dressed up as an empty result. Only the specified response code
    // takes the empty-result path.
    const duplex = createFakeDuplex([
      ...listingPrefix(),
      CONTINUATION,
      taggedBad("a5", "Invalid search criteria"),
      logoutExchange("a6"),
    ]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { keyword: ACCENTED_TERM },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });
});

describe("search pagination re-runs the search per page (D-25)", () => {
  it("sorts results descending client-side, relying on no server ordering", async () => {
    // The server answers in its own order — deliberately shuffled here, because
    // RFC 4731 warns a client "MUST NOT assume that messages/UIDs will be listed
    // in any particular order" and the classic response makes no promise either.
    const duplex = pageConversation([4803, 4801, 4805, 4802], PAGE_SIZE_DEFAULT);

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: "offer" },
      FAST_BOUNDS,
    );

    expect(page.messages.map((one) => one.uid)).toEqual([4805, 4803, 4802, 4801]);
  });

  it("constrains page two by an identifier range taken from the cursor", async () => {
    // Stateless: nothing is cached between pages, so nothing goes stale — and
    // the range key composes with the search keys by intersection, in the same
    // single command.
    const cursor = encodeCursor({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      lastUid: 4805,
    });

    expect(await searchCommandFor({ keyword: "offer" }, { cursor })).toBe(
      'a5 UID SEARCH UID 1:4804 TEXT "offer"',
    );
  });

  it("keeps the cursor small: one mailbox, one validity, one identifier", async () => {
    // A cursor carrying the whole result list would be enormous to hand a model
    // and would freeze a snapshot that silently drifts from the mailbox.
    const duplex = pageConversation([4801, 4802, 4803, 4804], 2);

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: "offer" },
      { ...FAST_BOUNDS, pageSize: 2 },
    );

    expect(decodeCursor(page.nextCursor!)).toEqual({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      lastUid: 4803,
    });
  });

  it("refuses a cursor minted for a different folder, before connecting", async () => {
    const duplex = createFakeDuplex([]);

    await expect(
      searchMessagesOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        { keyword: "offer" },
        {
          ...FAST_BOUNDS,
          cursor: encodeCursor({
            mailbox: "Archive",
            uidValidity: UIDVALIDITY,
            lastUid: 4805,
          }),
        },
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(duplex.writtenLines()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The unread listing (MAIL-05, D-17, D-27)
//
// D-17 gave this its own tool NAME and said in the same breath that it "shares
// the list implementation internally rather than duplicating it". The cases
// below assert that sharing on the wire rather than trusting it: a second
// paging implementation would drift in the ordering and the cursor arithmetic,
// which are exactly the parts nobody re-reads.
// ---------------------------------------------------------------------------

describe("the unread listing shares the listing implementation", () => {
  it("writes the SAME command sequence as a plain listing, plus one criterion", async () => {
    // The assertion the plan asks for, written as a diff rather than as a
    // count: a failure names WHICH command differs, and a reimplementation that
    // happened to issue the same number of commands still fails.
    const listed = pageConversation([4801, 4802], PAGE_SIZE_DEFAULT);
    await listMessagesOver(listed, principal, createSessionGate(), MAILBOX, FAST_BOUNDS);

    const unread = pageConversation([4801, 4802], PAGE_SIZE_DEFAULT);
    await listUnreadOver(unread, principal, createSessionGate(), MAILBOX, FAST_BOUNDS);

    const listedCommands = sessionCommands(listed);
    const unreadCommands = sessionCommands(unread);

    expect(unreadCommands).toHaveLength(listedCommands.length);
    expect(
      listedCommands.filter((line, index) => line !== unreadCommands[index]),
    ).toEqual(["a5 UID SEARCH ALL"]);
    expect(unreadCommands[1]).toBe("a5 UID SEARCH UNSEEN");
  });

  it("opens exactly ONE session and exactly one mailbox", async () => {
    // D-27's cost shape, and the reason the account-wide sweep was not built:
    // one mailbox open and one search per folder, serialised on a single
    // connection, against a twenty-second call deadline.
    const duplex = pageConversation([4801, 4802], PAGE_SIZE_DEFAULT);

    await listUnreadOver(duplex, principal, createSessionGate(), MAILBOX, FAST_BOUNDS);

    const lines = duplex.writtenLines();
    expect(lines.filter((line) => line.includes("EXAMINE"))).toHaveLength(1);
    expect(lines.filter((line) => line.includes("LOGIN"))).toHaveLength(1);
    expect(commandVerbs(sessionCommands(duplex))).toEqual([
      "EXAMINE",
      "UID SEARCH",
      "UID FETCH",
      "UID FETCH",
      "LOGOUT",
    ]);
  });

  it("defaults to the inbox when no folder is named", async () => {
    const duplex = pageConversation([], PAGE_SIZE_DEFAULT);

    await listUnreadOver(duplex, principal, createSessionGate(), undefined, FAST_BOUNDS);

    expect(sessionCommands(duplex)[0]).toBe('a4 EXAMINE "INBOX"');
  });

  it("takes an explicit folder when one is named", async () => {
    const duplex = pageConversation([], PAGE_SIZE_DEFAULT);

    await listUnreadOver(duplex, principal, createSessionGate(), "Archive", FAST_BOUNDS);

    expect(sessionCommands(duplex)[0]).toBe('a4 EXAMINE "Archive"');
  });

  it("yields an empty array and a false has-more for a folder with no unread", async () => {
    const duplex = pageConversation([], PAGE_SIZE_DEFAULT);

    const page = await listUnreadOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );

    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  it("orders newest first, because it is the SAME implementation", async () => {
    // No second ordering rule exists to drift, and this is what says so: the
    // server answers in a shuffled order and the rows come back descending.
    const duplex = pageConversation([4802, 4805, 4801, 4803], PAGE_SIZE_DEFAULT);

    const page = await listUnreadOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );

    expect(page.messages.map((one) => one.uid)).toEqual([4805, 4803, 4802, 4801]);
  });
});

describe("paging unread across a message that becomes read", () => {
  it("drops it with no duplicate and no skip", async () => {
    // The subtle one. The unread criterion and the cursor's identifier range
    // compose by INTERSECTION in a single command, so a message that stops
    // being unread between two pages simply stops matching — it does not shift
    // the window, and nothing after it is skipped.
    const firstPage = pageConversation([4805, 4804, 4803, 4802, 4801], 2);
    const one = await listUnreadOver(
      firstPage,
      principal,
      createSessionGate(),
      MAILBOX,
      { ...FAST_BOUNDS, pageSize: 2 },
    );

    expect(one.messages.map((row) => row.uid)).toEqual([4805, 4804]);
    expect(one.hasMore).toBe(true);
    expect(decodeCursor(one.nextCursor!).lastUid).toBe(4804);

    // Between the pages 4803 is read in Mail.app, so the server's second answer
    // no longer carries it. Nothing else changed.
    const secondPage = pageConversation([4802, 4801], 2);
    const two = await listUnreadOver(secondPage, principal, createSessionGate(), MAILBOX, {
      ...FAST_BOUNDS,
      pageSize: 2,
      cursor: one.nextCursor!,
    });

    // The second page's search carries BOTH keys — the range from the cursor
    // and the unread criterion — which is what makes the drop-out lossless.
    expect(sessionCommands(secondPage)[1]).toBe("a5 UID SEARCH UID 1:4803 UNSEEN");

    const seen = [
      ...one.messages.map((row) => row.uid),
      ...two.messages.map((row) => row.uid),
    ];
    // No duplicate...
    expect(new Set(seen).size).toBe(seen.length);
    // ...and no skip among the identifiers that were still unread. 4803 is
    // absent because it stopped being unread, which is the correct answer.
    expect(seen).toEqual([4805, 4804, 4802, 4801]);
  });
});

describe("one attempt per guess, on the login path only (D6)", () => {
  // Every assertion in this block is a COUNT, never a line. Both authentication
  // command lines carry the pool's ambient credential — the first one inline,
  // the fallback inside its base64 initial response — and a failed assertion on
  // the lines themselves would print them. The gate block above counts for
  // exactly this reason.
  const firstAttempts = (lines: string[]): number =>
    lines.filter((line) => /^\S+ LOGIN /.test(line)).length;
  const fallbackAttempts = (lines: string[]): number =>
    lines.filter((line) => /^\S+ AUTHENTICATE /.test(line)).length;

  /**
   * A conversation that refuses the first authentication attempt.
   *
   * `fallbackText` is the reply to the fallback attempt, and is left out for
   * the cases that must never make one. Leaving it out is load-bearing: a
   * script that answered anyway would let an unwanted second attempt pass on a
   * reply the fixture happened to provide, and the count below is the only
   * thing that would have noticed.
   */
  function refusedAuth(firstText: string, fallbackText?: string): FakeDuplex {
    const fallback =
      fallbackText === undefined ? [] : [taggedNo("a3", fallbackText)];
    return createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", firstText),
      ...fallback,
      logoutExchange(fallbackText === undefined ? "a3" : "a4"),
    ]);
  }

  /** The login proof's own shape: no mailbox, so nothing but the credential. */
  function proveOver(
    duplex: FakeDuplex,
    options: MailSessionOptions,
  ): Promise<string> {
    return withMailSessionOver(
      duplex,
      principal,
      createSessionGate(),
      null,
      null,
      async () => "unreached",
      options,
    );
  }

  it("falls back a second time when nothing asked it not to", async () => {
    // The default, and the half of the pair that pins today's behaviour. Every
    // tool call takes this path: a tool call is not a guess, so it keeps both
    // mechanisms.
    const duplex = refusedAuth(AUTH_REJECTED_LEGACY_TEXT, AUTH_REJECTED_TEXT);

    await expect(proveOver(duplex, FAST_BOUNDS)).rejects.toBeInstanceOf(
      ImapAuthError,
    );

    expect(firstAttempts(duplex.writtenLines())).toBe(1);
    expect(fallbackAttempts(duplex.writtenLines())).toBe(1);
  });

  it("spends one attempt at Apple when the login path asks for one", async () => {
    // The other half. A wrong password costs Apple two attempts by default and
    // one here, which is the whole of what D6 buys — and the error the caller
    // sees is the same one either way, so the page's message mapping does not
    // have to know which path it was on.
    const duplex = refusedAuth(AUTH_REJECTED_LEGACY_TEXT);

    await expect(
      proveOver(duplex, { ...FAST_BOUNDS, oneAttemptPerGuess: true }),
    ).rejects.toBeInstanceOf(ImapAuthError);

    expect(firstAttempts(duplex.writtenLines())).toBe(1);
    expect(fallbackAttempts(duplex.writtenLines())).toBe(0);
  });

  it("still raises the throttle error, and still writes no second line", async () => {
    // The classification is unchanged by the flag, and it still reads the
    // parsed tagged reply rather than a caught value. A server refusing on
    // availability grounds must not be reported as a bad password: the login
    // page branches on the error type, and this is the type it branches on.
    const duplex = refusedAuth(CONNECTION_LIMIT_TEXT);

    await expect(
      proveOver(duplex, { ...FAST_BOUNDS, oneAttemptPerGuess: true }),
    ).rejects.toBeInstanceOf(ImapThrottleError);

    expect(firstAttempts(duplex.writtenLines())).toBe(1);
    expect(fallbackAttempts(duplex.writtenLines())).toBe(0);
  });

  it("changes nothing on a conversation that authenticates first time", async () => {
    // Non-vacuity for the flag itself: it suppresses a fallback and nothing
    // else. An implementation that skipped the fallback by refusing earlier
    // would pass all three cases above and fail this one.
    const duplex = happyPathDuplex();

    await expect(
      withMailSessionOver(
        duplex,
        principal,
        createSessionGate(),
        MAILBOX,
        null,
        async () => "done",
        { ...FAST_BOUNDS, oneAttemptPerGuess: true },
      ),
    ).resolves.toBe("done");

    expect(firstAttempts(duplex.writtenLines())).toBe(1);
    expect(fallbackAttempts(duplex.writtenLines())).toBe(0);
  });
});

describe("a NO to the mailbox open", () => {
  it("is not_found, the same as every other unreachable resource", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      taggedNo("a4", "[NONEXISTENT] Unknown Mailbox"),
      logoutExchange("a5"),
    ]);

    await expect(
      getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });
});
