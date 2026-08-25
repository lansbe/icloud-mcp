// Deliberately hostile server turns, for the byte-counted reader.
//
// PROVENANCE — read this before treating any byte here as evidence.
//
// Every byte in this file is CONSTRUCTED. None of it was captured from
// `imap.mail.me.com` and none of it should be: these are protocol probes, not
// correspondence. The headline payload below contains a line spelling a tagged
// command completion, which is the shape an attacker composes to desynchronise
// a line-splitting reader — sending that through a real mail server to capture
// what came back would be the wrong way to obtain it, and would put hostile
// content into a real mailbox to do it.
//
// What these pin is the SHAPE of the failure, and the shape is what the reader
// gets right or wrong. No assertion built on them depends on a token only
// Apple could have produced.
//
// EVERY DECLARED OCTET COUNT IS DERIVED from its payload's actual byte length
// at build time. A hand-written count silently invalidates itself the moment
// anyone edits the payload, and a fixture with a wrong count teaches the parser
// the wrong framing — which is worse than having no fixture at all, because it
// fails in the direction of a green suite.

import { MAX_LITERAL_OCTETS } from "../../src/mail/imap-session";

const ENCODER = new TextEncoder();

/** Join lines with CRLF terminators and encode them as one server turn. */
export function wire(...lines: string[]): Uint8Array {
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

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
 * A FETCH reply carrying `payload` as a literal, framed with a derived count.
 *
 * Note where the CRLFs are and are not. There is none between the last literal
 * octet and the `)` that follows it: that `)` is the continuation of the SAME
 * logical line the `* 1 FETCH (` opened, and a reader that consumed a
 * terminator there would be off by two bytes for the rest of the session.
 */
export function fetchWithLiteral(
  tag: string,
  payload: Uint8Array,
  options: { uid?: number; declaredOctets?: number } = {},
): Uint8Array {
  const declared = options.declaredOctets ?? payload.byteLength;
  const head =
    `* 1 FETCH (UID ${options.uid ?? 4827} ` +
    `RFC822.SIZE ${payload.byteLength} BODY[] {${declared}}\r\n`;

  return concatBytes(
    ENCODER.encode(head),
    payload,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/**
 * The tagged completion this account's attacker would forge, spelled out.
 *
 * Tags are issued `a1`, `a2`, `a3`… from an instance counter, so they are
 * trivially predictable — which is exactly what makes this line composable by
 * anyone who can send mail to the account.
 */
export const FORGED_COMPLETION = "a5 OK UID FETCH completed";

/**
 * A message body containing a forged tagged completion on a line of its own.
 *
 * Surrounded by ordinary paragraphs, because a payload that was nothing but the
 * forgery would let an implementation "pass" by refusing anything that looks
 * like a completion — which is not the fix and would break real mail discussing
 * IMAP.
 */
export const HOSTILE_BODY = [
  "From: mallory@example.invalid",
  "Subject: about that protocol question",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Here is the transcript you asked about:",
  "",
  FORGED_COMPLETION,
  "",
  "and the session was desynchronised from that point onwards.",
  "",
].join("\r\n");

/** The hostile body, framed as a FETCH reply with a derived count. */
export const HOSTILE_FETCH = fetchWithLiteral(
  "a5",
  ENCODER.encode(HOSTILE_BODY),
);

/**
 * The hostile fetch followed by a SECOND, ordinary command exchange.
 *
 * The forged completion is BYTE-IDENTICAL to the real one, which is the whole
 * point of forging it — a test comparing only the returned tagged text cannot
 * tell the two apart and would pass against a line-splitting reader. What
 * distinguishes them is where the stream is left standing afterwards: a reader
 * that returned at the forgery leaves the rest of the body unread, and the next
 * command's reader then consumes attacker-chosen text as protocol.
 *
 * So the discriminating assertion is not about the first reply at all. It is
 * whether the SECOND command gets its own answer.
 */
export function hostileThenNextCommand(
  firstTag: string,
  secondTag: string,
): Uint8Array {
  return concatBytes(
    fetchWithLiteral(firstTag, ENCODER.encode(HOSTILE_BODY)),
    wire(
      "* CAPABILITY IMAP4rev1 UIDPLUS",
      `${secondTag} OK CAPABILITY completed`,
    ),
  );
}

/**
 * Bytes that are not valid UTF-8, wrapped in base64-looking text.
 *
 * `0xFF`, `0xFE` and a bare continuation byte cannot appear in well-formed
 * UTF-8, so a reader that decoded this to a string and handed the string back
 * would return U+FFFD where these are — irrecoverably, and with the byte count
 * no longer matching what arrived. That is the assertion the byte-identity case
 * makes, and it is the reason `readOctets` returns `Uint8Array`.
 */
export const BINARY_PAYLOAD = concatBytes(
  ENCODER.encode("SGVsbG8="),
  new Uint8Array([0xff, 0xfe, 0x80, 0x00, 0xc0, 0xaf]),
  ENCODER.encode("dHJhaWxpbmc="),
);

/** The binary payload, framed as a FETCH reply. */
export const BINARY_FETCH = fetchWithLiteral("a5", BINARY_PAYLOAD);

/**
 * A literal declaring more octets than the reader will keep.
 *
 * The payload really is that long, because the property under test is that all
 * of it is CONSUMED while only the capped prefix is kept. A fixture that
 * declared a huge count and sent a short payload would test a different thing
 * entirely — a truncated literal — and would pass against an implementation
 * that abandoned the read.
 *
 * The tail is recognisable so a test can prove the discarded end really was
 * discarded rather than silently kept.
 */
export const OVERSIZE_OCTETS = MAX_LITERAL_OCTETS + 4096;
export const OVERSIZE_TAIL = "THE-DISCARDED-TAIL";

export function oversizePayload(): Uint8Array {
  const payload = new Uint8Array(OVERSIZE_OCTETS).fill(0x61);
  payload.set(ENCODER.encode(OVERSIZE_TAIL), OVERSIZE_OCTETS - OVERSIZE_TAIL.length);
  return payload;
}

/**
 * An over-large literal followed by a SECOND, ordinary command exchange.
 *
 * The second half is the important half. Consuming past the cap keeps the
 * stream synchronised; abandoning the read would leave the remainder to be
 * misparsed as commands, and the only way to see the difference is to ask the
 * next command whether it still got its own answer.
 */
export function oversizeThenNextCommand(
  firstTag: string,
  secondTag: string,
): Uint8Array {
  return concatBytes(
    fetchWithLiteral(firstTag, oversizePayload()),
    wire(`* CAPABILITY IMAP4rev1 UIDPLUS`, `${secondTag} OK CAPABILITY completed`),
  );
}

/**
 * The count declared by the literal whose octets never arrive.
 *
 * This is the ONE count in this file not derived from a payload, and it cannot
 * be: the whole point of the fixture is that no payload follows. Naming it
 * rather than spelling it inline is what keeps it honest — the test can assert
 * against the same constant, so there is still exactly one place the number
 * lives and nothing to drift out of sync with.
 */
export const NEVER_ARRIVING_OCTETS = 5000;

/**
 * A literal head whose octets never arrive.
 *
 * Only the head is here — the fixture that replays it must go SILENT
 * afterwards rather than ending, because a readable that ends produces a
 * different failure (a short literal) on a different code path.
 */
export const TRUNCATED_LITERAL_HEAD = ENCODER.encode(
  `* 1 FETCH (UID 4827 BODY[] {${NEVER_ARRIVING_OCTETS}}\r\n`,
);

/**
 * A CRLF-heavy multipart body, for the reassembly assertion.
 *
 * Twenty-odd physical lines inside one literal inside one logical response. A
 * line-splitting reader turns this into twenty-odd unparseable fragments; a
 * byte-counting one sees a single response with one payload.
 */
export const MULTIPART_BODY = [
  "From: jane.doe@example.invalid",
  "Subject: multipart, deliberately CRLF-heavy",
  "MIME-Version: 1.0",
  'Content-Type: multipart/alternative; boundary="B1"',
  "",
  "--B1",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Paragraph one.",
  "",
  "Paragraph two.",
  "",
  "Paragraph three.",
  "",
  "--B1",
  "Content-Type: text/html; charset=utf-8",
  "",
  "<html><body><p>Paragraph one.</p>",
  "<p>Paragraph two.</p>",
  "<p>Paragraph three.</p>",
  "</body></html>",
  "",
  "--B1--",
  "",
].join("\r\n");

/** The multipart body, framed as a FETCH reply with a derived count. */
export const MULTIPART_FETCH = fetchWithLiteral(
  "a5",
  ENCODER.encode(MULTIPART_BODY),
);
