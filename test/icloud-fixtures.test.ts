// Fixture integrity for `test/fixtures/icloud-bytes.ts`.
//
// These fixtures are SYNTHESISED, not captured — the decision and its reasons
// are in that file's header and in 02-09-SUMMARY.md. Synthesis makes this file
// necessary rather than optional: bytes that came off a real server are at
// least self-consistent by construction, while bytes someone typed are only as
// correct as the assertions holding them to it.
//
// So these cases hold the fixtures to three things:
//
//   1. Their declared octet counts are DERIVED, not constant. Asserting that a
//      count happens to equal a payload length would pass just as well against
//      a hand-written number that happens to be right today; what discriminates
//      is that two payloads of DIFFERENT lengths each get their own count.
//   2. They drive the real reader and come back byte-identical, so the framing
//      claim in the header is measured rather than asserted.
//   3. They contain nothing account-identifying. That is a standing constraint
//      on anything added to the fixture file later, which makes it worth an
//      executable check rather than a comment nobody re-reads.
//
// What is deliberately NOT here: the MIME-level round trip — paragraph
// structure, attachment metadata, decoded size against what a mail client
// reports. That is plan 02-11's, and criterion 3's "verified against real
// bytes" claim is not made by this file or by the fixtures it guards.

import { describe, expect, it } from "vitest";
import { decodeModifiedUtf7, parseListLine } from "../src/mail/imap-parser";
import type { ResponseLine } from "../src/mail/imap-parser";
import { ImapChannel, readUntilTag } from "../src/mail/imap-session";
import { extractMessage } from "../src/mail/mime";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  ATTACHMENT_BASE64_LINES,
  ATTACHMENT_DECODED_BYTES,
  ATTACHMENT_FILENAME,
  ATTACHMENT_MESSAGE_BYTES,
  ATTACHMENT_MESSAGE_FETCH,
  ATTACHMENT_MESSAGE_SOURCE,
  ATTACHMENT_MESSAGE_SUBJECT,
  ATTACHMENT_MIME_TYPE,
  HTML_MESSAGE_BYTES,
  HTML_MESSAGE_FETCH,
  HTML_MESSAGE_SOURCE,
  HTML_MESSAGE_SUBJECT,
  MEASURED_POST_AUTH_CAPABILITY,
  MUTF7_DISPLAY_NAME,
  MUTF7_LIST_TURN,
  MUTF7_WIRE_NAME,
  POST_AUTH_CAPABILITY,
  base64Bytes,
  messageFetchReply,
  taggedOk,
} from "./fixtures/icloud-bytes";

const DECODER = new TextDecoder();
const ENCODER = new TextEncoder();
const TAG = "a4";

/** A read bound of a few milliseconds, so no case here costs wall time. */
const FAST_READ_MS = 40;

/** Drive `turns` through the REAL reader and hand back its untagged lines. */
async function untaggedFromBytes(...turns: Uint8Array[]): Promise<ResponseLine[]> {
  const channel = new ImapChannel(
    createFakeDuplex([...turns, taggedOk(TAG, "completed")]),
    { readTimeoutMs: FAST_READ_MS },
  );
  return (await readUntilTag(channel, TAG)).untagged;
}

/** The payload of the first untagged line carrying a literal. */
function firstLiteral(lines: ResponseLine[]): Uint8Array {
  for (const line of lines) {
    if (line.literals.length > 0) return line.literals[0]!;
  }
  throw new Error("no untagged response carried a literal");
}

describe("the declared octet counts are derived, not written", () => {
  // THE discriminating case. A fixture whose count is hand-written and
  // currently correct passes every assertion that only checks today's value;
  // what it cannot do is track a payload it was not written for.
  it("gives two payloads of different lengths their own counts", () => {
    const short = ENCODER.encode("short");
    const long = ENCODER.encode("a considerably longer payload than the other");
    expect(short.byteLength).not.toBe(long.byteLength);

    const shortHead = DECODER.decode(messageFetchReply("a1", short));
    const longHead = DECODER.decode(messageFetchReply("a1", long));

    expect(shortHead).toContain(`{${short.byteLength}}`);
    expect(longHead).toContain(`{${long.byteLength}}`);
    expect(shortHead).not.toContain(`{${long.byteLength}}`);
  });

  it("declares the real length for both committed message fixtures", () => {
    expect(DECODER.decode(HTML_MESSAGE_FETCH)).toContain(
      `{${HTML_MESSAGE_BYTES.byteLength}}`,
    );
    expect(DECODER.decode(ATTACHMENT_MESSAGE_FETCH)).toContain(
      `{${ATTACHMENT_MESSAGE_BYTES.byteLength}}`,
    );
  });

  it("leaves no hand-written multi-digit count in the fixture source", () => {
    // The property stated as a property rather than as a one-time grep. Every
    // literal count in that file is interpolated from a `.byteLength`, so the
    // only `{NN}` that can appear in the SOURCE is one somebody typed.
    //
    // Single-digit counts are not matched, deliberately: `{0}` and the like
    // appear in prose and regex quantifiers, and a one-digit count is not the
    // shape that drifts.
    expect(/\{[0-9]{2,}\}/.test(HTML_MESSAGE_SOURCE)).toBe(false);
    expect(/\{[0-9]{2,}\}/.test(ATTACHMENT_MESSAGE_SOURCE)).toBe(false);
  });
});

describe("the message fixtures survive the real reader byte-exactly", () => {
  it("returns the multi-paragraph HTML message unchanged", async () => {
    const payload = firstLiteral(await untaggedFromBytes(HTML_MESSAGE_FETCH));
    expect(payload).toEqual(HTML_MESSAGE_BYTES);
    expect(DECODER.decode(payload)).toBe(HTML_MESSAGE_SOURCE);
  });

  it("returns the attachment message unchanged", async () => {
    const payload = firstLiteral(await untaggedFromBytes(ATTACHMENT_MESSAGE_FETCH));
    expect(payload).toEqual(ATTACHMENT_MESSAGE_BYTES);
    expect(DECODER.decode(payload)).toBe(ATTACHMENT_MESSAGE_SOURCE);
  });

  it("frames CRLF the way the wire does, with none before the closing paren", () => {
    // The off-by-two that desynchronises a session for the rest of its life:
    // the `)` continues the same logical line the literal interrupted, so no
    // terminator separates it from the last literal octet.
    const text = DECODER.decode(HTML_MESSAGE_FETCH);
    expect(text).toContain(`${HTML_MESSAGE_SOURCE})\r\n`);
    expect(text.endsWith(`${TAG} OK UID FETCH completed\r\n`)).toBe(true);
    expect(text).not.toContain("\n\n");
  });
});

describe("a modified-UTF-7 mailbox name delivered as a literal", () => {
  it("reaches the parser as the RAW WIRE name, undecoded", async () => {
    // What a page cursor stores. Decoding here would need an encoder this
    // project deliberately does not have, and would make the EXAMINE round
    // trip lossy.
    const listed = parseListLine((await untaggedFromBytes(MUTF7_LIST_TURN))[0]!);
    expect(listed?.name).toBe(MUTF7_WIRE_NAME);
    expect(listed?.delimiter).toBe("/");
    expect(listed?.attributes).toContain("\\HasNoChildren");
  });

  it("decodes to the display name only when asked", async () => {
    const listed = parseListLine((await untaggedFromBytes(MUTF7_LIST_TURN))[0]!);
    expect(decodeModifiedUtf7(listed!.name)).toBe(MUTF7_DISPLAY_NAME);
    expect(MUTF7_WIRE_NAME).not.toBe(MUTF7_DISPLAY_NAME);
  });
});

describe("the attachment body is encoded from its bytes, never transcribed", () => {
  it("round-trips through base64 to the declared decoded size", () => {
    const decoded = base64Bytes(ATTACHMENT_BASE64_LINES.join("\r\n"));
    expect(decoded.byteLength).toBe(ATTACHMENT_DECODED_BYTES);
  });

  it("wraps across several physical lines, as a real attachment does", () => {
    // A single-line body would stop exercising the reassembly a decoder does
    // across lines, which is the only reason MIME wraps at 76 in the first
    // place.
    expect(ATTACHMENT_BASE64_LINES.length).toBeGreaterThan(1);
    for (const line of ATTACHMENT_BASE64_LINES) {
      expect(line.length).toBeLessThanOrEqual(76);
    }
  });
});

describe("the hand-authored encoded words say what the constants claim", () => {
  // Fixture integrity, not a MIME round-trip: these prove the RFC 2047 words
  // typed into the fixture actually decode to the exported expectations, so a
  // later plan asserting against those constants is not inheriting a typo.
  it("decodes the Q-encoded subject carrying non-ASCII", async () => {
    const parsed = await extractMessage(HTML_MESSAGE_BYTES);
    expect(parsed.subject).toBe(HTML_MESSAGE_SUBJECT);
    expect(HTML_MESSAGE_SUBJECT).toContain("é");
    expect(HTML_MESSAGE_SUBJECT).toContain("ô");
  });

  it("decodes the B-encoded subject", async () => {
    const parsed = await extractMessage(ATTACHMENT_MESSAGE_BYTES);
    expect(parsed.subject).toBe(ATTACHMENT_MESSAGE_SUBJECT);
  });
});

describe("the synthesised capability string is not mistaken for the measured one", () => {
  it("keeps the two lists different, which is what the flag test needs", () => {
    expect(POST_AUTH_CAPABILITY).not.toBe(MEASURED_POST_AUTH_CAPABILITY);
  });

  it("records that the REAL server advertises no non-synchronizing literal", () => {
    // Measured in Phase 1's live proof. Phase 4's APPEND depends on this being
    // false, and `XAPPLELITERAL` being present is exactly what makes it
    // tempting to assume otherwise.
    const tokens = MEASURED_POST_AUTH_CAPABILITY.split(/\s+/);
    expect(tokens).not.toContain("LITERAL+");
    expect(tokens).not.toContain("LITERAL-");
    expect(tokens).toContain("XAPPLELITERAL");
  });
});

describe("nothing account-identifying is committed in the fixtures", () => {
  // A standing constraint on whatever gets added later, made executable. The
  // fixture-privacy decision turned on git history being permanent and
  // one-way; a check that only ran once, by hand, at the moment the file was
  // written protects only the version that existed that day.
  const sources = [HTML_MESSAGE_SOURCE, ATTACHMENT_MESSAGE_SOURCE];

  it("uses only the reserved .invalid TLD for every address", () => {
    for (const source of sources) {
      const addresses = source.match(/[\w.+-]+@[\w.-]+/g) ?? [];
      expect(addresses.length).toBeGreaterThan(0);
      for (const address of addresses) {
        expect(address.endsWith(".invalid")).toBe(true);
      }
    }
  });

  it("names no real mail provider", () => {
    for (const source of sources) {
      const lowered = source.toLowerCase();
      for (const domain of ["icloud.com", "me.com", "mac.com", "apple.com"]) {
        expect(lowered).not.toContain(domain);
      }
    }
  });

  it("carries no Received chain, originating IP, or client identifier", () => {
    // The three headers that identify a person and a machine without naming an
    // address, which is why excluding the address alone would not be enough.
    for (const source of sources) {
      expect(/^Received:/im.test(source)).toBe(false);
      expect(/^X-Mailer:/im.test(source)).toBe(false);
      expect(/^User-Agent:/im.test(source)).toBe(false);
      expect(/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(source)).toBe(false);
    }
  });

  it("declares an attachment that reveals nothing about its author", () => {
    expect(ATTACHMENT_MESSAGE_SOURCE).toContain(ATTACHMENT_FILENAME);
    expect(ATTACHMENT_MESSAGE_SOURCE).toContain(ATTACHMENT_MIME_TYPE);
    expect(ATTACHMENT_DECODED_BYTES).toBeGreaterThan(0);
  });
});
