// The attachment part fetch, and the silent-truncation gap it would otherwise
// have inherited.
//
// This file exists because of one line of shipped Phase 2 code:
// `const keepLimit = Math.min(n, MAX_LITERAL_OCTETS)`. That bound governs what
// a literal read KEEPS, not what it REFUSES — everything past the ceiling is
// consumed and discarded, and the caller receives a short `Uint8Array` with no
// flag, no error, and no signal of any kind. The whole-message read path is
// protected because the service pre-checks `RFC822.SIZE` and takes a different
// branch; a part-scoped attachment fetch has no such pre-check, because until
// this plan no such fetch existed.
//
// A transfer-encoded part cut mid-stream does not fail. It decodes to a corrupt
// PREFIX of a real file — a PDF that opens, renders its first pages, and is
// wrong — and the user then attaches it to an outgoing message. That failure is
// undetectable from the outside, which is why the disposition here is a stated
// refusal rather than a truncation flag. `MAX_EXTRACTED_TEXT_BYTES` truncates
// and flags because on a READ path a partial answer is still an answer; on this
// path a partial attachment is a corrupt file, and the two are not the same
// shape of problem.
//
// The load-bearing assertions are therefore on the RECORDED WRITE LIST rather
// than on a return value: the property is that no fetch command line is ever
// written for an over-size part. A case that only inspected the result would
// pass against an implementation that fetched first and refused afterwards,
// which spends the bytes this refusal exists to save.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09).

import { beforeAll, describe, expect, it } from "vitest";
import { ImapNotFoundError } from "../src/errors";
import { decodeAttachmentId, encodeAttachmentId } from "../src/mail/ids";
import {
  ImapChannel,
  MAX_LITERAL_OCTETS,
  readGreeting,
  sendCommand,
} from "../src/mail/imap-session";
import {
  MAX_ATTACHMENT_PART_OCTETS,
  createSessionGate,
  getAttachmentBytesOver,
  getAttachmentContentOver,
} from "../src/mail/service";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  structureFetchReply,
  taggedBad,
  taggedOk,
} from "./fixtures/icloud-bytes";
import {
  OVERSIZE_OCTETS,
  OVERSIZE_TAIL,
  oversizeThenNextCommand,
} from "./fixtures/hostile-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

const MAILBOX = "INBOX";
const UIDVALIDITY = 1237268095;
const UID = 4827;
const PART_PATH = "2";

/** The reference a decoded attachment id yields. */
const ATTACHMENT_REF = {
  mailbox: MAILBOX,
  uidValidity: UIDVALIDITY,
  uid: UID,
  path: PART_PATH,
};

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
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
 * One FETCH reply keyed by a section specifier, count derived from the payload.
 *
 * The key is spelled WITHOUT the peek, because that is what a server sends back
 * for a peeking request. That asymmetry is why CLAUDE.md § 5's scan rule is
 * anchored on the fetch ITEM rather than on the spelling: a rule keyed on the
 * spelling would ban reading the answer to the command it protects.
 */
function partReply(tag: string, key: string, payload: Uint8Array): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} ${key} {${payload.byteLength}}\r\n`),
    payload,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** Base64 of a recognisable body, wrapped the way a real encoder wraps it. */
function base64Part(sourceBytes: number): Uint8Array {
  const source = new Uint8Array(sourceBytes).fill(0x41);
  let binary = "";
  for (const byte of source) binary += String.fromCharCode(byte);
  const encoded = btoa(binary);
  const lines: string[] = [];
  for (let at = 0; at < encoded.length; at += 76) {
    lines.push(encoded.slice(at, at + 76));
  }
  return ENCODER.encode(`${lines.join("\r\n")}\r\n`);
}

/** The accepting conversation: auth, EXAMINE, one part fetch, LOGOUT. */
function partDuplex(
  payload: Uint8Array,
  options: { uidValidity?: number } = {},
): ReturnType<typeof createFakeDuplex> {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4", 172, options.uidValidity ?? UIDVALIDITY),
    partReply("a5", `BODY[${PART_PATH}]`, payload),
    logoutExchange("a6"),
  ]);
}

/** The first literal any untagged line carried. */
function firstLiteral(untagged: { literals: Uint8Array[] }[]): Uint8Array {
  for (const line of untagged) {
    if (line.literals.length > 0) return line.literals[0]!;
  }
  throw new Error("no untagged response carried a literal");
}

/** Every written line that looks like a fetch command. */
function fetchLines(duplex: ReturnType<typeof createFakeDuplex>): string[] {
  return duplex.writtenLines().filter((line) => /\bFETCH\b/.test(line));
}

describe("the size pre-check, BEFORE the fetch command is written", () => {
  it("writes NO fetch line for a part declaring more than the ceiling", async () => {
    // The whole point of the pre-check, stated as a property of the wire
    // traffic. An implementation that fetched and then refused would pass an
    // assertion on the return value alone and fail this one.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineResponse("a4", 172, UIDVALIDITY),
      logoutExchange("a5"),
    ]);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      MAX_ATTACHMENT_PART_OCTETS + 1,
      FAST_BOUNDS,
    );

    expect(result.fetched).toBe(false);
    expect(fetchLines(duplex)).toEqual([]);
  });

  it("reports the part's octets AND the limit, and does not throw", async () => {
    // Two numbers rather than a sentence, following `searchPage`'s
    // `unsupportedCharset` precedent: the call SUCCEEDED, the server was never
    // asked, and none of the four closed error categories describes that. The
    // model gets what it needs to explain the problem to the user.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineResponse("a4", 172, UIDVALIDITY),
      logoutExchange("a5"),
    ]);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      9_000_000,
      FAST_BOUNDS,
    );

    expect(result).toEqual({
      fetched: false,
      refusal: "part-too-large",
      encodedOctets: 9_000_000,
      limitBytes: MAX_ATTACHMENT_PART_OCTETS,
    });
  });

  it("refuses AT the boundary only when strictly over it", async () => {
    // An off-by-one here is invisible: the boundary case is exactly the size a
    // 4 MiB staged file inflates to, so a strictly-greater-than written as a
    // greater-or-equal would refuse the largest file the phase means to serve.
    const payload = base64Part(600);
    const duplex = partDuplex(payload);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      MAX_ATTACHMENT_PART_OCTETS,
      FAST_BOUNDS,
    );

    expect(result.fetched).toBe(true);
    expect(fetchLines(duplex)).toHaveLength(1);
  });

  it("still refuses when the mailbox could not be opened at all", async () => {
    // A stale UIDVALIDITY is refused by the session gate before either the
    // pre-check or the fetch is reached, and the refusal is the ordinary
    // not-found rather than a size report — the part was never named.
    const duplex = partDuplex(base64Part(600), { uidValidity: UIDVALIDITY + 1 });

    await expect(
      getAttachmentBytesOver(
        duplex,
        principal,
        createSessionGate(),
        ATTACHMENT_REF,
        1024,
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(fetchLines(duplex)).toEqual([]);
  });
});

describe("the part fetch itself", () => {
  it("asks for exactly the one part, in the PEEKING form", async () => {
    // Convention 5, on the path it was written for. Reading an attachment must
    // not mark its message read: the mailbox is opened read-only for the whole
    // session AND the item itself peeks, which is the same two-mechanism shape
    // every other fetch on this path takes (D-47).
    const duplex = partDuplex(base64Part(600));

    await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      1024,
      FAST_BOUNDS,
    );

    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (BODY.PEEK[${PART_PATH}])`,
    ]);
  });

  it("opens the mailbox READ-ONLY, so the seen flag cannot move", async () => {
    const duplex = partDuplex(base64Part(600));

    await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      1024,
      FAST_BOUNDS,
    );

    const lines = duplex.writtenLines();
    expect(lines.some((line) => /\bEXAMINE\b/.test(line))).toBe(true);
    expect(lines.some((line) => /\bSELECT\b/.test(line))).toBe(false);
  });

  it("returns the bytes the server sent, byte for byte", async () => {
    // Raw, still transfer-encoded, and NOT decoded inside the session. Decoding
    // megabytes is CPU inside the 20-second call deadline, and the deadline
    // races only the session callback — so a decode held there holds a socket
    // against iCloud's low, undocumented per-account ceiling for no reason.
    const payload = base64Part(4096);
    const duplex = partDuplex(payload);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      payload.byteLength,
      FAST_BOUNDS,
    );

    expect(result.fetched).toBe(true);
    if (!result.fetched) return;
    expect(result.bytes.byteLength).toBe(payload.byteLength);
    expect(Array.from(result.bytes)).toEqual(Array.from(payload));
    // Non-vacuous: the payload really is base64 of the source, so a decode of
    // what came back is the file rather than a prefix of it.
    expect(atob(DECODER.decode(result.bytes).replace(/\r\n/g, "")).length).toBe(
      4096,
    );
  });

  it("raises not-found when the server refuses the section specifier", async () => {
    // BAD means the item list was malformed, which for this command means the
    // section specifier was rejected. There is no simpler question to fall back
    // to — this is already the smallest item list that names one part.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineResponse("a4", 172, UIDVALIDITY),
      taggedBad("a5", "UID FETCH invalid section"),
      logoutExchange("a6"),
    ]);

    await expect(
      getAttachmentBytesOver(
        duplex,
        principal,
        createSessionGate(),
        ATTACHMENT_REF,
        1024,
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });

  it("names a part by a path that came through the identifier codec", async () => {
    // The provenance contract, asserted rather than assumed: the path this call
    // takes is the one `decodeAttachmentId` produced, and that decoder already
    // ran `assertPartPath`. Minting the id here proves the round trip a caller
    // performs is the round trip this signature expects.
    const token = encodeAttachmentId(ATTACHMENT_REF);
    expect(typeof token).toBe("string");

    const duplex = partDuplex(base64Part(600));
    await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      1024,
      FAST_BOUNDS,
    );

    // No section keyword, no bracket, no byte range — the shape the assertion
    // in the codec guarantees, visible on the wire.
    const line = fetchLines(duplex)[0]!;
    expect(line).toContain(`BODY.PEEK[${PART_PATH}]`);
    expect(line).not.toMatch(/HEADER|TEXT|MIME|<\d/);
  });
});

describe("the injectable literal ceiling (D-51's seam, used a second time)", () => {
  it("honours an injected ceiling on the channel that asked for it", async () => {
    const payload = ENCODER.encode("x".repeat(200));
    const duplex = createFakeDuplex([
      GREETING,
      partReply("a5", "BODY[2]", payload),
    ]);
    const channel = new ImapChannel(duplex, {
      readTimeoutMs: 40,
      maxLiteralOctets: 64,
    });
    await readGreeting(channel);

    const result = await sendCommand(
      channel,
      "a5",
      `UID FETCH ${UID} (BODY.PEEK[2])`,
    );
    const kept = firstLiteral(result.untagged);

    expect(kept.byteLength).toBe(64);
  });

  it("leaves a channel built WITHOUT the option on the shipped default", async () => {
    // The regression this seam is most likely to cause, and the reason the
    // exported constant stays the default rather than being replaced: every
    // production path that does not ask for a raise must be byte-identical to
    // what Phase 2 shipped.
    const duplex = createFakeDuplex([
      GREETING,
      oversizeThenNextCommand("a5", "a6"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: 40 });
    await readGreeting(channel);

    const result = await sendCommand(
      channel,
      "a5",
      `UID FETCH ${UID} (BODY.PEEK[])`,
    );
    const kept = firstLiteral(result.untagged);

    expect(OVERSIZE_OCTETS).toBeGreaterThan(MAX_LITERAL_OCTETS);
    expect(kept.byteLength).toBe(MAX_LITERAL_OCTETS);
    expect(DECODER.decode(kept.subarray(-64))).not.toContain(OVERSIZE_TAIL);

    // And the stream stayed synchronised, exactly as before.
    const second = await sendCommand(channel, "a6", "CAPABILITY");
    expect(second.status).toBe("OK");
  });

  it("raises the ceiling for the attachment fetch and only for it", async () => {
    // The key link: the raise travels through `MailSessionOptions` per call
    // rather than being set globally, so the whole-message read path's exposure
    // is unchanged. A part between the shipped default and the attachment
    // ceiling comes back WHOLE here and would come back short anywhere else.
    const payload = ENCODER.encode("y".repeat(MAX_LITERAL_OCTETS + 4096));
    const duplex = partDuplex(payload);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      payload.byteLength,
      FAST_BOUNDS,
    );

    expect(result.fetched).toBe(true);
    if (!result.fetched) return;
    expect(result.bytes.byteLength).toBe(payload.byteLength);
    expect(result.bytes.byteLength).toBeGreaterThan(MAX_LITERAL_OCTETS);
  });
});

describe("the ceiling's own arithmetic", () => {
  it("covers a 4 MiB file once base64 has inflated it", () => {
    // The derivation the constant's docstring states, asserted rather than
    // left as prose: 4 MiB of decoded bytes at the measured 1.3684 inflation
    // fits under the ceiling with headroom.
    const stagedFileBytes = 4 * 1024 * 1024;
    expect(MAX_ATTACHMENT_PART_OCTETS).toBeGreaterThan(
      stagedFileBytes * 1.3684,
    );
    // And it stays far below anything that threatens a 128 MB isolate.
    expect(MAX_ATTACHMENT_PART_OCTETS * 6.1).toBeLessThan(64 * 1024 * 1024);
  });

  it("is strictly above the shipped whole-message literal ceiling", () => {
    expect(MAX_ATTACHMENT_PART_OCTETS).toBeGreaterThan(MAX_LITERAL_OCTETS);
  });
});

// ---------------------------------------------------------------------------
// Plan 04-07: the extraction dispatcher (ATT-02)
//
// The other half of the attachment path. Everything above is about GETTING the
// bytes; everything below is about turning them into text a model can read —
// and about the cases that are not text at all, which are refusals on a
// SUCCESSFUL call rather than errors.
//
// The PDF branch is built against `test/probes.test.ts`'s U3 measurement: an
// image-only document resolves with an EMPTY STRING. It does not throw, so a
// `no-text-layer` branch written as a `catch` would never fire.
//
// U3 measured the SCANNED case and only that one. A MALFORMED document —
// truncated, corrupt xref, encrypted — rejects, which is a different fact and a
// different refusal (`unreadable`). Reading U3 as "the parser does not throw"
// is how the rejection went unhandled, so both cases are asserted below.
// ---------------------------------------------------------------------------

import {
  EXTRACTABLE_TYPES,
  MAX_PDF_SOURCE_BYTES,
  extractAttachmentText,
} from "../src/mail/extract";
import { MAX_EXTRACTED_TEXT_BYTES, transferDecode } from "../src/mail/mime";
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

const UTF8 = new TextEncoder();

/**
 * A PDF carrying a real text layer, built by hand.
 *
 * The same construction `test/probes.test.ts` uses and for the same reason: a
 * generated document's contents are known exactly, so the assertion is an
 * equality rather than a fuzzy match against a downloaded file.
 */
function pdfWithText(lines: string[]): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: string | Uint8Array) => {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    parts.push(bytes);
    offset += bytes.length;
  };

  let content = "BT /F1 12 Tf 72 720 Td 14 TL\n";
  for (const line of lines) {
    content += `(${line.replace(/([()\\])/g, "\\$1")}) Tj T*\n`;
  }
  content += "ET\n";
  const stream = encoder.encode(content);

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [5 0 R] /Count 1 >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    null,
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R " +
      "/Resources << /Font << /F1 3 0 R >> >> >>",
  ];

  push("%PDF-1.4\n");
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(offset);
    push(`${index + 1} 0 obj\n`);
    if (object === null) {
      push(`<<  /Length ${stream.length} >>\nstream\n`);
      push(stream);
      push("\nendstream\n");
    } else {
      push(`${object}\n`);
    }
    push("endobj\n");
  });

  const xrefAt = offset;
  let table = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const at of offsets) table += `${String(at).padStart(10, "0")} 00000 n \n`;
  push(table);
  push(
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
      `startxref\n${xrefAt}\n%%EOF\n`,
  );

  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A scanned page: one raw RGB image, and no text operator anywhere. */
function pdfImageOnly(width: number, height: number): Uint8Array {
  const encoder = new TextEncoder();
  const pixels = new Uint8Array(width * height * 3);
  for (let index = 0; index < pixels.length; index += 1) {
    pixels[index] = (index * 37) & 0xff;
  }
  const draw = encoder.encode(`q ${width} 0 0 ${height} 0 0 cm /Im0 Do Q\n`);

  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: string | Uint8Array) => {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    parts.push(bytes);
    offset += bytes.length;
  };

  push("%PDF-1.4\n");
  const offsets: number[] = [];
  const emit = (index: number, body: () => void) => {
    offsets.push(offset);
    push(`${index} 0 obj\n`);
    body();
    push("endobj\n");
  };

  emit(1, () => push("<< /Type /Catalog /Pages 2 0 R >>\n"));
  emit(2, () => push("<< /Type /Pages /Kids [5 0 R] /Count 1 >>\n"));
  emit(3, () => {
    push(
      `<< /Type /XObject /Subtype /Image /Width ${width} /Height ${height} ` +
        `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length ${pixels.length} >>\n` +
        `stream\n`,
    );
    push(pixels);
    push("\nendstream\n");
  });
  emit(4, () => {
    push(`<<  /Length ${draw.length} >>\nstream\n`);
    push(draw);
    push("\nendstream\n");
  });
  emit(5, () =>
    push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] ` +
        `/Contents 4 0 R /Resources << /XObject << /Im0 3 0 R >> >> >>\n`,
    ),
  );

  const xrefAt = offset;
  let table = `xref\n0 6\n0000000000 65535 f \n`;
  for (const at of offsets) table += `${String(at).padStart(10, "0")} 00000 n \n`;
  push(table);
  push(`trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`);

  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

describe("extractAttachmentText: text/plain", () => {
  it("yields the file's decoded text", async () => {
    const result = await extractAttachmentText(
      UTF8.encode("Dear Russell,\n\nWe would like to schedule a call.\n"),
      "text/plain",
      "utf-8",
    );

    expect(result).toEqual({
      extracted: true,
      text: "Dear Russell,\n\nWe would like to schedule a call.\n",
      truncated: false,
      sourceType: "text/plain",
    });
  });

  it("honours the part's declared charset rather than assuming UTF-8", async () => {
    // A latin-1 e-acute is a single 0xE9 byte. Read as UTF-8 it becomes the
    // replacement character, so this case fails against an implementation that
    // hardcodes the decoder.
    const result = await extractAttachmentText(
      new Uint8Array([0x63, 0x61, 0x66, 0xe9]),
      "text/plain",
      "iso-8859-1",
    );

    expect(result).toMatchObject({
      extracted: true,
      text: `caf${String.fromCharCode(0xe9)}`,
    });
  });

  it("falls back to UTF-8 for a charset no decoder recognises", async () => {
    const result = await extractAttachmentText(
      UTF8.encode("plain"),
      "text/plain",
      "x-not-a-charset",
    );

    expect(result).toMatchObject({ extracted: true, text: "plain" });
  });

  it("matches a declared type carrying parameters and odd case", async () => {
    // `Text/Plain; charset=UTF-8` is a legal spelling of the same type, and a
    // dispatcher keyed on the raw string would refuse it as unsupported.
    const result = await extractAttachmentText(
      UTF8.encode("hello"),
      "Text/Plain; charset=UTF-8",
      null,
    );

    expect(result).toMatchObject({ extracted: true, text: "hello" });
  });
});

describe("extractAttachmentText: text/html", () => {
  it("converts through the shipped converter, not a second one", async () => {
    const result = await extractAttachmentText(
      UTF8.encode("<p>Hello <b>there</b></p><p>Second para</p>"),
      "text/html",
      "utf-8",
    );

    expect(result).toMatchObject({ extracted: true, sourceType: "text/html" });
    if (!result.extracted) return;
    expect(result.text).toContain("Hello there");
    expect(result.text).toContain("Second para");
    expect(result.text).not.toContain("<p>");
  });

  it("inherits the skip counter, so script source never reaches the text", async () => {
    // The security property probe A4's second half established: `t.removed` is
    // false on text inside a removed element, so the obvious loop leaks
    // attacker-authored JavaScript into the extracted string. Reusing
    // `htmlToText` is what inherits the fix; a second converter would not.
    const result = await extractAttachmentText(
      UTF8.encode(
        "<html><head><title>TITLELEAK</title>" +
          "<style>.x{content:'STYLELEAK'}</style></head>" +
          "<body><script>var leak = 'SCRIPTLEAK';</script>" +
          "<p>visible text</p></body></html>",
      ),
      "text/html",
      "utf-8",
    );

    expect(result.extracted).toBe(true);
    if (!result.extracted) return;
    expect(result.text).toContain("visible text");
    expect(result.text).not.toContain("SCRIPTLEAK");
    expect(result.text).not.toContain("STYLELEAK");
    expect(result.text).not.toContain("TITLELEAK");
  });
});

describe("extractAttachmentText: application/pdf", () => {
  it("yields a text-bearing document's own text", async () => {
    const result = await extractAttachmentText(
      pdfWithText(["Job description: Staff Engineer", "Remote, contract."]),
      "application/pdf",
      null,
    );

    expect(result).toMatchObject({
      extracted: true,
      truncated: false,
      sourceType: "application/pdf",
    });
    if (!result.extracted) return;
    expect(result.text).toContain("Job description: Staff Engineer");
    expect(result.text).toContain("Remote, contract.");
  });

  it("refuses a scanned image-only document as no-text-layer, without throwing", async () => {
    // Probe U3 measured the return: `{ totalPages: 1, text: "" }`, RESOLVED.
    // An empty string handed back as a success reads to a model as "this
    // document is blank", which is a different and false statement.
    const result = await extractAttachmentText(
      pdfImageOnly(240, 160),
      "application/pdf",
      null,
    );

    expect(result).toEqual({
      extracted: false,
      refusal: "no-text-layer",
      sourceType: "application/pdf",
    });
  });

  it("refuses a MALFORMED document as unreadable, rather than rejecting", async () => {
    // The limit of U3's measurement, which the block header above states in a
    // way that reads more broadly than it is. A SCANNED document resolves with
    // an empty string — that is what U3 measured, and it is why
    // `no-text-layer` is a check on the string. A MALFORMED one REJECTS, and a
    // sender-authored attachment is exactly where a truncated or corrupt file
    // arrives.
    //
    // Unhandled, that rejection reaches `mailErrorResult` as a class the closed
    // vocabulary does not recognise, so it is reported as `connection_failed` —
    // "safe to retry once" — for a document that fails identically forever.
    const truncated = pdfWithText(["Job description: Staff Engineer"]).slice(
      0,
      64,
    );

    const result = await extractAttachmentText(
      truncated,
      "application/pdf",
      null,
    );

    // Not `no-text-layer`: telling the user a corrupt file is a scan sends them
    // looking for OCR that would not have helped.
    expect(result).toEqual({
      extracted: false,
      refusal: "unreadable",
      sourceType: "application/pdf",
    });
  });

  it("does not consume the caller's array, which probe U4 measured it would", async () => {
    // `extractText` DETACHES the buffer it is handed. A caller that extracted
    // and then measured or re-read those bytes would silently get zero.
    const pdf = pdfWithText(["Job description: Staff Engineer"]);
    const before = pdf.byteLength;

    await extractAttachmentText(pdf, "application/pdf", null);

    expect(pdf.byteLength).toBe(before);
  });

  it("refuses a source past the PDF ceiling as source-too-large, with both numbers", async () => {
    const oversize = new Uint8Array(MAX_PDF_SOURCE_BYTES + 1);
    oversize.set(UTF8.encode("%PDF-1.4\n"), 0);

    const result = await extractAttachmentText(oversize, "application/pdf", null);

    expect(result).toEqual({
      extracted: false,
      refusal: "source-too-large",
      sourceType: "application/pdf",
      sizeBytes: MAX_PDF_SOURCE_BYTES + 1,
      limitBytes: MAX_PDF_SOURCE_BYTES,
    });
  });

  it("refuses BEFORE the parser runs, so the array is left intact", async () => {
    // The load-bearing half, and the same shape `readAttachmentPart`'s refusal
    // takes one layer down: a ceiling checked after the expensive thing ran has
    // spent exactly what it existed to save. Detachment is the observable
    // proof, since probe U4 measured that `extractText` always detaches.
    const oversize = new Uint8Array(MAX_PDF_SOURCE_BYTES + 1);
    const before = oversize.byteLength;

    await extractAttachmentText(oversize, "application/pdf", null);

    expect(oversize.byteLength).toBe(before);
  });
});

describe("extractAttachmentText: everything else", () => {
  it("refuses an unsupported type BY NAME, on a call that does not throw", async () => {
    const result = await extractAttachmentText(
      new Uint8Array([0xff, 0xd8, 0xff]),
      "image/jpeg",
      null,
    );

    expect(result).toEqual({
      extracted: false,
      refusal: "unsupported-type",
      sourceType: "image/jpeg",
    });
  });

  it("names the type the SENDER declared, normalised but not invented", async () => {
    const result = await extractAttachmentText(
      new Uint8Array([0]),
      "Application/Vnd.Ms-Excel",
      null,
    );

    expect(result).toMatchObject({
      extracted: false,
      refusal: "unsupported-type",
      sourceType: "application/vnd.ms-excel",
    });
  });

  it("refuses a word-processor type rather than guessing at its bytes", async () => {
    const result = await extractAttachmentText(
      UTF8.encode("PK"),
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      null,
    );

    expect(result.extracted).toBe(false);
  });
});

describe("the extracted-text ceiling", () => {
  it("TRUNCATES over-ceiling text with the flag set, and never refuses", async () => {
    const long = "x".repeat(MAX_EXTRACTED_TEXT_BYTES + 1024);
    const result = await extractAttachmentText(
      UTF8.encode(long),
      "text/plain",
      "utf-8",
    );

    expect(result.extracted).toBe(true);
    if (!result.extracted) return;
    expect(result.truncated).toBe(true);
    expect(new TextEncoder().encode(result.text).byteLength).toBeLessThanOrEqual(
      MAX_EXTRACTED_TEXT_BYTES,
    );
  });

  it("leaves the flag false for text inside the ceiling", async () => {
    const result = await extractAttachmentText(
      UTF8.encode("short"),
      "text/plain",
      "utf-8",
    );

    expect(result).toMatchObject({ truncated: false });
  });
});

describe("the result type carries no bytes on either arm", () => {
  it("publishes exactly the success keys, and none of them is a buffer", async () => {
    // The type contract, asserted as a VALUE property as well as by the
    // typechecker: a success arm that grew a bytes-typed field would fail here
    // even if someone widened the type to permit it.
    const result = await extractAttachmentText(
      UTF8.encode("hello"),
      "text/plain",
      "utf-8",
    );

    expect(Object.keys(result).sort()).toEqual([
      "extracted",
      "sourceType",
      "text",
      "truncated",
    ]);
    for (const value of Object.values(result)) {
      expect(ArrayBuffer.isView(value)).toBe(false);
      expect(value instanceof ArrayBuffer).toBe(false);
    }
  });

  it("publishes exactly the refusal keys on a stated refusal", async () => {
    const result = await extractAttachmentText(
      new Uint8Array([0xff]),
      "image/png",
      null,
    );

    expect(Object.keys(result).sort()).toEqual([
      "extracted",
      "refusal",
      "sourceType",
    ]);
  });
});

describe("EXTRACTABLE_TYPES", () => {
  it("is the single list the tool description and the dispatcher share", () => {
    expect([...EXTRACTABLE_TYPES]).toEqual([
      "text/plain",
      "text/html",
      "application/pdf",
    ]);
  });

  it("extracts for every type on it and refuses every type off it", async () => {
    // Set equality between the list and the dispatcher's behaviour, so the two
    // cannot drift: a type added to the list without a branch fails here.
    for (const type of EXTRACTABLE_TYPES) {
      const bytes =
        type === "application/pdf"
          ? pdfWithText(["some text"])
          : UTF8.encode("some text");
      const result = await extractAttachmentText(bytes, type, "utf-8");
      expect(result.extracted, type).toBe(true);
    }

    for (const type of ["image/png", "application/zip", "text/calendar"]) {
      const result = await extractAttachmentText(new Uint8Array([1]), type, null);
      expect(result, type).toMatchObject({ refusal: "unsupported-type" });
    }
  });
});

describe("MAX_PDF_SOURCE_BYTES' own arithmetic", () => {
  it("sits an order of magnitude under the measured benign budget", () => {
    // The derivation in the constant's docstring, asserted rather than left as
    // prose. Probe U2: 2443588 bytes in 640 ms is 3818 bytes/ms on a benign
    // document; 5000 ms of that budget is ~19 MB, and the ceiling carries a
    // factor-of-eight margin against a hostile document whose per-byte cost is
    // UNMEASURED.
    const benignBytesPerMs = 2443588 / 640;
    const benignBudgetBytes = benignBytesPerMs * 5000;

    expect(MAX_PDF_SOURCE_BYTES * 8).toBeLessThan(benignBudgetBytes);
  });

  it("is reachable through the transport, so the refusal is a live branch", () => {
    // `MAX_ATTACHMENT_PART_OCTETS` is 8 MiB ENCODED, which is ~5.8 MiB decoded
    // after base64's 1.37x inflation. A PDF ceiling above that could never fire.
    const largestDeliverableBytes = MAX_ATTACHMENT_PART_OCTETS / 1.3684;

    expect(MAX_PDF_SOURCE_BYTES).toBeLessThan(largestDeliverableBytes);
  });
});


// ---------------------------------------------------------------------------
// Plan 04-07: the structure-walk join, which is how the tool gets the two
// numbers the opaque id cannot carry
//
// `mail_get_attachment` is handed an id and nothing else (D-76). The id decodes
// to a mailbox, a UIDVALIDITY, a UID and a part path — and to nothing about the
// part's encoded octet count, its transfer encoding or its declared type, all
// three of which the caller needs. Plan 04-05 left that gap open by name. These
// cases are the answer: one session, a structure round trip, then the part.
// ---------------------------------------------------------------------------

/** The declared attachment in the structure below, and its own numbers. */
const CONTENT_FILENAME = "Profile-71.pdf";
const CONTENT_PLAINTEXT = "Job description: Staff Engineer at Example.\r\n";

/** Base64 of a known string, wrapped as a real encoder wraps it. */
function base64Of(text: string): string {
  const bytes = ENCODER.encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary);
  const lines: string[] = [];
  for (let at = 0; at < encoded.length; at += 76) {
    lines.push(encoded.slice(at, at + 76));
  }
  return `${lines.join("\r\n")}\r\n`;
}

const CONTENT_BASE64 = base64Of(CONTENT_PLAINTEXT);

/**
 * A two-part message: a text body at path 1, a PDF attachment at path 2.
 *
 * The attachment declares `BASE64` and its own `body-fld-octets`, which are the
 * two facts the walk exists to recover.
 */
const CONTENT_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${CONTENT_FILENAME}") NIL NIL "BASE64" ` +
  `${CONTENT_BASE64.length} NIL ` +
  `("attachment" ("FILENAME" "${CONTENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** A structure whose only attachment declares more octets than the ceiling. */
const OVERSIZE_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${CONTENT_FILENAME}") NIL NIL "BASE64" ` +
  `${MAX_ATTACHMENT_PART_OCTETS + 1} NIL ` +
  `("attachment" ("FILENAME" "${CONTENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** Auth, EXAMINE, the structure turn, then whatever the case scripts next. */
function contentDuplex(structure: string, ...rest: Uint8Array[]) {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4", 172, UIDVALIDITY),
    structureFetchReply("a5", structure, { uid: UID }),
    ...rest,
  ]);
}

describe("getAttachmentContentOver: the structure walk that supplies the numbers", () => {
  it("recovers the encoding, the type, the charset and both sizes", async () => {
    const duplex = contentDuplex(
      CONTENT_STRUCTURE,
      partReply("a6", `BODY[${PART_PATH}]`, ENCODER.encode(CONTENT_BASE64)),
      logoutExchange("a7"),
    );

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    // The two facts the id could not carry, and the reason this round trip
    // exists at all.
    expect(content.encoding).toBe("base64");
    expect(content.encodedOctets).toBe(CONTENT_BASE64.length);
    // And the three the model is told about.
    expect(content.mimeType).toBe("application/pdf");
    expect(content.filename).toBe(CONTENT_FILENAME);
    expect(content.sizeBytes).toBeLessThan(content.encodedOctets);
    expect(content.fetch.fetched).toBe(true);
  });

  it("returns the part STILL transfer-encoded, decoding to the real bytes", async () => {
    // The contract `getAttachmentBytes` set and this entry point inherits: the
    // decode happens after the session closes, never while a socket is held.
    const duplex = contentDuplex(
      CONTENT_STRUCTURE,
      partReply("a6", `BODY[${PART_PATH}]`, ENCODER.encode(CONTENT_BASE64)),
      logoutExchange("a7"),
    );

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(content.fetch.fetched).toBe(true);
    if (!content.fetch.fetched) return;
    // Still encoded on the wire...
    expect(DECODER.decode(content.fetch.bytes)).not.toContain("Staff Engineer");
    // ...and the shipped decoder is what recovers it.
    expect(DECODER.decode(transferDecode(content.fetch.bytes, content.encoding))).toBe(
      CONTENT_PLAINTEXT,
    );
  });

  it("uses the PEEKING form for BOTH round trips, so nothing is marked read", async () => {
    // Convention 5, and a two-round-trip path is where it is easiest to lose:
    // the structure fetch is new on this path and would be as damaging as the
    // part fetch. Asserted in full rather than by a substring.
    const duplex = contentDuplex(
      CONTENT_STRUCTURE,
      partReply("a6", `BODY[${PART_PATH}]`, ENCODER.encode(CONTENT_BASE64)),
      logoutExchange("a7"),
    );

    await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
      `a6 UID FETCH ${UID} (BODY.PEEK[${PART_PATH}])`,
    ]);
    expect(duplex.writtenLines().some((line) => line.includes("EXAMINE"))).toBe(true);
    expect(duplex.writtenLines().some((line) => /\bSELECT\b/.test(line))).toBe(false);
  });

  it("writes NO part fetch when the structure declares an over-size part", async () => {
    // 04-05's load-bearing property, inherited rather than re-implemented: the
    // refusal precedes the request. The structure line is present because that
    // is what supplies the number the refusal is decided on; the PART line is
    // absent, which is the assertion.
    const duplex = contentDuplex(OVERSIZE_STRUCTURE, logoutExchange("a6"));

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(content.fetch).toEqual({
      fetched: false,
      refusal: "part-too-large",
      encodedOctets: MAX_ATTACHMENT_PART_OCTETS + 1,
      limitBytes: MAX_ATTACHMENT_PART_OCTETS,
    });
    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
    ]);
    // The meta is still reported, so a refusal can say WHAT it refused.
    expect(content.mimeType).toBe("application/pdf");
    expect(content.filename).toBe(CONTENT_FILENAME);
  });

  it("refuses a path that is not an ATTACHMENT ROW, including the body part", async () => {
    // D-76's whole reason for an opaque id over a raw part path: a path
    // addresses ANY part of the message, its body included. Resolving against
    // the raw structure walk here would hand that capability back through the
    // side door, so the lookup runs against `attachmentsFrom`'s output instead —
    // which excludes the selected body part by path.
    const duplex = contentDuplex(CONTENT_STRUCTURE, logoutExchange("a6"));

    await expect(
      getAttachmentContentOver(
        duplex,
        principal,
        createSessionGate(),
        { ...ATTACHMENT_REF, path: "1" },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
    ]);
  });

  it("refuses a path no part carries at all", async () => {
    const duplex = contentDuplex(CONTENT_STRUCTURE, logoutExchange("a6"));

    await expect(
      getAttachmentContentOver(
        duplex,
        principal,
        createSessionGate(),
        { ...ATTACHMENT_REF, path: "9" },
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
  });

  it("drives the whole path end to end: id, one session, then extraction", async () => {
    // The composition `mail_get_attachment` performs, minus the MCP boundary.
    // The extraction runs AFTER the session has closed, which is the ordering
    // the tool fixes and the reason the decode is not inside the callback.
    const duplex = contentDuplex(
      CONTENT_STRUCTURE.replace('"APPLICATION" "PDF"', '"TEXT" "PLAIN"'),
      partReply("a6", `BODY[${PART_PATH}]`, ENCODER.encode(CONTENT_BASE64)),
      logoutExchange("a7"),
    );

    const ref = decodeAttachmentId(encodeAttachmentId(ATTACHMENT_REF));
    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ref,
      FAST_BOUNDS,
    );

    expect(content.fetch.fetched).toBe(true);
    if (!content.fetch.fetched) return;

    const extraction = await extractAttachmentText(
      transferDecode(content.fetch.bytes, content.encoding),
      content.mimeType,
      content.charset,
    );

    expect(extraction).toEqual({
      extracted: true,
      text: CONTENT_PLAINTEXT,
      truncated: false,
      sourceType: "text/plain",
    });
  });
});
