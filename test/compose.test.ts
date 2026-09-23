// The pure message builder, against the bytes it actually produces.
//
// Every assertion here runs against the finished `Uint8Array` or against a
// value decoded back out of it — never against an intermediate string the
// builder happened to construct on the way. That is the discriminating choice:
// the wire is bytes, the byte count is what the transport declares, and a
// fixture that asserted on a pre-encoding string would pass against the exact
// off-by-one this phase exists to avoid.
//
// The second discriminating choice is the oracle. The read side already ships
// in the bundle, so `PostalMime.parse()` and `decodeWords` are used to read the
// write side's output back. A case that passes against both a correct and a
// broken builder is testing nothing; a round trip through an independent parser
// is the cheapest thing here that cannot be satisfied by a builder that merely
// looks plausible.

import PostalMime, { decodeWords } from "postal-mime";
import { describe, expect, it, vi } from "vitest";
import type {
  DraftAttachment,
  DraftInput,
  QuotedSource,
} from "../src/mail/compose";
import {
  MAX_APPEND_LITERAL_BYTES,
  RE_PREFIX,
  addressField,
  buildDraft,
  contentDispositionParams,
  encodeHeaderText,
  foldReferences,
  freshBoundary,
  quoteOriginal,
  replySubject,
  rfc5322Date,
} from "../src/mail/compose";

const DECODER = new TextDecoder();
const ENCODER = new TextEncoder();

/** A fixed instant, so every emitted `Date` header is deterministic. */
const NOW = new Date(Date.UTC(2026, 7, 20, 14, 22, 5));

/** One draft's inputs, with only the field under test overridden. */
function draft(overrides: Partial<DraftInput> = {}): DraftInput {
  return {
    from: "someone@icloud.com",
    to: ["recruiter@example.invalid"],
    cc: [],
    subject: "Thanks for your time",
    text: "Hello there.\r\nBest,\r\nRussell",
    html: null,
    inReplyTo: null,
    references: [],
    attachments: [],
    quoted: null,
    now: NOW,
    ...overrides,
  };
}

/** A parent as the reply quotes it, with only the field under test overridden. */
function parent(overrides: Partial<QuotedSource> = {}): QuotedSource {
  return {
    date: "2026-08-19T09:14:02.000Z",
    fromName: "Jane Doe",
    fromAddress: "jane@example.invalid",
    text: "The original words.",
    html: null,
    bodySource: "text/plain",
    ...overrides,
  };
}

/** Build, asserting success, and hand back the finished bytes. */
function bytesOf(input: DraftInput): Uint8Array {
  const result = buildDraft(input);
  if (!result.built) {
    throw new Error(`expected a built draft, got refusal: ${result.refusal}`);
  }
  return result.bytes;
}

/** The finished message as text, for header and structure assertions. */
function messageOf(input: DraftInput): string {
  return DECODER.decode(bytesOf(input));
}

/**
 * One header's value, unfolded.
 *
 * Reads the header BLOCK only — everything before the first empty line — so a
 * body line that happens to look like a header cannot be mistaken for one.
 */
function headerValue(message: string, name: string): string | null {
  const block = message.split("\r\n\r\n")[0]!;
  const lines = block.split("\r\n");
  const lowered = `${name.toLowerCase()}:`;

  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index]!.toLowerCase().startsWith(lowered)) continue;
    let value = lines[index]!.slice(lowered.length).trim();
    // Continuation lines begin with whitespace and belong to this header.
    for (let next = index + 1; next < lines.length; next += 1) {
      if (!/^[ \t]/.test(lines[next]!)) break;
      value += ` ${lines[next]!.trim()}`;
    }
    return value;
  }
  return null;
}

/**
 * One value with every line ending reduced to a bare newline, then trimmed.
 *
 * The comparison is on CONTENT rather than on line-ending spelling: the parser
 * is free to normalise what it hands back, and asserting on its choice would be
 * asserting on the oracle rather than on the builder. The CRLF property is
 * asserted directly against the finished bytes elsewhere in this file, which is
 * the only place it can be asserted honestly.
 */
function normaliseBreaks(value: string): string {
  return value.replace(/\r\n/g, "\n").trim();
}

/** Every byte position where a line feed appears without a carriage return. */
function bareLineFeeds(bytes: Uint8Array): number[] {
  const found: number[] = [];
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0x0a) continue;
    if (index === 0 || bytes[index - 1] !== 0x0d) found.push(index);
  }
  return found;
}

// ---------------------------------------------------------------------------
// The three trees (D-75)
// ---------------------------------------------------------------------------

describe("the three body trees", () => {
  it("emits a single text/plain for a text-only draft", () => {
    const message = messageOf(draft({ text: "Just words.", html: null }));

    expect(headerValue(message, "Content-Type")).toMatch(/^text\/plain;/);
    expect(message).not.toContain("multipart/");
  });

  it("emits a single text/html for an HTML-only draft", () => {
    const message = messageOf(
      draft({ text: null, html: "<p>Just markup.</p>" }),
    );

    expect(headerValue(message, "Content-Type")).toMatch(/^text\/html;/);
    expect(message).not.toContain("multipart/");
  });

  it("never wraps a single part in a one-child multipart", () => {
    // A one-child multipart is legal and is a DIFFERENT message — it is the
    // shape that makes a draft open as a blob rather than as text in some
    // clients, so the absence of the wrap is the property, not a shortcut.
    for (const input of [
      draft({ text: "words", html: null }),
      draft({ text: null, html: "<p>markup</p>" }),
    ]) {
      expect(messageOf(input)).not.toContain("boundary=");
    }
  });

  it("emits multipart/alternative with the PLAIN part first when both are given", async () => {
    // RFC 2046 §5.1.4 orders parts by increasing faithfulness and a client
    // picks the LAST one it can display. Reversed, every rich client shows
    // plain text — a failure that looks like the draft simply lost its
    // formatting rather than like a structural bug.
    const message = messageOf(
      draft({ text: "plain words", html: "<p>rich words</p>" }),
    );

    expect(headerValue(message, "Content-Type")).toMatch(
      /^multipart\/alternative; boundary="/,
    );
    expect(message.indexOf("text/plain")).toBeGreaterThan(-1);
    expect(message.indexOf("text/plain")).toBeLessThan(
      message.indexOf("text/html"),
    );

    const parsed = await PostalMime.parse(message);
    expect(parsed.text?.trim()).toBe("plain words");
    expect(parsed.html).toContain("rich words");
  });

  it("quotes the boundary parameter", () => {
    const message = messageOf(draft({ text: "a", html: "<p>b</p>" }));

    expect(headerValue(message, "Content-Type")).toMatch(/boundary="[^"]+"$/);
  });

  it("closes the last part with the two-hyphen terminator", () => {
    const message = messageOf(draft({ text: "a", html: "<p>b</p>" }));
    const boundary = /boundary="([^"]+)"/.exec(message)![1]!;

    expect(message).toContain(`\r\n--${boundary}\r\n`);
    expect(message.endsWith(`\r\n--${boundary}--\r\n`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CRLF discipline (PITFALLS #8)
// ---------------------------------------------------------------------------

describe("CRLF discipline", () => {
  const CASES: [string, DraftInput][] = [
    ["text only", draft({ text: "one\r\ntwo", html: null })],
    ["html only", draft({ text: null, html: "<p>one</p>\r\n<p>two</p>" })],
    ["both parts", draft({ text: "one\r\ntwo", html: "<p>one</p>" })],
    [
      "a body authored with bare newlines",
      draft({ text: "one\ntwo\nthree", html: "<p>one</p>\n<p>two</p>" }),
    ],
    ["a body authored with bare carriage returns", draft({ text: "one\rtwo" })],
  ];

  for (const [label, input] of CASES) {
    it(`carries no line feed without a carriage return before it: ${label}`, () => {
      const bytes = bytesOf(input);

      expect(bareLineFeeds(bytes)).toEqual([]);
      // Non-vacuous: a builder emitting no line breaks at all would also pass.
      expect([...bytes].filter((byte) => byte === 0x0a).length).toBeGreaterThan(
        4,
      );
    });
  }

  it("separates the header block from the body with exactly one empty line", () => {
    const message = messageOf(draft());

    expect(message).toContain("\r\n\r\n");
    expect(message.split("\r\n\r\n")[0]).toContain("Subject:");
  });

  it("ends the message with a CRLF, counted in the bytes", () => {
    const bytes = bytesOf(draft());

    expect(bytes[bytes.length - 2]).toBe(0x0d);
    expect(bytes[bytes.length - 1]).toBe(0x0a);
  });
});

// ---------------------------------------------------------------------------
// Header text encoding (RFC 2047)
// ---------------------------------------------------------------------------

describe("encodeHeaderText", () => {
  it("emits pure printable US-ASCII raw", () => {
    // The common case stays readable in a raw dump, which is the difference
    // between a debuggable append and an undebuggable one.
    expect(encodeHeaderText("Thanks for your time")).toBe(
      "Thanks for your time",
    );
    expect(encodeHeaderText("Re: [Job] Senior Engineer (remote)")).toBe(
      "Re: [Job] Senior Engineer (remote)",
    );
  });

  it("encodes a non-ASCII value as encoded-words", () => {
    const encoded = encodeHeaderText("Grüße aus Köln");

    expect(encoded).toMatch(/^=\?UTF-8\?B\?/);
    expect(decodeWords(encoded)).toBe("Grüße aus Köln");
  });

  it("keeps every encoded-word at 75 characters or fewer, delimiters included", () => {
    const subject = "Rückmeldung zur Bewerbung ☕ ".repeat(6);
    const encoded = encodeHeaderText(subject);
    const words = encoded.split(" ");

    expect(words.length).toBeGreaterThan(1);
    for (const word of words) {
      expect(word).toMatch(/^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
      expect(word.length).toBeLessThanOrEqual(75);
    }
  });

  it("splits a long non-ASCII value on CHARACTER boundaries", () => {
    // The failure this catches is silent and only reproduces for values long
    // enough to need a second word: splitting the ENCODED output at a byte
    // boundary cuts a multi-byte sequence in half and produces mojibake in
    // every client. Decoding each word INDEPENDENTLY is what proves the split
    // happened before the encoding rather than after it.
    const subject = "Ü".repeat(100);
    const encoded = encodeHeaderText(subject);
    const words = encoded.split(" ");

    expect(words.length).toBeGreaterThan(1);
    let rejoined = "";
    for (const word of words) {
      const decoded = decodeWords(word);
      expect(decoded).not.toContain("�");
      rejoined += decoded;
    }
    expect(rejoined).toBe(subject);
    expect(decodeWords(encoded)).toBe(subject);
  });

  it("does not split an astral character across two words", () => {
    // A surrogate pair is one character and four UTF-8 bytes. A splitter that
    // walked code UNITS rather than code POINTS would cut it in half.
    const subject = "🔑".repeat(40);
    const encoded = encodeHeaderText(subject);

    expect(decodeWords(encoded)).toBe(subject);
    for (const word of encoded.split(" ")) {
      expect(decodeWords(word)).not.toContain("�");
    }
  });

  it("puts a non-ASCII subject on the message and reads it back through the parser", async () => {
    const subject = "Grüße — Rückmeldung ☕";
    const message = messageOf(draft({ subject }));

    expect(headerValue(message, "Subject")).toMatch(/^=\?UTF-8\?B\?/);
    expect(decodeWords(headerValue(message, "Subject")!)).toBe(subject);
    expect((await PostalMime.parse(message)).subject).toBe(subject);
  });
});

// ---------------------------------------------------------------------------
// Address fields
// ---------------------------------------------------------------------------

describe("addressField", () => {
  it("emits a bare address when there is no display name", () => {
    expect(addressField("someone@icloud.com", null)).toBe("someone@icloud.com");
  });

  it("emits an unquoted phrase for a plain ASCII display name", () => {
    expect(addressField("jane@example.invalid", "Jane Doe")).toBe(
      "Jane Doe <jane@example.invalid>",
    );
  });

  it("quotes a display name carrying an RFC 5322 special", () => {
    expect(addressField("jane@example.invalid", "Doe, Jane")).toBe(
      '"Doe, Jane" <jane@example.invalid>',
    );
    expect(addressField("jane@example.invalid", 'Jane "JD" Doe')).toBe(
      '"Jane \\"JD\\" Doe" <jane@example.invalid>',
    );
  });

  it("encodes a non-ASCII display name as an encoded-word, never the address", () => {
    // An encoded-word is legal in the phrase position and illegal inside the
    // address itself, so the two halves are treated differently on purpose.
    const field = addressField("jan@example.invalid", "Jan Müller")!;

    expect(field).toMatch(/^=\?UTF-8\?B\?.+\?= <jan@example\.invalid>$/);
    expect(decodeWords(field.split(" <")[0]!)).toBe("Jan Müller");
  });

  it("refuses CR, LF or NUL in either half rather than stripping them", () => {
    for (const address of [
      "a@b.invalid\r\nBcc: attacker@evil.invalid",
      "a@b.invalid\nX: y",
      "a@b.invalid ",
    ]) {
      expect(addressField(address, null)).toBeNull();
    }
    expect(addressField("a@b.invalid", "Jane\r\nBcc: attacker@evil.invalid")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Refusals — returned, never raised
// ---------------------------------------------------------------------------

describe("refusals", () => {
  it("RETURNS a refusal for a recipient carrying CR or LF, and throws nothing", () => {
    // A CR in a recipient terminates the header line early and injects a second
    // header built from the caller's own bytes. Refusing names the real
    // problem; escaping would send a value the peer rejects.
    for (const bad of [
      "victim@example.invalid\r\nBcc: attacker@evil.invalid",
      "victim@example.invalid\nSubject: forged",
      "victim@example.invalid ",
    ]) {
      // A raise here fails the case, and that is the point: the refusal is a
      // RETURNED result, so the caller is told what was wrong rather than
      // meeting an exception whose category does not describe it.
      expect(() => buildDraft(draft({ to: [bad] }))).not.toThrow();

      expect(buildDraft(draft({ to: [bad] }))).toMatchObject({
        built: false,
        refusal: "recipient-illegal-characters",
      });
    }
  });

  it("REFUSES an empty recipient list rather than emitting a bare To: line", () => {
    // `addressList([])` returns the empty string, and unlike `Cc` an empty `To`
    // is not omitted — so the draft was built with a bare `To: ` line, written,
    // and reported as `appended: true`. A draft the user cannot send, described
    // as a success.
    //
    // This is reachable without the caller doing anything wrong. The reply tool
    // omits `to` in the normal case and derives it from the parent, and the
    // derivation falls back to the parent's `From`, which is an empty list when
    // the parser could not read the sender.
    const result = buildDraft(draft({ to: [] }));

    expect(result).toMatchObject({ built: false, refusal: "no-recipients" });
    // Not the illegal-characters refusal: the caller supplied no addresses, so
    // telling it that its addresses are malformed is a wrong statement it
    // cannot act on.
    expect(result).not.toMatchObject({
      refusal: "recipient-illegal-characters",
    });
  });

  it("refuses an illegal Cc for the same reason", () => {
    const result = buildDraft(
      draft({ cc: ["ok@example.invalid", "bad@example.invalid\r\nX: y"] }),
    );

    expect(result).toMatchObject({
      built: false,
      refusal: "recipient-illegal-characters",
    });
  });

  it("refuses an illegal threading token rather than emitting a broken header", () => {
    const result = buildDraft(
      draft({ references: ["<a@b.invalid>", "<c@d.invalid>\r\nX: y"] }),
    );

    expect(result).toMatchObject({
      built: false,
      refusal: "references-illegal-characters",
    });
  });

  it("refuses an illegal attachment filename", () => {
    const result = buildDraft(
      draft({
        attachments: [
          {
            filename: "resume.pdf\r\nX: y",
            mimeType: "application/pdf",
            content: new Uint8Array([1, 2, 3]),
          },
        ],
      }),
    );

    expect(result).toMatchObject({
      built: false,
      refusal: "filename-illegal-characters",
    });
  });

  it("refuses an assembled message over the ceiling, carrying BOTH numbers", () => {
    // The refusal is a structured result rather than a raise, and rather than a
    // fifth error category: the build RAN and produced a stated answer, and the
    // two numbers are what let the model explain the problem rather than a
    // sentence it has to parse.
    const line = `${"a".repeat(900)}\n`;
    const result = buildDraft(draft({ text: line.repeat(15000) }));

    expect(result.built).toBe(false);
    if (result.built) return;
    expect(result.refusal).toBe("message-too-large");
    expect(result.limitBytes).toBe(MAX_APPEND_LITERAL_BYTES);
    expect(result.sizeBytes!).toBeGreaterThan(MAX_APPEND_LITERAL_BYTES);
  });

  it("builds a message comfortably under the ceiling", () => {
    // Non-vacuous companion to the case above: a builder that refused
    // everything would pass that one alone.
    const line = `${"a".repeat(900)}\n`;
    const result = buildDraft(draft({ text: line.repeat(100) }));

    expect(result.built).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Transfer encoding
// ---------------------------------------------------------------------------

describe("transfer encoding", () => {
  it("uses 7bit for an all-ASCII short-lined part", () => {
    const message = messageOf(draft({ text: "Hello there.\r\nBest," }));

    expect(headerValue(message, "Content-Transfer-Encoding")).toBe("7bit");
    expect(message).toContain("Hello there.");
  });

  it("uses base64 for a part carrying a non-ASCII byte", () => {
    const message = messageOf(draft({ text: "Grüße aus Köln ☕" }));

    expect(headerValue(message, "Content-Transfer-Encoding")).toBe("base64");
    expect(message).not.toContain("Grüße");
  });

  it("uses base64 for an all-ASCII part with a line over 990 octets", () => {
    // The BINDING constraint is the line length, not the character set: real
    // stranger-authored markup routinely has single lines in the tens of
    // kilobytes, and 7bit on such a part produces a message some servers
    // reject and some clients render wrong.
    const message = messageOf(draft({ text: "a".repeat(1200) }));

    expect(headerValue(message, "Content-Transfer-Encoding")).toBe("base64");
  });

  it("wraps base64 at 76 columns", () => {
    const message = messageOf(draft({ text: "Grüße ".repeat(400) }));
    const body = message.split("\r\n\r\n").slice(1).join("\r\n\r\n");

    const lines = body.split("\r\n").filter((line) => line.length > 0);
    expect(lines.length).toBeGreaterThan(4);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(76);
  });

  it("survives a large non-ASCII body through the parser", async () => {
    // The chunked encoder's own regression guard: a builder that fed a whole
    // megabyte through a spread call would fail here rather than in production.
    const text = "Grüße aus Köln ☕ ".repeat(40000);
    const parsed = await PostalMime.parse(messageOf(draft({ text })));

    expect(parsed.text?.replace(/\r\n/g, "").trim()).toContain("Grüße aus Köln");
    expect((parsed.text ?? "").length).toBeGreaterThan(500000);
  });
});

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

describe("freshBoundary", () => {
  it("never returns a candidate that occurs in any part's content", () => {
    const boundary = freshBoundary(["some content", "<p>markup</p>"]);

    expect(boundary).toMatch(/^----=_iCloudMCP_/);
    expect("some content".includes(boundary)).toBe(false);
  });

  it("REGENERATES when the first candidate collides", () => {
    // The probability argument is not available here: a later plan passes a
    // stranger's markup through unmodified, so the one place a collision could
    // be CHOSEN rather than stumbled into is the exact place this project
    // decided not to sanitise. Proving the loop runs needs the first candidate
    // to be forced, which is why the generator is stubbed rather than trusted.
    const spy = vi.spyOn(crypto, "randomUUID");
    spy.mockReturnValueOnce("11111111-1111-4111-8111-111111111111");
    spy.mockReturnValueOnce("22222222-2222-4222-8222-222222222222");

    const colliding = "----=_iCloudMCP_11111111-1111-4111-8111-111111111111";
    const boundary = freshBoundary([`prefix ${colliding} suffix`]);

    expect(boundary).not.toBe(colliding);
    expect(boundary).toBe("----=_iCloudMCP_22222222-2222-4222-8222-222222222222");
    spy.mockRestore();
  });

  it("emits a boundary absent from a part whose content IS a plausible boundary", () => {
    const hostile = "----=_iCloudMCP_00000000-0000-4000-8000-000000000000";
    const message = messageOf(
      draft({ text: hostile, html: `<p>${hostile}</p>` }),
    );
    const boundary = /boundary="([^"]+)"/.exec(message)![1]!;

    expect(boundary).not.toBe(hostile);
    expect(hostile.includes(boundary)).toBe(false);
    // And the emitted delimiter still occurs exactly where it should: twice as
    // an opening delimiter and once as the terminator.
    expect(message.split(`--${boundary}`).length - 1).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Dates, ids and the round trip
// ---------------------------------------------------------------------------

describe("rfc5322Date", () => {
  it("formats from a fixed English table in UTC", () => {
    expect(rfc5322Date(NOW)).toBe("Thu, 20 Aug 2026 14:22:05 +0000");
  });

  it("pads single-digit components", () => {
    expect(rfc5322Date(new Date(Date.UTC(2026, 0, 4, 3, 5, 9)))).toBe(
      "Sun, 04 Jan 2026 03:05:09 +0000",
    );
  });

  it("reads UTC components, so the host's own zone cannot change it", () => {
    // The `ical-jsdate` rule one protocol over exists because the vitest pool
    // inherits the developer's zone while production runs UTC, and the failure
    // is not an exception but silently wrong times.
    const instant = new Date(Date.UTC(2026, 11, 31, 23, 30, 0));

    expect(rfc5322Date(instant)).toBe("Thu, 31 Dec 2026 23:30:00 +0000");
    expect(rfc5322Date(instant)).toContain("+0000");
  });

  it("puts the injected clock on the message, never the wall clock", () => {
    expect(headerValue(messageOf(draft()), "Date")).toBe(
      "Thu, 20 Aug 2026 14:22:05 +0000",
    );
  });
});

describe("the message id", () => {
  it("mints one for every draft, never blank", () => {
    const value = headerValue(messageOf(draft()), "Message-ID");

    expect(value).toMatch(/^<[0-9a-f-]{36}@icloud\.com>$/);
  });

  it("gives two drafts different ids", () => {
    const first = headerValue(messageOf(draft()), "Message-ID");
    const second = headerValue(messageOf(draft()), "Message-ID");

    expect(first).not.toBe(second);
  });

  it("carries the sender's DOMAIN and never the local part", () => {
    // The domain is public and is already in the From header. The local part
    // is credential-adjacent, and a timestamp-plus-local-part id — a shape
    // several clients use — would put it in a second place, including in an
    // echoed tool response. The random value avoids that by construction.
    //
    // The domain is the reserved one (RFC 6761 `.invalid`), like every other
    // address fixture in this suite. It used to be a real iCloud domain, which
    // made the whole literal read as a near-miss of the repository owner's own
    // address on a repository with a public remote. The property under test is
    // unaffected: what matters is that the local part has structure worth
    // leaking and that the domain is a domain.
    const message = messageOf(draft({ from: "russell.moore@example.invalid" }));
    const value = headerValue(message, "Message-ID")!;

    expect(value).toContain("@example.invalid>");
    expect(value).not.toContain("russell.moore");
  });
});

describe("the header block", () => {
  it("omits Cc entirely when there are no copied recipients", () => {
    expect(headerValue(messageOf(draft({ cc: [] })), "Cc")).toBeNull();
  });

  it("emits Cc as a comma-separated list when there are", () => {
    const message = messageOf(
      draft({ cc: ["a@example.invalid", "b@example.invalid"] }),
    );

    expect(headerValue(message, "Cc")).toBe(
      "a@example.invalid, b@example.invalid",
    );
  });

  it("declares the MIME version", () => {
    expect(headerValue(messageOf(draft()), "MIME-Version")).toBe("1.0");
  });

  it("omits both threading headers when this slice supplies neither", () => {
    const message = messageOf(draft());

    expect(headerValue(message, "In-Reply-To")).toBeNull();
    expect(headerValue(message, "References")).toBeNull();
  });

  it("emits both threading headers when they are supplied", () => {
    const message = messageOf(
      draft({
        inReplyTo: "<parent@example.invalid>",
        references: ["<root@example.invalid>", "<parent@example.invalid>"],
      }),
    );

    expect(headerValue(message, "In-Reply-To")).toBe("<parent@example.invalid>");
    expect(headerValue(message, "References")).toBe(
      "<root@example.invalid> <parent@example.invalid>",
    );
  });
});

// ---------------------------------------------------------------------------
// The round trip — the read side as the write side's oracle
// ---------------------------------------------------------------------------

describe("the round trip through PostalMime", () => {
  const SHAPES: [string, DraftInput][] = [
    [
      "text only",
      draft({
        subject: "Following up on the Senior Engineer role",
        to: ["recruiter@example.invalid"],
        text: "Hello there.\r\n\r\nBest,\r\nRussell",
        html: null,
      }),
    ],
    [
      "html only",
      draft({
        subject: "Grüße — a note",
        to: ["jan@example.invalid"],
        text: null,
        html: "<p>Hello <strong>there</strong>.</p>",
      }),
    ],
    [
      "both parts",
      draft({
        subject: "Interview follow-up ☕",
        to: ["a@example.invalid", "b@example.invalid"],
        cc: ["c@example.invalid"],
        text: "Plain words for the fallback.",
        html: "<p>Rich words for the display.</p>",
      }),
    ],
  ];

  for (const [label, input] of SHAPES) {
    it(`parses back to the inputs it was built from: ${label}`, async () => {
      const parsed = await PostalMime.parse(messageOf(input));

      expect(parsed.subject).toBe(input.subject);
      expect(parsed.from?.address).toBe(input.from);
      expect((parsed.to ?? []).map((one) => one.address)).toEqual(input.to);
      expect((parsed.cc ?? []).map((one) => one.address)).toEqual(input.cc);
      expect(parsed.messageId).toMatch(/[0-9a-f-]{36}@/);

      if (input.text !== null) {
        expect(normaliseBreaks(parsed.text ?? "")).toBe(
          normaliseBreaks(input.text),
        );
      }
      if (input.html !== null) {
        expect(parsed.html).toContain(input.html.slice(3, 20));
      }
    });
  }

  it("survives a subject and a body that are both non-ASCII", async () => {
    const input = draft({
      subject: "Rückmeldung zur Bewerbung ☕",
      text: "Sehr geehrte Frau Müller,\r\n\r\nvielen Dank — ☕\r\n",
      html: null,
    });
    const parsed = await PostalMime.parse(messageOf(input));

    expect(parsed.subject).toBe(input.subject);
    expect(parsed.text).toContain("Sehr geehrte Frau Müller,");
    expect(parsed.text).toContain("vielen Dank — ☕");
  });
});

// ---------------------------------------------------------------------------
// The byte count discipline
// ---------------------------------------------------------------------------

describe("the byte count", () => {
  it("measures the SOURCE in bytes, which is not its character count", () => {
    // The divergence, measured on the value a caller actually supplies rather
    // than asserted in prose: 46 characters and 51 bytes. Every count on this
    // path is taken off an encoded array for exactly this reason.
    const text = "Sehr geehrte Frau Müller,\r\n\r\nvielen Dank — ☕\r\n";

    expect(text.length).toBe(46);
    expect(ENCODER.encode(text).byteLength).toBe(51);
  });

  it("emits a non-ASCII body as base64 rather than as bare multi-byte content", () => {
    // A consequence worth stating, because it is easy to misread as a reason
    // the count discipline does not matter: a non-ASCII part is base64-encoded
    // and a non-ASCII header is an encoded-word, so THIS builder's output for
    // an ordinary draft happens to be all-ASCII.
    //
    // It does not transfer. The transport declares a count for whatever bytes
    // it is handed, and it is handed arbitrary bytes — an internationalised
    // recipient address passes through this module raw, and 04-09's attachment
    // path carries binary. The count still comes off the array, every time.
    const bytes = bytesOf(
      draft({ text: "Sehr geehrte Frau Müller,\r\n\r\nvielen Dank — ☕\r\n" }),
    );

    expect(bytes.byteLength).toBe(
      ENCODER.encode(DECODER.decode(bytes)).byteLength,
    );
    expect([...bytes].some((byte) => byte > 0x7f)).toBe(false);
  });

  it("carries an internationalised recipient through raw, so the bytes DO diverge", () => {
    // The case that shows the all-ASCII property above is incidental rather
    // than structural: an address is not an encoded-word position, so a
    // non-ASCII one reaches the wire as multi-byte content.
    const bytes = bytesOf(draft({ to: ["jörg@example.invalid"] }));

    expect([...bytes].some((byte) => byte > 0x7f)).toBe(true);
    expect(bytes.byteLength).toBeGreaterThan(DECODER.decode(bytes).length);
  });

  it("counts the ceiling against the ENCODED bytes", () => {
    expect(MAX_APPEND_LITERAL_BYTES).toBe(12 * 1024 * 1024);
  });
});

// ---------------------------------------------------------------------------
// Threading (DRAFT-03, RESEARCH § 2.2's four rules)
//
// Every case here is a failure that returns a successful write. A reply whose
// References was truncated from the end, or whose In-Reply-To names an id
// nobody minted, appends exactly as cleanly as a correct one — so the only
// place the difference is visible is against the bytes.
// ---------------------------------------------------------------------------

/** Every emitted line's length in OCTETS, which is what RFC 5322 bounds. */
function lineOctets(bytes: Uint8Array): number[] {
  const widths: number[] = [];
  let width = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === 0x0d && bytes[index + 1] === 0x0a) {
      widths.push(width);
      width = 0;
      index += 1;
      continue;
    }
    width += 1;
  }
  if (width > 0) widths.push(width);
  return widths;
}

/** A run of well-formed reference tokens, distinct and ordered. */
function chain(count: number): string[] {
  return Array.from(
    { length: count },
    (_, index) => `<msg-${index}@example.invalid>`,
  );
}

describe("the four threading rules", () => {
  it("appends the parent's own id to the parent's References", () => {
    const message = messageOf(
      draft({
        inReplyTo: "<parent@example.invalid>",
        references: ["<one@example.invalid>", "<two@example.invalid>"],
      }),
    );

    expect(headerValue(message, "In-Reply-To")).toBe("<parent@example.invalid>");
    expect(headerValue(message, "References")).toBe(
      "<one@example.invalid> <two@example.invalid> <parent@example.invalid>",
    );
  });

  it("does not repeat the parent's id when it already ends the chain", () => {
    // RFC 5322 tolerates the duplicate; Mail.app's threading is unverified on
    // the point, so the chain is emitted the way the RFC describes building it.
    const message = messageOf(
      draft({
        inReplyTo: "<parent@example.invalid>",
        references: ["<one@example.invalid>", "<parent@example.invalid>"],
      }),
    );

    expect(headerValue(message, "References")).toBe(
      "<one@example.invalid> <parent@example.invalid>",
    );
  });

  it("emits NEITHER header when the parent carried no Message-ID", async () => {
    // A fabricated In-Reply-To is worse than none: it creates an orphan
    // reference some clients render as a broken thread. `messageId` on a parsed
    // message is nullable, so this case is reachable rather than theoretical.
    const message = messageOf(
      draft({ inReplyTo: null, references: ["<one@example.invalid>"] }),
    );
    const parsed = await PostalMime.parse(message);

    expect(headerValue(message, "In-Reply-To")).toBeNull();
    expect(headerValue(message, "References")).toBeNull();
    expect(parsed.inReplyTo).toBeUndefined();
    expect(parsed.references).toBeUndefined();
  });

  it("emits neither header when the parent's id is not an angle-bracket token", () => {
    // Absent and unusable are the same fact for this purpose. Emitting a
    // malformed id would put a value into a threading header that no other
    // client will match, which is the fabricated-reference failure by another
    // route.
    const message = messageOf(
      draft({ inReplyTo: "parent@example.invalid", references: [] }),
    );

    expect(headerValue(message, "In-Reply-To")).toBeNull();
    expect(headerValue(message, "References")).toBeNull();
  });

  it("FOLDS a long chain rather than dropping tokens from its end", () => {
    // The tempting wrong answer, and the one that looks like success: RFC 5322
    // §3.6.4 permits dropping from the MIDDLE, and a client that drops from the
    // end breaks the chain for every message after it.
    const tokens = chain(40);
    const bytes = bytesOf(
      draft({ inReplyTo: "<parent@example.invalid>", references: tokens }),
    );
    const message = DECODER.decode(bytes);

    for (const width of lineOctets(bytes)) {
      expect(width).toBeLessThanOrEqual(998);
    }

    const value = headerValue(message, "References");
    expect(value).not.toBeNull();
    for (const token of [...tokens, "<parent@example.invalid>"]) {
      expect(value, `dropped ${token}`).toContain(token);
    }
    expect(value!.split(" ")).toHaveLength(41);
    // Non-vacuous: the chain really did need more than one line.
    expect(message).toContain("\r\n <");
  });

  it("drops a token that is not shaped like a message id, and keeps the rest", () => {
    const message = messageOf(
      draft({
        inReplyTo: "<parent@example.invalid>",
        references: [
          "<one@example.invalid>",
          "not an id",
          "<two@example.invalid>",
        ],
      }),
    );

    expect(headerValue(message, "References")).toBe(
      "<one@example.invalid> <two@example.invalid> <parent@example.invalid>",
    );
  });

  it("REFUSES the whole build for a reference token carrying a carriage return", () => {
    // Refuse rather than repair. The parent's References is stranger-authored,
    // and a CR in a header value is header injection into a message the user
    // will send — stripping it would send a message built partly from an
    // attacker's intent while reporting success.
    const result = buildDraft(
      draft({
        inReplyTo: "<parent@example.invalid>",
        references: ["<one@example.invalid>\r\nBcc: attacker@example.invalid"],
      }),
    );

    expect(result).toMatchObject({
      built: false,
      refusal: "references-illegal-characters",
    });
    // Nothing was stripped and nothing was emitted: there are no bytes at all.
    expect("bytes" in result).toBe(false);
  });

  it("refuses a line feed in a reference token too", () => {
    expect(
      buildDraft(
        draft({
          inReplyTo: "<parent@example.invalid>",
          references: ["<one@example.invalid>\nBcc: attacker@example.invalid"],
        }),
      ),
    ).toMatchObject({ built: false, refusal: "references-illegal-characters" });
  });

  it("refuses a carriage return in the parent's own id", () => {
    expect(
      buildDraft(
        draft({ inReplyTo: "<parent@example.invalid>\r\nBcc: x@y.invalid" }),
      ),
    ).toMatchObject({ built: false, refusal: "references-illegal-characters" });
  });
});

describe("foldReferences", () => {
  it("returns an empty value for an empty chain", () => {
    expect(foldReferences([])).toBe("");
  });

  it("keeps one line for a chain that fits", () => {
    expect(foldReferences(chain(3))).toBe(
      "<msg-0@example.invalid> <msg-1@example.invalid> <msg-2@example.invalid>",
    );
  });

  it("folds with CRLF and a single space, and never inside a token", () => {
    const folded = foldReferences(chain(60))!;
    const lines = folded.split("\r\n");

    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines.slice(1)) {
      expect(line.startsWith(" ")).toBe(true);
    }
    for (const token of chain(60)) {
      expect(folded).toContain(token);
    }
    // Every token survived whole: none was split across the fold.
    expect(folded.split(/\s+/).filter((one) => one.length > 0)).toHaveLength(60);
  });

  it("DROPS a token too wide to fold, rather than breaking the 998 ceiling", () => {
    // `REFERENCE_TOKEN` places no length bound on what sits between the angle
    // brackets, and the parent's References is stranger-authored —
    // `parseParentHeaders` splits it on whitespace and nothing else, so a
    // single 2,000-character message id arrives as ONE token. The fold loop
    // starts a fresh line for a token that will not fit beside the previous
    // one, but a token wider than a whole line has nowhere to go.
    //
    // The result is a header line past RFC 5322's hard limit on a message the
    // user SENDS, and some MTAs reject an over-long line outright — the same
    // "Apple rejects it hours later in Mail.app" failure the size ceiling was
    // added to avoid.
    const monstrous = `<${"x".repeat(2000)}@example.invalid>`;

    for (const tokens of [
      // First in the chain: the branch that opens the first line.
      [monstrous, ...chain(3)],
      // Mid-chain: the branch that opens a CONTINUATION line, which the fix
      // has to cover too. Both assignments were unchecked.
      [...chain(3), monstrous, ...chain(3)],
      // Alone, where there is no other token to hide the overflow.
      [monstrous],
    ]) {
      const folded = foldReferences(tokens);
      expect(folded).not.toBeNull();
      expect(folded).not.toContain(monstrous);

      // The property that actually matters, asserted on the EMITTED header
      // rather than on the token list: no line, counting the field name the
      // folder budgeted for, exceeds the ceiling.
      const lines = String(folded).split("\r\n");
      const encoder = new TextEncoder();
      lines.forEach((line, index) => {
        const width = encoder.encode(
          index === 0 ? `References: ${line}` : line,
        ).byteLength;
        expect(width).toBeLessThanOrEqual(998);
      });
    }
  });

  it("keeps a token that is wide but still foldable", () => {
    // The paired assertion. A bound tested only from above is indistinguishable
    // from one that drops everything, and this function dropping every token
    // would look exactly like a chain that simply did not thread.
    const wide = `<${"x".repeat(900)}@example.invalid>`;

    expect(foldReferences([wide])).toContain(wide);
  });

  it("returns null for a token carrying CR, LF or NUL", () => {
    expect(foldReferences(["<a@b.invalid>\r"])).toBeNull();
    expect(foldReferences(["<a@b.invalid>\n"])).toBeNull();
  });

  it("checks for CR BEFORE it checks the token's shape", () => {
    // The ordering is load-bearing. A token carrying a CR also fails the shape
    // check, so a shape-first implementation would silently DROP it — turning a
    // refusal into a repair, which is the thing this project does not do.
    expect(
      foldReferences(["not an id\r\nBcc: attacker@example.invalid"]),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The reply subject (RESEARCH § 2.5, a CONTEXT discretion item)
// ---------------------------------------------------------------------------

describe("replySubject", () => {
  it("adds exactly one prefix to a bare subject", () => {
    expect(replySubject("Interview follow-up")).toBe("Re: Interview follow-up");
  });

  it("collapses a run of three stacked ASCII prefixes to exactly one", () => {
    expect(replySubject("Re: RE: re: Interview follow-up")).toBe(
      "Re: Interview follow-up",
    );
  });

  it("collapses a bracketed counter and stray spacing too", () => {
    expect(replySubject("RE[2]: Re : Interview follow-up")).toBe(
      "Re: Interview follow-up",
    );
  });

  it("KEEPS an unrecognised localised prefix and puts one ASCII prefix in front", () => {
    // Stripping a prefix you do not recognise is how a subject loses a word
    // that was actually part of it, and a fixed table of foreign prefixes is a
    // table that is wrong for the next language. Doing the least is the answer.
    expect(replySubject("Aw: Vielen Dank")).toBe("Re: Aw: Vielen Dank");
    expect(replySubject("SV: Tack")).toBe("Re: SV: Tack");
    expect(replySubject("Antw: Bedankt")).toBe("Re: Antw: Bedankt");
  });

  it("does not eat a subject that merely BEGINS with those two letters", () => {
    expect(replySubject("Reminder about Tuesday")).toBe(
      "Re: Reminder about Tuesday",
    );
  });

  it("yields the bare prefix for a null or empty parent subject", () => {
    // Odd but honest. An absent Subject header on a draft is worse.
    expect(replySubject(null).trim()).toBe("Re:");
    expect(replySubject("").trim()).toBe("Re:");
  });

  it("exports the pattern it strips with, so the rule is inspectable", () => {
    expect(RE_PREFIX.test("Re: x")).toBe(true);
    expect(RE_PREFIX.test("Aw: x")).toBe(false);
  });

  it("survives a round trip through the builder as a header", async () => {
    const parsed = await PostalMime.parse(
      messageOf(draft({ subject: replySubject("Re: Grüße ☕") })),
    );

    expect(parsed.subject).toBe("Re: Grüße ☕");
  });
});

// ---------------------------------------------------------------------------
// The quoted original (D-71, D-73)
// ---------------------------------------------------------------------------

/** Markup a sanitiser would have removed, and that D-73 says must survive. */
const HOSTILE_FRAGMENT =
  '<img src="https://tracker.example.invalid/pixel.gif" width="1">' +
  '<a href="https://phish.example.invalid" onclick="steal()">click</a>';

describe("quoteOriginal", () => {
  it("names the date and the sender in the attribution line", async () => {
    const quoted = await quoteOriginal(parent());

    expect(quoted.attribution).toBe(
      "On Wed, 19 Aug 2026 09:14:02 +0000, Jane Doe wrote:",
    );
  });

  it("falls back to the address when the sender chose no display name", async () => {
    const quoted = await quoteOriginal(parent({ fromName: null }));

    expect(quoted.attribution).toContain("jane@example.invalid wrote:");
  });

  it("omits the date clause entirely when the parent's Date is absent or junk", async () => {
    expect((await quoteOriginal(parent({ date: null }))).attribution).toBe(
      "Jane Doe wrote:",
    );
    expect((await quoteOriginal(parent({ date: "whenever" }))).attribution).toBe(
      "Jane Doe wrote:",
    );
  });

  it("runs an HTML parent through the SHIPPED converter for the plain half", async () => {
    const quoted = await quoteOriginal(
      parent({
        bodySource: "text/html",
        html: "<p>First line.</p><p>Second <strong>line</strong>.</p>",
        text: "ignored — the converter is the source of truth here",
      }),
    );

    expect(quoted.text).toContain("First line.");
    expect(quoted.text).toContain("Second line.");
    expect(quoted.text).not.toContain("<p>");
  });

  it("uses the parent's own text when its chosen part was already plain", async () => {
    const quoted = await quoteOriginal(parent({ text: "Plain as sent." }));

    expect(quoted.text).toBe("Plain as sent.");
  });

  it("carries the parent's HTML through with no modification at all", async () => {
    const quoted = await quoteOriginal(
      parent({ bodySource: "text/html", html: HOSTILE_FRAGMENT }),
    );

    expect(quoted.html).toBe(HOSTILE_FRAGMENT);
  });
});

describe("the quoted original in the built draft", () => {
  it("puts the caller's words, a blank line and the attribution above the quote", async () => {
    const quoted = await quoteOriginal(parent());
    const parsed = await PostalMime.parse(
      messageOf(draft({ text: "Thanks for this.", html: null, quoted })),
    );
    const body = normaliseBreaks(parsed.text ?? "");

    expect(body.indexOf("Thanks for this.")).toBe(0);
    expect(body).toContain(
      "\n\nOn Wed, 19 Aug 2026 09:14:02 +0000, Jane Doe wrote:",
    );
    expect(body.indexOf("The original words.")).toBeGreaterThan(
      body.indexOf("Jane Doe wrote:"),
    );
  });

  it("nests the parent's HTML BYTE-IDENTICALLY inside a blockquote", async () => {
    // D-73, and the assertion that keeps it honest. A sanitiser, an allowlist
    // or an escaping pass would each break exactly this case, which is why the
    // gate is behavioural rather than a grep over the source.
    const quoted = await quoteOriginal(
      parent({
        bodySource: "text/html",
        html: `<p>Original.</p>${HOSTILE_FRAGMENT}`,
      }),
    );
    const parsed = await PostalMime.parse(
      messageOf(draft({ text: null, html: "<p>Thanks.</p>", quoted })),
    );

    expect(parsed.html).toContain("<blockquote");
    expect(parsed.html).toContain(HOSTILE_FRAGMENT);
    expect(parsed.html!.indexOf("<blockquote")).toBeLessThan(
      parsed.html!.indexOf(HOSTILE_FRAGMENT),
    );
    expect(parsed.html!.indexOf("Thanks.")).toBeLessThan(
      parsed.html!.indexOf("<blockquote"),
    );
  });

  it("ESCAPES the attribution line, which is this module's own construction", async () => {
    // Not a departure from D-73. The parent's CONTENT passes through untouched;
    // the attribution is a line this builder authors around a display name a
    // stranger chose, and an unescaped one would let that stranger write markup
    // OUTSIDE the blockquote, where a reader reads it as the user's own words.
    const quoted = await quoteOriginal(
      parent({ fromName: '<b>Bank of "Trust"</b> & Co' }),
    );
    const parsed = await PostalMime.parse(
      messageOf(draft({ text: null, html: "<p>Thanks.</p>", quoted })),
    );

    expect(parsed.html).toContain("&lt;b&gt;");
    expect(parsed.html).not.toContain("<b>Bank of");
  });

  it("escapes a plain-only parent when it reaches the HTML half", async () => {
    const quoted = await quoteOriginal(
      parent({ text: "1 < 2 & 3 > 2", html: null }),
    );
    const parsed = await PostalMime.parse(
      messageOf(draft({ text: null, html: "<p>Thanks.</p>", quoted })),
    );

    expect(parsed.html).toContain("1 &lt; 2 &amp; 3 &gt; 2");
  });

  it("carries the quote into BOTH halves of a two-part draft", async () => {
    const quoted = await quoteOriginal(
      parent({ bodySource: "text/html", html: "<p>Original words.</p>" }),
    );
    const parsed = await PostalMime.parse(
      messageOf(draft({ text: "Thanks.", html: "<p>Thanks.</p>", quoted })),
    );

    expect(parsed.text).toContain("Original words.");
    expect(parsed.html).toContain("<p>Original words.</p>");
  });

  it("keeps the boundary out of a quote that tries to carry one", async () => {
    // D-73 is what makes the boundary check adversarial rather than
    // probabilistic: the one place a collision could be CHOSEN is the exact
    // place this project decided not to sanitise.
    const quoted = await quoteOriginal(
      parent({ bodySource: "text/html", html: "<p>----=_iCloudMCP_ hello</p>" }),
    );
    const message = messageOf(
      draft({ text: "Thanks.", html: "<p>Thanks.</p>", quoted }),
    );
    const boundary = /boundary="([^"]+)"/.exec(message)![1]!;

    expect(message.split(`--${boundary}`)).toHaveLength(4);
  });

  it("still emits no line feed without a carriage return", () => {
    const bytes = bytesOf(
      draft({
        text: "Thanks.",
        html: "<p>Thanks.</p>",
        quoted: {
          attribution: "Jane Doe wrote:",
          text: "one\ntwo\nthree",
          html: "<p>one</p>\n<p>two</p>",
        },
      }),
    );

    expect(bareLineFeeds(bytes)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The attachment wrap (D-72's nesting sentence) and the stranger-authored
// filename that must never reach a header intact
//
// **The failure this section exists to catch is silent in both directions.** A
// wrapper emitted when none was wanted still appends; a wrapper omitted when one
// was wanted still appends; a `Content-Disposition` carrying a line break still
// appends, and the second header it injects was written by whoever named the
// file. Nothing here can be validated by "the message was accepted".
// ---------------------------------------------------------------------------

/** One attachment, with only the field under test overridden. */
function attachment(overrides: Partial<DraftAttachment> = {}): DraftAttachment {
  return {
    filename: "job-description.pdf",
    mimeType: "application/pdf",
    content: ENCODER.encode("%PDF-1.7 not really a document"),
    ...overrides,
  };
}

/** The FIRST boundary a message declares, which is always the outermost. */
function outerBoundary(message: string): string {
  return /boundary="([^"]+)"/.exec(message)![1]!;
}

/** Every boundary the message declares, outermost first. */
function boundaries(message: string): string[] {
  return [...message.matchAll(/boundary="([^"]+)"/g)].map((one) => one[1]!);
}

/**
 * The canonical two-part message, as the builder emitted it BEFORE this task.
 *
 * Committed rather than re-derived, which is the whole point: a test that built
 * the expected value from the same code under test would pass against any
 * regression the outer wrap introduced. The two identifiers are stubbed so the
 * fixture is a fixed value rather than a shape.
 */
const CANONICAL_NO_ATTACHMENT = [
  "From: someone@icloud.com",
  "To: recruiter@example.invalid",
  "Subject: Thanks for your time",
  "Date: Thu, 20 Aug 2026 14:22:05 +0000",
  "Message-ID: <bbbbbbbb-0000-4000-8000-000000000002@icloud.com>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/alternative; boundary="----=_iCloudMCP_aaaaaaaa-0000-4000-8000-000000000001"',
  "",
  "",
  "------=_iCloudMCP_aaaaaaaa-0000-4000-8000-000000000001",
  'Content-Type: text/plain; charset="UTF-8"',
  "Content-Transfer-Encoding: 7bit",
  "",
  "Hello there.",
  "------=_iCloudMCP_aaaaaaaa-0000-4000-8000-000000000001",
  'Content-Type: text/html; charset="UTF-8"',
  "Content-Transfer-Encoding: 7bit",
  "",
  "<p>Hello there.</p>",
  "------=_iCloudMCP_aaaaaaaa-0000-4000-8000-000000000001--",
  "",
].join("\r\n");

/** The inputs that produced `CANONICAL_NO_ATTACHMENT`, and nothing else. */
function canonicalDraft(overrides: Partial<DraftInput> = {}): DraftInput {
  return draft({
    text: "Hello there.",
    html: "<p>Hello there.</p>",
    ...overrides,
  });
}

/** Stub the identifier generator with a fixed sequence, in draw order. */
function stubUuids(...values: string[]): { mockRestore: () => void } {
  const spy = vi.spyOn(crypto, "randomUUID");
  for (const value of values) {
    spy.mockReturnValueOnce(value as `${string}-${string}-${string}-${string}-${string}`);
  }
  return spy;
}

describe("the multipart/mixed outer wrap", () => {
  it("emits NO wrapper at all when no file travels with the draft", () => {
    // The byte-identity case, against a committed fixture. Plans 04-03 and
    // 04-04 shaped the body assembly as a record precisely so this task is an
    // outer wrap rather than a restructure, and this is the assertion that
    // holds them to it.
    const spy = stubUuids(
      "aaaaaaaa-0000-4000-8000-000000000001",
      "bbbbbbbb-0000-4000-8000-000000000002",
    );
    const message = messageOf(canonicalDraft());
    spy.mockRestore();

    expect(message).toBe(CANONICAL_NO_ATTACHMENT);
    expect(message).not.toContain("multipart/mixed");
  });

  it("wraps the body tree in a multipart/mixed when one file travels with it", () => {
    const message = messageOf(canonicalDraft({ attachments: [attachment()] }));
    const declared = boundaries(message);

    // Outermost first: mixed wrapping alternative, never the other way round.
    expect(message).toContain("Content-Type: multipart/mixed;");
    expect(message.indexOf("multipart/mixed")).toBeLessThan(
      message.indexOf("multipart/alternative"),
    );
    expect(declared).toHaveLength(2);
    expect(declared[0]).not.toBe(declared[1]);
  });

  it("puts the body tree FIRST and every attachment after it", () => {
    const message = messageOf(
      canonicalDraft({
        attachments: [
          attachment({ filename: "first.pdf" }),
          attachment({ filename: "second.txt", mimeType: "text/plain" }),
        ],
      }),
    );
    const boundary = outerBoundary(message);
    const parts = message.split(`\r\n--${boundary}`);

    // One preamble-free head, three children, one terminator segment.
    expect(parts).toHaveLength(5);
    expect(parts[1]).toContain("multipart/alternative");
    expect(parts[1]).not.toContain("Content-Disposition:");
    expect(parts[2]).toContain('filename="first.pdf"');
    expect(parts[3]).toContain('filename="second.txt"');
    expect(parts[4]!.startsWith("--")).toBe(true);
  });

  it("wraps a SINGLE-part body just the same, without inventing a second body part", () => {
    // D-75's single-part tree is still a single part inside the wrap. A
    // one-child multipart/alternative here would be a different message.
    const message = messageOf(
      draft({ text: "Only plain.", html: null, attachments: [attachment()] }),
    );

    expect(message).toContain("Content-Type: multipart/mixed;");
    expect(message).not.toContain("multipart/alternative");
    expect(boundaries(message)).toHaveLength(1);
  });

  it("REGENERATES the outer boundary when its first candidate is the inner one", () => {
    // The adversarial case, and the only one that proves the scan covers the
    // inner boundary rather than only the part bodies. The first outer
    // candidate is forced to collide with the inner boundary, which occurs in
    // the rendered body tree's own headers and delimiters.
    const spy = stubUuids(
      "11111111-1111-4111-8111-111111111111", // the inner boundary
      "11111111-1111-4111-8111-111111111111", // the outer's first candidate
      "22222222-2222-4222-8222-222222222222", // the outer, regenerated
      "33333333-3333-4333-8333-333333333333", // the message id
    );
    const message = messageOf(canonicalDraft({ attachments: [attachment()] }));
    spy.mockRestore();

    const [outer, inner] = boundaries(message);
    expect(inner).toBe("----=_iCloudMCP_11111111-1111-4111-8111-111111111111");
    expect(outer).toBe("----=_iCloudMCP_22222222-2222-4222-8222-222222222222");
    expect(outer).not.toBe(inner);
  });

  it("emits an outer boundary absent from a part whose CONTENT is a plausible one", () => {
    // D-73 lets a stranger choose part content, so the collision is a chosen
    // value rather than a stumbled-into one.
    const hostile = "----=_iCloudMCP_00000000-0000-4000-8000-000000000000";
    const message = messageOf(
      draft({
        text: hostile,
        html: `<p>${hostile}</p>`,
        attachments: [attachment()],
      }),
    );

    for (const boundary of boundaries(message)) {
      expect(hostile.includes(boundary)).toBe(false);
    }
  });

  it("base64-encodes every attachment part whatever its declared type", () => {
    // A binary attachment has no other legal encoding, and a text/plain one
    // gets the same treatment rather than a per-type decision that can be
    // wrong. The wrap is RFC 2045's own 76-character figure.
    const message = messageOf(
      canonicalDraft({
        attachments: [
          attachment({
            filename: "notes.txt",
            mimeType: "text/plain",
            content: ENCODER.encode("plain words ".repeat(40)),
          }),
        ],
      }),
    );
    const part = message.split('Content-Disposition: attachment; filename="notes.txt"')[1]!;
    const body = part.split("\r\n\r\n")[1]!.split("\r\n------")[0]!;

    expect(message).toContain("Content-Transfer-Encoding: base64");
    expect(message).not.toContain('Content-Type: text/plain; charset="UTF-8"\r\nContent-Transfer-Encoding: 7bit\r\n\r\nplain words');
    for (const line of body.split("\r\n")) {
      expect(line.length).toBeLessThanOrEqual(76);
    }
    expect(atob(body.split("\r\n").join(""))).toBe("plain words ".repeat(40));
  });

  it("still emits no line feed without a carriage return, with binary bytes attached", () => {
    const bytes = bytesOf(
      canonicalDraft({
        attachments: [
          attachment({
            content: new Uint8Array([0x0a, 0x00, 0x0d, 0x0a, 0xff, 0x0a]),
          }),
        ],
      }),
    );

    expect(bareLineFeeds(bytes)).toEqual([]);
  });

  it("falls back to a neutral media type when the declared one cannot be a header", () => {
    // The declared type is sender-authored on the from-message path and reaches
    // a header of a message the user will send. It is metadata rather than a
    // gate, so an unusable one is replaced rather than refused — the same
    // disposition the staging module already gives it for storage.
    const message = messageOf(
      canonicalDraft({
        attachments: [attachment({ mimeType: 'application/pdf"; x="y' })],
      }),
    );

    expect(message).toContain("Content-Type: application/octet-stream");
    expect(message).not.toContain('x="y');
  });
});

describe("contentDispositionParams", () => {
  it("emits the plain parameter alone for an ordinary ASCII name", () => {
    expect(contentDispositionParams("resume.pdf")).toBe(
      '; filename="resume.pdf"',
    );
    expect(contentDispositionParams("resume.pdf")).not.toContain("filename*");
  });

  it("emits BOTH forms for a non-ASCII name, with the extension intact", () => {
    // The extended form takes precedence in a client that understands it; the
    // plain one is the fallback for a client that does not. The extension is
    // what decides whether the attachment opens, so it survives the fallback.
    const params = contentDispositionParams("Lebenslauf Müller.pdf")!;

    expect(params).toContain('filename="Lebenslauf M_ller.pdf"');
    expect(params).toContain("filename*=UTF-8''Lebenslauf%20M%C3%BCller.pdf");
    expect(params.endsWith(".pdf")).toBe(true);
  });

  it("uses RFC 2231, never an encoded-word, in a parameter value", () => {
    // Encoded-words are not valid in a parameter value. Matching the senders
    // who put one there is bug compatibility, and this server controls both
    // sides of what it writes.
    const params = contentDispositionParams("Grüße.txt")!;

    expect(params).not.toContain("=?UTF-8?");
    expect(params).toContain("filename*=UTF-8''Gr%C3%BC%C3%9Fe.txt");
  });

  it("keeps the plain form safely inside its quoted string", () => {
    // A quote or a backslash inside a quoted-string ends or escapes it. Both
    // are replaced in the fallback, and the extended form carries the original
    // losslessly — which is why the replacement is not a lossy repair.
    const params = contentDispositionParams('say "hi"\\.txt')!;

    expect(params).toContain('filename="say _hi__.txt"');
    expect(params).toContain("filename*=UTF-8''say%20%22hi%22%5C.txt");
  });

  it("REFUSES CR, LF and NUL rather than stripping them", () => {
    // The reason transfers from the two places this project already refuses
    // rather than repairs: a control character in a header parameter terminates
    // the header early and injects a second one built from a stranger's bytes,
    // into a message the user will send.
    expect(
      contentDispositionParams('a.pdf"\r\nBcc: attacker@evil.invalid'),
    ).toBeNull();
    expect(contentDispositionParams("a\nb.pdf")).toBeNull();
    expect(contentDispositionParams("a\rb.pdf")).toBeNull();
    expect(contentDispositionParams("a\x00b.pdf")).toBeNull();
  });
});

describe("a filename that tries to inject a header", () => {
  it("RETURNS a refusal and emits NO part carrying a partial name", () => {
    const hostile = 'invoice.pdf"\r\nBcc: attacker@evil.invalid';
    const result = buildDraft(
      canonicalDraft({ attachments: [attachment({ filename: hostile })] }),
    );

    expect(() =>
      buildDraft(
        canonicalDraft({ attachments: [attachment({ filename: hostile })] }),
      ),
    ).not.toThrow();
    expect(result).toEqual({
      built: false,
      refusal: "filename-illegal-characters",
    });
    // Nothing was assembled, so there is nothing carrying a truncated name.
    expect(result).not.toHaveProperty("bytes");
  });

  it("refuses the WHOLE build when only the second of two names is hostile", () => {
    // All-or-nothing, for the reason `addressList` already gives: a message
    // missing one attachment because that attachment was quietly dropped is a
    // worse outcome than a message that was not built.
    const result = buildDraft(
      canonicalDraft({
        attachments: [
          attachment({ filename: "fine.pdf" }),
          attachment({ filename: "bad\r\nX: y.pdf" }),
        ],
      }),
    );

    expect(result).toEqual({
      built: false,
      refusal: "filename-illegal-characters",
    });
  });
});

describe("two attachments, read back through PostalMime", () => {
  it("comes back with both filenames, both types and both byte lengths", async () => {
    // The independent oracle. A builder that merely looks plausible produces a
    // message this parser cannot take apart.
    const first = attachment({
      filename: "job-description.pdf",
      mimeType: "application/pdf",
      content: ENCODER.encode("%PDF-1.7 first document body"),
    });
    const second = attachment({
      filename: "notes.txt",
      mimeType: "text/plain",
      content: ENCODER.encode("second, and shorter"),
    });

    const parsed = await PostalMime.parse(
      messageOf(canonicalDraft({ attachments: [first, second] })),
    );

    expect(parsed.attachments).toHaveLength(2);
    expect(parsed.attachments.map((one) => one.filename)).toEqual([
      "job-description.pdf",
      "notes.txt",
    ]);
    expect(parsed.attachments.map((one) => one.mimeType)).toEqual([
      "application/pdf",
      "text/plain",
    ]);
    expect(
      parsed.attachments.map((one) => (one.content as ArrayBuffer).byteLength),
    ).toEqual([first.content.byteLength, second.content.byteLength]);
    expect(
      DECODER.decode(parsed.attachments[0]!.content as ArrayBuffer),
    ).toBe("%PDF-1.7 first document body");

    // The body halves are untouched by the wrap.
    expect(normaliseBreaks(parsed.text ?? "")).toBe("Hello there.");
    expect(parsed.html).toContain("<p>Hello there.</p>");
  });

  it("round-trips a non-ASCII filename through the extended parameter", async () => {
    const parsed = await PostalMime.parse(
      messageOf(
        canonicalDraft({
          attachments: [attachment({ filename: "Lebenslauf Müller.pdf" })],
        }),
      ),
    );

    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0]!.filename).toBe("Lebenslauf Müller.pdf");
  });
});
