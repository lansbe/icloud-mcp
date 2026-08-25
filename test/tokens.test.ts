// Direct coverage of the protocol-neutral token codec.
//
// `test/ids.test.ts` already exercises every one of these behaviours THROUGH
// the mail identifier layer, and it is deliberately not edited by the plan that
// created this file: it is the regression fence proving the extraction did not
// change what a mail token does. This suite is the other half — it drives the
// codec directly, so a future protocol tree that reuses it inherits assertions
// about the codec itself rather than assertions about mail.
//
// The last describe block is the join between the two. It asserts the
// PARAMETERISED REFUSAL: the neutral module throws a neutral error, and the
// mail tree translates it into its own not-found class at its own boundary. A
// codec that started leaking `TokenDecodeError` past that boundary would still
// pass every test above it, and would surface to a caller as
// `connection_failed` — a network diagnosis for a malformed identifier.

import { describe, expect, it } from "vitest";
import { ImapNotFoundError } from "../src/errors";
import { decodeCursor, decodeMessageId, encodeMessageId } from "../src/mail/ids";
import {
  TOKEN_DECODER,
  TOKEN_ENCODER,
  TokenDecodeError,
  base64Bytes,
  fromBase64Url,
  toBase64Url,
} from "../src/tokens";

describe("toBase64Url", () => {
  it("emits base64url's alphabet only — no padding, no + and no /", () => {
    // 0xFB 0xFF exercises both substituted characters: standard base64 of these
    // bytes carries a `+` and a `/`, which are exactly what must not survive.
    const encoded = toBase64Url(new Uint8Array([0xfb, 0xff, 0xbf, 0x00]));

    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("strips padding at every input length, so no = ever needs escaping", () => {
    // One, two and three bytes are the three padding cases; a token is carried
    // in places where `=` would need escaping, and this is why it never does.
    for (const length of [1, 2, 3, 4, 5]) {
      const bytes = new Uint8Array(length).fill(0xff);
      expect(toBase64Url(bytes)).not.toContain("=");
    }
  });

  it("round-trips arbitrary bytes, including every byte value", () => {
    const every = new Uint8Array(256);
    for (let index = 0; index < 256; index += 1) every[index] = index;

    expect(Array.from(fromBase64Url(toBase64Url(every)))).toEqual(
      Array.from(every),
    );
  });

  it("round-trips the empty case as an empty string, not as a throw", () => {
    expect(toBase64Url(new Uint8Array(0))).toBe("");
  });
});

describe("fromBase64Url refuses with a protocol-neutral error", () => {
  // Every case here names the SAME error, and that is the point of the whole
  // extraction: a neutral module cannot throw a protocol-specific class without
  // becoming protocol-specific itself, and a second decoder that threw a
  // different one would be a rule living in two places.
  const refused: [string, string][] = [
    ["a character outside the base64url alphabet", "abcd!"],
    ["standard base64's + character", "ab+d"],
    ["standard base64's / character", "ab/d"],
    ["standard base64 padding", "abcd=="],
    ["leading whitespace", " abcd"],
    ["trailing whitespace", "abcd "],
    ["embedded whitespace", "ab cd"],
    ["an embedded newline", "ab\ncd"],
    ["the empty string", ""],
    // `atob` tolerates whitespace and accepts the standard alphabet, so the
    // three cases above are refused by the alphabet check running BEFORE the
    // runtime primitive rather than by the primitive itself.
    ["a length that cannot be a base64 quantum", "AAAAA"],
  ];

  for (const [label, token] of refused) {
    it(`refuses ${label}`, () => {
      expect(() => fromBase64Url(token)).toThrow(TokenDecodeError);
    });
  }

  it("names no protocol in what it throws", () => {
    // The refusal is the one part of the extraction that was not mechanical.
    // If this class ever became a protocol-specific one, the neutral module
    // would be importing from a protocol tree — the exact dependency the
    // zero-import boundary exists to prevent.
    try {
      fromBase64Url("!");
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      expect(error).toBeInstanceOf(TokenDecodeError);
      expect(error).not.toBeInstanceOf(ImapNotFoundError);
      expect((error as TokenDecodeError).kind).toBe("token-decode");
    }
  });

  it("quotes nothing back — the offending token never reaches the message", () => {
    // Same discipline as every other error class in this repository: a
    // diagnosis that echoed the token, or explained which check it failed,
    // would teach the caller the format the opaque layer exists to withhold.
    try {
      fromBase64Url("SECRET-FOLDER!");
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      const surfaced = String((error as Error).message);
      expect(surfaced).not.toContain("SECRET-FOLDER");
      expect(surfaced).not.toContain("base64");
      expect(surfaced).not.toContain("alphabet");
    }
  });
});

describe("TOKEN_DECODER is strict, and both options are load-bearing", () => {
  it("throws on a malformed UTF-8 byte sequence, because fatal is set", () => {
    // The lenient default substitutes U+FFFD, which is repair rather than
    // decoding: a damaged token would silently become a token naming a
    // DIFFERENT resource, and the caller would receive a valid-looking answer
    // with no error anywhere.
    expect(() => TOKEN_DECODER.decode(new Uint8Array([0xff]))).toThrow();
    expect(() =>
      TOKEN_DECODER.decode(new Uint8Array([0x7b, 0xc3, 0x28, 0x7d])),
    ).toThrow();
  });

  it("keeps a leading byte-order mark rather than stripping it, because ignoreBOM is set", () => {
    // `ignoreBOM: true` is the stricter of the two readings despite how it
    // sounds. The mark survives as a code point, which is what lets JSON.parse
    // one layer up refuse a BOM-prefixed payload instead of accepting it as
    // though it had arrived clean.
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]);

    expect(TOKEN_DECODER.decode(withBom)).toBe("﻿{}");
    expect(() => JSON.parse(TOKEN_DECODER.decode(withBom))).toThrow();
    // The same bytes without the mark parse fine, so the assertion above is
    // about the mark and not about the payload.
    expect(JSON.parse(TOKEN_DECODER.decode(new Uint8Array([0x7b, 0x7d])))).toEqual(
      {},
    );
  });

  it("round-trips non-ASCII text through the encoder and back", () => {
    const text = "Entwürfe/€/日本語";

    expect(TOKEN_DECODER.decode(TOKEN_ENCODER.encode(text))).toBe(text);
  });

  it("encodes to UTF-8 bytes, not to UTF-16 code units", () => {
    // Two bytes for U+00E9, not one code unit. This is the same measurement
    // error as counting a wire length in code units.
    expect(Array.from(TOKEN_ENCODER.encode("é"))).toEqual([0xc3, 0xa9]);
  });
});

describe("base64Bytes", () => {
  it("encodes a non-ASCII input over its UTF-8 bytes, not its UTF-16 code units", () => {
    // The trap the signature exists to close. Handing a JavaScript string
    // straight to the runtime's base64 primitive encodes UTF-16 code units,
    // which is wrong for every non-ASCII byte — and the two answers differ, so
    // the bug is not cosmetic.
    const text = "Entwürfe";

    expect(base64Bytes(TOKEN_ENCODER.encode(text))).toBe("RW50d8O8cmZl");
    // btoa over the raw string would produce this instead. Asserting the two
    // are different is what makes the assertion above a measurement rather
    // than a restatement.
    expect(base64Bytes(TOKEN_ENCODER.encode(text))).not.toBe(btoa("Entwürfe"));
  });

  it("takes bytes, so the caller has already decided the encoding", () => {
    // A signature that accepted a string would let the caller skip that
    // decision, which is the whole failure mode above.
    expect(base64Bytes(new Uint8Array([0x00, 0xff]))).toBe("AP8=");
  });

  it("keeps standard base64's alphabet and padding, unlike toBase64Url", () => {
    // These two are deliberately different functions rather than one with a
    // flag: a Basic credential header needs standard base64 WITH padding, and
    // an identifier carried through a tool response needs neither.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);

    expect(base64Bytes(bytes)).toBe("+/+/");
    expect(toBase64Url(bytes)).toBe("-_-_");
    expect(base64Bytes(new Uint8Array([0x00]))).toContain("=");
  });
});

describe("the refusal is translated at each protocol tree's own boundary", () => {
  // The extraction's one non-mechanical change, asserted end to end. The neutral
  // module throws a neutral error; the mail identifier layer catches it and
  // throws its own not-found class. If that translation were ever lost, the
  // suites above would all still pass and the caller would be told the network
  // failed.
  const malformed = [
    "a character outside the alphabet",
    "abcd!",
    "leading whitespace",
    " abcd",
    "standard base64 padding",
    "abcd==",
  ];

  for (let index = 0; index < malformed.length; index += 2) {
    const label = malformed[index];
    const token = malformed[index + 1];

    it(`surfaces ${label} as the mail tree's not-found, never as the neutral error`, () => {
      expect(() => decodeMessageId(token)).toThrow(ImapNotFoundError);
      expect(() => decodeMessageId(token)).not.toThrow(TokenDecodeError);
      expect(() => decodeCursor(token)).toThrow(ImapNotFoundError);
    });
  }

  it("still round-trips a well-formed token after the extraction", () => {
    // The other half of the fence: refusing everything would pass every
    // assertion above.
    const token = encodeMessageId({
      mailbox: "Entw&APw-rfe",
      uidValidity: 3857529045,
      uid: 42,
    });

    expect(decodeMessageId(token)).toEqual({
      mailbox: "Entw&APw-rfe",
      uidValidity: 3857529045,
      uid: 42,
    });
  });
});
