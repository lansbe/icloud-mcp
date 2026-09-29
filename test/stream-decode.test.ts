// The save path's transfer decoder, checked window by window.
//
// The windows here are cut at every offset near the start, at fixed sizes, and
// at random places, because the save read cuts a part wherever its window size
// lands and not where a quantum or a line ends. Each valid case is also checked
// against the shipped decoder run over the joined text, so the two cannot
// quietly disagree about what a well-formed part decodes to.
//
// Every refusal case checks that no bytes come back. A short or empty array on
// a bad part is the failure this module exists to prevent.
//
// Pure. Nothing here opens a socket, stores anything or prints anything.

import { describe, expect, it } from "vitest";
import { transferDecode } from "../src/mail/mime";
import { decodeWindows, type DecodeOutcome } from "../src/mail/stream-decode";

const ENCODER = new TextEncoder();

/** A seeded byte source, so a failing case can be run again exactly. */
function seededBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let index = 0; index < length; index += 1) {
    // xorshift32
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[index] = state & 0xff;
  }
  return out;
}

/** Base64 of some bytes, wrapped at 76 columns with CRLF, as MIME sends it. */
function mimeBase64(bytes: Uint8Array): Uint8Array {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  const encoded = btoa(binary);
  const lines: string[] = [];
  for (let at = 0; at < encoded.length; at += 76) {
    lines.push(encoded.slice(at, at + 76));
  }
  return ENCODER.encode(lines.length === 0 ? "" : `${lines.join("\r\n")}\r\n`);
}

/** Cut `bytes` at the given offsets. Each window is its own copy. */
function cutAt(bytes: Uint8Array, cuts: readonly number[]): Uint8Array[] {
  const sorted = [...new Set(cuts)]
    .filter((cut) => cut > 0 && cut < bytes.length)
    .sort((a, b) => a - b);
  const windows: Uint8Array[] = [];
  let from = 0;
  for (const cut of sorted) {
    windows.push(bytes.slice(from, cut));
    from = cut;
  }
  windows.push(bytes.slice(from));
  return windows;
}

/** Cut `bytes` into windows of `size`. */
function windowsOf(bytes: Uint8Array, size: number): Uint8Array[] {
  const windows: Uint8Array[] = [];
  for (let at = 0; at < bytes.length; at += size) {
    windows.push(bytes.slice(at, at + size));
  }
  return windows;
}

function joined(windows: readonly Uint8Array[]): Uint8Array {
  const total = windows.reduce((sum, one) => sum + one.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const one of windows) {
    out.set(one, at);
    at += one.length;
  }
  return out;
}

/** The bytes of an outcome, or a failure naming the refusal it got instead. */
function bytesOf(outcome: DecodeOutcome): Uint8Array {
  if (!outcome.ok) throw new Error(`refused: ${outcome.refusal}`);
  return outcome.bytes;
}

/** A pure refusal: not ok, the named reason, and no bytes of any kind. */
function expectRefused(outcome: DecodeOutcome, refusal: string): void {
  expect(outcome.ok).toBe(false);
  expect(outcome).toEqual({ ok: false, refusal });
  expect("bytes" in outcome).toBe(false);
}

function sameBytes(actual: Uint8Array, expected: Uint8Array): boolean {
  if (actual.length !== expected.length) return false;
  for (let index = 0; index < actual.length; index += 1) {
    if (actual[index] !== expected[index]) return false;
  }
  return true;
}

const text = (value: string): Uint8Array => ENCODER.encode(value);

describe("decodeWindows: base64 across any window split", () => {
  const original = seededBytes(50_000, 0x29103);
  const encoded = mimeBase64(original);

  it("the fixture is real: 50,000 bytes, wrapped lines, and the shipped decoder agrees", () => {
    expect(encoded.length).toBeGreaterThan(66_000);
    expect(new TextDecoder().decode(encoded.subarray(76, 78))).toBe("\r\n");
    expect(sameBytes(transferDecode(encoded, "base64"), original)).toBe(true);
  });

  it("a single cut at every offset from 1 to 200 decodes to the exact original", () => {
    const failures: number[] = [];
    for (let cut = 1; cut <= 200; cut += 1) {
      const outcome = decodeWindows(cutAt(encoded, [cut]), "base64");
      if (!outcome.ok || !sameBytes(outcome.bytes, original)) failures.push(cut);
    }
    expect(failures).toEqual([]);
  });

  it("windows of every size from 1 to 200 decode to the exact original", () => {
    const failures: number[] = [];
    for (let size = 1; size <= 200; size += 1) {
      const outcome = decodeWindows(windowsOf(encoded, size), "base64");
      if (!outcome.ok || !sameBytes(outcome.bytes, original)) failures.push(size);
    }
    expect(failures).toEqual([]);
  });

  it("a few hundred random multi-cut splits decode to the exact original", () => {
    const picks = seededBytes(300 * 8 * 4, 0xc0ffee);
    const view = new DataView(picks.buffer);
    const failures: number[] = [];
    for (let trial = 0; trial < 300; trial += 1) {
      const cuts: number[] = [];
      for (let slot = 0; slot < 8; slot += 1) {
        cuts.push(view.getUint32((trial * 8 + slot) * 4) % encoded.length);
      }
      const windows = cutAt(encoded, cuts);
      const outcome = decodeWindows(windows, "base64");
      if (!outcome.ok || !sameBytes(outcome.bytes, original)) failures.push(trial);
    }
    expect(failures).toEqual([]);
  });

  it("the encoded windows are handed over separately, and none of them is the joined text", () => {
    const windows = windowsOf(encoded, 4096);
    const outcome = decodeWindows(windows, "base64");
    expect(windows.length).toBeGreaterThan(10);
    expect(sameBytes(bytesOf(outcome), original)).toBe(true);
    // The windows are unchanged by the decode.
    expect(sameBytes(joined(windows), encoded)).toBe(true);
  });
});

describe("decodeWindows: base64 cut at the awkward places", () => {
  it("a cut inside a four-character quantum decodes exactly", () => {
    const original = text("Hello, window!");
    const encoded = mimeBase64(original);
    for (const cut of [1, 2, 3, 5, 6, 7]) {
      expect(sameBytes(bytesOf(decodeWindows(cutAt(encoded, [cut]), "base64")), original)).toBe(
        true,
      );
    }
  });

  it("a cut between CR and LF decodes exactly", () => {
    const original = seededBytes(300, 7);
    const encoded = mimeBase64(original);
    const cr = encoded.indexOf(0x0d);
    expect(encoded[cr + 1]).toBe(0x0a);
    const outcome = decodeWindows(cutAt(encoded, [cr + 1]), "base64");
    expect(sameBytes(bytesOf(outcome), original)).toBe(true);
  });

  it("a cut between the two padding characters decodes exactly", () => {
    const original = seededBytes(301, 11); // 301 % 3 === 1, so two padding characters
    const encoded = mimeBase64(original);
    const firstPad = encoded.indexOf(0x3d);
    expect(encoded[firstPad + 1]).toBe(0x3d);
    const outcome = decodeWindows(cutAt(encoded, [firstPad + 1]), "base64");
    expect(sameBytes(bytesOf(outcome), original)).toBe(true);
  });

  it.each([
    [3000, 0, "no padding"],
    [3001, 2, "two padding characters"],
    [3002, 1, "one padding character"],
  ])("a file of %i bytes (%s padding characters: %s) decodes exactly", (length, pads) => {
    const original = seededBytes(length, length);
    const encoded = mimeBase64(original);
    const trimmed = new TextDecoder().decode(encoded).trimEnd();
    expect(trimmed.length - trimmed.replace(/=+$/, "").length).toBe(pads);
    expect(sameBytes(bytesOf(decodeWindows(windowsOf(encoded, 97), "base64")), original)).toBe(
      true,
    );
  });

  it("space and tab inside the text are skipped", () => {
    const original = text("spaces and tabs");
    const plain = new TextDecoder().decode(mimeBase64(original)).trim();
    const spaced = `${plain.slice(0, 5)} \t ${plain.slice(5, 9)}\t${plain.slice(9)} `;
    const outcome = decodeWindows(cutAt(text(spaced), [6, 7]), "base64");
    expect(sameBytes(bytesOf(outcome), original)).toBe(true);
  });

  it("every valid case above equals the shipped decoder's answer on the joined text", () => {
    const cases: Uint8Array[][] = [];
    for (const length of [0, 1, 2, 3, 57, 58, 59, 300, 301, 302]) {
      const encoded = mimeBase64(seededBytes(length, length + 1));
      cases.push(windowsOf(encoded, 5), cutAt(encoded, [1, 13, 77, 78]));
    }
    for (const windows of cases) {
      const outcome = decodeWindows(windows, "base64");
      expect(sameBytes(bytesOf(outcome), transferDecode(joined(windows), "base64"))).toBe(true);
    }
  });
});

describe("decodeWindows: malformed base64 is refused by name, never shortened", () => {
  it.each([
    ["an exclamation mark", "QUJD!RA=="],
    ["a hyphen (the URL alphabet)", "QUJD-A=="],
    ["an underscore (the URL alphabet)", "QUJD_A=="],
    ["a NUL byte", "QUJD\u0000RA=="],
    ["a vertical tab", "QUJD\u000bRA=="],
    ["a form feed", "QUJD\u000cRA=="],
  ])("a character outside the alphabet (%s) is malformed", (_label, body) => {
    expectRefused(decodeWindows([text(body)], "base64"), "malformed-encoding");
  });

  it("a byte above 0x7F is malformed", () => {
    expectRefused(
      decodeWindows([text("QUJD"), new Uint8Array([0xc3, 0xa9]), text("RA==")], "base64"),
      "malformed-encoding",
    );
  });

  it.each([
    ["alphabet after padding", "QQ==QUJD"],
    ["alphabet after padding, across a window", "QQ==|QUJD"],
    ["a second padded quantum after the first", "QQ==\r\nQQ=="],
    ["three padding characters", "QQ==="],
    ["padding in the second place", "Q==="],
    ["padding in the first place", "====QUJD"],
    ["padding then alphabet inside one quantum", "QQ=A"],
  ])("padding out of place (%s) is malformed", (_label, body) => {
    const windows = body.split("|").map(text);
    expectRefused(decodeWindows(windows, "base64"), "malformed-encoding");
  });

  it.each([
    ["two characters", "QUJDRA"],
    ["three characters", "QUJDREU"],
    ["one character", "QUJDR"],
    ["a single padding character short", "QQ="],
  ])("a tail that is not a whole quantum (%s) is malformed", (_label, body) => {
    expectRefused(decodeWindows([text(body)], "base64"), "malformed-encoding");
  });

  it("where the shipped decoder answers empty or drops a character, this one refuses", () => {
    // Not a claim about the shipped decoder being wrong: it is right for a snippet.
    // Padding in the middle: the shipped decoder answers with no bytes at all.
    expect(transferDecode(text("QQ==QUJD"), "base64").length).toBe(0);
    expectRefused(decodeWindows([text("QQ==QUJD")], "base64"), "malformed-encoding");
    // A foreign character: the shipped decoder drops it and decodes the rest.
    expect(transferDecode(text("QUJD!RA=="), "base64").length).toBe(4);
    expectRefused(decodeWindows([text("QUJD!RA==")], "base64"), "malformed-encoding");
  });
});

describe("decodeWindows: quoted-printable across a window split", () => {
  const whole = "Caf=C3=A9 and a soft=\r\nbreak, then =41 and a bare = sign.\r\nend=\r\n";
  const uncut = bytesOf(decodeWindows([text(whole)], "quoted-printable"));

  it("the uncut text decodes as the shipped decoder decodes it", () => {
    expect(sameBytes(uncut, transferDecode(text(whole), "quoted-printable"))).toBe(true);
    expect(new TextDecoder().decode(uncut)).toBe(
      "Café and a softbreak, then A and a bare = sign.\r\nend",
    );
  });

  it('a soft line break cut as "=" | CRLF decodes the same as the uncut text', () => {
    const cut = whole.indexOf("=\r\n") + 1;
    const outcome = decodeWindows(cutAt(text(whole), [cut]), "quoted-printable");
    expect(sameBytes(bytesOf(outcome), uncut)).toBe(true);
  });

  it('a soft line break cut as "=CR" | LF decodes the same as the uncut text', () => {
    const cut = whole.indexOf("=\r\n") + 2;
    const outcome = decodeWindows(cutAt(text(whole), [cut]), "quoted-printable");
    expect(sameBytes(bytesOf(outcome), uncut)).toBe(true);
  });

  it('an escape cut as "=4" | "1" decodes the same as the uncut text', () => {
    const cut = whole.indexOf("=41") + 2;
    const outcome = decodeWindows(cutAt(text(whole), [cut]), "quoted-printable");
    expect(sameBytes(bytesOf(outcome), uncut)).toBe(true);
  });

  it("windows of every size from 1 to 40 decode the same as the uncut text", () => {
    const failures: number[] = [];
    for (let size = 1; size <= 40; size += 1) {
      const outcome = decodeWindows(windowsOf(text(whole), size), "quoted-printable");
      if (!outcome.ok || !sameBytes(outcome.bytes, uncut)) failures.push(size);
    }
    expect(failures).toEqual([]);
  });

  it("the encoding name is matched without regard to case", () => {
    const outcome = decodeWindows([text(whole)], "Quoted-Printable");
    expect(sameBytes(bytesOf(outcome), uncut)).toBe(true);
  });
});

describe("decodeWindows: 7bit, 8bit and binary pass through", () => {
  const raw = seededBytes(1000, 42);

  it.each(["7bit", "8bit", "binary", "BINARY", "8Bit", "7BIT"])(
    "%s returns the windows' bytes joined, byte for byte",
    (encoding) => {
      const windows = cutAt(raw, [1, 99, 500, 999]);
      const outcome = decodeWindows(windows, encoding);
      expect(sameBytes(bytesOf(outcome), raw)).toBe(true);
    },
  );
});

describe("decodeWindows: anything else is refused by name", () => {
  it.each(["x-uuencode", "", "base-64", "quoted_printable", "uuencode", " base64"])(
    "encoding %j is encoding-unsupported",
    (encoding) => {
      expectRefused(decodeWindows([text("QUJD")], encoding), "encoding-unsupported");
    },
  );
});

describe("decodeWindows: no windows at all", () => {
  it.each(["base64", "quoted-printable", "7bit", "8bit", "binary"])(
    "an empty window list with %s decodes to zero bytes",
    (encoding) => {
      const outcome = decodeWindows([], encoding);
      expect(outcome.ok).toBe(true);
      expect(bytesOf(outcome).length).toBe(0);
    },
  );

  it("an empty window list with an unsupported encoding is still refused", () => {
    expectRefused(decodeWindows([], "x-uuencode"), "encoding-unsupported");
  });
});
