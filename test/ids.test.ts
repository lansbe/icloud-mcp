// The opaque identifier layer: round-trip fidelity, and refusal of everything
// that is not a token this codec minted.
//
// Pure units. No sockets, no session, no network — the module under test is
// attached to nothing but one error class.

import { describe, expect, it } from "vitest";
import { toErrorCategory } from "../src/errors";
import { ImapNotFoundError } from "../src/errors";
import type { AttachmentRef, MessageRef, PageCursor, StagedRef } from "../src/mail/ids";
import {
  STAGED_ID_TTL_MS,
  TOKEN_VERSION,
  decodeAttachmentId,
  decodeCursor,
  decodeFolderId,
  decodeMessageId,
  decodeStagedId,
  encodeAttachmentId,
  encodeCursor,
  encodeFolderId,
  encodeMessageId,
  encodeStagedId,
} from "../src/mail/ids";

/**
 * Base64url of an arbitrary value, re-implemented here on purpose.
 *
 * The negative cases below must be built WITHOUT the encoder under test,
 * because a bug shared between encoder and test helper would cancel out and
 * leave the refusal cases green against a broken codec.
 */
function mint(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** The bytes of a string, so "byte-identical" is asserted rather than asserted-ish. */
function bytesOf(value: string): number[] {
  return Array.from(new TextEncoder().encode(value));
}

/**
 * Base64url of arbitrary BYTES, for the cases that cannot be expressed as a
 * JavaScript string at all.
 *
 * `mint` above goes through `JSON.stringify`, which can only produce well-formed
 * UTF-8. The two decoder-strictness cases below need deliberately malformed
 * bytes, so they are built at this level instead.
 */
function mintRaw(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A payload that is entirely valid, used as the base for byte-level damage. */
const WELL_FORMED_PAYLOAD = '{"v":1,"k":"m","m":"INBOX","uv":1,"u":1}';

const ASCII_REF: MessageRef = {
  mailbox: "INBOX",
  uidValidity: 1234567890,
  uid: 4711,
};

const ASCII_CURSOR: PageCursor = {
  mailbox: "INBOX",
  uidValidity: 1234567890,
  lastUid: 4725,
};

/**
 * The wire form of a French folder as a server actually emits it.
 *
 * Modified UTF-7 is ASCII by construction — `Réunions` goes out as
 * `R&AOk-unions`. The point of this fixture is that the codec must NOT decode
 * it: what goes in must come out spelled exactly this way, because this is the
 * byte sequence that will be written back into `EXAMINE`.
 */
const MUTF7_WIRE_NAME = "R&AOk-unions";

/** A server that speaks RFC 6855 emits the name as raw UTF-8 instead. */
const RAW_UTF8_WIRE_NAME = "Réunions ☕ 受信箱";

const ASCII_ATTACHMENT: AttachmentRef = {
  mailbox: "INBOX",
  uidValidity: 1234567890,
  uid: 4711,
  path: "2",
};

/**
 * A fixed instant, so the expiry assertions are about the expiry and not about
 * how long the suite took to run.
 *
 * Every staged case injects its own `now` rather than leaning on the wall
 * clock. Both `encodeStagedId` and `decodeStagedId` take the current time as a
 * parameter for exactly this reason: a TTL tested against a real clock is a TTL
 * tested by waiting, and an expiry fixture pinned to a literal instant would
 * otherwise start failing the moment the wall clock passed it.
 */
const MINT_INSTANT = 1_766_000_000_000;

const FRESH_STAGED: StagedRef = {
  key: "staging/resume.pdf-1766000000000",
  expiresAt: MINT_INSTANT + STAGED_ID_TTL_MS,
};

describe("round-tripping a message id", () => {
  it("returns exactly the values that went in, for an ordinary ASCII mailbox", () => {
    expect(decodeMessageId(encodeMessageId(ASCII_REF))).toEqual(ASCII_REF);
  });

  it("carries a modified-UTF-7 wire name through without decoding it", () => {
    // The decoder this project needs is modified-UTF-7 -> display, applied at
    // the presentation edge. It must never run here, or the name written back
    // into EXAMINE would be the display form and would select nothing.
    const ref: MessageRef = { ...ASCII_REF, mailbox: MUTF7_WIRE_NAME };
    const decoded = decodeMessageId(encodeMessageId(ref));

    expect(decoded.mailbox).toBe(MUTF7_WIRE_NAME);
    expect(decoded.mailbox).not.toBe("Réunions");
    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(MUTF7_WIRE_NAME));
  });

  it("carries raw non-ASCII wire bytes through byte-identically", () => {
    // The base64-over-UTF-16-code-units bug credentials.ts records would show
    // up here and nowhere else: every one of these characters is multi-byte.
    const ref: MessageRef = { ...ASCII_REF, mailbox: RAW_UTF8_WIRE_NAME };
    const decoded = decodeMessageId(encodeMessageId(ref));

    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(RAW_UTF8_WIRE_NAME));
  });

  it("carries a UIDVALIDITY and a UID above 2^31 without corrupting them", () => {
    // 3857529045 is RFC 3501's own worked UIDVALIDITY example and sits above
    // 2^31. A signed-32-bit assumption anywhere on this path turns it negative.
    const ref: MessageRef = {
      mailbox: "INBOX",
      uidValidity: 3857529045,
      uid: 4294967295,
    };
    const decoded = decodeMessageId(encodeMessageId(ref));

    expect(decoded.uidValidity).toBe(3857529045);
    expect(decoded.uid).toBe(4294967295);
    expect(decoded.uidValidity).toBeGreaterThan(2 ** 31);
  });
});

describe("round-tripping a page cursor", () => {
  it("returns exactly the values that went in", () => {
    expect(decodeCursor(encodeCursor(ASCII_CURSOR))).toEqual(ASCII_CURSOR);
  });

  it("carries a non-ASCII wire name and a large UIDVALIDITY", () => {
    const cursor: PageCursor = {
      mailbox: RAW_UTF8_WIRE_NAME,
      uidValidity: 3857529045,
      lastUid: 2147483648,
    };
    expect(decodeCursor(encodeCursor(cursor))).toEqual(cursor);
  });
});

describe("round-tripping a folder id", () => {
  it("returns exactly the wire name that went in", () => {
    expect(decodeFolderId(encodeFolderId({ mailbox: "INBOX" }))).toEqual({
      mailbox: "INBOX",
    });
  });

  it("carries a modified-UTF-7 wire name through without decoding it", () => {
    // The one that matters most for this kind: a folder token is what a listing
    // hands the model, and the listing is also where the DISPLAY name is
    // produced. Minting the display form here would need an encoder this
    // project deliberately does not have, and the name written back into
    // EXAMINE would select nothing.
    const decoded = decodeFolderId(
      encodeFolderId({ mailbox: MUTF7_WIRE_NAME }),
    );

    expect(decoded.mailbox).toBe(MUTF7_WIRE_NAME);
    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(MUTF7_WIRE_NAME));
  });

  it("carries raw non-ASCII wire bytes through byte-identically", () => {
    const decoded = decodeFolderId(
      encodeFolderId({ mailbox: RAW_UTF8_WIRE_NAME }),
    );

    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(RAW_UTF8_WIRE_NAME));
  });

  it("does not expose the wire name as a readable substring of the token", () => {
    // Not a security property — base64 is not encryption — but the reason the
    // model is handed a token rather than a name is that a name it can read is
    // a name it can construct. A token that spelled the mailbox out would
    // invite exactly that.
    expect(encodeFolderId({ mailbox: "Sent Messages" })).not.toContain(
      "Sent Messages",
    );
  });

  it("refuses an empty mailbox on the way OUT as well as the way in", () => {
    // A token that could not survive its own decoder must never be handed to a
    // caller: the failure would surface arbitrarily far from the code that
    // built it, against a token that by then looks like the model's fault.
    expect(() => encodeFolderId({ mailbox: "" })).toThrow(ImapNotFoundError);
  });
});

describe("round-tripping an attachment id", () => {
  it("returns exactly the values that went in", () => {
    expect(decodeAttachmentId(encodeAttachmentId(ASCII_ATTACHMENT))).toEqual(
      ASCII_ATTACHMENT,
    );
  });

  it("carries a nested part path through unchanged", () => {
    // `1.2.3` is what the BODYSTRUCTURE walk emits for an attachment inside a
    // nested multipart. The path is the address a later part fetch uses, so a
    // segment lost or reordered here addresses a different part of the same
    // message — the "wrong answer, no error" shape this module exists to refuse.
    const ref: AttachmentRef = { ...ASCII_ATTACHMENT, path: "1.2.3" };

    expect(decodeAttachmentId(encodeAttachmentId(ref)).path).toBe("1.2.3");
  });

  it("carries a modified-UTF-7 wire name through without decoding it", () => {
    const ref: AttachmentRef = {
      ...ASCII_ATTACHMENT,
      mailbox: MUTF7_WIRE_NAME,
    };
    const decoded = decodeAttachmentId(encodeAttachmentId(ref));

    expect(decoded.mailbox).toBe(MUTF7_WIRE_NAME);
    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(MUTF7_WIRE_NAME));
  });

  it("carries raw non-ASCII wire bytes through byte-identically", () => {
    const ref: AttachmentRef = {
      ...ASCII_ATTACHMENT,
      mailbox: RAW_UTF8_WIRE_NAME,
    };
    const decoded = decodeAttachmentId(encodeAttachmentId(ref));

    expect(bytesOf(decoded.mailbox)).toEqual(bytesOf(RAW_UTF8_WIRE_NAME));
  });

  it("carries a UIDVALIDITY and a UID above 2^31 without corrupting them", () => {
    // D-18's gate rides along unchanged: an attachment id minted before a
    // mailbox's validity changed must not silently address a different message.
    const ref: AttachmentRef = {
      mailbox: "INBOX",
      uidValidity: 3857529045,
      uid: 4294967295,
      path: "2",
    };
    const decoded = decodeAttachmentId(encodeAttachmentId(ref));

    expect(decoded.uidValidity).toBe(3857529045);
    expect(decoded.uid).toBe(4294967295);
  });

  it("does not expose the mailbox as a readable substring of the token", () => {
    // Same argument the folder kind makes: a value the model can read is a
    // value the model can construct, and D-76 rejected a hand-constructible
    // part path precisely because it addresses ANY part including the body.
    // Asserted on the mailbox rather than on the path, because a two-character
    // path would collide with the base64 alphabet by chance and turn a real
    // property into a flaky one.
    expect(
      encodeAttachmentId({ ...ASCII_ATTACHMENT, mailbox: "Sent Messages" }),
    ).not.toContain("Sent Messages");
  });
});

describe("refusing a part path the structure walk could not have produced", () => {
  /**
   * Every segment the walk emits is `String(index + 1)` (`mime.ts:353`), so the
   * producible set is digits with no leading zero, joined by single dots. A
   * decoded path outside that set names nothing the server described, and the
   * ones carrying a letter or a bracket are how a section keyword would reach a
   * fetch item (T-04-02-03).
   */
  const BAD_PATHS: ReadonlyArray<readonly [string, unknown]> = [
    ["an absent path", undefined],
    ["a null path", null],
    ["a numeric path", 2],
    [
      "the empty string — legal for a BodyPart, but no attachment carries one",
      "",
    ],
    ["a zero segment", "0"],
    ["a leading zero", "01"],
    ["a leading zero in a later segment", "1.02"],
    ["a leading dot", ".1"],
    ["a trailing dot", "1."],
    ["a doubled dot", "1..2"],
    ["a letter", "1.a"],
    ["a section keyword", "1.HEADER"],
    ["a fetch-item bracket", "1]"],
    ["a byte range", "1<0.1024>"],
    ["whitespace", "1 2"],
    ["a CRLF", "1\r\n2"],
    ["a negative segment", "-1"],
    ["a fractional-looking path", "1.5.x"],
  ];

  for (const [name, path] of BAD_PATHS) {
    it(`refuses ${name} on decode`, () => {
      const token = mint({
        v: TOKEN_VERSION,
        k: "a",
        m: "INBOX",
        uv: 1,
        u: 1,
        p: path,
      });

      expect(() => decodeAttachmentId(token)).toThrow(ImapNotFoundError);
    });
  }

  it("refuses a bad path on the way OUT as well as the way in", () => {
    expect(() =>
      encodeAttachmentId({ ...ASCII_ATTACHMENT, path: "1.HEADER" }),
    ).toThrow(ImapNotFoundError);
    expect(() => encodeAttachmentId({ ...ASCII_ATTACHMENT, path: "" })).toThrow(
      ImapNotFoundError,
    );
  });

  it("refuses an out-of-range UID and an empty mailbox at encode time", () => {
    expect(() =>
      encodeAttachmentId({ ...ASCII_ATTACHMENT, uid: -1 }),
    ).toThrow(ImapNotFoundError);
    expect(() =>
      encodeAttachmentId({ ...ASCII_ATTACHMENT, mailbox: "" }),
    ).toThrow(ImapNotFoundError);
  });
});

describe("round-tripping a staged id", () => {
  it("returns exactly the values that went in", () => {
    const token = encodeStagedId(FRESH_STAGED, MINT_INSTANT);

    expect(decodeStagedId(token, MINT_INSTANT)).toEqual(FRESH_STAGED);
  });

  it("carries a non-ASCII object key through byte-identically", () => {
    const ref: StagedRef = { ...FRESH_STAGED, key: "staging/Réunions ☕.pdf-1" };
    const decoded = decodeStagedId(
      encodeStagedId(ref, MINT_INSTANT),
      MINT_INSTANT,
    );

    expect(bytesOf(decoded.key)).toEqual(bytesOf(ref.key));
  });

  it("is still valid one millisecond before it expires", () => {
    const token = encodeStagedId(FRESH_STAGED, MINT_INSTANT);

    expect(
      decodeStagedId(token, FRESH_STAGED.expiresAt - 1).key,
    ).toBe(FRESH_STAGED.key);
  });

  it("is refused at the instant it expires, not one millisecond after", () => {
    // "At or before" rather than "before": the boundary is closed on purpose,
    // because the alternative leaves a one-millisecond window in which the
    // token is valid and its stated expiry has passed.
    const token = encodeStagedId(FRESH_STAGED, MINT_INSTANT);

    expect(() => decodeStagedId(token, FRESH_STAGED.expiresAt)).toThrow(
      ImapNotFoundError,
    );
  });

  it("refuses a token whose expiry has passed, with no check at the call site", () => {
    // D-82's whole point: the staged id carries its own expiry, so a caller
    // holding one cannot forget to ask whether it is still good.
    const token = encodeStagedId(FRESH_STAGED, MINT_INSTANT);

    expect(() =>
      decodeStagedId(token, FRESH_STAGED.expiresAt + 60 * 60 * 1000),
    ).toThrow(ImapNotFoundError);
  });

  it("expires exactly 24 hours after minting", () => {
    // The number is load-bearing rather than decorative: the bytes live 24-48
    // hours under a whole-day lifecycle rule, so a token living longer than 24
    // could name an object the sweep has already removed (D-82).
    expect(STAGED_ID_TTL_MS).toBe(24 * 60 * 60 * 1000);
    expect(FRESH_STAGED.expiresAt - MINT_INSTANT).toBe(STAGED_ID_TTL_MS);
  });

  it("refuses to mint a token that is already expired", () => {
    expect(() =>
      encodeStagedId(
        { key: "staging/late.pdf-1", expiresAt: MINT_INSTANT - 1 },
        MINT_INSTANT,
      ),
    ).toThrow(ImapNotFoundError);
  });

  it("refuses to mint a token with no object key", () => {
    expect(() =>
      encodeStagedId(
        { key: "", expiresAt: MINT_INSTANT + STAGED_ID_TTL_MS },
        MINT_INSTANT,
      ),
    ).toThrow(ImapNotFoundError);
  });

  /** The expiry guard, which is where a millisecond/second mix-up would hide. */
  const BAD_EXPIRIES: ReadonlyArray<readonly [string, unknown]> = [
    ["an absent expiry", undefined],
    ["a null expiry", null],
    ["a string expiry", "1766086400000"],
    ["a fractional expiry", MINT_INSTANT + 0.5],
    ["a NaN expiry", Number.NaN],
    ["an infinite expiry", Number.POSITIVE_INFINITY],
    ["a zero expiry", 0],
    ["a negative expiry", -1],
    ["an expiry beyond the safe-integer range", 2 ** 53],
  ];

  for (const [name, expiry] of BAD_EXPIRIES) {
    it(`refuses ${name}`, () => {
      const token = mint({
        v: TOKEN_VERSION,
        k: "s",
        o: "staging/resume.pdf-1",
        x: expiry,
      });

      expect(() => decodeStagedId(token, MINT_INSTANT)).toThrow(
        ImapNotFoundError,
      );
    });
  }

  it("refuses a payload whose object key is missing or not a string", () => {
    const noKey = mint({
      v: TOKEN_VERSION,
      k: "s",
      x: MINT_INSTANT + STAGED_ID_TTL_MS,
    });
    const numericKey = mint({
      v: TOKEN_VERSION,
      k: "s",
      o: 7,
      x: MINT_INSTANT + STAGED_ID_TTL_MS,
    });

    expect(() => decodeStagedId(noKey, MINT_INSTANT)).toThrow(
      ImapNotFoundError,
    );
    expect(() => decodeStagedId(numericKey, MINT_INSTANT)).toThrow(
      ImapNotFoundError,
    );
  });

  it("does not read the kind letter as the object key", () => {
    // The reason the field is `o` rather than `key`: `payload.k` is a non-empty
    // string on every well-formed token, so a decoder reading it by mistake
    // would pass a string assertion and hand back an object key of "s".
    const decoded = decodeStagedId(
      encodeStagedId(FRESH_STAGED, MINT_INSTANT),
      MINT_INSTANT,
    );

    expect(decoded.key).not.toBe("s");
    expect(decoded.key).toBe(FRESH_STAGED.key);
  });

  it("defaults to the wall clock when no time is injected", () => {
    // The injected parameter exists for the tests; the default is what every
    // caller actually gets, and a default wired to the wrong thing would make
    // every assertion above meaningless in production.
    const token = encodeStagedId({
      key: "staging/soon.pdf-1",
      expiresAt: Date.now() + STAGED_ID_TTL_MS,
    });

    expect(decodeStagedId(token).key).toBe("staging/soon.pdf-1");

    const stale = mint({
      v: TOKEN_VERSION,
      k: "s",
      o: "staging/stale.pdf-1",
      x: Date.now() - 1,
    });

    expect(() => decodeStagedId(stale)).toThrow(ImapNotFoundError);
  });
});

/**
 * Five kinds is twenty ORDERED pairs, and the table below is generated rather
 * than hand-written so it cannot quietly cover nineteen.
 *
 * A refusal asserted in one direction only is half a rule. The two directions
 * genuinely differ: a message id fed to the attachment decoder fails the kind
 * check AND the required-field check, while an attachment id fed to the message
 * decoder fails the kind check alone — its `m`, `uv` and `u` are a real
 * message's. Asserting only the easy direction would leave the barrier that
 * actually carries the weight untested.
 */
const KIND_NAMES = [
  "message",
  "cursor",
  "folder",
  "attachment",
  "staged",
] as const;

type KindName = (typeof KIND_NAMES)[number];

const MINT_BY_KIND: Record<KindName, () => string> = {
  message: () => encodeMessageId(ASCII_REF),
  cursor: () => encodeCursor(ASCII_CURSOR),
  folder: () => encodeFolderId({ mailbox: "INBOX" }),
  attachment: () => encodeAttachmentId(ASCII_ATTACHMENT),
  staged: () => encodeStagedId(FRESH_STAGED, MINT_INSTANT),
};

const DECODE_BY_KIND: Record<KindName, (token: string) => unknown> = {
  message: (token) => decodeMessageId(token),
  cursor: (token) => decodeCursor(token),
  folder: (token) => decodeFolderId(token),
  attachment: (token) => decodeAttachmentId(token),
  staged: (token) => decodeStagedId(token, MINT_INSTANT),
};

const CROSS_USE_PAIRS: ReadonlyArray<readonly [KindName, KindName]> =
  KIND_NAMES.flatMap((minted) =>
    KIND_NAMES.filter((decoder) => decoder !== minted).map(
      (decoder) => [minted, decoder] as const,
    ),
  );

describe("no kind is interchangeable with any other, in either direction", () => {
  it("covers every one of the twenty ordered pairs", () => {
    expect(CROSS_USE_PAIRS).toHaveLength(20);
  });

  for (const [minted, decoder] of CROSS_USE_PAIRS) {
    it(`refuses a ${minted} token handed to the ${decoder} decoder`, () => {
      expect(() => DECODE_BY_KIND[decoder](MINT_BY_KIND[minted]())).toThrow(
        ImapNotFoundError,
      );
    });
  }

  it("mints five visibly different tokens for the same underlying message", () => {
    const tokens = KIND_NAMES.map((kind) => MINT_BY_KIND[kind]());

    expect(new Set(tokens).size).toBe(KIND_NAMES.length);
  });
});

describe("why the first three kinds are not interchangeable", () => {
  it("refuses a folder id handed to the message-id decoder", () => {
    // The folder payload carries no numeric field AT ALL, so this token cannot
    // name a message even in principle — and the kind check refuses it before
    // any field is read, so it never reaches the question.
    const folderToken = encodeFolderId({ mailbox: "INBOX" });

    expect(() => decodeMessageId(folderToken)).toThrow(ImapNotFoundError);
    expect(() => decodeCursor(folderToken)).toThrow(ImapNotFoundError);
  });

  it("refuses a message id and a cursor handed to the folder decoder", () => {
    expect(() => decodeFolderId(encodeMessageId(ASCII_REF))).toThrow(
      ImapNotFoundError,
    );
    expect(() => decodeFolderId(encodeCursor(ASCII_CURSOR))).toThrow(
      ImapNotFoundError,
    );
  });

  it("refuses a cursor handed to the message-id decoder", () => {
    // Without the kind tag this decodes SUCCESSFULLY into a nonsense
    // reference and the caller fetches whatever UID sat in the lastUid slot —
    // the exact "wrong message, silently" failure MAIL-06 exists to prevent.
    const cursorToken = encodeCursor(ASCII_CURSOR);

    expect(() => decodeMessageId(cursorToken)).toThrow(ImapNotFoundError);
  });

  it("refuses a message id handed to the cursor decoder", () => {
    const messageToken = encodeMessageId(ASCII_REF);

    expect(() => decodeCursor(messageToken)).toThrow(ImapNotFoundError);
  });

  it("mints visibly different tokens for the same mailbox and number", () => {
    const token = encodeMessageId({
      mailbox: "INBOX",
      uidValidity: 7,
      uid: 99,
    });
    const cursor = encodeCursor({
      mailbox: "INBOX",
      uidValidity: 7,
      lastUid: 99,
    });

    expect(token).not.toBe(cursor);
  });
});

describe("refusing anything this codec did not mint", () => {
  const validMessageToken = encodeMessageId(ASCII_REF);

  /**
   * Each case is named, so a failure reports which input decoded rather than
   * which loop iteration did.
   */
  const MALFORMED: ReadonlyArray<readonly [string, string]> = [
    ["an empty string", ""],
    ["a single character", "x"],
    ["a truncated token", validMessageToken.slice(0, -8)],
    [
      "a token with its first character flipped",
      // Position 0 carries the top six bits of the opening `{`, so this is a
      // structural break rather than a lucky one. An unsigned token is not
      // tamper-PROOF and does not claim to be (T-02-16, accepted): flipping a
      // byte inside the mailbox name yields a different, valid token. What is
      // claimed, and asserted here, is that structural damage refuses instead
      // of half-decoding.
      `${validMessageToken[0] === "e" ? "f" : "e"}${validMessageToken.slice(1)}`,
    ],
    ["the token base64url-encoded a second time", mint(validMessageToken)],
    ["a character outside the base64url alphabet", `${validMessageToken}!`],
    ["standard base64 padding characters", `${validMessageToken}==`],
    ["leading whitespace", ` ${validMessageToken}`],
    ["valid base64url that is not JSON at all", "bm90LWpzb24"],
    ["a JSON string rather than an object", mint("just a string")],
    ["a JSON array rather than an object", mint([1, 2, 3])],
    ["a JSON null", mint(null)],
    ["a JSON number", mint(7)],
    [
      "a payload with a wrong version",
      mint({ v: TOKEN_VERSION + 1, k: "m", m: "INBOX", uv: 1, u: 1 }),
    ],
    [
      "a payload with no version at all",
      mint({ k: "m", m: "INBOX", uv: 1, u: 1 }),
    ],
    [
      "a payload with an unknown kind",
      mint({ v: TOKEN_VERSION, k: "z", m: "INBOX", uv: 1, u: 1 }),
    ],
    [
      "a hand-constructed payload using plausible field names",
      mint({ mailbox: "INBOX", uidvalidity: 1, uid: 1 }),
    ],
    [
      "a payload missing its uid",
      mint({ v: TOKEN_VERSION, k: "m", m: "INBOX", uv: 1 }),
    ],
    [
      "a payload missing its mailbox",
      mint({ v: TOKEN_VERSION, k: "m", uv: 1, u: 1 }),
    ],
    [
      "a payload with an empty mailbox",
      mint({ v: TOKEN_VERSION, k: "m", m: "", uv: 1, u: 1 }),
    ],
    [
      "a payload whose mailbox is not a string",
      mint({ v: TOKEN_VERSION, k: "m", m: 42, uv: 1, u: 1 }),
    ],
  ];

  for (const [name, token] of MALFORMED) {
    it(`refuses ${name}`, () => {
      expect(() => decodeMessageId(token)).toThrow(ImapNotFoundError);
    });
  }

  /** The numeric guard, which is where a signed-int assumption would hide. */
  const OUT_OF_RANGE: ReadonlyArray<readonly [string, unknown]> = [
    ["a negative UID", -1],
    ["a fractional UID", 1.5],
    ["a UID above the unsigned 32-bit ceiling", 4294967296],
    ["a UID that is not a number", "4711"],
    ["a null UID", null],
  ];

  for (const [name, uid] of OUT_OF_RANGE) {
    it(`refuses ${name}`, () => {
      const token = mint({
        v: TOKEN_VERSION,
        k: "m",
        m: "INBOX",
        uv: 1,
        u: uid,
      });
      expect(() => decodeMessageId(token)).toThrow(ImapNotFoundError);
    });
  }

  it("refuses bytes that are not valid UTF-8, rather than substituting U+FFFD", () => {
    // This is the case that makes the decoder's `fatal` setting load-bearing,
    // and it is the sharpest failure in the whole module. Under lenient
    // decoding the bad byte becomes U+FFFD *inside the mailbox name*, the
    // payload then parses perfectly, and the caller receives a valid-looking
    // reference naming a mailbox that does not exist — a wrong answer with no
    // error anywhere. Refusing is the only correct handling.
    const damaged = new TextEncoder().encode(WELL_FORMED_PAYLOAD);
    // 0xFF cannot appear in any well-formed UTF-8 sequence. Placed inside the
    // mailbox value, where lenient repair would be invisible.
    damaged[WELL_FORMED_PAYLOAD.indexOf("INBOX") + 2] = 0xff;

    expect(() => decodeMessageId(mintRaw(damaged))).toThrow(ImapNotFoundError);
  });

  it("refuses a payload prefixed with a UTF-8 byte-order mark", () => {
    // The companion to the case above: `ignoreBOM: true` keeps the mark as a
    // code point so `JSON.parse` rejects it. The permissive setting strips it
    // silently and the token is accepted as though it had arrived clean.
    const payload = new TextEncoder().encode(WELL_FORMED_PAYLOAD);
    const withBom = new Uint8Array(payload.length + 3);
    withBom.set([0xef, 0xbb, 0xbf], 0);
    withBom.set(payload, 3);

    expect(() => decodeMessageId(mintRaw(withBom))).toThrow(ImapNotFoundError);
    // The same bytes without the mark are a perfectly good token, so the
    // assertion above is about the mark and not about the payload.
    expect(decodeMessageId(mintRaw(payload)).mailbox).toBe("INBOX");
  });

  it("refuses every malformed input on the cursor decoder too", () => {
    // The cross-check that matters for the shared-codec choice: one codec
    // means one set of refusal semantics, so both decoders must behave
    // identically on the same garbage.
    for (const [, token] of MALFORMED) {
      expect(() => decodeCursor(token)).toThrow(ImapNotFoundError);
    }
  });

  it("refuses every malformed input on all five decoders", () => {
    // The same cross-check extended to the kinds added by 04-02. They inherit
    // `decodePayload` unchanged and must therefore inherit its refusals exactly
    // — a fourth and fifth kind that were quietly more permissive would make
    // "one codec, one set of refusal semantics" false while every existing
    // assertion stayed green.
    for (const [, token] of MALFORMED) {
      expect(() => decodeFolderId(token)).toThrow(ImapNotFoundError);
      expect(() => decodeAttachmentId(token)).toThrow(ImapNotFoundError);
      expect(() => decodeStagedId(token, MINT_INSTANT)).toThrow(
        ImapNotFoundError,
      );
    }
  });

  it("refuses a wrong version on the attachment and staged kinds", () => {
    // The version check lives in `decodePayload` and runs before the kind
    // check, so the new kinds get it for free — but "for free" is exactly the
    // kind of claim that stops being true unnoticed.
    const staleAttachment = mint({
      v: TOKEN_VERSION + 1,
      k: "a",
      m: "INBOX",
      uv: 1,
      u: 1,
      p: "2",
    });
    const staleStaged = mint({
      v: TOKEN_VERSION + 1,
      k: "s",
      o: "staging/resume.pdf-1",
      x: MINT_INSTANT + STAGED_ID_TTL_MS,
    });

    expect(() => decodeAttachmentId(staleAttachment)).toThrow(
      ImapNotFoundError,
    );
    expect(() => decodeStagedId(staleStaged, MINT_INSTANT)).toThrow(
      ImapNotFoundError,
    );
  });

  it("says nothing that would teach a caller how to build a staged token", () => {
    // The staged payload names a real bucket object. An error that quoted it
    // back would hand a caller both the format and a live key.
    const offending = mint({
      v: 99,
      k: "s",
      o: "staging/SECRET-KEY-1",
      x: MINT_INSTANT,
    });

    try {
      decodeStagedId(offending, MINT_INSTANT);
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      const surfaced = JSON.stringify(toErrorCategory(error));

      expect(surfaced).not.toContain("SECRET-KEY-1");
      expect(surfaced).not.toContain("staging/");
      expect(surfaced).not.toContain("expire");
    }
  });
});

describe("what a refusal tells the caller", () => {
  it("reaches the caller as not_found", () => {
    // The category was reserved and unreachable throughout Phase 1. This is
    // the first code path in the project that arrives at it.
    try {
      decodeMessageId("not-a-token-this-codec-minted");
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      expect(toErrorCategory(error).category).toBe("not_found");
    }
  });

  it("says nothing that would teach a caller how to build a token", () => {
    // Legibility is the property D-18 deliberately gave up. An error message
    // naming the field that failed, or quoting the token back, would hand that
    // property straight back — and an error path is the easiest place to leak
    // a format for free.
    const offending = mint({ v: 99, k: "m", m: "SECRET-FOLDER", uv: 1, u: 1 });

    try {
      decodeMessageId(offending);
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      const surfaced = JSON.stringify(toErrorCategory(error));

      expect(surfaced).not.toContain("SECRET-FOLDER");
      expect(surfaced).not.toContain(offending);
      expect(surfaced).not.toContain("uidValidity");
      expect(surfaced).not.toContain("base64");
      expect(surfaced).not.toContain("version");
    }
  });
});

describe("minting refuses what it could not read back", () => {
  // A token that cannot survive its own decoder must never be handed out: the
  // failure would surface arbitrarily far from the code that built it, against
  // a token that by then looks like the caller's fault.
  it("refuses an out-of-range UID at encode time", () => {
    expect(() =>
      encodeMessageId({ mailbox: "INBOX", uidValidity: 1, uid: -1 }),
    ).toThrow(ImapNotFoundError);
    expect(() =>
      encodeMessageId({ mailbox: "INBOX", uidValidity: 2 ** 32, uid: 1 }),
    ).toThrow(ImapNotFoundError);
  });

  it("refuses an empty mailbox at encode time", () => {
    expect(() =>
      encodeCursor({ mailbox: "", uidValidity: 1, lastUid: 1 }),
    ).toThrow(ImapNotFoundError);
  });
});
