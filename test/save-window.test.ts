// The save read's outbound command lines, written down byte for byte.
//
// The save read fetches a large attachment in fixed windows, inside one
// read-only session, so any attachment iCloud can hold can be saved. This file
// pins every command it sends, and every refusal and deferral it makes, the
// way `./read-path-wire.test.ts` pins the other reads. That file is not edited
// by this work, and one case below runs its attachment read again to show it.
//
// The same rules as that file:
//
//   - Every array below is a literal. No snapshot assertion of any kind is
//     used, because a snapshot can be re-blessed with a flag. A probe at the
//     bottom fails if a snapshot matcher ever appears here.
//
//   - The login line is redacted before every comparison. It carries the
//     pool's credential, and a failed comparison prints both sides.
//
//   - The script builders are COPIED from the files that own them rather than
//     imported, so a later change to another test file cannot change what this
//     one drives.
//
// Every server byte here is synthesised. Nothing opens a network connection
// and nothing authenticates against a real Apple ID. This file stores nothing,
// prints nothing and reports nothing.

import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(() => {
    throw new Error("no iCloud session is expected in this file");
  }),
}));

import { ImapNotFoundError } from "../src/errors";
import type { AttachmentRef } from "../src/mail/ids";
import {
  CALL_DEADLINE_MS,
  SAVE_MAX_CALL_OCTETS,
  SAVE_MAX_PARTS,
  SAVE_MAX_PART_OCTETS,
  SAVE_START_BUDGET_MS,
  SAVE_WINDOW_OCTETS,
  createSessionGate,
  getAttachmentContentOver,
  getAttachmentsForSave,
  getAttachmentsForSaveOver,
  type SavePartRead,
  type SaveReadOptions,
} from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { decodeWindows } from "../src/mail/stream-decode";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

// This file's own source, for the no-snapshot probe in the last describe.
// @ts-expect-error — a raw import has no ambient declaration here.
import OWN_SOURCE from "./save-window.test.ts?raw";
// The service module's own source, for the one probe that reads it as text.
// @ts-expect-error — a raw import has no ambient declaration here.
import SERVICE_SOURCE from "../src/mail/service.ts?raw";

let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The mailbox, validity and message every scripted conversation agrees on. */
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;
const UID = 42;

/** The fixed text a credential-carrying line is reduced to. */
const REDACTED = "[redacted]";

// ---------------------------------------------------------------------------
// The redactor, copied from test/read-path-wire.test.ts
// ---------------------------------------------------------------------------

function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    const command = (tokens[1] ?? "").toUpperCase();
    if (command === "LOGIN") {
      return `${tokens[0]} ${tokens[1]} ${REDACTED}`;
    }
    if (command === "AUTHENTICATE") {
      return `${tokens[0]} ${tokens[1]} ${tokens[2] ?? ""} ${REDACTED}`;
    }
    return line;
  });
}

/** What a duplex was sent, redacted. The only form any golden is compared in. */
function wireOf(duplex: FakeDuplex): string[] {
  return redacted(duplex.writtenLines());
}

// ---------------------------------------------------------------------------
// Script builders, copied from test/read-path-wire.test.ts
// ---------------------------------------------------------------------------

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** The untagged set a read-only open returns, then its completion. */
function examineReply(tag: string): Uint8Array {
  const lines = [
    "* 172 EXISTS",
    "* 0 RECENT",
    "* OK [UNSEEN 12] Message 12 is first unseen",
    `* OK [UIDVALIDITY ${UIDVALIDITY}] UIDs valid`,
    "* OK [UIDNEXT 4392] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
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

/** One `key {n}\r\n<payload>` pair, count derived from the payload. */
function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

/** One FETCH reply carrying one literal, keyed by the reply's spelling. */
function literalReply(tag: string, key: string, payload: string): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} `),
    literalItem(key, payload),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The structure-and-size reply, with no literal in it. */
function structureReply(tag: string, structure: string, wireSize: number): Uint8Array {
  return wire(
    `* 1 FETCH (UID ${UID} FLAGS () ` +
      `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
      `RFC822.SIZE ${wireSize} BODYSTRUCTURE ${structure})`,
    `${tag} OK UID FETCH completed`,
  );
}

// ---------------------------------------------------------------------------
// The message: a text body at path 1, attachments from path 2 on
// ---------------------------------------------------------------------------

/** "Hello, save!!" (13 bytes) in base64: exactly 20 octets, two padding characters. */
const PART_A = "SGVsbG8sIHNhdmUhIQ==";
/** "Second file." (12 bytes) in base64: exactly 16 octets, no padding. */
const PART_B = "U2Vjb25kIGZpbGUu";

/** One attachment part of the structure, base64, with its encoded octet count. */
function attachmentPart(filename: string, octets: number): string {
  return (
    `("APPLICATION" "PDF" ("NAME" "${filename}") NIL NIL "BASE64" ${octets} NIL ` +
    `("attachment" ("FILENAME" "${filename}")) NIL)`
  );
}

/** A mixed message: text at path 1, then the given attachments at 2, 3, … */
function mixedStructure(...attachments: string[]): string {
  return (
    '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
    attachments.join("") +
    ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)'
  );
}

/** A reference to one part of the one message. */
function refTo(path: string): AttachmentRef {
  return { mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: UID, path };
}

/** The windows of a fetched read, as text. */
function windowTexts(read: SavePartRead | undefined): string[] {
  if (read === undefined || read.outcome !== "fetched") {
    throw new Error(`not fetched: ${JSON.stringify(read?.outcome)}`);
  }
  return read.windows.map((one) => DECODER.decode(one));
}

/** A window of 8 octets, so a 20-octet part takes three windows. */
const EIGHT: SaveReadOptions = { ...FAST_BOUNDS, windowOctets: 8 };

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

describe("the save read on the wire", () => {
  it("one part, three windows: exactly these lines, with the origin moving forward", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      logoutExchange("a9"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      EIGHT,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[2]<8.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[2]<16.4>)",
      "a9 LOGOUT",
    ]);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({
      outcome: "fetched",
      ref: refTo("2"),
      filename: "offer.pdf",
      mimeType: "application/pdf",
      encoding: "base64",
      encodedOctets: 20,
    });
  });

  it("the reply keys for a non-zero origin are read, and the windows are the scripted literals", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      logoutExchange("a9"),
    ]);

    const [read] = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      EIGHT,
    );

    expect(windowTexts(read)).toEqual(["SGVsbG8s", "IHNhdmUh", "IQ=="]);
    // And the windows, decoded outside the session, are the file.
    if (read?.outcome !== "fetched") throw new Error("not fetched");
    const decoded = decodeWindows(read.windows, read.encoding);
    expect(decoded.ok && DECODER.decode(decoded.bytes)).toBe("Hello, save!!");
  });

  it("two attachments of one message: one sign-in, one open, one structure read, then each part's windows in turn", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(attachmentPart("offer.pdf", 20), attachmentPart("second.pdf", 16)),
        4000,
      ),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      literalReply("a9", "BODY[3]<0>", "U2Vjb25k"),
      literalReply("a10", "BODY[3]<8>", "IGZpbGUu"),
      logoutExchange("a11"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2"), refTo("3")],
      EIGHT,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[2]<8.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[2]<16.4>)",
      "a9 UID FETCH 42 (BODY.PEEK[3]<0.8>)",
      "a10 UID FETCH 42 (BODY.PEEK[3]<8.8>)",
      "a11 LOGOUT",
    ]);
    expect(windowTexts(reads[0])).toEqual(["SGVsbG8s", "IHNhdmUh", "IQ=="]);
    expect(windowTexts(reads[1])).toEqual(["U2Vjb25k", "IGZpbGUu"]);
    expect(reads[1]).toMatchObject({ filename: "second.pdf", encodedOctets: 16 });
  });
});

// ---------------------------------------------------------------------------
// Refusals: named, and no window line for the refused part
// ---------------------------------------------------------------------------

describe("the save read refuses a part by name", () => {
  it("a part over the per-part cap is refused with its size and the cap, and no window line is sent", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("big.pdf", 20)), 4000),
      logoutExchange("a6"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      { ...EIGHT, maxPartOctets: 16 },
    );

    expect(reads).toEqual([
      {
        outcome: "refused",
        ref: refTo("2"),
        refusal: "part-too-large",
        encodedOctets: 20,
        limitBytes: 16,
        filename: "big.pdf",
        mimeType: "application/pdf",
      },
    ]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 LOGOUT",
    ]);
  });

  it("a part with zero encoded octets is refused as empty", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("nothing.pdf", 0)), 4000),
      logoutExchange("a6"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      EIGHT,
    );

    expect(reads).toEqual([
      {
        outcome: "refused",
        ref: refTo("2"),
        refusal: "empty",
        encodedOctets: 0,
        filename: "nothing.pdf",
        mimeType: "application/pdf",
      },
    ]);
    expect(wireOf(duplex)).toHaveLength(6);
  });

  it("a path that is not an attachment row is refused as not-found, and the call goes on to the next part", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      logoutExchange("a9"),
    ]);

    // Path 1 is the text body, not an attachment row. Path 7 does not exist.
    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("1"), refTo("7"), refTo("2")],
      EIGHT,
    );

    expect(reads[0]).toEqual({ outcome: "refused", ref: refTo("1"), refusal: "not-found" });
    expect(reads[1]).toEqual({ outcome: "refused", ref: refTo("7"), refusal: "not-found" });
    expect(windowTexts(reads[2])).toEqual(["SGVsbG8s", "IHNhdmUh", "IQ=="]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[2]<8.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[2]<16.4>)",
      "a9 LOGOUT",
    ]);
  });

  it("a window reply shorter than asked refuses the part as changed, and no further window is sent for it", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(attachmentPart("offer.pdf", 20), attachmentPart("second.pdf", 16)),
        4000,
      ),
      literalReply("a6", "BODY[2]<0>", "SGVsbG"),
      literalReply("a7", "BODY[3]<0>", "U2Vjb25k"),
      literalReply("a8", "BODY[3]<8>", "IGZpbGUu"),
      logoutExchange("a9"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2"), refTo("3")],
      EIGHT,
    );

    expect(reads[0]).toEqual({
      outcome: "refused",
      ref: refTo("2"),
      refusal: "part-changed",
      encodedOctets: 20,
      filename: "offer.pdf",
      mimeType: "application/pdf",
    });
    expect(windowTexts(reads[1])).toEqual(["U2Vjb25k", "IGZpbGUu"]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[3]<0.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[3]<8.8>)",
      "a9 LOGOUT",
    ]);
  });

  it("a window reply longer than asked refuses the part as changed, and no further window is sent for it", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8sI"),
      logoutExchange("a7"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      EIGHT,
    );

    expect(reads).toEqual([
      {
        outcome: "refused",
        ref: refTo("2"),
        refusal: "part-changed",
        encodedOctets: 20,
        filename: "offer.pdf",
        mimeType: "application/pdf",
      },
    ]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 LOGOUT",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Deferrals: the rest of the call comes back for a later call
// ---------------------------------------------------------------------------

describe("the save read defers what does not fit in this call", () => {
  it("an eleventh ref comes back deferred, with no line sent for it", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      logoutExchange("a6"),
    ]);

    // Ten refs to paths that are not attachment rows, then the real one.
    const refs = ["3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "2"].map(refTo);
    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      refs,
      EIGHT,
    );

    expect(reads.map((one) => one.outcome)).toEqual([
      ...Array.from({ length: 10 }, () => "refused"),
      "deferred",
    ]);
    expect(reads[10]).toEqual({ outcome: "deferred", ref: refTo("2") });
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 LOGOUT",
    ]);
  });

  it("a part that would take the call over the per-call cap, and every ref after it, come back deferred", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(
          attachmentPart("offer.pdf", 20),
          attachmentPart("second.pdf", 16),
          attachmentPart("third.pdf", 4),
        ),
        4000,
      ),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      logoutExchange("a9"),
    ]);

    // 20 fetched; 20 + 16 is over 30, so the second is deferred. The third
    // would fit (20 + 4), and is deferred anyway: once the call defers, it
    // defers everything after, so the rest come back in order next time.
    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2"), refTo("3"), refTo("4"), refTo("9")],
      { ...EIGHT, maxCallOctets: 30 },
    );

    expect(reads.map((one) => one.outcome)).toEqual([
      "fetched",
      "deferred",
      "deferred",
      "deferred",
    ]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[2]<8.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[2]<16.4>)",
      "a9 LOGOUT",
    ]);
  });

  it("past the time budget, the second and later refs come back deferred; the first is always attempted", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(attachmentPart("offer.pdf", 20), attachmentPart("second.pdf", 16)),
        4000,
      ),
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      literalReply("a7", "BODY[2]<8>", "IHNhdmUh"),
      literalReply("a8", "BODY[2]<16>", "IQ=="),
      logoutExchange("a9"),
    ]);

    // The first reading is the start; every reading after it is past the budget.
    let readings = 0;
    const now = (): number => {
      readings += 1;
      return readings === 1 ? 0 : SAVE_START_BUDGET_MS + 1;
    };

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2"), refTo("3"), refTo("2")],
      { ...EIGHT, now },
    );

    expect(reads.map((one) => one.outcome)).toEqual(["fetched", "deferred", "deferred"]);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2]<0.8>)",
      "a7 UID FETCH 42 (BODY.PEEK[2]<8.8>)",
      "a8 UID FETCH 42 (BODY.PEEK[2]<16.4>)",
      "a9 LOGOUT",
    ]);
  });
});

// ---------------------------------------------------------------------------
// The refs name one message, checked before any socket
// ---------------------------------------------------------------------------

describe("the save read's refs name exactly one message", () => {
  it.each([
    ["two different UIDs", [refTo("2"), { ...refTo("2"), uid: 43 }]],
    ["two different mailboxes", [refTo("2"), { ...refTo("2"), mailbox: "Archive" }]],
    ["two different validities", [refTo("2"), { ...refTo("2"), uidValidity: 1 }]],
    ["no refs at all", []],
  ])("%s: refused as not found, and the socket open is never called", async (_label, refs) => {
    const opened = vi.mocked(connectImap);
    opened.mockClear();

    await expect(
      getAttachmentsForSave(principal, createSessionGate(), refs as AttachmentRef[], FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
    expect(opened).not.toHaveBeenCalled();
  });

  it("the stream-pair variant refuses the same way, before writing a single line", async () => {
    const duplex = createFakeDuplex([...authPrefix()]);
    await expect(
      getAttachmentsForSaveOver(
        duplex,
        principal,
        createSessionGate(),
        [refTo("2"), { ...refTo("3"), uid: 43 }],
        FAST_BOUNDS,
      ),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
    expect(wireOf(duplex)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The limits can only be lowered, and the deadline is the ordinary one
// ---------------------------------------------------------------------------

describe("an injected limit can only lower a SAVE_ constant", () => {
  it("the constants are the decided numbers", () => {
    expect(SAVE_WINDOW_OCTETS).toBe(4 * 1024 * 1024);
    expect(SAVE_MAX_PART_OCTETS).toBe(20 * 1024 * 1024);
    expect(SAVE_MAX_CALL_OCTETS).toBe(20 * 1024 * 1024);
    expect(SAVE_MAX_PARTS).toBe(10);
    expect(SAVE_START_BUDGET_MS).toBe(10_000);
  });

  it("a per-part cap above the constant is clamped: a part one octet over the constant is still refused", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(attachmentPart("huge.pdf", SAVE_MAX_PART_OCTETS + 1)),
        SAVE_MAX_PART_OCTETS + 4000,
      ),
      logoutExchange("a6"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      {
        ...FAST_BOUNDS,
        maxPartOctets: SAVE_MAX_PART_OCTETS * 4,
        maxCallOctets: SAVE_MAX_CALL_OCTETS * 4,
      },
    );

    expect(reads).toEqual([
      {
        outcome: "refused",
        ref: refTo("2"),
        refusal: "part-too-large",
        encodedOctets: 20971521,
        limitBytes: 20971520,
        filename: "huge.pdf",
        mimeType: "application/pdf",
      },
    ]);
    expect(wireOf(duplex)).toHaveLength(6);
  });

  it("a window above the constant is clamped: the first window asked for is the constant", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply(
        "a5",
        mixedStructure(attachmentPart("large.pdf", 5 * 1024 * 1024)),
        6 * 1024 * 1024,
      ),
      // A short reply ends the part as changed, so no 4 MiB literal is needed.
      literalReply("a6", "BODY[2]<0>", "SGVsbG8s"),
      logoutExchange("a7"),
    ]);

    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      [refTo("2")],
      { ...FAST_BOUNDS, windowOctets: SAVE_WINDOW_OCTETS * 8 },
    );

    expect(reads[0]).toMatchObject({ outcome: "refused", refusal: "part-changed" });
    expect(wireOf(duplex)[5]).toBe("a6 UID FETCH 42 (BODY.PEEK[2]<0.4194304>)");
  });

  it("a part count above the constant is clamped: the eleventh ref is still deferred", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      logoutExchange("a6"),
    ]);

    const refs = ["3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "2"].map(refTo);
    const reads = await getAttachmentsForSaveOver(
      duplex,
      principal,
      createSessionGate(),
      refs,
      { ...EIGHT, maxParts: 50 },
    );

    expect(reads[10]).toEqual({ outcome: "deferred", ref: refTo("2") });
  });
});

describe("the save read keeps the ordinary call deadline", () => {
  /** Every delay handed to `setTimeout` while `run` is in flight. */
  async function delaysDuring(run: () => Promise<unknown>): Promise<number[]> {
    const delays: number[] = [];
    const real = globalThis.setTimeout;
    const spy = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(((handler: () => void, ms?: number) => {
        delays.push(ms ?? 0);
        return real(handler, ms);
      }) as typeof setTimeout);
    try {
      await run();
    } finally {
      spy.mockRestore();
    }
    return delays;
  }

  function oneWindowDuplex(): FakeDuplex {
    return createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("second.pdf", 16)), 4000),
      literalReply("a6", "BODY[2]<0>", PART_B),
      logoutExchange("a7"),
    ]);
  }

  const noDeadline = { readTimeoutMs: 40, drainTimeoutMs: 20, closeTimeoutMs: 20 };

  it("with no override, CALL_DEADLINE_MS races the work, and nothing longer does", async () => {
    const delays = await delaysDuring(() =>
      getAttachmentsForSaveOver(
        oneWindowDuplex(),
        principal,
        createSessionGate(),
        [refTo("2")],
        noDeadline,
      ),
    );

    expect(CALL_DEADLINE_MS).toBe(20000);
    expect(delays).toContain(CALL_DEADLINE_MS);
    expect(Math.max(...delays)).toBe(CALL_DEADLINE_MS);
  });

  it("an override above CALL_DEADLINE_MS is clamped down to it", async () => {
    const delays = await delaysDuring(() =>
      getAttachmentsForSaveOver(
        oneWindowDuplex(),
        principal,
        createSessionGate(),
        [refTo("2")],
        { ...noDeadline, callDeadlineMs: 60_000 },
      ),
    );

    expect(delays).not.toContain(60_000);
    expect(Math.max(...delays)).toBe(CALL_DEADLINE_MS);
  });

  it("the save read's options helper sets the literal ceiling and never raises the deadline", () => {
    const source = SERVICE_SOURCE as string;
    const start = source.search(/\bfunction\s+saveSessionOptions\b/);
    expect(start).toBeGreaterThan(-1);
    const end = source.indexOf("\n}\n", start);
    const body = source
      .slice(start, end)
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "");
    expect(body).toContain("maxLiteralOctets");
    expect(body).toMatch(/callDeadlineMs:\s*Math\.min\(/);
  });
});

// ---------------------------------------------------------------------------
// The shipped attachment read is unchanged
// ---------------------------------------------------------------------------

describe("mail_get_attachment's read is unchanged", () => {
  it("still sends one whole-part peeking fetch, with no window", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", mixedStructure(attachmentPart("offer.pdf", 20)), 4000),
      literalReply("a6", "BODY[2]", PART_A),
      logoutExchange("a7"),
    ]);

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      refTo("2"),
      FAST_BOUNDS,
    );

    expect(content.fetch.fetched).toBe(true);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 42 (BODY.PEEK[2])",
      "a7 LOGOUT",
    ]);
  });
});

// ---------------------------------------------------------------------------
// The goldens are literal
// ---------------------------------------------------------------------------

/** Drop block comments and line comments, so prose cannot count as code. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

describe("the goldens are literal", () => {
  it("uses no snapshot matcher anywhere in this file", () => {
    expect(typeof OWN_SOURCE).toBe("string");
    const code = withoutComments(OWN_SOURCE as string);

    // Non-vacuity: this is really the file, and it really compares arrays.
    expect(code.includes("getAttachmentsForSaveOver")).toBe(true);
    expect(code.includes(".toEqual(")).toBe(true);

    expect(
      /\.(?:toMatch(?:Inline|File)?Snapshot|toThrowErrorMatching(?:Inline)?Snapshot)\s*\(/.test(
        code,
      ),
    ).toBe(false);
  });
});
