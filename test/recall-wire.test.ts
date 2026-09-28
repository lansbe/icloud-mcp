// The recall build's own mail read, written down byte for byte (Phase 26, D-19).
//
// These are the window's UID snapshot and the new-mail range read, recorded by
// the rules test/read-path-wire.test.ts keeps for every other read. That file is
// not edited by this phase: it holds the reads that existed before, and these
// are new.
//
// The rules:
//
//   - Every expected line array is a literal. No snapshot matcher is used,
//     because a snapshot can be re-blessed with a flag and a re-blessed snapshot
//     makes a changed wire look unchanged. A probe at the bottom fails if one
//     ever appears here.
//
//   - The login line is redacted before every comparison. It carries the pool's
//     credential, and a failed comparison prints both sides. The redactor and
//     the script builders are copied, not imported, so a change to another test
//     file cannot change what this one drives.
//
//   - If this file goes red after a change to the service module, the change is
//     wrong until shown otherwise. Editing an array here is a decision.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID (D-13: live Apple testing is owner-only).

import { beforeAll, describe, expect, it } from "vitest";
import { ImapNotFoundError } from "../src/errors";
import { createSessionGate, summariesInRangeOver, windowUidsOver } from "../src/mail/service";
import type { Principal } from "../src/principal";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// This file's own source, for the no-snapshot probe. Read at build time by
// Vite, as test/read-path-wire.test.ts reads its own.
// @ts-expect-error — a raw import has no ambient declaration here.
import OWN_SOURCE from "./recall-wire.test.ts?raw";

let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

// ---------------------------------------------------------------------------
// The redactor, copied from test/read-path-wire.test.ts
// ---------------------------------------------------------------------------

function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    const command = (tokens[1] ?? "").toUpperCase();
    if (command === "LOGIN") return `${tokens[0]} ${tokens[1]} [redacted]`;
    if (command === "AUTHENTICATE") {
      return `${tokens[0]} ${tokens[1]} ${tokens[2] ?? ""} [redacted]`;
    }
    return line;
  });
}

function wireOf(duplex: FakeDuplex): string[] {
  return redacted(duplex.writtenLines());
}

// ---------------------------------------------------------------------------
// Script builders, copied from the files that own them
// ---------------------------------------------------------------------------

/** The four turns every session opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A read-only open of the inbox. Copied from test/read-path-wire.test.ts. */
function examineReply(tag: string): Uint8Array {
  const lines = [
    "* 172 EXISTS",
    "* 0 RECENT",
    `* OK [UIDVALIDITY ${UIDVALIDITY}] UIDs valid`,
    "* OK [UIDNEXT 4395] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

/** The untagged search reply for a set of identifiers, in server order. */
function searchReply(tag: string, uids: readonly number[]): Uint8Array {
  return wire(`* SEARCH ${uids.join(" ")}`, `${tag} OK SEARCH completed`);
}

/** A single-part plain text structure. Copied from test/read-path-wire.test.ts. */
const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

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

function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

/** The listing's batched metadata reply. Copied from test/read-path-wire.test.ts. */
function pageMetadataReply(tag: string, uids: readonly number[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const [i, uid] of uids.entries()) {
    chunks.push(
      ENCODER.encode(
        `* ${i + 1} FETCH (UID ${uid} FLAGS () ` +
          `INTERNALDATE "26-Sep-2026 10:15:02 +0000" ` +
          `RFC822.SIZE ${12000 + uid} ` +
          `BODYSTRUCTURE ${PLAIN_STRUCTURE} `,
      ),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]",
        [
          `Subject: Subject for ${uid}`,
          `From: "Sender ${uid}" <s${uid}@example.invalid>`,
          "Date: Thu, 13 Aug 2026 09:14:02 -0700",
          `Message-ID: <m${uid}@example.invalid>`,
          "",
          "",
        ].join("\r\n"),
      ),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** The listing's preview reply. Copied from test/read-path-wire.test.ts. */
function snippetReply(tag: string, uids: readonly number[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const [i, uid] of uids.entries()) {
    chunks.push(
      ENCODER.encode(`* ${i + 1} FETCH (UID ${uid} `),
      literalItem("BODY[1]<0>", `Preview of message ${uid}.`),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

// ---------------------------------------------------------------------------
// The window's UID snapshot
// ---------------------------------------------------------------------------

describe("windowUidsOver records exactly one read-only open and one search (D-17b, D-19)", () => {
  it("a one-digit day: examine, the search since that day, logout; the UIDs as listed, once each", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4801, 4803, 4802, 4803]),
      logoutExchange("a6"),
    ]);

    const snapshot = await windowUidsOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      "2026-07-05",
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH SINCE 5-Jul-2026",
      "a6 LOGOUT",
    ]);
    expect(snapshot).toEqual({ uidValidity: UIDVALIDITY, uids: [4801, 4803, 4802] });
  });

  it("a two-digit day with no mail since it: the same lines, and no UIDs", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      wire("a5 OK SEARCH completed"),
      logoutExchange("a6"),
    ]);

    const snapshot = await windowUidsOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      "2026-06-29",
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH SINCE 29-Jun-2026",
      "a6 LOGOUT",
    ]);
    expect(snapshot).toEqual({ uidValidity: UIDVALIDITY, uids: [] });
  });

  it("a malformed day is refused before any line is written", async () => {
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    for (const day of ["2026-02-31", "2026-7-05", ""]) {
      await expect(
        windowUidsOver(duplex, principal, createSessionGate(), MAILBOX, day, FAST_BOUNDS),
      ).rejects.toBeInstanceOf(ImapNotFoundError);
    }

    expect(wireOf(duplex)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The new-mail range
// ---------------------------------------------------------------------------

describe("summariesInRangeOver records one read-only open, one bounded search and the listing's own fetches (D-16, D-19)", () => {
  it("40 new messages from 100: the search is 100:139, the oldest 25 are fetched, and the next read starts at 125", async () => {
    // The server answers the range out of order; every UID in it exists.
    const present = Array.from({ length: 40 }, (_, i) => 139 - i);
    const oldest25 = Array.from({ length: 25 }, (_, i) => 100 + i);
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", present),
      pageMetadataReply("a6", oldest25),
      snippetReply("a7", oldest25),
      logoutExchange("a8"),
    ]);

    const page = await summariesInRangeOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      UIDVALIDITY,
      100,
      140,
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH UID 100:139",
      "a6 UID FETCH 100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])",
      "a7 UID FETCH 100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124 (BODY.PEEK[1]<0.1024>)",
      "a8 LOGOUT",
    ]);
    expect(page.nextFrom).toBe(125);
    expect(page.rows.map((row) => row.uid)).toEqual(oldest25);
    expect(page.rows[0]).toEqual({
      id: expect.any(String),
      uid: 100,
      unread: true,
      internalDate: "26-Sep-2026 10:15:02 +0000",
      wireSizeBytes: 12100,
      subject: "Subject for 100",
      fromName: "Sender 100",
      fromAddress: "s100@example.invalid",
      snippet: "Preview of message 100.",
      hasAttachments: false,
    });
  });
});

describe("this file keeps its own rules", () => {
  it("uses no snapshot matcher", () => {
    const matcher = "toMatch" + "Snapshot";
    const inline = "toMatchInline" + "Snapshot";
    expect(String(OWN_SOURCE).length).toBeGreaterThan(1000);
    expect(String(OWN_SOURCE)).not.toContain(matcher);
    expect(String(OWN_SOURCE)).not.toContain(inline);
  });
});
