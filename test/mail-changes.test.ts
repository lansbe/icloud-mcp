// The change check's mail reads, written down byte for byte.
//
// This is the change check's own record, by the rules test/read-path-wire.test.ts
// keeps for every other read. That file is not edited by this phase: it holds
// the reads that existed before, and these are new.
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
import { decodeMessageId } from "../src/mail/ids";
import {
  MAX_NEW_MAIL_ROWS,
  createSessionGate,
  folderSnapshotsOver,
  newMailOver,
} from "../src/mail/service";
import type { Principal } from "../src/principal";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  statusResponse,
  taggedNo,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// This file's own source, for the no-snapshot probe. Read at build time by
// Vite, as test/read-path-wire.test.ts reads its own.
// @ts-expect-error — a raw import has no ambient declaration here.
import OWN_SOURCE from "./mail-changes.test.ts?raw";

let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;
const ROW_FETCH_ITEMS =
  "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])";

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

function searchReply(tag: string, uids: readonly number[]): Uint8Array {
  return wire(`* SEARCH ${uids.join(" ")}`, `${tag} OK SEARCH completed`);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

interface HeaderRow {
  uid: number;
  flags: string;
  subject: string;
  from: string;
}

/** One header-only FETCH reply per row, then the tagged completion. */
function headerFetchReply(tag: string, rows: readonly HeaderRow[]): Uint8Array {
  const parts: Uint8Array[] = [];
  rows.forEach((row, index) => {
    const header = ENCODER.encode(
      `Subject: ${row.subject}\r\nFrom: ${row.from}\r\n\r\n`,
    );
    parts.push(
      ENCODER.encode(
        `* ${index + 1} FETCH (UID ${row.uid} FLAGS (${row.flags}) ` +
          `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
          `BODY[HEADER.FIELDS (SUBJECT FROM)] {${header.length}}\r\n`,
      ),
      header,
      ENCODER.encode(")\r\n"),
    );
  });
  parts.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concat(parts);
}

function row(uid: number, flags = ""): HeaderRow {
  return {
    uid,
    flags,
    subject: `Message ${uid}`,
    from: `"Sender ${uid}" <sender${uid}@example.invalid>`,
  };
}

// ---------------------------------------------------------------------------
// New mail: search, then one header-only fetch
// ---------------------------------------------------------------------------

describe("newMailOver records exactly the header-only reads (CHNG-09)", () => {
  it("three in-range UIDs: examine, bounded search, one peek fetch newest first", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4392, 4393, 4394]),
      headerFetchReply("a6", [row(4394), row(4393, "\\Seen"), row(4392)]),
      logoutExchange("a7"),
    ]);

    const found = await newMailOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      UIDVALIDITY,
      4392,
      4395,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH UID 4392:4394",
      "a6 UID FETCH 4394,4393,4392 (UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])",
      "a7 LOGOUT",
    ]);
    expect(found.count).toBe(3);
    expect(found.rows.map((one) => one.uid)).toEqual([4394, 4393, 4392]);
    expect(found.rows.map((one) => one.unread)).toEqual([true, false, true]);
  });

  it("more than 25 in range: the count is exact, the fetch names only the newest 25", async () => {
    const uids = Array.from({ length: 30 }, (_, index) => 5000 + index);
    const newest = [...uids].sort((a, b) => b - a).slice(0, 25);
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", uids),
      headerFetchReply("a6", newest.map((uid) => row(uid))),
      logoutExchange("a7"),
    ]);

    const found = await newMailOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      UIDVALIDITY,
      5000,
      5030,
    );

    expect(MAX_NEW_MAIL_ROWS).toBe(25);
    expect(found.count).toBe(30);
    expect(found.rows).toHaveLength(25);
    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH UID 5000:5029",
      `a6 UID FETCH ${newest.join(",")} ${ROW_FETCH_ITEMS}`,
      "a7 LOGOUT",
    ]);
  });

  it("a UID the search named and the fetch did not answer: the row is absent, no error", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4392, 4393]),
      headerFetchReply("a6", [row(4393)]),
      logoutExchange("a7"),
    ]);

    const found = await newMailOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      UIDVALIDITY,
      4392,
      4394,
    );

    expect(found.count).toBe(2);
    expect(found.rows.map((one) => one.uid)).toEqual([4393]);
  });

  it("a row carries exactly id, uid, unread, receivedAt, sender and subject", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4392]),
      headerFetchReply("a6", [row(4392)]),
      logoutExchange("a7"),
    ]);

    const found = await newMailOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      UIDVALIDITY,
      4392,
      4393,
    );

    const [only] = found.rows;
    expect(Object.keys(only!).sort()).toEqual(
      ["fromAddress", "fromName", "id", "receivedAt", "subject", "uid", "unread"],
    );
    expect(only).toEqual({
      id: only!.id,
      uid: 4392,
      unread: true,
      receivedAt: "13-Aug-2026 09:14:02 -0700",
      fromName: "Sender 4392",
      fromAddress: "sender4392@example.invalid",
      subject: "Message 4392",
    });
    expect(decodeMessageId(only!.id)).toEqual({
      mailbox: MAILBOX,
      uidValidity: UIDVALIDITY,
      uid: 4392,
    });
  });
});

// ---------------------------------------------------------------------------
// Snapshots: the status command, no mailbox opened
// ---------------------------------------------------------------------------

describe("folderSnapshotsOver opens no mailbox (CHNG-07)", () => {
  it("the inbox: exactly one status line and no open", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      statusResponse("a4", "INBOX", UIDVALIDITY, 4392, 172, "118"),
      logoutExchange("a5"),
    ]);

    const outcomes = await folderSnapshotsOver(
      duplex,
      principal,
      createSessionGate(),
      [MAILBOX],
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 STATUS "INBOX" (UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)',
      "a5 LOGOUT",
    ]);
    expect(outcomes).toEqual([
      {
        mailbox: MAILBOX,
        answered: true,
        snapshot: {
          name: MAILBOX,
          uidValidity: UIDVALIDITY,
          uidNext: 4392,
          messages: 172,
          highestModseq: "118",
        },
      },
    ]);
  });

  it("a name with a carriage return sends no status line and is not answered", async () => {
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    const outcomes = await folderSnapshotsOver(
      duplex,
      principal,
      createSessionGate(),
      ["Bad\rName"],
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      "a4 LOGOUT",
    ]);
    expect(outcomes).toEqual([{ mailbox: "Bad\rName", answered: false }]);
  });

  it("a status answered NO is not answered, and the next folder is still asked", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", "[NONEXISTENT] Mailbox does not exist"),
      statusResponse("a5", "INBOX", UIDVALIDITY, 4392, 172),
      logoutExchange("a6"),
    ]);

    const outcomes = await folderSnapshotsOver(
      duplex,
      principal,
      createSessionGate(),
      ["Gone", MAILBOX],
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 STATUS "Gone" (UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)',
      'a5 STATUS "INBOX" (UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)',
      "a6 LOGOUT",
    ]);
    // NONEXISTENT is the one refusal that says the folder is gone (D-21).
    expect(outcomes[0]).toEqual({ mailbox: "Gone", answered: false, gone: true });
    expect(outcomes[1]).toMatchObject({ mailbox: MAILBOX, answered: true });
    // Absent is null, never zero.
    expect(outcomes[1]).toMatchObject({ snapshot: { highestModseq: null } });
  });
});

describe("a refused status that does not say the folder is gone (D-21)", () => {
  it.each([
    ["no response code", "Mailbox is busy"],
    ["a busy code", "[UNAVAILABLE] Try again later"],
    ["a code that is not NONEXISTENT", "[CANNOT] Not permitted"],
  ])("%s: not answered, and not gone", async (_label, text) => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", text),
      logoutExchange("a5"),
    ]);

    const outcomes = await folderSnapshotsOver(
      duplex,
      principal,
      createSessionGate(),
      ["Receipts"],
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 STATUS "Receipts" (UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)',
      "a5 LOGOUT",
    ]);
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]!.answered).toBe(false);
    expect("gone" in outcomes[0]! && outcomes[0]!.gone === true).toBe(false);
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
