// The recall page source over IMAP (Phase 26, D-11, RCLL-08, plan 26-03).
//
// The socket module is mocked for this file only, so the listing's own connect
// step hands back an in-memory duplex and `searchMessages` runs for real over
// scripted replies, the way test/mark-read-tool.test.ts drives its tool. Each
// session takes the next scripted duplex. Nothing here opens a network
// connection and nothing signs in to a real Apple ID (D-13).
//
// What is proved: the source reads the window newest first through the
// existing listing, 25 to a page; the stored snippet is the subject and only
// the subject, and the body preview reaches the embedded text and nothing else;
// a row whose date does not parse is left out; a stale cursor is read again
// from the top so the engine sees the new validity; and the window's first day
// is the retention window's.

import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { ImapNotFoundError } from "../src/errors";
import { decodeMessageId, encodeMessageId, type PageCursor } from "../src/mail/ids";
import { createSessionGate, summariesInRange, windowUids } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import type { Principal } from "../src/principal";
import {
  mailRecallSource,
  newMailPage,
  parseInternalDate,
  recallItemOf,
  windowStartDay,
} from "../src/recall/mail-source";
import { RECALL_TTL_MS } from "../src/recall/retention";
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

let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

const ENCODER = new TextEncoder();
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;
const OLD_VALIDITY = 1111111111;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

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

function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

function examineReply(tag: string, validity = UIDVALIDITY): Uint8Array {
  const lines = [
    "* 172 EXISTS",
    "* 0 RECENT",
    `* OK [UIDVALIDITY ${validity}] UIDs valid`,
    "* OK [UIDNEXT 4395] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

function searchReply(tag: string, uids: readonly number[]): Uint8Array {
  if (uids.length === 0) return wire(`${tag} OK SEARCH completed`);
  return wire(`* SEARCH ${uids.join(" ")}`, `${tag} OK SEARCH completed`);
}

/** One scripted row. `internalDate: null` leaves the item out of the reply. */
interface Row {
  uid: number;
  seq: number;
  internalDate: string | null;
  subject: string;
  fromName: string;
  preview: string;
}

function row(uid: number, overrides: Partial<Row> = {}): Row {
  return {
    uid,
    seq: uid,
    internalDate: "26-Sep-2026 10:15:02 +0000",
    subject: `Subject for ${uid}`,
    fromName: `Sender ${uid}`,
    preview: `Preview of message ${uid}.`,
    ...overrides,
  };
}

function metadataReply(tag: string, rows: readonly Row[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const r of rows) {
    const date = r.internalDate === null ? "" : `INTERNALDATE "${r.internalDate}" `;
    chunks.push(
      ENCODER.encode(
        `* ${r.seq} FETCH (UID ${r.uid} FLAGS () ${date}` +
          `RFC822.SIZE ${12000 + r.uid} BODYSTRUCTURE ${PLAIN_STRUCTURE} `,
      ),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]",
        [
          `Subject: ${r.subject}`,
          `From: "${r.fromName}" <s${r.uid}@example.invalid>`,
          "Date: Thu, 13 Aug 2026 09:14:02 -0700",
          `Message-ID: <m${r.uid}@example.invalid>`,
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

function snippetReply(tag: string, rows: readonly Row[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const r of rows) {
    chunks.push(
      ENCODER.encode(`* ${r.seq} FETCH (UID ${r.uid} `),
      literalItem("BODY[1]<0>", r.preview),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** A whole page session: open, search, metadata, previews, logout. */
function pageSession(searched: readonly number[], rows: readonly Row[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineReply("a4"),
    searchReply("a5", searched),
    metadataReply("a6", rows),
    snippetReply("a7", rows),
    logoutExchange("a8"),
  ]);
}

/** A session whose search finds nothing: open, search, logout. */
function emptySession(validity = UIDVALIDITY): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineReply("a4", validity),
    searchReply("a5", []),
    logoutExchange("a6"),
  ]);
}

/** Hand these duplexes out, one per session, in order. */
function sessions(...duplexes: FakeDuplex[]): void {
  for (const duplex of duplexes) vi.mocked(connectImap).mockReturnValueOnce(duplex as never);
}

/** The protocol's spelling of a `YYYY-MM-DD` day. */
function imapDay(day: string): string {
  const [y, m, d] = day.split("-").map(Number);
  return `${d}-${MONTHS[m! - 1]}-${y}`;
}

// ---------------------------------------------------------------------------
// The window's first day, and the date parser
// ---------------------------------------------------------------------------

describe("windowStartDay", () => {
  it("is the UTC day of now minus the retention window", () => {
    const now = Date.UTC(2026, 8, 27, 1, 0, 0);
    expect(windowStartDay(now)).toBe("2026-06-29");
    expect(windowStartDay(Date.UTC(2026, 8, 27, 0, 0, 0))).toBe("2026-06-29");
    expect(windowStartDay(Date.UTC(2026, 8, 27, 0, 0, 0) - 1)).toBe("2026-06-28");
    expect(windowStartDay(now)).toBe(new Date(now - RECALL_TTL_MS).toISOString().slice(0, 10));
  });
});

describe("parseInternalDate is strict (T-26-19)", () => {
  const accepted: [string, number][] = [
    ["26-Sep-2026 10:15:02 +0000", Date.UTC(2026, 8, 26, 10, 15, 2)],
    [" 7-Jul-2026 09:00:00 -0700", Date.UTC(2026, 6, 7, 16, 0, 0)],
    ["31-Dec-2025 23:59:59 +1400", Date.UTC(2025, 11, 31, 9, 59, 59)],
    ["7-Jul-2026 09:00:00 +0530", Date.UTC(2026, 6, 7, 3, 30, 0)],
  ];
  it.each(accepted)("reads %j", (value, expected) => {
    expect(parseInternalDate(value)).toBe(expected);
  });

  const refused: (string | null)[] = [
    "31-Feb-2026 10:00:00 +0000",
    "26-Sep-2026 10:15:02",
    "26-sep-2026 10:15:02 +0000",
    "",
    null,
    "26-Sep-26 10:15:02 +0000",
    "26-Sep-2026 24:00:00 +0000",
    "26-Sep-2026 10:15:02 +00",
    '"26-Sep-2026 10:15:02 +0000"',
    "126-Sep-2026 10:15:02 +0000",
  ];
  it.each(refused)("refuses %j", (value) => {
    expect(parseInternalDate(value)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// One page
// ---------------------------------------------------------------------------

describe("mailRecallSource.page reads the window through the listing (D-11)", () => {
  it("no cursor: one session, the window's search, 25 to a page, one item per row, the next cursor", async () => {
    // Thirty UIDs in the window. The page names the newest 25; the server
    // answers three of them, the rest having gone between the two commands.
    const searched = Array.from({ length: 30 }, (_, i) => 4771 + i);
    const rows = [row(4800), row(4799), row(4798)];
    const duplex = pageSession(searched, rows);
    sessions(duplex);

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    expect(connectImap).toHaveBeenCalledTimes(1);
    const lines = duplex.writtenLines();
    expect(lines[4]).toBe(`a5 UID SEARCH SINCE ${imapDay(windowStartDay())}`);
    const newest25 = searched.slice(5).reverse();
    expect(lines[5]!.startsWith(`a6 UID FETCH ${newest25.join(",")} (`)).toBe(true);

    expect(page.uidValidity).toBe(UIDVALIDITY);
    expect(page.items).toHaveLength(3);
    for (const [i, item] of page.items.entries()) {
      const r = rows[i]!;
      expect(item.ref).toEqual({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: r.uid });
      expect(item.snippet).toBe(r.subject);
      expect(item.text).toBe(`${r.subject}\n${r.fromName}\n${r.preview}`);
      expect(item.messageDate).toBe(Date.UTC(2026, 8, 26, 10, 15, 2));
    }
    expect(page.next).toEqual({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, lastUid: 4776 });
  });

  it("every fetch the page sends is the peeking form, and nothing opens the mailbox for changing", async () => {
    const duplex = pageSession([4800], [row(4800)]);
    sessions(duplex);

    await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    const lines = duplex.writtenLines();
    expect(lines.some((line) => /\bSELECT\b/.test(line))).toBe(false);
    const fetches = lines.filter((line) => line.includes(" UID FETCH "));
    expect(fetches).toHaveLength(2);
    for (const line of fetches) {
      expect(line.replace(/BODY\.PEEK\[/g, "")).not.toMatch(/BODY\[|RFC822(?!\.SIZE)/);
    }
  });

  it("the item's ref is the row id decoded, and next is null when there is no more", async () => {
    sessions(pageSession([4800], [row(4800)]));

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    expect(page.next).toBeNull();
    expect(page.items).toHaveLength(1);
    // The id the listing minted for this row, decoded.
    const minted = encodeMessageId({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: 4800 });
    expect(page.items[0]!.ref).toEqual(decodeMessageId(minted));
  });

  it("a body-preview canary reaches the embedded text and never the stored snippet (RCLL-08)", async () => {
    const canary = row(4800, { preview: "BODY-CANARY-3 lives in the body only." });
    sessions(pageSession([4800], [canary]));

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    expect(page.items).toHaveLength(1);
    expect(page.items[0]!.text).toContain("BODY-CANARY-3");
    expect(page.items[0]!.snippet).not.toContain("BODY-CANARY-3");
    expect(page.items[0]!.snippet).toBe(canary.subject);
  });

  it("a row with no subject stores an empty snippet, and its text is the name and the preview", () => {
    const item = recallItemOf({
      id: encodeMessageId({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: 9 }),
      uid: 9,
      unread: true,
      internalDate: "26-Sep-2026 10:15:02 +0000",
      wireSizeBytes: 1,
      subject: null,
      fromName: "Somebody",
      fromAddress: "s@example.invalid",
      snippet: "the body",
      hasAttachments: false,
    });
    expect(item).not.toBeNull();
    expect(item!.snippet).toBe("");
    expect(item!.text).toBe("Somebody\nthe body");
  });

  it("a row whose INTERNALDATE is missing or malformed is left out; the others are kept", async () => {
    const rows = [
      row(4803),
      row(4802, { internalDate: null }),
      row(4801, { internalDate: "31-Feb-2026 10:00:00 +0000" }),
      row(4800),
    ];
    sessions(pageSession([4800, 4801, 4802, 4803], rows));

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    expect(page.items.map((item) => item.ref.uid)).toEqual([4803, 4800]);
    expect(page.uidValidity).toBe(UIDVALIDITY);
  });

  it("a cursor the server still accepts, with no rows below it: one session, and the cursor's validity", async () => {
    const cursor: PageCursor = { mailbox: MAILBOX, uidValidity: UIDVALIDITY, lastUid: 100 };
    const duplex = emptySession();
    sessions(duplex);

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, cursor);

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(duplex.writtenLines()[4]).toBe(
      `a5 UID SEARCH UID 1:99 SINCE ${imapDay(windowStartDay())}`,
    );
    expect(page).toEqual({ uidValidity: UIDVALIDITY, items: [], next: null });
  });

  it("a cursor whose validity the mailbox no longer has: page one is read fresh, with the mailbox's current validity (T-26-21)", async () => {
    const stale: PageCursor = { mailbox: MAILBOX, uidValidity: OLD_VALIDITY, lastUid: 4000 };
    const refused = createFakeDuplex([...authPrefix(), examineReply("a4"), logoutExchange("a5")]);
    const fresh = pageSession([4800], [row(4800)]);
    sessions(refused, fresh);

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, stale);

    expect(connectImap).toHaveBeenCalledTimes(2);
    // The refused session wrote no search and no fetch.
    expect(refused.writtenLines().some((line) => line.includes("SEARCH"))).toBe(false);
    // The fresh session searched from the top: no range below a cursor.
    expect(fresh.writtenLines()[4]).toBe(`a5 UID SEARCH SINCE ${imapDay(windowStartDay())}`);
    expect(page.uidValidity).toBe(UIDVALIDITY);
    expect(page.uidValidity).not.toBe(stale.uidValidity);
    expect(page.items.map((item) => item.ref.uid)).toEqual([4800]);
  });

  it("a stale cursor on a window that is now empty: the snapshot supplies the new validity", async () => {
    const stale: PageCursor = { mailbox: MAILBOX, uidValidity: OLD_VALIDITY, lastUid: 4000 };
    const refused = createFakeDuplex([...authPrefix(), examineReply("a4"), logoutExchange("a5")]);
    sessions(refused, emptySession(), emptySession());

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, stale);

    expect(connectImap).toHaveBeenCalledTimes(3);
    expect(page).toEqual({ uidValidity: UIDVALIDITY, items: [], next: null });
  });

  it("no cursor and no rows: the validity comes from the window's UID snapshot of the same mailbox", async () => {
    const listing = emptySession();
    const snapshot = emptySession(UIDVALIDITY + 7);
    sessions(listing, snapshot);

    const page = await mailRecallSource.page(createSessionGate(), principal, MAILBOX, null);

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(snapshot.writtenLines()[3]).toBe('a4 EXAMINE "INBOX"');
    expect(snapshot.writtenLines()[4]).toBe(`a5 UID SEARCH SINCE ${imapDay(windowStartDay())}`);
    expect(page).toEqual({ uidValidity: UIDVALIDITY + 7, items: [], next: null });
  });

  it("an error that is not a refused cursor is not retried", async () => {
    const cursor: PageCursor = { mailbox: MAILBOX, uidValidity: UIDVALIDITY, lastUid: 4000 };
    vi.mocked(connectImap).mockImplementationOnce(() => {
      throw new Error("no socket");
    });

    await expect(
      mailRecallSource.page(createSessionGate(), principal, MAILBOX, cursor),
    ).rejects.not.toBeInstanceOf(ImapNotFoundError);
    expect(connectImap).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// The UID snapshot
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// New mail in a bounded range (plan 26-04, D-16)
// ---------------------------------------------------------------------------

/** A range session: open, the range search, metadata, previews, logout. */
function rangeSession(searched: readonly number[], rows: readonly Row[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineReply("a4"),
    searchReply("a5", searched),
    metadataReply("a6", rows),
    snippetReply("a7", rows),
    logoutExchange("a8"),
  ]);
}

function uidsFrom(from: number, count: number): number[] {
  return Array.from({ length: count }, (_, i) => from + i);
}

describe("summariesInRange reads new mail oldest first, bounded at both ends", () => {
  it("UIDs 100 to 139 exist: rows 100 to 124 in ascending order, and nextFrom 125", async () => {
    const oldest = uidsFrom(100, 25);
    const duplex = rangeSession(uidsFrom(100, 40).reverse(), oldest.map((uid) => row(uid)));
    sessions(duplex);

    const page = await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, 100, 140);

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(duplex.writtenLines()[4]).toBe("a5 UID SEARCH UID 100:139");
    expect(page.rows.map((r) => r.uid)).toEqual(oldest);
    expect(page.rows[0]!.subject).toBe("Subject for 100");
    expect(page.rows[0]!.snippet).toBe("Preview of message 100.");
    expect(page.nextFrom).toBe(125);
  });

  it("only UIDs 100 to 110 exist: rows 100 to 110, and nextFrom is the range's end", async () => {
    const present = uidsFrom(100, 11);
    sessions(rangeSession(present, present.map((uid) => row(uid))));

    const page = await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, 100, 140);

    expect(page.rows.map((r) => r.uid)).toEqual(present);
    expect(page.nextFrom).toBe(140);
  });

  it("a UID the server answers outside the range is ignored", async () => {
    const duplex = rangeSession([99, 100, 101, 140, 4000], [row(100), row(101)]);
    sessions(duplex);

    const page = await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, 100, 140);

    expect(duplex.writtenLines()[5]!.startsWith("a6 UID FETCH 100,101 (")).toBe(true);
    expect(page.rows.map((r) => r.uid)).toEqual([100, 101]);
    expect(page.nextFrom).toBe(140);
  });

  it("a range with nothing in it any more: no fetch, no rows, and nextFrom is the range's end", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", []),
      logoutExchange("a6"),
    ]);
    sessions(duplex);

    const page = await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, 100, 140);

    expect(duplex.writtenLines().some((line) => line.includes("FETCH"))).toBe(false);
    expect(page).toEqual({ rows: [], nextFrom: 140 });
  });

  it("a mailbox whose validity is not the stored one is refused before any search, as not found", async () => {
    const duplex = createFakeDuplex([...authPrefix(), examineReply("a4"), logoutExchange("a5")]);
    sessions(duplex);

    await expect(
      summariesInRange(principal, createSessionGate(), MAILBOX, OLD_VALIDITY, 100, 140),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
    expect(duplex.writtenLines().some((line) => line.includes("SEARCH"))).toBe(false);
  });

  it("toUidExclusive not above fromUid: no socket, no rows, and nextFrom is fromUid", async () => {
    for (const [from, to] of [
      [140, 140],
      [140, 100],
    ] as const) {
      const page = await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, from, to);
      expect(page).toEqual({ rows: [], nextFrom: from });
    }
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("an end that is not a UID is refused before any socket", async () => {
    for (const [from, to] of [
      [0, 140],
      [100, 1.5],
      [Number.NaN, 140],
    ] as const) {
      await expect(
        summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, from, to),
      ).rejects.toBeInstanceOf(ImapNotFoundError);
    }
    expect(connectImap).not.toHaveBeenCalled();
  });

  it("every fetch it sends is the peeking form, and nothing opens the mailbox for changing", async () => {
    const duplex = rangeSession([100], [row(100)]);
    sessions(duplex);

    await summariesInRange(principal, createSessionGate(), MAILBOX, UIDVALIDITY, 100, 101);

    const lines = duplex.writtenLines();
    expect(lines.some((line) => /\bSELECT\b/.test(line))).toBe(false);
    const fetches = lines.filter((line) => line.includes(" UID FETCH "));
    expect(fetches).toHaveLength(2);
    for (const line of fetches) {
      expect(line.replace(/BODY\.PEEK\[/g, "")).not.toMatch(/BODY\[|RFC822(?!\.SIZE)/);
    }
  });
});

describe("newMailPage maps the range's rows the way the window's pages do", () => {
  it("subject stored, preview only embedded, an unparseable date skipped, nextFrom unchanged", async () => {
    const oldest = uidsFrom(100, 25);
    const rows = oldest.map((uid) =>
      uid === 101
        ? row(uid, { internalDate: "31-Feb-2026 10:00:00 +0000" })
        : uid === 100
          ? row(uid, { preview: "BODY-CANARY-4 lives in the body only." })
          : row(uid),
    );
    sessions(rangeSession(uidsFrom(100, 30), rows));

    const page = await newMailPage(createSessionGate(), principal, MAILBOX, UIDVALIDITY, 100, 130);

    expect(page.nextFrom).toBe(125);
    expect(page.items.map((item) => item.ref.uid)).toEqual(oldest.filter((uid) => uid !== 101));
    const first = page.items[0]!;
    expect(first.ref).toEqual({ mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: 100 });
    expect(first.snippet).toBe("Subject for 100");
    expect(first.text).toContain("BODY-CANARY-4");
    expect(first.snippet).not.toContain("BODY-CANARY-4");
    expect(first.text).toBe("Subject for 100\nSender 100\nBODY-CANARY-4 lives in the body only.");
  });

  it("an empty range answers at once with no items and no socket", async () => {
    const page = await newMailPage(createSessionGate(), principal, MAILBOX, UIDVALIDITY, 140, 140);
    expect(page).toEqual({ items: [], nextFrom: 140 });
    expect(connectImap).not.toHaveBeenCalled();
  });
});

describe("mailRecallSource.uids and windowUids", () => {
  it("uids is the window's snapshot of the mailbox, since the window's first day", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4801, 4800]),
      logoutExchange("a6"),
    ]);
    sessions(duplex);

    const snapshot = await mailRecallSource.uids(createSessionGate(), principal, MAILBOX);

    expect(snapshot).toEqual({ uidValidity: UIDVALIDITY, uids: [4801, 4800] });
    expect(duplex.writtenLines()[4]).toBe(`a5 UID SEARCH SINCE ${imapDay(windowStartDay())}`);
  });

  it("windowUids refuses a malformed day before any socket is opened", async () => {
    await expect(
      windowUids(principal, createSessionGate(), MAILBOX, "2026-02-30"),
    ).rejects.toBeInstanceOf(ImapNotFoundError);
    expect(connectImap).not.toHaveBeenCalled();
  });
});
