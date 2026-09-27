// The move TOOLS, driven from their registered callbacks down to the bytes.
//
// iCloud has no move command, so every move here is an emulation: the copy,
// proven from the server's reply; the removal mark, conditional on the MODSEQ
// the preview sealed; the removal of that one UID; and a re-read of the source.
// The hazard is that a wrong version still looks like success, so the
// assertions are on the RECORDED BYTES and their ORDER, and on what the server
// sent back, never on a tagged OK alone (PITFALLS #31, #34, #35).
//
// The preview runs on the read path and has its own golden here. The read-path
// golden file, test/read-path-wire.test.ts, is not touched.
//
// The socket module is mocked for this file only, so each call's connect step
// hands back an in-memory duplex: the preview's first, then the commit's.
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID (D-13: live Apple testing is owner-only). The login line is redacted
// before every comparison, as in test/triage.test.ts.

import type { McpServer } from "@modelcontextprotocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import {
  decodeMessageId,
  encodeFolderId,
  encodeMessageId,
} from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { registerMailTools } from "../src/mcp/tools/mail";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  selectResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>) => Promise<ToolAnswer>;

/** The callbacks the mail tools register, on one gate, as one request would. */
function tools(): { move: Callback; commit: Callback } {
  const callbacks = new Map<string, Callback>();
  const server = {
    registerTool(name: string, _options: unknown, handler: Callback) {
      callbacks.set(name, handler);
    },
  };
  registerMailTools(server as unknown as McpServer, createSessionGate(), ownerPrincipal());
  expect(callbacks.get("mail_move"), "mail_move is not registered").toBeDefined();
  expect(callbacks.get("mail_commit"), "mail_commit is not registered").toBeDefined();
  return { move: callbacks.get("mail_move")!, commit: callbacks.get("mail_commit")! };
}

/** The fixed text a credential-carrying line is reduced to. */
const REDACTED = "[redacted]";

/** Every written line, with the login line redacted. */
function wireOf(duplex: FakeDuplex): string[] {
  return duplex.writtenLines().map((line) => {
    const tokens = line.split(" ");
    if ((tokens[1] ?? "").toUpperCase() === "LOGIN") {
      return `${tokens[0]} ${tokens[1]} ${REDACTED}`;
    }
    return line;
  });
}

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** The lines every session writes before its mailbox open. */
const SIGN_IN = ["a1 CAPABILITY", `a2 LOGIN ${REDACTED}`, "a3 CAPABILITY"];

// ---------------------------------------------------------------------------
// Local fixture builders. Used by this file only.
// ---------------------------------------------------------------------------

const ENCODER = new TextEncoder();

/** The destination folder's wire name. */
const RECEIPTS = "Receipts";

/**
 * The destination's UIDVALIDITY, deliberately DIFFERENT from the source's.
 *
 * RFC 4315 §3 puts the destination's validity first in COPYUID. A fixture where
 * the two were equal would pass whichever field a parser read (PITFALLS #35).
 */
const RECEIPTS_UIDVALIDITY = 1_726_000_001;

/** The internal date every fixture message carries, and its seconds. */
const INTERNAL_DATE = "13-Aug-2026 09:14:02 -0700";

/** A folder listing with INBOX and Receipts, then its completion. */
function listingReply(tag: string): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* STATUS "INBOX" (MESSAGES 172 UNSEEN 3)',
    `* LIST (\\HasNoChildren) "/" "${RECEIPTS}"`,
    `* STATUS "${RECEIPTS}" (MESSAGES 10 UNSEEN 0)`,
    `${tag} OK LIST completed`,
  );
}

/** One message as the fixtures describe it. */
interface Fixture {
  uid: number;
  size: number;
  modSeq: string;
  subject: string;
}

/** The fingerprint items of one message, as a FETCH reply's list. */
function fingerprintItems(message: Fixture): string {
  return (
    `UID ${message.uid} FLAGS (\\Seen) RFC822.SIZE ${message.size} ` +
    `INTERNALDATE "${INTERNAL_DATE}" MODSEQ (${message.modSeq})`
  );
}

/** The preview's fetch reply: fingerprint items plus a header literal each. */
function previewFetchReply(tag: string, messages: Fixture[]): Uint8Array {
  const parts: Uint8Array[] = [];
  messages.forEach((message, index) => {
    const header = ENCODER.encode(
      `Subject: ${message.subject}\r\nFrom: Shop <shop@example.com>\r\n` +
        "Date: Thu, 13 Aug 2026 09:14:02 -0700\r\n\r\n",
    );
    parts.push(
      ENCODER.encode(
        `* ${index + 1} FETCH (${fingerprintItems(message)} ` +
          `BODY[HEADER.FIELDS (SUBJECT FROM DATE)] {${header.byteLength}}\r\n`,
      ),
      header,
      ENCODER.encode(")\r\n"),
    );
  });
  parts.push(ENCODER.encode(`${tag} OK FETCH completed\r\n`));
  return concat(parts);
}

/** The commit's fingerprint re-read reply. */
function fingerprintReply(tag: string, messages: Fixture[]): Uint8Array {
  return wire(
    ...messages.map((message, index) => `* ${index + 1} FETCH (${fingerprintItems(message)})`),
    `${tag} OK FETCH completed`,
  );
}

/** A copy's completion carrying COPYUID: destination validity FIRST. */
function copyReply(tag: string, sourceUid: number, newUid: number): Uint8Array {
  return wire(
    `${tag} OK [COPYUID ${RECEIPTS_UIDVALIDITY} ${sourceUid} ${newUid}] COPY completed`,
  );
}

/** The removal mark's echo, then its completion. */
function markEcho(tag: string, uid: number, modSeq: string): Uint8Array {
  return wire(
    `* 1 FETCH (UID ${uid} MODSEQ (${modSeq}) FLAGS (\\Seen \\Deleted))`,
    `${tag} OK STORE completed`,
  );
}

/** A search reply listing `uids`, then its completion. */
function searchReply(tag: string, uids: number[]): Uint8Array {
  return wire(
    uids.length === 0 ? "* SEARCH" : `* SEARCH ${uids.join(" ")}`,
    `${tag} OK SEARCH completed`,
  );
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

/** A message id in INBOX. */
function idOf(uid: number): string {
  return encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid });
}

const RECEIPTS_ID = encodeFolderId({ mailbox: RECEIPTS });

/** The preview's conversation for `messages`. Its logout is tag `a7`. */
function previewServer(messages: Fixture[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    listingReply("a5"),
    previewFetchReply("a6", messages),
    logoutExchange("a7"),
  ]);
}

/** The preview's whole recorded line array for `uids`. */
function previewLines(uids: number[]): string[] {
  return [
    ...SIGN_IN,
    'a4 EXAMINE "INBOX"',
    'a5 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
    `a6 UID FETCH ${uids.join(",")} (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ ` +
      "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])",
    "a7 LOGOUT",
  ];
}

/** Parse a text block of an answer. */
function body(answer: ToolAnswer, index = 0): Record<string, unknown> {
  return JSON.parse(answer.content[index]!.text) as Record<string, unknown>;
}

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

describe("move one message to a named folder, previewed and committed", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Receipt" };

  it("previews on the read path, then moves, and reports moved from the re-read", async () => {
    const { move, commit } = tools();
    const preview = previewServer([MESSAGE]);
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [MESSAGE]),
      copyReply("a6", MESSAGE.uid, 88),
      markEcho("a7", MESSAGE.uid, "743"),
      wire("* 1 EXPUNGE", "a8 OK EXPUNGE completed"),
      searchReply("a9", []),
      logoutExchange("a10"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(MESSAGE.uid)];
    const previewed = await move({ ids, destination: RECEIPTS_ID });

    expect(previewed.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    const trusted = body(previewed);
    expect(typeof trusted.confirmToken).toBe("string");
    expect(trusted.change).toEqual({ op: "move", ids, destination: RECEIPTS_ID });
    expect(trusted.confirmationLine).toBe(
      "Moving 1 message from 'INBOX' to 'Receipts'. It can be moved back.",
    );
    expect(trusted.count).toBe(1);
    // The stranger-authored half sits behind the fence, not in the trusted block.
    expect(previewed.content[0]!.text).not.toContain("Receipt for");
    expect(previewed.content[1]!.text).toContain('"subject":"Receipt"');

    const answer = await commit({
      confirmToken: trusted.confirmToken,
      change: trusted.change,
    });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(committed)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 UID FETCH 4242 (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
      'a6 UID COPY 4242 "Receipts"',
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID EXPUNGE 4242",
      "a9 UID SEARCH UID 4242",
      "a10 LOGOUT",
    ]);

    const result = body(answer) as {
      confirmationLine: string;
      results: { id: string; outcome: string; reason: string; newId: string; destination: string }[];
    };
    expect(result.confirmationLine).toBe(
      "Moved 1 message from 'INBOX' to 'Receipts'. It can be moved back.",
    );
    expect(result.results).toHaveLength(1);
    expect(result.results[0]).toMatchObject({
      id: ids[0],
      outcome: "moved",
      reason: "verified-gone",
      destination: RECEIPTS_ID,
    });
    // The new id carries the DESTINATION's validity from COPYUID, never the
    // source's (PITFALLS #35).
    expect(decodeMessageId(result.results[0]!.newId)).toEqual({
      mailbox: RECEIPTS,
      uidValidity: RECEIPTS_UIDVALIDITY,
      uid: 88,
    });
    expect(RECEIPTS_UIDVALIDITY).not.toBe(INBOX_UIDVALIDITY);
  });

  it("refuses to spend the same confirmation twice", async () => {
    const { move, commit } = tools();
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(
        createFakeDuplex([
          ...authPrefix(),
          selectResponse("a4", "[READ-WRITE]"),
          fingerprintReply("a5", [MESSAGE]),
          copyReply("a6", MESSAGE.uid, 88),
          markEcho("a7", MESSAGE.uid, "743"),
          wire("a8 OK EXPUNGE completed"),
          searchReply("a9", []),
          logoutExchange("a10"),
        ]) as never,
      );

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    await commit({ confirmToken: trusted.confirmToken, change: trusted.change });
    const again = await commit({ confirmToken: trusted.confirmToken, change: trusted.change });

    expect(again.isError).toBe(true);
    expect(body(again).category).toBe("confirmation_invalid");
    // The second commit opened nothing.
    expect(connectImap).toHaveBeenCalledTimes(2);
  });
});

describe("move two messages in one session", () => {
  const FIRST: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "One" };
  const SECOND: Fixture = { uid: 4250, size: 2_048, modSeq: "760", subject: "Two" };

  it("fetches both fingerprints at once, then each message's four lines in the caller's order", async () => {
    const { move, commit } = tools();
    const preview = previewServer([FIRST, SECOND]);
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [FIRST, SECOND]),
      copyReply("a6", FIRST.uid, 88),
      markEcho("a7", FIRST.uid, "761"),
      wire("a8 OK EXPUNGE completed"),
      searchReply("a9", []),
      copyReply("a10", SECOND.uid, 89),
      markEcho("a11", SECOND.uid, "762"),
      wire("a12 OK EXPUNGE completed"),
      searchReply("a13", []),
      logoutExchange("a14"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(FIRST.uid), idOf(SECOND.uid)];
    const trusted = body(await move({ ids, destination: RECEIPTS_ID }));

    expect(wireOf(preview)).toEqual(previewLines([FIRST.uid, SECOND.uid]));
    expect(trusted.confirmationLine).toBe(
      "Moving 2 messages from 'INBOX' to 'Receipts'. They can be moved back.",
    );

    const answer = body(
      await commit({ confirmToken: trusted.confirmToken, change: trusted.change }),
    ) as { confirmationLine: string; results: { id: string; outcome: string; newId: string }[] };

    expect(wireOf(committed)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 UID FETCH 4242,4250 (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
      'a6 UID COPY 4242 "Receipts"',
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID EXPUNGE 4242",
      "a9 UID SEARCH UID 4242",
      'a10 UID COPY 4250 "Receipts"',
      "a11 UID STORE 4250 (UNCHANGEDSINCE 760) +FLAGS (\\Deleted)",
      "a12 UID EXPUNGE 4250",
      "a13 UID SEARCH UID 4250",
      "a14 LOGOUT",
    ]);
    expect(answer.confirmationLine).toBe(
      "Moved 2 messages from 'INBOX' to 'Receipts'. They can be moved back.",
    );
    expect(answer.results.map((one) => [one.id, one.outcome])).toEqual([
      [ids[0], "moved"],
      [ids[1], "moved"],
    ]);
    expect(decodeMessageId(answer.results[1]!.newId).uid).toBe(89);
  });
});

describe("a MODSEQ past 2^53", () => {
  // RFC 7162 permits 63 bits. This value and its neighbour are the same JS
  // number, so a MODSEQ that went through one would arrive on the wire wrong.
  const BIG = "4611686018427387905";
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: BIG, subject: "Big" };

  it("reaches the removal-mark line byte for byte", async () => {
    const { move, commit } = tools();
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [MESSAGE]),
      copyReply("a6", MESSAGE.uid, 88),
      markEcho("a7", MESSAGE.uid, "4611686018427387906"),
      wire("a8 OK EXPUNGE completed"),
      searchReply("a9", []),
      logoutExchange("a10"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(committed as never);

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    await commit({ confirmToken: trusted.confirmToken, change: trusted.change });

    expect(wireOf(committed)).toContain(
      `a7 UID STORE 4242 (UNCHANGEDSINCE ${BIG}) +FLAGS (\\Deleted)`,
    );
    expect(String(Number(BIG))).not.toBe(BIG);
  });
});

describe("the verdict comes from the re-read, not from an OK (TRIA-06)", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Still" };

  it("reports copied_not_removed when the removal answers OK and the search still lists the UID", async () => {
    const { move, commit } = tools();
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(
        createFakeDuplex([
          ...authPrefix(),
          selectResponse("a4", "[READ-WRITE]"),
          fingerprintReply("a5", [MESSAGE]),
          copyReply("a6", MESSAGE.uid, 88),
          markEcho("a7", MESSAGE.uid, "743"),
          wire("a8 OK EXPUNGE completed"),
          searchReply("a9", [MESSAGE.uid]),
          logoutExchange("a10"),
        ]) as never,
      );

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    const answer = body(
      await commit({ confirmToken: trusted.confirmToken, change: trusted.change }),
    ) as { confirmationLine: string; results: { outcome: string; reason: string; newId: string }[] };

    expect(answer.results[0]).toMatchObject({
      outcome: "copied_not_removed",
      reason: "still-in-source",
    });
    // The copy was proven, so the answer still says where it went.
    expect(decodeMessageId(answer.results[0]!.newId).uidValidity).toBe(RECEIPTS_UIDVALIDITY);
    expect(answer.confirmationLine).toBe(
      "Moved 0 of 1 message from 'INBOX' to 'Receipts'; 1 copied but not removed. " +
        "It can be moved back.",
    );
  });
});
