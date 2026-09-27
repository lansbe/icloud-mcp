// The draft delete, driven from its registered callbacks down to the bytes
// (Phase 22, DRFT-03 to DRFT-07).
//
// A draft delete is a move of one draft to Trash, and nothing else. It reuses
// Phase 21's move step: the copy, proven from the server's reply; the removal
// mark, conditional on the MODSEQ the preview sealed; the removal of that one
// UID; and a count re-read of the drafts folder. The hazard is that a wrong
// version still looks like success, so the assertions are on the RECORDED BYTES
// and their ORDER, and on what the server sent back, never on a tagged OK alone.
//
// The preview runs on the read path and has its own golden here. The read-path
// golden file, test/read-path-wire.test.ts, is not touched.
//
// The socket module is mocked for this file only, so each call's connect step
// hands back an in-memory duplex: the preview's first, then the commit's. The
// tools are built on the real lease runner, so every call takes the person's
// real lease in the pool's object. Nothing here opens a network connection and
// nothing signs in to a real Apple ID (D-18: live Apple testing is owner-only).
// The login line is redacted before every comparison.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { createLeasedMail } from "../src/agent/lease";
import { verifyConfirmation } from "../src/confirm";
import type { MailConfirmPayload } from "../src/confirm";
import { decodeFolderId, decodeMessageId, encodeMessageId } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { DRAFT_GUARANTEE, registerMailTools } from "../src/mcp/tools/mail";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import {
  DRAFTS_UIDVALIDITY,
  GREETING,
  MEASURED_POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  TRASH_UIDVALIDITY,
  capabilityResponse,
  draftFingerprintReply,
  draftListingReply,
  draftPreviewFetchReply,
  esearchCountReply,
  examineResponse,
  logoutExchange,
  selectResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import type { DraftFixture } from "./fixtures/icloud-bytes";

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>) => Promise<ToolAnswer>;

/** The callbacks the mail tools register, on one gate and one lease runner. */
function tools(): { preview: Callback; commit: Callback } {
  const callbacks = new Map<string, Callback>();
  const server = {
    registerTool(name: string, _options: unknown, handler: Callback) {
      callbacks.set(name, handler);
    },
  };
  registerMailTools(
    server as unknown as McpServer,
    createLeasedMail(createSessionGate()),
    ownerPrincipal(),
  );
  expect(callbacks.get("mail_delete_draft"), "mail_delete_draft is not registered").toBeDefined();
  expect(callbacks.get("mail_commit"), "mail_commit is not registered").toBeDefined();
  return { preview: callbacks.get("mail_delete_draft")!, commit: callbacks.get("mail_commit")! };
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

/**
 * The four turns every conversation opens with. The next tag is `a4`. The
 * capability line is the one iCloud really sent: UIDPLUS and CONDSTORE for the
 * move, ESEARCH for its count re-read.
 */
function authPrefix(capability = MEASURED_POST_AUTH_CAPABILITY): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", capability),
  ];
}

/** The lines every session writes before its mailbox open. */
const SIGN_IN = ["a1 CAPABILITY", `a2 LOGIN ${REDACTED}`, "a3 CAPABILITY"];

/** The internal date every fixture draft carries, and its whole seconds. */
const INTERNAL_DATE = "24-Sep-2026 10:02:11 -0700";
const INTERNAL_SECONDS = Date.UTC(2026, 8, 24, 17, 2, 11) / 1000;

/** The draft most cases use. */
const DRAFT: DraftFixture = {
  uid: 311,
  size: 2_417,
  modSeq: "88120",
  flags: "\\Draft \\Seen",
  internalDate: INTERNAL_DATE,
  subject: "Thank you for today",
  to: "Recruiter <recruiter@example.invalid>",
};

/** A message id in Drafts. */
function draftId(uid = DRAFT.uid): string {
  return encodeMessageId({ mailbox: "Drafts", uidValidity: DRAFTS_UIDVALIDITY, uid });
}

/** The preview's fetch line for `uid`. */
function previewFetchLine(tag: string, uid = DRAFT.uid): string {
  return (
    `${tag} UID FETCH ${uid} (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ ` +
    "BODY.PEEK[HEADER.FIELDS (SUBJECT TO CC DATE)])"
  );
}

/** The preview's conversation for `draft`. Its logout is tag `a7`. */
function previewServer(draft: DraftFixture = DRAFT): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4", 3, DRAFTS_UIDVALIDITY),
    draftListingReply("a5"),
    draftPreviewFetchReply("a6", draft),
    logoutExchange("a7"),
  ]);
}

/** The preview's whole recorded line array. */
const PREVIEW_LINES = [
  ...SIGN_IN,
  'a4 EXAMINE "Drafts"',
  'a5 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
  previewFetchLine("a6"),
  "a7 LOGOUT",
];

/** A copy's completion carrying COPYUID: Trash's validity FIRST. */
function copyReply(tag: string, sourceUid: number, newUid: number): Uint8Array {
  return wire(`${tag} OK [COPYUID ${TRASH_UIDVALIDITY} ${sourceUid} ${newUid}] COPY completed`);
}

/** The removal mark's echo, then its completion. */
function markEcho(tag: string, uid: number, modSeq: string): Uint8Array {
  return wire(
    `* 1 FETCH (UID ${uid} MODSEQ (${modSeq}) FLAGS (\\Draft \\Seen \\Deleted))`,
    `${tag} OK STORE completed`,
  );
}

/** The commit's opening lines: the mutating open, then the fingerprint re-read. */
const OPEN_AND_CHECK = [
  ...SIGN_IN,
  'a4 SELECT "Drafts"',
  `a5 UID FETCH ${DRAFT.uid} (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)`,
];

/** The move step's four lines for the draft, from tag `a6`. */
const MOVE_LINES = [
  `a6 UID COPY ${DRAFT.uid} "Deleted Messages"`,
  `a7 UID STORE ${DRAFT.uid} (UNCHANGEDSINCE ${DRAFT.modSeq}) +FLAGS (\\Deleted)`,
  `a8 UID EXPUNGE ${DRAFT.uid}`,
  `a9 UID SEARCH RETURN (COUNT) UID ${DRAFT.uid}`,
];

/** Parse a text block of an answer. */
function body(answer: ToolAnswer, index = 0): Record<string, unknown> {
  return JSON.parse(answer.content[index]!.text) as Record<string, unknown>;
}

/** The person's lease record in the pool's object, or `undefined` when free. */
async function readLease(): Promise<unknown> {
  const stub = env.USER_AGENT.getByName((await ownerPrincipal()).userId);
  return runInDurableObject(stub, (_instance, state) => state.storage.kv.get("lease"));
}

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

// ---------------------------------------------------------------------------
// The tracer
// ---------------------------------------------------------------------------

describe("delete one draft, end to end", () => {
  it("previews on the read path, then moves the draft to Trash, and reports moved from the re-read", async () => {
    const { preview, commit } = tools();
    const previewed = previewServer();
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 3, DRAFTS_UIDVALIDITY),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      markEcho("a7", DRAFT.uid, "88121"),
      wire("* 1 EXPUNGE", "a8 OK EXPUNGE completed"),
      esearchCountReply("a9", 0),
      logoutExchange("a10"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewed as never)
      .mockReturnValueOnce(committed as never);

    const id = draftId();
    const previewAnswer = await preview({ id });

    // The preview: one read-only session, and the lease given back.
    expect(previewAnswer.isError).toBeUndefined();
    expect(wireOf(previewed)).toEqual(PREVIEW_LINES);
    expect(await readLease()).toBeUndefined();

    const trusted = body(previewAnswer);
    expect(trusted.change).toEqual({ op: "draft-delete", id, subject: DRAFT.subject });
    expect(trusted.confirmationLine).toBe(
      `Moving draft '${DRAFT.subject}' to Trash. It can be moved back out of Trash until ` +
        "Trash is emptied.",
    );
    expect(trusted.guarantee).toBe(DRAFT_GUARANTEE);
    expect(DRAFT_GUARANTEE).toBe(
      "This acts only on a draft, in the drafts folder, exactly as you were just shown it. " +
        "It does not check who wrote the draft.",
    );
    // The draft's own text sits behind the fence, not in the trusted block.
    expect(previewAnswer.content[1]!.text).toContain("recruiter@example.invalid");
    expect(previewAnswer.content[0]!.text).not.toContain("recruiter@example.invalid");

    // The confirmation seals every value the server supplied.
    const payload = (await verifyConfirmation(
      String(trusted.confirmToken),
      env.CONFIRM_SECRET,
      (await ownerPrincipal()).userId,
      "mail",
    )) as MailConfirmPayload;
    expect(payload.t).toBe("mail");
    expect(payload.k).toBe("delete");
    expect(payload.qr).toBe("trash");
    expect(decodeFolderId(payload.m).mailbox).toBe("Drafts");
    expect(payload.q).not.toBeNull();
    expect(decodeFolderId(payload.q!).mailbox).toBe("Deleted Messages");
    expect(payload.uv).toBe(DRAFTS_UIDVALIDITY);
    expect(payload.l).toEqual([
      { i: DRAFT.uid, z: DRAFT.size, d: INTERNAL_SECONDS, n: DRAFT.modSeq },
    ]);

    const answer = await commit({ confirmToken: trusted.confirmToken, change: trusted.change });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(committed)).toEqual([...OPEN_AND_CHECK, ...MOVE_LINES, "a10 LOGOUT"]);
    expect(await readLease()).toBeUndefined();

    const result = body(answer) as {
      confirmationLine: string;
      results: { id: string; outcome: string; reason: string; newId: string; destination: string }[];
      guarantee: string;
    };
    expect(Object.keys(result).sort()).toEqual(["confirmationLine", "guarantee", "results"]);
    expect(result.confirmationLine).toBe(
      `Moved draft '${DRAFT.subject}' to Trash. It can be moved back out of Trash until ` +
        "Trash is emptied.",
    );
    expect(result.guarantee).toBe(DRAFT_GUARANTEE);
    expect(result.results).toHaveLength(1);
    expect(result.results[0]).toMatchObject({
      id,
      outcome: "moved",
      reason: "verified-gone",
      destination: payload.q,
    });
    // The new id carries TRASH's validity from COPYUID, never the drafts
    // folder's (PITFALLS #35).
    expect(decodeMessageId(result.results[0]!.newId)).toEqual({
      mailbox: "Deleted Messages",
      uidValidity: TRASH_UIDVALIDITY,
      uid: 97,
    });
    expect(TRASH_UIDVALIDITY).not.toBe(DRAFTS_UIDVALIDITY);
  });
});
