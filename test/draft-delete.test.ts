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
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  composeConfirmationLine,
  draftChangeHashOf,
  mailMoveChangeHashOf,
  mintConfirmation,
  reserveConfirmation,
  verifyConfirmation,
} from "../src/confirm";
import type { MailConfirmPayload, MailSetEntry } from "../src/confirm";
import { ImapConnectError } from "../src/errors";
import {
  decodeFolderId,
  decodeMessageId,
  encodeFolderId,
  encodeMessageId,
} from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { deleteDraftOver } from "../src/mail/triage";
import type { DraftDeleteOutcome } from "../src/mail/triage";
import { DRAFT_GUARANTEE, registerMailTools } from "../src/mcp/tools/mail";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex, createStallingDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import {
  DRAFTS_UIDVALIDITY,
  GREETING,
  INBOX_UIDVALIDITY,
  MEASURED_POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  TRASH_UIDVALIDITY,
  capabilityResponse,
  draftFingerprintReply,
  draftListingReply,
  draftPreviewFetchReply,
  emptySearchReply,
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
function tools(): { preview: Callback; commit: Callback; descriptions: Map<string, string> } {
  const callbacks = new Map<string, Callback>();
  const descriptions = new Map<string, string>();
  const server = {
    registerTool(name: string, options: { description?: string }, handler: Callback) {
      callbacks.set(name, handler);
      descriptions.set(name, String(options.description));
    },
  };
  registerMailTools(
    server as unknown as McpServer,
    createLeasedMail(createSessionGate()),
    ownerPrincipal(),
  );
  expect(callbacks.get("mail_delete_draft"), "mail_delete_draft is not registered").toBeDefined();
  expect(callbacks.get("mail_commit"), "mail_commit is not registered").toBeDefined();
  return {
    preview: callbacks.get("mail_delete_draft")!,
    commit: callbacks.get("mail_commit")!,
    descriptions,
  };
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

// ---------------------------------------------------------------------------
// Every way the delete can fail (22-01 Task 3)
//
// Each case asserts the whole recorded line array and the answer's exact key
// set. A refusal is plain JSON with the guarantee; an error is the fixed
// category and message and nothing else.
// ---------------------------------------------------------------------------

/** Every answer a case produced, for the guarantee and the wording checks. */
const SEEN_ANSWERS: ToolAnswer[] = [];

/** Record an answer and hand it back. */
function seen(answer: ToolAnswer): ToolAnswer {
  SEEN_ANSWERS.push(answer);
  return answer;
}

/** The answer's top-level keys, sorted. */
function keysOf(answer: ToolAnswer): string[] {
  return Object.keys(body(answer)).sort();
}

/** Assert a named draft refusal: plain JSON, the guarantee, no token. */
function expectDraftRefusal(
  answer: ToolAnswer,
  refusal: string,
  keys: string[],
): Record<string, unknown> {
  expect(answer.isError, "a refusal is not an error").toBeUndefined();
  const parsed = body(answer);
  expect(parsed.refusal).toBe(refusal);
  expect(typeof parsed.reason).toBe("string");
  expect(parsed.guarantee).toBe(DRAFT_GUARANTEE);
  expect(keysOf(answer)).toEqual([...keys].sort());
  return parsed;
}

/** Assert a tool error of `category`: the fixed pair, and nothing else. */
function expectCategory(answer: ToolAnswer, category: string): void {
  expect(answer.isError).toBe(true);
  expect(body(answer).category).toBe(category);
  expect(keysOf(answer)).toEqual(["category", "message"]);
}

/** A preview conversation whose open, listing and fetch reply the case chooses. */
function previewServerWith(parts: {
  open?: Uint8Array;
  listing?: Uint8Array;
  fetched?: Uint8Array | null;
  logoutTag?: string;
}): FakeDuplex {
  const fetched = parts.fetched === undefined ? draftPreviewFetchReply("a6", DRAFT) : parts.fetched;
  return createFakeDuplex([
    ...authPrefix(),
    parts.open ?? examineResponse("a4", 3, DRAFTS_UIDVALIDITY),
    parts.listing ?? draftListingReply("a5"),
    ...(fetched === null ? [] : [fetched]),
    logoutExchange(parts.logoutTag ?? (fetched === null ? "a6" : "a7")),
  ]);
}

/** The preview's lines up to and including the listing, for `mailbox`. */
function previewThroughListing(mailbox = "Drafts"): string[] {
  return [
    ...SIGN_IN,
    `a4 EXAMINE "${mailbox}"`,
    'a5 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
  ];
}

/** Preview `draft` on the standard server, and hand back the trusted block. */
async function previewedDraft(
  preview: Callback,
  draft: DraftFixture = DRAFT,
): Promise<Record<string, unknown>> {
  vi.mocked(connectImap).mockReturnValueOnce(previewServer(draft) as never);
  const answer = seen(await preview({ id: draftId(draft.uid) }));
  expect(answer.isError).toBeUndefined();
  return body(answer);
}

/** The commit's opening replies: sign-in on `capability`, then a writable open. */
function openReplies(capability = MEASURED_POST_AUTH_CAPABILITY): Uint8Array[] {
  return [...authPrefix(capability), selectResponse("a4", "[READ-WRITE]", 3, DRAFTS_UIDVALIDITY)];
}

/** Preview the standard draft, then commit it against `script`. */
async function previewThenCommit(
  script: Uint8Array[],
): Promise<{ answer: ToolAnswer; lines: string[]; id: string }> {
  const { preview, commit } = tools();
  const trusted = await previewedDraft(preview);
  const committed = createFakeDuplex(script);
  vi.mocked(connectImap).mockReturnValueOnce(committed as never);
  const answer = seen(
    await commit({ confirmToken: trusted.confirmToken, change: trusted.change }),
  );
  expect(connectImap).toHaveBeenCalledTimes(2);
  expect(await readLease()).toBeUndefined();
  return { answer, lines: wireOf(committed), id: draftId() };
}

/** The command word of a recorded line, past its tag and any `UID` prefix. */
function commandWord(line: string): string {
  const tokens = line.split(" ");
  const word = (tokens[1] ?? "").toUpperCase() === "UID" ? tokens[2] : tokens[1];
  return (word ?? "").toUpperCase();
}

/** The three commands that change mail. None may follow a refusal. */
const CHANGING = ["COPY", "STORE", "EXPUNGE"];

function expectNothingChanging(lines: string[]): void {
  expect(lines.filter((line) => CHANGING.includes(commandWord(line)))).toEqual([]);
}

/** The sentences a draft commit answer may carry, by outcome. */
const UNKNOWN_LINE =
  `This may have partly happened to draft '${DRAFT.subject}'. Look in Drafts and Trash ` +
  "before trying again.";
const NOT_COPIED_LINE = `Draft '${DRAFT.subject}' was not moved. Nothing was changed.`;
const COPIED_NOT_REMOVED_LINE =
  `Copied draft '${DRAFT.subject}' to Trash, but could not remove it from Drafts. ` +
  "It is now in both folders.";

type AppliedBody = {
  confirmationLine: string;
  results: {
    id: string;
    outcome: string;
    reason: string;
    newId: string | null;
    destination: string;
  }[];
  guarantee: string;
};

/** Assert an applied commit answer and hand back its body. */
function expectApplied(answer: ToolAnswer): AppliedBody {
  expect(answer.isError, "an applied answer is not an error").toBeUndefined();
  expect(keysOf(answer)).toEqual(["confirmationLine", "guarantee", "results"]);
  const parsed = body(answer) as AppliedBody;
  expect(parsed.guarantee).toBe(DRAFT_GUARANTEE);
  expect(parsed.results).toHaveLength(1);
  expect(Object.keys(parsed.results[0]!).sort()).toEqual([
    "destination",
    "id",
    "newId",
    "outcome",
    "reason",
  ]);
  return parsed;
}

describe("the preview refuses", () => {
  it("a listing with no drafts folder at all: not_found, and nothing is fetched or guessed", async () => {
    const { preview } = tools();
    const server = previewServerWith({
      listing: draftListingReply("a5", [
        ["INBOX", "\\HasNoChildren"],
        ["Deleted Messages", "\\HasNoChildren \\Trash"],
      ]),
      fetched: null,
    });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectCategory(answer, "not_found");
    expect(wireOf(server)).toEqual([...previewThroughListing(), "a6 LOGOUT"]);
    expect(await readLease()).toBeUndefined();
  });

  it("an INBOX message: not-in-drafts, and no fingerprint fetch is sent", async () => {
    const { preview } = tools();
    const server = previewServerWith({ open: examineResponse("a4"), fetched: null });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);
    const id = encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid: 4242 });

    const answer = seen(await preview({ id }));

    const parsed = expectDraftRefusal(answer, "not-in-drafts", ["id", "refusal", "reason", "guarantee"]);
    expect(parsed.id).toBe(id);
    expect(wireOf(server)).toEqual([...previewThroughListing("INBOX"), "a6 LOGOUT"]);
  });

  it("a Drafts message without the draft flag: not-a-draft, and no token", async () => {
    const { preview } = tools();
    const server = previewServerWith({
      fetched: draftPreviewFetchReply("a6", { ...DRAFT, flags: "\\Seen" }),
    });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectDraftRefusal(answer, "not-a-draft", ["id", "refusal", "reason", "guarantee"]);
    expect(wireOf(server)).toEqual(PREVIEW_LINES);
  });

  it.each<[string, [string, string][]]>([
    ["one folder named Trash, with no attribute", [["Trash", "\\HasNoChildren"]]],
    ["one folder named Deleted Messages, with no attribute", [["Deleted Messages", "\\HasNoChildren"]]],
    [
      "two Trash-like names, neither with the attribute",
      [
        ["Trash", "\\HasNoChildren"],
        ["Deleted Messages", "\\HasNoChildren"],
      ],
    ],
    ["no Trash-like folder at all", []],
  ])("%s: no-trash-folder, and no fetch", async (_label, trashFolders) => {
    const { preview } = tools();
    const server = previewServerWith({
      listing: draftListingReply("a5", [
        ["INBOX", "\\HasNoChildren"],
        ["Drafts", "\\HasNoChildren"],
        ...trashFolders,
      ]),
      fetched: null,
    });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectDraftRefusal(answer, "no-trash-folder", ["id", "refusal", "reason", "guarantee"]);
    expect(wireOf(server)).toEqual([...previewThroughListing(), "a6 LOGOUT"]);
  });

  it("two folders the server marks as Trash: ambiguous-role-folder, and neither is picked", async () => {
    const { preview } = tools();
    const server = previewServerWith({
      listing: draftListingReply("a5", [
        ["INBOX", "\\HasNoChildren"],
        ["Drafts", "\\HasNoChildren"],
        ["Deleted Messages", "\\HasNoChildren \\Trash"],
        ["Bin", "\\HasNoChildren \\Trash"],
      ]),
      fetched: null,
    });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectDraftRefusal(answer, "ambiguous-role-folder", ["id", "refusal", "reason", "guarantee"]);
    expect(wireOf(server)).toEqual([...previewThroughListing(), "a6 LOGOUT"]);
  });

  it("a draft already carrying the removal mark: already-marked-for-removal", async () => {
    const { preview } = tools();
    const server = previewServerWith({
      fetched: draftPreviewFetchReply("a6", { ...DRAFT, flags: "\\Draft \\Deleted" }),
    });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectDraftRefusal(answer, "already-marked-for-removal", ["id", "refusal", "reason", "guarantee"]);
    expect(wireOf(server)).toEqual(PREVIEW_LINES);
  });

  it("a fetch carrying MODSEQ answered BAD: no-change-numbers", async () => {
    const { preview } = tools();
    const server = previewServerWith({ fetched: wire("a6 BAD [CLIENTBUG] MODSEQ not supported") });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectDraftRefusal(answer, "no-change-numbers", ["id", "refusal", "reason", "guarantee"]);
    expect(wireOf(server)).toEqual(PREVIEW_LINES);
  });

  it("a fetch with no reply for the UID: not_found, and nothing else is looked up", async () => {
    const { preview } = tools();
    const server = previewServerWith({ fetched: wire("a6 OK FETCH completed") });
    vi.mocked(connectImap).mockReturnValueOnce(server as never);

    const answer = seen(await preview({ id: draftId() }));

    expectCategory(answer, "not_found");
    expect(wireOf(server)).toEqual(PREVIEW_LINES);
  });
});

describe("the commit reports what happened", () => {
  const MISMATCHES: [string, Uint8Array][] = [
    ["a different size", draftFingerprintReply("a5", { ...DRAFT, size: DRAFT.size + 1 })],
    [
      "a different internal date",
      draftFingerprintReply("a5", { ...DRAFT, internalDate: "24-Sep-2026 10:02:12 -0700" }),
    ],
    ["a different MODSEQ", draftFingerprintReply("a5", { ...DRAFT, modSeq: "88121" })],
    ["no reply for the UID", wire("a5 OK FETCH completed")],
    ["the draft flag gone", draftFingerprintReply("a5", { ...DRAFT, flags: "\\Seen" })],
    ["the removal mark appeared", draftFingerprintReply("a5", { ...DRAFT, flags: "\\Draft \\Deleted" })],
  ];

  it.each(MISMATCHES)(
    "%s at the re-read: changed-since-preview, and nothing after the re-read but the logout",
    async (_label, reread) => {
      const { answer, lines, id } = await previewThenCommit([
        ...openReplies(),
        reread,
        logoutExchange("a6"),
      ]);

      const parsed = expectDraftRefusal(answer, "changed-since-preview", [
        "refusal",
        "reason",
        "changedIds",
        "guarantee",
      ]);
      expect(parsed.changedIds).toEqual([id]);
      expect(parsed.reason).toBe(
        "The draft changed or is gone since the preview. Nothing was changed. Preview it again.",
      );
      expect(lines).toEqual([...OPEN_AND_CHECK, "a6 LOGOUT"]);
      expectNothingChanging(lines);
    },
  );

  it("no fallback: a sealed UID with no reply is refused, never searched for by subject or header", async () => {
    // Another message answers the re-read, carrying the same size, date and
    // MODSEQ. It is not the draft that was previewed, and it is not looked at.
    const { answer, lines } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", { ...DRAFT, uid: 400 }),
      logoutExchange("a6"),
    ]);

    expectDraftRefusal(answer, "changed-since-preview", [
      "refusal",
      "reason",
      "changedIds",
      "guarantee",
    ]);
    expect(lines).toEqual([...OPEN_AND_CHECK, "a6 LOGOUT"]);
    expect(lines.filter((line) => commandWord(line) === "SEARCH")).toEqual([]);
    expect(lines.filter((line) => line.includes("400"))).toEqual([]);
  });

  it("a changed UIDVALIDITY: not_found from the open's gate, with nothing after the open", async () => {
    const { answer, lines } = await previewThenCommit([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 3, DRAFTS_UIDVALIDITY + 1),
      logoutExchange("a5"),
    ]);

    expectCategory(answer, "not_found");
    expect(lines).toEqual([...SIGN_IN, 'a4 SELECT "Drafts"', "a5 LOGOUT"]);
  });

  it("an open that completes read-only: mailbox-read-only, nothing after the open", async () => {
    const { answer, lines } = await previewThenCommit([
      ...authPrefix(),
      selectResponse("a4", "[READ-ONLY]", 3, DRAFTS_UIDVALIDITY),
      logoutExchange("a5"),
    ]);

    expectDraftRefusal(answer, "mailbox-read-only", ["refusal", "reason", "guarantee"]);
    expect(lines).toEqual([...SIGN_IN, 'a4 SELECT "Drafts"', "a5 LOGOUT"]);
  });

  it.each([["UIDPLUS"], ["CONDSTORE"]])(
    "a capability line without %s: commands-unavailable, nothing after the open",
    async (missing) => {
      const capability = MEASURED_POST_AUTH_CAPABILITY.split(" ")
        .filter((atom) => atom !== missing)
        .join(" ");
      const { answer, lines } = await previewThenCommit([
        ...openReplies(capability),
        logoutExchange("a5"),
      ]);

      expectDraftRefusal(answer, "commands-unavailable", ["refusal", "reason", "guarantee"]);
      expect(lines).toEqual([...SIGN_IN, 'a4 SELECT "Drafts"', "a5 LOGOUT"]);
    },
  );

  it("permanent flags that do not keep the removal mark: removal-not-kept, nothing after the open", async () => {
    const { answer, lines } = await previewThenCommit([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 3, DRAFTS_UIDVALIDITY, "\\Answered \\Seen \\Draft \\*"),
      logoutExchange("a5"),
    ]);

    expectDraftRefusal(answer, "removal-not-kept", ["refusal", "reason", "guarantee"]);
    expect(lines).toEqual([...SIGN_IN, 'a4 SELECT "Drafts"', "a5 LOGOUT"]);
  });

  it("the copy refused: not_copied, and the line says nothing changed", async () => {
    const { answer, lines, id } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      wire("a6 NO [OVERQUOTA] COPY failed"),
      logoutExchange("a7"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({
      id,
      outcome: "not_copied",
      reason: "copy-refused",
      newId: null,
    });
    expect(parsed.confirmationLine).toBe(NOT_COPIED_LINE);
    expect(lines).toEqual([...OPEN_AND_CHECK, MOVE_LINES[0], "a7 LOGOUT"]);
  });

  it("the removal mark answered [MODIFIED]: copied_not_removed, changed-since-preview, no removal, and the line names both folders", async () => {
    const { answer, lines } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      wire(`a7 OK [MODIFIED ${DRAFT.uid}] Conditional STORE failed`),
      esearchCountReply("a8", 1),
      logoutExchange("a9"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({
      outcome: "copied_not_removed",
      reason: "changed-since-preview",
    });
    expect(decodeMessageId(parsed.results[0]!.newId!)).toEqual({
      mailbox: "Deleted Messages",
      uidValidity: TRASH_UIDVALIDITY,
      uid: 97,
    });
    expect(parsed.confirmationLine).toBe(COPIED_NOT_REMOVED_LINE);
    expect(lines).toEqual([
      ...OPEN_AND_CHECK,
      MOVE_LINES[0],
      MOVE_LINES[1],
      `a8 UID SEARCH RETURN (COUNT) UID ${DRAFT.uid}`,
      "a9 LOGOUT",
    ]);
    expect(lines.filter((line) => commandWord(line) === "EXPUNGE")).toEqual([]);
  });

  it("the removal refused: copied_not_removed, removal-refused, and the line names both folders", async () => {
    const { answer, lines } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      markEcho("a7", DRAFT.uid, "88121"),
      wire("a8 NO EXPUNGE failed"),
      esearchCountReply("a9", 1),
      logoutExchange("a10"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({
      outcome: "copied_not_removed",
      reason: "removal-refused",
    });
    expect(parsed.confirmationLine).toBe(COPIED_NOT_REMOVED_LINE);
    expect(lines).toEqual([...OPEN_AND_CHECK, ...MOVE_LINES, "a10 LOGOUT"]);
  });

  it("a connection lost after the copy was sent: unknown, connection-lost, per message, never connection_failed", async () => {
    const { answer, lines, id } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      // The script ends here, so the copy's reply never comes.
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toEqual({
      id,
      outcome: "unknown",
      reason: "connection-lost",
      newId: null,
      destination: parsed.results[0]!.destination,
    });
    expect(parsed.confirmationLine).toBe(UNKNOWN_LINE);
    expect(JSON.stringify(body(answer))).not.toContain("connection_failed");
    expect(lines).toEqual([...OPEN_AND_CHECK, MOVE_LINES[0], "a7 LOGOUT"]);
  });

  it("the re-read counts the draft still there: copied_not_removed, still-in-source", async () => {
    const { answer, lines } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      markEcho("a7", DRAFT.uid, "88121"),
      wire("a8 OK EXPUNGE completed"),
      esearchCountReply("a9", 1),
      logoutExchange("a10"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({
      outcome: "copied_not_removed",
      reason: "still-in-source",
    });
    expect(parsed.confirmationLine).toBe(COPIED_NOT_REMOVED_LINE);
    expect(lines).toEqual([...OPEN_AND_CHECK, ...MOVE_LINES, "a10 LOGOUT"]);
  });

  it.each<[string, Uint8Array, string]>([
    ["the re-read refused", wire("a9 NO SEARCH failed"), "verify-refused"],
    ["an OK with no count for its own tag", emptySearchReply("a9"), "verify-unanswered"],
  ])("%s: unknown, and never moved", async (_label, reread, reason) => {
    const { answer, lines } = await previewThenCommit([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      markEcho("a7", DRAFT.uid, "88121"),
      wire("a8 OK EXPUNGE completed"),
      reread,
      logoutExchange("a10"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({ outcome: "unknown", reason });
    expect(parsed.confirmationLine).toBe(UNKNOWN_LINE);
    expect(lines).toEqual([...OPEN_AND_CHECK, ...MOVE_LINES, "a10 LOGOUT"]);
  });

  it("a capability line without ESEARCH: no re-read is sent, and the answer is unknown, verify-unanswered", async () => {
    const withoutEsearch = MEASURED_POST_AUTH_CAPABILITY.split(" ")
      .filter((atom) => atom !== "ESEARCH")
      .join(" ");
    const { answer, lines } = await previewThenCommit([
      ...openReplies(withoutEsearch),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      markEcho("a7", DRAFT.uid, "88121"),
      wire("a8 OK EXPUNGE completed"),
      logoutExchange("a9"),
    ]);

    const parsed = expectApplied(answer);
    expect(parsed.results[0]).toMatchObject({ outcome: "unknown", reason: "verify-unanswered" });
    expect(parsed.confirmationLine).toBe(UNKNOWN_LINE);
    expect(lines).toEqual([...OPEN_AND_CHECK, ...MOVE_LINES.slice(0, 3), "a9 LOGOUT"]);
  });
});

// ---------------------------------------------------------------------------
// The call deadline, at the verb (22-01 Task 3)
//
// These drive `deleteDraftOver` directly over a fake duplex, so each case can
// set a short deadline the tool path never would.
// ---------------------------------------------------------------------------

/** The target a verified draft-delete confirmation decodes to. */
const TARGET = {
  draftsMailbox: "Drafts",
  uidValidity: DRAFTS_UIDVALIDITY,
  entry: {
    uid: DRAFT.uid,
    size: DRAFT.size,
    internalDate: INTERNAL_SECONDS,
    modSeq: DRAFT.modSeq,
  },
  trashMailbox: "Deleted Messages",
};

async function runDelete(
  duplex: FakeDuplex,
  options: Record<string, number>,
): Promise<DraftDeleteOutcome> {
  return deleteDraftOver(duplex, await ownerPrincipal(), createSessionGate(), TARGET, options);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("the call deadline", () => {
  it("firing while the copy waits for its reply: the ledger's unknown, connection-lost, and nothing changing after it", async () => {
    const duplex = createStallingDuplex([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      // The copy's reply never comes, and the stream never ends.
    ]);

    const outcome = await runDelete(duplex, {
      readTimeoutMs: 400,
      drainTimeoutMs: 20,
      closeTimeoutMs: 20,
      callDeadlineMs: 120,
    });

    expect(outcome).toEqual({
      applied: true,
      result: {
        uid: DRAFT.uid,
        outcome: "unknown",
        reason: "connection-lost",
        newUid: null,
        destinationUidValidity: null,
      },
    });
    // Per message, and the answer's sentence is D-15's unknown line.
    expect(
      composeConfirmationLine({ kind: "draft", name: DRAFT.subject, outcome: "unknown" }, "did"),
    ).toBe(UNKNOWN_LINE);

    // Give any late continuation of the abandoned step time to act.
    await sleep(500);
    const lines = wireOf(duplex);
    expect(lines).toEqual([...OPEN_AND_CHECK, MOVE_LINES[0], "a7 LOGOUT"]);
    expect(lines.filter((line) => ["STORE", "EXPUNGE"].includes(commandWord(line)))).toEqual([]);
  });

  it("passing after a proven copy and before the mark: copied_not_removed, stopped-for-time, with the new id, and nothing after the copy but the logout", async () => {
    const duplex = createFakeDuplex([
      ...openReplies(),
      draftFingerprintReply("a5", DRAFT),
      copyReply("a6", DRAFT.uid, 97),
      logoutExchange("a7"),
    ]);
    // Time jumps past the deadline the moment the copy is written, and not
    // before: the step's own check after the proven copy must see it.
    const realNow = Date.now.bind(Date);
    const copied = (): boolean =>
      duplex.writtenLines().some((line) => commandWord(line) === "COPY");
    const now = vi.spyOn(Date, "now").mockImplementation(() =>
      copied() ? realNow() + 60_000 : realNow(),
    );

    let outcome: DraftDeleteOutcome;
    try {
      outcome = await runDelete(duplex, {
        readTimeoutMs: 400,
        drainTimeoutMs: 20,
        closeTimeoutMs: 20,
        callDeadlineMs: 5_000,
      });
    } finally {
      now.mockRestore();
    }

    expect(outcome).toEqual({
      applied: true,
      result: {
        uid: DRAFT.uid,
        outcome: "copied_not_removed",
        reason: "stopped-for-time",
        newUid: 97,
        destinationUidValidity: TRASH_UIDVALIDITY,
      },
    });
    expect(wireOf(duplex)).toEqual([...OPEN_AND_CHECK, MOVE_LINES[0], "a7 LOGOUT"]);
  });

  it("before the fingerprint re-read completes: the ordinary error, because nothing was changed", async () => {
    const duplex = createStallingDuplex([
      ...openReplies(),
      // The re-read's reply never comes.
    ]);

    await expect(
      runDelete(duplex, {
        readTimeoutMs: 400,
        drainTimeoutMs: 20,
        closeTimeoutMs: 20,
        callDeadlineMs: 120,
      }),
    ).rejects.toBeInstanceOf(ImapConnectError);

    await sleep(300);
    const lines = wireOf(duplex);
    expect(lines).toEqual([...OPEN_AND_CHECK, "a6 LOGOUT"]);
    expectNothingChanging(lines);
  });
});

// ---------------------------------------------------------------------------
// The mail commit refuses before the lease and before any socket
// ---------------------------------------------------------------------------

type StoredLease = { token: string; expiresAt: number };

async function seedLease(record: StoredLease): Promise<void> {
  const stub = env.USER_AGENT.getByName((await ownerPrincipal()).userId);
  await runInDurableObject(stub, (_instance, state) => {
    state.storage.kv.put("lease", record);
  });
}

async function clearLease(): Promise<void> {
  const stub = env.USER_AGENT.getByName((await ownerPrincipal()).userId);
  await runInDurableObject(stub, (_instance, state) => {
    state.storage.kv.delete("lease");
  });
}

/** A draft-delete change for the standard draft. */
function draftChange(id = draftId()) {
  return { op: "draft-delete" as const, id, subject: DRAFT.subject };
}

/** Mint a mail confirmation, draft-delete shaped unless a field is overridden. */
async function minted(overrides: {
  u?: string;
  k?: "delete" | "move";
  qr?: "trash" | "archive" | null;
  l?: MailSetEntry[];
  h?: string;
} = {}): Promise<{ confirmToken: string; jti: string; expiry: number }> {
  const actor = await ownerPrincipal();
  const jti = crypto.randomUUID();
  const expiry = Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS;
  const confirmToken = await mintConfirmation(
    {
      v: CONFIRM_VERSION,
      t: "mail",
      k: overrides.k ?? "delete",
      j: jti,
      m: encodeFolderId({ mailbox: "Drafts" }),
      uv: DRAFTS_UIDVALIDITY,
      q: encodeFolderId({ mailbox: "Deleted Messages" }),
      qr: overrides.qr === undefined ? "trash" : overrides.qr,
      l: overrides.l ?? [{ i: DRAFT.uid, z: DRAFT.size, d: INTERNAL_SECONDS, n: DRAFT.modSeq }],
      h: overrides.h ?? (await draftChangeHashOf(draftChange())),
      x: expiry,
      u: overrides.u ?? actor.userId,
    },
    env.CONFIRM_SECRET,
  );
  return { confirmToken, jti, expiry };
}

describe("the mail commit refuses a draft delete that does not match, before the lease", () => {
  const held: StoredLease = { token: "another-request", expiresAt: Date.now() + 600_000 };

  // With another request holding the lease, a check that ran AFTER the lease
  // would answer connection_busy. Each of these answers confirmation_invalid,
  // so each check ran first, and no socket opened.
  it.each<[string, () => Promise<{ confirmToken: string; change: unknown }>]>([
    [
      "a confirmation minted for another user",
      async () => ({
        confirmToken: (await minted({ u: "someone-else" })).confirmToken,
        change: draftChange(),
      }),
    ],
    [
      "a Phase 21 move token handed back with a draft-delete change",
      async () => ({
        confirmToken: (
          await minted({
            k: "move",
            qr: "trash",
            h: await mailMoveChangeHashOf({
              op: "move",
              ids: [draftId()],
              destination: encodeFolderId({ mailbox: "Deleted Messages" }),
            }),
          })
        ).confirmToken,
        change: draftChange(),
      }),
    ],
    [
      "a draft-delete token whose l has two entries",
      async () => ({
        confirmToken: (
          await minted({
            l: [
              { i: DRAFT.uid, z: DRAFT.size, d: INTERNAL_SECONDS, n: DRAFT.modSeq },
              { i: DRAFT.uid + 1, z: 10, d: INTERNAL_SECONDS, n: "5" },
            ],
          })
        ).confirmToken,
        change: draftChange(),
      }),
    ],
    [
      "a draft-delete token whose qr is not trash",
      async () => ({
        confirmToken: (await minted({ qr: "archive" })).confirmToken,
        change: draftChange(),
      }),
    ],
    [
      "a draft-delete token whose qr is null",
      async () => ({ confirmToken: (await minted({ qr: null })).confirmToken, change: draftChange() }),
    ],
    [
      "a change whose id decodes to another UID",
      async () => {
        const other = draftChange(draftId(DRAFT.uid + 1));
        return {
          confirmToken: (await minted({ h: await draftChangeHashOf(other) })).confirmToken,
          change: other,
        };
      },
    ],
    [
      "a change whose subject differs from the one sealed",
      async () => ({
        confirmToken: (await minted()).confirmToken,
        change: { ...draftChange(), subject: "Something else" },
      }),
    ],
  ])("%s: confirmation_invalid, no lease taken, no socket", async (_label, build) => {
    const { commit } = tools();
    const args = await build();
    await seedLease(held);
    try {
      const answer = seen(await commit(args as Record<string, unknown>));

      expectCategory(answer, "confirmation_invalid");
      expect(connectImap).not.toHaveBeenCalled();
    } finally {
      await clearLease();
    }
  });

  it("a spent confirmation: confirmation_invalid, no socket, and the lease given back", async () => {
    // The one-time slot is claimed inside the lease, so this refusal comes
    // after the lease is taken; it still opens nothing, and gives the lease back.
    const { commit } = tools();
    const { confirmToken, jti, expiry } = await minted();
    await reserveConfirmation(env.CONFIRM_KV, (await ownerPrincipal()).userId, jti, expiry);

    const answer = seen(await commit({ confirmToken, change: draftChange() }));

    expectCategory(answer, "confirmation_invalid");
    expect(connectImap).not.toHaveBeenCalled();
    expect(await readLease()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// What every answer carries, and what none may claim (DRFT-07)
// ---------------------------------------------------------------------------

describe("every draft answer carries the guarantee, and none claims more", () => {
  const STRONGER = /permanent|irrecoverabl|written by this server|this server wrote/i;

  it("the cases above produced answers to check", () => {
    expect(SEEN_ANSWERS.length).toBeGreaterThan(20);
  });

  it("every answer that is not an error carries the guarantee word for word", () => {
    for (const answer of SEEN_ANSWERS.filter((one) => one.isError === undefined)) {
      expect(body(answer).guarantee, answer.content[0]!.text).toBe(DRAFT_GUARANTEE);
    }
  });

  it("no answer, and neither description, says the delete is final or that this server wrote the draft", () => {
    const { descriptions } = tools();
    for (const name of ["mail_delete_draft", "mail_commit"]) {
      expect(descriptions.get(name), name).not.toMatch(STRONGER);
    }
    for (const answer of SEEN_ANSWERS) {
      for (const block of answer.content) expect(block.text).not.toMatch(STRONGER);
    }
  });
});
