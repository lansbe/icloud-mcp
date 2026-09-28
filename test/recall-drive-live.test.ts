// The real recall step after a real tool call (Phase 26, RCLL-08; D-26, D-29,
// D-35).
//
// Everything here is real except the socket: the real server factory, the real
// seam, the real step, the real person's object and the real connection lease.
// The socket module is mocked for this file only and hands out scripted
// conversations, so nothing signs in to a real Apple ID.
//
// ORDER IS ASSERTED ON THE WIRE, never by the lease record's absence. The
// tool's own session must have sent its logout before the step's socket
// opens. That holds whether the lease release is awaited (strict) or fired and
// forgotten (SPIKE-11's advisory alternative), so every case here holds under
// either verdict.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { AUTONOMY_CLIENT_ID } from "../src/agent/autonomy-client";
import { ensureRecallSchema, utcDay, writeState } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { connectImap } from "../src/mail/socket";
import { createServerFactory } from "../src/mcp/server";
import {
  guardAgainstPause,
  PASSWORD_PAUSE_KEY_PREFIX,
  PASSWORD_PAUSE_SECONDS,
} from "../src/password-pause";
import type { Principal } from "../src/principal";
import { RECALL_MAX_PAGES_PER_DAY } from "../src/recall/retention";
import { McpServer } from "@modelcontextprotocol/server";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

type Answer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>, extra?: unknown) => Promise<Answer>;

/** An ordinary client id: anything that is not the autonomy client. */
const ORDINARY = "ordinary-client";

/** The archive folder the listing marks with the archive role. */
const ARCHIVE = "Archive";

// ---------------------------------------------------------------------------
// The person's object
// ---------------------------------------------------------------------------

type StoredLease = { token: string; expiresAt: number };

async function ownerObject() {
  return env.USER_AGENT.getByName((await ownerPrincipal()).userId);
}

/** A fresh person: no recall tables, no stored name, no lease. */
async function resetOwner(): Promise<void> {
  await runInDurableObject(await ownerObject(), (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    state.storage.kv.delete("lease");
  });
}

async function readLease(): Promise<StoredLease | undefined> {
  return runInDurableObject(await ownerObject(), (_instance, state) =>
    state.storage.kv.get<StoredLease>("lease"),
  );
}

/** The stored folder list, read straight from the object's own state. */
async function storedFolders(): Promise<string[] | null> {
  return (await (await ownerObject()).recallSyncState()).folders;
}

/** Every recall state row, for a before-and-after compare. */
async function recallRows(): Promise<string[]> {
  return runInDurableObject(await ownerObject(), (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    return state.storage.sql
      .exec<{ k: string; v: string }>("select k, v from recall_state order by k")
      .toArray()
      .map((row) => `${row.k}=${row.v}`);
  });
}

/** Count every call the object's slot read receives, through its prototype. */
async function countSlotReads() {
  return runInDurableObject(await ownerObject(), (instance: UserAgent) => {
    const prototype = Object.getPrototypeOf(instance) as UserAgent;
    return vi.spyOn(prototype, "recallSyncState");
  });
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

/**
 * A folder listing session: sign in, list INBOX, a sent folder and an archive
 * folder with its role, and log out.
 */
function listingSession(): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 172 UNSEEN 4)',
      '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
      '* STATUS "Sent Messages" (MESSAGES 40 UNSEEN 0)',
      `* LIST (\\HasNoChildren \\Archive) "/" "${ARCHIVE}"`,
      `* STATUS "${ARCHIVE}" (MESSAGES 900 UNSEEN 0)`,
      "a4 OK LIST completed",
    ),
    logoutExchange("a5"),
  ]);
}

function sentLogout(duplex: FakeDuplex): boolean {
  return duplex.writtenLines().some((line) => /^a\d+ LOGOUT$/.test(line));
}

// ---------------------------------------------------------------------------
// The real factory
// ---------------------------------------------------------------------------

/** One tool from the real factory, built with this grant reader. */
function realTool(
  name: string,
  grantClient: () => Promise<string | null>,
  principal: Promise<Principal> = ownerPrincipal(),
): Callback {
  const spy = vi.spyOn(McpServer.prototype, "registerTool");
  try {
    createServerFactory(principal, [], grantClient)({ era: "modern" } as never);
    const found = (spy.mock.calls as unknown as [string, unknown, Callback][]).find(
      ([registered]) => registered === name,
    );
    expect(found, `${name} is not registered`).toBeDefined();
    return found![2];
  } finally {
    spy.mockRestore();
  }
}

/** The key the pause marker lives under for the owner. */
async function pauseKey(): Promise<string> {
  return `${PASSWORD_PAUSE_KEY_PREFIX}${(await ownerPrincipal()).userId}`;
}

beforeEach(async () => {
  vi.mocked(connectImap).mockReset();
  await resetOwner();
});

afterEach(async () => {
  vi.restoreAllMocks();
  await env.OAUTH_KV.delete(await pauseKey());
  await resetOwner();
});

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

describe("one successful mail call moves a fresh person's build by one step (D-26)", () => {
  it("two sockets, in order; the step lists the folders; the answer is the one a null reader gets", async () => {
    // The answer from a factory that runs no step, for the compare. It opens
    // exactly one socket: the default-null reader runs nothing.
    const alone = listingSession();
    vi.mocked(connectImap).mockReturnValueOnce(alone as never);
    const baseline = await realTool("mail_list_folders", async () => null)({});
    expect(baseline.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(await storedFolders()).toBeNull();
    vi.mocked(connectImap).mockReset();

    // Now the driven call. The second socket records whether the tool's own
    // session had already logged out at the moment it was opened.
    const toolSession = listingSession();
    const stepSession = listingSession();
    let toolHadLoggedOut: boolean | null = null;
    vi.mocked(connectImap)
      .mockImplementationOnce(() => toolSession as never)
      .mockImplementationOnce(() => {
        toolHadLoggedOut = sentLogout(toolSession);
        return stepSession as never;
      });

    const answer = await realTool("mail_list_folders", async () => ORDINARY)({});

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(toolHadLoggedOut).toBe(true);
    // The second session is the step's folder listing.
    expect(stepSession.writtenLines().some((line) => /^a4 LIST /.test(line))).toBe(true);
    expect(sentLogout(stepSession)).toBe(true);
    // The object holds the build's folders: INBOX, then the archive folder.
    expect(await storedFolders()).toEqual(["INBOX", ARCHIVE]);
    // The answer is untouched by the step.
    expect(answer.isError).toBeUndefined();
    expect(answer.content[0]!.text).toBe(baseline.content[0]!.text);
  });
});

describe("the step stops silently, and the answer is unchanged (D-29)", () => {
  it("lease taken by another request between the tool's session and the step: lease busy, one socket", async () => {
    // Another request takes the lease the moment the tool's session gives it
    // back: the object's release, for this one call, writes that request's
    // record instead of freeing the lease. The step's acquire then runs the
    // object's own, unmodified logic and finds the lease held.
    const other = { token: "another-request", expiresAt: Date.now() + 60000 };
    await runInDurableObject(await ownerObject(), (instance: UserAgent) => {
      const prototype = Object.getPrototypeOf(instance) as UserAgent;
      vi.spyOn(prototype, "release").mockImplementationOnce(function (this: UserAgent) {
        (this as unknown as { ctx: DurableObjectState }).ctx.storage.kv.put("lease", other);
      });
    });
    vi.mocked(connectImap).mockReturnValueOnce(listingSession() as never);

    const answer = await realTool("mail_list_folders", async () => ORDINARY)({});

    expect(answer.isError).toBeUndefined();
    expect(JSON.parse(answer.content[0]!.text)).not.toHaveProperty("category");
    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(await readLease()).toEqual(other);
    expect(await storedFolders()).toBeNull();
  });

  it("the day's page count at the cap: one socket, nothing stored", async () => {
    await runInDurableObject(await ownerObject(), (_instance, state) => {
      ensureRecallSchema(state.storage.sql);
      writeState(state.storage.sql, "pages_day", utcDay(Date.now()));
      writeState(state.storage.sql, "pages_count", String(RECALL_MAX_PAGES_PER_DAY));
    });
    const before = await recallRows();
    vi.mocked(connectImap).mockReturnValueOnce(listingSession() as never);

    const answer = await realTool("mail_list_folders", async () => ORDINARY)({});

    expect(answer.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
    // The slot read may remember the object's own name; nothing of the build
    // was stored.
    expect(await storedFolders()).toBeNull();
    expect((await recallRows()).filter((row) => !before.includes(row))).toEqual([]);
  });
});

describe("no step on the autonomy grant, or after a refusal (D-28, D-35)", () => {
  it("the grant reader answers the autonomy client: one socket, and the slot is never read", async () => {
    const slotReads = await countSlotReads();
    vi.mocked(connectImap).mockReturnValueOnce(listingSession() as never);

    const answer = await realTool("mail_list_folders", async () => AUTONOMY_CLIENT_ID)({});

    expect(answer.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(slotReads).not.toHaveBeenCalled();
  });

  it("a positive control: an ordinary client's step does read the slot", async () => {
    const slotReads = await countSlotReads();
    vi.mocked(connectImap)
      .mockReturnValueOnce(listingSession() as never)
      .mockReturnValueOnce(listingSession() as never);

    await realTool("mail_list_folders", async () => ORDINARY)({});

    expect(slotReads).toHaveBeenCalledTimes(1);
  });

  it("a paused person: the tool refuses as before, and the slot is never read", async () => {
    await env.OAUTH_KV.put(await pauseKey(), "1", { expirationTtl: PASSWORD_PAUSE_SECONDS });
    const slotReads = await countSlotReads();
    const paused = guardAgainstPause(ownerPrincipal(), env.OAUTH_KV);
    paused.catch(() => {});

    const answer = await realTool("mail_list_folders", async () => ORDINARY, paused)({});

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text).category).toBe("auth_failed");
    expect(connectImap).not.toHaveBeenCalled();
    expect(slotReads).not.toHaveBeenCalled();
  });
});
