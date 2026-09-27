// The per-person connection lease (Phase 24, DOBJ-01, DOBJ-02, DOBJ-03).
//
// Everything here runs against the REAL Durable Object in the pool: the class
// exported from src/index.ts, bound as USER_AGENT in wrangler.jsonc, with its
// storage read and seeded through `runInDurableObject`. Nothing about the
// object is mocked.
//
// The socket module IS mocked, for this file only, exactly as
// test/mark-read-tool.test.ts does it, so a leased tool's own connect step
// hands back an in-memory duplex. Nothing here opens a network connection and
// nothing signs in to a real Apple ID. `vi.mock` is scoped to the file it sits
// in, which is why this is its own file.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { createLeasedMail } from "../src/agent/lease";
import { SAFE_MESSAGES } from "../src/errors";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { registerMailTools } from "../src/mcp/tools/mail";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type NoArgCallback = () => Promise<ToolAnswer>;

/** The lease record as the object stores it. */
type StoredLease = { token: string; expiresAt: number };

/** The callback the mail tools register for `mail_list_folders`. */
function listFoldersCallback(principal: Promise<Principal>): NoArgCallback {
  let callback: NoArgCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: NoArgCallback) {
      if (name === "mail_list_folders") callback = handler;
    },
  };
  registerMailTools(server as unknown as McpServer, createSessionGate(), principal);
  expect(callback, "mail_list_folders is not registered").toBeDefined();
  return callback!;
}

/**
 * A server that signs in and answers the folder listing. The listing is tag
 * `a4`, copied from test/read-path-wire.test.ts's `folderListing`.
 */
function folderListingServer() {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    wire(
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 172 UNSEEN 4)',
      '* LIST (\\HasNoChildren) "/" "Drafts"',
      '* STATUS "Drafts" (MESSAGES 3 UNSEEN 0)',
      "a4 OK LIST completed",
    ),
    logoutExchange("a5"),
  ]);
}

/** The person's object, reached the way the tests may: by the user id. */
function objectFor(userId: string) {
  return env.USER_AGENT.getByName(userId);
}

/** The stored lease record for this user id, or undefined. */
function readLease(userId: string): Promise<StoredLease | undefined> {
  return runInDurableObject(objectFor(userId), (_instance, state) =>
    state.storage.kv.get<StoredLease>("lease"),
  );
}

/** Store `record` as this user id's lease, bypassing the object's own logic. */
function seedLease(userId: string, record: StoredLease): Promise<void> {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    state.storage.kv.put("lease", record);
  });
}

/** Remove any lease this user id holds. */
function clearLease(userId: string): Promise<void> {
  return runInDurableObject(objectFor(userId), (_instance, state) => {
    state.storage.kv.delete("lease");
  });
}

let OWNER_ID = "";

beforeEach(async () => {
  vi.mocked(connectImap).mockReset();
  OWNER_ID = (await ownerPrincipal()).userId;
  // Storage may persist between cases in one file; start every case free.
  for (const id of [OWNER_ID, USER_A.userId, USER_B.userId]) await clearLease(id);
});

describe("mail_list_folders takes the per-person lease (tracer)", () => {
  it("runs when the lease is free, and leaves no lease behind", async () => {
    vi.mocked(connectImap).mockReturnValue(folderListingServer() as never);

    const answer = await listFoldersCallback(ownerPrincipal())();

    expect(answer.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
    const body = JSON.parse(answer.content[0]!.text) as { folders: unknown[] };
    expect(body.folders).toHaveLength(2);
    expect(await readLease(OWNER_ID)).toBeUndefined();
  });

  it("is refused with connection_busy, opens no socket, and leaves the holder's record alone", async () => {
    const held: StoredLease = {
      token: "held-by-another-request",
      expiresAt: Date.now() + 60000,
    };
    await seedLease(OWNER_ID, held);

    const answer = await listFoldersCallback(ownerPrincipal())();

    expect(answer.isError).toBe(true);
    expect(JSON.parse(answer.content[0]!.text)).toEqual({
      category: "connection_busy",
      message: SAFE_MESSAGES.connection_busy,
    });
    expect(connectImap).toHaveBeenCalledTimes(0);
    expect(await readLease(OWNER_ID)).toEqual(held);
  });

  it("keeps two people apart: A's held lease never refuses B", async () => {
    const held: StoredLease = {
      token: "held-by-a",
      expiresAt: Date.now() + 60000,
    };
    await seedLease(USER_A.userId, held);
    vi.mocked(connectImap).mockReturnValue(folderListingServer() as never);

    const answer = await listFoldersCallback(testPrincipal(USER_B))();

    expect(answer.isError).toBeUndefined();
    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(await readLease(USER_A.userId)).toEqual(held);
    expect(await readLease(USER_B.userId)).toBeUndefined();
  });

  it("holds a record with a string token while the work runs, and none after", async () => {
    const principal = await ownerPrincipal();
    const leased = createLeasedMail(createSessionGate());
    let during: StoredLease | undefined;

    const value = await leased.withConnectionLease(principal, async () => {
      during = await readLease(principal.userId);
      return "done";
    });

    expect(value).toBe("done");
    expect(typeof during?.token).toBe("string");
    expect(during!.token.length).toBeGreaterThan(0);
    expect(await readLease(principal.userId)).toBeUndefined();
  });
});
