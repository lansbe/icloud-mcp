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
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { createLeasedMail } from "../src/agent/lease";
import { LEASE_TTL_MS } from "../src/agent/user-agent";
import type { UserAgent } from "../src/agent/user-agent";
import { ConnectionBusyError, ImapConnectError, SAFE_MESSAGES } from "../src/errors";
import { CLOSE_TIMEOUT_MS, DRAIN_TIMEOUT_MS } from "../src/mail/imap-session";
import { CALL_DEADLINE_MS, createSessionGate } from "../src/mail/service";
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
  registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), principal);
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

/**
 * Make one RPC method of the object class throw, for the next call.
 *
 * The spy sits on the PROTOTYPE of the live instance, read through
 * `runInDurableObject`. A spy on the instance itself does not work in this pool
 * version: it puts a function on the instance as an own property, and the RPC
 * layer then refuses the call with "The RPC receiver does not implement the
 * method", which is not the failure being tested and left the object unable to
 * evict. `vi.restoreAllMocks()` in the `afterEach` below takes the spy off.
 */
function breakMethod(userId: string, method: "acquire" | "release"): Promise<void> {
  return runInDurableObject(objectFor(userId), (instance: UserAgent) => {
    const prototype = Object.getPrototypeOf(instance) as UserAgent;
    vi.spyOn(prototype, method).mockImplementation(() => {
      throw new Error("the object could not answer");
    });
  });
}

describe("the lease (DOBJ-02, DOBJ-03)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("lasts the call deadline plus drain plus close plus a 5 000 ms margin, which is 30 000", () => {
    expect(LEASE_TTL_MS).toBe(CALL_DEADLINE_MS + DRAIN_TIMEOUT_MS + CLOSE_TIMEOUT_MS + 5000);
    expect(LEASE_TTL_MS).toBe(30000);
  });

  it("stores an absolute expiry LEASE_TTL_MS after the grant", async () => {
    const before = Date.now();
    const answer = await objectFor(OWNER_ID).acquire();
    expect(answer.held).toBe(true);

    const stored = await readLease(OWNER_ID);
    expect(stored).toBeDefined();
    expect(stored!.token).toBe((answer as { token: string }).token);
    const lifetime = stored!.expiresAt - before;
    expect(lifetime).toBeGreaterThanOrEqual(LEASE_TTL_MS - 2000);
    expect(lifetime).toBeLessThanOrEqual(LEASE_TTL_MS + 2000);
  });

  it("refuses a second acquire while held, and leaves the record identical", async () => {
    const first = await objectFor(OWNER_ID).acquire();
    expect(first.held).toBe(true);
    const stored = await readLease(OWNER_ID);

    const second = await objectFor(OWNER_ID).acquire();

    expect(second).toEqual({ held: false });
    expect(await readLease(OWNER_ID)).toEqual(stored);
  });

  it("replaces an expired record with a new grant and a new token", async () => {
    const expired: StoredLease = { token: "expired-holder", expiresAt: Date.now() - 1 };
    await seedLease(OWNER_ID, expired);

    const answer = await objectFor(OWNER_ID).acquire();

    expect(answer.held).toBe(true);
    const token = (answer as { token: string }).token;
    expect(token).not.toBe(expired.token);
    expect((await readLease(OWNER_ID))!.token).toBe(token);
  });

  it("ignores a release with the expired holder's old token once the lease was re-granted", async () => {
    await seedLease(OWNER_ID, { token: "expired-holder", expiresAt: Date.now() - 1 });
    const answer = await objectFor(OWNER_ID).acquire();
    const current = await readLease(OWNER_ID);

    await objectFor(OWNER_ID).release("expired-holder");

    expect(answer.held).toBe(true);
    expect(await readLease(OWNER_ID)).toEqual(current);
  });

  it("changes nothing, and does not throw, on a release with anything but the holder's token", async () => {
    await objectFor(OWNER_ID).acquire();
    const current = await readLease(OWNER_ID);

    const wrong: unknown[] = ["not-the-token", 42, undefined, null, { token: current!.token }];
    for (const value of wrong) {
      await expect(objectFor(OWNER_ID).release(value)).resolves.toBeUndefined();
      expect(await readLease(OWNER_ID)).toEqual(current);
    }
  });

  it("deletes the record on the holder's own token, and the next acquire grants", async () => {
    const answer = await objectFor(OWNER_ID).acquire();
    const token = (answer as { token: string }).token;

    await objectFor(OWNER_ID).release(token);

    expect(await readLease(OWNER_ID)).toBeUndefined();
    const next = await objectFor(OWNER_ID).acquire();
    expect(next.held).toBe(true);
  });

  it("survives eviction: a held lease is still held after the object is evicted", async () => {
    const answer = await objectFor(OWNER_ID).acquire();
    expect(answer.held).toBe(true);

    await evictDurableObject(objectFor(OWNER_ID));

    expect(await objectFor(OWNER_ID).acquire()).toEqual({ held: false });
  });

  it("refuses with the floor category, and never runs the work, when the object cannot answer", async () => {
    const principal = await ownerPrincipal();
    await breakMethod(principal.userId, "acquire");
    const fn = vi.fn(async () => "ran");

    const call = createLeasedMail(createSessionGate()).withConnectionLease(principal, fn);

    await expect(call).rejects.toBeInstanceOf(ImapConnectError);
    expect(fn).not.toHaveBeenCalled();
  });

  it("still answers with the work's value when the release fails", async () => {
    const principal = await ownerPrincipal();
    await breakMethod(principal.userId, "release");

    const value = await createLeasedMail(createSessionGate()).withConnectionLease(
      principal,
      async () => "the work's value",
    );

    expect(value).toBe("the work's value");
    // The record is still there, which proves the release really failed rather
    // than the spy missing it. The expiry is what frees it now.
    const left = await readLease(principal.userId);
    expect(typeof left?.token).toBe("string");
  });

  it("frees the lease when the work fails, and passes the same error on", async () => {
    const principal = await ownerPrincipal();
    const failure = new Error("the work failed");

    const call = createLeasedMail(createSessionGate()).withConnectionLease(principal, async () => {
      throw failure;
    });

    await expect(call).rejects.toBe(failure);
    expect(await readLease(principal.userId)).toBeUndefined();
  });

  it("never runs the work when the lease is held", async () => {
    const principal = await ownerPrincipal();
    await seedLease(principal.userId, { token: "held", expiresAt: Date.now() + 60000 });
    const fn = vi.fn(async () => "ran");

    const call = createLeasedMail(createSessionGate()).withConnectionLease(principal, fn);

    await expect(call).rejects.toBeInstanceOf(ConnectionBusyError);
    expect(fn).not.toHaveBeenCalled();
  });
});
