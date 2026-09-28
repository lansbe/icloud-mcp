// A recall result that no longer opens is removed at once (Phase 26, RCLL-08,
// ARCHITECTURE §4.6(a)).
//
// `mail_get_message` is driven through its real registered callback. The socket
// module is mocked for this file only, so the read's own connect step hands back
// an in-memory duplex: nothing here opens a network connection or signs in to a
// real Apple ID. The person's object is the REAL `UserAgent` in the pool.
//
// Two more seams, both scoped to this file by `vi.mock`:
// - `recallDeps` answers the fake store and embedder of the case running, so the
//   tool's own default reaches the fakes. The pool cannot reach either binding
//   for real (vitest.config.ts says why).
// - `agentFor` is wrapped, and still answers the real object unless a case asks
//   for a failing one. The tool's lease reaches the object from inside the lease
//   module, so the wrapper sees only the calls made from outside it: the
//   dead-ref check and the removal.

import type { McpServer } from "@modelcontextprotocol/server";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

const current: { deps: RecallDeps | null } = { deps: null };

vi.mock("../src/recall/pipeline", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/recall/pipeline")>()),
  recallDeps: vi.fn(() => {
    if (current.deps === null) throw new Error("no fake recall deps for this case");
    return current.deps;
  }),
}));

vi.mock("../src/agent/lease", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/agent/lease")>();
  return { ...real, agentFor: vi.fn(real.agentFor) };
});

import { agentFor, createLeasedMail } from "../src/agent/lease";
import { ensureRecallSchema } from "../src/agent/recall-ledger";
import type { UserAgent } from "../src/agent/user-agent";
import { ImapNotFoundError } from "../src/errors";
import { encodeMessageId, type MessageRef } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { mailErrorResult, registerMailTools } from "../src/mcp/tools/mail";
import type { Principal } from "../src/principal";
import { forgetDeadRef } from "../src/recall/dead-ref";
import { createEmbedder } from "../src/recall/embed";
import { vectorIdOf } from "../src/recall/ids";
import { createRecallStore } from "../src/recall/index";
import { indexItems, type RecallDeps } from "../src/recall/pipeline";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { createFakeAi } from "./fixtures/fake-embedder";
import { createFakeDuplex, type FakeDuplex } from "./fixtures/fake-duplex";
import { createFakeVectorize, type FakeVectorize } from "./fixtures/fake-vectorize";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type GetCallback = (args: { id: string; includeHtml?: boolean }) => Promise<ToolAnswer>;

const DAY_MS = 24 * 60 * 60 * 1000;
const UID = 42;
const REF: MessageRef = { mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid: UID };

/** The callback the mail tools register for `mail_get_message`. */
function getMessageCallback(): GetCallback {
  let callback: GetCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: GetCallback) {
      if (name === "mail_get_message") callback = handler;
    },
  };
  registerMailTools(
    server as unknown as McpServer,
    createLeasedMail(createSessionGate()),
    ownerPrincipal(),
  );
  expect(callback, "mail_get_message is not registered").toBeDefined();
  return callback!;
}

function objectFor(principal: Principal): DurableObjectStub<UserAgent> {
  return env.USER_AGENT.getByName(principal.userId);
}

/** Drop the recall tables, the stored name and the lease. */
function resetObject(principal: Principal) {
  return runInDurableObject(objectFor(principal), (_instance, state) => {
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_vectors");
    state.storage.sql.exec("DROP TABLE IF EXISTS recall_state");
    state.storage.kv.delete("own-name");
    state.storage.kv.delete("lease");
  });
}

/** Whether the person's ledger holds `id`, read inside the object. */
function ledgerHolds(principal: Principal, id: string): Promise<boolean> {
  return runInDurableObject(objectFor(principal), (_instance, state) => {
    ensureRecallSchema(state.storage.sql);
    const row = state.storage.sql
      .exec<{ n: number }>("select count(*) as n from recall_vectors where vector_id = ?", id)
      .one();
    return row.n > 0;
  });
}

interface Fakes {
  index: FakeVectorize;
  deps: RecallDeps;
}

function fakes(): Fakes {
  const index = createFakeVectorize();
  return { index, deps: { store: createRecallStore(index), embedder: createEmbedder(createFakeAi()) } };
}

/** Index `ref` for the owner, then clear the store's call record. */
async function indexed(principal: Principal, f: Fakes, ref: MessageRef): Promise<string> {
  const count = await indexItems(
    principal,
    [{ ref, text: "Offer letter for the staff role", snippet: "Offer", messageDate: Date.now() - DAY_MS }],
    f.deps,
  );
  expect(count).toBe(1);
  const id = await vectorIdOf(principal, encodeMessageId(ref));
  expect(await ledgerHolds(principal, id)).toBe(true);
  expect(f.index.vectors.has(id)).toBe(true);
  f.index.calls.length = 0;
  return id;
}

/** Sign in, open the inbox read-only, and find nothing for the fetch. */
function serverWithoutTheMessage(): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4"),
    taggedOk("a5", "UID FETCH completed"),
    logoutExchange("a6"),
  ]);
}

/** Sign in, and open the inbox under a DIFFERENT validity: the gate refuses. */
function serverWithNewValidity(): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4", 172, INBOX_UIDVALIDITY + 1),
    logoutExchange("a5"),
  ]);
}

/** A small plain-text message, whole. */
const RAW = "From: Jane <jane@example.invalid>\r\nSubject: Hello\r\n\r\nHello there.\r\n";
const RAW_BYTES = new TextEncoder().encode(RAW).byteLength;

/** Sign in, open the inbox, and answer the message in full. */
function serverWithTheMessage(): FakeDuplex {
  const structure = `("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 14 1 NIL NIL NIL NIL)`;
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4"),
    wire(
      `* 1 FETCH (UID ${UID} FLAGS (\\Seen) INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
        `RFC822.SIZE ${RAW_BYTES} BODYSTRUCTURE ${structure})`,
      "a5 OK UID FETCH completed",
    ),
    new TextEncoder().encode(
      `* 1 FETCH (UID ${UID} BODY[] {${RAW_BYTES}}\r\n${RAW})\r\na6 OK UID FETCH completed\r\n`,
    ),
    logoutExchange("a7"),
  ]);
}

/** The answer a not-found read gives, built by the tool's own error shaper. */
const NOT_FOUND = mailErrorResult(new ImapNotFoundError());

let principal: Principal;

beforeEach(async () => {
  principal = await ownerPrincipal();
  await resetObject(principal);
  vi.mocked(connectImap).mockReset();
  vi.mocked(agentFor).mockClear();
  current.deps = null;
});

afterEach(() => {
  current.deps = null;
});

describe("mail_get_message removes a recall result that no longer opens", () => {
  it("removes the vector from the store and the ledger, and answers exactly the not-found answer", async () => {
    const f = fakes();
    current.deps = f.deps;
    const id = await indexed(principal, f, REF);
    vi.mocked(connectImap).mockReturnValue(serverWithoutTheMessage() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer).toEqual(NOT_FOUND);
    const deletes = f.index.calls.filter((call) => call.method === "deleteByIds");
    expect(deletes).toHaveLength(1);
    expect(deletes[0]!.args[0]).toEqual([id]);
    expect(f.index.vectors.has(id)).toBe(false);
    expect(await ledgerHolds(principal, id)).toBe(false);
  });

  it("removes it too when the mailbox's validity changed and the read is refused", async () => {
    const f = fakes();
    current.deps = f.deps;
    const id = await indexed(principal, f, REF);
    vi.mocked(connectImap).mockReturnValue(serverWithNewValidity() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer).toEqual(NOT_FOUND);
    expect(f.index.vectors.has(id)).toBe(false);
    expect(await ledgerHolds(principal, id)).toBe(false);
  });

  it("gives the same answer for a message that was never indexed, and makes no store call", async () => {
    const f = fakes();
    current.deps = f.deps;
    vi.mocked(connectImap).mockReturnValue(serverWithoutTheMessage() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer).toEqual(NOT_FOUND);
    expect(f.index.calls).toEqual([]);
    // Non-vacuous: the dead-ref check did ask the object.
    expect(agentFor).toHaveBeenCalled();
  });

  it("answers the same when the ledger check fails, and throws nothing", async () => {
    const f = fakes();
    current.deps = f.deps;
    const id = await indexed(principal, f, REF);
    vi.mocked(agentFor).mockImplementationOnce(
      () =>
        ({
          recallHolds: () => Promise.reject(new Error("object unreachable")),
        }) as never,
    );
    vi.mocked(connectImap).mockReturnValue(serverWithoutTheMessage() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer).toEqual(NOT_FOUND);
    expect(f.index.calls).toEqual([]);
    // Nothing was removed: the next sync finds it.
    expect(f.index.vectors.has(id)).toBe(true);
    expect(await ledgerHolds(principal, id)).toBe(true);
  });

  it("answers the same when the store delete fails, and throws nothing", async () => {
    const f = fakes();
    current.deps = f.deps;
    const id = await indexed(principal, f, REF);
    f.index.failing.add("deleteByIds");
    vi.mocked(connectImap).mockReturnValue(serverWithoutTheMessage() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer).toEqual(NOT_FOUND);
    // The store delete was tried and failed, so the ledger still holds the id:
    // the ledger stays a superset of the store.
    expect(f.index.calls.filter((call) => call.method === "deleteByIds")).toHaveLength(1);
    expect(await ledgerHolds(principal, id)).toBe(true);
  });

  it("makes no object call and no store call for an id that does not decode", async () => {
    const f = fakes();
    current.deps = f.deps;

    const answer = await getMessageCallback()({ id: "not-a-message-id" });

    expect(answer.isError).toBe(true);
    expect(answer).toEqual(NOT_FOUND);
    expect(connectImap).not.toHaveBeenCalled();
    expect(agentFor).not.toHaveBeenCalled();
    expect(f.index.calls).toEqual([]);
  });

  it("makes no object call and no store call when the message opens", async () => {
    const f = fakes();
    current.deps = f.deps;
    const id = await indexed(principal, f, REF);
    vi.mocked(agentFor).mockClear();
    vi.mocked(connectImap).mockReturnValue(serverWithTheMessage() as never);

    const answer = await getMessageCallback()({ id: encodeMessageId(REF) });

    expect(answer.isError).toBeUndefined();
    expect(agentFor).not.toHaveBeenCalled();
    expect(f.index.calls).toEqual([]);
    expect(await ledgerHolds(principal, id)).toBe(true);
  });
});

describe("forgetDeadRef on its own", () => {
  it("never throws, even when the fake deps cannot be built", async () => {
    const f = fakes();
    await indexed(principal, f, REF);
    await expect(
      forgetDeadRef(principal, REF, () => {
        throw new Error("no deps");
      }),
    ).resolves.toBeUndefined();
  });

  it("builds no deps at all when the index does not hold the message", async () => {
    let built = 0;
    await forgetDeadRef(principal, REF, () => {
      built += 1;
      return fakes().deps;
    });
    expect(built).toBe(0);
  });
});

describe("recallHolds answers only the held subset of what it was asked", () => {
  it("returns only the ids it holds", async () => {
    const f = fakes();
    const held = await indexed(principal, f, REF);
    const notHeld = await vectorIdOf(principal, encodeMessageId({ ...REF, uid: UID + 1 }));

    expect(await objectFor(principal).recallHolds([notHeld, held])).toEqual([held]);
    expect(await objectFor(principal).recallHolds([notHeld])).toEqual([]);
  });

  it("ignores anything that is not 64 lower-case hex", async () => {
    const f = fakes();
    const held = await indexed(principal, f, REF);

    expect(
      await objectFor(principal).recallHolds([
        held.toUpperCase(),
        held.slice(1),
        `${held}0`,
        42,
        null,
        { id: held },
      ]),
    ).toEqual([]);
    expect(await objectFor(principal).recallHolds("not an array")).toEqual([]);
    // Non-vacuous: the same id in its real shape is held.
    expect(await objectFor(principal).recallHolds([held])).toEqual([held]);
  });

  it("reads at most 1000 entries", async () => {
    const f = fakes();
    const held = await indexed(principal, f, REF);
    const filler = "0".repeat(64);

    const beyond = [...Array.from({ length: 1000 }, () => filler), held];
    expect(await objectFor(principal).recallHolds(beyond)).toEqual([]);

    const within = [...Array.from({ length: 999 }, () => filler), held];
    expect(await objectFor(principal).recallHolds(within)).toEqual([held]);
  });
});
