// The mark-read TOOL, driven from its registered callback down to the bytes.
//
// test/triage.test.ts proves each verb writes the right flag change. It calls
// the verbs directly, so it cannot see the one line in the tool that picks a
// verb from the caller's `read` boolean. A swapped choice there, or the same
// verb on both sides, would mark mail the opposite way from what the user asked
// and leave that file green. This file closes that gap (WR-04): it invokes the
// callback the tool module registers, and reads the flag change off the
// recorded command line.
//
// The socket module is mocked for this file only, so the verb's own connect
// step hands back an in-memory duplex. Nothing here opens a network connection
// and nothing signs in to a real Apple ID (D-13: live Apple testing is
// owner-only). `vi.mock` is scoped to the file it sits in, which is why this is
// its own file rather than a block in one of the others.

import type { McpServer } from "@modelcontextprotocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import { encodeMessageId } from "../src/mail/ids";
import type { MessageRef } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { registerMailTools } from "../src/mcp/tools/mail";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  flagEcho,
  logoutExchange,
  selectResponse,
  taggedOk,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

/** The message every case acts on. */
const UID = 4242;
const REF: MessageRef = { mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid: UID };

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type MarkReadCallback = (args: { id: string; read: boolean }) => Promise<ToolAnswer>;

/** The callback the mail tools register for `mail_mark_read`. */
function markReadCallback(): MarkReadCallback {
  let callback: MarkReadCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: MarkReadCallback) {
      if (name === "mail_mark_read") callback = handler;
    },
  };
  registerMailTools(server as unknown as McpServer, createSessionGate(), ownerPrincipal());
  expect(callback, "mail_mark_read is not registered").toBeDefined();
  return callback!;
}

/**
 * A server that signs in, opens the mailbox for changing, and echoes `flags`
 * back for the message. The flag change is tag `a5`.
 */
function serverEchoing(flags: string): FakeDuplex {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    selectResponse("a4", "[READ-WRITE]"),
    flagEcho("a5", 17, UID, flags),
    logoutExchange("a6"),
  ]);
}

/** The flag-change line, found by its tag. Never the login line. */
function flagChangeLine(duplex: FakeDuplex): string | undefined {
  return duplex.writtenLines().find((line) => line.startsWith("a5 "));
}

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

describe("mail_mark_read picks the verb from `read` (WR-04)", () => {
  it("read: true writes the add form of the flag change, and reports read", async () => {
    const duplex = serverEchoing("\\Seen");
    vi.mocked(connectImap).mockReturnValue(duplex as never);
    const id = encodeMessageId(REF);

    const answer = await markReadCallback()({ id, read: true });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(flagChangeLine(duplex)).toBe(`a5 UID STORE ${UID} +FLAGS (\\Seen)`);
    expect(answer.isError).toBeUndefined();
    expect(JSON.parse(answer.content[0]!.text)).toEqual({
      id,
      requested: "read",
      state: "read",
      stateSource: "store-echo",
    });
  });

  it("read: false writes the remove form of the flag change, and reports unread", async () => {
    const duplex = serverEchoing("");
    vi.mocked(connectImap).mockReturnValue(duplex as never);
    const id = encodeMessageId(REF);

    const answer = await markReadCallback()({ id, read: false });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(flagChangeLine(duplex)).toBe(`a5 UID STORE ${UID} -FLAGS (\\Seen)`);
    expect(answer.isError).toBeUndefined();
    expect(JSON.parse(answer.content[0]!.text)).toEqual({
      id,
      requested: "unread",
      state: "unread",
      stateSource: "store-echo",
    });
  });
});
