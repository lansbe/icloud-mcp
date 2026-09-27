// The flag TOOL, driven from its registered callback down to the bytes.
//
// test/triage.test.ts proves each flag verb writes the right change. It calls
// the verbs directly, so it cannot see the one line in the tool that picks a
// verb from the caller's `flagged` boolean. A swapped choice there would flag
// mail the user asked to clear, and leave that file green. This file closes
// that gap, as test/mark-read-tool.test.ts does for marking read (WR-04): it
// invokes the callback the tool module registers, and reads the flag change
// off the recorded command line.
//
// The socket module is mocked for this file only. Nothing here opens a network
// connection and nothing signs in to a real Apple ID (D-13). `vi.mock` is
// scoped to the file it sits in, which is why this is its own file.

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
type FlagCallback = (args: { id: string; flagged: boolean }) => Promise<ToolAnswer>;

/** The callback the mail tools register for `mail_flag`. */
function flagCallback(): FlagCallback {
  let callback: FlagCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: FlagCallback) {
      if (name === "mail_flag") callback = handler;
    },
  };
  registerMailTools(server as unknown as McpServer, createSessionGate(), ownerPrincipal());
  expect(callback, "mail_flag is not registered").toBeDefined();
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

describe("mail_flag picks the verb from `flagged`", () => {
  it("flagged: true writes the add form of the flag change, and reports flagged", async () => {
    const duplex = serverEchoing("\\Seen \\Flagged");
    vi.mocked(connectImap).mockReturnValue(duplex as never);
    const id = encodeMessageId(REF);

    const answer = await flagCallback()({ id, flagged: true });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(flagChangeLine(duplex)).toBe(`a5 UID STORE ${UID} +FLAGS (\\Flagged)`);
    expect(answer.isError).toBeUndefined();
    expect(JSON.parse(answer.content[0]!.text)).toEqual({
      id,
      requested: "flagged",
      state: "flagged",
      stateSource: "store-echo",
    });
  });

  it("flagged: false writes the remove form of the flag change, and reports unflagged", async () => {
    const duplex = serverEchoing("\\Seen");
    vi.mocked(connectImap).mockReturnValue(duplex as never);
    const id = encodeMessageId(REF);

    const answer = await flagCallback()({ id, flagged: false });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(flagChangeLine(duplex)).toBe(`a5 UID STORE ${UID} -FLAGS (\\Flagged)`);
    expect(answer.isError).toBeUndefined();
    expect(JSON.parse(answer.content[0]!.text)).toEqual({
      id,
      requested: "unflagged",
      state: "unflagged",
      stateSource: "store-echo",
    });
  });

  it("refuses a malformed id before any socket", async () => {
    const answer = await flagCallback()({ id: "not-an-id", flagged: true });

    expect(connectImap).not.toHaveBeenCalled();
    expect(answer.isError).toBe(true);
  });
});
