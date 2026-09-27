// The change-check TOOL, driven from its registered callback down to the bytes.
//
// The socket module is mocked for this file only, so each session's connect
// step hands back the next in-memory duplex. Nothing here opens a network
// connection and nothing signs in to a real Apple ID (D-13: live Apple testing
// is owner-only). Every recorded line array is a literal, and the login line is
// redacted before any comparison, by the rules test/read-path-wire.test.ts
// keeps. The redactor is copied from there rather than imported.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import type { MarkerContent } from "../src/change-marker";
import { readMarker, sealMarker } from "../src/change-marker";
import { createSessionGate } from "../src/mail/service";
import { connectImap } from "../src/mail/socket";
import { CHANGES_TOOL_NAME, registerChangesTool } from "../src/mcp/tools/changes";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  statusResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type ChangesCallback = (args: { marker?: string }) => Promise<ToolAnswer>;

const STATUS_LINE =
  'a4 STATUS "INBOX" (UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)';

/** The callback the tool module registers. */
function changesCallback(): ChangesCallback {
  let callback: ChangesCallback | undefined;
  const server = {
    registerTool(name: string, _options: unknown, handler: ChangesCallback) {
      if (name === CHANGES_TOOL_NAME) callback = handler;
    },
  };
  registerChangesTool(
    server as unknown as McpServer,
    createSessionGate(),
    ownerPrincipal(),
  );
  expect(callback, `${CHANGES_TOOL_NAME} is not registered`).toBeDefined();
  return callback!;
}

/** Copied from test/read-path-wire.test.ts: the login line, reduced. */
function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    const command = (tokens[1] ?? "").toUpperCase();
    if (command === "LOGIN") return `${tokens[0]} ${tokens[1]} [redacted]`;
    if (command === "AUTHENTICATE") {
      return `${tokens[0]} ${tokens[1]} ${tokens[2] ?? ""} [redacted]`;
    }
    return line;
  });
}

function wireOf(duplex: FakeDuplex): string[] {
  return redacted(duplex.writtenLines());
}

/** The four turns every session opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A session that answers one status command for the inbox. */
function statusSession(uidNext: number, modseq: string | null): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    statusResponse("a4", "INBOX", INBOX_UIDVALIDITY, uidNext, 172, modseq),
    logoutExchange("a5"),
  ]);
}

async function markerFor(content: MarkerContent): Promise<string> {
  const { userId } = await ownerPrincipal();
  return sealMarker(content, userId, env.CONFIRM_SECRET);
}

function trustedOf(answer: ToolAnswer): Record<string, any> {
  return JSON.parse(answer.content[0]!.text);
}

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

describe("changes_since for the inbox (CHNG-01, CHNG-03, CHNG-07)", () => {
  it("with no marker: one status command, no mailbox opened, a starting point", async () => {
    const session = statusSession(4392, "118");
    vi.mocked(connectImap).mockReturnValueOnce(session as never);

    const answer = await changesCallback()({});

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(wireOf(session)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      STATUS_LINE,
      "a5 LOGOUT",
    ]);

    expect(answer.isError).toBeUndefined();
    const text = answer.content[0]!.text;
    expect(text.startsWith('{"counts":')).toBe(true);
    const trusted = trustedOf(answer);
    expect(Object.keys(trusted)).toEqual(["counts", "overall", "since", "marker"]);
    expect(trusted.counts).toEqual([
      {
        source: "mail",
        folder: "INBOX",
        state: "started",
        newMessages: null,
        otherActivity: null,
        mechanism: "status-uidnext",
      },
    ]);
    expect(trusted.overall).toContain("starting point");
    expect(trusted.overall).not.toMatch(/nothing has changed/i);
    expect(trusted.since).toBeNull();

    const { userId } = await ownerPrincipal();
    const reading = await readMarker(trusted.marker, userId, env.CONFIRM_SECRET);
    expect(reading.kind).toBe("current");
    if (reading.kind !== "current") return;
    expect(reading.content.folders).toEqual([
      {
        mailbox: "INBOX",
        uidValidity: INBOX_UIDVALIDITY,
        uidNext: 4392,
        highestModseq: "118",
      },
    ]);
    expect(reading.content.calendar).toBeNull();
  });

  it("with a marker and the same next UID: no mailbox opened, no_changes, a fresh marker", async () => {
    const marker = await markerFor({
      folders: [
        {
          mailbox: "INBOX",
          uidValidity: INBOX_UIDVALIDITY,
          uidNext: 4392,
          highestModseq: "118",
        },
      ],
      calendar: null,
      mintedAt: 1790000000,
    });
    const session = statusSession(4392, "118");
    vi.mocked(connectImap).mockReturnValueOnce(session as never);

    const answer = await changesCallback()({ marker });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(wireOf(session)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      STATUS_LINE,
      "a5 LOGOUT",
    ]);

    const trusted = trustedOf(answer);
    expect(trusted.counts).toEqual([
      {
        source: "mail",
        folder: "INBOX",
        state: "no_changes",
        newMessages: 0,
        otherActivity: false,
        mechanism: "status-modseq",
      },
    ]);
    expect(trusted.overall).toMatch(/^Nothing has changed/);
    expect(trusted.since).toBe(new Date(1790000000 * 1000).toISOString());
    expect(trusted.marker).toEqual(expect.any(String));
    expect(trusted.marker).not.toBe(marker);
  });

  it("with a marker three UIDs behind: a bounded search counts only the range", async () => {
    const marker = await markerFor({
      folders: [
        {
          mailbox: "INBOX",
          uidValidity: INBOX_UIDVALIDITY,
          uidNext: 4392,
          highestModseq: "118",
        },
      ],
      calendar: null,
      mintedAt: 1790000000,
    });
    const first = statusSession(4395, "124");
    const second = createFakeDuplex([
      ...authPrefix(),
      examineResponse("a4"),
      // 4391 is below the range. A server may answer with it; it is not new.
      wire("* SEARCH 4391 4392 4393 4394", "a5 OK SEARCH completed"),
      logoutExchange("a6"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(first as never)
      .mockReturnValueOnce(second as never);

    const answer = await changesCallback()({ marker });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(wireOf(first)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      STATUS_LINE,
      "a5 LOGOUT",
    ]);
    expect(wireOf(second)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH UID 4392:4394",
      "a6 LOGOUT",
    ]);

    const trusted = trustedOf(answer);
    expect(trusted.counts).toEqual([
      {
        source: "mail",
        folder: "INBOX",
        state: "changes",
        newMessages: 3,
        otherActivity: null,
        mechanism: "status-modseq",
      },
    ]);

    const { userId } = await ownerPrincipal();
    const reading = await readMarker(trusted.marker, userId, env.CONFIRM_SECRET);
    expect(reading.kind).toBe("current");
    if (reading.kind !== "current") return;
    expect(reading.content.folders[0]!.uidNext).toBe(4395);
    expect(reading.content.folders[0]!.highestModseq).toBe("124");
  });
});
