// The recall build's own mail read, written down byte for byte (Phase 26, D-19).
//
// This is the window's UID snapshot, recorded by the rules
// test/read-path-wire.test.ts keeps for every other read. That file is not
// edited by this phase: it holds the reads that existed before, and this one is
// new.
//
// The rules:
//
//   - Every expected line array is a literal. No snapshot matcher is used,
//     because a snapshot can be re-blessed with a flag and a re-blessed snapshot
//     makes a changed wire look unchanged. A probe at the bottom fails if one
//     ever appears here.
//
//   - The login line is redacted before every comparison. It carries the pool's
//     credential, and a failed comparison prints both sides. The redactor and
//     the script builders are copied, not imported, so a change to another test
//     file cannot change what this one drives.
//
//   - If this file goes red after a change to the service module, the change is
//     wrong until shown otherwise. Editing an array here is a decision.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID (D-13: live Apple testing is owner-only).

import { beforeAll, describe, expect, it } from "vitest";
import { ImapNotFoundError } from "../src/errors";
import { createSessionGate, windowUidsOver } from "../src/mail/service";
import type { Principal } from "../src/principal";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// This file's own source, for the no-snapshot probe. Read at build time by
// Vite, as test/read-path-wire.test.ts reads its own.
// @ts-expect-error — a raw import has no ambient declaration here.
import OWN_SOURCE from "./recall-wire.test.ts?raw";

let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

// ---------------------------------------------------------------------------
// The redactor, copied from test/read-path-wire.test.ts
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Script builders, copied from the files that own them
// ---------------------------------------------------------------------------

/** The four turns every session opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** A read-only open of the inbox. Copied from test/read-path-wire.test.ts. */
function examineReply(tag: string): Uint8Array {
  const lines = [
    "* 172 EXISTS",
    "* 0 RECENT",
    `* OK [UIDVALIDITY ${UIDVALIDITY}] UIDs valid`,
    "* OK [UIDNEXT 4395] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

/** The untagged search reply for a set of identifiers, in server order. */
function searchReply(tag: string, uids: readonly number[]): Uint8Array {
  return wire(`* SEARCH ${uids.join(" ")}`, `${tag} OK SEARCH completed`);
}

// ---------------------------------------------------------------------------
// The window's UID snapshot
// ---------------------------------------------------------------------------

describe("windowUidsOver records exactly one read-only open and one search (D-17b, D-19)", () => {
  it("a one-digit day: examine, the search since that day, logout; the UIDs as listed, once each", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      searchReply("a5", [4801, 4803, 4802, 4803]),
      logoutExchange("a6"),
    ]);

    const snapshot = await windowUidsOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      "2026-07-05",
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH SINCE 5-Jul-2026",
      "a6 LOGOUT",
    ]);
    expect(snapshot).toEqual({ uidValidity: UIDVALIDITY, uids: [4801, 4803, 4802] });
  });

  it("a two-digit day with no mail since it: the same lines, and no UIDs", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      wire("a5 OK SEARCH completed"),
      logoutExchange("a6"),
    ]);

    const snapshot = await windowUidsOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      "2026-06-29",
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH SINCE 29-Jun-2026",
      "a6 LOGOUT",
    ]);
    expect(snapshot).toEqual({ uidValidity: UIDVALIDITY, uids: [] });
  });

  it("a malformed day is refused before any line is written", async () => {
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    for (const day of ["2026-02-31", "2026-7-05", ""]) {
      await expect(
        windowUidsOver(duplex, principal, createSessionGate(), MAILBOX, day, FAST_BOUNDS),
      ).rejects.toBeInstanceOf(ImapNotFoundError);
    }

    expect(wireOf(duplex)).toEqual([]);
  });
});

describe("this file keeps its own rules", () => {
  it("uses no snapshot matcher", () => {
    const matcher = "toMatch" + "Snapshot";
    const inline = "toMatchInline" + "Snapshot";
    expect(String(OWN_SOURCE).length).toBeGreaterThan(1000);
    expect(String(OWN_SOURCE)).not.toContain(matcher);
    expect(String(OWN_SOURCE)).not.toContain(inline);
  });
});
