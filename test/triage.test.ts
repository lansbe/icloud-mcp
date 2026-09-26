// The mutating mail path, driven byte for byte with no socket.
//
// This is the first command in this project that changes per-user state on a
// mailbox, and the hazard PITFALLS #33 names is that the wrong version still
// looks like success: a mailbox that opened read-only answers OK, a flag change
// on it can be swallowed, and a tool that reports from the tagged OK alone
// tells the user their mail was sorted when nothing changed. So the assertions
// here are on the RECORDED BYTES and their ORDER, and on what the server sent
// back, never on the call's return value alone.
//
// The login line is redacted before every comparison, as in
// test/read-path-wire.test.ts: it carries the pool's credential, and a failed
// comparison prints both sides.
//
// Nothing here opens a network connection and nothing signs in to a real
// Apple ID (D-13: live Apple testing is owner-only).

import { beforeAll, describe, expect, it } from "vitest";
import { encodeMessageId } from "../src/mail/ids";
import type { MessageRef } from "../src/mail/ids";
import { createSessionGate } from "../src/mail/service";
import { markReadOver, markUnreadOver } from "../src/mail/triage";
import { readStateToolResult } from "../src/mcp/tools/mail";
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
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The message every case acts on. */
const UID = 4242;
const REF: MessageRef = {
  mailbox: "INBOX",
  uidValidity: INBOX_UIDVALIDITY,
  uid: UID,
};

/** The fixed text a credential-carrying line is reduced to. */
const REDACTED = "[redacted]";

/** Every written line, with the login and SASL lines redacted. */
function wireOf(duplex: FakeDuplex): string[] {
  return duplex.writtenLines().map((line) => {
    const tokens = line.split(" ");
    const command = (tokens[1] ?? "").toUpperCase();
    if (command === "LOGIN") return `${tokens[0]} ${tokens[1]} ${REDACTED}`;
    if (command === "AUTHENTICATE") {
      return `${tokens[0]} ${tokens[1]} ${tokens[2] ?? ""} ${REDACTED}`;
    }
    return line;
  });
}

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/** The lines every session writes before its mailbox open. */
const SIGN_IN = ["a1 CAPABILITY", `a2 LOGIN ${REDACTED}`, "a3 CAPABILITY"];

describe("mark read and unread, end to end", () => {
  it("marks one message read, and reports the seen state from the echo", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID, "\\Seen"),
      logoutExchange("a6"),
    ]);

    const outcome = await markReadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
      "a6 LOGOUT",
    ]);
    expect(outcome).toEqual({ applied: true, seen: true, source: "store-echo" });

    const id = encodeMessageId(REF);
    const answer = JSON.parse(
      readStateToolResult(id, true, outcome).content[0]!.text,
    ) as Record<string, unknown>;
    expect(answer).toEqual({
      id,
      requested: "read",
      state: "read",
      stateSource: "store-echo",
    });
  });

  it("marks one message unread, and reports the seen state from the echo", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID, "\\Flagged"),
      logoutExchange("a6"),
    ]);

    const outcome = await markUnreadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} -FLAGS (\\Seen)`,
      "a6 LOGOUT",
    ]);
    expect(outcome).toEqual({ applied: true, seen: false, source: "store-echo" });

    const id = encodeMessageId(REF);
    const answer = JSON.parse(
      readStateToolResult(id, false, outcome).content[0]!.text,
    ) as Record<string, unknown>;
    expect(answer).toEqual({
      id,
      requested: "unread",
      state: "unread",
      stateSource: "store-echo",
    });
  });
});
