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
import { ImapNotFoundError, ImapThrottleError } from "../src/errors";
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
  taggedNo,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The verbs module's own source, for the no-body guard. Read at build time by
// Vite, as test/service.test.ts reads the service module: a Workers isolate has
// no filesystem. The one suppression is proven non-vacuous by `tsc`, which
// errors on one that suppresses nothing.
// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here; see above.
const TRIAGE_SOURCE: Record<string, string> = import.meta.glob(
  "../src/mail/triage.ts",
  { query: "?raw", import: "default", eager: true },
);

/** Drop block comments and line comments, so prose cannot count as code. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

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

/** Whether any written line is a flag change: its second token is the verb. */
function wroteFlagChange(duplex: FakeDuplex): boolean {
  return duplex.writtenLines().some((line) => {
    const tokens = line.split(" ");
    return tokens[1] === "UID" && tokens[2] === "STORE";
  });
}

/** Teardown ran after the readable was done, whatever the call did. */
function expectClosedAfterRead(duplex: FakeDuplex): void {
  expect(duplex.firstIndexOf("readable-done")).toBeGreaterThanOrEqual(0);
  expect(duplex.firstIndexOf("close")).toBeGreaterThan(
    duplex.firstIndexOf("readable-done"),
  );
}

describe("the mutating path refuses and reports honestly", () => {
  it("refuses a mailbox that opened read-only, and writes no flag change", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-ONLY]"),
      logoutExchange("a5"),
    ]);

    const outcome = await markReadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(outcome).toEqual({ applied: false, refusal: "mailbox-read-only" });
    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 LOGOUT",
    ]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);

    // The answer says what happened and that retrying will not help.
    const answer = JSON.parse(
      readStateToolResult("x", true, outcome).content[0]!.text,
    ) as Record<string, unknown>;
    expect(Object.keys(answer).sort()).toEqual([
      "id",
      "reason",
      "refusal",
      "requested",
    ]);
    expect(answer.refusal).toBe("mailbox-read-only");
    expect(String(answer.reason)).toContain("nothing was changed");
    expect(String(answer.reason)).toContain("Retrying will not help");
    expect(readStateToolResult("x", true, outcome).isError).toBeUndefined();
  });

  it("refuses a mailbox that opened with no access code at all, the same way", async () => {
    // Absent is not read-write (PITFALLS #33).
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", ""),
      logoutExchange("a5"),
    ]);

    const outcome = await markUnreadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(outcome).toEqual({ applied: false, refusal: "mailbox-read-only" });
    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 LOGOUT",
    ]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);
  });

  it("refuses a read-write mailbox whose permanent flags leave out the seen flag (WR-01)", async () => {
    // RFC 3501 §7.1: a flag missing from the permanent-flags list changes for
    // this session only. The change would be echoed back as done and then be
    // gone at logout, which is PITFALLS #33's shape exactly.
    for (const permanent of ["", "\\Answered \\Flagged", "\\Answered \\*"]) {
      const duplex = createFakeDuplex([
        ...authPrefix(),
        selectResponse("a4", "[READ-WRITE]", 172, INBOX_UIDVALIDITY, permanent),
        logoutExchange("a5"),
      ]);

      const outcome = await markReadOver(
        duplex,
        principal,
        createSessionGate(),
        REF,
        FAST_BOUNDS,
      );

      expect(outcome, `list (${permanent})`).toEqual({
        applied: false,
        refusal: "mailbox-read-only",
      });
      expect(wireOf(duplex)).toEqual([
        ...SIGN_IN,
        'a4 SELECT "INBOX"',
        "a5 LOGOUT",
      ]);
      expect(wroteFlagChange(duplex)).toBe(false);
      expectClosedAfterRead(duplex);
    }
  });

  it("goes on when the permanent-flags list is absent, or names the seen flag in any case", async () => {
    // Absent: RFC 3501 §6.3.1 says to assume every flag is kept.
    for (const permanent of [null, "\\seen", "\\Answered \\SEEN"]) {
      const duplex = createFakeDuplex([
        ...authPrefix(),
        selectResponse("a4", "[READ-WRITE]", 172, INBOX_UIDVALIDITY, permanent),
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

      expect(outcome, `list ${String(permanent)}`).toEqual({
        applied: true,
        seen: true,
        source: "store-echo",
      });
      expect(wireOf(duplex)).toEqual([
        ...SIGN_IN,
        'a4 SELECT "INBOX"',
        `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
        "a6 LOGOUT",
      ]);
    }
  });

  it("is not_found when the open is answered NO, and writes no flag change", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", "Mailbox does not exist"),
      logoutExchange("a5"),
    ]);

    await expect(
      markReadOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 LOGOUT",
    ]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);
  });

  it("is not_found when the folder's validity changed, before any change (D-10)", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 172, INBOX_UIDVALIDITY - 1),
      logoutExchange("a5"),
    ]);

    await expect(
      markReadOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 LOGOUT",
    ]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);
  });

  it("is not_found when the open reports no validity at all", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 172, null),
      logoutExchange("a5"),
    ]);

    await expect(
      markUnreadOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 LOGOUT",
    ]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);
  });

  it("is not_found when the flag change is answered NO", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      taggedNo("a5", "STORE failed"),
      logoutExchange("a6"),
    ]);

    await expect(
      markReadOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
      "a6 LOGOUT",
    ]);
    expectClosedAfterRead(duplex);
  });

  it("re-reads the flags when the change had no echo, and reports from the re-read", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      taggedOk("a5", "STORE completed"),
      wire(`* 17 FETCH (UID ${UID} FLAGS (\\Seen))`, "a6 OK FETCH completed"),
      logoutExchange("a7"),
    ]);

    const outcome = await markReadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(outcome).toEqual({ applied: true, seen: true, source: "read-back" });
    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
      `a6 UID FETCH ${UID} (UID FLAGS)`,
      "a7 LOGOUT",
    ]);
    const answer = JSON.parse(
      readStateToolResult("x", true, outcome).content[0]!.text,
    ) as Record<string, unknown>;
    expect(answer.stateSource).toBe("read-back");
  });

  it("is not_found when neither the change nor the re-read says anything about the message (D-11)", async () => {
    // A UID that names nothing gets a tagged OK and no reply about it, on both
    // commands. That is the commonest shape of "the message is gone".
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      taggedOk("a5", "STORE completed"),
      taggedOk("a6", "FETCH completed"),
      logoutExchange("a7"),
    ]);

    await expect(
      markUnreadOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} -FLAGS (\\Seen)`,
      `a6 UID FETCH ${UID} (UID FLAGS)`,
      "a7 LOGOUT",
    ]);
    expectClosedAfterRead(duplex);
  });

  it("treats an echo for a DIFFERENT UID as no echo at all", async () => {
    // Keyed by the reply's own UID, not by position. The only reply names
    // another message, so this one's state is still unknown and is re-read.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID + 1, "\\Seen"),
      wire(`* 18 FETCH (UID ${UID} FLAGS ())`, "a6 OK FETCH completed"),
      logoutExchange("a7"),
    ]);

    const outcome = await markReadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(outcome).toEqual({ applied: true, seen: false, source: "read-back" });
    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
      `a6 UID FETCH ${UID} (UID FLAGS)`,
      "a7 LOGOUT",
    ]);
  });

  it("reports the echo when it disagrees with the request (PITFALLS #33)", async () => {
    // Asked read; the server's own reply says the flag is not set. The answer
    // is the server's word, never the request echoed back.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID, "\\Flagged"),
      logoutExchange("a6"),
    ]);

    const outcome = await markReadOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(outcome).toEqual({ applied: true, seen: false, source: "store-echo" });
    expect(wireOf(duplex)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      `a5 UID STORE ${UID} +FLAGS (\\Seen)`,
      "a6 LOGOUT",
    ]);
    const answer = JSON.parse(
      readStateToolResult("x", true, outcome).content[0]!.text,
    ) as Record<string, unknown>;
    expect(answer).toEqual({
      id: "x",
      requested: "read",
      state: "unread",
      stateSource: "store-echo",
    });
  });

  it("quotes the mailbox name on the open line", async () => {
    const ref: MessageRef = { ...REF, mailbox: 'Work "Q3"' };
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 1, UID, "\\Seen"),
      logoutExchange("a6"),
    ]);

    await markReadOver(duplex, principal, createSessionGate(), ref, FAST_BOUNDS);

    expect(wireOf(duplex)[3]).toBe('a4 SELECT "Work \\"Q3\\""');
  });

  it("refuses a mailbox name carrying a carriage return before any open line", async () => {
    const ref: MessageRef = { ...REF, mailbox: "INBOX\r\na9 LOGOUT" };
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    await expect(
      markReadOver(duplex, principal, createSessionGate(), ref, FAST_BOUNDS),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual([...SIGN_IN, "a4 LOGOUT"]);
    expect(wroteFlagChange(duplex)).toBe(false);
    expectClosedAfterRead(duplex);
  });

  it("names no body fetch item and no RFC822 item in the verbs module's code", () => {
    // A body fetch on a mailbox opened for changing is how mail gets marked
    // read by accident. The verbs send a flag change and a flags-only re-read,
    // and nothing else. Comments are stripped, so prose cannot pass or fail it.
    const code = withoutComments(Object.values(TRIAGE_SOURCE)[0] ?? "");

    expect(code).toContain("UID STORE");
    expect(/BODY(?!\.PEEK)\[/.test(code)).toBe(false);
    expect(/\bRFC822(?!\.SIZE)\b/.test(code)).toBe(false);
    // Stronger than the two above: no body item at all, peeking or not.
    expect(/\bBODY(?:\.PEEK)?\[/.test(code)).toBe(false);
  });
});

describe("one mark-read per request (D-08, MUTA-05)", () => {
  it("refuses a second mark-read on the same gate, and writes nothing for it", async () => {
    // Two verb calls in one request share one gate. The verb reaches the
    // gate's acquire with no await ahead of it, so the first call already
    // holds it when the second is made. This is the run-time half that stands
    // in for listing the verbs in the scan's fan-out rule.
    const gate = createSessionGate();
    const firstDuplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID, "\\Seen"),
      logoutExchange("a6"),
    ]);
    const secondDuplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      flagEcho("a5", 17, UID, "\\Seen"),
      logoutExchange("a6"),
    ]);

    const first = markReadOver(firstDuplex, principal, gate, REF, FAST_BOUNDS);
    const second = markReadOver(secondDuplex, principal, gate, REF, FAST_BOUNDS);

    await expect(second).rejects.toBeInstanceOf(ImapThrottleError);
    // Only a count: the login line carries the pool's credential.
    expect(secondDuplex.writtenLines().length).toBe(0);
    expect(wroteFlagChange(secondDuplex)).toBe(false);

    await expect(first).resolves.toEqual({
      applied: true,
      seen: true,
      source: "store-echo",
    });
    expect(wroteFlagChange(firstDuplex)).toBe(true);
    expect(gate.held).toBe(false);
  });
});
