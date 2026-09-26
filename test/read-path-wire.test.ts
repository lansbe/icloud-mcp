// The read path's outbound command lines, written down byte for byte.
//
// This is the frozen record for MUTA-02 (decision D-02 of phase 20). It holds
// the whole outbound command sequence of every read that goes through the mail
// session orchestrator, plus the orchestrator's own failure paths. It was
// captured in plan 20-01 against `src/mail/service.ts` exactly as main 3b559aa
// left it, before phase 20 changed a line of that module.
//
// Why it exists. Phase 20 splits the orchestrator into a private core and two
// wrappers. A green test count does not prove that split changed nothing on
// the wire. A record of what went out BEFORE, compared with what goes out
// AFTER, does. This file is that record.
//
// The rules that govern it:
//
//   - Every array below is a literal, on purpose. No snapshot assertion of any
//     kind is used, because a snapshot can be re-blessed with a command-line
//     flag, and a re-blessed snapshot makes a changed wire look unchanged. A
//     literal array can only change by a visible edit to this file. A probe at
//     the bottom fails if a snapshot matcher ever appears here.
//
//   - The login line is redacted before every comparison. It carries the
//     pool's credential, and a failed comparison prints both sides. The SASL
//     line is redacted the same way, because its initial response is the same
//     credential in base64. The redactor proves it is not vacuous by booleans
//     only, so nothing secret is printed even when that check fails.
//
//   - If this file goes red after a change to the service module, the change
//     is wrong. Do not edit an array to make it pass. Editing this file is a
//     decision, not a fix.
//
// Every server byte here is synthesised, in the same spirit as
// `./fixtures/icloud-bytes.ts`. The script builders are COPIED from the test
// files that own them rather than imported, so a later change to another test
// file cannot change what this one drives.
//
// Nothing here opens a network connection and nothing authenticates against a
// real Apple ID (D-13: live Apple testing is owner-only). This file stores
// nothing, prints nothing and reports nothing.

import { beforeAll, describe, expect, it } from "vitest";
import {
  ImapAuthError,
  ImapConnectError,
  ImapNotFoundError,
} from "../src/errors";
import type { MailSessionOptions } from "../src/mail/service";
import {
  createSessionGate,
  withMailSessionOver,
} from "../src/mail/service";
import {
  AUTH_REJECTED_TEXT,
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedNo,
  taggedOk,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import type { Principal } from "../src/principal";
import {
  FAKE_APPLE_ID,
  FAKE_APP_PASSWORD,
  ownerPrincipal,
} from "./fixtures/bound-secrets";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The mailbox, validity and message every scripted conversation agrees on. */
const MAILBOX = "INBOX";
const UIDVALIDITY = 3857529045;

/** The fixed text a credential-carrying line is reduced to. */
const REDACTED = "[redacted]";

// ---------------------------------------------------------------------------
// The redactor
// ---------------------------------------------------------------------------

/**
 * Every written line, with the credential-carrying ones reduced to a fixed
 * text.
 *
 * A line is credential-carrying when its second token is the login command, or
 * the SASL authenticate command. The login line keeps its tag and command; the
 * SASL line keeps its tag, command and mechanism. Everything after that is
 * replaced. The command word is compared upper-cased, so a lower-case spelling
 * is redacted too: this errs toward hiding more, never less.
 *
 * Every other line passes through unchanged.
 */
function redacted(lines: readonly string[]): string[] {
  return lines.map((line) => {
    const tokens = line.split(" ");
    const command = (tokens[1] ?? "").toUpperCase();
    if (command === "LOGIN") {
      return `${tokens[0]} ${tokens[1]} ${REDACTED}`;
    }
    if (command === "AUTHENTICATE") {
      return `${tokens[0]} ${tokens[1]} ${tokens[2] ?? ""} ${REDACTED}`;
    }
    return line;
  });
}

/** What a duplex was sent, redacted. The only form any golden is compared in. */
function wireOf(duplex: FakeDuplex): string[] {
  return redacted(duplex.writtenLines());
}

// ---------------------------------------------------------------------------
// Script builders, copied from the files that own them
// ---------------------------------------------------------------------------

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

/**
 * The untagged set a read-only open returns, then its completion.
 *
 * Copied from `test/service.test.ts`. `uidValidity: null` drops the validity
 * line altogether, which is the fail-closed case.
 */
function examineReply(
  tag: string,
  options: { uidValidity?: number | null; exists?: number } = {},
): Uint8Array {
  const validity =
    options.uidValidity === undefined ? UIDVALIDITY : options.uidValidity;
  const lines = [
    `* ${options.exists ?? 172} EXISTS`,
    "* 0 RECENT",
    "* OK [UNSEEN 12] Message 12 is first unseen",
    ...(validity === null ? [] : [`* OK [UIDVALIDITY ${validity}] UIDs valid`]),
    "* OK [UIDNEXT 4392] Predicted next UID",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  ];
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

// ---------------------------------------------------------------------------
// The goldens
// ---------------------------------------------------------------------------

/** One recorded read: whether it opens a mailbox, and every line it wrote. */
interface Golden {
  readonly opensMailbox: boolean;
  readonly lines: readonly string[];
}

/**
 * The orchestrator's own bytes, one entry per shape.
 *
 * Written from reading `withMailSessionOver` and `authenticate`, then checked
 * against what the code actually sends. Nothing under `src/` was changed to
 * make any of these pass.
 */
const ORCHESTRATOR_GOLDENS = {
  "sign-in proof: no mailbox, no work": {
    opensMailbox: false,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      "a4 LOGOUT",
    ],
  },
  "INBOX with the matching validity, no work": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 LOGOUT",
    ],
  },
  "validity differs from the expected one": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 LOGOUT",
    ],
  },
  "no validity in the open's reply": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 LOGOUT",
    ],
  },
  "open refused with a tagged NO": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 LOGOUT",
    ],
  },
  "mailbox name carrying a carriage return": {
    opensMailbox: false,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      "a4 LOGOUT",
    ],
  },
  "login refused, then the SASL retry refused": {
    opensMailbox: false,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 AUTHENTICATE PLAIN [redacted]",
      "a4 LOGOUT",
    ],
  },
  "work that never settles, past the call deadline": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 LOGOUT",
    ],
  },
} as const satisfies Record<string, Golden>;

type OrchestratorCase = keyof typeof ORCHESTRATOR_GOLDENS;

function orchestratorGolden(name: OrchestratorCase): readonly string[] {
  return ORCHESTRATOR_GOLDENS[name].lines;
}

/** Run the orchestrator over a scripted duplex, with the given shape. */
function runSession(
  duplex: FakeDuplex,
  mailbox: string | null,
  expectedUidValidity: number | null,
  work: () => Promise<unknown> = async () => {},
  options: MailSessionOptions = FAST_BOUNDS,
): Promise<unknown> {
  return withMailSessionOver(
    duplex,
    principal,
    createSessionGate(),
    mailbox,
    expectedUidValidity,
    work,
    options,
  );
}

describe("the redactor", () => {
  it("reduces the login line to the fixed text, and leaves no credential behind", async () => {
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);
    await runSession(duplex, null, null);

    const raw = duplex.writtenLines();
    const clean = wireOf(duplex);

    // Booleans only. A matcher that printed a line would print the password
    // on the very failure this case exists to catch.
    const rawLoginCarriesAddress =
      raw.filter((line) => line.includes(FAKE_APPLE_ID)).length === 1;
    const rawLoginCarriesPassword =
      raw.filter((line) => line.includes(FAKE_APP_PASSWORD)).length === 1;
    const exactlyOneRedactedLogin =
      clean.filter((line) => line === `a2 LOGIN ${REDACTED}`).length === 1;
    const addressGone = clean.every(
      (line) => !line.includes(principal.appleId) && !line.includes(FAKE_APPLE_ID),
    );
    const passwordGone = clean.every((line) => !line.includes(FAKE_APP_PASSWORD));

    // Non-vacuity first: there was a credential on the wire to remove.
    expect(rawLoginCarriesAddress).toBe(true);
    expect(rawLoginCarriesPassword).toBe(true);
    expect(exactlyOneRedactedLogin).toBe(true);
    expect(addressGone).toBe(true);
    expect(passwordGone).toBe(true);
  });

  it("reduces the SASL retry line too, whose initial response is the credential in base64", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);
    await runSession(duplex, null, null).catch(() => undefined);

    const raw = duplex.writtenLines();
    const clean = wireOf(duplex);
    const encoded = btoa(`\0${FAKE_APPLE_ID}\0${FAKE_APP_PASSWORD}`);

    const rawCarriesEncoded =
      raw.filter((line) => line.includes(encoded)).length === 1;
    const exactlyOneRedactedSasl =
      clean.filter((line) => line === `a3 AUTHENTICATE PLAIN ${REDACTED}`)
        .length === 1;
    const encodedGone = clean.every((line) => !line.includes(encoded));

    expect(rawCarriesEncoded).toBe(true);
    expect(exactlyOneRedactedSasl).toBe(true);
    expect(encodedGone).toBe(true);
  });
});

describe("the orchestrator's own bytes", () => {
  it("sign-in proof: no mailbox, no work", async () => {
    // The exact call `proveWithApple` in src/auth/login-handler.ts makes,
    // options included.
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    await runSession(duplex, null, null, async () => {}, {
      ...FAST_BOUNDS,
      oneAttemptPerGuess: true,
    });

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("sign-in proof: no mailbox, no work"),
    );
  });

  it("INBOX with the matching validity, no work", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      logoutExchange("a5"),
    ]);

    await runSession(duplex, MAILBOX, UIDVALIDITY);

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("INBOX with the matching validity, no work"),
    );
  });

  it("validity differs from the expected one", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      logoutExchange("a5"),
    ]);

    await expect(
      runSession(duplex, MAILBOX, UIDVALIDITY + 1),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("validity differs from the expected one"),
    );
  });

  it("no validity in the open's reply", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4", { uidValidity: null }),
      logoutExchange("a5"),
    ]);

    await expect(runSession(duplex, MAILBOX, null)).rejects.toBeInstanceOf(
      ImapNotFoundError,
    );

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("no validity in the open's reply"),
    );
  });

  it("open refused with a tagged NO", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      taggedNo("a4", "Mailbox does not exist"),
      logoutExchange("a5"),
    ]);

    await expect(runSession(duplex, MAILBOX, null)).rejects.toBeInstanceOf(
      ImapNotFoundError,
    );

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("open refused with a tagged NO"),
    );
  });

  it("mailbox name carrying a carriage return", async () => {
    const duplex = createFakeDuplex([...authPrefix(), logoutExchange("a4")]);

    await expect(
      runSession(duplex, "IN\rBOX", null),
    ).rejects.toBeInstanceOf(ImapNotFoundError);

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("mailbox name carrying a carriage return"),
    );
  });

  it("login refused, then the SASL retry refused", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    await expect(runSession(duplex, null, null)).rejects.toBeInstanceOf(
      ImapAuthError,
    );

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("login refused, then the SASL retry refused"),
    );
  });

  it("work that never settles, past the call deadline", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      logoutExchange("a5"),
    ]);

    await expect(
      runSession(
        duplex,
        MAILBOX,
        UIDVALIDITY,
        () => new Promise<never>(() => {}),
        { ...FAST_BOUNDS, callDeadlineMs: 30 },
      ),
    ).rejects.toBeInstanceOf(ImapConnectError);

    expect(wireOf(duplex)).toEqual(
      orchestratorGolden("work that never settles, past the call deadline"),
    );
  });
});
