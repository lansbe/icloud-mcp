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
import { runDiagnosticOver } from "../src/mail/diagnose";
import type { MailSessionOptions } from "../src/mail/service";
import {
  MAX_WIRE_MESSAGE_BYTES,
  appendDraftOver,
  createSessionGate,
  getAttachmentBytesOver,
  getAttachmentContentOver,
  getMessageOver,
  getReplyParentOver,
  listFoldersOver,
  listMessagesOver,
  listUnreadOver,
  searchMessagesOver,
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
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import type { Principal } from "../src/principal";
import {
  FAKE_APPLE_ID,
  FAKE_APP_PASSWORD,
  ownerPrincipal,
} from "./fixtures/bound-secrets";

// This file's own source, for the no-snapshot probe in the last describe.
//
// This project carries no Node type package and a Workers isolate has no
// filesystem, so the source is read at build time by Vite. Not through
// `import.meta.glob` as test/service.test.ts does: the glob leaves out the file
// that calls it, so a glob of this file from inside this file comes back
// empty. A direct raw import of itself is not filtered that way. The one
// suppression is proven non-vacuous by `tsc` itself, which errors on one that
// suppresses nothing.
// @ts-expect-error — a raw import has no ambient declaration here; see above.
import OWN_SOURCE from "./read-path-wire.test.ts?raw";

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

// ---------------------------------------------------------------------------
// Script builders for the entry points, copied from the files that own them
// ---------------------------------------------------------------------------

/** The message every single-message read below asks for. */
const UID = 4827;

/** The reference a decoded message id yields. */
const REF = { mailbox: MAILBOX, uidValidity: UIDVALIDITY, uid: UID };

/** The attachment's part path, and the reference a decoded attachment id yields. */
const PART_PATH = "2";
const ATTACHMENT_REF = { ...REF, path: PART_PATH };

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

/** One `key {n}\r\n<payload>` pair, count derived from the payload. */
function literalItem(key: string, payload: string): Uint8Array {
  const bytes = ENCODER.encode(payload);
  return concatBytes(ENCODER.encode(`${key} {${bytes.byteLength}}\r\n`), bytes);
}

/**
 * One FETCH reply carrying one literal, keyed by the reply's spelling.
 *
 * Copied from `sectionReply` (test/append.test.ts) and `partReply`
 * (test/attachments.test.ts), which are the same shape. The key is spelled
 * without the peek, because that is what a server sends back for a peeking
 * request.
 */
function literalReply(tag: string, key: string, payload: string): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} `),
    literalItem(key, payload),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The structure-and-size reply, with no literal in it. */
function structureReply(
  tag: string,
  structure: string,
  wireSize: number,
): Uint8Array {
  return wire(
    `* 1 FETCH (UID ${UID} FLAGS () ` +
      `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
      `RFC822.SIZE ${wireSize} BODYSTRUCTURE ${structure})`,
    `${tag} OK UID FETCH completed`,
  );
}

/** A two-part message: text at path 1, a base64 attachment at path 2. */
const ATTACHMENT_FILENAME = "offer.pdf";
const ATTACHMENT_BASE64 = "SGVsbG8sIFBERiE=";

const RAW_MESSAGE = [
  'From: "Doe, Jane" <jane.doe@example.invalid>',
  "To: russell@example.invalid",
  "Subject: Re: your interview on Thursday",
  "Date: Thu, 13 Aug 2026 09:14:02 -0700",
  "Message-ID: <a1b2c3@example.invalid>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="Apple-Mail-A1"',
  "",
  "--Apple-Mail-A1",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hi, following up on our conversation.",
  "",
  "--Apple-Mail-A1",
  "Content-Type: application/pdf",
  `Content-Disposition: attachment; filename="${ATTACHMENT_FILENAME}"`,
  "Content-Transfer-Encoding: base64",
  "",
  ATTACHMENT_BASE64,
  "",
  "--Apple-Mail-A1--",
  "",
].join("\r\n");

/** `RAW_MESSAGE`'s structure, attachment count derived from its body. */
const MIXED_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${ATTACHMENT_FILENAME}") NIL NIL "BASE64" ` +
  `${ATTACHMENT_BASE64.length} NIL ` +
  `("attachment" ("FILENAME" "${ATTACHMENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** A single-part text message. */
const PLAIN_STRUCTURE = '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)';

/** The whole-message size a structure reply declares for `RAW_MESSAGE`. */
const RAW_MESSAGE_BYTES = ENCODER.encode(RAW_MESSAGE).byteLength;

/** The ceiling path's reply: headers, the part's MIME headers, the part. */
function partScopedReply(tag: string, path: string): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} `),
    literalItem(
      "BODY[HEADER]",
      [
        'From: "Doe, Jane" <jane.doe@example.invalid>',
        "Subject: Re: your interview on Thursday",
        "Date: Thu, 13 Aug 2026 09:14:02 -0700",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="Apple-Mail-A1"',
        "",
        "",
      ].join("\r\n"),
    ),
    ENCODER.encode(" "),
    literalItem(`BODY[${path}.MIME]`, "Content-Type: text/plain; charset=utf-8\r\n"),
    ENCODER.encode(" "),
    literalItem(`BODY[${path}]`, "Thanks, Thursday works.\r\n"),
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** The six reply-parent header fields, References folded. */
const PARENT_HEADER_BLOCK = [
  "Message-ID: <parent@example.invalid>",
  "References: <one@example.invalid>",
  " <two@example.invalid>",
  "Reply-To: Jane At Home <reply@example.invalid>",
  'From: "Doe, Jane" <jane@example.invalid>',
  "To: russell@example.invalid, Colleague <colleague@example.invalid>",
  "Cc: watcher@example.invalid",
  "",
  "",
].join("\r\n");

/** The parent as a whole message, for the quoted original. */
const PARENT_RAW = [
  'From: "Doe, Jane" <jane@example.invalid>',
  "To: russell@example.invalid",
  "Subject: Re: your interview on Thursday",
  "Date: Wed, 19 Aug 2026 09:14:02 +0000",
  "Message-ID: <parent@example.invalid>",
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "The original words.",
  "",
].join("\r\n");

const PARENT_STRUCTURE =
  '("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 21 1)';

const PARENT_HEADERS_KEY =
  "BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES REPLY-TO FROM TO CC)]";

/** Base64 of a known string, wrapped as a real encoder wraps it. */
function base64Of(text: string): string {
  const bytes = ENCODER.encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary);
  const lines: string[] = [];
  for (let at = 0; at < encoded.length; at += 76) {
    lines.push(encoded.slice(at, at + 76));
  }
  return `${lines.join("\r\n")}\r\n`;
}

const CONTENT_FILENAME = "Profile-71.pdf";
const CONTENT_BASE64 = base64Of("Job description: Staff Engineer at Example.\r\n");

/** A text body at path 1 and a PDF attachment at path 2. */
const CONTENT_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${CONTENT_FILENAME}") NIL NIL "BASE64" ` +
  `${CONTENT_BASE64.length} NIL ` +
  `("attachment" ("FILENAME" "${CONTENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** One folder listing turn with counts, as `listTurn` in test/service.test.ts. */
function folderListing(tag: string): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* STATUS "INBOX" (MESSAGES 172 UNSEEN 4)',
    '* LIST (\\HasNoChildren) "/" "Drafts"',
    '* STATUS "Drafts" (MESSAGES 3 UNSEEN 0)',
    '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
    '* STATUS "Sent Messages" (MESSAGES 91 UNSEEN 0)',
    `${tag} OK LIST completed`,
  );
}

/** The listing the draft write resolves its folder from, as iCloud sends it. */
function draftsListing(tag: string): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* LIST (\\HasNoChildren) "/" "Drafts"',
    '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
    '* LIST (\\HasNoChildren \\Trash) "/" "Deleted Messages"',
    `${tag} OK LIST completed`,
  );
}

/** One draft's bytes. */
const DRAFT = ENCODER.encode("Subject: hello\r\n\r\nHello there.\r\n");

/** One row of a scripted page. The sequence number is never the UID. */
interface PageRow {
  uid: number;
  seq: number;
}

/** Three plain messages, newest first. */
const PAGE_ROWS: PageRow[] = [
  { uid: 4803, seq: 1 },
  { uid: 4802, seq: 2 },
  { uid: 4801, seq: 3 },
];

/** The untagged search reply for a set of identifiers, in server order. */
function searchReply(tag: string, uids: number[]): Uint8Array {
  return wire(
    `* SEARCH${uids.map((uid) => ` ${uid}`).join("")}`,
    `${tag} OK SEARCH completed`,
  );
}

/** The batched metadata reply: one untagged line per row, then completion. */
function pageMetadataReply(tag: string, rows: PageRow[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const row of rows) {
    chunks.push(
      ENCODER.encode(
        `* ${row.seq} FETCH (UID ${row.uid} FLAGS () ` +
          `INTERNALDATE "01-Jan-2026 00:00:00 +0000" ` +
          `RFC822.SIZE ${12000 + row.uid} ` +
          `BODYSTRUCTURE ${PLAIN_STRUCTURE} `,
      ),
      literalItem(
        "BODY[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]",
        [
          `Subject: Subject for ${row.uid}`,
          `From: "Sender ${row.uid}" <s${row.uid}@example.invalid>`,
          "Date: Thu, 13 Aug 2026 09:14:02 -0700",
          `Message-ID: <m${row.uid}@example.invalid>`,
          "",
          "",
        ].join("\r\n"),
      ),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** The snippet window reply for the text part of each row. */
function snippetReply(tag: string, rows: PageRow[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const row of rows) {
    chunks.push(
      ENCODER.encode(`* ${row.seq} FETCH (UID ${row.uid} `),
      literalItem("BODY[1]<0>", `Preview of message ${row.uid}.`),
      ENCODER.encode(")\r\n"),
    );
  }
  chunks.push(ENCODER.encode(`${tag} OK UID FETCH completed\r\n`));
  return concatBytes(...chunks);
}

/** A whole page conversation: open, search, metadata, snippets, logout. */
function pageDuplex(): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineReply("a4"),
    searchReply("a5", [4801, 4802, 4803]),
    pageMetadataReply("a6", PAGE_ROWS),
    snippetReply("a7", PAGE_ROWS),
    logoutExchange("a8"),
  ]);
}

// ---------------------------------------------------------------------------
// The entry points' goldens
// ---------------------------------------------------------------------------

/**
 * One golden per read entry point, plus the diagnostic.
 *
 * Written from reading each entry point's work function, then checked against
 * what the code actually sends. Nothing under `src/` was changed to make any
 * of these pass. The numbers inside them are literals on purpose, the snippet
 * window and the draft's byte count included: a golden that interpolated a
 * constant would move when the constant moved, and then it would record
 * nothing.
 */
const ENTRY_GOLDENS = {
  "getMessageOver, under the size ceiling": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 4827 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 4827 BODY.PEEK[]",
      "a7 LOGOUT",
    ],
  },
  "getMessageOver, over the size ceiling": {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 4827 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 4827 (BODY.PEEK[HEADER] BODY.PEEK[1.MIME] BODY.PEEK[1])",
      "a7 LOGOUT",
    ],
  },
  getReplyParentOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 4827 (BODY.PEEK[HEADER.FIELDS (MESSAGE-ID REFERENCES REPLY-TO FROM TO CC)])",
      "a6 UID FETCH 4827 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a7 UID FETCH 4827 BODY.PEEK[]",
      "a8 LOGOUT",
    ],
  },
  getAttachmentBytesOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 4827 (BODY.PEEK[2])",
      "a6 LOGOUT",
    ],
  },
  getAttachmentContentOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID FETCH 4827 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)",
      "a6 UID FETCH 4827 (BODY.PEEK[2])",
      "a7 LOGOUT",
    ],
  },
  listFoldersOver: {
    opensMailbox: false,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
      "a5 LOGOUT",
    ],
  },
  listMessagesOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH ALL",
      "a6 UID FETCH 4803,4802,4801 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])",
      "a7 UID FETCH 4803,4802,4801 (BODY.PEEK[1]<0.1024>)",
      "a8 LOGOUT",
    ],
  },
  searchMessagesOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      'a5 UID SEARCH TEXT "recruiter"',
      "a6 UID FETCH 4803,4802,4801 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])",
      "a7 UID FETCH 4803,4802,4801 (BODY.PEEK[1]<0.1024>)",
      "a8 LOGOUT",
    ],
  },
  listUnreadOver: {
    opensMailbox: true,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 EXAMINE "INBOX"',
      "a5 UID SEARCH UNSEEN",
      "a6 UID FETCH 4803,4802,4801 (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])",
      "a7 UID FETCH 4803,4802,4801 (BODY.PEEK[1]<0.1024>)",
      "a8 LOGOUT",
    ],
  },
  "appendDraftOver, no folder given": {
    opensMailbox: false,
    lines: [
      "a1 CAPABILITY",
      "a2 LOGIN [redacted]",
      "a3 CAPABILITY",
      'a4 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
      'a5 APPEND "Drafts" (\\Draft \\Seen) {32}',
      "Subject: hello",
      "Hello there.",
      "a6 LOGOUT",
    ],
  },
  runDiagnosticOver: {
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

type EntryCase = keyof typeof ENTRY_GOLDENS;

function entryGolden(name: EntryCase): readonly string[] {
  return ENTRY_GOLDENS[name].lines;
}

describe("every read entry point, byte for byte", () => {
  it("getMessageOver, under the size ceiling", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", MIXED_STRUCTURE, RAW_MESSAGE_BYTES),
      literalReply("a6", "BODY[]", RAW_MESSAGE),
      logoutExchange("a7"),
    ]);

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    expect(wireOf(duplex)).toEqual(
      entryGolden("getMessageOver, under the size ceiling"),
    );
  });

  it("getMessageOver, over the size ceiling", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", MIXED_STRUCTURE, MAX_WIRE_MESSAGE_BYTES + 1),
      partScopedReply("a6", "1"),
      logoutExchange("a7"),
    ]);

    await getMessageOver(duplex, principal, createSessionGate(), REF, FAST_BOUNDS);

    expect(wireOf(duplex)).toEqual(
      entryGolden("getMessageOver, over the size ceiling"),
    );
  });

  it("getReplyParentOver", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      literalReply("a5", PARENT_HEADERS_KEY, PARENT_HEADER_BLOCK),
      structureReply(
        "a6",
        PARENT_STRUCTURE,
        ENCODER.encode(PARENT_RAW).byteLength,
      ),
      literalReply("a7", "BODY[]", PARENT_RAW),
      logoutExchange("a8"),
    ]);

    await getReplyParentOver(
      duplex,
      principal,
      createSessionGate(),
      REF,
      FAST_BOUNDS,
    );

    expect(wireOf(duplex)).toEqual(entryGolden("getReplyParentOver"));
  });

  it("getAttachmentBytesOver", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      literalReply("a5", `BODY[${PART_PATH}]`, CONTENT_BASE64),
      logoutExchange("a6"),
    ]);

    const result = await getAttachmentBytesOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      CONTENT_BASE64.length,
      FAST_BOUNDS,
    );

    expect(result.fetched).toBe(true);
    expect(wireOf(duplex)).toEqual(entryGolden("getAttachmentBytesOver"));
  });

  it("getAttachmentContentOver", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      structureReply("a5", CONTENT_STRUCTURE, 0),
      literalReply("a6", `BODY[${PART_PATH}]`, CONTENT_BASE64),
      logoutExchange("a7"),
    ]);

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(content.fetch.fetched).toBe(true);
    expect(wireOf(duplex)).toEqual(entryGolden("getAttachmentContentOver"));
  });

  it("listFoldersOver", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      folderListing("a4"),
      logoutExchange("a5"),
    ]);

    await listFoldersOver(duplex, principal, createSessionGate(), FAST_BOUNDS);

    expect(wireOf(duplex)).toEqual(entryGolden("listFoldersOver"));
  });

  it("listMessagesOver", async () => {
    const duplex = pageDuplex();

    const page = await listMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );

    expect(page.messages).toHaveLength(3);
    expect(wireOf(duplex)).toEqual(entryGolden("listMessagesOver"));
  });

  it("searchMessagesOver", async () => {
    const duplex = pageDuplex();

    const page = await searchMessagesOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      { keyword: "recruiter" },
      FAST_BOUNDS,
    );

    expect(page.messages).toHaveLength(3);
    expect(wireOf(duplex)).toEqual(entryGolden("searchMessagesOver"));
  });

  it("listUnreadOver", async () => {
    const duplex = pageDuplex();

    const page = await listUnreadOver(
      duplex,
      principal,
      createSessionGate(),
      MAILBOX,
      FAST_BOUNDS,
    );

    expect(page.messages).toHaveLength(3);
    expect(wireOf(duplex)).toEqual(entryGolden("listUnreadOver"));
  });

  it("appendDraftOver, no folder given", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      draftsListing("a4"),
      wire("+ Ready for literal data"),
      wire("a5 OK [APPENDUID 1237268096 92] APPEND completed"),
      logoutExchange("a6"),
    ]);

    const outcome = await appendDraftOver(
      duplex,
      principal,
      createSessionGate(),
      null,
      DRAFT,
      FAST_BOUNDS,
    );

    expect(outcome.appended).toBe(true);
    expect(wireOf(duplex)).toEqual(entryGolden("appendDraftOver, no folder given"));
  });

  it("runDiagnosticOver", async () => {
    // The one read with its own mailbox open, outside the orchestrator.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      examineReply("a4"),
      logoutExchange("a5"),
    ]);

    const { failed } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(false);
    expect(wireOf(duplex)).toEqual(entryGolden("runDiagnosticOver"));
  });
});

// ---------------------------------------------------------------------------
// The invariant over every recorded read
// ---------------------------------------------------------------------------

/** Every golden in this file, from both describes, keyed by case name. */
const ALL_GOLDENS: Record<string, Golden> = {
  ...ORCHESTRATOR_GOLDENS,
  ...ENTRY_GOLDENS,
};

const TABLE = Object.entries(ALL_GOLDENS);

/** The command word of one line: its second token, upper-cased. */
function commandOf(line: string): string {
  return (line.split(" ")[1] ?? "").toUpperCase();
}

/** The command after a `UID` prefix, or the command itself. */
function uidCommandOf(line: string): string {
  const tokens = line.split(" ");
  const first = (tokens[1] ?? "").toUpperCase();
  if (first !== "UID") return first;
  return (tokens[2] ?? "").toUpperCase();
}

describe("every recorded read opens read-only and changes nothing", () => {
  it("has enough rows to mean something", () => {
    expect(TABLE.length).toBeGreaterThanOrEqual(18);
    expect(
      TABLE.filter(([, golden]) => golden.opensMailbox).length,
    ).toBeGreaterThanOrEqual(10);
  });

  it.each(TABLE)("%s", (_name, golden) => {
    const lines = golden.lines;

    // The read-only open: once when the read opens a mailbox, never otherwise.
    const readOnlyOpens = lines.filter((line) => commandOf(line) === "EXAMINE");
    expect(readOnlyOpens).toHaveLength(golden.opensMailbox ? 1 : 0);

    // The mutating open: never, on any read.
    expect(lines.filter((line) => commandOf(line) === "SELECT")).toEqual([]);

    // A flag change: never, in either the UID form or the plain form.
    expect(lines.filter((line) => uidCommandOf(line) === "STORE")).toEqual([]);

    // Every fetch that asks for a body asks for it the peeking way, and none
    // asks for the RFC822 body synonyms. The two regexes are the ones in
    // test/service.test.ts's peeking case.
    const fetches = lines.filter((line) => uidCommandOf(line) === "FETCH");
    for (const line of fetches) {
      expect(/BODY(?!\.PEEK)\[/.test(line)).toBe(false);
      expect(/\bRFC822(?!\.SIZE)\b/.test(line)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// The file keeps its own promise
// ---------------------------------------------------------------------------

/** Drop block comments and line comments, so prose cannot count as code. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

describe("the goldens are literal", () => {
  it("uses no snapshot matcher anywhere in this file", () => {
    expect(typeof OWN_SOURCE).toBe("string");
    const code = withoutComments(OWN_SOURCE as string);

    // Non-vacuity: this is really the file, and it really compares arrays.
    expect(code.includes("ENTRY_GOLDENS")).toBe(true);
    expect(code.includes(".toEqual(")).toBe(true);

    expect(
      /\.(?:toMatch(?:Inline|File)?Snapshot|toThrowErrorMatching(?:Inline)?Snapshot)\s*\(/.test(
        code,
      ),
    ).toBe(false);
  });
});
