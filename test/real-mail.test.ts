// Criterion 3, against the two message SHAPES it names — and an honest label on
// what that does and does not establish.
//
// ─── READ THIS BEFORE TREATING ANY BYTE HERE AS EVIDENCE ────────────────────
//
// The plan that commissioned this file described it as verifying criterion 3
// "against the real captured bytes". **There are no real captured bytes.** Plan
// 02-09 asked, at a blocking checkpoint, what a capture from a personal mail
// account may leave in a permanent git history, and the answer was option C:
// commit nothing captured, build from an observed shape instead. Its summary
// records the consequence in as many words — criterion 3's "verified against
// real bytes" claim "is NOT made by this plan… It moves to 02-11's real-mail
// test or to manual UAT."
//
// This file takes the half it can honestly take, and does not take the other.
//
//   WHAT IT ESTABLISHES. That THIS CLIENT, driven end to end through the real
//   byte-counted reader and the real two-round-trip fetch, handles the two
//   message shapes criterion 3 names: a multi-paragraph HTML message with a
//   quoted-printable body and an RFC 2047 encoded subject, and a message
//   carrying a base64 attachment whose reported size is the decoded one. No
//   shortcut past the transport, because the literal framing is half of what is
//   being verified — though see the first case below for how narrowly the
//   framing half is actually pinned HERE, as opposed to in the reader's own
//   tests.
//
//   WHAT IT DOES NOT ESTABLISH. That iCloud emits these bytes. Every byte below
//   comes from `./fixtures/icloud-bytes.ts`, which says of itself that every
//   byte in it is synthesised. A fixture cannot evidence a server's behaviour
//   however carefully it is written, and calling this file `real-mail` does not
//   change that — the name is the plan's; the disclaimer is this file's.
//
// So a failure here is a finding about THIS CLIENT and about nothing else. The
// remaining half of criterion 3 — that a real message from this account round
// trips — is a human-run verification, recorded in `02-VALIDATION.md`.
//
// ─── AND WHY NOTHING HERE LOGS IN ───────────────────────────────────────────
//
// D-09 forbids any automated job in this repository from authenticating against
// the real Apple ID, and plan 02-09 declined to create a capture entry point on
// exactly that ground (T-02-32: a live-credential entry point that dumps raw
// server bytes is unused attack surface). No opt-in live path was added here
// either, and none should be: this file opens no socket and reads no
// credential, so `npx vitest run` on a machine with no secrets configured is
// green and silent, with nothing to gate.

import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { createSessionGate, getMessageOver } from "../src/mail/service";
import { messageToolResult } from "../src/mcp/tools/mail";
import {
  assertMailSecretsBound,
  entryEnv,
  ownerPrincipal,
  type BoundMailSecrets,
} from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  ATTACHMENT_DECODED_BYTES,
  ATTACHMENT_ENCODED_OCTETS,
  ATTACHMENT_FILENAME,
  ATTACHMENT_MESSAGE_BYTES,
  ATTACHMENT_MESSAGE_STRUCTURE,
  ATTACHMENT_MESSAGE_SUBJECT,
  ATTACHMENT_MIME_TYPE,
  GREETING,
  HTML_MESSAGE_BYTES,
  HTML_MESSAGE_PARAGRAPHS,
  HTML_MESSAGE_SUBJECT,
  HTML_MESSAGE_SUBJECT_ENCODED,
  HTML_MESSAGE_STRUCTURE,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  messageFetchReply,
  structureFetchReply,
  taggedOk,
} from "./fixtures/icloud-bytes";
import type { Principal } from "../src/principal";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

/** Bounds a few milliseconds wide, so no case here waits out a real timeout. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 400,
};

const MAILBOX = "INBOX";

/**
 * The whole conversation, with the fixture's message as its two fetch turns.
 *
 * Tagged `a5` and `a6` rather than driven from the fixture's own pre-built
 * turns, because those carry the single-round-trip tag from before the fetch was
 * split. The PAYLOAD is the fixture's, byte for byte — only the tag differs, and
 * a tag belongs to the conversation rather than to the message.
 */
function conversation(
  structure: string,
  message: Uint8Array,
  uid: number,
  flags = "",
) {
  return createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4"),
    structureFetchReply("a5", structure, {
      uid,
      flags,
      wireSize: message.byteLength,
    }),
    messageFetchReply("a6", message, { uid, flags }),
    logoutExchange("a7"),
  ]);
}

const HTML_UID = 4827;
const ATTACHMENT_UID = 4831;

function refFor(uid: number) {
  return { mailbox: MAILBOX, uidValidity: INBOX_UIDVALIDITY, uid };
}

// ---------------------------------------------------------------------------
// The multi-paragraph HTML message
// ---------------------------------------------------------------------------

describe("a multi-paragraph HTML message, driven through the real reader", () => {
  async function fetchHtmlMessage(includeHtml = false) {
    const duplex = conversation(
      HTML_MESSAGE_STRUCTURE,
      HTML_MESSAGE_BYTES,
      HTML_UID,
      "\\Seen",
    );
    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      refFor(HTML_UID),
      { ...FAST_BOUNDS, includeHtml },
    );
    return { duplex, detail };
  }

  it("runs both round trips in order and reaches its logout", async () => {
    // **What this proves, stated narrowly because it was measured.** It proves
    // the conversation survives a literal-bearing FETCH reply: two commands,
    // in the right order, and the tagged logout still reached afterwards.
    //
    // It does NOT prove the literal was consumed by EXACT count, and asserting
    // that it did would be an overclaim. Mutating `readOctets` to take one
    // octet too few, twenty too few, and one too many each left this file
    // entirely green: the bytes at the tail of these fixtures are a closing
    // MIME delimiter the parser tolerates the absence of, and the reader
    // absorbs the stray remainder into the following line rather than losing
    // the tag. Byte-exactness is pinned where it can be pinned — directly
    // against the reader, in `test/icloud-fixtures.test.ts` and
    // `test/imap-session.test.ts` — not here.
    const { duplex } = await fetchHtmlMessage();

    expect(duplex.writtenLines().at(-1)).toBe("a7 LOGOUT");
    expect(duplex.writtenLines().filter((line) => line.includes("FETCH"))).toEqual([
      `a5 UID FETCH ${HTML_UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
      `a6 UID FETCH ${HTML_UID} BODY.PEEK[]`,
    ]);
  });

  it("preserves the paragraph structure of the readable body", async () => {
    // Asserted as a SEPARATION COUNT and as each paragraph's opening words,
    // rather than against the whole body as one string. A body compared whole
    // fails as a single opaque diff; this localises — a lost blank line fails
    // the count, a mangled paragraph fails its own line.
    const { detail } = await fetchHtmlMessage();

    const paragraphs = detail.text
      .trim()
      .split(/\r?\n\s*\r?\n/)
      .map((one) => one.trim())
      .filter((one) => one.length > 0);

    expect(paragraphs).toHaveLength(3);
    expect(paragraphs[0]!.startsWith("First paragraph")).toBe(true);
    expect(paragraphs[1]!.startsWith("Second paragraph")).toBe(true);
    expect(paragraphs[2]!.startsWith("Third paragraph")).toBe(true);
  });

  it("prefers the plain alternative, and says so", async () => {
    const { detail } = await fetchHtmlMessage();

    expect(detail.bodySource).toBe("text/plain");
    expect(detail.truncated).toBe(false);
  });

  it("rejoins the HTML part's soft line break and decodes its non-ASCII", async () => {
    // The two hazards that make quoted-printable more than an identity
    // transform on ASCII, and they live in the HTML half of this message: a
    // line ending in `=` that a naive decoder leaves splitting a word, and
    // `=C3=B4` that a naive decoder leaves as three literal characters.
    //
    // Asserted against the paragraph texts VERBATIM. A decoder that dropped the
    // soft break without rejoining would leave `quoted-` and `printable` as two
    // words, which no substring check on a shorter fragment would notice.
    const { detail } = await fetchHtmlMessage(true);

    expect(detail.html).not.toBeNull();
    for (const paragraph of HTML_MESSAGE_PARAGRAPHS) {
      expect(detail.html!).toContain(paragraph);
    }
    expect(detail.html!).toContain("rôle");
  });

  it("decodes the encoded-word subject to its real characters", async () => {
    // The decoded form, not the encoded one. Asserting `toContain("Quarterly")`
    // would pass against a subject still reading `Quarterly_r=C3=A9sum=C3=A9`.
    const { detail } = await fetchHtmlMessage();

    expect(detail.subject).toBe(HTML_MESSAGE_SUBJECT);
    expect(detail.subject).toContain("résumé");
    expect(detail.subject).toContain("rôle");
    expect(detail.subject).not.toContain("=?utf-8?Q?");
    expect(detail.subject).not.toBe(HTML_MESSAGE_SUBJECT_ENCODED);
  });

  it("carries the sender's display name AND address, as two distinct values", async () => {
    // Both halves, and distinct. A parser that filled the display name from the
    // address produces a plausible-looking result and loses the only part of
    // the pair a sender freely chose.
    const { detail } = await fetchHtmlMessage();

    expect(detail.fromName).toBe("Reyes, Marta");
    expect(detail.fromAddress).toBe("marta.reyes@example.invalid");
    expect(detail.fromName).not.toBe(detail.fromAddress);
  });
});

// ---------------------------------------------------------------------------
// The message carrying an attachment
// ---------------------------------------------------------------------------

describe("a message carrying an attachment, driven through the real reader", () => {
  async function fetchAttachmentMessage() {
    const duplex = conversation(
      ATTACHMENT_MESSAGE_STRUCTURE,
      ATTACHMENT_MESSAGE_BYTES,
      ATTACHMENT_UID,
    );
    const detail = await getMessageOver(
      duplex,
      principal,
      createSessionGate(),
      refFor(ATTACHMENT_UID),
      FAST_BOUNDS,
    );
    return { duplex, detail };
  }

  it("reports the filename and the lowercased media type the sender declared", async () => {
    const { detail } = await fetchAttachmentMessage();

    expect(detail.attachments).toHaveLength(1);
    expect(detail.attachments[0]!.filename).toBe(ATTACHMENT_FILENAME);
    expect(detail.attachments[0]!.mimeType).toBe(ATTACHMENT_MIME_TYPE);
    expect(detail.attachments[0]!.disposition).toBe("attachment");
  });

  it("reports the DECODED size, materially below the declared octet count", async () => {
    // The specific trap this case exists for. `body-fld-octets` sits exactly
    // where a size field would sit and looks entirely plausible; base64 runs
    // ~1.37x, so reporting it raw tells a user their 135 KB PDF is 180 KB.
    //
    // Both directions are asserted. The gap against the declared count proves
    // the conversion happened at all; the match against the derived decoded
    // length proves it converted to the RIGHT number rather than merely to a
    // smaller one.
    const { detail } = await fetchAttachmentMessage();
    const reported = detail.attachments[0]!.sizeBytes;

    expect(reported).toBeLessThan(ATTACHMENT_ENCODED_OCTETS * 0.8);
    expect(reported).toBeGreaterThanOrEqual(ATTACHMENT_DECODED_BYTES);
    // The tolerance is the MIME line-wrapping overhead the octet count carries
    // and the decoded length does not — see `sizesAgree` in `src/mail/service.ts`
    // for the derivation. It is a bound on noise, not a licence to be wrong.
    expect(reported - ATTACHMENT_DECODED_BYTES).toBeLessThanOrEqual(
      Math.ceil(ATTACHMENT_DECODED_BYTES / 8) + 3,
    );
  });

  it("agrees with the parsed message about which file is attached", async () => {
    // Two independent derivations — the structure walk and the MIME parse —
    // reaching the same answer by different routes. This is the case that would
    // fail if the structure fixture and the message fixture drifted apart, which
    // is why both octet counts are derived from the message rather than stated.
    const { detail } = await fetchAttachmentMessage();

    expect(detail.attachmentsDisagree).toBe(false);
  });

  it("returns the message's OWN body, not the attachment's content", async () => {
    // The failure this catches is a body that renders the attachment: a walk
    // that let an attached part become the primary body would return `%PDF-1.7`
    // as the message text, which is both wrong and a small data leak into a
    // field a user reads as prose.
    const { detail } = await fetchAttachmentMessage();

    expect(detail.text).toContain("The summary is attached.");
    expect(detail.text).not.toContain("%PDF");
    expect(detail.text).not.toContain("synthetic fixture payload");
    expect(detail.bodySource).toBe("text/plain");
  });

  it("decodes the B-encoded subject", async () => {
    const { detail } = await fetchAttachmentMessage();

    expect(detail.subject).toBe(ATTACHMENT_MESSAGE_SUBJECT);
    expect(detail.subject).not.toContain("=?utf-8?B?");
  });
});

// ---------------------------------------------------------------------------
// And across both
// ---------------------------------------------------------------------------

describe("neither shaped result carries a credential", () => {
  // Narrowed by assertion, never by a coalesce: `?? ""` would typecheck and
  // keep both cases below green while making `not.toContain("")` trivially
  // true, which is exactly what the non-zero-length guards prevent.
  const entry = entryEnv();
  assertMailSecretsBound(entry);
  const bound: BoundMailSecrets = entry;

  const cases: [string, string, Uint8Array, number][] = [
    ["the HTML message", HTML_MESSAGE_STRUCTURE, HTML_MESSAGE_BYTES, HTML_UID],
    [
      "the attachment message",
      ATTACHMENT_MESSAGE_STRUCTURE,
      ATTACHMENT_MESSAGE_BYTES,
      ATTACHMENT_UID,
    ],
  ];

  for (const [label, structure, message, uid] of cases) {
    it(`contains neither bound value: ${label}`, async () => {
      expect(bound.APPLE_ID.length).toBeGreaterThan(0);
      expect(bound.APPLE_APP_PASSWORD.length).toBeGreaterThan(0);

      const detail = await getMessageOver(
        conversation(structure, message, uid),
        principal,
        createSessionGate(),
        refFor(uid),
        { ...FAST_BOUNDS, includeHtml: true },
      );

      // The WHOLE response, both blocks. Unlike the tool-boundary cases, no
      // fixture here embeds a credential in its own content, so there is no
      // stranger-authored copy to carve out — anything matching would be ours.
      const whole = messageToolResult(detail)
        .content.map((block) => block.text)
        .join("\n");

      expect(whole).not.toContain(bound.APPLE_ID);
      expect(whole).not.toContain(bound.APPLE_APP_PASSWORD);
    });
  }
});
