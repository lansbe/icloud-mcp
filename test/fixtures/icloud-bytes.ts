// Server-side byte sequences for the socket-free IMAP tests.
//
// PROVENANCE — read this before treating any byte here as evidence.
//
// Every byte in this file is SYNTHESISED. None of it was captured from
// `imap.mail.me.com`, and that is a decision rather than an omission.
//
// Plan 02-09 was written to replace this file with a real capture, and asked
// first what such a capture may leave in a permanent git history. The decision
// taken was to commit nothing captured and to build from an observed shape
// instead. It was taken with the downside visible, and it leaves the ledger
// entry that asked for real bytes OPEN rather than closed. See
// `.planning/phases/02-imap-client-mail-read/02-09-SUMMARY.md`.
//
// WHAT THESE FIXTURES ESTABLISH
//
//   - That the reader handles these FRAMING shapes: CRLF terminators, a
//     literal whose declared octet count must be consumed exactly, a literal
//     in a non-FETCH position, and a `)` that continues the same logical line
//     the literal interrupted.
//   - That the decoders above the reader handle modified-UTF-7 mailbox names,
//     RFC 2047 encoded words carrying non-ASCII, and both base64 and
//     quoted-printable transfer encodings.
//   - The SHAPE of the exchange: command ordering, tag matching, teardown
//     ordering, and the derivation of the non-synchronizing-literal flag from
//     the post-authentication capability list rather than the pre-
//     authentication one.
//
// WHAT THEY DO NOT ESTABLISH
//
//   - That iCloud emits these exact bytes. The capability strings are the
//     community-reported shapes carried in the phase research — aggregated
//     forum reporting, not an Apple document.
//   - In particular, `POST_AUTH_CAPABILITY` below advertises the
//     non-synchronizing-literal capability and THE REAL SERVER DOES NOT. That
//     is measured, not assumed: `01-IMAP-PROOF.md` records the real
//     post-authentication list, reproduced below as
//     `MEASURED_POST_AUTH_CAPABILITY`, and it is authoritative over anything
//     here. The synthesised string keeps the token deliberately, because the
//     tests built on it exist to prove the flag is read from the RIGHT LIST,
//     which needs the two lists to differ. Do not read it as an answer about
//     Apple; read `MEASURED_POST_AUTH_CAPABILITY` for that.
//   - That a real multi-paragraph HTML message, or a real message carrying an
//     attachment, round-trips. Criterion 3's "verified against real bytes"
//     claim is NOT made by this file. It moves to plan 02-11's real-mail test
//     or to manual UAT.
//
// EVERY DECLARED OCTET COUNT IS DERIVED from its payload's actual byte length
// at module load, and every base64 body is encoded from its decoded bytes
// rather than transcribed. Nothing here can be edited into disagreeing with
// its own length prefix.
//
// That is the failure the fixture-privacy decision actually names, and it is
// worth stating separately because it is INDEPENDENT of whether the bytes were
// captured or synthesised: a hand-written count invalidates itself the moment
// anyone edits the payload, and a fixture with a wrong count teaches the parser
// the WRONG framing — worse than having no fixture at all, because it fails in
// the direction of a green suite. Committing nothing captured does not address
// that hazard, so it is eliminated here by construction anyway.
//
// NOTHING ACCOUNT-IDENTIFYING APPEARS HERE, and that is a standing constraint
// on anything added later rather than an accident of synthesis: no real
// address, no `Received:` chain, no originating IP, no `X-Mailer` or
// `User-Agent`. Every address below uses the `.invalid` TLD, which RFC 6761
// reserves permanently for exactly this purpose and guarantees can never
// resolve.

const ENCODER = new TextEncoder();

/** Join lines with CRLF terminators and encode them as one server turn. */
export function wire(...lines: string[]): Uint8Array {
  return ENCODER.encode(lines.map((line) => `${line}\r\n`).join(""));
}

// ---------------------------------------------------------------------------
// Line-level constants (for the pure parser tests)
// ---------------------------------------------------------------------------

/** The connection greeting. Untagged by definition — nothing may precede it. */
export const GREETING_LINE =
  "* OK [CAPABILITY IMAP4 IMAP4rev1 SASL-IR AUTH=ATOKEN AUTH=PLAIN] iCloud ready";

/**
 * The PRE-authentication capability list.
 *
 * Note what is absent: the non-synchronizing-literal capability. Reading the
 * advertised list only here is the mistake this phase exists to avoid — it
 * produces a false negative that a later phase's APPEND design would be built
 * on.
 */
export const PRE_AUTH_CAPABILITY =
  "XAPPLEPUSHSERVICE IMAP4 IMAP4rev1 SASL-IR AUTH=ATOKEN AUTH=PLAIN";

/**
 * The POST-authentication capability list.
 *
 * Longer than the pre-authentication one, and this is normal, specified IMAP
 * behaviour rather than an iCloud quirk. This is the string the reported
 * `LITERAL+` token appears in.
 */
export const POST_AUTH_CAPABILITY =
  "XAPPLEPUSHSERVICE IMAP4 IMAP4rev1 SASL-IR AUTH=ATOKEN AUTH=PLAIN " +
  "LITERAL+ NAMESPACE UIDPLUS CHILDREN BINARY UNSELECT SORT CONDSTORE " +
  "ENABLE QRESYNC IDLE";

/**
 * The post-authentication capability list the REAL server sent.
 *
 * The one string in this file that is evidence. Measured during Phase 1's live
 * proof and recorded in `01-IMAP-PROOF.md` §1; reproduced here so the contrast
 * with the synthesised `POST_AUTH_CAPABILITY` above is visible at the point of
 * use rather than only in a planning document. It carries no account-
 * identifying data — it is a protocol advertisement, identical for every user
 * of the service — so committing it costs nothing the proof did not already
 * commit.
 *
 * Two things it settles, and both are load-bearing for Phase 4:
 *
 *   - The non-synchronizing-literal capability is ABSENT. `APPEND` must send
 *     `{N}` with no `+` and wait for the server's `+` continuation.
 *   - `XAPPLELITERAL` is present and is NOT an equivalent. It is Apple-
 *     proprietary and undocumented, and assuming it means what its name
 *     suggests is the specific mistake this measurement exists to prevent.
 */
export const MEASURED_POST_AUTH_CAPABILITY =
  "XAPPLEPUSHSERVICE IMAP4 IMAP4rev1 CONDSTORE ENABLE QRESYNC QUOTA " +
  "XAPPLELITERAL NAMESPACE UIDPLUS UNSELECT SORT ESEARCH ESORT CONTEXT=SORT " +
  "WITHIN SASL-IR ID IDLE X-APPLE-REMOTE-LINKS LIST-STATUS";

/** Representative rejection text for a wrong app-specific password. */
export const AUTH_REJECTED_TEXT =
  "[AUTHENTICATIONFAILED] Authentication failed";

/**
 * Representative rejection text for a legacy account whose username format is
 * wrong — the failure that otherwise looks identical to a wrong password.
 */
export const AUTH_REJECTED_LEGACY_TEXT =
  "[AUTHENTICATIONFAILED] LOGIN failed - unknown or invalid user";

/** Representative refusal text when the server is at its connection ceiling. */
export const CONNECTION_LIMIT_TEXT =
  "[UNAVAILABLE] Too many simultaneous connections; try again later";

/**
 * A server-side fault, named by a response code that says nothing at all about
 * the credential.
 *
 * Authentication does not succeed on this reply, and it is not a connection
 * ceiling either — so it lands in the same `authenticated: false` branch a
 * genuine credential refusal does. That collision is the whole reason
 * `credentialRefused` exists as a second, narrower fact: a password the server
 * never got as far as checking has not been refused.
 */
export const AUTH_SERVER_FAULT_TEXT = "[SERVERBUG] Internal error";

/**
 * The other server-side fault code: a human at Apple has to fix something.
 *
 * Like `[SERVERBUG]` it is a statement about the server, not a verdict on the
 * credential, so it is the second entry on `indicatesCredentialRefusal`'s
 * exclusion list and it does not start a pause.
 */
export const AUTH_CONTACTADMIN_TEXT =
  "[CONTACTADMIN] Contact your administrator";

/**
 * A refusal carrying no response code at all — prose only.
 *
 * **This one DOES read as a dead password**, per the owner decision of
 * 2026-09-22. Nothing in this repository has ever measured what
 * `imap.mail.me.com` replies to a wrong app-specific password, and plenty of
 * IMAP servers answer exactly this shape — prose, no bracketed code. Reading it
 * as "says nothing about the password" is what left the account retrying against
 * an unpublished lockout threshold on every call. See
 * `indicatesCredentialRefusal` for the full argument.
 *
 * The wording is deliberately availability-flavoured and carries no credential
 * prose at all, so no test here can pass by accident on a word like "password".
 */
export const AUTH_UNCLASSIFIED_TEXT = "Server busy, please try again";

/**
 * A prose-only refusal in the wording a real IMAP server most often uses.
 *
 * The shape the allow-list missed, spelled the way it actually arrives. Kept
 * beside `AUTH_UNCLASSIFIED_TEXT` rather than replacing it: one of the two says
 * nothing about credentials and the other says everything, and both must pause,
 * because the classifier does not read the prose at all.
 */
export const AUTH_REFUSED_PROSE_TEXT = "Authentication failed.";

/** A capability line carrying two spaces, to prove the parser does not tidy. */
export const UNTIDY_CAPABILITY_LINE = "* CAPABILITY  IMAP4rev1   liTeRaL+ ";

// ---------------------------------------------------------------------------
// Byte-level server turns (for the fake-duplex scripts)
// ---------------------------------------------------------------------------

/** The greeting turn. */
export const GREETING = wire(GREETING_LINE);

/** An untagged capability response followed by its tagged completion. */
export function capabilityResponse(tag: string, capability: string): Uint8Array {
  return wire(`* CAPABILITY ${capability}`, `${tag} OK CAPABILITY completed`);
}

/** A tagged success completion. */
export function taggedOk(tag: string, text = "completed"): Uint8Array {
  return wire(`${tag} OK ${text}`);
}

/** A tagged refusal completion carrying the server's own text. */
export function taggedNo(tag: string, text: string): Uint8Array {
  return wire(`${tag} NO ${text}`);
}

/** A tagged protocol-error completion. */
export function taggedBad(tag: string, text = "syntax error"): Uint8Array {
  return wire(`${tag} BAD ${text}`);
}

/** The LOGOUT exchange: an untagged BYE, then the tagged completion. */
export function logoutExchange(tag: string): Uint8Array {
  return wire("* BYE Logging out", `${tag} OK LOGOUT completed`);
}

/**
 * The UIDVALIDITY the scripted inbox reports.
 *
 * RFC 3501's own worked example, chosen because it exceeds 2^31 — the value is
 * unsigned 32-bit, and a signed-int assumption anywhere on this path corrupts
 * it into a negative silently. A small round number would never catch that.
 */
export const INBOX_UIDVALIDITY = 3857529045;

/** How many messages the scripted inbox holds. */
export const INBOX_EXISTS = 172;

/**
 * A read-only mailbox open, with the untagged replies a real one carries.
 *
 * `[READ-ONLY]` on the completion is what the server sends back for the
 * non-mutating form, and it is the shape the diagnostic must produce: a tool
 * whose whole purpose is observation must not mark a mailbox — or anything in
 * it — as it looks.
 */
export function examineResponse(
  tag: string,
  exists = INBOX_EXISTS,
  uidValidity = INBOX_UIDVALIDITY,
): Uint8Array {
  return wire(
    `* ${exists} EXISTS`,
    "* 0 RECENT",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    `* OK [UIDVALIDITY ${uidValidity}] UIDs valid`,
    `${tag} OK [READ-ONLY] EXAMINE completed`,
  );
}

/** A greeting that itself refuses on connection count. */
export const GREETING_AT_CONNECTION_LIMIT = wire(
  "* BYE Too many simultaneous connections from this IP; try again later",
);

/**
 * Several untagged lines before the tagged completion.
 *
 * This is the shape that breaks a reader which stops at the first line it can
 * parse, and it is entirely ordinary traffic — a server may volunteer any
 * number of untagged responses before answering the command in flight.
 */
export function untaggedFloodThenTagged(tag: string): Uint8Array {
  return wire(
    "* 3 EXISTS",
    "* 0 RECENT",
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    "* OK [UIDVALIDITY 1] UIDs valid",
    `${tag} OK completed`,
  );
}

// ---------------------------------------------------------------------------
// Derived-count builders
//
// Nothing below this line writes a byte count, a base64 body, or a decoded
// size by hand. Each is computed from the payload it describes, so editing a
// payload cannot leave a stale number behind — see the header for why that
// matters more than where the bytes came from.
// ---------------------------------------------------------------------------

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

/** Decode a base64 body to its raw bytes, so a decoded SIZE is never guessed. */
export function base64Bytes(base64: string): Uint8Array {
  const binary = atob(base64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Encode raw bytes to base64. The inverse of `base64Bytes`. */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Wrap a base64 body at MIME's 76-character line limit.
 *
 * A single-line body would not exercise the reassembly a decoder does across
 * physical lines, which is the whole reason a real attachment arrives wrapped.
 */
function wrapBase64(base64: string): string[] {
  const lines: string[] = [];
  for (let index = 0; index < base64.length; index += 76) {
    lines.push(base64.slice(index, index + 76));
  }
  return lines;
}

/**
 * One untagged FETCH reply carrying `payload` as a literal, then the tagged
 * completion.
 *
 * The declared octet count is DERIVED from the payload's byte length. Note
 * where the CRLFs are and are not: there is none between the last literal
 * octet and the `)` that follows it, because that `)` continues the SAME
 * logical line the `* n FETCH (` opened. A reader that consumed a terminator
 * there would be off by two bytes for the rest of the session.
 */
export function messageFetchReply(
  tag: string,
  payload: Uint8Array,
  options: { uid?: number; sequence?: number; flags?: string } = {},
): Uint8Array {
  const head =
    `* ${options.sequence ?? 1} FETCH (UID ${options.uid ?? 4827} ` +
    `FLAGS (${options.flags ?? ""}) ` +
    `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
    `RFC822.SIZE ${payload.byteLength} BODY[] {${payload.byteLength}}\r\n`;

  return concatBytes(
    ENCODER.encode(head),
    payload,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/**
 * The bytes of one part's BODY, taken out of a multipart source.
 *
 * Derived rather than declared, for the reason this whole section exists: a
 * body-structure fixture that states an octet count by hand invalidates itself
 * the moment anyone edits the part it describes, and it fails in the direction
 * of a green suite — the structure and the message would simply describe
 * different content while both looking plausible.
 *
 * The trailing CRLF is dropped because it belongs to the boundary delimiter
 * that follows, not to the part (RFC 2046 §5.1.1).
 */
function partBodyBytes(
  source: string,
  boundary: string,
  index: number,
): Uint8Array {
  const segment = source.split(`--${boundary}`)[index + 1] ?? "";
  const separator = segment.indexOf("\r\n\r\n");
  if (separator === -1) return new Uint8Array(0);
  return ENCODER.encode(segment.slice(separator + 4).replace(/\r\n$/, ""));
}

/**
 * One untagged FETCH reply carrying a body structure, then its completion.
 *
 * The counterpart to `messageFetchReply` above, and the reason a message fixture
 * now needs two turns rather than one: plan 02-11 split the fetch into a
 * structure round trip and a content round trip, so a conversation that scripts
 * only the content half desynchronises at the first command.
 *
 * Nothing in this reply is a literal, which is the whole point of the split —
 * its size does not depend on the message's.
 */
export function structureFetchReply(
  tag: string,
  structure: string,
  options: { uid?: number; sequence?: number; flags?: string; wireSize?: number } = {},
): Uint8Array {
  return wire(
    `* ${options.sequence ?? 1} FETCH (UID ${options.uid ?? 4827} ` +
      `FLAGS (${options.flags ?? ""}) ` +
      `INTERNALDATE "13-Aug-2026 09:14:02 -0700" ` +
      `RFC822.SIZE ${options.wireSize ?? 0} BODYSTRUCTURE ${structure})`,
    `${tag} OK UID FETCH completed`,
  );
}

/**
 * An untagged LIST reply whose mailbox NAME arrives as a literal.
 *
 * A literal outside a FETCH, which is the position a reader that special-cases
 * FETCH gets wrong. Servers use it for exactly the names that matter here:
 * a modified-UTF-7 name contains `&`, and a name containing a quote or a
 * backslash cannot be sent as a quoted string at all.
 */
export function listWithLiteralName(
  attributes: string,
  delimiter: string,
  wireName: string,
): Uint8Array {
  const bytes = ENCODER.encode(wireName);
  return concatBytes(
    ENCODER.encode(`* LIST (${attributes}) ${delimiter} {${bytes.byteLength}}\r\n`),
    bytes,
    ENCODER.encode("\r\n"),
  );
}

// ---------------------------------------------------------------------------
// A mailbox name that must survive the wire unchanged
// ---------------------------------------------------------------------------

/**
 * The RAW WIRE form, which is what a page cursor stores.
 *
 * Never the display form: storing the decoded name and re-encoding it later
 * would need an encoder this project deliberately does not have, and would
 * make the EXAMINE round trip lossy. Byte-exact by construction is the point.
 */
export const MUTF7_WIRE_NAME = "Archiv&AOk-";

/** What `decodeModifiedUtf7` must turn `MUTF7_WIRE_NAME` into. */
export const MUTF7_DISPLAY_NAME = "Archivé";

/** That name delivered the awkward way — as a literal, with a derived count. */
export const MUTF7_LIST_TURN = listWithLiteralName(
  "\\HasNoChildren",
  '"/"',
  MUTF7_WIRE_NAME,
);

// ---------------------------------------------------------------------------
// A multi-paragraph HTML message
// ---------------------------------------------------------------------------

/**
 * The subject as it arrives: an RFC 2047 Q-encoded word carrying non-ASCII.
 *
 * Q-encoding rather than B-, because the two have different hazards and this
 * one has the underscore-means-space rule that a naive decoder drops.
 */
export const HTML_MESSAGE_SUBJECT_ENCODED =
  "=?utf-8?Q?Quarterly_r=C3=A9sum=C3=A9_of_the_r=C3=B4le?=";

/** What a correct RFC 2047 decode yields. */
export const HTML_MESSAGE_SUBJECT = "Quarterly résumé of the rôle";

/**
 * The three paragraphs the HTML part carries, in order, already decoded.
 *
 * Exported as the paragraph TEXTS rather than as one expected output string,
 * because the exact shape of the extractor's output — separator, trailing
 * newline, entity handling — is plan 02-11's assertion to make, not this
 * file's to prescribe.
 */
export const HTML_MESSAGE_PARAGRAPHS = [
  "First paragraph, with a soft line break inside the encoding so the quoted-printable decoder is genuinely exercised.",
  "Second paragraph, carrying a non-ASCII character: rôle.",
  "Third paragraph, so the structure is genuinely multi-paragraph rather than a plain-text one-liner.",
];

/**
 * `multipart/alternative` with a 7bit plain part and a quoted-printable HTML
 * part.
 *
 * The HTML part carries a soft line break (a line ending in `=`), which is the
 * feature that makes quoted-printable more than an identity transform on ASCII
 * — a decoder that ignores it splits a word in half.
 */
export const HTML_MESSAGE_SOURCE = [
  'From: "Reyes, Marta" <marta.reyes@example.invalid>',
  "To: recipient@example.invalid",
  `Subject: ${HTML_MESSAGE_SUBJECT_ENCODED}`,
  "Date: Thu, 13 Aug 2026 09:14:02 -0700",
  "Message-ID: <b7d1e4f0@example.invalid>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/alternative; boundary="alt-boundary-01"',
  "",
  "--alt-boundary-01",
  "Content-Type: text/plain; charset=utf-8",
  "Content-Transfer-Encoding: 7bit",
  "",
  "First paragraph, plain text alternative.",
  "",
  "Second paragraph.",
  "",
  "Third paragraph.",
  "",
  "--alt-boundary-01",
  "Content-Type: text/html; charset=utf-8",
  "Content-Transfer-Encoding: quoted-printable",
  "",
  "<html><body>",
  "<p>First paragraph, with a soft line break inside the encoding so the quoted-=",
  "printable decoder is genuinely exercised.</p>",
  "<p>Second paragraph, carrying a non-ASCII character: r=C3=B4le.</p>",
  "<p>Third paragraph, so the structure is genuinely multi-paragraph rather than=",
  " a plain-text one-liner.</p>",
  "</body></html>",
  "",
  "--alt-boundary-01--",
  "",
].join("\r\n");

/** The same message as bytes, which is what a literal count is derived from. */
export const HTML_MESSAGE_BYTES = ENCODER.encode(HTML_MESSAGE_SOURCE);

/** A FETCH turn delivering it whole. */
export const HTML_MESSAGE_FETCH = messageFetchReply("a4", HTML_MESSAGE_BYTES, {
  uid: 4827,
  flags: "\\Seen",
});

/**
 * The body structure a server would report for the message above.
 *
 * Both octet counts are DERIVED from the parts they describe, so the structure
 * and the message cannot drift into describing different content. The line
 * counts are the one field left approximate: nothing in this project reads
 * `body-fld-lines`, and stating a derived-looking number for a field no code
 * consults would suggest a precision that is not being maintained.
 */
export const HTML_MESSAGE_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" ' +
  `${partBodyBytes(HTML_MESSAGE_SOURCE, "alt-boundary-01", 0).byteLength} 5 ` +
  'NIL NIL NIL)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" ' +
  `${partBodyBytes(HTML_MESSAGE_SOURCE, "alt-boundary-01", 1).byteLength} 7 ` +
  'NIL NIL NIL) "ALTERNATIVE" ("BOUNDARY" "alt-boundary-01") NIL NIL)';

/** The structure round trip for that message, with a derived wire size. */
export const HTML_MESSAGE_STRUCTURE_FETCH = structureFetchReply(
  "a4",
  HTML_MESSAGE_STRUCTURE,
  { uid: 4827, flags: "\\Seen", wireSize: HTML_MESSAGE_BYTES.byteLength },
);

// ---------------------------------------------------------------------------
// A message carrying an attachment
// ---------------------------------------------------------------------------

/** The attachment's filename, as the disposition declares it. */
export const ATTACHMENT_FILENAME = "quarterly-summary.pdf";

/** The attachment's declared MIME type. */
export const ATTACHMENT_MIME_TYPE = "application/pdf";

/**
 * The attachment's DECODED content.
 *
 * Long enough that its base64 wraps across several lines, so the decoder is
 * exercised across physical lines the way a real attachment forces. The bytes
 * are a PDF header and nothing more — a synthetic stand-in, not a document.
 */
const ATTACHMENT_CONTENT = ENCODER.encode(
  "%PDF-1.7\n% synthetic fixture payload, not a real document. " +
    "Its only job is to be long enough that its base64 body wraps.\n",
);

/**
 * The decoded size in bytes, DERIVED.
 *
 * This is the number an attachment listing must report, and the one a mail
 * client shows next to the filename. Deriving it is the point: written by
 * hand next to a hand-transcribed base64 body, it is the single easiest number
 * in this project to leave stale.
 */
export const ATTACHMENT_DECODED_BYTES = ATTACHMENT_CONTENT.byteLength;

/** The base64 body, ENCODED from the content above rather than transcribed. */
export const ATTACHMENT_BASE64_LINES = wrapBase64(toBase64(ATTACHMENT_CONTENT));

/** `multipart/mixed`: one text part, one base64 attachment part. */
export const ATTACHMENT_MESSAGE_SOURCE = [
  'From: "Okonkwo, Ada" <ada.okonkwo@example.invalid>',
  "To: recipient@example.invalid",
  "Subject: =?utf-8?B?U3VtbWFyeSBhdHRhY2hlZA==?=",
  "Date: Thu, 13 Aug 2026 11:02:44 -0700",
  "Message-ID: <c4e9a220@example.invalid>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="mixed-boundary-01"',
  "",
  "--mixed-boundary-01",
  "Content-Type: text/plain; charset=utf-8",
  "Content-Transfer-Encoding: 7bit",
  "",
  "The summary is attached.",
  "",
  "--mixed-boundary-01",
  `Content-Type: ${ATTACHMENT_MIME_TYPE}; name="${ATTACHMENT_FILENAME}"`,
  `Content-Disposition: attachment; filename="${ATTACHMENT_FILENAME}"`,
  "Content-Transfer-Encoding: base64",
  "",
  ...ATTACHMENT_BASE64_LINES,
  "",
  "--mixed-boundary-01--",
  "",
].join("\r\n");

/** What the B-encoded subject above decodes to. */
export const ATTACHMENT_MESSAGE_SUBJECT = "Summary attached";

/** The same message as bytes. */
export const ATTACHMENT_MESSAGE_BYTES = ENCODER.encode(ATTACHMENT_MESSAGE_SOURCE);

/** A FETCH turn delivering it whole. */
export const ATTACHMENT_MESSAGE_FETCH = messageFetchReply(
  "a4",
  ATTACHMENT_MESSAGE_BYTES,
  { uid: 4831, flags: "" },
);

/**
 * The attachment part's ENCODED octet count, as `body-fld-octets` states it.
 *
 * Derived from the wrapped base64 body the message actually carries — which is
 * the number a server counts, CRLFs included. It is deliberately exported
 * beside `ATTACHMENT_DECODED_BYTES` so the gap between the two is visible at
 * the point of use: this is the figure that must NEVER be reported as a size,
 * and the two being adjacent is what makes a confusion between them obvious.
 */
export const ATTACHMENT_ENCODED_OCTETS = partBodyBytes(
  ATTACHMENT_MESSAGE_SOURCE,
  "mixed-boundary-01",
  1,
).byteLength;

/** The body structure a server would report for the attachment message. */
export const ATTACHMENT_MESSAGE_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" ' +
  `${partBodyBytes(ATTACHMENT_MESSAGE_SOURCE, "mixed-boundary-01", 0).byteLength} 1 ` +
  `NIL NIL NIL)("APPLICATION" "PDF" ("NAME" "${ATTACHMENT_FILENAME}") NIL NIL ` +
  `"BASE64" ${ATTACHMENT_ENCODED_OCTETS} NIL ` +
  `("attachment" ("FILENAME" "${ATTACHMENT_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "mixed-boundary-01") NIL NIL)';

/** The structure round trip for that message, with a derived wire size. */
export const ATTACHMENT_MESSAGE_STRUCTURE_FETCH = structureFetchReply(
  "a4",
  ATTACHMENT_MESSAGE_STRUCTURE,
  { uid: 4831, wireSize: ATTACHMENT_MESSAGE_BYTES.byteLength },
);
