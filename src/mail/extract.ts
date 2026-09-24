// Attachment bytes in, readable text out — or a stated reason why not.
//
// Pure and CPU-bound: no socket, no binding, no I/O of any kind. It imports the
// MIME module for the converter and the ceiling it must not duplicate, and
// `unpdf` for the PDF branch, and nothing else. That is deliberate — this is the
// module that runs AFTER the session has closed, and giving it a transport
// dependency would invite a later reader to move it back inside one.
//
// **Raw bytes are never returned to the caller, on any branch (a CONTEXT
// discretion item, decided here).** A base64 blob of a binary file in a tool
// response is the token-bloat shape PITFALLS #11 describes with none of the
// benefit: the model cannot open a PDF, cannot render a JPEG, and cannot do
// anything with several megabytes of base64 except pay for it and then say it
// could not read the file. The result type has no bytes-typed field on either
// arm, so the property is held by the typechecker rather than by care.
//
// **Extracted text is UNTRUSTED CONTENT, and this module does not fence it.**
// PITFALLS #12 is explicit that text pulled out of a PDF attachment carries the
// same risk as email body text; the framing is applied one layer up, by the
// single `untrustedBlock` call site in `../mcp/untrusted.ts`, because a second
// fence would be a second thing that can drift. This module's job is to hand
// that layer a string and say what it is.
//
// This module contains no logging calls of any kind and must never acquire any.

import { extractText } from "unpdf";
import {
  MAX_EXTRACTED_TEXT_BYTES,
  decoderFor,
  htmlToText,
  truncateToBytes,
} from "./mime";

/**
 * Every media type this server will attempt to read.
 *
 * **One list, exported, because two readers need the same answer.** The
 * dispatcher below branches on it and `mail_get_attachment`'s description names
 * it, so the tool cannot advertise a type the dispatcher refuses or stay silent
 * about one it handles. A description restating the list in prose is a second
 * copy with its own lifetime, and the day they disagreed the model would be the
 * one acting on the wrong one.
 *
 * **The scope decision itself (a CONTEXT discretion item), settled here.**
 * `text/plain`, `text/html` and `application/pdf`. Nothing else, and the two
 * near misses are worth naming because both are plausible additions:
 *
 * - **`message/rfc822`.** Research § 4.3 suggested it on the grounds that
 *   postal-mime already parses one. It is declined because a forwarded message
 *   is not a file — it has its own attachments, its own sender and its own body
 *   parts, and reporting it as a flat string would flatten exactly the structure
 *   `mail_get_message` exists to present. The right shape for it is a second
 *   addressable message, not an extraction, and that is a design decision rather
 *   than a branch.
 * - **Office formats.** A `.docx` is a ZIP of XML and a `.xlsx` is worse. Both
 *   would need a new dependency with its own supply-chain audit for a case this
 *   project has never observed, against a phase that already spent a blocking
 *   human checkpoint on one package pin.
 *
 * Everything off this list returns `unsupported-type` NAMING the type, which is
 * a more useful answer than an empty string and a shrug: the model can tell the
 * user "that is a spreadsheet and I cannot read it" instead of "I got nothing".
 */
export const EXTRACTABLE_TYPES = [
  "text/plain",
  "text/html",
  "application/pdf",
] as const;

/**
 * The largest PDF this server hands to the parser.
 *
 * **Calibrated from probe U2, and the arithmetic is the point.**
 * `test/probes.test.ts` measured a 600-page, 2 443 588-byte text-heavy document
 * extracting in 640 ms inside real workerd, cross-checked at 546 ms on Node's
 * true wall clock. That is 3 818 bytes per millisecond. Against the same 5 000 ms
 * the abort criterion was stated in, a BENIGN document could be about 19 MB.
 *
 * This ceiling is 2 MiB — a factor of eight below that. The margin is not
 * timidity: **the measured rate is for a benign document, and a hostile one's
 * per-byte cost is unmeasured.** A PDF is a container format with compressed
 * streams, an object graph that may be cyclic, and font programs that are
 * themselves interpreted; nothing in probe U2 bounds what an attacker-composed
 * document costs per byte, and the honest response to an unmeasured worst case
 * is headroom rather than a number that looks precise.
 *
 * **Calibrated, not measured**, in `MAX_ATTACHMENT_PART_OCTETS`'s sense — the
 * benign rate is measured, the safety factor is a judgement, and a later session
 * revising this should revise the factor on evidence about hostile documents
 * rather than reason afresh from the benign figure.
 *
 * Two MiB also matches every other ceiling this project ships
 * (`MAX_WIRE_MESSAGE_BYTES`, `MAX_LITERAL_OCTETS`, `MAX_EXTRACTED_TEXT_BYTES`),
 * which is a consistency argument rather than a coincidence: they are all the
 * same "one operation must not be unbounded" limit seen from different sides.
 *
 * **It is reachable, and that matters.** `MAX_ATTACHMENT_PART_OCTETS` is 8 MiB
 * of ENCODED octets, which is roughly 5.8 MiB decoded once base64's 1.37x comes
 * off — comfortably above this, so `source-too-large` is a branch a real message
 * can reach rather than dead code guarded by a tighter limit upstream.
 *
 * The refusal happens BEFORE `extractText` is called. That ordering is the whole
 * mitigation for T-04-07-02: a ceiling checked after the expensive thing ran has
 * spent exactly what it existed to save.
 */
export const MAX_PDF_SOURCE_BYTES = 2 * 1024 * 1024;

/**
 * What one extraction produced, or the reason there is nothing to produce.
 *
 * **The refusal is a field on a SUCCESSFUL result, and this is the shape that
 * makes criterion 5's "clear reason" survive a closed error vocabulary.** The
 * precedent is `searchPage`'s `unsupportedCharset`, whose docstring gives the
 * argument in the concrete: the call RAN, this server declined or could not
 * proceed, and none of the four values in the FND-05 vocabulary describes that
 * honestly — `not_found` would tell the model the attachment does not exist,
 * and `connection_failed` would tell it to retry something that will fail
 * identically every time. `readAttachmentPart` one layer down returns
 * `part-too-large` on exactly these terms.
 *
 * A fifth category for "too big" was rejected by D-35 and the rejection is
 * restated in three shipped docstrings and inherited by Phases 3 through 6. It
 * stays closed. What the model gets instead is the declared type and, where
 * relevant, the two numbers — which is a clearer reason than any error string,
 * because it is something the model can explain to the user rather than a
 * sentence it has to parse.
 *
 * **No arm carries bytes** (T-04-07-05). The success arm's four keys and the
 * refusal arm's five are the whole surface, and `test/attachments.test.ts`
 * asserts both key sets exactly so a later addition cannot slip one in.
 */
export type ExtractResult =
  | {
      extracted: true;
      /** The document's text. Stranger-authored, and fenced by the caller. */
      text: string;
      /** Whether `MAX_EXTRACTED_TEXT_BYTES` cut it. Never a refusal. */
      truncated: boolean;
      /** The normalised media type this text was read out of. */
      sourceType: string;
    }
  | {
      extracted: false;
      /**
       * Why there is no text, in four values this server chose.
       *
       * `no-text-layer` is a scanned document: real pages, no characters.
       * `unsupported-type` is a file this server will not attempt.
       * `source-too-large` is a PDF past `MAX_PDF_SOURCE_BYTES`.
       * `unreadable` is a document the parser could not open at all.
       *
       * **`unreadable` and `no-text-layer` are different facts and must not be
       * collapsed.** The first says the file is not a readable document of its
       * declared type — truncated, corrupt in its cross-reference table, or
       * encrypted. The second says the document is fine and has no character
       * layer, which is what a scan looks like and is the answer that lets the
       * model say "this is scanned; I cannot read it, and this server does not
       * do OCR." Telling the user a corrupt file is a scan is a wrong statement
       * about their file, and the reverse sends them looking for OCR that would
       * not have helped.
       */
      refusal:
        | "no-text-layer"
        | "unsupported-type"
        | "source-too-large"
        | "unreadable";
      /** The normalised media type that was refused, named rather than hidden. */
      sourceType: string;
      /** The source size, on a size refusal only. */
      sizeBytes?: number;
      /** `MAX_PDF_SOURCE_BYTES`, so the two numbers travel together. */
      limitBytes?: number;
    };

/**
 * The bare media type, lowercased, with any parameters removed.
 *
 * A part may declare `Text/Plain; charset=UTF-8`, and RFC 2045 makes the type
 * and subtype case-insensitive. A dispatcher keyed on the raw string would
 * refuse that legal spelling as unsupported, so the normalisation happens once
 * here and the normalised value is what gets REPORTED too — the model is told
 * `text/plain`, which is true, rather than the sender's exact casing, which
 * carries no information and would make two identical refusals look different.
 */
function normaliseType(declared: string): string {
  const [bare] = declared.split(";");
  return bare.trim().toLowerCase();
}

/**
 * Apply the shipped extracted-text ceiling, and nothing else.
 *
 * `MAX_EXTRACTED_TEXT_BYTES` truncates and sets a flag; it never raises, and its
 * docstring already carries the no-fifth-category argument for why. That
 * disposition is right here for the reason it is right on the body path and
 * wrong on the part-fetch path one layer down: **a partial answer is still an
 * answer when the thing being produced is text a human will read**, and it is a
 * corrupt file when the thing being produced is a file. This module produces
 * text, so it truncates. `readAttachmentPart` produces a file, so it refuses.
 *
 * A second ceiling was deliberately not invented. The existing one is
 * byte-measured, applied once to the assembled string, and already reasoned
 * about in `mime.ts`; a parallel constant here would be a second number to keep
 * in step with no argument for why the two should ever differ.
 */
function bounded(text: string, sourceType: string): ExtractResult {
  const { text: capped, truncated } = truncateToBytes(
    text,
    MAX_EXTRACTED_TEXT_BYTES,
  );
  return { extracted: true, text: capped, truncated, sourceType };
}

/**
 * Read a PDF's text layer, or say why there is none.
 *
 * **Built against probe U3's MEASUREMENT, not against the assumption research
 * carried.** `04-RESEARCH.md` § 4.2 marked the scanned image-only case
 * `[ASSUMED]`; U3 measured it inside real workerd and it resolves with
 * `{ totalPages: 1, text: "" }`. Two things follow, and both are load-bearing:
 *
 * - **The branch is a check on the string, not a `catch`.** A `no-text-layer`
 *   arm written as an exception handler would never fire, because nothing
 *   throws. U3's second case asserts the promise resolves, so that mistake fails
 *   in the suite rather than in front of a user holding a scanned document.
 *
 *   **That argument is about `no-text-layer` only, and it does NOT extend to
 *   "therefore no `catch` is needed at all"** — which is exactly how it reads
 *   at a glance, and why the limit is written down. A SCANNED document
 *   resolves; a MALFORMED one rejects, and pdf.js rejects on a truncated file,
 *   a corrupt cross-reference table or an encrypted document. A
 *   sender-authored attachment is precisely where a malformed PDF arrives, so
 *   the rejection is reachable from a stranger's mail. Unhandled it propagates
 *   to `mailErrorResult`, where an unrecognised class becomes
 *   `connection_failed` — the floor, which still offers a retry — for a
 *   document that will fail identically on every retry. The union already had the right shape for
 *   this; it only lacked a member, which `unreadable` now is.
 * - **An empty string must not be returned as a success.** To a model, `text:
 *   ""` on a successful extraction reads as "this document is blank", which is a
 *   different and false statement about a page full of scanned words. The
 *   refusal is what lets it say the true thing: there are pages, there is no
 *   text layer, and this server does not do OCR.
 *
 * `.trim()` rather than a length check, because pdf.js emits page separators
 * even for pages with no content, so an image-only document can come back as a
 * short run of newlines rather than as the empty string exactly.
 *
 * **The array is COPIED before it is handed over, and that is a mitigation
 * rather than a habit.** Probe U4 measured that `extractText` DETACHES its
 * input: after the call the caller's own `Uint8Array` has `byteLength === 0` and
 * a second call on it rejects. Nothing in `unpdf`'s documentation says so.
 * Anything upstream that extracted and then measured, hashed or re-read those
 * bytes would silently get zero, so this module does not consume what it was
 * lent.
 */
async function extractPdf(
  bytes: Uint8Array,
  sourceType: string,
): Promise<ExtractResult> {
  if (bytes.byteLength > MAX_PDF_SOURCE_BYTES) {
    return {
      extracted: false,
      refusal: "source-too-large",
      sourceType,
      sizeBytes: bytes.byteLength,
      limitBytes: MAX_PDF_SOURCE_BYTES,
    };
  }

  // `mergePages: true` selects the overload returning ONE string. The per-page
  // overload returns an array whose `.length` is a PAGE COUNT, and a byte
  // ceiling applied to that would silently bound the wrong quantity — probe U1's
  // second case pins both arms so the distinction cannot be lost in a refactor.
  // No defensive array branch here: the typechecker types the other arm `never`,
  // which is a stronger statement than a runtime check and does not rot.
  let merged: string;
  try {
    ({ text: merged } = await extractText(bytes.slice(), {
      mergePages: true,
    }));
  } catch {
    // The caught value is never read. A parser's message quotes the document it
    // failed on, and the document is stranger-authored.
    return { extracted: false, refusal: "unreadable", sourceType };
  }

  if (merged.trim().length === 0) {
    return { extracted: false, refusal: "no-text-layer", sourceType };
  }

  return bounded(merged, sourceType);
}

/**
 * Turn one attachment's decoded bytes into readable text, or refuse by name.
 *
 * The bytes arrive ALREADY transfer-decoded. That split is deliberate and is
 * inherited from `getAttachmentBytes`'s docstring one layer down: the transfer
 * decode is arithmetic over megabytes and has no business happening while a
 * socket is held open, so the caller does it after the session closes and hands
 * the result here. This module therefore never sees a base64 line, a
 * quoted-printable escape, or anything else about how the bytes travelled.
 *
 * `charset` is the part's own declared parameter, or `null`. It matters only for
 * the two text branches: a `text/plain` attachment written in latin-1 decodes to
 * replacement characters if the decoder is hardcoded to UTF-8, and a recruiter's
 * European name is exactly where that shows up. `decoderFor` is the shipped
 * helper and already answers an unrecognised charset with a UTF-8 fallback
 * rather than a throw.
 *
 * **The html branch calls `htmlToText`, and writing a second converter here
 * would be a security regression rather than a duplication.** That function is
 * `HTMLRewriter`-based, was probed rather than assumed, and carries a skip
 * counter that exists because the obvious implementation put attacker-authored
 * `<script>` source into the extracted string (probe A4, second half). It also
 * carries the void-element guard probe P2 forced and the handler-ordering guard
 * probe P4 forced. Reproducing that badly is how an attachment becomes a worse
 * injection vector than the message body it arrived on.
 *
 * `"omit-links"` rather than `"emit-links"`, and the asymmetry with the body
 * path is deliberate: a body's links are what the user asked about — a meeting
 * URL, a job posting — whereas an HTML attachment is usually a saved page or a
 * marketing artefact whose link volume would swamp the prose it came for.
 *
 * Never throws for a content reason. Every outcome this module can foresee is a
 * value on the returned union, so the tool boundary above reaches
 * `mailErrorResult` only for a genuine transport or authentication failure and
 * the four-value vocabulary stays closed.
 *
 * **That claim is held by a `catch` in `extractPdf`, not by the absence of
 * anything that throws**, and the difference is worth stating because the claim
 * was once true only by inspection. The PDF parser rejects on a document it
 * cannot open, and a sender-authored attachment is where such a document
 * arrives; the rejection becomes the `unreadable` refusal rather than escaping.
 * A later branch added here that awaits any parser owes the union the same
 * treatment.
 */
export async function extractAttachmentText(
  bytes: Uint8Array,
  declaredType: string,
  charset: string | null,
): Promise<ExtractResult> {
  const sourceType = normaliseType(declaredType);

  if (sourceType === "application/pdf") {
    return extractPdf(bytes, sourceType);
  }

  if (sourceType === "text/plain") {
    return bounded(decoderFor(charset).decode(bytes), sourceType);
  }

  if (sourceType === "text/html") {
    const markup = decoderFor(charset).decode(bytes);
    return bounded(await htmlToText(markup, "omit-links"), sourceType);
  }

  return { extracted: false, refusal: "unsupported-type", sourceType };
}
