// The opaque identifier layer. Every message and every page in this phase is
// addressed by a token minted here and by nothing else.
//
// This is D-11's zero-parameter `connectImap()` reasoning applied to message
// identity. The goal is not that a UID paired with the wrong folder is
// *rejected* — it is that the pairing is unspeakable, because no caller ever
// holds a bare UID to pair. Mailbox, UIDVALIDITY and UID travel together or not
// at all.
//
// Pure, and attached to nothing but the one error class below and the neutral
// byte-level codec in `../tokens`: no socket, no transport module, no runtime
// dependency. It therefore unit-tests against literal strings with nothing
// stood up, the same shape `imap-parser.ts` keeps.
//
// The codec moved up because calendar and contacts identifiers need exactly the
// same strictness, and D-56's argument about a second nonce implementation is
// the argument here too — one codec drifts nowhere, two drift apart. What did
// NOT move is the refusal a caller sees: `fromBase64Url` throws a neutral
// `TokenDecodeError`, and translating it into this tree's `ImapNotFoundError`
// is this module's own responsibility. See `decodePayload` for where that
// happens and why it is the only place it needs to.
//
// This module contains no logging calls of any kind and must never acquire any.

import { ImapNotFoundError } from "../errors";
import {
  TOKEN_DECODER,
  TOKEN_ENCODER,
  fromBase64Url,
  toBase64Url,
} from "../tokens";

/**
 * The wire format version, written into every token and checked on every
 * decode.
 *
 * Bumping this is a DECISION, not a refactor. The format is a one-way door:
 * these tokens are what every mail tool accepts, Phase 4's draft-reply tool
 * will accept them too, and a token already handed to a model or saved in a
 * client transcript stops working the moment the format changes. There is no
 * migration path for an identifier that has already left the building.
 *
 * The field exists from day one as the cheapest possible hedge on that. It buys
 * one property and it is worth the bytes: a future format change becomes
 * *detectable* — an old token is refused outright — rather than silently
 * misread as the new shape.
 */
export const TOKEN_VERSION = 1;

/**
 * The kind discriminator. One codec serves both token types, so this is what
 * keeps them from being interchangeable.
 *
 * Without it, a page cursor handed where a message id is expected would decode
 * *successfully* into a nonsense reference, and the caller would fetch whatever
 * UID happened to sit in the `lastUid` slot. That is precisely the "wrong
 * message, silently" failure MAIL-06 exists to prevent, and it is the reason
 * one shared codec was chosen over two: the cross-use refusal is a single rule,
 * and a rule living in two decoders is a rule that drifts.
 *
 * The two payloads additionally name their UID field differently (`u` against
 * `l`), so a token that somehow cleared the kind check would still fail the
 * required-field check. Two independent barriers, because this one matters.
 */
const KIND_MESSAGE = "m";
const KIND_CURSOR = "c";

/**
 * The third kind: a folder, named without its contents.
 *
 * Added by plan 02-10, which is the first plan whose tool hands the model a
 * FOLDER rather than a message or a position. It lives here rather than beside
 * the listing operation because this module's own header is unconditional —
 * every identifier in this phase is minted here and nowhere else — and a second
 * codec somewhere else is exactly the drift that header exists to prevent.
 *
 * It carries no UIDVALIDITY, and that is not an omission. A folder listing
 * opens no mailbox, so no validity has been reported for any of these folders
 * and inventing one would be a claim this server cannot make. The validity gate
 * still runs wherever a folder token is later turned into an open mailbox: the
 * mailbox is opened there, the server states its validity there, and the
 * message ids minted from that point carry it.
 *
 * The field-shape barrier the two kinds above rely on holds here more strongly
 * rather than less: this payload has no numeric field AT ALL, so a folder token
 * fed where a message id is expected fails the kind check and would fail the
 * required-field check behind it.
 */
const KIND_FOLDER = "f";

/**
 * The fourth kind: one attachment of one message, named by its part path.
 *
 * Added by plan 04-02 (D-76), the first plan whose tool hands the model a PART
 * of a message rather than the message. It lives here rather than beside the
 * attachment fetch for the same unconditional reason the folder kind does —
 * every identifier this project mints is minted in this module and nowhere else
 * — and D-77 rejected the alternative by name: a separate minter in its own
 * tree creates two kind namespaces, and two namespaces can assign the same
 * letter to two different things.
 *
 * The letter is `a`, and it is a DECISION rather than a spelling, for the
 * reason `TOKEN_VERSION` above states: the format is published MCP surface the
 * moment any id is handed out, and there is no migration path for an identifier
 * that has already left the building. D-76 is rated one-way on exactly that.
 * `a` and `s` were chosen over any other pair because neither collides with
 * `m`, `c` or `f` and both are mnemonic, so a token dump stays readable.
 *
 * This is D-18 extended one level. The payload is a message payload plus one
 * field: `m`, `uv` and `u` spelled exactly as `encodeMessageId` writes them,
 * and `p` for the IMAP part path. Rejected: a message id paired with an array
 * index — a small integer a model can guess or transpose, needing a second
 * structure walk to resolve — and a message id paired with a raw part path,
 * which is hand-constructible and addresses ANY part including the body, which
 * is precisely the value class D-18 exists to make unspeakable.
 *
 * The field-shape barrier behind the kind check holds in both directions, and
 * the two directions are NOT symmetric — which is why both are asserted rather
 * than one. A message id fed to the attachment decoder fails the kind check and
 * would then fail the required-field check behind it, because no other kind's
 * payload carries `p` at all. An attachment id fed to the message decoder fails
 * the kind check ALONE: its `m`, `uv` and `u` are genuinely a message's, and the
 * extra `p` is a field that decoder never reads. That asymmetry is the whole
 * reason the kind is checked before any field is read.
 */
const KIND_ATTACHMENT = "a";

/**
 * The fifth kind: a file staged in a bucket, waiting to be attached.
 *
 * Added by plan 04-02 (D-77). This kind names no message at all, which makes it
 * the strongest case for this module's header rather than an exception to it: a
 * staged file is not a mail concept, and giving it its own minter in its own
 * tree was considered and rejected precisely because the cross-use refusal must
 * stay ONE rule covering every identifier the model holds. A staged id handed
 * where an attachment id belongs is refused by the same check that already
 * refuses a cursor handed where a message id belongs, and it is refused there
 * because both route through `decodePayload`. Two decoders would be two rules,
 * and a rule living in two places is a rule that drifts. Also rejected: a plain
 * bucket object key — a constructible string, with no version field and no
 * cross-use refusal at all.
 *
 * The letter is `s`; see `KIND_ATTACHMENT` for why the pair was chosen and why
 * choosing it was a one-way decision rather than a naming preference.
 *
 * The field-shape barrier holds here more strongly than for any other kind:
 * this payload has NO UIDVALIDITY and NO UID — it names an object in a bucket,
 * not a message — so it shares not one field name with the other four. Its
 * fields are `o` for the object key and `x` for the expiry. A staged token fed
 * where a message id is expected fails the kind check and would fail the
 * required-field check behind it; an attachment token fed to the staged decoder
 * fails the same way in reverse.
 *
 * **`o` rather than `key`.** Every payload already carries a `k` — the kind
 * discriminator. A field named `key` sitting beside it puts `payload.k` one
 * character away from `payload.key`, and `payload.k` is a non-empty string on
 * every well-formed token, so that typo would sail through a string assertion
 * and hand back a reference whose object key is the letter `s`. A wrong answer
 * with no error is the single outcome this module exists to refuse, so the
 * collision is removed rather than guarded against.
 *
 * **The expiry is ABSOLUTE** — an epoch-millisecond instant baked into the
 * token at mint time — rather than a mint timestamp that decode compares
 * against a TTL constant. That makes D-82's ordering unreachable by
 * construction instead of merely observed. D-82 needs the token to die BEFORE
 * the bytes: a bucket lifecycle rule is expressed in whole days and executes
 * within 24 hours OF the expiration, so the bytes live 24-48 hours while this
 * token dies at exactly 24. A TTL held in a constant is a number a later edit
 * can LENGTHEN, and lengthening it would retroactively stretch every token
 * already in flight past the bytes it names — producing a valid staged id that
 * addresses an object the sweep has already removed, which is exactly the
 * failure D-82 was written to prevent. Shortening is safe; lengthening is the
 * failure. Baking the instant into each issued token makes the failure
 * unreachable, because an edit to a constant cannot reach a token that was
 * minted before it.
 */
const KIND_STAGED = "s";

/**
 * The kind byte on an UPLOAD ticket — a grant that has not been confirmed.
 *
 * **A fourth kind rather than a reused third, and the reason is the whole point
 * of the confirm step.** An upload ticket and a staged id name the same shape of
 * thing: an object key and an absolute expiry. If they shared a kind byte, a
 * ticket handed straight to the compose path would decode cleanly and attach the
 * bytes — bypassing the step that exists precisely because the server has not
 * looked at them yet. The size check, the delete-on-overrun and the per-file cap
 * would all be skippable by a caller that simply did not call confirm, and
 * nothing would report it.
 *
 * The kind check in `decodePayload` is what makes that unspeakable rather than
 * merely discouraged: a ticket presented where a staged id is expected fails on
 * `k` before any field of it is read. That is the same cross-use refusal the
 * other three kinds already rely on, applied to the one pair that is genuinely
 * substitutable by shape.
 *
 * The ticket's expiry is the instant its grant lapses, and confirm carries that
 * instant forward as a CEILING on the identifier it mints. D-82's ordering
 * therefore survives a delayed confirm, which is the one gap this ingress opens
 * that the other two do not.
 */
const KIND_UPLOAD = "u";

/**
 * The upper bound on every numeric field.
 *
 * IMAP's `nz-number` is an unsigned 32-bit value, so a UIDVALIDITY may
 * legitimately exceed 2^31 — RFC 3501's own worked example is 3857529045, which
 * is above it. That value is exactly representable as a JavaScript number and
 * is precisely what a signed-32-bit assumption anywhere on this path would
 * corrupt into a negative. The bound is asserted here and exercised by a test
 * rather than left as a comment, because the failure it guards against is
 * silent.
 */
const MAX_WIRE_NUMBER = 0xffffffff;

/**
 * How long a staged file's identifier stays valid, from the instant it is
 * minted.
 *
 * **CALIBRATED, NOT MEASURED**, and that sentence comes first for the reason
 * `MAX_WIRE_MESSAGE_BYTES` gives: a reader who believes a number was measured
 * will never revisit it. This one is derived from one platform constraint and
 * one ordering requirement, and from nothing else.
 *
 * **The ordering is the reason the number works (D-82), and it is the part
 * worth reading before changing it.** Bucket lifecycle expiration is expressed
 * in WHOLE DAYS — there is no sub-day setting — and the platform's own wording
 * is that a rule executes *within 24 hours of* the defined expiration. A
 * one-day rule therefore deletes somewhere in a 24-48 hour window rather than
 * on a deadline. The bytes consequently live 24-48 hours while this token dies
 * at exactly 24, so the token ALWAYS expires before the bytes, never after.
 *
 * Reverse the two numbers and the failure is immediate and silent: a staged id
 * that still decodes cleanly, naming an object the sweep has already removed.
 * That is why the expiry is baked into each issued token as an absolute instant
 * rather than being applied from this constant at decode time — see
 * `KIND_STAGED`. Shortening this value is safe. Lengthening it is the failure
 * mode, and the absolute field is what puts tokens already in flight beyond its
 * reach.
 *
 * It also echoes D-59's 24-hour discovery cache, so the project has one
 * "roughly a day" and not two.
 */
export const STAGED_ID_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * A message, named completely.
 *
 * `mailbox` is the RAW WIRE name exactly as the server emitted it in its `LIST`
 * response — never the display-decoded form. That single choice is what makes
 * the later `EXAMINE` round trip byte-exact by construction, and it is why this
 * project needs a modified-UTF-7 *decoder* only and never an encoder. An
 * encoder is a thing that can be subtly wrong; not having one cannot be.
 */
export interface MessageRef {
  /** The raw wire mailbox name from `LIST`. Never display-decoded. */
  mailbox: string;
  /** The mailbox's UIDVALIDITY at the time the token was minted. */
  uidValidity: number;
  /** The message's UID within that mailbox. */
  uid: number;
}

/**
 * A folder, named by the only thing that identifies one.
 *
 * `mailbox` is the RAW WIRE name exactly as the server emitted it in its `LIST`
 * response — never the display-decoded form, for the same reason `MessageRef`
 * says so: the round trip back to `EXAMINE` is byte-exact by construction, and
 * this project needs a modified-UTF-7 decoder only, never an encoder.
 */
export interface FolderRef {
  /** The raw wire mailbox name from `LIST`. Never display-decoded. */
  mailbox: string;
}

/**
 * One attachment of one message, named completely.
 *
 * A message reference plus the part path, and the pairing is the point: the
 * path alone addresses nothing, and a caller never holds one to pair. This is
 * `MessageRef`'s guarantee extended one level down — mailbox, UIDVALIDITY, UID
 * and path travel together or not at all.
 */
export interface AttachmentRef {
  /** The raw wire mailbox name from `LIST`. Never display-decoded. */
  mailbox: string;
  /** The mailbox's UIDVALIDITY at the time the token was minted. */
  uidValidity: number;
  /** The message's UID within that mailbox. */
  uid: number;
  /**
   * The IMAP part path from the server's own `BODYSTRUCTURE`, e.g. `2`, `1.2.3`.
   *
   * Server-derived, via the structure walk in `./mime.ts` — never composed by a
   * caller and never read off anything a message sender authored.
   */
  path: string;
}

/**
 * A file staged in the attachment bucket, named with its own expiry.
 *
 * The only reference in this module that names no message. It carries its
 * expiry rather than leaving the caller to ask, because a caller that can forget
 * to ask is a caller that will (D-81, D-82).
 */
export interface StagedRef {
  /** The bucket object key. Authored by the staging module, never by a caller. */
  key: string;
  /** The instant this identifier stops decoding, in epoch milliseconds. */
  expiresAt: number;
}

/**
 * A position in a paged listing.
 *
 * Carries UIDVALIDITY for the same reason `MessageRef` does, and for one more:
 * D-21 rejected an exposed `beforeUid` parameter precisely so the validity
 * cannot travel separately from the position it qualifies, where a caller could
 * omit it.
 */
export interface PageCursor {
  /** The raw wire mailbox name from `LIST`. Never display-decoded. */
  mailbox: string;
  /** The mailbox's UIDVALIDITY at the time the cursor was minted. */
  uidValidity: number;
  /** The last UID already returned; the next page continues below it. */
  lastUid: number;
}

/**
 * Whether a value is a plausible IMAP wire number.
 *
 * `Number.isInteger` rejects `NaN`, both infinities, and every fractional
 * value, so the three checks together admit only a non-negative integer inside
 * the unsigned 32-bit range.
 *
 * Exported as a PREDICATE alongside the assertion below, because the write path
 * in `./service.ts` reads two of these numbers straight off a tagged response
 * code and must report an out-of-range one as "the server named nothing"
 * rather than raise. It shares this definition rather than restating the bound:
 * one definition drifts nowhere, and two drift apart — which is the same
 * argument this module's own header makes about a second codec.
 */
export function isWireNumber(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= MAX_WIRE_NUMBER
  );
}

/** Refuse a numeric field that is not a plausible IMAP wire number. */
function assertWireNumber(value: unknown): asserts value is number {
  if (!isWireNumber(value)) throw new ImapNotFoundError();
}

/** Refuse a mailbox field that is absent, empty, or not a string. */
function assertMailbox(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ImapNotFoundError();
  }
}

/**
 * Refuse a bucket object key that is absent, empty, or not a string.
 *
 * The same shape as `assertMailbox` and deliberately NOT a call to it. The two
 * fields look alike and answer to different authorities: a mailbox name is a
 * raw wire value the server emitted, while an object key is composed by this
 * project's own staging module. Sharing one assertion would make the next bound
 * added to either — a length cap, a character class, a required prefix —
 * silently apply to the other, and one of those two would be wrong. One
 * definition per field that has its own rules; the duplication is two lines and
 * the coupling would be permanent.
 */
function assertObjectKey(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ImapNotFoundError();
  }
}

/**
 * The exact set of part paths the `BODYSTRUCTURE` walk can produce: one or more
 * segments joined by single dots, each a positive integer with no leading zero.
 *
 * Every segment `./mime.ts` emits is `String(index + 1)`, so `0` and `01` are
 * outside the producible set and are refused for that reason rather than on
 * taste. Anchored at both ends, because a pattern that merely *finds* a valid
 * path inside a longer string would admit every value the exclusions below
 * exist to refuse.
 */
const PART_PATH = /^[1-9][0-9]*(?:\.[1-9][0-9]*)*$/;

/**
 * Refuse a part-path field that names something the structure walk did not
 * produce.
 *
 * **The empty string is deliberately refused here even though it is a LEGAL
 * `BodyPart.path`.** `mime.ts:80-89` is explicit that an empty path means "the
 * top-level multipart" — RFC 3501 §6.4.5 does not number a top-level multipart
 * and its children start at 1, so the empty path records that fact rather than
 * hiding the node. This is not that field. `attachmentsFrom()` skips multiparts
 * outright, so no attachment can ever carry an empty path, and a token that
 * claimed one would be naming a container rather than a file. Written down here
 * because the alternative is a future reader finding an apparent contradiction
 * between two modules and 'fixing' the wrong one.
 *
 * Restricting the field to digits and dots is also what keeps a decoded path
 * from carrying a section keyword, a byte range, a bracket or a CRLF into the
 * fetch item it later becomes (T-04-02-03). The value class D-18 exists to make
 * unspeakable is exactly a caller-composed part address.
 */
function assertPartPath(value: unknown): asserts value is string {
  if (typeof value !== "string" || !PART_PATH.test(value)) {
    throw new ImapNotFoundError();
  }
}

/**
 * Refuse an expiry that is not a usable instant, or that has already passed.
 *
 * Deliberately NOT `assertWireNumber`: an epoch-millisecond instant is far
 * above the unsigned 32-bit ceiling that bounds every IMAP wire number, so
 * sharing that assertion would refuse every well-formed expiry. `isSafeInteger`
 * is the right bound instead — it rejects `NaN`, both infinities, every
 * fractional value, and any magnitude at which millisecond arithmetic stops
 * being exact.
 *
 * The comparison is `<=` rather than `<` on purpose. A token is dead AT its
 * stated expiry, not one millisecond after it; the open boundary would leave a
 * window in which the token decodes and its own stated expiry has passed.
 *
 * `now` is a parameter rather than a `Date.now()` call inside the body so the
 * refusal is testable without faking a clock, and so mint and decode can be
 * asked the same question about the same instant.
 */
function assertExpiry(value: unknown, now: number): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value <= now
  ) {
    throw new ImapNotFoundError();
  }
}

/**
 * Decode a token to its payload object, refusing rather than repairing.
 *
 * Every failure below throws the same error and there is no path that returns a
 * partially-decoded value — no "best effort" reference, no defaulted field, no
 * null the caller might forget to check. The rationale is `credentials.ts`'s,
 * one layer up: a refusal is the honest diagnosis. Repairing around a malformed
 * identifier does not recover the message the caller wanted; it fetches a
 * different one and reports it as the one asked for, which is a worse outcome
 * than any error and is undetectable from the outside.
 *
 * The version and kind are checked BEFORE any field is read, so a token of the
 * wrong shape never reaches the field extraction at all.
 *
 * **This is also this tree's translation boundary for the neutral codec**, and
 * it is the ONLY one it needs. `fromBase64Url` throws `TokenDecodeError`, which
 * is an internal signal rather than a caller-visible outcome; the `catch` below
 * turns it — along with a `fatal` UTF-8 failure and a JSON syntax error, which
 * are the two other ways the same expression can throw — into the one error
 * this module is allowed to raise. That the boundary is a single `catch` is not
 * luck: `fromBase64Url` and the strict decoder are each reached from exactly
 * one place in this file, and it is this one. Adding a second call site outside
 * this `try` would let a neutral error escape to a caller, where the shared
 * categoriser would report it as a connection failure.
 */
function decodePayload(
  token: string,
  kind: string,
): Record<string, unknown> {
  if (typeof token !== "string" || token.length === 0) {
    throw new ImapNotFoundError();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(TOKEN_DECODER.decode(fromBase64Url(token)));
  } catch {
    // A refused base64url token, bytes that are not valid UTF-8, or valid UTF-8
    // that is not valid JSON. A single flipped character reaches here by one
    // route or another, and all three surface identically.
    throw new ImapNotFoundError();
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ImapNotFoundError();
  }

  const payload = parsed as Record<string, unknown>;
  if (payload.v !== TOKEN_VERSION) throw new ImapNotFoundError();
  if (payload.k !== kind) throw new ImapNotFoundError();
  return payload;
}

/**
 * Mint the token that names a message.
 *
 * The fields are validated on the way out as well as on the way in. A token
 * that could not survive its own decoder must never be handed to a caller: the
 * failure would surface arbitrarily far from the code that built it, against a
 * token that by then looks like the model's fault.
 */
export function encodeMessageId(ref: MessageRef): string {
  assertMailbox(ref.mailbox);
  assertWireNumber(ref.uidValidity);
  assertWireNumber(ref.uid);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_MESSAGE,
        m: ref.mailbox,
        uv: ref.uidValidity,
        u: ref.uid,
      }),
    ),
  );
}

/** Read a message token back, or refuse it. Never returns a partial result. */
export function decodeMessageId(token: string): MessageRef {
  const payload = decodePayload(token, KIND_MESSAGE);

  const mailbox = payload.m;
  const uidValidity = payload.uv;
  const uid = payload.u;
  assertMailbox(mailbox);
  assertWireNumber(uidValidity);
  assertWireNumber(uid);

  return { mailbox, uidValidity, uid };
}

/**
 * Mint the token that names a folder.
 *
 * This is the value the model round-trips when a later call has to say WHICH
 * folder — the listing and search tools accept it, and Phase 4's draft tools
 * will. The alternative was letting the model pass a folder name, and it was
 * rejected for D-18's reason rather than a new one: a name the model can read
 * is a name the model can construct, and a constructed name is how a wire value
 * this project never encodes gets invented one character off.
 */
export function encodeFolderId(ref: FolderRef): string {
  assertMailbox(ref.mailbox);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_FOLDER,
        m: ref.mailbox,
      }),
    ),
  );
}

/** Read a folder token back, or refuse it. Never returns a partial result. */
export function decodeFolderId(token: string): FolderRef {
  const payload = decodePayload(token, KIND_FOLDER);

  const mailbox = payload.m;
  assertMailbox(mailbox);

  return { mailbox };
}

/**
 * Mint the token that names one attachment of one message.
 *
 * The fields are validated on the way out as well as on the way in, for
 * `encodeMessageId`'s reason: a token that could not survive its own decoder
 * must never be handed to a caller, or the failure surfaces arbitrarily far
 * from the code that built it against a token that by then looks like the
 * model's fault.
 */
export function encodeAttachmentId(ref: AttachmentRef): string {
  assertMailbox(ref.mailbox);
  assertWireNumber(ref.uidValidity);
  assertWireNumber(ref.uid);
  assertPartPath(ref.path);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_ATTACHMENT,
        m: ref.mailbox,
        uv: ref.uidValidity,
        u: ref.uid,
        p: ref.path,
      }),
    ),
  );
}

/**
 * Read an attachment token back, or refuse it. Never returns a partial result.
 *
 * `decodePayload` has already checked the version and the kind before the first
 * field is read; every field is then re-asserted here, because a token's kind
 * being right says nothing about its fields being well-formed.
 */
export function decodeAttachmentId(token: string): AttachmentRef {
  const payload = decodePayload(token, KIND_ATTACHMENT);

  const mailbox = payload.m;
  const uidValidity = payload.uv;
  const uid = payload.u;
  const path = payload.p;
  assertMailbox(mailbox);
  assertWireNumber(uidValidity);
  assertWireNumber(uid);
  assertPartPath(path);

  return { mailbox, uidValidity, uid, path };
}

/**
 * Mint the token that names a staged file.
 *
 * `now` is injected and defaults to the wall clock, so the encode-time expiry
 * check can be asked about the same instant the test asks the decoder about. It
 * matters that this check exists at all: an already-expired staged id is a
 * token that cannot survive its own decoder, and handing one out would report
 * the failure against whoever presents it rather than whoever minted it.
 *
 * The caller supplies the instant rather than a duration. `STAGED_ID_TTL_MS` is
 * exported for it to add to the clock, and its docstring carries the ordering
 * argument for why that number and no other.
 */
export function encodeStagedId(ref: StagedRef, now: number = Date.now()): string {
  assertObjectKey(ref.key);
  assertExpiry(ref.expiresAt, now);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_STAGED,
        o: ref.key,
        x: ref.expiresAt,
      }),
    ),
  );
}

/**
 * Read a staged token back, or refuse it. Never returns a partial result.
 *
 * **The expiry is enforced HERE, not at the call site**, and that is the whole
 * shape D-81 asked for: a caller holding a staged id cannot forget to ask
 * whether it is still good, because an expired one never becomes a reference at
 * all. The refusal is the same `ImapNotFoundError` every other failure in this
 * module raises — an expired identifier names nothing, which is precisely what
 * that error says.
 *
 * `now` defaults to the wall clock and is injectable for the tests, which is
 * the only way to assert a 24-hour boundary without waiting 24 hours.
 */
export function decodeStagedId(
  token: string,
  now: number = Date.now(),
): StagedRef {
  const payload = decodePayload(token, KIND_STAGED);

  const key = payload.o;
  const expiresAt = payload.x;
  assertObjectKey(key);
  assertExpiry(expiresAt, now);

  return { key, expiresAt };
}

/**
 * Mint the ticket that names an upload nobody has looked at yet.
 *
 * Same fields as a staged id and a different kind byte — see `KIND_UPLOAD` for
 * why that difference is load-bearing rather than tidy.
 *
 * `expiresAt` is the instant the upload grant lapses, not a day from now. It is
 * the caller's number because the caller is the one that minted the grant, and
 * confirm reads it back as the ceiling on the identifier it issues.
 */
export function encodeUploadId(ref: StagedRef, now: number = Date.now()): string {
  assertObjectKey(ref.key);
  assertExpiry(ref.expiresAt, now);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_UPLOAD,
        o: ref.key,
        x: ref.expiresAt,
      }),
    ),
  );
}

/**
 * Read an upload ticket back, or refuse it.
 *
 * A staged id presented here fails the kind check, and a ticket presented to the
 * staged decoder fails it in reverse. Neither direction is a nicety: one would
 * let a confirmed file be re-confirmed, and the other would let an unconfirmed
 * upload be attached.
 */
export function decodeUploadId(
  token: string,
  now: number = Date.now(),
): StagedRef {
  const payload = decodePayload(token, KIND_UPLOAD);

  const key = payload.o;
  const expiresAt = payload.x;
  assertObjectKey(key);
  assertExpiry(expiresAt, now);

  return { key, expiresAt };
}

/**
 * Mint the token that continues a paged listing.
 *
 * Unsigned, deliberately. D-21 weighed an HMAC here and declined it: the worst
 * case on a read path is a wrong page, the contents are values the same caller
 * already saw in the list response it came from, and Phase 5 is where signing
 * machinery earns its ceremony.
 */
export function encodeCursor(cursor: PageCursor): string {
  assertMailbox(cursor.mailbox);
  assertWireNumber(cursor.uidValidity);
  assertWireNumber(cursor.lastUid);

  return toBase64Url(
    TOKEN_ENCODER.encode(
      JSON.stringify({
        v: TOKEN_VERSION,
        k: KIND_CURSOR,
        m: cursor.mailbox,
        uv: cursor.uidValidity,
        l: cursor.lastUid,
      }),
    ),
  );
}

/** Read a cursor back, or refuse it. Never returns a partial result. */
export function decodeCursor(token: string): PageCursor {
  const payload = decodePayload(token, KIND_CURSOR);

  const mailbox = payload.m;
  const uidValidity = payload.uv;
  const lastUid = payload.l;
  assertMailbox(mailbox);
  assertWireNumber(uidValidity);
  assertWireNumber(lastUid);

  return { mailbox, uidValidity, lastUid };
}
