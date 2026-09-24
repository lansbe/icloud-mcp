// The confirmation capability, and its protocol-neutral refusal.
//
// A signed, single-use, short-lived authorisation to apply ONE reviewed change
// to ONE named resource. Nothing here knows what a calendar is, what a mailbox
// is, or how a change is eventually written; it mints a payload, seals it,
// reads it back, hashes a change canonically, and reserves a one-time slot.
//
// **Why the source root rather than inside a protocol tree.** `V2-MAIL-02`
// ("mail delete and move behind the same preview-then-commit safety") is
// already on the books, so the NEXT consumer of this module is a mail delete,
// not a calendar write. A confirmation module living in `src/dav/` would later
// have to be either imported across ARCHITECTURE Q1's zero-import boundary or
// copied — and `src/tokens.ts` names the copy as the failure in its own header:
// *a rule living in two decoders is a rule that drifts.* The rule that would
// drift here is the six-causes-one-answer refusal below, which is a paragraph
// of reasoning attached to a five-line function, and a copy without the
// paragraph is a copy someone makes helpful.
//
// **The obligation that placement creates.** This module raises a NEUTRAL
// error, and every protocol tree that verifies a confirmation owes it a
// translation at that tree's own boundary. See `ConfirmationInvalidError`.
//
// **The single-use guarantee is bounded, and this is where that is said.**
// Cloudflare KV is eventually consistent: a read at one edge location is not
// guaranteed to see a write made at another for a short propagation window, so
// two commits carrying the same confirmation, racing inside that window, can
// BOTH find the slot free and both pass. That is not a hedge against a
// hypothetical — it is how KV works, and claiming otherwise would leave a
// reader over-trusting this layer. Three things bound it:
//
//   - the token's own lifetime is minutes, so the window is a small fraction
//     of the period in which a replay is even possible;
//   - a confirmation is bound to ONE user — `ConfirmPayload.u` — and the
//     reserved slot is keyed under that same user, so the two commits racing
//     for one slot have to be signed in as the SAME person on two clients at
//     once. This bullet used to say something stronger and simpler: that this
//     is a single-user server, so two racing clients do not exist at all. That
//     stopped being true the moment the payload gained a user field, and a
//     bound that is quietly false is worse than a narrower one that is true;
//     and
//   - `If-Match` at the DAV server is an entirely independent second layer.
//     The loser of the race carries an etag the winner's write already
//     invalidated, and no amount of KV staleness turns that into a success.
//
// Neither layer is sufficient alone. This one refuses BEFORE any request is
// issued, which is what the requirement asks for; `If-Match` refuses at the
// server, which is what actually holds under a race.
//
// **Option B, which was NOT chosen, and is worth knowing about.** No KV at all
// — rely on `If-Match` plus the short lifetime, so a replayed update fails its
// precondition and a replayed delete finds nothing. That is genuinely
// defensible on the mechanics, and it is what keeps working if KV is ever
// unavailable. It was rejected for one reason only: the requirement says an
// already-used confirmation is rejected *before any DAV request is issued*, and
// `If-Match` cannot satisfy that, because it IS the DAV request.
//
// This module contains no logging calls of any kind and must never acquire any.
// ./.claude/CLAUDE.md §4 is not "no logging of credentials" — it is no logging
// at all under `src/` — and this is exactly the module where a "log the payload
// I am about to sign" line is tempting.

import { isConfiguredSecret } from "./auth/login-handler";
import { TOKEN_DECODER, TOKEN_ENCODER, fromBase64Url, toBase64Url } from "./tokens";

/**
 * The refusal, named without naming a protocol — and without naming a cause.
 *
 * Built on `TokenDecodeError`'s shape: a fixed internal label, a `readonly
 * kind` discriminant, a `name` assignment, and no constructor argument at all.
 * The absent argument is the point rather than an omission — there is nowhere
 * for a cause, a field name or a quoted token to ride, even by accident.
 *
 * **What each protocol tree owes this class: a translation at its own
 * boundary.** This error is an internal signal, not a caller-visible outcome.
 * Every tree that verifies a confirmation must catch it and rethrow its own
 * class, because the shared error-categorisation function dispatches on TYPE
 * and falls through to a connection diagnosis for anything it does not
 * recognise — so a `ConfirmationInvalidError` that escaped would tell a caller
 * the network failed when what actually happened is that a confirmation was
 * refused. That is not merely imprecise: it points at the wrong remedy, telling
 * a model to retry the thing that will be refused identically.
 *
 * The DAV tree's translation is `DavConfirmationError` in `src/dav/errors.ts`,
 * which `davToErrorCategory` maps to `confirmation_invalid`. The join is
 * asserted end to end — and mutation-tested rather than assumed — in the final
 * describe block of `test/confirm.test.ts`.
 *
 * **Every cause answers identically, and that is a security property rather
 * than tidiness.** An unusable signing key, a token that is not two encoded
 * parts, a seal that does not verify, a payload that is not JSON, a version
 * this build does not know, a lifetime that has run out, a change that does not
 * match what was confirmed, and one already spent — all of them raise this, with
 * the same label and the same shape. A distinguishable refusal is an oracle for
 * the confirmation's internal structure, and the commonest way to reach one is
 * a model probing the format.
 */
export class ConfirmationInvalidError extends Error {
  readonly kind = "confirmation-invalid" as const;

  constructor() {
    super("confirmation-invalid");
    this.name = "ConfirmationInvalidError";
  }
}

/**
 * The payload format version.
 *
 * Bumping this is a DECISION rather than a refactor, on `DAV_TOKEN_VERSION`'s
 * reasoning with one difference in the blast radius. An identifier that has
 * left the building is in a transcript forever; a confirmation is dead in
 * minutes, so a format change invalidates only what is in flight at the moment
 * it lands. That makes this the cheap version field rather than the expensive
 * one — but it earns its bytes for the same reason: a future format change
 * becomes DETECTABLE, refused outright, rather than silently misread as the
 * current shape and applied to the wrong resource.
 *
 * **Bumped to 2 when the payload gained `u`, and the cost is named rather than
 * discovered.** Every preview in flight at that deploy dies: its token carries
 * `v: 1`, the check below is a strict inequality against this constant, and a
 * version this build does not know is refused outright. That is the correct
 * behaviour rather than a fault — a v1 token has no `u` at all, and admitting
 * one would be admitting a confirmation nobody can say belongs to anyone. The
 * owner accepted this cost by name (D-12); it costs each affected preview one
 * re-preview and nothing else.
 *
 * **Bumped to 3 when the payload gained `t`, and the cost is the same cost,
 * named again rather than assumed to have been paid once.** Every preview in
 * flight at THAT deploy dies too: its token carries `v: 2`, the check below is
 * the same strict inequality, and a version this build does not know is refused
 * outright. That is the correct behaviour rather than a fault — a v2 token says
 * nothing about which KIND of resource it names, and admitting one would be
 * admitting a confirmation whose fields a commit would read under whatever
 * field names that commit happened to expect. The owner priced this in D-12 and
 * in ARCHITECTURE §7; it costs one re-preview per confirmation alive at the
 * deploy, and the window in which any are alive is `CONFIRM_TTL_SECONDS` wide.
 *
 * No compatibility arm admits a v2 token back. An arm that read the old shape
 * and filled in a discriminator would be guessing at the one field the guess
 * was added to remove.
 */
export const CONFIRM_VERSION = 3;

/**
 * The operation a confirmation authorises.
 *
 * Read from the SIGNED payload and never inferred from which tool was called.
 * A handler that inferred the operation from its own endpoint would be a
 * handler whose identity could disagree with the token's, and the disagreement
 * would resolve in favour of whatever the caller chose to invoke.
 */
export type ConfirmKind = "create" | "update" | "delete";

/**
 * How long a confirmation stays usable: five minutes.
 *
 * The ROADMAP fixed a two-to-five-minute band, and this sits at its top. Both
 * ends were argued rather than one:
 *
 * **Against a shorter value.** A person reading a preview is reading the thing
 * this whole phase exists to make them read — who is being told, what they are
 * being told, and which Tuesday it is. Two minutes is enough time to do that
 * and it is also enough time to be interrupted, and a confirmation that dies
 * mid-thought costs a re-preview at exactly the moment the user was being
 * careful. The eventual-consistency window on the single-use record points the
 * same way: that window is seconds, so against a five-minute life it is a small
 * fraction of the period in which a replay is possible at all, where against a
 * sixty-second life the two numbers become comparable and the reservation stops
 * being a meaningful first layer.
 *
 * **Against a longer value.** This is a signed capability to write to the
 * user's real calendar, and it is live for exactly as long as this number says
 * — including every second after the user has already answered. The band's own
 * ceiling is the answer to "why not ten minutes", and the reason the band has a
 * ceiling is that the value of a longer window accrues entirely to a replay.
 *
 * This constant is used to COMPUTE an absolute expiry at mint time. It is never
 * compared against a mint time at verify time; see `ConfirmPayload.x`.
 */
export const CONFIRM_TTL_SECONDS = 300;

/**
 * The key namespace for spent-confirmation records, versioned.
 *
 * The version buys the hedge `DAV_CACHE_KEY_PREFIX` and `DAV_TOKEN_VERSION`
 * buy: a future change to the stored shape becomes detectable rather than
 * silently misread as the current one. The stored value carries nothing — the
 * KEY is the fact — so there is no payload to leak and no shape to misparse.
 *
 * `v2` because the user id now sits between this prefix and the jti, and that
 * id is a SECOND LAYER rather than tidiness.
 *
 * An earlier version of this comment said the opposite — that the jti is a UUID
 * and could not have collided across users anyway, so the id here was
 * housekeeping and the real fix was the check inside `verifyConfirmation`.
 * Measurement retracted that (D-12, corrected by plan 10-04). Mutating the user
 * check out of `verifyConfirmation` did NOT redden the slot-leak test, because
 * the scoped key closes the slot half of audit row T1 on its own: a caller who
 * reaches the reservation holding somebody else's confirmation burns a slot
 * under their OWN id, and the owner's confirmation still spends. Reddening that
 * test took a PAIR of mutations — the check moved after the reservation AND
 * this key flattened back. Two independent layers, not one layer and a tidy-up.
 *
 * So flattening this key would reopen half of T1. Two things refuse that today
 * and both are worth knowing, because neither is obvious from here: the key
 * shape is pinned byte-for-byte in `test/key-shapes.test.ts`, and a key
 * expression that does not put a user id straight after a prefix constant is
 * what the `store-key-without-a-user` scan rule exists to reject — the flat
 * form is that rule's own known-violating sample. What is NOT held is the
 * reasoning: a reader who decides from this paragraph that the id is optional
 * can change both of those to match. That is why the measurement is written
 * down here rather than only in the phase record.
 *
 * `v3` because the payload above it now names its own target, and the two
 * version segments are kept in step deliberately: a stored record and the token
 * it was written for belong to the same format, and a namespace that lagged
 * behind the payload would let a v3 token find a v2 slot already spent by a
 * token of a different shape. The user id still sits immediately after this
 * prefix and that has not moved — the bump changes the namespace and nothing
 * about the key's structure.
 */
export const CONFIRM_KEY_PREFIX = "confirm:v3:";

/**
 * The separator between the sealed payload and its seal.
 *
 * A single character, and its identity is load-bearing rather than cosmetic: it
 * is NOT a member of the base64url alphabet `src/tokens.ts` enforces, which is
 * what makes cross-use with this project's opaque identifiers STRUCTURALLY
 * impossible rather than merely checked.
 *
 * `fromBase64Url` tests `/^[A-Za-z0-9_-]+$/` before it reaches the runtime's
 * base64 primitive, so a confirmation handed to `decodeEventId` fails at the
 * alphabet check with no kind comparison ever running — and an event id handed
 * to `verifyConfirmation` has no separator to split on. Neither decoder
 * performs a check against the other's format; there is nothing to omit.
 *
 * Nothing is exported for this. The assertion belongs in the test and reads the
 * alphabet constraint out of the shipped codec, on `DAV_KIND_LETTERS`'s
 * precedent — a guard restating the character class would agree with itself
 * rather than with `src/tokens.ts`.
 */
const TOKEN_SEPARATOR = ".";

/**
 * What every confirmation carries, whatever it names.
 *
 * The protocol-neutral half: the version, the operation, the single-use id, the
 * change hash, the expiry and the user. Nothing here says what kind of resource
 * the confirmation points at — that is the discriminated half, one arm below
 * per target, and `ConfirmPayload` is the union of those arms.
 *
 * Single-character field names, for the reason `src/dav/ids.ts` gives about its
 * own tokens: a token is paid for on every response for the life of the server,
 * and this one rides alongside a preview a model must read in full.
 */
export interface ConfirmPayloadBase {
  /** Format version. See `CONFIRM_VERSION`. */
  v: typeof CONFIRM_VERSION;
  /** The operation authorised, read from here and never from the endpoint. */
  k: ConfirmKind;
  /** The jti — `crypto.randomUUID()`, and the single-use key. */
  j: string;
  /** The canonical change hash. See `changeHashOf`. */
  h: string;
  /**
   * The expiry, as ABSOLUTE seconds since the epoch.
   *
   * **Absolute, and never a mint time compared against a TTL constant at verify
   * time.** This is D-82's rule carried to a second token type, and its
   * reasoning transfers without alteration: a lifetime held in a constant is a
   * number a later edit can lengthen, and lengthening it would retroactively
   * stretch every token already in flight. Shortening is safe; lengthening is
   * the failure; an absolute field makes the failure unreachable, because the
   * only thing a later edit can change is how long the NEXT token lives.
   *
   * Whole seconds, and expiry is `>=` rather than `>`: the second a token names
   * belongs to the dead side, so a confirmation can never be spent in the
   * second it expires.
   */
  x: number;
  /**
   * The user this confirmation was minted FOR.
   *
   * The 64-hex id of the signed-in principal at the preview, taken from
   * `Principal.userId` and from nothing else. It is never read off a caller's
   * request, never parsed out of a URL, and never recovered from a key — a
   * subject a caller could choose is not a subject, it is a field.
   *
   * **What it buys, and it is not the obvious thing.** A confirmation is
   * already tied to one resource by `c` and `o`, so another user presenting it
   * cannot write to their own calendar with it — the home containment check
   * turns them away. What they COULD do until this field existed is spend the
   * one-time slot: the reservation ran before anyone asked who the token
   * belonged to, so a refused commit still burnt the owner's confirmation and
   * the owner had to preview again. `verifyConfirmation` compares this field
   * five checks and one KV round trip ahead of that reservation, so a mismatch
   * now spends nothing at all.
   */
  u: string;
}

/**
 * Which kind of resource a confirmation names.
 *
 * Three literals, and only the first has a call site today. The other two
 * arrive with the arms below, and the type carries all three from the start so
 * that the predicate's arm table and `verifyConfirmation`'s parameter are
 * written once rather than widened each time a phase lands.
 *
 * `"dav"` is one CalDAV or CardDAV OBJECT; `"col"` is a DAV COLLECTION;
 * `"mail"` is one message in one mailbox.
 */
export type ConfirmTarget = "dav" | "col" | "mail";

/** A confirmation naming ONE CalDAV or CardDAV object. */
export interface DavObjectConfirmPayload extends ConfirmPayloadBase {
  /**
   * The kind of resource this confirmation names.
   *
   * **The discriminator is load-bearing rather than a label.** Every arm of
   * this union reuses the same short field letters for entirely different
   * values, because the letters are paid for on every response and there are
   * not many of them. `o` is an absolute object URL here and a UID's home
   * nowhere else; `m` is a mailbox token on the mail arm and absent here.
   *
   * The silent failure it forbids is mechanical rather than hypothetical. A
   * mail confirmation handed to a DAV commit would have its fields read under
   * the DAV arm's names, so a mailbox token lands in the slot naming a
   * collection URL and a UID lands in the slot naming an object URL. tsdav
   * resolves a request URL against the account's own root, so a mailbox name
   * becomes an absolute-looking URL, the request goes out, and something is
   * written or removed at a path nobody chose. Nothing raises: every field is a
   * string of the right type, which is the entire class of failure a structural
   * predicate alone cannot see.
   *
   * A REQUIRED discriminator makes that unreachable rather than merely checked.
   * `verifyConfirmation` takes the target its caller expects and refuses a
   * mismatch itself, so there is no call site that can forget the comparison,
   * and the payload it returns is already narrowed to the matching arm.
   *
   * Single-character, for the reason the interface header gives.
   */
  t: "dav";
  /** The collection URL, absolute. */
  c: string;
  /** The object URL, absolute. The commit reads its target from HERE. */
  o: string;
  /** The recurrence id, or `null` on a non-recurring target. */
  r: string | null;
  /**
   * The ETag the preview observed, byte-exact with its quotes — or `null`, and
   * `null` ONLY for a create.
   *
   * **The null-only-for-create rule is load-bearing rather than cosmetic.**
   * tsdav's header builder drops any falsy entry before the request goes out,
   * so an empty string here does not fail: it silently turns a CONDITIONAL
   * write into an unconditional one, and the server answers 200. The optimistic
   * concurrency guarantee disappears with no error, no warning, and a result
   * that looks exactly like success. `null` is used for the create case
   * precisely so that "absent" is a value a type can forbid on the other two,
   * rather than a state an empty string can reach by accident.
   *
   * Quotes are kept because an ETag is an opaque quoted string: stripping and
   * re-adding them is a normalisation that eventually meets a weak ETag and
   * gets it wrong.
   */
  e: string | null;
  /**
   * The `SEQUENCE` the previewed resource carried — or `null` when it carried
   * none, and `null` for a create, which has no resource to have carried one.
   *
   * **Here rather than in the change, and the distinction is the whole reason
   * this field exists at all.** `h` binds what the USER APPROVED; a caller
   * re-supplies that change and the hash refuses any alteration of it. This is
   * not that. It is a fact about the RESOURCE at read time — the ETag's own
   * footing, one field up — and it is not something a caller was ever shown,
   * asked about, or could sensibly re-supply.
   *
   * **Why it has to travel at all.** A commit has exactly one outbound request
   * and it is the write, so it never sees the resource's bytes. The rewrite
   * must nevertheless emit a revision PAST the stored one: a `SEQUENCE` that
   * goes backwards makes every other calendar client treat the update as stale
   * and ignore it, and it raises nothing anywhere — not in this server, not at
   * iCloud, not in the receiving client. The preview's multi-get is the last
   * moment the stored value exists in this server's hands, so it is sealed here
   * and read back at the write. See `nextSequence` in `src/dav/icalendar.ts`.
   *
   * Sealed rather than re-supplied for the obvious reason: a caller that could
   * choose the revision could choose one BELOW the stored value, which is
   * exactly the silent failure the field exists to prevent.
   */
  s: number | null;
}

/**
 * A confirmation naming ONE DAV collection — a calendar, an address book.
 *
 * Deliberately a separate arm rather than the object arm with a nullable ETag.
 * A collection is not a resource with an entity tag, so there is nothing to put
 * in `e`; `e`'s own docstring reserves `null` for a create and that reservation
 * is what stops an unbound update or delete being representable. See `b`.
 */
export interface DavCollectionConfirmPayload extends ConfirmPayloadBase {
  /** The kind of resource this confirmation names. See `DavObjectConfirmPayload.t`. */
  t: "col";
  /** The home set the collection lives under, absolute. */
  c: string;
  /** The collection URL, absolute. The commit reads its target from HERE. */
  o: string;
  /**
   * What the collection looked like at preview, sealed — its binding.
   *
   * **A distinct field rather than a reused `e`, and that is what keeps
   * "absent" from acquiring a second meaning.** `e` is the ETag the preview
   * observed, and its docstring reserves `null` for a create precisely so that
   * "unbound" is a state a type can forbid on an update and a delete.
   *
   * The silent failure that forbids: a collection has no entity tag, so the
   * path of least resistance is to pass `null` in `e` and move on. That turns
   * the one value reserved for creates into a value that ALSO means "we could
   * not bind this", and once one field carries both meanings the type can no
   * longer forbid an unbound delete. The most destructive operation in the
   * milestone loses its binding and nothing fails — no error, no warning, and a
   * delete that looks exactly like the one the user approved.
   *
   * REQUIRED, `string`, never `string | null` and never optional, on its own
   * arm. That is what makes unbound unreachable rather than discouraged: there
   * is no value a caller can put here that means "no binding", and no arm of
   * this union that omits the field.
   *
   * **This arm carries NO `e`, NO `r` and NO `s`, and each is absent rather
   * than null for its own reason.** A collection is not a resource with an
   * entity tag, so `e` has nothing to hold. A collection does not recur, so
   * there is no occurrence for `r` to name. A collection is not an iCalendar
   * object, so it carries no `SEQUENCE` for `s` to record. A null in any of the
   * three would be this arm claiming a fact about the resource it does not have.
   *
   * **What goes in it.** The collection's `CS:getctag`, or a DAV `sync-token`
   * from a `sync-collection` report — both move when any member of the
   * collection changes, and SPIKE-03 confirmed `sync-collection` is advertised.
   * This module does not care which. It never reads the value: it seals it and
   * hands it back, byte for byte, and the choice belongs to whichever preview
   * mints the token.
   *
   * **And the limit, said out loud rather than left to be discovered.** Until a
   * commit RE-READS this binding and refuses a collection that moved, this arm
   * has the one-time KV slot and nothing else — exactly the position the mail
   * arm is in, and for the same reason. That re-read is Phase 17's work. A
   * bound that is quietly false is worse than a narrower one that is true, so
   * the narrower one is what is claimed here: the field travels, and nothing in
   * this build yet compares it against anything.
   */
  b: string;
}

/**
 * What a confirmation carries, sealed — one arm per kind of target.
 *
 * A union rather than one interface with optional fields, and the difference is
 * the whole point: an optional field makes "absent" carry two meanings at once,
 * which is the failure `e`'s own docstring is built to avoid. On a union, a
 * field that does not belong to a target is not absent — it does not exist.
 */
export type ConfirmPayload =
  | DavObjectConfirmPayload
  | DavCollectionConfirmPayload;

/**
 * True only for a signing key this module is willing to use.
 *
 * `isConfiguredSecret` is REUSED rather than restated, on `src/dav/transport.ts`'s
 * precedent — one definition of what a usable configured secret looks like,
 * shared with the `/authorize` path that first needed it (CR-01).
 *
 * The whitespace clause is this module's own addition, and it is a composition
 * rather than an edit to the shared predicate. Widening `isConfiguredSecret`
 * itself would change the behaviour of a shipped authentication path for a
 * reason belonging to this one. The reason it is needed HERE is specific: on
 * the authorize form the configured secret is the thing a submission is
 * compared AGAINST, so a whitespace-only value is still a value an attacker has
 * to know. As an HMAC key it is a key an attacker can guess on the first try,
 * and a Workers Secret acquires one the ordinary way — provisioned by paste, or
 * from a file that held only a newline.
 */
function isUsableSigningKey(secret: string | undefined): secret is string {
  return isConfiguredSecret(secret) && secret.trim().length > 0;
}

/**
 * Import the signing key, non-extractably.
 *
 * `extractable: false` is deliberate and is the module's structural half of
 * ./.claude/CLAUDE.md §4. Nothing here needs to read the key back, and a
 * non-extractable `CryptoKey` cannot be `JSON.stringify`d, attached to an
 * `Error`, or spread into a response — the same write-only property
 * `src/mail/credentials.ts` gets by consuming its inputs and returning nothing.
 * The difference is that this one holds even against code that WANTS the value:
 * a habit can be broken by the next edit, and a non-extractable key cannot.
 *
 * The fail-closed check runs here as well as at both call sites, and the
 * duplication is on purpose. `crypto.subtle.importKey` accepts a zero-length
 * raw HMAC key in some implementations rather than throwing, and a server that
 * both signs and verifies with the empty key verifies its own forgeries
 * perfectly and accepts everyone else's too — every signature valid, nothing
 * erroring, the gate simply absent. A check on the one function that can
 * produce that state is the check that cannot be forgotten by a future third
 * caller.
 *
 * **Exported for one purpose only.** Nothing outside this module calls it in
 * the running server; the export exists so `test/confirm.test.ts` can assert
 * the non-extractability against the real `CryptoKey` rather than against a
 * comment claiming it, on `DAV_KIND_LETTERS`'s export-for-one-purpose
 * precedent.
 */
export async function importConfirmationKey(
  secret: string | undefined,
): Promise<CryptoKey> {
  if (!isUsableSigningKey(secret)) throw new ConfirmationInvalidError();

  return crypto.subtle.importKey(
    "raw",
    TOKEN_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Mint a sealed confirmation.
 *
 * Refuses to issue anything at all when the signing key is unusable, rather
 * than only refusing to verify. Both halves matter and only one of them is
 * obvious: a server that verifies with an empty key accepts anyone's forgery,
 * and a server that MINTS with one hands out tokens that outlive the
 * misconfiguration — they were never really signed, so they stay acceptable to
 * whatever accepts an empty key next.
 */
export async function mintConfirmation(
  payload: ConfirmPayload,
  secret: string | undefined,
): Promise<string> {
  const key = await importConfirmationKey(secret);

  const payloadPart = toBase64Url(
    TOKEN_ENCODER.encode(JSON.stringify(payload)),
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    TOKEN_ENCODER.encode(payloadPart),
  );

  return `${payloadPart}${TOKEN_SEPARATOR}${toBase64Url(new Uint8Array(mac))}`;
}

/**
 * Read a confirmation back, or refuse it.
 *
 * **The order is fixed and is not negotiable.** Split into exactly two parts;
 * verify the seal; decode and parse; check the version; check the TARGET; check
 * the user; check the expiry. Nothing reads a field out of the payload before
 * the seal has verified, so a caller-authored payload never reaches the field
 * extraction at all — the discipline `decodeDavPayload` records for its own
 * decode.
 *
 * **The target check sits between the version and the user, and the position is
 * the point rather than an accident.** It compares two facts this server
 * already holds — the arm the caller is about to read the payload as, and the
 * arm this server sealed into it — so it is cheaper than the user comparison
 * and reaches nothing at all. Below the user check it would mean a token minted
 * for the wrong protocol had already been measured against a principal before
 * anyone asked whether it named the right kind of thing, and further down still
 * it would sit past the reservation and burn a slot. Above the version check it
 * would be reading a field out of a payload whose format this build has not yet
 * agreed it understands.
 *
 * `crypto.subtle.verify` and never `crypto.subtle.sign` followed by a
 * comparison. Cloudflare's own signing example says why in a comment: a string
 * comparison bails on the first mismatch, which leaks. This repository
 * separately forbids hand-rolled comparison loops anywhere — all cryptography
 * is the runtime's or the OAuth library's.
 *
 * **Refuse, never repair, and never explain.** Nothing thrown from here names
 * the check that failed, quotes the token back, or mentions a field name, a
 * version or an encoding. There is no partially-decoded return, no defaulted
 * field, and no null a caller might forget to check. Every failure below is one
 * `throw new ConfirmationInvalidError()`, and the single `catch` is what keeps
 * `TokenDecodeError` — which `fromBase64Url` raises on a MAC part outside the
 * alphabet — from escaping as a neutral error a caller would be told was a
 * network fault.
 */
export async function verifyConfirmation<T extends ConfirmTarget>(
  token: string,
  secret: string | undefined,
  /** The signed-in user. Never read out of the token it is checked against. */
  userId: string,
  /**
   * The target the CALLER expects, never read out of the token it is checked
   * against — the same discipline `userId` above it is held to.
   *
   * The return type narrows on this parameter, so a caller gets back a payload
   * already restricted to the matching arm. That is what removes the job from
   * every call site: there is no cast to write and no `t` comparison to repeat,
   * and a comparison repeated at N call sites is one a later call site forgets.
   */
  expected: T,
): Promise<Extract<ConfirmPayload, { t: T }>> {
  const key = await importConfirmationKey(secret);

  if (typeof token !== "string") throw new ConfirmationInvalidError();

  const parts = token.split(TOKEN_SEPARATOR);
  if (parts.length !== 2) throw new ConfirmationInvalidError();

  const [payloadPart, macPart] = parts;
  if (payloadPart.length === 0 || macPart.length === 0) {
    throw new ConfirmationInvalidError();
  }

  let parsed: unknown;
  try {
    const verified = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64Url(macPart),
      TOKEN_ENCODER.encode(payloadPart),
    );
    // Raised INSIDE the block its own `catch` swallows, and that is deliberate
    // rather than an oversight. A seal that does not match and a payload that
    // will not decode must be indistinguishable, so both leave by the same
    // route; hoisting this check out would give the two causes two exits, and
    // two exits are two places a later edit can make one of them explain
    // itself. The `catch` rethrows exactly what this line throws.
    if (!verified) throw new ConfirmationInvalidError();

    parsed = JSON.parse(TOKEN_DECODER.decode(fromBase64Url(payloadPart)));
  } catch {
    // A MAC or a payload outside the base64url alphabet, bytes that are not
    // valid UTF-8, valid UTF-8 that is not JSON, or the seal simply not
    // matching. A single flipped character reaches here by one route or
    // another, and every route surfaces identically.
    throw new ConfirmationInvalidError();
  }

  if (!isConfirmPayload(parsed)) throw new ConfirmationInvalidError();
  if (parsed.v !== CONFIRM_VERSION) throw new ConfirmationInvalidError();

  // The target this confirmation names, compared against the target the caller
  // is about to read it as. The refusal is the SAME single throw every other
  // cause uses, with no message, no cause and no distinguishable shape: a
  // caller who could tell "wrong target" from "forged" would have an oracle for
  // which arms this build knows about.
  //
  // See the paragraph in the docstring for why it runs HERE and not one line
  // lower.
  if (parsed.t !== expected) throw new ConfirmationInvalidError();

  // The user this confirmation was minted for. A plain comparison, not the
  // timing-safe one `changeHashMatches` uses two functions down: that one is
  // timing-safe because the change hash is CALLER-SUPPLIED and a length-
  // dependent throw would be an oracle. Neither operand here is caller-supplied
  // — one comes from the signed-in principal and the other out of a payload
  // this server sealed — so there is no secret for a timing difference to leak,
  // and the runtime primitive would additionally demand both sides be 32 bytes,
  // which a 64-character hex string is not.
  //
  // The refusal is the SAME single throw every other cause uses, with no
  // message, no cause and no distinguishable shape: a wrong user must be
  // indistinguishable from an expired, forged or malformed token, or the
  // refusal tells an attacker their guess was well formed.
  //
  // It runs HERE, and the position is the point rather than an accident.
  // `applyCommit` reaches this line first, then checks the kind, the supplied
  // kind's agreement, the change hash and the scope, and only then claims the
  // one-time slot. So a mismatch is refused five checks and one KV round trip
  // ahead of the reservation, and costs the user it was minted for nothing.
  if (parsed.u !== userId) throw new ConfirmationInvalidError();

  // `>=`: the second a token names belongs to the dead side.
  if (Math.floor(Date.now() / 1000) >= parsed.x) {
    throw new ConfirmationInvalidError();
  }

  // The ONE assertion in this module's narrowing story, and it is here so that
  // no call site needs one. TypeScript narrows a union on a comparison against
  // a literal, but not on a comparison against a value of a generic parameter,
  // so the check above cannot teach the compiler what it has just proved at
  // runtime. Written here, where the proof is three lines up and visible; a
  // cast at a call site would be the same assertion with the proof missing.
  return parsed as Extract<ConfirmPayload, { t: T }>;
}

/**
 * One person a change would tell.
 *
 * `email` is what the change is keyed on; `name` rides along because CALW-08
 * reports who is being told, and a bare address is a worse answer than a name
 * beside one. Both are caller-supplied and neither is repaired.
 */
export interface AttendeeChange {
  email: string;
  name: string | null;
}

/**
 * The shape a preview and a commit both reduce their request to.
 *
 * Every optional field is already resolved to `null` rather than absent by the
 * time it reaches here — that is what "normalized" means in the name, and it is
 * load-bearing rather than tidy: an absent key and an explicit null are
 * different bytes for the same meaning, so a caller that omitted a key could
 * otherwise move the hash without changing the request.
 */
export interface NormalizedChange {
  /** The operation, matching the confirmation's own `k`. */
  kind: ConfirmKind;
  /**
   * The recurrence discriminator — which occurrences a change reaches — or
   * `null` on a non-recurring target.
   *
   * Deliberately typed `string | null` rather than narrowed to the write-scope
   * union. That vocabulary belongs to the plan that introduces it, and this
   * module has no opinion on its members: the hash COVERS the value, so a
   * scope that changed between preview and commit fails the comparison whether
   * or not this file has heard of the new member. Narrowing it here would be
   * this module claiming an authority it does not have, and would make adding a
   * scope a two-file change for no gain.
   */
  scope: string | null;
  summary: string | null;
  startLocal: string | null;
  startTzid: string | null;
  endLocal: string | null;
  endTzid: string | null;
  allDay: boolean;
  location: string | null;
  description: string | null;
  attendees: AttendeeChange[];
}

/**
 * Fold one address for matching.
 *
 * `toLowerCase` and NOT the locale-aware form, on the precedent `fold` in
 * `src/dav/calendar.ts` already set: the locale-aware fold gives a different
 * answer under a Turkish locale, where a dotted capital I folds to a dotless
 * one — and the vitest pool inherits the developer's locale while production
 * runs its own. A hash that depended on the host's locale would match at
 * preview and mismatch at commit on one machine and not another.
 */
function foldAddress(value: string): string {
  return value.toLowerCase();
}

/**
 * The bytes a change hashes to, as a fixed-order tuple.
 *
 * **The property that matters: the same requested change must hash identically
 * at preview and at commit.** `JSON.stringify` over a caller-supplied object
 * does NOT have that property, and it fails in two separate ways — key order
 * follows insertion order, so two call sites that built their object in a
 * different sequence disagree; and an absent key and an explicit `null` are
 * different bytes for the same meaning. Both are fixed here, before any
 * hashing, by reading named fields into a positional tuple and coercing every
 * absent one to `null`.
 *
 * **Never hash the built iCalendar resource.** It carries a `DTSTAMP`, so two
 * serialisations of an identical change differ by construction — the hash would
 * refuse every commit, and the obvious "fix" would be to stop comparing.
 *
 * Attendees become fixed-order `[foldedAddress, name]` pairs sorted by the
 * folded address, so the same three people in a different order are the same
 * change.
 *
 * **Duplicate addresses collapse FIRST-WINS**, keeping the earlier entry's
 * name. That is the rule this project already chose once, for duplicate
 * message headers, and choosing it again rather than inventing a second one is
 * the point. The consequence is worth naming because it is caller-visible: the
 * recipient count CALW-08 reports is the COLLAPSED count, because that is how
 * many people are actually told.
 *
 * **No Unicode normalisation is applied to an address or to a name.** NFC and
 * NFD are left exactly as the caller sent them. Normalising a person's own name
 * — or their own address — is a repair, and this project refuses repairs on
 * user-authored text as firmly as it refuses them on stranger-authored text.
 * Stated here so a later reader does not "fix" it; a test pins it red.
 */
export function canonicalChange(change: NormalizedChange): string {
  const seen = new Set<string>();
  const attendees: [string, string | null][] = [];

  for (const attendee of change.attendees ?? []) {
    const folded = foldAddress(attendee.email);
    if (seen.has(folded)) continue;
    seen.add(folded);
    attendees.push([folded, attendee.name ?? null]);
  }

  attendees.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  return JSON.stringify([
    change.kind,
    change.scope ?? null,
    change.summary ?? null,
    change.startLocal ?? null,
    change.startTzid ?? null,
    change.endLocal ?? null,
    change.endTzid ?? null,
    change.allDay ?? false,
    change.location ?? null,
    change.description ?? null,
    attendees,
  ]);
}

/** The canonical change, digested and carried as base64url. */
export async function changeHashOf(change: NormalizedChange): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    TOKEN_ENCODER.encode(canonicalChange(change)),
  );
  return toBase64Url(new Uint8Array(digest));
}

/**
 * Whether two change hashes name the same change, in constant time.
 *
 * Both sides are digested AGAIN and the two 32-byte digests compared. Digesting
 * an already-digested value looks redundant and is not: it is `secretMatches`'
 * reason one module over. The runtime's comparison THROWS on inputs of unequal
 * length, and a throw that happens only for the wrong length is itself an
 * oracle — so a caller-supplied hash of the wrong size would be distinguishable
 * from one of the right size that simply did not match. Digests are always 32
 * bytes, which is what makes the comparison reachable unconditionally.
 *
 * A plain `===` here would be a timing oracle, and no comparison loop is
 * hand-rolled anywhere in this repository.
 */
export async function changeHashMatches(
  a: string,
  b: string,
): Promise<boolean> {
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", TOKEN_ENCODER.encode(a)),
    crypto.subtle.digest("SHA-256", TOKEN_ENCODER.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(left, right);
}

/**
 * Claim a confirmation's one-time slot, or refuse.
 *
 * Reads the key first and refuses if it is present, so an already-spent
 * confirmation is rejected with ZERO outbound requests to iCloud — the KV read
 * precedes any network call, which is what the requirement asks for and what
 * `If-Match` structurally cannot deliver, because `If-Match` IS the request.
 *
 * **The write happens BEFORE the caller's own write, and that ordering is the
 * decision.** A Worker invocation can end at any point. Writing the spent
 * record AFTER a successful write leaves a window in which the write landed and
 * the confirmation is still live; writing it before leaves a window in which
 * the confirmation is spent and the write did not land. The second failure
 * costs the user one re-preview and the first costs them a second, unintended
 * change to their calendar. Fail toward the recoverable side.
 *
 * **A failed KV write FAILS the reservation, and this is the one place this
 * module deliberately diverges from the discovery cache.** That cache swallows
 * a failed write silently, because a failed cache write degrades the call to
 * uncached and the values in hand are correct either way. Here the failed write
 * means the single-use guarantee does not hold for this confirmation, so
 * proceeding would be enforcing nothing while reporting that it had. The caught
 * value is never read — only its existence matters, and reading it would put
 * whatever KV said into a path that must stay silent.
 *
 * `expirationTtl` is the confirmation's OWN remaining life, floored at 60
 * because KV refuses less. The floor extends the RECORD and never the
 * confirmation: the token still dies at `x`, and a record that expired before
 * its token did would let that token be spent twice.
 */
export async function reserveConfirmation(
  kv: KVNamespace,
  /**
   * The signed-in user, from the principal.
   *
   * Never parsed out of the key, and never the id the confirmation itself
   * carries. That second half is the one a reader is tempted by — the slot
   * belongs to the token, surely — and it is wrong. The two values are equal
   * whenever this runs, because `verifyConfirmation` already refused a
   * mismatch, so taking it off the confirmation would make this slot DEPEND on
   * that check instead of standing beside it. Audit row T1 is closed by the
   * two standing separately: keyed on the caller, somebody presenting another
   * person's confirmation burns a slot under their OWN id and the owner's
   * confirmation still spends. Keyed on the confirmation, they burn the
   * owner's slot and the owner previews again, which is T1 as it was.
   *
   * The swap is invisible to every test in this repository. What refuses it is
   * the `confirm-reserve-keyed-on-the-token` scan rule, which is anchored on
   * this call and reads the argument list. Its limits are written down beside
   * it; binding the value to a local first walks past it.
   *
   * The banned member is described by role here and never spelled, on the same
   * footing as the transport and write rules: a comment naming it would fail
   * the check it was explaining.
   */
  userId: string,
  jti: string,
  expirySeconds: number,
): Promise<void> {
  const key = `${CONFIRM_KEY_PREFIX}${userId}:${jti}`;

  const existing = await kv.get(key);
  if (existing !== null) throw new ConfirmationInvalidError();

  const remaining = expirySeconds - Math.floor(Date.now() / 1000);
  try {
    await kv.put(key, "1", { expirationTtl: Math.max(remaining, 60) });
  } catch {
    throw new ConfirmationInvalidError();
  }
}

/**
 * Whether a parsed value has every field a `ConfirmPayload` must have.
 *
 * The seal has already verified by the time this runs, so this is not
 * defending against a forgery — it is defending against a payload THIS server
 * signed under a different build, which is the case the version field exists
 * for and the case a type assertion would wave through. A missing field would
 * otherwise reach a caller as `undefined` in the slot naming which resource to
 * write to.
 */
function isConfirmPayload(value: unknown): value is ConfirmPayload {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;

  if (!hasConfirmPayloadBase(candidate)) return false;

  // Dispatched on the discriminator with a plain comparison rather than a
  // `switch`, because there is no `switch` on a union discriminant anywhere
  // under `src/` and one here would be the first.
  //
  // The FALL-THROUGH is the load-bearing line, not the arms. A `t` this build
  // does not know — a value from a later build, or no `t` at all — reaches the
  // `false` below and the token is refused. An arm added without a branch here
  // is therefore refused rather than admitted with nothing checked.
  if (candidate.t === "dav") return hasDavObjectArm(candidate);
  if (candidate.t === "col") return hasDavCollectionArm(candidate);
  return false;
}

/** The protocol-neutral fields every arm carries. See `ConfirmPayloadBase`. */
function hasConfirmPayloadBase(candidate: Record<string, unknown>): boolean {
  return (
    typeof candidate.v === "number" &&
    (candidate.k === "create" ||
      candidate.k === "update" ||
      candidate.k === "delete") &&
    typeof candidate.j === "string" &&
    typeof candidate.h === "string" &&
    // No `"u" in candidate` companion, and the difference from `s` on the
    // object arm is deliberate rather than an omission. `s` needs one because
    // its type ADMITS null, so an absent field and a present null are both
    // `candidate.s === null` and the predicate cannot tell them apart. `u` is a
    // plain string, and `undefined` fails a `typeof === "string"` test on its
    // own — a payload with no user field is already refused by this line.
    typeof candidate.u === "string" &&
    typeof candidate.x === "number" &&
    Number.isInteger(candidate.x)
  );
}

/** The fields `DavObjectConfirmPayload` adds, and the ones it must NOT carry. */
function hasDavObjectArm(candidate: Record<string, unknown>): boolean {
  return (
    typeof candidate.c === "string" &&
    typeof candidate.o === "string" &&
    (candidate.r === null || typeof candidate.r === "string") &&
    (candidate.e === null || typeof candidate.e === "string") &&
    // A payload from a build that predates the field arrives with `s` absent,
    // and absent must NOT read as "the resource carried no revision" — that is
    // the reading that emits `SEQUENCE:1` over a stored three. Refused here
    // instead, which is what the version field and this predicate exist for:
    // the token is five minutes old at most, so the cost of refusing is one
    // re-preview and the cost of admitting it is a silent lost update.
    (candidate.s === null ||
      (typeof candidate.s === "number" && Number.isInteger(candidate.s))) &&
    "s" in candidate &&
    // And NOT a collection binding. Refusing a field that is PRESENT but does
    // not belong is the half a structural predicate usually skips, and it is
    // the half that matters on a union: a payload carrying both an ETag and a
    // binding satisfies both arms, and the one that reads it is whichever
    // asked first. See `hasDavCollectionArm` for the mirror of this line.
    !("b" in candidate)
  );
}

/**
 * The fields `DavCollectionConfirmPayload` adds, and the ones it must NOT carry.
 *
 * The three absences are asserted rather than assumed. A collection payload
 * that also carried an ETag would satisfy the object arm, and the whole point
 * of `b` is that a collection target cannot be committed as an object one.
 */
function hasDavCollectionArm(candidate: Record<string, unknown>): boolean {
  return (
    typeof candidate.c === "string" &&
    typeof candidate.o === "string" &&
    // Non-empty, and the emptiness check is not fussiness. An empty binding is
    // the shape a missing header or a blank property answer reaches by
    // accident, and it is not "no binding" — it is a binding that compares
    // equal to the next empty one. `b`'s type forbids `null`; this forbids the
    // value a cast or a malformed payload would reach for instead.
    typeof candidate.b === "string" &&
    candidate.b.length > 0 &&
    !("e" in candidate) &&
    !("r" in candidate) &&
    !("s" in candidate)
  );
}
