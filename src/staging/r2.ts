// The staging bucket. Bytes land here between the call that stages them and
// the call that attaches them to a draft, and nowhere else.
//
// **This module is the first of its kind in the repository.** 04-PATTERNS.md
// verified it: there is no object storage anywhere else in this codebase, and
// the discovery cache one tree over is a get-or-refresh cache with a TTL rather
// than blob storage, so its access shape does not transfer. Two things were
// borrowed rather than invented, and only two — the module-header shape and the
// mint/decode discipline from `../mail/ids.ts`, and the containment instinct
// from `../dav/discovery.ts`'s `assertUnderHome`, which refuses a request target
// that is not underneath the account's own home. Nothing else here has a
// precedent and nothing else pretends to.
//
// **Every operation in this module happens OUTSIDE the mail session**, and that
// is an architectural rule rather than a preference. Production allows six
// simultaneous connections per Worker invocation and the budget counts object
// storage against the same six slots as sockets, outbound requests and cache
// reads — one of which the OAuth provider has already spent before any of this
// code runs. So a storage round trip taken while a socket is open is a
// connection held for the duration of an unrelated operation, against iCloud's
// own per-account ceiling, which is lower, undocumented and deliberately
// unmeasured. The ordering is held structurally: nothing in this file can open
// a session, because nothing in this file imports anything that could.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { Env } from "../env";
import { STAGED_ID_TTL_MS, encodeStagedId } from "../mail/ids";

/**
 * The one prefix every staged object lives under.
 *
 * **A lifecycle rule created OUT OF BAND expires everything beneath this prefix
 * after one day, and that rule is not in git.** It is account state; nothing in
 * this repository proves it exists, and
 * `.planning/milestones/v1.0-phases/04-mail-write-attachments/04-UAT.md` holds
 * its recorded listing instead. That path moved when the first milestone was
 * archived; the listing is the same one. That sentence is here because the
 * alternative is a later reader treating this prefix as decoration — renaming
 * it, flattening it, or dropping it for a bare key — which would silently
 * detach every object written afterwards from the only thing that sweeps
 * abandoned bytes away (D-81's third layer). The prefix IS the sweep's
 * selector.
 *
 * **A key carries a user segment beneath this prefix, and the sweep still
 * reaches it.** A store prefix matches through separators, so a rule on
 * `staging/` covers `staging/<user id>/<name>` exactly as it covered the flat
 * form. The rule was read again before the segment was added, and it was
 * unchanged; no expiry has been observed, only the rule read and the semantics
 * cited.
 *
 * Trailing slash included, so a key is a concatenation and never a join.
 */
export const STAGING_PREFIX = "staging/";

/**
 * The ceiling on one staged file, decoded.
 *
 * **CALIBRATED, NOT MEASURED**, and that sentence comes first for the reason the
 * wire-size ceiling in `../mail/service.ts` gives: a reader who believes this
 * number was measured against real files will never revisit it, and it has not
 * been. It is derived from three things this project does know, and from
 * nothing else.
 *
 * **Far above any real case this project exists to serve.** The driver sentence
 * is a job-description PDF, which runs 50-500 KB, and a resume, which runs
 * 100-300 KB. Four mebibytes is an order of magnitude above both.
 *
 * **Far below anything that threatens the isolate.** A naive assembly of a
 * message carrying a file of size F holds roughly six times F live before the
 * garbage collector can reach any of it — the fetched bytes, an intermediate
 * one-byte string, the unwrapped base64, the wrapped copy, the assembled
 * message and its encoded form. Six times four mebibytes is about 25 MB against
 * a 128 MB isolate. The naive figure is the right one to size against, because
 * the naive shape is what gets written first.
 *
 * **Consistent in REASONING with the three ceilings already shipped**, all of
 * which sit at 2 MiB and all of which argue exactly this way. That consistency
 * is worth more than the extra few megabytes nobody will use: four constants
 * that were each derived the same way can be re-derived by one reader, and four
 * that were each picked differently cannot.
 *
 * It also leaves the assembled-message ceiling comfortably under Apple's
 * published per-message limit — read from the support page rather than inferred,
 * and recorded in `04-UAT.md` — even with two attachments and a long quoted
 * thread. That matters because the failure the user should see is this server's
 * stated refusal at staging time, not Apple's silent rejection hours later in
 * Mail.app with nothing connecting it to the tool call that caused it.
 */
export const MAX_STAGED_FILE_BYTES = 4 * 1024 * 1024;

/**
 * The ceiling on a file handed over as base64 inside a tool call, decoded.
 *
 * **Bounded by the model's context, not by the isolate's heap**, and the two
 * constants sit sixteen times apart for exactly that reason. Base64 inflates by
 * a third, so 256 KiB of source arrives as roughly 350 KB of text in a single
 * tool argument — already tens of thousands of tokens. A 400 KB file becomes
 * about 533 KB of base64, which is roughly a hundred and fifty thousand tokens
 * in one call. That is the arithmetic D-78 records as severe, and this is the
 * number behind it.
 *
 * `ARCHITECTURE.md` §5 already says tool arguments are not the place for binary
 * payloads. This constant is what turns that sentence into a refusal.
 *
 * The path that needs a real file is the other one: copying an attachment
 * straight out of a message spends no context at all, because not one byte
 * passes through the transcript.
 */
export const MAX_INLINE_BASE64_BYTES = 256 * 1024;

/**
 * The longest sanitised name a key may carry.
 *
 * A bound rather than a repair, which is why it does not refuse: an object key
 * has a byte ceiling of its own, and a name is a label for a human reading a
 * listing rather than data. Ninety-six characters is longer than any filename a
 * person types and short enough that the finished key stays far inside the
 * store's limit even after the prefix and the timestamp are added.
 */
const MAX_STAGED_FILENAME_CHARS = 96;

/**
 * How many random bytes lead a staged object's key.
 *
 * Eight, matching `KEY_RANDOM_BYTES` in `./presign.ts` so the two staging paths
 * build keys the same width. Sixty-four bits is far more than the collision it
 * closes needs — two stages inside one millisecond — and the segment is not a
 * secret and guards nothing: `underStagingPrefix` is what keeps a forged
 * identifier confined, and it does that by comparing the key's USER SEGMENT
 * against the signed-in caller's own id rather than by anyone having to guess
 * these characters. Guessing these eight bytes would buy nothing anyway: a key
 * naming someone else's segment is refused however well formed the rest of it
 * is.
 */
const KEY_RANDOM_BYTES = 8;

/**
 * The one shape a user id can take: 64 lowercase hex, anchored at both ends.
 *
 * No `g` flag, so it carries no `lastIndex` between calls and is safe to share
 * with `./presign.ts`, which imports it so the two checkers cannot drift.
 */
export const USER_SEGMENT = /^[0-9a-f]{64}$/;

/**
 * The character class refused outright in a name, rather than stripped.
 *
 * CR and LF terminate a header line early and inject a second one, and NUL is
 * rejected outright by every conformant HTTP implementation. That matters twice
 * here rather than once: the name shapes an object key, AND the untouched
 * original is written into custom metadata, where it becomes a header value on
 * the S3 path. Refusing at the single point every name enters this module is
 * what stops the second landing ever being reached.
 *
 * The class is widened to every C0 and C1 control character, because none of
 * them belongs in a filename and the three named above are only the ones with a
 * known exploit today.
 */
const CONTROL_CHARACTERS = /[\x00-\x1f\x7f-\x9f]/;

/** The characters a sanitised name may contain, and nothing else. */
const DISALLOWED_IN_NAME = /[^A-Za-z0-9._-]/g;

/**
 * A conservative media type: two tokens either side of one slash.
 *
 * Not a gate on WHAT may be staged — see `StageRequest.mimeType` — but a gate on
 * what may be written into a stored header. A declared type that does not match
 * is replaced by the neutral default below for storage purposes only, and the
 * declared value still round-trips through custom metadata and is reported to
 * the caller as declared rather than as verified.
 */
const MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;

/** What an unusable declared type is stored as. Says nothing about the bytes. */
const DEFAULT_MEDIA_TYPE = "application/octet-stream";

/** The custom-metadata keys this module writes. ASCII, and fixed. */
const META_FILENAME = "filename";
const META_MIME_TYPE = "declaredType";
const META_SIZE = "declaredSize";
const META_STAGED_AT = "stagedAt";

/**
 * Why a stage did not happen, from a closed set.
 *
 * **A refusal is a field on a SUCCESSFUL result, never a raised error**, and the
 * precedent is the shipped charset rejection in `../mail/service.ts`: the call
 * RAN, this server declined to store what it was given, and none of the four
 * values in the closed error vocabulary describes that honestly. D-35 closed
 * that vocabulary at four deliberately and phases three through six all inherit
 * it; a fifth category for "too big" was considered there and rejected, and
 * nothing here reopens it.
 *
 * Handing the model two numbers is a clearer reason than any sentence would be,
 * because the numbers are what it needs in order to explain the problem to the
 * user — a sentence is a thing it has to parse and paraphrase.
 */
export type StageRefusal = "too-large" | "empty" | "filename-unusable";

/**
 * What one staging attempt produced.
 *
 * The success arm carries an identifier and never a key. The key is inside the
 * token and stays there: a bucket key is a constructible string, and D-77
 * rejected handing one to the model for precisely that reason.
 */
export type StageResult =
  | {
      staged: true;
      /** The opaque staged id, minted in the one identifier module. */
      id: string;
      /** The name the object was stored under, sanitised. */
      filename: string;
      /** The decoded byte count actually written. */
      sizeBytes: number;
      /** When the identifier stops decoding, as an ISO instant. */
      expiresAt: string;
    }
  | {
      staged: false;
      refusal: StageRefusal;
      /** What was offered. Zero on an empty payload. */
      sizeBytes: number;
      /** The ceiling it was decided against. */
      limitBytes: number;
    };

/** One staged object, read back. */
export interface StagedObject {
  /** The key it was found under. Always beneath the staging prefix. */
  key: string;
  /** The bytes exactly as written. */
  bytes: Uint8Array;
  /** The ORIGINAL filename, unsanitised. Stranger- or caller-authored. */
  filename: string | null;
  /** The DECLARED media type. Declared at stage time, never verified. */
  mimeType: string;
  /** The instant it was written, in epoch milliseconds. */
  stagedAt: number;
  /** The decoded byte count. */
  sizeBytes: number;
}

/**
 * One staged object's metadata, WITHOUT its bytes.
 *
 * **Structurally `StagedObject` minus the one expensive field**, and the
 * omission is the entire point rather than an economy. A caller that only needs
 * to know how big an object is must not have to allocate it to find out — a
 * size check performed after the allocation it exists to prevent is not a
 * bound, it is a report.
 *
 * `sizeBytes` here is R2's own recorded object size rather than the length of
 * an array this module read, which is the same fact by a cheaper route: the
 * store counted the bytes as they landed.
 */
export interface StagedHead {
  /** The key it was found under. Always beneath the staging prefix. */
  key: string;
  /** The ORIGINAL filename, unsanitised. Stranger- or caller-authored. */
  filename: string | null;
  /** The DECLARED media type. Declared at stage time, never verified. */
  mimeType: string;
  /** The size R2 recorded for the object. */
  sizeBytes: number;
}

/** One staging attempt, described completely. */
export interface StageRequest {
  /** The decoded bytes. Never base64, never transfer-encoded. */
  bytes: Uint8Array;
  /**
   * The name to stage under.
   *
   * Untrusted on both paths: sender-authored when the file came out of a
   * message, caller-authored when it arrived in a tool argument.
   */
  filename: string;
  /**
   * The declared media type.
   *
   * **Metadata, never a gate.** It is declared by whoever supplied the file and
   * this server does not sniff content to check it. Nothing branches on it, so a
   * wrong one costs a mislabelled object rather than a wrong decision.
   */
  mimeType: string;
  /**
   * The ceiling THIS call is decided against.
   *
   * A parameter so the inline path can be bounded lower than the per-file cap,
   * and clamped below so it can never be bounded HIGHER. A ceiling a caller can
   * raise is a ceiling this module only advises, and the caller is one edit away
   * from being wrong about it.
   */
  limitBytes: number;
  /** The instant, injected. This module never reads the wall clock itself. */
  nowMs: number;
}

/**
 * Reduce a stranger's filename to something that can safely name an object.
 *
 * **This is the one place in the phase that deliberately runs against this
 * project's refuse-rather-than-repair grain, and D-83 records it as such on
 * purpose.** Written down here because a reviewer who knows the project's habit
 * and does not know the decision will read this function as an oversight and
 * "fix" it back to a refusal. The trade was made with its cost named: a
 * sanitiser is a thing that can be subtly wrong, and it was chosen anyway,
 * because seeing `resume.pdf` in a bucket listing beats seeing a UUID when
 * working out what accumulated. What is NOT repaired is anything dangerous —
 * see the refusals below.
 *
 * **That encoded traversal is a live concern rather than a hypothetical**, and
 * this project has its own record of it: `../mail/mime.ts`'s T-02-22 note
 * records that percent-decoding the wrong parameter section turns an encoded
 * separator sequence into a real one. Nothing here decodes anything; the
 * allowlist below refuses a percent sign along with everything else outside it,
 * so the encoded form never becomes the decoded one.
 *
 * Three things are REFUSED rather than cleaned, and returning `null` is how:
 *
 *   - Any control character, CR, LF and NUL included. They have no escaped form
 *     in a header value and no business in a filename.
 *   - A name that reduces to nothing. Without this the key would be the prefix
 *     and a timestamp, which identifies no file to anyone reading the listing —
 *     the exact property the derivation exists to buy.
 *   - Nothing else. Everything outside the allowlist becomes a hyphen.
 */
export function sanitiseFilename(name: string): string | null {
  if (typeof name !== "string" || name.length === 0) return null;
  if (CONTROL_CHARACTERS.test(name)) return null;

  const reduced = name
    .replace(DISALLOWED_IN_NAME, "-")
    .replace(/-+/g, "-")
    .replace(/\.+/g, ".")
    .replace(/^[.-]+/, "")
    .replace(/[.-]+$/, "")
    .slice(0, MAX_STAGED_FILENAME_CHARS)
    .replace(/[.-]+$/, "");

  return reduced.length === 0 ? null : reduced;
}

/**
 * Derive the key one staged file is written under.
 *
 * `staging/{sanitised name}-{epoch milliseconds}`, per D-83.
 *
 * **The prefix check at the end is a POST-condition, not a pre-condition, and
 * that placement is the load-bearing half of this function.** A pre-condition
 * asks whether the input looked safe; a post-condition asks whether the finished
 * key actually is, and it holds no matter what the sanitiser above missed. It is
 * the same instinct `assertUnderHome` embodies one protocol over, where the
 * question is whether a constructed request target really does sit beneath the
 * account's own home rather than whether the token that produced it looked
 * plausible.
 *
 * **D-83's collision window is CLOSED, and this paragraph records why the
 * accepted cost stopped being acceptable.** The original derivation was
 * `{sanitised name}-{epoch milliseconds}`, and D-83 knowingly took a residual:
 * two stages inside the same millisecond produce the same key. At the time the
 * worst case was one draft carrying the wrong file. D-81's delete-on-attach then
 * COMPOUNDED it — a successful attach deletes the staged object, so a collision
 * became one draft's attach removing bytes another draft still points at. Plan
 * 04-09 recorded that escalation; the developer reversed the trade on 2026-08-21
 * once the consequence had changed, and this is that reversal.
 *
 * The random segment leads, and the name still follows it, so the legibility
 * D-83 chose the derivation FOR is unaffected: a bucket listing still shows
 * `resume.pdf` next to every key. What it no longer shows is two of them that
 * are the same key.
 *
 * **The random segment leads rather than separating name from timestamp**, and
 * the shape deliberately matches `presignedKeyFor`'s
 * `{stem}-{random}-{milliseconds}` one module over. Two staging paths that build
 * keys in visibly different shapes are two paths a reader has to check
 * separately.
 *
 * It stays inside ONE path segment rather than becoming `{random}/{name}`. The
 * post-condition below rejects a slash in the name portion, and that rejection
 * is the load-bearing half of this function — a nested form would have required
 * loosening it, which is the wrong direction for a check whose whole value is
 * that it constrains the finished key.
 *
 * **This function is no longer deterministic, and that is the point.** Two calls
 * with identical arguments return different keys. A test asserting equality
 * across two calls would be asserting the collision.
 *
 * `userId` is the signed-in user's id, and it LEADS the parameter list for
 * `underStagingPrefix`'s reason — see that function. It becomes the key's own
 * segment, directly beneath the prefix, which is what makes a staged object
 * belong to one user rather than to whoever can name it.
 */
export function stagingKeyFor(
  userId: string,
  filename: string,
  nowMs: number,
): string | null {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) return null;

  const safe = sanitiseFilename(filename);
  if (safe === null) return null;

  const random = new Uint8Array(KEY_RANDOM_BYTES);
  crypto.getRandomValues(random);
  const segment = [...random]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  const key = `${STAGING_PREFIX}${userId}/${segment}-${safe}-${nowMs}`;

  // The post-condition. Anything below this line is a statement about the
  // FINISHED key rather than about the name it was built from.
  //
  // It calls the READ side's own checker rather than restating its rules. One
  // rule then governs both sides, and this function cannot emit a key the read
  // path would refuse — which is the failure mode a second copy produces the
  // moment the two copies drift by one condition.
  if (!underStagingPrefix(userId, key)) return null;
  const named = key.slice(STAGING_PREFIX.length + userId.length + 1);
  if (DISALLOWED_IN_NAME.test(named)) {
    DISALLOWED_IN_NAME.lastIndex = 0;
    return null;
  }
  DISALLOWED_IN_NAME.lastIndex = 0;

  return key;
}

/**
 * Refuse a key that does not sit beneath the CALLER's own segment of the
 * staging prefix.
 *
 * **This is not belt-and-braces on the writer; it is the check that makes the
 * READ side safe.** A staged identifier is unsigned — the identifier module
 * mints it as base64url over JSON with no signature, and D-21 recorded that
 * choice for cursors with the same reasoning — so a caller can construct one
 * naming any key it likes. The bucket is dedicated to staging, so the worst case
 * is reaching another staged object rather than anything of the user's; this
 * keeps even that unreachable, at the cost of one comparison.
 *
 * Returns rather than throws, because both callers already have a "there is
 * nothing there" answer that says exactly the right thing.
 *
 * **`userId` comes BEFORE `key`, and the order is the guard rather than a
 * style.** They are two adjacent strings, so a call site can transpose them and
 * the typecheck cannot see it. Placing the id first makes every signature in
 * both staging modules read the same way round, which is the property a reader
 * can check at a glance. What CATCHES a transposition is the shape test below:
 * a key handed where an id belongs is not 64 hex characters, and an id handed
 * where a key belongs does not start with the prefix, so a transposed call is
 * refused the first time it happens, at runtime.
 *
 * **The id is PASSED IN and is never parsed out of the key.** That is the whole
 * difference between a check and a decoration. A staged identifier is something
 * a caller can write from nothing, so a checker that read the user segment out
 * of the key it was given would be comparing a value the caller chose against
 * itself: every check would pass and nothing would be refused.
 *
 * The rule, in the order it runs: the value is a string; it starts with the
 * prefix; the remainder holds a separator past its first character; the
 * remainder holds no SECOND separator; the segment before the separator is 64
 * lowercase hex; that segment equals the passed-in id; the segment after it is
 * non-empty; neither segment holds a dot-dot.
 *
 * It is deliberately NOT "any depth beneath the user segment". Nothing this
 * project builds produces a deeper key, so the only producer of one is a
 * forgery.
 *
 * **Exported, and the export is the point.** Four call sites depend on this
 * rule: the read, head and delete paths here, `stagingKeyFor`'s own
 * post-condition, and the write grant in `./presign.ts`. The grant used to
 * restate all seven conditions by hand, sharing only `USER_SEGMENT` while its
 * docstring claimed the two could not drift — true of the constant, false of
 * the logic. One rule now governs every one of them, so a drift of one
 * condition is not detected, it is unwriteable. That is the same argument
 * `stagingKeyFor` makes three hundred lines up, applied to the one caller that
 * had ignored it.
 *
 * The two answers a caller can want are NOT unified, and that difference is
 * deliberate. This returns, because the read paths have a "there is nothing
 * there" answer that says exactly the right thing. The grant throws, because
 * there is no capability to hand back and a silent failure there would be
 * indistinguishable from success — and because a returned `false` on a
 * grant path is an existence oracle. Keep the refusal at the call site; the
 * RULE is what is shared.
 */
export function underStagingPrefix(userId: string, key: string): boolean {
  if (typeof key !== "string") return false;
  if (!key.startsWith(STAGING_PREFIX)) return false;

  const rest = key.slice(STAGING_PREFIX.length);
  const slash = rest.indexOf("/");
  // No user segment at all — the shape every object staged before this landed.
  if (slash <= 0) return false;
  // A second separator: deeper than anything this project builds.
  if (rest.indexOf("/", slash + 1) !== -1) return false;

  const segment = rest.slice(0, slash);
  const named = rest.slice(slash + 1);

  // **The shape test is not redundant with the equality below.** It refuses a
  // key when the CALLER's own id is malformed — an empty or absent id would
  // otherwise admit whatever key happened to carry the same empty segment —
  // and it is what catches a transposed `userId`/`key` pair, which the
  // typecheck cannot see because both are strings. It also states the shape at
  // the one place a reader will look for it.
  if (!USER_SEGMENT.test(segment)) return false;
  if (segment !== userId) return false;
  if (named.length === 0) return false;
  // The hex shape already excludes a dot-dot from the first segment. The line
  // states the rule for both segments rather than leaving one of them resting
  // on a second constant's shape, which is what would silently go false if that
  // shape were ever widened.
  if (segment.includes("..") || named.includes("..")) return false;
  return true;
}

/**
 * Encode one value for storage in custom metadata.
 *
 * **Those keys become `x-amz-meta-*` HEADERS on the S3 path**, so a value
 * carrying CR or LF would terminate a header line early and inject a second one
 * built from a stranger's own bytes. The untouched original filename is written
 * here, which makes this the SECOND place the same untrusted string arrives —
 * and the easier of the two to miss, because the key derivation is the one
 * everybody remembers to guard.
 *
 * Percent-encoding rather than refusing, and the difference from the sanitiser's
 * disposition is deliberate: this is a lossless transformation with an exact
 * inverse, so the original survives intact and can be read back byte for byte.
 * Refusing here would additionally throw away a perfectly ordinary non-ASCII
 * filename, which is the common case rather than the adversarial one.
 *
 * The assertion below is a post-condition that cannot fire, and it stays for
 * `stagingKeyFor`'s reason: it is a statement about the finished value rather
 * than about the transformation that produced it, so it holds if the
 * transformation is ever changed to something weaker.
 *
 * **The encode is TOTAL, and the `catch` is reachable rather than defensive.**
 * `encodeURIComponent` throws `URIError` on a lone surrogate, and a lone
 * surrogate survives every check upstream of here: it is a legal JSON string,
 * it passes `z.string()`, `CONTROL_CHARACTERS` does not match it, and the
 * sanitiser reduces it to a perfectly valid key. Without the guard `putStaged`
 * throws instead of returning, which breaks its stated contract that every
 * refusal returns before a byte is written — and the throw then escapes to the
 * tool boundary, where `toErrorCategory` maps a class it does not recognise to
 * `connection_failed` and tells the model the failure "may be transient — safe
 * to retry once." It is not transient. The same name fails identically forever,
 * so the model retries a call that can never succeed.
 *
 * `null` rather than a distinct answer, because a name this module cannot
 * encode is a name it cannot store, which is exactly what the existing
 * `filename-unusable` refusal already says. Note the asymmetry this closes:
 * `metadataValueOf` on the read side has always wrapped its decode.
 */
function metadataValue(raw: string): string | null {
  let encoded: string;
  try {
    encoded = encodeURIComponent(raw);
  } catch {
    // The caught value is never read.
    return null;
  }
  return /^[\x20-\x7e]*$/.test(encoded) ? encoded : null;
}

/**
 * A stored content type, if R2 holds a usable one.
 *
 * Only the presigned ingress ever reaches this — the binding-side paths write
 * `META_MIME_TYPE` into custom metadata and resolve before it. See `getStaged`
 * for why the arm exists (WINDOWS 51).
 *
 * `MEDIA_TYPE` is the gate rather than a bare non-empty check, and deliberately
 * the SAME gate `putStaged` applies on the way in. The value originates in a
 * header the uploading client chose, and it ends up in the `Content-Type` of a
 * message the user sends under their own name — 04-09 already had to close the
 * neighbouring hole where a stranger-declared type could inject a parameter
 * there. Anything that does not match a plain `type/subtype` is treated as
 * absent, which lands the caller on the neutral default rather than on the
 * client's text.
 */
function storedContentType(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return MEDIA_TYPE.test(trimmed) ? trimmed : null;
}

/**
 * The media type one stored object should be reported as carrying.
 *
 * **One function rather than an expression at each read site**, because there
 * are now two of them — the body-bearing read and the metadata-only one — and a
 * resolution order that disagreed between them would report a different type
 * for the same object depending on which call the caller happened to make.
 *
 * The custom-metadata key first, then the object's own stored content type,
 * then the default. **The middle arm is the presigned ingress and it was added
 * after a live defect, not on principle** (WINDOWS 51, observed 2026-08-21).
 *
 * `putStaged` writes `META_MIME_TYPE` into `customMetadata`, so the two
 * binding-side ingresses — from-message and inline base64 — resolve on the
 * first arm. A presigned upload never calls `putStaged`: it goes straight to
 * R2's S3 API, and `mintUploadUrl` signs only the filename metadata header. So
 * that key is simply ABSENT on a presigned object, the read fell through to the
 * default, and a declared `text/plain` arrived in the draft as
 * `application/octet-stream`. The from-message path kept `application/pdf` in
 * the same session, which is the control that isolated it to this branch.
 *
 * **The type was never lost, only unread.** The uploader's `content-type`
 * header is part of the signature — an oversize probe proved the signature
 * covers `content-length` on the same terms — so R2 stores it as the object's
 * own content type. Consulting it here fixes the defect with no change to the
 * caller's upload invocation, which is why this arm is preferable to signing a
 * second metadata header the uploader would then have to reproduce exactly.
 *
 * **The two arms are NOT equally validated, and the asymmetry is deliberate —
 * but it is not what an earlier version of this comment claimed.** That version
 * said "a type reaching a caller has passed the identical check whichever
 * ingress produced it." That is true of the second arm and FALSE of the first,
 * and the difference matters because a reader deciding whether a new consumer of
 * `StagedObject.mimeType` needs a gate of its own would have trusted it.
 *
 * - **Second arm — GATED.** The stored content type is a plain string from R2,
 *   not a custom-metadata value, so it is validated against `MEDIA_TYPE` here
 *   rather than decoded. That is the same gate `putStaged` applies on the way
 *   in.
 * - **First arm — NOT gated, on purpose.** `putStaged` writes `META_MIME_TYPE`
 *   as `metadataValue(request.mimeType)`, which requires only that the
 *   percent-encoded form be printable ASCII, and `metadataValueOf` decodes it
 *   back byte for byte. So the inline-base64 ingress round-trips a declared type
 *   EXACTLY as declared, including one carrying a parameter of its own. That is
 *   `MEDIA_TYPE`'s own stated property — the declared value "is reported to the
 *   caller as declared rather than as verified" — and reporting it faithfully is
 *   the point: the caller is told what was declared, not what this module would
 *   have preferred.
 *
 * **What that means for a caller: this value is DECLARED, never verified, and a
 * consumer that puts it into a header owes it a gate.** The one consumer that
 * does is `attachmentEntity` in `../mail/compose.ts`, which re-applies
 * `MEDIA_TYPE` and falls back to the neutral default — which is what keeps a
 * caller-supplied parameter out of the `Content-Type` of a message the user
 * sends under their own name. That containment is pinned by a test rather than
 * left to these two docstrings agreeing with each other, because they are in
 * different modules and only one of them is read at the call site.
 */
function stagedMimeType(
  metadata: Record<string, string> | undefined,
  contentType: string | undefined,
): string {
  return (
    metadataValueOf(metadata, META_MIME_TYPE) ??
    storedContentType(contentType) ??
    DEFAULT_MEDIA_TYPE
  );
}

/** Read one custom-metadata value back, or `null` if it was not written here. */
function metadataValueOf(
  metadata: Record<string, string> | undefined,
  key: string,
): string | null {
  const raw = metadata?.[key];
  if (raw === undefined) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    // The caught value is never read. A value this module did not write is not
    // a value this module can report, and refusing beats guessing at it.
    return null;
  }
}

/**
 * Write one file into the staging bucket, or say why not.
 *
 * The order of the three refusals is deliberate. The two size questions are
 * asked first because they are questions about the PAYLOAD, and a five-megabyte
 * file with an awkward name is more usefully described as too large than as
 * badly named — the first is the fact the user has to act on. The name question
 * is asked last and costs nothing to reach.
 *
 * Every refusal returns before a single byte is written, which is criterion 5's
 * first clause in mechanical form: rejected AT staging, with a reason, rather
 * than failing partway through placing a message into the drafts folder, where
 * the user would meet the failure with no obvious connection to the call that
 * caused it.
 *
 * The identifier is minted through the one identifier module and nowhere else,
 * with an absolute expiry of now plus the shared constant. D-82's ordering lives
 * in that constant's docstring and is not restated here, because restating it
 * would be a second copy that can drift from the one the decoder enforces.
 */
export async function putStaged(
  env: Env,
  userId: string,
  request: StageRequest,
): Promise<StageResult> {
  const sizeBytes = request.bytes.byteLength;
  // Clamped, never trusted: the parameter exists to bound this call LOWER.
  const limitBytes = Math.min(request.limitBytes, MAX_STAGED_FILE_BYTES);

  if (sizeBytes === 0) {
    return { staged: false, refusal: "empty", sizeBytes: 0, limitBytes };
  }
  if (sizeBytes > limitBytes) {
    return { staged: false, refusal: "too-large", sizeBytes, limitBytes };
  }

  const key = stagingKeyFor(userId, request.filename, request.nowMs);
  const storedFilename = metadataValue(request.filename);
  const storedType = metadataValue(request.mimeType);
  // `filename-unusable` has a second cause that the name does not describe, and
  // it is worth one clause here so nobody spends an afternoon on the filename.
  // Since Phase 10 `stagingKeyFor` also returns null when its post-condition
  // rejects the finished key because the USER ID is malformed, which has
  // nothing to do with the name. Unreachable today: every caller passes
  // `actor.userId`, and `userIdOf` guarantees 64 lowercase hex characters. The
  // refusal is not split because a second value would be a distinction the
  // caller cannot act on and this project does not hand callers refusal
  // vocabulary it cannot use.
  if (key === null || storedFilename === null || storedType === null) {
    return { staged: false, refusal: "filename-unusable", sizeBytes, limitBytes };
  }

  await env.ATTACHMENT_STAGING.put(key, request.bytes, {
    httpMetadata: {
      contentType: MEDIA_TYPE.test(request.mimeType)
        ? request.mimeType
        : DEFAULT_MEDIA_TYPE,
    },
    customMetadata: {
      [META_FILENAME]: storedFilename,
      [META_MIME_TYPE]: storedType,
      [META_SIZE]: String(sizeBytes),
      [META_STAGED_AT]: String(request.nowMs),
    },
  });

  const expiresAt = request.nowMs + STAGED_ID_TTL_MS;

  return {
    staged: true,
    id: encodeStagedId({ key, expiresAt }, request.nowMs),
    // The NAME, and only the name. The key carries a user segment between the
    // prefix and the name now, so slicing the prefix alone would put the
    // caller's own user id into a tool response. The post-condition above
    // proved the segment is exactly `userId`, so this offset is exact.
    filename: key.slice(STAGING_PREFIX.length + userId.length + 1),
    sizeBytes,
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

/**
 * Read one staged object back, or `null` when there is nothing there.
 *
 * A key outside the staging prefix is `null` rather than an error, and it is
 * `null` for the same reason a missing object is: from the caller's side the two
 * situations are identical, and a distinguishable refusal would be an existence
 * oracle handed to the very forged identifier the containment check exists to
 * refuse.
 */
export async function getStaged(
  env: Env,
  userId: string,
  key: string,
): Promise<StagedObject | null> {
  if (!underStagingPrefix(userId, key)) return null;

  const object = await env.ATTACHMENT_STAGING.get(key);
  if (object === null) return null;

  const bytes = new Uint8Array(await object.arrayBuffer());
  const stagedAt = Number(
    metadataValueOf(object.customMetadata, META_STAGED_AT) ?? "",
  );

  return {
    key,
    bytes,
    filename: metadataValueOf(object.customMetadata, META_FILENAME),
    mimeType: stagedMimeType(
      object.customMetadata,
      object.httpMetadata?.contentType,
    ),
    stagedAt: Number.isSafeInteger(stagedAt) ? stagedAt : 0,
    sizeBytes: bytes.byteLength,
  };
}

/**
 * Read one staged object's metadata, or `null` when there is nothing there.
 *
 * **The body is never fetched, and that is a memory bound rather than a
 * micro-optimisation.** `getStaged` materialises the whole object in the
 * isolate; a caller that only wants to know how large an object is — or what
 * name and type it was recorded under — would pay that allocation in order to
 * decide it was too big to allocate. The confirm step on the presigned ingress
 * is exactly that caller, so it reads through here.
 *
 * The three fields are resolved identically to `getStaged`'s: the same
 * containment check, the same filename decode, and the same `stagedMimeType`.
 * Sharing the resolution rather than restating it is what keeps the two reads
 * from answering the same question differently.
 *
 * A key outside the staging prefix is `null` rather than an error, for
 * `getStaged`'s reason: a distinguishable refusal would be an existence oracle
 * handed to a forged identifier.
 */
export async function headStaged(
  env: Env,
  userId: string,
  key: string,
): Promise<StagedHead | null> {
  if (!underStagingPrefix(userId, key)) return null;

  const object = await env.ATTACHMENT_STAGING.head(key);
  if (object === null) return null;

  return {
    key,
    filename: metadataValueOf(object.customMetadata, META_FILENAME),
    mimeType: stagedMimeType(
      object.customMetadata,
      object.httpMetadata?.contentType,
    ),
    sizeBytes: object.size,
  };
}

/**
 * Remove one staged object.
 *
 * **A delete of something that is not there is the NORMAL outcome and must not
 * fail**, because two of D-81's three layers re-delete freely: the attach path
 * deletes on success, and the bucket's own sweep may already have taken the
 * object. A delete that raised on an absent key would turn the backstop into a
 * failure mode.
 *
 * A key outside the prefix is a silent no-op for `getStaged`'s reason.
 */
export async function deleteStaged(
  env: Env,
  userId: string,
  key: string,
): Promise<void> {
  if (!underStagingPrefix(userId, key)) return;
  await env.ATTACHMENT_STAGING.delete(key);
}
