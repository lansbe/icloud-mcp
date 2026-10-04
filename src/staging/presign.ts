// The presigned upload path: a write grant this server signs, and the step that
// looks at what actually landed before any of it becomes usable.
//
// **This module is the ONLY reader of the two R2 credentials in the entire
// codebase**, and it is written in `../mail/credentials.ts`'s shape for that
// reason. The secrets are consumed and a URL STRING is returned. No object
// holding either of them is ever handed to a caller, so there is nothing to
// serialise, attach to an error, or spread into a response — and Convention 4's
// zero-logging rule covers them without amendment.
//
// **The honest limit on that claim, stated rather than left to be inferred.**
// The signing library's client object necessarily holds both values for the
// duration of one call: that is what a signer is. It is constructed inside the
// one function that signs, is never assigned at module scope, is never returned,
// and nothing in this repository reads a field off it. That is a weaker property
// than `credentials.ts`'s — where there is nothing to read because nothing is
// built — and `../dav/transport.ts` already records the same divergence in the
// same words for the same reason. Writing the weaker claim down is the point;
// asserting the stronger one would be false.
//
// This module contains no logging calls of any kind and must never acquire any.

import { AwsClient } from "aws4fetch";
import { mintFreeUpload } from "../free/upload";
import { isConfiguredSecret } from "../auth/login-handler";
import type { Env } from "../env";
import { ImapAuthError, ImapNotFoundError } from "../errors";
import { STAGED_ID_TTL_MS, encodeStagedId } from "../mail/ids";
import type { StageResult } from "./r2";
import {
  MAX_STAGED_FILE_BYTES,
  STAGING_PREFIX,
  deleteStaged,
  headStaged,
  underStagingPrefix,
} from "./r2";

/**
 * How long a minted URL stays usable.
 *
 * Fifteen minutes: short enough that a URL which leaks — into a transcript, a
 * shell history, a screenshot — is not a standing write grant against the
 * bucket, and long enough for a person to find a file and upload it without
 * having to ask for a second URL.
 *
 * **Unrelated to `STAGED_ID_TTL_MS`, and neither should ever be derived from
 * the other.** The two bound genuinely different things. This one bounds a
 * WRITE GRANT: how long anyone holding a string can put bytes into the bucket.
 * That one bounds an IDENTIFIER'S VALIDITY, and its value is pinned by D-82's
 * ordering against the bucket's own daily sweep — a token has to die before the
 * bytes it names. Tying them together would make a change to either one silently
 * a change to the other, and only one of the two has an argument behind its
 * number that a reader could reconstruct.
 */
export const UPLOAD_URL_TTL_SECONDS = 15 * 60;

/**
 * The storage host, per account.
 *
 * The account id comes from a Worker var rather than a literal here, for the
 * reason `wrangler.jsonc` gives at the `vars` block: one declared place, so a
 * change is visible in a diff rather than buried under the source tree.
 */
const STORAGE_HOST_SUFFIX = ".r2.cloudflarestorage.com";

/**
 * The bucket the grant is scoped to.
 *
 * A literal, and the one value in this module that duplicates configuration.
 * The binding in `src/env.ts` is an object with methods and no name on it — the
 * runtime does not expose the bucket it resolved to — so the S3-shaped path has
 * nowhere else to get this from. Kept beside the host above so the two halves of
 * the URL's prefix are read together, and it must stay equal to `bucket_name` in
 * `wrangler.jsonc`.
 */
const STAGING_BUCKET = "icloud-mcp-attachments";

/** The service and region a bucket's S3-compatible endpoint is signed for. */
const SIGNING_SERVICE = "s3";
const SIGNING_REGION = "auto";

/**
 * The characters that cannot appear inside an HTTP header value.
 *
 * The same three `../mail/credentials.ts` and `../dav/transport.ts` refuse, for
 * the same class of reason: CR and LF terminate a header line early and inject a
 * second one, and NUL is rejected outright by every conformant implementation.
 */
const ILLEGAL_IN_HEADER_VALUE = /[\r\n\x00]/;

/** What a percent-encoded metadata value is allowed to reduce to. */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** How many random bytes go into a presigned object key. */
const KEY_RANDOM_BYTES = 8;

/**
 * The fixed name segment every presigned key carries.
 *
 * **This path deliberately does NOT derive its key from the offered filename,
 * and that is a departure from D-83 scoped to this one ingress.** D-83 chose a
 * name-derived key for legibility when listing the bucket, and that argument is
 * unchanged everywhere else. It does not survive here for one specific reason:
 * the key becomes part of a URL this server publishes in the TRUSTED half of a
 * tool result, and plan 04-08 established that a sanitised derivative of
 * caller-authored text must not be published there — it shares most of its
 * characters with the original and arrives looking like server-derived data.
 *
 * Nothing is lost that mattered. The offered name still reaches the object, in
 * the metadata header signed into the grant below, so the file the recipient
 * receives carries the name the user gave it. What a bucket listing loses is the
 * ability to identify an ABANDONED object by name — and an abandoned object on
 * this path is one nobody confirmed, so there is no name this server ever
 * verified anyway.
 *
 * The random segment additionally CLOSES D-83's same-millisecond collision
 * window on this path, which is the deferred fix D-83 names in its own docstring
 * and declines only because it costs the legibility this path has already given
 * up.
 */
const PRESIGNED_KEY_STEM = "upload";

/** The metadata header carrying the offered filename to the object. */
const HEADER_META_FILENAME = "x-amz-meta-filename";

/** The two headers the correction below is about. */
const HEADER_CONTENT_TYPE = "content-type";
const HEADER_CONTENT_LENGTH = "content-length";

/** Everything one upload grant is asked for. */
export interface UploadRequest {
  /** The object key the grant is aimed at. Must sit beneath the staging prefix. */
  key: string;
  /** The media type the uploader declares, bound into the signature. */
  contentType: string;
  /** The exact byte count the uploader declares, bound into the signature. */
  contentLength: number;
  /**
   * The name to record on the object.
   *
   * Caller-authored, so untrusted. It travels in a signed metadata header rather
   * than in the key — see `PRESIGNED_KEY_STEM` — and is percent-encoded on the
   * way, exactly as `putStaged` encodes the same field for the same reason:
   * these values become headers on the S3 path.
   */
  filename: string;
}

/**
 * Refuse a binding that was never provisioned.
 *
 * **The check is BEHAVIOURAL, not compiler-driven, and must not be removed on
 * the grounds that the typecheck passes without it.** `../dav/transport.ts`
 * records the reason and it applies here unchanged: the values land in a
 * template literal, and a template literal accepts an absent binding silently —
 * it stringifies to the nine characters spelling the absent value. Without this,
 * an unprovisioned account id produces a syntactically perfect URL aimed at a
 * host named for a value nobody set, and an unprovisioned key produces a
 * well-formed signature over an empty credential. Neither announces itself; both
 * surface as a rejection from the storage endpoint hours later, in a context
 * with nothing connecting it back to the missing configuration.
 *
 * `isConfiguredSecret` is reused rather than restated: one definition of what a
 * usable configured value looks like, shared with the authorize path that first
 * needed it.
 */
function assertProvisioned(value: string | undefined): asserts value is string {
  if (!isConfiguredSecret(value)) throw new ImapAuthError();
}

/** Refuse a value carrying a character that is illegal in a header value. */
function assertNoIllegalCharacters(value: string): void {
  if (ILLEGAL_IN_HEADER_VALUE.test(value)) throw new ImapAuthError();
}

/**
 * Refuse a key the grant must not be aimed at.
 *
 * A presigned URL is a bearer write capability. A key outside the staging prefix
 * is a grant to write somewhere the one-day sweep does not reach, so it would
 * leave bytes behind with nothing to remove them — and a key with a separator in
 * its name segment is a grant to write to a path the containment post-condition
 * in `./r2.ts` exists to make unreachable.
 *
 * Throws rather than returning, unlike its counterpart one file over. That one
 * guards a READ, where "there is nothing there" is both true and the right
 * answer; this guards the construction of a capability, where there is no
 * capability to hand back and silence would be indistinguishable from success.
 *
 * **`userId` comes BEFORE `key`, and the order is the guard rather than a
 * style**, exactly as in `underStagingPrefix` one file over. They are two
 * adjacent strings, so a call site can transpose them and the typecheck cannot
 * see it; putting the id first makes every signature in both staging modules
 * read the same way round. What CATCHES a transposition is the shape test
 * below: a key handed where an id belongs is not 64 hex characters, and an id
 * handed where a key belongs does not start with the prefix.
 *
 * **The id is PASSED IN and is never parsed out of the key**, for the reason
 * `underStagingPrefix` gives in full: a checker that read the user segment out
 * of the value it was handed would be comparing a caller's choice against
 * itself.
 *
 * **The rule is not restated here, it is CALLED.** This function used to
 * hand-copy all seven of the read side's conditions, importing only the shape
 * constant, and its docstring said "the shape constant is imported rather than
 * copied so the two cannot drift". That was true of the constant and false of
 * the logic, which is the worse half: a reader took the sentence to cover both,
 * and a one-condition drift would have opened the write grant or the read path
 * without opening the other, with no test in the repository able to see it.
 * `stagingKeyFor` had already made this exact argument for its own
 * post-condition — "the failure mode a second copy produces the moment the two
 * copies drift by one condition" — three hundred lines from the copy. One rule
 * now governs all four call sites and the docstring's claim is true rather than
 * asserted.
 *
 * **Only the refusal stays here, and it stays here on purpose.** The read side
 * returns a boolean because "there is nothing there" is both true and the right
 * answer for it; this guards the construction of a capability, where a returned
 * `false` is an existence oracle and silence is indistinguishable from success.
 * Sharing the rule is not the same as sharing the answer. Do not collapse the
 * two by making the shared predicate throw.
 *
 * The dot-dot condition that used to sit at the bottom of this function came
 * with it and left its reasoning behind: it can never fire, because the line
 * above already required 64 characters of lowercase hex. The read side carries
 * the same line WITH four lines of comment saying the redundancy is deliberate.
 * The copy read as a live check a reader would either trust or delete. It is
 * now stated once, in the one place that explains it.
 */
function assertGrantableKey(
  userId: string,
  key: string,
): asserts key is string {
  if (!underStagingPrefix(userId, key)) throw new ImapNotFoundError();
}

/**
 * Derive the key one presigned upload is aimed at.
 *
 * `staging/{user id}/upload-{random}-{epoch milliseconds}`. See
 * `PRESIGNED_KEY_STEM` for why the offered filename is deliberately absent from
 * it, and why the random segment is here rather than deferred.
 *
 * Returns a key directly rather than routing through `stagingKeyFor`, because
 * that function's whole purpose is to reduce an untrusted name to something
 * safe, and there is no untrusted name on this path — every character below is
 * this module's own. Running a sanitiser over a string with no input in it would
 * read as though there were.
 *
 * `userId` is the signed-in user's id, and it LEADS the parameter list for
 * `assertGrantableKey`'s reason — see that function. It becomes the key's own
 * segment, directly beneath the prefix, so the grant this key is aimed at is a
 * grant to write inside one user's own scope and nowhere else.
 */
export function presignedKeyFor(
  userId: string,
  nowMs: number,
): string | null {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) return null;

  const random = new Uint8Array(KEY_RANDOM_BYTES);
  crypto.getRandomValues(random);
  const segment = [...random]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return `${STAGING_PREFIX}${userId}/${PRESIGNED_KEY_STEM}-${segment}-${nowMs}`;
}

/**
 * The exact headers an uploading client must reproduce.
 *
 * **One definition, used both to SIGN and to REPORT.** The signature covers
 * every header present, so a client that sends a different set — or the same set
 * with one value spelled differently — is rejected by the endpoint. If the
 * signing site and the reporting site each built their own map, a drift between
 * them would surface as an unexplainable rejection from storage rather than as a
 * failing test here.
 *
 * The filename is percent-encoded for the reason `putStaged` percent-encodes the
 * same field: these values become headers on the S3 path, and a name carrying
 * CR or LF would terminate a header line early. The transformation is lossless
 * and has an exact inverse, so `getStaged` reads the original back byte for
 * byte — which is what makes the file the recipient receives carry the name the
 * user typed.
 *
 * **The encode is TOTAL.** `encodeURIComponent` throws `URIError` on a lone
 * surrogate, which is a legal JSON string and passes `z.string()`, so an
 * unguarded call raises a class `toErrorCategory` does not recognise — reported
 * to the model as `connection_failed` — the floor, which still offers a retry
 * — for an input that fails identically forever. The refusal this function already has for an
 * unencodable name is the right answer and is reused rather than joined by a
 * second one. See `metadataValue` in `./r2.ts`, which closes the same hole on
 * the binding-side ingress.
 */
export function uploadHeadersFor(request: UploadRequest): Record<string, string> {
  let filename: string;
  try {
    filename = encodeURIComponent(request.filename);
  } catch {
    // The caught value is never read.
    throw new ImapNotFoundError();
  }
  if (!PRINTABLE_ASCII.test(filename)) throw new ImapNotFoundError();

  assertNoIllegalCharacters(request.contentType);

  return {
    [HEADER_CONTENT_TYPE]: request.contentType,
    [HEADER_CONTENT_LENGTH]: String(request.contentLength),
    [HEADER_META_FILENAME]: filename,
  };
}

/**
 * Mint one presigned upload URL.
 *
 * Returns a STRING. See the module header for what that buys and for the one
 * limit on the claim.
 *
 * **The option that makes every present header signable is LOAD-BEARING, and
 * the whole reason is written here because a later reader will otherwise
 * simplify it away as noise.** The signing library filters an unsignable-header
 * set out of the signed-header list by default, and that set contains BOTH the
 * declared media type and the declared length. The vendor's own published
 * example omits the option while stating that the media-type restriction works —
 * so an implementation that followed the documentation verbatim would produce a
 * URL accepting any type and any size, and nothing about it would look wrong.
 * This was read out of the shipped library bundle rather than inferred, and the
 * paired tests in `test/staging.test.ts` pin both halves: one asserts this URL
 * names the two headers, and the other asserts the library's default drops them.
 *
 * **The second-order effect, stated honestly.** With every present header
 * signed, the uploading client must reproduce all of them exactly — the declared
 * type, the exact length, and the encoded filename. That is a brittler contract
 * to hand a person with a command line than a type-only binding would be, and it
 * is one of the three reasons the confirm step below stays even though an exact
 * size can now be bound. `uploadHeadersFor` above exists so the contract has one
 * definition rather than two.
 *
 * **What is bound is an EXACT size, not a ceiling.** There is no mechanism here
 * for a range: the bucket's S3 surface implements no post-object operation, so
 * the policy condition that expresses one does not exist. Combined with the
 * caller checking the declared size against the per-file cap before asking for a
 * grant, an oversized upload cannot be minted for at all — and an upload that
 * does not match its declared size breaks the signature.
 */
export async function mintUploadUrl(
  env: Env,
  userId: string,
  request: UploadRequest,
): Promise<string> {
  if (env.FREE_BLOBS) return mintFreeUpload(env, userId, request);
  const accountId = env.R2_ACCOUNT_ID;
  const accessKeyId = env.R2_ACCESS_KEY_ID;
  const secretAccessKey = env.R2_SECRET_ACCESS_KEY;

  // Before anything is constructed. See `assertProvisioned`.
  assertProvisioned(accountId);
  assertProvisioned(accessKeyId);
  assertProvisioned(secretAccessKey);
  assertNoIllegalCharacters(accountId);
  assertGrantableKey(userId, request.key);

  const headers = uploadHeadersFor(request);

  const url = new URL(
    `https://${accountId}${STORAGE_HOST_SUFFIX}/${STAGING_BUCKET}/${request.key}`,
  );
  url.searchParams.set("X-Amz-Expires", String(UPLOAD_URL_TTL_SECONDS));

  // Constructed here rather than at module scope, and never assigned anywhere a
  // later call could reach. See the module header for the honest limit.
  const signer = new AwsClient({
    accessKeyId,
    secretAccessKey,
    service: SIGNING_SERVICE,
    region: SIGNING_REGION,
  });

  const signed = await signer.sign(url.toString(), {
    method: "PUT",
    headers,
    aws: { signQuery: true, allHeaders: true },
  });

  return signed.url;
}

/**
 * Why a confirm did not produce a staged id, from a closed set.
 *
 * Three members, and only three, because those are the three this function can
 * actually decide. The staging module's own refusals are not repeated here for
 * the reason 04-08 records about the transport-encoding refusal one layer up: a
 * member a union's own code cannot produce reads as dead code to the next person
 * through.
 *
 * **`size-mismatch` is deliberately not folded into `too-large`.** They describe
 * opposite facts and ask the caller for different things: `too-large` means more
 * bytes landed than may be staged and the file must be smaller, `size-mismatch`
 * means FEWER bytes landed than were promised and the upload should be repeated.
 * Reporting a truncated file as too large would send the caller to shrink a file
 * that was already too small.
 *
 * A refusal is a field on a SUCCESSFUL result, never a raised error. D-35 closed
 * the error vocabulary at four values, phases three through six inherit it, and
 * nothing here reopens it.
 */
export type ConfirmRefusal = "not-found" | "too-large" | "size-mismatch";

/**
 * What one confirm produced.
 *
 * The success arm IS `StageResult`'s success arm — the same four fields with the
 * same meanings — because a caller holding a staged id should not be able to
 * tell which ingress produced it. `Extract` rather than a restatement, so the
 * two cannot drift, and an INTERSECTION rather than a widening for the two extra
 * fields, so the shape stays assignable wherever a stage result is expected.
 *
 * Those two extra fields are read off the object rather than derived: they are
 * what the UPLOADER recorded, so they are untrusted on the way back out exactly
 * as the offered name is on the other two ingresses. They are here rather than
 * fetched again by the caller because the object has already been read.
 */
export type ConfirmResult =
  | (Extract<StageResult, { staged: true }> & {
      /** The name the uploader recorded on the object. Caller-authored. */
      offeredFilename: string | null;
      /** The type the uploader declared. Declared, never verified. */
      offeredType: string;
    })
  | {
      staged: false;
      refusal: ConfirmRefusal;
      /** The size actually OBSERVED on the object. Zero when there was none. */
      sizeBytes: number;
      /** The ceiling it was decided against. */
      limitBytes: number;
    };

/**
 * Look at what actually landed, and mint an identifier only if it is what was
 * promised.
 *
 * **The size is read from the OBJECT, never from its metadata, and that
 * distinction is the entire point of this step.** The metadata was written by
 * the mint call before a single byte existed, so it records what was CLAIMED.
 * The object's own size field is what ACTUALLY landed. A confirm that read the
 * metadata would be asking the uploader whether the uploader was honest.
 *
 * **The read is METADATA-ONLY, and that is a memory bound rather than a
 * refinement.** `headStaged` returns the recorded size, name and type without
 * fetching a byte of body. A confirm that read the body first would allocate
 * the whole object in the isolate BEFORE comparing its size against the ceiling
 * — the bound applied after the allocation it exists to prevent, which is not a
 * bound at all. Nothing below ever touches the bytes: this function uses only
 * `sizeBytes`, `filename` and `mimeType`, so the body read was wasted work in
 * the benign case and a crash in the adversarial one. A crash here is
 * additionally self-perpetuating, because the delete on the refusal arm never
 * runs and the same oversized object is still there on the retry.
 *
 * **Why this step survives even though the signature now binds an exact length.
 * Three reasons, and all three are here because "the signature binds it, so the
 * confirm is redundant" is the exact simplification a later reader will
 * attempt.**
 *
 *   1. The storage endpoint DOES enforce a signed content length, and that is
 *      now MEASURED rather than assumed. 04-UAT.md row 26 declared 72 bytes and
 *      PUT 200; the endpoint answered `403 SignatureDoesNotMatch` and echoed
 *      `content-length:200` in the canonical request it had computed, which is
 *      the signature covering the header rather than the server checking a
 *      length. **What that settles is the OVER direction only**, and the
 *      distinction is worth keeping: a body SHORTER than the signed length is a
 *      different exchange and was not tested, so this step remains the only
 *      thing standing between a truncated upload and a staged id.
 *   2. Signing every present header makes the upload contract brittle for the
 *      client, so the pressure to sign fewer headers is real and permanent. This
 *      step is what makes that a cost decision rather than a security one.
 *   3. Decisively: this step is what turns a DECLARED size into an OBSERVED one.
 *      "Rejected at staging, with a clear reason" is a property about what the
 *      server has seen, and until it looks, it has not seen anything.
 *
 * **Deleting on overrun is not optional.** An object that failed confirm has no
 * path to ever becoming a staged id, so leaving it costs storage and leaves an
 * unreferenced blob under a prefix the user may well inspect. The bucket's own
 * sweep would take it within a day or two; that layer exists for objects nobody
 * ever came back for, not as an excuse to skip a delete this code is standing
 * right next to (D-81).
 *
 * **The identifier is minted only AFTER the size check passes, and the ordering
 * is the mechanism rather than a tidiness preference.** Before that call the
 * object exists and is unusable, because nothing can name it. After it, the
 * identifier is precisely what makes it usable.
 *
 * **A second confirm on the same key is IDEMPOTENT, not additive.** It mints an
 * identifier naming the same key with the same expiry rule, so one upload cannot
 * become two live attachments: attaching either one deletes the object, and the
 * other then resolves to nothing. That is the same "the object it named is gone"
 * answer an expired token gives, which the compose path already treats as one
 * situation.
 *
 * The instant is INJECTED rather than read from the wall clock here, exactly as
 * `putStaged` takes one: the expiry is baked into the issued token as an
 * absolute value, so a test that could not fix the clock could not assert what
 * the token actually says.
 *
 * **`expiresNoLaterThan` is what keeps D-82's ordering true on THIS path, and it
 * is the one parameter here whose absence would be a silent bug rather than a
 * missing feature.** On every other ingress the object is written and named in
 * the same call, so "now plus a day" is also "the object's own creation plus a
 * day", and the token reliably dies before the bucket's sweep reaches the bytes.
 * This ingress separates the two: the grant is minted, some time passes, the
 * bytes arrive, and more time may pass before anyone confirms. A token minted a
 * plain day from the confirm would outlive an object the sweep had already
 * scheduled — exactly the failure D-82 says reversing the two numbers produces,
 * arriving instead through a gap between them. The caller passes the instant its
 * upload grant was going to lapse anyway, and the identifier can never outlast
 * it.
 *
 * The declared size is supplied by the caller and is therefore a number the
 * caller can get wrong. That is bounded rather than trusted: the per-file cap is
 * checked independently and is not caller-supplied, so the worst a wrong
 * declaration can do is refuse an upload that would have been fine. It can no
 * longer admit one, because the observed size must EQUAL the declared one and
 * the cap is a separate clamp above it.
 *
 * **The check is two-sided.** A ceiling alone bounds the isolate and says
 * nothing about correctness: an object smaller than promised is a TRUNCATED
 * file, and a truncated file is the one failure here that produces a wrong
 * result rather than a refused one. See the check itself for the argument.
 */
export async function confirmStagedUpload(
  env: Env,
  userId: string,
  key: string,
  declaredSize: number,
  nowMs: number,
  expiresNoLaterThan: number,
): Promise<ConfirmResult> {
  const object = await headStaged(env, userId, key);

  if (object === null) {
    // The same answer a key outside the prefix gets, and for the same reason the
    // staging module gives: a distinguishable refusal would be an existence
    // oracle handed to a forged identifier.
    return {
      staged: false,
      refusal: "not-found",
      sizeBytes: 0,
      limitBytes: MAX_STAGED_FILE_BYTES,
    };
  }

  // The observed size. `headStaged` reports the size R2 recorded as the bytes
  // landed, not the number the mint call wrote into custom metadata before any
  // of them existed.
  const sizeBytes = object.sizeBytes;

  // Both ceilings, and the smaller one is the one reported. A declared size over
  // the cap cannot have been minted for, so the cap binds even when a caller
  // declares something larger.
  const limitBytes = Math.min(declaredSize, MAX_STAGED_FILE_BYTES);

  if (sizeBytes > limitBytes) {
    await deleteStaged(env, userId, key);
    return { staged: false, refusal: "too-large", sizeBytes, limitBytes };
  }

  // **The bound is two-sided, and the under-direction is the half that produces
  // a WRONG FILE rather than a refused one.** A ceiling check alone accepts an
  // object smaller than it was promised to be — an interrupted PUT, or an
  // endpoint that does not enforce the signed length downward, which row 26
  // measured only in the over-direction. The confirm would then mint an
  // identifier for a TRUNCATED file, which is base64-encoded whole into a draft
  // and sent by the user.
  //
  // `readAttachmentPart` refuses exactly this one module over, in language that
  // applies here verbatim: "a base64 part cut mid-stream decodes to a corrupt
  // PREFIX of a real file. A PDF cut that way opens, renders its first pages,
  // and is wrong, and the user then attaches it to a message they send." The
  // fetch path refused it and the upload path did not.
  //
  // Equality rather than a floor, and it costs a compliant client nothing: the
  // signature binds an EXACT length rather than a range, so an upload that
  // reaches the bucket at all already agreed to this number. See `mintUploadUrl`.
  if (sizeBytes !== declaredSize) {
    await deleteStaged(env, userId, key);
    return { staged: false, refusal: "size-mismatch", sizeBytes, limitBytes };
  }

  const expiresAt = Math.min(nowMs + STAGED_ID_TTL_MS, expiresNoLaterThan);

  return {
    staged: true,
    id: encodeStagedId({ key, expiresAt }, nowMs),
    // The NAME, and only the name. `headStaged` above answered non-null, which
    // is only possible when the key's user segment is exactly `userId`, so this
    // offset is exact. Slicing the prefix alone would put the caller's own user
    // id into a tool response.
    filename: key.slice(STAGING_PREFIX.length + userId.length + 1),
    sizeBytes,
    expiresAt: new Date(expiresAt).toISOString(),
    offeredFilename: object.filename,
    offeredType: object.mimeType,
  };
}
