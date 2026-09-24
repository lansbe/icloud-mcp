// The staging bucket: a key a stranger's filename cannot aim, two caps that
// each carry their own arithmetic, and a round trip through the REAL binding.
//
// **Nothing here is faked.** `env.ATTACHMENT_STAGING` is a live R2 bucket
// supplied by Miniflare from the Worker's own configuration — plan 04-01
// verified with an in-pool probe that it is a LOCAL implementation rather than
// a reach at the account's real bucket, which is what makes a put/get/delete
// suite safe to run on every commit. A hand-written fake would have proven
// something about the fake.
//
// **The adversarial filename corpus is the point of this file**, and it is
// written in the spirit of `test/dav-home-containment.test.ts`: a fixture built
// only from well-behaved names passes against both a correct sanitiser and a
// missing one. Every entry below was chosen because some plausible
// implementation gets it wrong — a percent-encoded separator, a leading dot, a
// name that reduces to nothing, a name carrying a line break.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09).

import { AwsClient } from "aws4fetch";
import { env } from "cloudflare:workers";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { ImapNotFoundError } from "../src/errors";
import type { DraftInput } from "../src/mail/compose";
import { MAX_APPEND_LITERAL_BYTES, buildDraft } from "../src/mail/compose";
import {
  STAGED_ID_TTL_MS,
  decodeStagedId,
  decodeUploadId,
  encodeMessageId,
  encodeStagedId,
  encodeUploadId,
} from "../src/mail/ids";
import type { AttachmentContent } from "../src/mail/service";
import {
  MAX_ATTACHMENT_PART_OCTETS,
  appendDraftOver,
  createSessionGate,
  getAttachmentContentOver,
} from "../src/mail/service";
import {
  MAX_ATTACHMENTS_PER_DRAFT,
  composeWithAttachments,
  releaseStagedAttachments,
  resolveStagedAttachments,
  stageAttachmentContent,
  stageInlineBytes,
} from "../src/mcp/tools/mail";
import {
  UPLOAD_URL_TTL_SECONDS,
  confirmStagedUpload,
  mintUploadUrl,
  presignedKeyFor,
} from "../src/staging/presign";
import {
  MAX_INLINE_BASE64_BYTES,
  MAX_STAGED_FILE_BYTES,
  STAGING_PREFIX,
  deleteStaged,
  getStaged,
  putStaged,
  sanitiseFilename,
  stagingKeyFor,
  underStagingPrefix,
} from "../src/staging/r2";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  structureFetchReply,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/** A fixed instant, so every key in this file is reproducible. */
const NOW = 1_776_000_000_000;

/** Every object currently in the bucket, whatever prefix it carries. */
async function everyKey(): Promise<string[]> {
  const listed = await env.ATTACHMENT_STAGING.list();
  return listed.objects.map((one) => one.key).sort();
}

/** A bucket with nothing in it, before every case. */
beforeEach(async () => {
  for (const key of await everyKey()) {
    await env.ATTACHMENT_STAGING.delete(key);
  }
  expect(await everyKey()).toEqual([]);
});

// ---------------------------------------------------------------------------
// The key: legible when listing the bucket, and confined no matter what
// ---------------------------------------------------------------------------

describe("stagingKeyFor: a legible name that cannot leave its prefix", () => {
  it("keeps an ordinary filename recognisable in a bucket listing", () => {
    // D-83's whole reason for a filename-derived key over a random one: seeing
    // `resume.pdf` beats seeing a UUID when working out what accumulated. The
    // random segment added on 2026-08-21 LEADS the name rather than replacing
    // it, so that reason survives the collision fix intact.
    const key = stagingKeyFor(principal.userId, "Resume-2026.pdf", NOW);

    expect(key).toMatch(
      new RegExp(
        `^${STAGING_PREFIX}${principal.userId}/[0-9a-f]{16}-Resume-2026\\.pdf-${NOW}$`,
      ),
    );
  });

  it("cannot produce the same key twice, even inside one millisecond", () => {
    // THE COLLISION IS THE POINT OF THIS TEST, and it asserts the opposite of
    // what it asserted before 2026-08-21.
    //
    // D-83 originally took a knowing residual: `{name}-{milliseconds}` collides
    // for two stages inside the same millisecond. That was accepted when the
    // worst case was one draft carrying the wrong file. D-81's delete-on-attach
    // compounded it into one draft's attach deleting bytes another draft still
    // points at, and the developer reversed the trade once the consequence had
    // changed.
    //
    // The superseded assertion was `toBe` across two calls with identical
    // arguments — i.e. it asserted determinism, which on this function is
    // exactly the collision. Same arguments, different keys, is the fix.
    const identicalArguments = stagingKeyFor(principal.userId, "note.txt", NOW);
    expect(identicalArguments).not.toBe(stagingKeyFor(principal.userId, "note.txt", NOW));

    // And the timestamp still moves independently, so neither half is carrying
    // the property alone.
    expect(stagingKeyFor(principal.userId, "note.txt", NOW)).not.toBe(
      stagingKeyFor(principal.userId, "note.txt", NOW + 1),
    );

    // A hundred draws with one name and one instant, all distinct. A regression
    // that dropped the random segment would leave a set of size one, and it
    // would do so silently against the two assertions above only if they were
    // read as being about the timestamp.
    const drawn = new Set(
      Array.from({ length: 100 }, () => stagingKeyFor(principal.userId, "note.txt", NOW)),
    );
    expect(drawn.size).toBe(100);
  });

  it("refuses a name that sanitises to nothing rather than emitting a bare prefix", () => {
    // The failure this refusal prevents is specific: without it the key is the
    // prefix and a timestamp, so two different files with two different useless
    // names both land somewhere nobody can identify from a listing.
    expect(sanitiseFilename("....")).toBeNull();
    expect(sanitiseFilename("-----")).toBeNull();
    expect(sanitiseFilename("")).toBeNull();
    expect(stagingKeyFor(principal.userId, "....", NOW)).toBeNull();
  });

  it("refuses CR, LF and NUL outright rather than stripping them", () => {
    // The one place these three matter twice: the key AND the custom metadata
    // value, which becomes a header on the S3 path. Refusing at the sanitiser
    // is what stops the second one ever being reached.
    expect(sanitiseFilename("head\r\ninjected.pdf")).toBeNull();
    expect(sanitiseFilename("carriage\rreturn.pdf")).toBeNull();
    expect(sanitiseFilename("line\nfeed.pdf")).toBeNull();
    expect(sanitiseFilename("nul\x00byte.pdf")).toBeNull();
    expect(sanitiseFilename("bell\x07.pdf")).toBeNull();
  });
});

/**
 * Names chosen because a plausible sanitiser gets each one wrong.
 *
 * `refused` records the EXPECTED disposition, so the corpus asserts a decision
 * rather than "whatever happened". A corpus where every entry were permitted
 * would pass against a sanitiser that refused nothing, and one where every
 * entry were refused would pass against a sanitiser that refused everything.
 */
const ADVERSARIAL_NAMES: { name: string; refused: boolean; why: string }[] = [
  {
    name: "../../etc/passwd",
    refused: false,
    why: "the plain traversal, and the one every reader pictures",
  },
  {
    name: "..%2f..%2fetc%2fpasswd",
    refused: false,
    why: "the ENCODED traversal — mime.ts's own T-02-22 note records that percent-decoding the wrong section turns this into a real one",
  },
  {
    name: "..%252f..%252fpasswd",
    refused: false,
    why: "doubly-encoded, for a sanitiser that decodes once and then trusts",
  },
  {
    name: "/absolute/path.pdf",
    refused: false,
    why: "a leading separator, which a naive join would honour",
  },
  {
    name: "..\\..\\windows\\system32\\config",
    refused: false,
    why: "the other separator, which a POSIX-only rule misses entirely",
  },
  {
    name: `${STAGING_PREFIX}already-prefixed.pdf`,
    refused: false,
    why: "a name that claims the prefix itself, so a naive concatenation doubles it",
  },
  {
    name: ".hidden",
    refused: false,
    why: "a leading dot, which is not a traversal but reads as one in a listing",
  },
  {
    name: "....",
    refused: true,
    why: "reduces to nothing, and a prefix-only key names no file",
  },
  {
    name: `${"a".repeat(400)}.pdf`,
    refused: false,
    why: "far longer than any real filename; a key has a byte ceiling",
  },
  {
    name: "line\r\nbreak.pdf",
    refused: true,
    why: "CR and LF reach a header on the S3 path through custom metadata",
  },
  {
    name: "nul\x00byte.pdf",
    refused: true,
    why: "NUL is rejected outright by every conformant HTTP implementation",
  },
  {
    name: "resumé — final(2).pdf",
    refused: false,
    why: "non-ASCII and spaces — ordinary, and the case a strict allowlist must still stage",
  },
];

describe("the adversarial filename corpus", () => {
  it("carries at least eight entries, and decides in both directions", () => {
    // Non-vacuity, in the shape `test/forbidden-tokens.test.ts` uses for its
    // rule samples: a corpus that permitted everything would pass against a
    // sanitiser that did nothing at all.
    expect(ADVERSARIAL_NAMES.length).toBeGreaterThanOrEqual(8);
    expect(ADVERSARIAL_NAMES.some((one) => one.refused)).toBe(true);
    expect(ADVERSARIAL_NAMES.some((one) => !one.refused)).toBe(true);
  });

  for (const entry of ADVERSARIAL_NAMES) {
    it(`confines or refuses: ${JSON.stringify(entry.name).slice(0, 48)} — ${entry.why}`, () => {
      const key = stagingKeyFor(principal.userId, entry.name, NOW);

      if (entry.refused) {
        expect(key).toBeNull();
        return;
      }

      expect(key).not.toBeNull();
      // The post-condition D-83 and RESEARCH's security section both ask for.
      // It holds regardless of what the sanitiser missed, which is the whole
      // reason it is asserted separately from the sanitiser's own output.
      expect(key!.startsWith(STAGING_PREFIX)).toBe(true);
      // The key sits under the caller's OWN segment, and the name is what
      // follows it. Slicing the prefix alone would hand the assertions below a
      // string that begins with the user id and a separator, so every one of
      // them would be deciding about the wrong half of the key.
      expect(key!.startsWith(`${STAGING_PREFIX}${principal.userId}/`)).toBe(true);

      const named = key!.slice(
        STAGING_PREFIX.length + principal.userId.length + 1,
      );
      expect(named).not.toContain("/");
      expect(named).not.toContain("\\");
      expect(named).not.toContain("..");
      expect(named).not.toContain("%");
      // And positively: only the allowlisted class survives.
      expect(named).toMatch(/^[A-Za-z0-9._-]+$/);
    });
  }

  it("produces a key short enough for the object store, from any length of name", () => {
    const key = stagingKeyFor(principal.userId, `${"a".repeat(4000)}.pdf`, NOW);

    expect(key).not.toBeNull();
    expect(ENCODER.encode(key!).byteLength).toBeLessThan(1024);
  });
});

// ---------------------------------------------------------------------------
// The two caps, each refusing on a SUCCESSFUL call
// ---------------------------------------------------------------------------

describe("the caps and their arithmetic", () => {
  it("sets the per-file cap at 4 MiB and the inline cap far below it", () => {
    // The two numbers are bounded by different things and the gap is the point:
    // one is the isolate's heap, the other is the model's context.
    expect(MAX_STAGED_FILE_BYTES).toBe(4 * 1024 * 1024);
    expect(MAX_INLINE_BASE64_BYTES).toBe(256 * 1024);
    expect(MAX_INLINE_BASE64_BYTES).toBeLessThan(MAX_STAGED_FILE_BYTES);
  });

  it("keeps the naive append peak well inside the isolate", () => {
    // RESEARCH § 6.2's measured 6.1x naive peak against the 128 MB isolate,
    // asserted rather than left in a docstring — the assertion is what makes a
    // later raise of the constant fail loudly instead of silently.
    expect(MAX_STAGED_FILE_BYTES * 6.1).toBeLessThan(64 * 1024 * 1024);
  });

  it("refuses over-cap bytes with BOTH numbers, and does not raise", async () => {
    const oversize = new Uint8Array(MAX_STAGED_FILE_BYTES + 1);

    const result = await putStaged(env, principal.userId, {
      bytes: oversize,
      filename: "huge.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result).toEqual({
      staged: false,
      refusal: "too-large",
      sizeBytes: MAX_STAGED_FILE_BYTES + 1,
      limitBytes: MAX_STAGED_FILE_BYTES,
    });
    // Criterion 5's first clause: rejected AT STAGING, so nothing was written
    // that a later append would have to unwind.
    expect(await everyKey()).toEqual([]);
  });

  it("refuses an empty payload", async () => {
    const result = await putStaged(env, principal.userId, {
      bytes: new Uint8Array(0),
      filename: "nothing.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(false);
    if (result.staged) return;
    expect(result.refusal).toBe("empty");
    expect(result.sizeBytes).toBe(0);
    expect(await everyKey()).toEqual([]);
  });

  it("refuses an unusable filename and writes NOTHING", async () => {
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("real bytes"),
      filename: "....",
      mimeType: "text/plain",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(false);
    if (result.staged) return;
    expect(result.refusal).toBe("filename-unusable");
    expect(await everyKey()).toEqual([]);
  });

  it("REFUSES a name that cannot be percent-encoded, rather than throwing", async () => {
    // A lone surrogate. It is a legal JSON string, it passes `z.string()`, the
    // control-character gate does not match it, and the sanitiser reduces it to
    // a valid key — so it reaches the metadata encode, where
    // `encodeURIComponent` throws `URIError`.
    //
    // The throw is the defect rather than the input. It breaks this function's
    // stated contract that every refusal RETURNS before a byte is written, and
    // it escapes to the tool boundary as an unrecognised class, which is
    // reported to the model as a transient connection failure that is "safe to
    // retry once". The same name fails identically forever.
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("real bytes"),
      filename: JSON.parse('"\\ud800.pdf"') as string,
      mimeType: "text/plain",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(false);
    if (result.staged) return;
    expect(result.refusal).toBe("filename-unusable");
    expect(await everyKey()).toEqual([]);
  });

  it("clamps a caller-supplied limit to the per-file cap, never above it", async () => {
    // The parameter exists so the inline path can be bounded LOWER. Letting it
    // bound HIGHER would make the module's own ceiling advisory, and the caller
    // is one edit away from being wrong about it.
    const result = await putStaged(env, principal.userId, {
      bytes: new Uint8Array(MAX_STAGED_FILE_BYTES + 1),
      filename: "huge.pdf",
      mimeType: "application/pdf",
      limitBytes: 64 * 1024 * 1024,
      nowMs: NOW,
    });

    expect(result.staged).toBe(false);
    if (result.staged) return;
    expect(result.limitBytes).toBe(MAX_STAGED_FILE_BYTES);
  });
});

// ---------------------------------------------------------------------------
// The round trip, through the real binding
// ---------------------------------------------------------------------------

describe("put, get and delete over the real Miniflare binding", () => {
  const PAYLOAD = "Job description: Staff Engineer at Example.\r\n— ends";

  it("round-trips the exact bytes that were written", async () => {
    const bytes = ENCODER.encode(PAYLOAD);

    const result = await putStaged(env, principal.userId, {
      bytes,
      filename: "Job Description.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    const { key } = decodeStagedId(result.id, NOW);
    const fetched = await getStaged(env, principal.userId, key);

    expect(fetched).not.toBeNull();
    expect(DECODER.decode(fetched!.bytes)).toBe(PAYLOAD);
    expect(fetched!.sizeBytes).toBe(bytes.byteLength);
  });

  it("records the ORIGINAL filename and the DECLARED type in metadata", async () => {
    // The key is sanitised; the metadata is not. Both facts matter: the key is
    // what a human reads in a listing, and the original is what the user called
    // the file.
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode(PAYLOAD),
      filename: "resumé — final(2).pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    const fetched = await getStaged(env, principal.userId, decodeStagedId(result.id, NOW).key);

    expect(fetched!.filename).toBe("resumé — final(2).pdf");
    expect(fetched!.mimeType).toBe("application/pdf");
    expect(fetched!.stagedAt).toBe(NOW);
  });

  it("keeps every stored metadata value free of CR, LF and NUL", async () => {
    // The second place the same untrusted string lands (T-04-08-02), and the
    // easiest to miss: these keys become `x-amz-meta-*` HEADERS on the S3 path.
    // Asserted on what was actually STORED rather than on what was passed in.
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode(PAYLOAD),
      filename: "quarterly—report.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    const object = await env.ATTACHMENT_STAGING.get(
      decodeStagedId(result.id, NOW).key,
    );
    const stored = Object.values(object!.customMetadata ?? {});

    expect(stored.length).toBeGreaterThan(2);
    for (const value of stored) {
      expect(value).toMatch(/^[\x20-\x7e]*$/);
    }
  });

  it("returns null for a key that is not there", async () => {
    // Well formed for THIS caller, and simply not there. A flat key would be
    // null too, but for the scope check rather than for absence, which would
    // make this case pass without ever reaching the store.
    expect(
      await getStaged(
        env,
        principal.userId,
        `${STAGING_PREFIX}${principal.userId}/absent-1.pdf`,
      ),
    ).toBeNull();
  });

  it("deletes, and a delete of an absent key does not fail", async () => {
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode(PAYLOAD),
      filename: "gone.txt",
      mimeType: "text/plain",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;
    const { key } = decodeStagedId(result.id, NOW);

    await deleteStaged(env, principal.userId, key);
    expect(await getStaged(env, principal.userId, key)).toBeNull();
    // D-81's sweep and its delete-on-attach layer both re-delete freely, and an
    // absent object is the NORMAL outcome for the second of them.
    await expect(deleteStaged(env, principal.userId, key)).resolves.toBeUndefined();
  });

  it("stages every object under the one prefix", async () => {
    await putStaged(env, principal.userId, {
      bytes: ENCODER.encode(PAYLOAD),
      filename: "../../escape.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    const keys = await everyKey();
    expect(keys).toHaveLength(1);
    expect(keys[0]!.startsWith(STAGING_PREFIX)).toBe(true);
  });

  it("a key one segment deeper is still INSIDE a listing by the prefix", async () => {
    // **What this case shows, and what it does not.**
    //
    // It shows that in an R2 implementation a prefix match reaches through a
    // separator: an object at `staging/<user id>/<name>` comes back from a
    // listing whose prefix is `staging/`. That is the property the whole user
    // segment rests on, because the one-day lifecycle rule that sweeps
    // abandoned bytes selects on that same prefix, and adding a segment
    // beneath it would be worth nothing if the sweep stopped at the first
    // separator.
    //
    // It shows NOTHING about whether the production lifecycle rule fires. No
    // expiry is observed here and none can be: this is the pool's local bucket,
    // the rule is account state created out of band, and the only evidence for
    // it is that the rule was read and found unchanged. This case is a local
    // measurement of prefix semantics standing beside that citation, not a
    // replacement for it.
    const deeper = `${STAGING_PREFIX}${principal.userId}/deeper-probe.txt`;
    await env.ATTACHMENT_STAGING.put(deeper, "bytes");

    const listed = await env.ATTACHMENT_STAGING.list({
      prefix: STAGING_PREFIX,
    });

    expect(listed.objects.map((one) => one.key)).toContain(deeper);
  });

  it("refuses to read or delete a key outside the prefix", async () => {
    // The staged token is UNSIGNED — `encodeStagedId` is base64url over JSON
    // with no MAC — so a caller can mint one naming any key it likes. The
    // containment check on the read side is what makes that forgery reach
    // nothing, and it is the same instinct `assertUnderHome` embodies one
    // protocol over.
    await env.ATTACHMENT_STAGING.put("elsewhere/secret.txt", "not yours");

    expect(await getStaged(env, principal.userId, "elsewhere/secret.txt")).toBeNull();
    await deleteStaged(env, principal.userId, "elsewhere/secret.txt");
    expect(await everyKey()).toEqual(["elsewhere/secret.txt"]);
  });
});

// ---------------------------------------------------------------------------
// The identifier, and D-82's ordering
// ---------------------------------------------------------------------------

describe("the staged identifier", () => {
  it("decodes back to the key that was written", async () => {
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("bytes"),
      filename: "Round-Trip.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    // Shape rather than an exact string: the key gained a leading random
    // segment on 2026-08-21 to close D-83's same-millisecond collision. What
    // this case is about is that the id round-trips to the key the object was
    // actually written under, and the name is still legible in it.
    expect(decodeStagedId(result.id, NOW).key).toMatch(
      new RegExp(
        `^${STAGING_PREFIX}${principal.userId}/[0-9a-f]{16}-Round-Trip\\.pdf-${NOW}$`,
      ),
    );
  });

  it("expires exactly 24 hours after the injected clock, never later", async () => {
    // D-82's ordering, asserted rather than described: the token must die
    // BEFORE the bytes, because the bucket sweep lands 24-48 hours out. A token
    // that outlived its object would decode cleanly and name nothing.
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("bytes"),
      filename: "Expiring.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    const ref = decodeStagedId(result.id, NOW);
    expect(ref.expiresAt).toBe(NOW + STAGED_ID_TTL_MS);
    expect(result.expiresAt).toBe(new Date(NOW + STAGED_ID_TTL_MS).toISOString());
    expect(STAGED_ID_TTL_MS).toBe(24 * 60 * 60 * 1000);
  });

  it("stops decoding AT its own expiry, with no help from the caller", async () => {
    // The expiry is enforced by the decoder, so a caller holding a staged id
    // cannot forget to ask whether it is still good (D-81). The boundary is
    // closed rather than open: a token is dead AT its stated instant.
    const result = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("bytes"),
      filename: "Expiring.pdf",
      mimeType: "application/pdf",
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    expect(() => decodeStagedId(result.id, NOW + STAGED_ID_TTL_MS - 1)).not.toThrow();
    expect(() => decodeStagedId(result.id, NOW + STAGED_ID_TTL_MS)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// The primary ingress: a message's attachment copied into the bucket, with the
// socket already closed (ATT-03, D-78 path 1)
//
// "Attach the job description from the recruiter's email to my thank-you note"
// is PROJECT.md's own driver sentence, and this is the only ingress shape that
// serves it without dragging a PDF through the model's context. Not one byte
// crosses the transcript.
//
// **The ordering is the property under test, not an implementation detail.**
// Every storage operation happens outside the session, because the production
// six-connection budget counts object storage against the same six slots as
// sockets — and the OAuth provider has already spent one of them before any
// mail code runs. `wrangler dev` does not enforce that cap, so this ordering is
// held by the SHAPE of the code and by the assertions below rather than by
// anything that fails at runtime.
// ---------------------------------------------------------------------------

const MAILBOX = "INBOX";
const UIDVALIDITY = 1237268095;
const UID = 4827;
const PART_PATH = "2";

/** The reference a decoded attachment id yields. */
const ATTACHMENT_REF = {
  mailbox: MAILBOX,
  uidValidity: UIDVALIDITY,
  uid: UID,
  path: PART_PATH,
};

/** Short bounds, so no case here costs wall time. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
  ];
}

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

/**
 * One fetch reply keyed by a section specifier.
 *
 * The key is spelled WITHOUT the peek, because that is what a server sends back
 * for a peeking request — the asymmetry CLAUDE.md § 5's scan rule is anchored
 * against.
 */
function partReply(tag: string, key: string, payload: Uint8Array): Uint8Array {
  return concatBytes(
    ENCODER.encode(`* 1 FETCH (UID ${UID} ${key} {${payload.byteLength}}\r\n`),
    payload,
    ENCODER.encode(`)\r\n${tag} OK UID FETCH completed\r\n`),
  );
}

/** Base64 of a known string, wrapped the way a real encoder wraps it. */
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

const SENDER_FILENAME = "Staff Engineer — job description.pdf";
const SENDER_PAYLOAD = "Job description: Staff Engineer at Example.\r\n";
const SENDER_BASE64 = base64Of(SENDER_PAYLOAD);

/** A two-part message: a text body at path 1, a PDF attachment at path 2. */
const CONTENT_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${SENDER_FILENAME}") NIL NIL "BASE64" ` +
  `${SENDER_BASE64.length} NIL ` +
  `("attachment" ("FILENAME" "${SENDER_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** The same message, with the attachment declaring more octets than the ceiling. */
const OVERSIZE_STRUCTURE =
  '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 96 3 NIL NIL NIL)' +
  `("APPLICATION" "PDF" ("NAME" "${SENDER_FILENAME}") NIL NIL "BASE64" ` +
  `${MAX_ATTACHMENT_PART_OCTETS + 1} NIL ` +
  `("attachment" ("FILENAME" "${SENDER_FILENAME}")) NIL)` +
  ' "MIXED" ("BOUNDARY" "Apple-Mail-A1") NIL NIL)';

/** Auth, EXAMINE, the structure turn, then whatever the case scripts next. */
function contentDuplex(structure: string, ...rest: Uint8Array[]) {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4", 172, UIDVALIDITY),
    structureFetchReply("a5", structure, { uid: UID }),
    ...rest,
  ]);
}

/** Every written line that looks like a fetch command. */
function fetchLines(duplex: ReturnType<typeof createFakeDuplex>): string[] {
  return duplex.writtenLines().filter((line) => /\bFETCH\b/.test(line));
}

/** The accepting conversation, end to end. */
function acceptingDuplex() {
  return contentDuplex(
    CONTENT_STRUCTURE,
    partReply("a6", `BODY[${PART_PATH}]`, ENCODER.encode(SENDER_BASE64)),
    logoutExchange("a7"),
  );
}

/**
 * A content record assembled by hand, for the cases a duplex cannot reach
 * cheaply.
 *
 * Used only where the declared size is the fact under test: building a real
 * six-megabyte fixture to prove a four-megabyte refusal would cost wall time on
 * every commit to assert something the declared number already decides.
 */
function contentOf(over: Partial<AttachmentContent> = {}): AttachmentContent {
  return {
    mimeType: "application/pdf",
    filename: SENDER_FILENAME,
    sizeBytes: SENDER_PAYLOAD.length,
    charset: null,
    encoding: "base64",
    encodedOctets: SENDER_BASE64.length,
    fetch: { fetched: true, bytes: ENCODER.encode(SENDER_BASE64) },
    ...over,
  };
}

describe("staging from a message: the copy that never reaches the transcript", () => {
  it("writes the attachment's REAL bytes into the bucket", async () => {
    const duplex = acceptingDuplex();

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );
    const outcome = await stageAttachmentContent(env, principal.userId, content, null, NOW);

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;

    const fetched = await getStaged(env, principal.userId, decodeStagedId(outcome.id, NOW).key);
    // The bytes that landed are the DECODED file, not the wire form.
    expect(DECODER.decode(fetched!.bytes)).toBe(SENDER_PAYLOAD);
    expect(outcome.sizeBytes).toBe(ENCODER.encode(SENDER_PAYLOAD).byteLength);
  });

  it("writes to the bucket only AFTER the session has closed", async () => {
    // The ordering assertion, made on the RECORDED EXCHANGE rather than on
    // timing: the teardown turn is on the wire and the bucket is still empty at
    // the moment the fetch returns, so the write cannot have happened inside the
    // session. Timing would be flaky; this is a fact about what was written.
    const duplex = acceptingDuplex();

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(
      duplex.writtenLines().some((line) => /\bLOGOUT\b/.test(line)),
      "the session had not closed",
    ).toBe(true);
    expect(await everyKey(), "an object existed before the session closed").toEqual([]);

    await stageAttachmentContent(env, principal.userId, content, null, NOW);

    expect(await everyKey()).toHaveLength(1);
  });

  it("uses the peeking form for both round trips, so nothing is marked read", async () => {
    // Convention 5. Staging reads a message the user has not opened, and a
    // fetch that set the seen flag would corrupt an answer another tool
    // reports.
    const duplex = acceptingDuplex();

    await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
      `a6 UID FETCH ${UID} (BODY.PEEK[${PART_PATH}])`,
    ]);
  });

  it("defaults the staged name to the SENDER's filename", async () => {
    const duplex = acceptingDuplex();
    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    const outcome = await stageAttachmentContent(env, principal.userId, content, null, NOW);

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;
    const fetched = await getStaged(env, principal.userId, decodeStagedId(outcome.id, NOW).key);
    expect(fetched!.filename).toBe(SENDER_FILENAME);
  });

  it("lets the caller rename, and the override reaches the stored metadata", async () => {
    // The one place the user can intervene before a stranger's chosen filename
    // travels into a header of their own outgoing message.
    const duplex = acceptingDuplex();
    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );

    const outcome = await stageAttachmentContent(
      env, principal.userId,
      content,
      "job-description.pdf",
      NOW,
    );

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;
    const { key } = decodeStagedId(outcome.id, NOW);
    // The rename is what this case is about, so assert the OVERRIDDEN name is
    // the one in the key — matched by shape, since the key gained a leading
    // random segment on 2026-08-21 (D-83's collision closure).
    expect(key).toMatch(
      new RegExp(
        `^${STAGING_PREFIX}${principal.userId}/[0-9a-f]{16}-job-description\\.pdf-${NOW}$`,
      ),
    );
    expect((await getStaged(env, principal.userId, key))!.filename).toBe("job-description.pdf");
  });

  it("refuses an over-size part with NO part fetch written and NO object created", async () => {
    // The refusal precedes the request. The structure line is present because
    // that is what supplies the number the refusal is decided on; the PART line
    // is absent, and its absence is the assertion.
    const duplex = contentDuplex(OVERSIZE_STRUCTURE, logoutExchange("a6"));

    const content = await getAttachmentContentOver(
      duplex,
      principal,
      createSessionGate(),
      ATTACHMENT_REF,
      FAST_BOUNDS,
    );
    const outcome = await stageAttachmentContent(env, principal.userId, content, null, NOW);

    expect(fetchLines(duplex)).toEqual([
      `a5 UID FETCH ${UID} (UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)`,
    ]);
    expect(outcome).toEqual({
      staged: false,
      refusal: "part-too-large",
      sizeBytes: MAX_ATTACHMENT_PART_OCTETS + 1,
      limitBytes: MAX_ATTACHMENT_PART_OCTETS,
    });
    expect(await everyKey()).toEqual([]);
  });

  it("surfaces a service refusal as a STAGING refusal, never as an error", async () => {
    // The four-value error vocabulary stays closed (D-35). A part this server
    // declined to ask for is a successful call carrying two numbers.
    const outcome = await stageAttachmentContent(
      env, principal.userId,
      contentOf({
        fetch: {
          fetched: false,
          refusal: "part-too-large",
          encodedOctets: 9_000_000,
          limitBytes: MAX_ATTACHMENT_PART_OCTETS,
        },
      }),
      null,
      NOW,
    );

    expect(outcome.staged).toBe(false);
    if (outcome.staged) return;
    expect(outcome.refusal).toBe("part-too-large");
    expect(outcome.limitBytes).toBe(MAX_ATTACHMENT_PART_OCTETS);
    expect(await everyKey()).toEqual([]);
  });

  it("refuses a part over the per-file cap BEFORE decoding it", async () => {
    // Discriminating on purpose: the declared decoded size is over the cap
    // while the fetched bytes are tiny. An implementation that decoded first
    // and measured afterwards would report the SMALL number and stage the file.
    const outcome = await stageAttachmentContent(
      env, principal.userId,
      contentOf({ sizeBytes: MAX_STAGED_FILE_BYTES + 1 }),
      null,
      NOW,
    );

    expect(outcome).toEqual({
      staged: false,
      refusal: "too-large",
      sizeBytes: MAX_STAGED_FILE_BYTES + 1,
      limitBytes: MAX_STAGED_FILE_BYTES,
    });
    expect(await everyKey()).toEqual([]);
  });

  it("stages a part whose sender declared no filename at all", async () => {
    const outcome = await stageAttachmentContent(
      env, principal.userId,
      contentOf({ filename: null }),
      null,
      NOW,
    );

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;
    expect(decodeStagedId(outcome.id, NOW).key).toContain(STAGING_PREFIX);
  });
});

// ---------------------------------------------------------------------------
// The inline ingress: small files handed over as base64 (ATT-03, D-78 path 2)
//
// **Bounded by the model's context, not by the isolate's heap**, and that is
// the whole reason this cap sits sixteen times below the per-file one. A 400 KB
// PDF becomes roughly 533 KB of base64, which is roughly a hundred and fifty
// thousand tokens in a single tool call. `ARCHITECTURE.md` §5 already says tool
// arguments are not the place for binary payloads; `MAX_INLINE_BASE64_BYTES` is
// the number behind that sentence.
// ---------------------------------------------------------------------------

/** Base64 of an arbitrary byte count, unwrapped, as a tool argument arrives. */
function inlineBase64(sourceBytes: number): string {
  const source = new Uint8Array(sourceBytes).fill(0x42);
  let binary = "";
  for (const byte of source) binary += String.fromCharCode(byte);
  return btoa(binary);
}

describe("staging from bytes handed over in the tool call", () => {
  it("decodes, stages, and returns the exact bytes it was given", async () => {
    const original = ENCODER.encode("Cover letter, third draft.\r\nSincerely,");
    let binary = "";
    for (const byte of original) binary += String.fromCharCode(byte);

    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: btoa(binary), filename: "cover-letter.txt", mimeType: "text/plain" },
      NOW,
    );

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;

    const fetched = await getStaged(env, principal.userId, decodeStagedId(outcome.id, NOW).key);
    expect(DECODER.decode(fetched!.bytes)).toBe(
      "Cover letter, third draft.\r\nSincerely,",
    );
    expect(outcome.sizeBytes).toBe(original.byteLength);
  });

  it("round-trips bytes that are not text at all", async () => {
    // The path exists for files, not for strings. A payload carrying every byte
    // value is what proves the decode is byte-exact rather than string-shaped.
    const original = new Uint8Array(256);
    for (let at = 0; at < 256; at += 1) original[at] = at;
    let binary = "";
    for (const byte of original) binary += String.fromCharCode(byte);

    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: btoa(binary), filename: "every-byte.bin", mimeType: null },
      NOW,
    );

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;
    const fetched = await getStaged(env, principal.userId, decodeStagedId(outcome.id, NOW).key);
    expect([...fetched!.bytes]).toEqual([...original]);
  });

  it("refuses an over-cap payload with both numbers, and writes no object", async () => {
    const payload = inlineBase64(MAX_INLINE_BASE64_BYTES + 3);

    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: payload, filename: "too-big.pdf", mimeType: "application/pdf" },
      NOW,
    );

    expect(outcome.staged).toBe(false);
    if (outcome.staged) return;
    expect(outcome.refusal).toBe("too-large");
    expect(outcome.sizeBytes).toBe(MAX_INLINE_BASE64_BYTES + 3);
    expect(outcome.limitBytes).toBe(MAX_INLINE_BASE64_BYTES);
    expect(await everyKey()).toEqual([]);
  });

  it("decides the size refusal BEFORE decoding anything", async () => {
    // Discriminating on purpose: this payload is over the cap AND is not valid
    // base64 at all. An implementation that decoded first would allocate the
    // whole buffer and then report the wrong refusal; one that reads the
    // declared length first never touches it. The refusal it returns is the
    // observable difference.
    const encodedLength = 4 * Math.ceil((MAX_INLINE_BASE64_BYTES + 64) / 3);
    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: "!".repeat(encodedLength), filename: "junk.pdf", mimeType: null },
      NOW,
    );

    expect(outcome.staged).toBe(false);
    if (outcome.staged) return;
    expect(outcome.refusal).toBe("too-large");
    expect(await everyKey()).toEqual([]);
  });

  it("refuses a payload that is not valid base64 rather than staging garbage", async () => {
    for (const payload of ["not base64 at all!!", "aGk", "###=", "aGk*"]) {
      const outcome = await stageInlineBytes(
        env, principal.userId,
        { base64: payload, filename: "junk.bin", mimeType: null },
        NOW,
      );

      expect(outcome.staged, payload).toBe(false);
      if (outcome.staged) return;
      expect(outcome.refusal, payload).toBe("not-base64");
    }
    expect(await everyKey()).toEqual([]);
  });

  it("refuses an empty payload", async () => {
    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: "", filename: "empty.txt", mimeType: "text/plain" },
      NOW,
    );

    expect(outcome.staged).toBe(false);
    if (outcome.staged) return;
    expect(outcome.refusal).toBe("empty");
    expect(await everyKey()).toEqual([]);
  });

  it("tolerates the line breaks a wrapped payload arrives with", async () => {
    const original = ENCODER.encode("wrapped payload");
    let binary = "";
    for (const byte of original) binary += String.fromCharCode(byte);
    const wrapped = btoa(binary).replace(/(.{4})/g, "$1\r\n");

    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: wrapped, filename: "wrapped.txt", mimeType: "text/plain" },
      NOW,
    );

    expect(outcome.staged).toBe(true);
  });

  it("stages a declared type outside any conservative list, as METADATA", async () => {
    // The declared type is never a gate on this path. It is caller-authored,
    // nothing branches on it, and it is reported as declared rather than as
    // verified — the same footing `AttachmentMeta.mimeType` already sits on.
    const outcome = await stageInlineBytes(
      env, principal.userId,
      {
        base64: btoa("zip-ish"),
        filename: "archive.7z",
        mimeType: "application/x-made-up",
      },
      NOW,
    );

    expect(outcome.staged).toBe(true);
    if (!outcome.staged) return;
    expect((await getStaged(env, principal.userId, decodeStagedId(outcome.id, NOW).key))!.mimeType).toBe(
      "application/x-made-up",
    );
  });

  it("is bounded by the INLINE cap, never by the per-file one", async () => {
    // The two caps are bounded by different things, and using the larger one
    // here would put a hundred and fifty thousand tokens in a tool call.
    const payload = inlineBase64(MAX_INLINE_BASE64_BYTES + 3);

    const outcome = await stageInlineBytes(
      env, principal.userId,
      { base64: payload, filename: "mid.pdf", mimeType: "application/pdf" },
      NOW,
    );

    expect(outcome.staged).toBe(false);
    if (outcome.staged) return;
    expect(outcome.limitBytes).toBe(MAX_INLINE_BASE64_BYTES);
    expect(outcome.limitBytes).not.toBe(MAX_STAGED_FILE_BYTES);
  });
});

// ---------------------------------------------------------------------------
// Attaching a staged file to a draft (ATT-04, D-81's three layers, criterion 4)
//
// **The ordering is the whole of this section's subject, and both halves of it
// are the kind a later reader "fixes".** Every bucket read precedes the socket
// and every delete follows it, because the production six-connection budget
// counts object storage against the same six slots as sockets and the OAuth
// provider has already drawn on one before any mail code runs. And the delete
// happens only after a write the server reported as successful, never after a
// failed one — on one ingress path the staged bytes are the only copy.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09).
// ---------------------------------------------------------------------------

/** The folder listing this account actually reports, drafts without a flag. */
function draftsListing(tag: string): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* LIST (\\HasNoChildren) "/" "Drafts"',
    '* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"',
    `${tag} OK LIST completed`,
  );
}

/** A continuation request: the server saying it is ready for the octets. */
const CONTINUATION = wire("+ Ready for literal data");

/** A conversation that accepts the write and names the result. */
function appendingDuplex(
  completion = "a5 OK [APPENDUID 1237268096 92] APPEND completed",
): ReturnType<typeof createFakeDuplex> {
  return createFakeDuplex([
    ...authPrefix(),
    draftsListing("a4"),
    CONTINUATION,
    wire(completion),
    logoutExchange("a6"),
  ]);
}

/** A conversation whose server declines the write outright. */
function refusingDuplex(): ReturnType<typeof createFakeDuplex> {
  return createFakeDuplex([
    ...authPrefix(),
    draftsListing("a4"),
    CONTINUATION,
    wire("a5 NO [OVERQUOTA] Mailbox is full"),
    logoutExchange("a6"),
  ]);
}

/** One draft's inputs, with only the field under test overridden. */
function draftInput(overrides: Partial<DraftInput> = {}): DraftInput {
  return {
    from: "someone@icloud.com",
    to: ["recruiter@example.invalid"],
    cc: [],
    subject: "Thanks for your time",
    text: "The attachment is enclosed.",
    html: null,
    inReplyTo: null,
    references: [],
    attachments: [],
    quoted: null,
    now: new Date(NOW),
    ...overrides,
  };
}

/** A bucket that records every call, in start/end pairs, around the real one. */
function recordingEnv(overrides: {
  failDelete?: boolean;
} = {}): { env: Env; events: string[] } {
  const events: string[] = [];
  const real = env.ATTACHMENT_STAGING;

  const bucket = {
    async get(key: string) {
      events.push(`get:start ${key}`);
      const object = await real.get(key);
      events.push(`get:end ${key}`);
      return object;
    },
    // Recorded separately from `get`, which is what lets a test decide whether
    // a caller read an object's SIZE or its BODY. The two are indistinguishable
    // from the outside otherwise, and on the confirm path the difference is a
    // memory bound rather than a detail.
    async head(key: string) {
      events.push(`head ${key}`);
      return real.head(key);
    },
    async put(key: string, value: ArrayBuffer | Uint8Array, options?: unknown) {
      return real.put(key, value as ArrayBuffer, options as never);
    },
    async delete(key: string) {
      events.push(`delete ${key}`);
      if (overrides.failDelete === true) {
        throw new Error("the bucket declined the delete");
      }
      return real.delete(key);
    },
    async list(options?: unknown) {
      return real.list(options as never);
    },
  };

  return {
    env: { ...env, ATTACHMENT_STAGING: bucket as unknown as R2Bucket },
    events,
  };
}

/** Stage one file and hand back its id and its bucket key. */
async function stageOne(
  filename: string,
  body: string | Uint8Array,
  at = NOW,
): Promise<{ id: string; key: string }> {
  const result = await putStaged(env, principal.userId, {
    bytes: typeof body === "string" ? ENCODER.encode(body) : body,
    filename,
    mimeType: "application/pdf",
    limitBytes: MAX_STAGED_FILE_BYTES,
    nowMs: at,
  });
  expect(result.staged, "the fixture failed to stage").toBe(true);
  if (!result.staged) throw new Error("unreachable");
  return { id: result.id, key: decodeStagedId(result.id, at).key };
}

describe("resolving staged ids into attachments", () => {
  it("hands back the bytes, the name and the declared type, in id order", async () => {
    const first = await stageOne("job-description.pdf", "the first document");
    const second = await stageOne("notes.txt", "the second document");

    const staged = await resolveStagedAttachments(
      env, principal.userId,
      [first.id, second.id],
      NOW,
    );

    expect(staged.keys).toEqual([first.key, second.key]);
    expect(staged.attachments.map((one) => one.filename)).toEqual([
      "job-description.pdf",
      "notes.txt",
    ]);
    expect(DECODER.decode(staged.attachments[0]!.content)).toBe(
      "the first document",
    );
    expect(staged.totalBytes).toBe(
      "the first document".length + "the second document".length,
    );
  });

  it("REFUSES an expired id before any bucket read at all", async () => {
    // The cheapest possible refusal: the token carries its own expiry, so a
    // stale one costs nothing and never reaches the bucket. Asserted on the
    // recorded calls rather than on the object surviving, because a read leaves
    // no trace of its own.
    const staged = await stageOne("stale.pdf", "still here");
    const recording = recordingEnv();

    await expect(
      resolveStagedAttachments(
        recording.env,
        principal.userId,
        [staged.id],
        NOW + STAGED_ID_TTL_MS,
      ),
    ).rejects.toThrow(ImapNotFoundError);

    expect(recording.events).toEqual([]);
    expect(await everyKey()).toEqual([staged.key]);
  });

  it("refuses a MESSAGE id by the same cross-use rule, not by a new one", async () => {
    // D-77 keeps the cross-use refusal one rule covering every identifier the
    // model holds. A staging id handed where an attachment id belongs is
    // refused by the check that already refuses a cursor handed for a message.
    const foreign = encodeMessageId({
      mailbox: "INBOX",
      uidValidity: 1237268095,
      uid: 4827,
    });
    const recording = recordingEnv();

    await expect(
      resolveStagedAttachments(recording.env, principal.userId, [foreign], NOW),
    ).rejects.toThrow(ImapNotFoundError);
    expect(recording.events).toEqual([]);
  });

  it("refuses a well-formed id naming an object that is not there", async () => {
    const staged = await stageOne("gone.pdf", "about to vanish");
    await deleteStaged(env, principal.userId, staged.key);

    await expect(
      resolveStagedAttachments(env, principal.userId, [staged.id], NOW),
    ).rejects.toThrow(ImapNotFoundError);
  });

  it("refuses a FORGED id naming a key outside the staging prefix", async () => {
    // The staged token is unsigned, so a caller can mint one naming any key.
    // The staging module's own containment check is what refuses it, and it
    // returns the missing-object answer rather than a distinguishable one — a
    // second check here would be a second thing to drift.
    const forged = encodeStagedId(
      { key: "secrets/not-staging", expiresAt: NOW + STAGED_ID_TTL_MS },
      NOW,
    );

    await expect(resolveStagedAttachments(env, principal.userId, [forged], NOW)).rejects.toThrow(
      ImapNotFoundError,
    );
  });

  it("treats an EMPTY staged name as absent, not as a name", async () => {
    // `??` catches null and undefined and passes "" straight through. An empty
    // string is reachable on the presigned ingress — the stage refinement only
    // required the field to be PRESENT, the header encode maps "" to "", and
    // confirm reports it back — and `contentDispositionParams` returns the
    // empty string for it. The part then shipped as a bare
    // `Content-Disposition: attachment` with no filename parameter at all, so
    // the file reached the recipient unnamed.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("an unnamed document"), {
      filename: "",
    });
    const confirmed = await confirmStagedUpload(
      env, principal.userId,
      key,
      "an unnamed document".length,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );
    expect(confirmed.staged).toBe(true);
    if (!confirmed.staged) return;

    const staged = await resolveStagedAttachments(env, principal.userId, [confirmed.id], NOW);

    expect(staged.attachments[0]!.filename).toBe("attachment");

    // And the part carries a filename parameter rather than none.
    const built = buildDraft(draftInput({ attachments: staged.attachments }));
    expect(built.built).toBe(true);
    if (!built.built) return;
    expect(DECODER.decode(built.bytes)).toContain('filename="attachment"');
  });

  it("REFUSES the same id twice rather than attaching one file twice", async () => {
    // The cheapest way to exhaust the isolate on this path, and the one that
    // needs a single upload rather than several: nothing deduped, so one 4 MiB
    // file named N times allocated N copies and was then base64-encoded N times
    // over. D-81's delete-on-attach also makes the second occurrence meaningless
    // — it names bytes the first one consumes.
    //
    // Asserted on the recorded calls, because the refusal has to land in pass
    // one. A dedupe that ran after the reads would fix the draft and not the
    // allocation.
    const staged = await stageOne("resume.pdf", "attached once");
    const recording = recordingEnv();

    await expect(
      resolveStagedAttachments(
        recording.env,
        principal.userId,
        [staged.id, staged.id],
        NOW,
      ),
    ).rejects.toThrow(ImapNotFoundError);

    expect(recording.events).toEqual([]);
    // Refusing must not consume it. The caller can retry with one id.
    expect(await everyKey()).toEqual([staged.key]);
  });

  it("REFUSES more ids than the per-draft cap, before any bucket read", async () => {
    // The schema is where this is normally refused, before the handler runs at
    // all. This function is exported, so the schema is not the only door, and
    // the bound is restated here for the caller that did not come through MCP.
    const ids: string[] = [];
    for (let index = 0; index <= MAX_ATTACHMENTS_PER_DRAFT; index += 1) {
      ids.push((await stageOne(`file-${index}.pdf`, `document ${index}`)).id);
    }
    const recording = recordingEnv();

    await expect(
      resolveStagedAttachments(recording.env, principal.userId, ids, NOW),
    ).rejects.toThrow(ImapNotFoundError);
    expect(recording.events).toEqual([]);
  });

  it("accepts exactly the cap, so the bound is off by nothing", async () => {
    // The paired assertion. A cap tested only from above is indistinguishable
    // from one that is one too tight.
    const ids: string[] = [];
    for (let index = 0; index < MAX_ATTACHMENTS_PER_DRAFT; index += 1) {
      ids.push((await stageOne(`file-${index}.pdf`, `document ${index}`)).id);
    }

    const staged = await resolveStagedAttachments(env, principal.userId, ids, NOW);

    expect(staged.attachments).toHaveLength(MAX_ATTACHMENTS_PER_DRAFT);
  });

  it("bounds the peak at the ceiling the assembled message is measured against", async () => {
    // The arithmetic `MAX_ATTACHMENTS_PER_DRAFT` is derived from, asserted
    // rather than left in prose. The equality is what makes the peak statically
    // bounded by a ceiling `buildDraft` already enforces, which is why no
    // running total has to be carried through the read loop and no fifth error
    // category had to be invented for one. Raising either constant without the
    // other breaks the derivation, and this fails when it does.
    expect(MAX_ATTACHMENTS_PER_DRAFT * MAX_STAGED_FILE_BYTES).toBe(
      MAX_APPEND_LITERAL_BYTES,
    );
  });

  it("round-trips a declared type EXACTLY, and the builder is what contains it", async () => {
    // The asymmetry `stagedMimeType` documents, asserted in both halves,
    // because the two live in different modules and a docstring in one is not a
    // guarantee at a call site in the other.
    //
    // Half one: the custom-metadata arm is not gated, on purpose. A declared
    // type is reported to the caller AS DECLARED rather than as verified, which
    // is `MEDIA_TYPE`'s own stated property, so a type carrying a parameter
    // comes back out byte for byte.
    const injected = 'text/plain; boundary="x"';
    const staged = await putStaged(env, principal.userId, {
      bytes: ENCODER.encode("some notes"),
      filename: "notes.txt",
      mimeType: injected,
      limitBytes: MAX_STAGED_FILE_BYTES,
      nowMs: NOW,
    });
    expect(staged.staged).toBe(true);
    if (!staged.staged) return;
    const key = decodeStagedId(staged.id, NOW).key;

    expect((await getStaged(env, principal.userId, key))?.mimeType).toBe(injected);

    // Half two, and this is the half that makes the first one safe. The one
    // consumer that puts this value into a header re-applies `MEDIA_TYPE` and
    // falls back to the neutral default, so a caller-supplied parameter cannot
    // reach the `Content-Type` of a message the user sends under their own
    // name.
    const resolved = await resolveStagedAttachments(env, principal.userId, [staged.id], NOW);
    const built = buildDraft(
      draftInput({ attachments: resolved.attachments }),
    );
    expect(built.built).toBe(true);
    if (!built.built) return;

    const message = DECODER.decode(built.bytes);
    expect(message).not.toContain(injected);
    expect(message).toContain("Content-Type: application/octet-stream");
  });

  it("reads the objects SERIALLY, never through a concurrent combinator", async () => {
    // Every concurrent operation is a connection slot. The scan rule fires on a
    // combinator wrapped around the session specifically; the argument behind it
    // applies to the bucket for the same reason, and a serial read of two small
    // objects costs nothing worth having. Interleaved start/end pairs are what
    // a combinator would produce, so this decides in both directions.
    const first = await stageOne("one.pdf", "first");
    const second = await stageOne("two.pdf", "second");
    const recording = recordingEnv();

    await resolveStagedAttachments(
      recording.env,
      principal.userId,
      [first.id, second.id],
      NOW,
    );

    expect(recording.events).toEqual([
      `get:start ${first.key}`,
      `get:end ${first.key}`,
      `get:start ${second.key}`,
      `get:end ${second.key}`,
    ]);
  });
});

describe("composing with an attachment: every read before the socket", () => {
  it("has finished every bucket read before the greeting is consumed", async () => {
    // The ordering assertion, on the RECORDED EXCHANGE rather than on timing:
    // the build callback runs after the last read and before the session, and
    // nothing is on the wire at that moment.
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");
    const duplex = appendingDuplex();
    let linesAtAssembly: string[] = ["not recorded"];

    const composition = await composeWithAttachments(
      env, principal.userId,
      [staged.id],
      (attachments) => {
        linesAtAssembly = duplex.writtenLines();
        return buildDraft(draftInput({ attachments }));
      },
      (message) =>
        appendDraftOver(
          duplex,
          principal,
          createSessionGate(),
          null,
          message,
          FAST_BOUNDS,
        ),
      NOW,
    );

    expect(linesAtAssembly).toEqual([]);
    expect(composition.built.built).toBe(true);
    expect(composition.outcome?.appended).toBe(true);
    expect(composition.attachedCount).toBe(1);
    expect(composition.attachedBytes).toBe("%PDF-1.7 body".length);
  });

  it("carries the staged bytes into the message the session writes", async () => {
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");
    const duplex = appendingDuplex();
    let written: Uint8Array = new Uint8Array(0);

    await composeWithAttachments(
      env, principal.userId,
      [staged.id],
      (attachments) => buildDraft(draftInput({ attachments })),
      async (message) => {
        written = message;
        return appendDraftOver(
          duplex,
          principal,
          createSessionGate(),
          null,
          message,
          FAST_BOUNDS,
        );
      },
      NOW,
    );

    const message = DECODER.decode(written);
    expect(message).toContain("multipart/mixed");
    expect(message).toContain('filename="job-description.pdf"');
    expect(message).toContain(btoa("%PDF-1.7 body"));
  });

  it("refuses over the append ceiling with BOTH numbers and NO socket opened", async () => {
    // A set of individually legal files can exceed the message ceiling
    // together, and the refusal has to land here rather than in Mail.app hours
    // later. Three at the per-file cap is what it takes: two of them encode to
    // under the ceiling, which is arithmetic worth asserting rather than
    // rediscovering.
    expect(MAX_STAGED_FILE_BYTES * 2 * 1.3684).toBeLessThan(
      MAX_APPEND_LITERAL_BYTES,
    );
    expect(MAX_STAGED_FILE_BYTES * 3 * 1.3684).toBeGreaterThan(
      MAX_APPEND_LITERAL_BYTES,
    );

    const ids: string[] = [];
    for (let at = 0; at < 3; at += 1) {
      const staged = await stageOne(
        `bulky-${at}.pdf`,
        new Uint8Array(MAX_STAGED_FILE_BYTES).fill(0x41),
        NOW + at,
      );
      ids.push(staged.id);
    }

    const duplex = appendingDuplex();
    let appendCalls = 0;

    const composition = await composeWithAttachments(
      env, principal.userId,
      ids,
      (attachments) => buildDraft(draftInput({ attachments })),
      (message) => {
        appendCalls += 1;
        return appendDraftOver(
          duplex,
          principal,
          createSessionGate(),
          null,
          message,
          FAST_BOUNDS,
        );
      },
      NOW,
    );

    expect(composition.built).toMatchObject({
      built: false,
      refusal: "message-too-large",
      limitBytes: MAX_APPEND_LITERAL_BYTES,
    });
    expect(
      (composition.built as { sizeBytes: number }).sizeBytes,
    ).toBeGreaterThan(MAX_APPEND_LITERAL_BYTES);
    expect(appendCalls).toBe(0);
    expect(duplex.writtenLines()).toEqual([]);
    // Nothing was written, so nothing was consumed and nothing was deleted.
    expect(composition.consumed).toEqual([]);
    expect(await everyKey()).toHaveLength(3);
  });
});

describe("D-81's delete-on-attach layer", () => {
  /** Drive one compose against a duplex, with one staged file attached. */
  async function composeOver(
    duplex: ReturnType<typeof createFakeDuplex>,
    ids: string[],
    over: Env = env,
  ) {
    return composeWithAttachments(
      over,
      // `over` is the storage environment and nothing else. The compose acts
      // for the owner, whichever storage is swapped in.
      principal.userId,
      ids,
      (attachments) => buildDraft(draftInput({ attachments })),
      (message) =>
        appendDraftOver(
          duplex,
          // `over` is the storage environment and nothing else now. The write
          // acts for the owner's principal, whichever storage is swapped in.
          principal,
          createSessionGate(),
          null,
          message,
          FAST_BOUNDS,
        ),
      NOW,
    );
  }

  it("deletes the staged object once the write reported success", async () => {
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");
    expect(await everyKey()).toEqual([staged.key]);

    const composition = await composeOver(appendingDuplex(), [staged.id]);

    expect(composition.outcome?.appended).toBe(true);
    expect(await everyKey()).toEqual([]);
    expect(composition.consumed).toEqual([staged.id]);
  });

  it("KEEPS the staged object when the server declined the write", async () => {
    // The bytes are the only copy on one ingress path, and losing them means
    // re-uploading. A delete after a failed write is the ordering a later
    // reader most plausibly gets backwards.
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");

    await expect(composeOver(refusingDuplex(), [staged.id])).rejects.toThrow();

    expect(await everyKey()).toEqual([staged.key]);
  });

  it("KEEPS the staged object when the write was refused before the socket", async () => {
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");
    const duplex = appendingDuplex();

    const composition = await composeWithAttachments(
      env, principal.userId,
      [staged.id],
      (attachments) => buildDraft(draftInput({ attachments })),
      async () => ({
        appended: false as const,
        refusal: "message-too-large" as const,
        sizeBytes: 99,
        limitBytes: 98,
      }),
      NOW,
    );

    expect(composition.outcome?.appended).toBe(false);
    expect(composition.consumed).toEqual([]);
    expect(await everyKey()).toEqual([staged.key]);
    expect(duplex.writtenLines()).toEqual([]);
  });

  it("does NOT fail the call when the delete itself fails", async () => {
    // The write happened; the draft is real and sitting in the user's Drafts
    // folder. Turning that into a failed tool call would tell the user their
    // draft does not exist. The bucket's own prefix-scoped sweep is the
    // backstop for exactly this, which is what makes swallowing correct rather
    // than sloppy.
    const staged = await stageOne("job-description.pdf", "%PDF-1.7 body");
    const recording = recordingEnv({ failDelete: true });

    const composition = await composeOver(
      appendingDuplex(),
      [staged.id],
      recording.env,
    );

    expect(composition.outcome?.appended).toBe(true);
    expect(composition.consumed).toEqual([staged.id]);
    expect(recording.events).toContain(`delete ${staged.key}`);
    // The object survives, and the sweep is what removes it.
    expect(await everyKey()).toEqual([staged.key]);
  });

  it("deletes every attached object, not only the first", async () => {
    const first = await stageOne("one.pdf", "first", NOW);
    const second = await stageOne("two.pdf", "second", NOW + 1);

    const composition = await composeOver(appendingDuplex(), [
      first.id,
      second.id,
    ]);

    expect(composition.consumed).toEqual([first.id, second.id]);
    expect(await everyKey()).toEqual([]);
  });
});

describe("releaseStagedAttachments, on its own", () => {
  it("deletes nothing at all when the write did not succeed", async () => {
    const staged = await stageOne("kept.pdf", "still here");
    const recording = recordingEnv();

    await releaseStagedAttachments(
      recording.env,
      principal.userId,
      [staged.key],
      false,
    );

    expect(recording.events).toEqual([]);
    expect(await everyKey()).toEqual([staged.key]);
  });

  it("deletes each key serially when it did", async () => {
    const first = await stageOne("one.pdf", "first", NOW);
    const second = await stageOne("two.pdf", "second", NOW + 1);
    const recording = recordingEnv();

    await releaseStagedAttachments(
      recording.env,
      principal.userId,
      [first.key, second.key],
      true,
    );

    expect(recording.events).toEqual([
      `delete ${first.key}`,
      `delete ${second.key}`,
    ]);
    expect(await everyKey()).toEqual([]);
  });

  it("carries on to the second key when the first delete throws", async () => {
    // A swallowed failure must not become a skipped one: the second object
    // would otherwise be left behind for the sweep on every multi-attachment
    // draft rather than only on a genuinely failing delete.
    const first = await stageOne("one.pdf", "first", NOW);
    const second = await stageOne("two.pdf", "second", NOW + 1);
    const events: string[] = [];
    const real = env.ATTACHMENT_STAGING;
    const bucket = {
      async delete(key: string) {
        events.push(key);
        if (key === first.key) throw new Error("declined");
        return real.delete(key);
      },
    };

    await expect(
      releaseStagedAttachments(
        { ...env, ATTACHMENT_STAGING: bucket as unknown as R2Bucket },
        principal.userId,
        [first.key, second.key],
        true,
      ),
    ).resolves.toBeUndefined();

    expect(events).toEqual([first.key, second.key]);
    expect(await everyKey()).toEqual([first.key]);
  });
});

// ---------------------------------------------------------------------------
// The third ingress: a URL this server signed (ATT-03, ATT-05, D-79)
//
// **The signed-header assertion below is the highest-value test in this half of
// the phase, and it is worth saying why in the file rather than only in a
// summary.** D-79's recorded rationale says the signature "can bind
// Content-Type" and "cannot bind a size ceiling". Both clauses are wrong in a
// way nothing observable would reveal: the signing library filters an
// unsignable-header set out of the signed-header list by default, and that set
// contains BOTH of those headers. So a URL minted the way the vendor's own
// published example shows it binds NEITHER — it accepts any type and any size,
// and looks exactly like one that works.
//
// The two tests that pin this are deliberately a pair. One signs the same
// request through the library with the option omitted and asserts the two
// headers are absent, which pins the library's default rather than trusting a
// paragraph about it. The other asserts this project's minted URL names them,
// which pins the fix. Either alone could pass against a mistake; together they
// cannot.
//
// Nothing here reaches the network and nothing here uses a real credential —
// the fakes come from the test pool's own bindings (D-09).
// ---------------------------------------------------------------------------

/**
 * The exact nine characters a template literal produces from an absent binding.
 *
 * Derived rather than typed out, so the assertion cannot drift from what the
 * runtime actually does.
 */
const ABSENT_SPELLING = String(undefined);

/** The env the pool supplies, with one binding taken away. */
function envWithout(
  binding: "R2_ACCOUNT_ID" | "R2_ACCESS_KEY_ID" | "R2_SECRET_ACCESS_KEY",
): Env {
  return { ...env, [binding]: undefined } as unknown as Env;
}

/** One ordinary mint, with a fixed key so the assertions are reproducible. */
async function mintOne(over: Partial<Parameters<typeof mintUploadUrl>[2]> = {}) {
  return mintUploadUrl(env, principal.userId, {
    key: `${STAGING_PREFIX}${principal.userId}/upload-a1b2c3d4e5f60718-${NOW}`,
    contentType: "application/pdf",
    contentLength: 65_536,
    filename: "Staff Engineer — job description.pdf",
    ...over,
  });
}

describe("the write grant and the read path answer one adversarial key table", () => {
  // WR-04. These two used to be copies. `assertGrantableKey` in presign.ts
  // restated all seven of `underStagingPrefix`'s conditions by hand, sharing
  // only the shape constant, while its docstring claimed the two could not
  // drift — true of the constant, false of the logic. They agreed, but nothing
  // held them together, and a one-condition drift would have opened the write
  // grant or the read path without opening the other with every test green.
  //
  // The grant now calls the read side's predicate, so there is no second copy
  // left to drift. This table is what catches somebody putting one back: every
  // row is asserted against BOTH the exported predicate and the public mint,
  // so a re-inlined copy that differs by one condition goes red here rather
  // than in production. The refusals stay different on purpose — the read side
  // returns false, the grant throws, because a returned false on a grant path
  // is an existence oracle — so the table asserts the ANSWER and not the shape
  // of the answer.
  const OTHER_USER = "f".repeat(64);

  // The rows are built from the id rather than closed over it: `principal` is
  // assigned in a `beforeAll`, so a table evaluated while the suite is being
  // collected reads `undefined`.
  const refused: ReadonlyArray<readonly [string, (u: string) => string]> = [
    ["no user segment at all — the shape staged before Phase 10", () => `${STAGING_PREFIX}upload-a1b2c3d4e5f60718-${NOW}`],
    ["another person's segment, forged", () => `${STAGING_PREFIX}${OTHER_USER}/upload-a1b2c3d4e5f60718-${NOW}`],
    ["deeper than anything this project builds", (u) => `${STAGING_PREFIX}${u}/sub/upload-1`],
    ["a leading separator, so the segment is empty", () => `${STAGING_PREFIX}/upload-1`],
    ["a trailing separator, so the name is empty", (u) => `${STAGING_PREFIX}${u}/`],
    ["a segment that is not 64 hex", () => `${STAGING_PREFIX}abc/upload-1`],
    ["the right id in the wrong case", (u) => `${STAGING_PREFIX}${u.toUpperCase()}/upload-1`],
    ["a dot-dot in the name segment", (u) => `${STAGING_PREFIX}${u}/a..b`],
    ["outside the staging prefix entirely", (u) => `other/${u}/upload-1`],
    ["empty", () => ""],
  ];

  for (const [why, build] of refused) {
    it(`refuses on both sides: ${why}`, async () => {
      const key = build(principal.userId);

      expect(underStagingPrefix(principal.userId, key), "the read side admitted it").toBe(
        false,
      );
      await expect(mintOne({ key }), "the write grant admitted it").rejects.toBeInstanceOf(
        ImapNotFoundError,
      );
    });
  }

  it("admits on both sides: the key this project actually builds", async () => {
    const key = `${STAGING_PREFIX}${principal.userId}/upload-a1b2c3d4e5f60718-${NOW}`;

    expect(underStagingPrefix(principal.userId, key)).toBe(true);
    await expect(mintOne({ key })).resolves.toBeTypeOf("string");
  });
});

describe("the minted upload URL", () => {
  it("signs BOTH the declared type and the declared length", async () => {
    // T-04-10-01. Without this the URL is a bearer grant to write anything of
    // any size under a key this server named, for the whole of its lifetime.
    const signedHeaders = new URL(await mintOne()).searchParams.get(
      "X-Amz-SignedHeaders",
    );

    expect(signedHeaders, "the URL carries no signed-header list").not.toBeNull();
    const named = String(signedHeaders).split(";");

    expect(named).toContain("content-type");
    expect(named).toContain("content-length");
    // `host` is always signed, so its presence proves nothing on its own — it
    // is asserted only so a list that somehow lost everything is not read as a
    // pass on the two that matter.
    expect(named).toContain("host");
  });

  it("REFUSES a name that cannot be percent-encoded, in its own vocabulary", async () => {
    // The mirror of the binding-side case in `putStaged`. A lone surrogate
    // makes `encodeURIComponent` throw `URIError`, which is a class
    // `toErrorCategory` does not recognise — so it reaches the model as a
    // connection failure at the floor, which still offers a retry, for a name
    // that fails identically forever. The refusal this function already has for
    // an unencodable name is the right answer, and the assertion is that the
    // raised class is that one rather than the encoder's.
    await expect(
      mintOne({ filename: JSON.parse('"\\ud800.pdf"') as string }),
    ).rejects.toThrow(ImapNotFoundError);
  });

  it("names the metadata header the uploader must reproduce", async () => {
    // The filename does NOT travel in the key on this path (see the key test
    // below), so this header is the only thing that carries it to the object —
    // and from there to the name on the file the recipient receives.
    const named = String(
      new URL(await mintOne()).searchParams.get("X-Amz-SignedHeaders"),
    ).split(";");

    expect(named).toContain("x-amz-meta-filename");
  });

  it("is the LIBRARY DEFAULT that drops those two, which is the correction", async () => {
    // The measurement behind the correction to D-79, pinned as a test rather
    // than as a claim. This signs the identical request through the shipped
    // library with the option omitted — the shape the vendor's own published
    // example shows — and asserts the two headers are filtered out. If a later
    // version of the library changed that default, this test would fail and the
    // correction note in 04-CONTEXT.md would need revisiting; that is exactly
    // the signal it should give.
    const client = new AwsClient({
      accessKeyId: "test-access-key-not-real",
      secretAccessKey: "test-secret-key-not-real",
      service: "s3",
      region: "auto",
    });

    const url = new URL("https://account.r2.cloudflarestorage.com/bucket/staging/x-1");
    url.searchParams.set("X-Amz-Expires", "900");

    const asDocumented = await client.sign(url.toString(), {
      method: "PUT",
      headers: {
        "content-type": "application/pdf",
        "content-length": "65536",
        "x-amz-meta-filename": "x.pdf",
      },
      aws: { signQuery: true },
    });

    const named = String(
      new URL(asDocumented.url).searchParams.get("X-Amz-SignedHeaders"),
    ).split(";");

    expect(named).not.toContain("content-type");
    expect(named).not.toContain("content-length");
    // And the one header that is NOT in the unsignable set survives, which is
    // what makes this a statement about the FILTER rather than about signing
    // having failed altogether.
    expect(named).toContain("x-amz-meta-filename");
  });

  it("expires after the configured window, and the window is short", async () => {
    const expires = new URL(await mintOne()).searchParams.get("X-Amz-Expires");

    expect(expires).toBe(String(UPLOAD_URL_TTL_SECONDS));
    // A leaked URL is a standing write grant for exactly this long. The bound
    // is asserted rather than only the equality, so raising it is a visible
    // decision rather than a one-character edit.
    expect(UPLOAD_URL_TTL_SECONDS).toBeLessThanOrEqual(30 * 60);
    expect(UPLOAD_URL_TTL_SECONDS).toBeGreaterThanOrEqual(5 * 60);
  });

  it("targets a key beneath the staging prefix, and nothing else", async () => {
    const path = new URL(await mintOne()).pathname;

    expect(path).toContain(`/${STAGING_PREFIX}`);
    expect(path.endsWith(`upload-a1b2c3d4e5f60718-${NOW}`)).toBe(true);
  });

  it("refuses a key that is not beneath the staging prefix", async () => {
    // The URL is a write grant. A key outside the prefix is a grant to write
    // somewhere the one-day sweep does not reach, so it is refused rather than
    // signed and reported.
    await expect(mintOne({ key: "elsewhere/x" })).rejects.toThrow();
    // Kept, and worth knowing it changed meaning without changing colour. It
    // was green because the NAME held a separator. It is green now because `a`
    // is not the caller's user id. The sibling below is what actually holds the
    // depth rule, and nothing else in the suite does.
    await expect(mintOne({ key: `${STAGING_PREFIX}a/b` })).rejects.toThrow();
  });

  it("refuses a key one segment DEEPER than the caller's own", async () => {
    // The depth half of the rule, and the only assertion in the suite that can
    // see it. The first segment here IS the caller's own id, so every other
    // condition passes: the prefix matches, the segment is 64 lowercase hex,
    // and it equals the id this call carries. Only the second separator refuses
    // it.
    //
    // The rule is deliberately "exactly one user segment, then a name with no
    // separator" rather than "any depth beneath the user segment". Nothing this
    // project builds produces a deeper key, so the only producer of one is a
    // forgery — and a check that stopped at the user segment would admit it.
    await expect(
      mintOne({ key: `${STAGING_PREFIX}${principal.userId}/a/b` }),
    ).rejects.toThrow();
  });

  it("refuses before constructing anything when a binding is absent", async () => {
    // Behavioural, not compiler-driven, and it must not be removed on the
    // grounds that the typecheck passes without it: the values land in a
    // template literal, and a template literal accepts an absent binding
    // silently.
    for (const binding of [
      "R2_ACCOUNT_ID",
      "R2_ACCESS_KEY_ID",
      "R2_SECRET_ACCESS_KEY",
    ] as const) {
      await expect(
        mintUploadUrl(envWithout(binding), principal.userId, {
          key: `${STAGING_PREFIX}${principal.userId}/upload-a1b2c3d4e5f60718-${NOW}`,
          contentType: "application/pdf",
          contentLength: 65_536,
          filename: "x.pdf",
        }),
        binding,
      ).rejects.toThrow();
    }
  });

  it("never lets the nine characters of an absent value reach the URL", async () => {
    // The failure this guards is not an exception. It is a syntactically
    // perfect URL aimed at a host named for a value nobody set.
    expect(await mintOne()).not.toContain(ABSENT_SPELLING);
  });

  it("returns a STRING carrying only the parameters a signature needs", async () => {
    // The whole shape of the module: the two secrets are consumed and a string
    // comes back, so no object holding either of them is ever handed to a
    // caller.
    //
    // The containment claim is made as an ALLOW-LIST over the query rather than
    // as "the secret does not appear in it", and deliberately: the negative
    // form has to name the secret in the test, and a failing `toContain`
    // assertion prints both sides. An allow-list proves the stronger property
    // — nothing rides along at all — without ever holding the value.
    const minted = await mintOne();

    expect(typeof minted).toBe("string");

    const permitted = new Set([
      "X-Amz-Algorithm",
      "X-Amz-Credential",
      "X-Amz-Date",
      "X-Amz-Expires",
      "X-Amz-Signature",
      "X-Amz-SignedHeaders",
    ]);

    const parameters = [...new URL(minted).searchParams.keys()];
    expect(parameters.length).toBeGreaterThan(4);
    for (const name of parameters) {
      expect(permitted.has(name), `an unexpected parameter rode along: ${name}`).toBe(
        true,
      );
    }

    // A signature is present and is what a signature looks like. The access key
    // id necessarily appears in the credential parameter — that is what a
    // presigned URL IS — and the secret half is what produced this hex.
    expect(new URL(minted).searchParams.get("X-Amz-Signature")).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });
});

describe("the key a presigned upload is aimed at", () => {
  it("carries no part of any caller-supplied name", () => {
    // 04-08 established that the sanitised name must not reach the trusted
    // block, because it is derived from untrusted text and shares most of its
    // characters. The minted URL DOES sit in the trusted block — it is a value
    // this server generated — so the key inside it cannot be name-derived.
    const key = presignedKeyFor(principal.userId, NOW);

    expect(key).not.toBeNull();
    expect(String(key)).toMatch(
      new RegExp(
        `^${STAGING_PREFIX}${principal.userId}/upload-[0-9a-f]{16}-${NOW}$`,
      ),
    );
  });

  it("is unique across mints inside the same millisecond", () => {
    // D-83 accepted a same-millisecond collision window and named the deferred
    // fix: a random segment. This path takes that fix, because it has already
    // given up the legibility the window was accepted to buy.
    const keys = new Set(
      Array.from({ length: 64 }, () => String(presignedKeyFor(principal.userId, NOW))),
    );

    expect(keys.size).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// Confirm: the step that looks at what actually landed (ATT-05, D-79, D-81)
//
// **This is the step that makes "rejected AT staging, with a clear reason"
// literally true on the presigned path**, and the reason it exists is that a
// declared size and an observed size are different facts. Until the server
// looks, it has only been told.
//
// The discriminating test in this block is the metadata one. An implementation
// that read the size out of custom metadata would pass every other assertion
// here, because on an honest upload the two numbers agree. The fixture below
// makes them disagree on purpose, and the refusal it produces is the difference.
// ---------------------------------------------------------------------------

/** Write an object straight through the binding, bypassing every cap. */
async function uploadRaw(
  key: string,
  bytes: Uint8Array,
  customMetadata: Record<string, string> = {},
): Promise<void> {
  await env.ATTACHMENT_STAGING.put(key, bytes, {
    httpMetadata: { contentType: "application/pdf" },
    customMetadata: { filename: "resume.pdf", ...customMetadata },
  });
}

/** The key a presigned upload in this block is aimed at. */
function uploadKey(): string {
  return String(presignedKeyFor(principal.userId, NOW));
}

describe("confirming a presigned upload", () => {
  it("mints an id only after the size check passes, on the injected clock", async () => {
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("a real upload"));

    const result = await confirmStagedUpload(env, principal.userId, key, 13, NOW, NOW + STAGED_ID_TTL_MS);

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    // The identifier is what makes the object usable. Before this call it
    // existed and could not be named.
    expect(decodeStagedId(result.id, NOW).key).toBe(key);
    expect(decodeStagedId(result.id, NOW).expiresAt).toBe(NOW + STAGED_ID_TTL_MS);
    expect(result.expiresAt).toBe(new Date(NOW + STAGED_ID_TTL_MS).toISOString());
    expect(result.sizeBytes).toBe(13);
    // And the object is still there, because a passing confirm does not consume
    // it — D-81's delete-on-attach layer is what removes it later.
    expect(await everyKey()).toContain(key);
  });

  it("deletes an object bigger than it said it would be, and mints nothing", async () => {
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("x".repeat(4096)));

    const result = await confirmStagedUpload(env, principal.userId, key, 1024, NOW, NOW + STAGED_ID_TTL_MS);

    expect(result.staged).toBe(false);
    if (result.staged) return;

    expect(result.refusal).toBe("too-large");
    // Both numbers, because those are what the model needs in order to explain
    // the problem rather than paraphrase a sentence (D-35).
    expect(result.sizeBytes).toBe(4096);
    expect(result.limitBytes).toBe(1024);
    // Gone. An object that failed confirm has no path to ever becoming a staged
    // id, so leaving it costs storage and leaves an unreferenced blob under a
    // prefix the user may well inspect.
    expect(await everyKey()).not.toContain(key);
    expect(await getStaged(env, principal.userId, key)).toBeNull();
  });

  it("deletes an over-cap object even when the DECLARED size was under it", async () => {
    // The per-file cap is not caller-supplied, which is what bounds the damage a
    // wrong declaration can do. A caller declaring something enormous cannot
    // raise the ceiling the isolate's memory actually depends on.
    const key = uploadKey();
    await uploadRaw(key, new Uint8Array(MAX_STAGED_FILE_BYTES + 1));

    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      MAX_STAGED_FILE_BYTES + 4096,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );

    expect(result.staged).toBe(false);
    if (result.staged) return;

    expect(result.refusal).toBe("too-large");
    expect(result.sizeBytes).toBe(MAX_STAGED_FILE_BYTES + 1);
    expect(result.limitBytes).toBe(MAX_STAGED_FILE_BYTES);
    expect(await everyKey()).not.toContain(key);
  });

  it("reads the size off the OBJECT, never off its custom metadata", async () => {
    // The discriminating fixture. The metadata was written before any bytes
    // existed, so it records what was CLAIMED; the object's own size is what
    // ACTUALLY landed. An implementation that trusted the metadata would see ten
    // bytes here, find them comfortably under the declared hundred, and mint an
    // id for a five-kilobyte object.
    const key = uploadKey();
    await uploadRaw(key, new Uint8Array(5000), { declaredSize: "10" });

    const result = await confirmStagedUpload(env, principal.userId, key, 100, NOW, NOW + STAGED_ID_TTL_MS);

    expect(result.staged).toBe(false);
    if (result.staged) return;

    expect(result.refusal).toBe("too-large");
    expect(result.sizeBytes).toBe(5000);
    expect(result.sizeBytes).not.toBe(10);
  });

  it("reads the SIZE without reading the body, on both arms", async () => {
    // The bound this step exists to apply, applied before the allocation rather
    // than after it. Reading through the body-bearing path materialised the
    // whole object in the isolate and only then compared its size against the
    // ceiling — which is not a bound, it is a report. Nothing here ever touches
    // the bytes: only the size, the name and the type are used.
    //
    // Asserted on the recorded calls, in both directions, because an
    // implementation that fetched the body would pass every other assertion in
    // this block. On the refusal arm the crash was additionally
    // self-perpetuating: the delete below never ran, so the same oversized
    // object was still waiting on the retry.
    const passing = uploadKey();
    await uploadRaw(passing, ENCODER.encode("a real upload"));
    const refused = uploadKey();
    await uploadRaw(refused, ENCODER.encode("x".repeat(4096)));
    const recording = recordingEnv();

    const accepted = await confirmStagedUpload(
      recording.env,
      principal.userId,
      passing,
      13,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );
    const rejected = await confirmStagedUpload(
      recording.env,
      principal.userId,
      refused,
      1024,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );

    expect(accepted.staged).toBe(true);
    expect(rejected.staged).toBe(false);
    expect(recording.events).toEqual([
      `head ${passing}`,
      `head ${refused}`,
      `delete ${refused}`,
    ]);
  });

  it("deletes an object SMALLER than it said it would be, and mints nothing", async () => {
    // The half a ceiling check cannot see, and the one that produces a wrong
    // FILE rather than a refused one. An interrupted PUT leaves a truncated
    // object; a ceiling-only bound accepts it, mints an id for it, and the
    // truncation is then base64-encoded whole into a draft the user sends.
    //
    // `readAttachmentPart` refuses exactly this one module over: "a base64 part
    // cut mid-stream decodes to a corrupt PREFIX of a real file. A PDF cut that
    // way opens, renders its first pages, and is wrong." The fetch path refused
    // it and the upload path did not.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("x".repeat(600)));

    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      1024,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );

    expect(result.staged).toBe(false);
    if (result.staged) return;

    // Not `too-large`, which would send the caller to shrink a file that was
    // already too small.
    expect(result.refusal).toBe("size-mismatch");
    expect(result.sizeBytes).toBe(600);
    expect(result.limitBytes).toBe(1024);
    // Deleted on the same terms as an overrun: an object that failed confirm
    // has no path to ever becoming a staged id.
    expect(await everyKey()).not.toContain(key);
  });

  it("accepts an EXACT match, so the equality is not merely a floor", async () => {
    // The paired assertion. A two-sided check tested only from below is
    // indistinguishable from one that refuses everything.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("x".repeat(600)));

    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      600,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );

    expect(result.staged).toBe(true);
  });

  it("refuses a key with nothing behind it, without throwing", async () => {
    const result = await confirmStagedUpload(env, principal.userId, uploadKey(), 1024, NOW, NOW + STAGED_ID_TTL_MS);

    expect(result.staged).toBe(false);
    if (result.staged) return;

    expect(result.refusal).toBe("not-found");
    expect(result.sizeBytes).toBe(0);
  });

  it("gives a forged key outside the prefix the same answer as a missing one", async () => {
    // The staged identifier is unsigned, so a caller can name any key it likes.
    // A distinguishable refusal here would be an existence oracle handed to
    // exactly that forgery, which is the reasoning `getStaged` already carries.
    const outside = await confirmStagedUpload(env, principal.userId, "elsewhere/secret", 1024, NOW, NOW + STAGED_ID_TTL_MS);
    const missing = await confirmStagedUpload(env, principal.userId, uploadKey(), 1024, NOW, NOW + STAGED_ID_TTL_MS);

    expect(outside).toEqual(missing);
  });

  it("is IDEMPOTENT on a second confirm, never additive", async () => {
    // One upload must not become two live attachments. Both ids name the same
    // key, so attaching either one deletes the object and the other then
    // resolves to the same "there is nothing there" answer an expired token
    // gives.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("uploaded once"));

    const declared = "uploaded once".length;
    const first = await confirmStagedUpload(env, principal.userId, key, declared, NOW, NOW + STAGED_ID_TTL_MS);
    const second = await confirmStagedUpload(env, principal.userId, key, declared, NOW, NOW + STAGED_ID_TTL_MS);

    expect(first.staged && second.staged).toBe(true);
    if (!first.staged || !second.staged) return;

    expect(decodeStagedId(second.id, NOW).key).toBe(
      decodeStagedId(first.id, NOW).key,
    );
    expect((await everyKey()).filter((one) => one === key)).toHaveLength(1);
  });

  it("hands back an id the attach path resolves, name and type included", async () => {
    // The end of the third ingress, joined to plan 04-09's path: the file the
    // recipient receives carries the name the user typed, which is what the
    // signed metadata header exists to carry.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("the uploaded document"), {
      filename: encodeURIComponent("Staff Engineer — job description.pdf"),
    });

    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      "the uploaded document".length,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );
    expect(result.staged).toBe(true);
    if (!result.staged) return;

    const staged = await resolveStagedAttachments(env, principal.userId, [result.id], NOW);

    expect(staged.attachments).toHaveLength(1);
    expect(staged.attachments[0].filename).toBe(
      "Staff Engineer — job description.pdf",
    );
    expect(DECODER.decode(staged.attachments[0].content)).toBe(
      "the uploaded document",
    );
    expect(staged.keys).toEqual([key]);
  });
});

describe("the confirmed identifier cannot outlive the bytes (D-82)", () => {
  it("caps the minted expiry at the grant's own lapse instant", async () => {
    // The gap this ingress opens and the other two do not: the grant is minted,
    // time passes, the bytes arrive, and more time may pass before anyone
    // confirms. A token minted a plain day from the CONFIRM would outlive an
    // object the sweep had already scheduled from its upload.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("uploaded late"));

    const mintedAt = NOW;
    const confirmedAt = NOW + 6 * 60 * 60 * 1000;
    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      "uploaded late".length,
      confirmedAt,
      mintedAt + STAGED_ID_TTL_MS,
    );

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    // Twenty-four hours from the MINT, not from the confirm.
    expect(decodeStagedId(result.id, confirmedAt).expiresAt).toBe(
      mintedAt + STAGED_ID_TTL_MS,
    );
    expect(decodeStagedId(result.id, confirmedAt).expiresAt).toBeLessThan(
      confirmedAt + STAGED_ID_TTL_MS,
    );
  });

  it("still uses the ordinary window when the grant lapses later", async () => {
    // The cap is a ceiling, not a replacement. A caller passing something
    // generous does not extend the ordinary day.
    const key = uploadKey();
    await uploadRaw(key, ENCODER.encode("uploaded promptly"));

    const result = await confirmStagedUpload(
      env, principal.userId,
      key,
      "uploaded promptly".length,
      NOW,
      NOW + 90 * STAGED_ID_TTL_MS,
    );

    expect(result.staged).toBe(true);
    if (!result.staged) return;

    expect(decodeStagedId(result.id, NOW).expiresAt).toBe(NOW + STAGED_ID_TTL_MS);
  });
});

describe("the third ingress, end to end", () => {
  it("mints, accepts an upload, confirms, and attaches through 04-09's path", async () => {
    // The whole arc in one test, because each half is convincing alone and the
    // JOIN is where a shape mismatch would live. The middle step stands in for
    // the person with a command line: bytes arrive at the key the grant named,
    // carrying the metadata header the signature required.
    const key = uploadKey();
    const minted = await mintUploadUrl(env, principal.userId, {
      key,
      contentType: "application/pdf",
      contentLength: 13,
      filename: "Job description.pdf",
    });

    // The grant names this key and no other.
    expect(new URL(minted).pathname).toContain(key);

    await uploadRaw(key, ENCODER.encode("%PDF-1.7 body"), {
      filename: encodeURIComponent("Job description.pdf"),
    });

    const confirmed = await confirmStagedUpload(
      env, principal.userId,
      key,
      13,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );
    expect(confirmed.staged).toBe(true);
    if (!confirmed.staged) return;
    expect(confirmed.offeredFilename).toBe("Job description.pdf");

    const duplex = appendingDuplex();
    let written: Uint8Array = new Uint8Array(0);

    const composition = await composeWithAttachments(
      env, principal.userId,
      [confirmed.id],
      (attachments) => buildDraft(draftInput({ attachments })),
      async (message) => {
        written = message;
        return appendDraftOver(
          duplex,
          principal,
          createSessionGate(),
          null,
          message,
          FAST_BOUNDS,
        );
      },
      NOW,
    );

    expect(composition.outcome?.appended).toBe(true);
    expect(composition.attachedCount).toBe(1);
    // The name the user typed, on the file the recipient receives. That is what
    // the signed metadata header exists to carry, and it is the reason the key
    // could give up carrying it.
    expect(DECODER.decode(written)).toContain("Job description.pdf");
    // D-81's delete-on-attach layer, unchanged by the new ingress.
    expect(await everyKey()).not.toContain(key);
  });

  it("will not let an UNCONFIRMED upload be attached", async () => {
    // The hole a shared token kind would have opened. An upload ticket and a
    // staged id name the same shape of thing, so if they carried the same kind
    // byte a caller could skip confirm entirely — and with it the size check,
    // the delete-on-overrun and the per-file cap — by handing the ticket
    // straight to the compose path.
    const key = uploadKey();
    await uploadRaw(key, new Uint8Array(64));

    const ticket = encodeUploadId({ key, expiresAt: NOW + STAGED_ID_TTL_MS }, NOW);

    await expect(resolveStagedAttachments(env, principal.userId, [ticket], NOW)).rejects.toThrow(
      ImapNotFoundError,
    );
    // And the reverse: a confirmed staged id is not a ticket that can be
    // re-confirmed.
    const confirmed = await confirmStagedUpload(
      env, principal.userId,
      key,
      64,
      NOW,
      NOW + STAGED_ID_TTL_MS,
    );
    expect(confirmed.staged).toBe(true);
    if (!confirmed.staged) return;
    expect(() => decodeUploadId(confirmed.id, NOW)).toThrow(ImapNotFoundError);
  });
});

// ---------------------------------------------------------------------------
// WINDOWS 51 — the declared type must survive the PRESIGNED ingress
//
// Found in live UAT on 2026-08-21, not by a test, and that is the reason this
// block exists: every ingress had coverage, but only through `putStaged`, so
// nothing exercised an object written the way a presigned upload writes one.
// ---------------------------------------------------------------------------

describe("the declared type survives an object written outside putStaged", () => {
  // A LET assigned in `beforeAll`, not a `const` at collection time. The key
  // now carries the owner's user segment, and `principal` is itself resolved in
  // a `beforeAll` — a const here would interpolate `undefined` into the key
  // before any hook had run.
  let KEY: string;

  beforeAll(() => {
    KEY = `${STAGING_PREFIX}${principal.userId}/0123456789abcdef-typed.txt-${NOW}`;
  });

  beforeEach(async () => {
    await env.ATTACHMENT_STAGING.delete(KEY);
  });

  it("reads the stored content type when no custom metadata was written", async () => {
    // A presigned PUT lands in the bucket WITHOUT `declaredType`, because it
    // never calls `putStaged` — it goes straight to R2's S3 API, and the mint
    // signs only the filename metadata header. This writes an object in exactly
    // that shape: an http content type, and no custom type key.
    //
    // Before the fix this returned `application/octet-stream`, and a draft built
    // from it carried that in its Content-Type despite the caller having
    // declared `text/plain` and R2 having stored it correctly all along.
    await env.ATTACHMENT_STAGING.put(KEY, new Uint8Array([1, 2, 3]), {
      httpMetadata: { contentType: "text/plain" },
      customMetadata: { filename: "typed.txt", stagedAt: String(NOW) },
    });

    const fetched = await getStaged(env, principal.userId, KEY);

    expect(fetched).not.toBeNull();
    expect(fetched!.mimeType).toBe("text/plain");
  });

  it("prefers custom metadata over the stored type, so the binding paths are unchanged", async () => {
    // The arms are ordered, and the order is what keeps this fix from being a
    // behaviour change for the two ingresses that already worked. `putStaged`
    // writes both, and the custom value is the one it validated on the way in.
    await env.ATTACHMENT_STAGING.put(KEY, new Uint8Array([1, 2, 3]), {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: {
        filename: "typed.txt",
        declaredType: "application/pdf",
        stagedAt: String(NOW),
      },
    });

    expect((await getStaged(env, principal.userId, KEY))!.mimeType).toBe("application/pdf");
  });

  it("refuses a stored type that is not a media type, rather than passing it on", async () => {
    // The value originates in a header the uploading client chose, and it ends
    // up in the Content-Type of a message the user sends under their own name.
    // 04-09 already closed the neighbouring hole where a stranger-declared type
    // could inject a parameter there, so this arm applies the SAME gate
    // `putStaged` applies rather than trusting the header.
    await env.ATTACHMENT_STAGING.put(KEY, new Uint8Array([1, 2, 3]), {
      httpMetadata: { contentType: 'text/plain"; x="y' },
      customMetadata: { filename: "typed.txt", stagedAt: String(NOW) },
    });

    expect((await getStaged(env, principal.userId, KEY))!.mimeType).toBe(
      "application/octet-stream",
    );
  });
});
