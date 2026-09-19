// Cross-user tests: user A makes a thing, user B presents A's value, and B must
// be refused.
//
// **What this file proves.** For each store, one test says what MUST be true
// (B is turned away) and records whether it is true today. Where it is not, the
// test is marked as an expected fail, so the suite stays green now and goes red
// the moment a fix lands — which forces the fix to be noticed and the mark to be
// removed on purpose (D-06). Each expected fail sits beside a plain green
// control that uses the same setup and shows A can reach A's own thing.
//
// Everything goes through TODAY'S signatures at the tool layer (D-05). Nothing
// here is written against a signature that does not exist yet. A later phase
// changes how the fixture says "this is B", and nothing about what is asserted.
//
// **The stores are real.** `env.ATTACHMENT_STAGING` is the pool's real local
// bucket, the same one `test/staging.test.ts` uses, and `env.CONFIRM_KV` and
// `env.DAV_CACHE` are the pool's real namespaces. The one thing that is faked is
// iCloud itself: the DAV tests install the two-home stub from
// `./fixtures/two-user-dav`, which answers every request and forwards none.
//
// **What would make an expected fail pass for the wrong reason.** The runner
// turns ANY failure inside such a body into a pass and throws the error away.
// It cannot tell "B got A's bytes" from a typo. So a body that blew up in setup
// would sit there looking like recorded evidence of a leak while proving
// nothing. Three rules close that, and every expected-fail body in this file
// follows all three:
//
//   1. Only the leak assertion may throw. It is the one `expect` in the body,
//      and its message starts `LEAK:` and says what leaked in plain words.
//   2. Setup that cannot complete does an early `return`, with no assertion.
//      The body then PASSES, so the runner reports "Expect test to fail" and
//      the test goes red. That is the right direction to break in.
//   3. B's action goes through `attempt()`, which turns a throw into a value.
//      After the fix B's call will throw, and a throw that escaped would keep
//      the expected fail "failing" for ever.
//
// Before any test here was marked, it was run once as a plain test and its
// failure line was captured. That line is copied in a comment above the test,
// so the evidence lives in git and not only in a private note (D-07).
//
// One clock per test: `Date.now()` is read once at the top and that same number
// is handed to every call that takes a clock, so an id minted in a test cannot
// expire half way through it.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09).

import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getEvent } from "../src/dav/calendar";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { DavNotFoundError } from "../src/dav/errors";
import { decodeEventId } from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import {
  STAGED_ID_TTL_MS,
  decodeStagedId,
  decodeUploadId,
  encodeStagedId,
  encodeUploadId,
} from "../src/mail/ids";
import {
  mintUploadGrant,
  releaseStagedAttachments,
  resolveStagedAttachments,
  stageInlineBytes,
} from "../src/mcp/tools/mail";
import { TOKEN_DECODER, fromBase64Url } from "../src/tokens";
import {
  CANARY_SUMMARY_A,
  EVENT_A_ID,
  HOME_A,
  HOME_B,
  twoUserDavStub,
} from "./fixtures/two-user-dav";
import {
  USER_A,
  USER_B,
  attempt,
  envFor,
  readToolResult,
  toolsFor,
} from "./fixtures/two-users";
import type { TwoUserDavStub } from "./fixtures/two-user-dav";
import type { RecordedToolResult } from "./fixtures/two-users";

const DECODER = new TextDecoder();
const ENCODER = new TextEncoder();

/**
 * A's file, as a string nothing else in the suite could produce by accident.
 * If it ever turns up in something B received, that is the leak.
 */
const MARKER_A = "CANARY-A-staged-file-7f3c9e";

/** Every object currently in the bucket, whatever prefix it carries. */
async function everyStagedKey(): Promise<string[]> {
  const listed = await env.ATTACHMENT_STAGING.list();
  return listed.objects.map((one) => one.key).sort();
}

/**
 * Stage A's file as A, and hand back the id A was given and the bucket key it
 * names. Gives null when staging did not succeed.
 *
 * It holds no assertion and it never throws, so it is safe inside an
 * expected-fail body: a control asserts on its result with a message, and a
 * leak test returns early on null.
 */
async function stageAsA(
  now: number,
): Promise<{ id: string; key: string } | null> {
  try {
    const staged = await stageInlineBytes(
      envFor(USER_A),
      { base64: btoa(MARKER_A), filename: "a.txt", mimeType: "text/plain" },
      now,
    );
    if (!staged.staged) return null;
    return { id: staged.id, key: decodeStagedId(staged.id, now).key };
  } catch {
    return null;
  }
}

/** The file A uploads through a presigned grant. A second canary, like MARKER_A. */
const UPLOAD_MARKER_A = "CANARY-A-uploaded-file-51d2b8";
const UPLOAD_BYTES_A = ENCODER.encode(UPLOAD_MARKER_A);

/**
 * A asks for an upload grant, and the bytes land at the key it names.
 *
 * The `put` stands in for the presigned PUT, so no network is used. It writes
 * the same content type and the same filename metadata the real upload would.
 * Gives null when the grant was not granted or the write did not happen.
 *
 * It holds no assertion and it never throws, so it is safe inside an
 * expected-fail body.
 *
 * `now` must be the wall clock. The confirm callback reads the wall clock for
 * itself, so a ticket minted at a fixed instant in the past would look expired
 * to it, and an expiry would stand in for a refusal and hide the leak.
 */
async function grantAndUploadAsA(
  now: number,
): Promise<{ uploadId: string; key: string } | null> {
  try {
    const grant = await mintUploadGrant(
      envFor(USER_A),
      {
        filename: "a.pdf",
        mimeType: "application/pdf",
        sizeBytes: UPLOAD_BYTES_A.length,
      },
      now,
    );
    if (!grant.granted || grant.uploadId === null) return null;

    const key = decodeUploadId(grant.uploadId, now).key;
    await env.ATTACHMENT_STAGING.put(key, UPLOAD_BYTES_A, {
      httpMetadata: { contentType: "application/pdf" },
      customMetadata: { filename: "a.pdf" },
    });
    return { uploadId: grant.uploadId, key };
  } catch {
    return null;
  }
}

/**
 * An upload ticket for `key` that B wrote by hand, or null if it cannot be built.
 *
 * B never saw the ticket A was given. The ticket is not signed, so B can write
 * one from the key alone. The leak test and its control BOTH build their ticket
 * here, and that is what makes the control's call the same call as the leak
 * test's.
 *
 * It holds no assertion and it never throws.
 */
function handBuiltTicketFor(key: string, now: number): string | null {
  try {
    return encodeUploadId({ key, expiresAt: now + STAGED_ID_TTL_MS }, now);
  } catch {
    return null;
  }
}

/**
 * Did the tool turn B away? True when the result is an error result, or when
 * the server's own half says nothing was staged.
 *
 * It takes a result that is not null, holds no assertion and never throws. The
 * error flag is always read inline through `readToolResult`, because a raw
 * success result has no such field.
 */
function refusedByTool(result: RecordedToolResult): boolean {
  if (readToolResult(result).isError) return true;
  return readToolResult(result).trusted?.staged === false;
}

/** Every confirm key currently in the store. */
async function everyConfirmKey(): Promise<string[]> {
  const listed = await env.CONFIRM_KV.list({ prefix: "confirm:" });
  return listed.keys.map((one) => one.name).sort();
}

/**
 * Forget every cached DAV home: the pool's own, A's and B's.
 *
 * All three, because today the calendar callbacks key the cache by the pool's
 * own identity while the functions under them key it by whoever's environment
 * they were handed. A home left behind under any of the three would let one
 * test's discovery answer another test's question.
 *
 * One at a time, never together. Each is a store operation, and this project
 * does not fan those out.
 */
async function forgetEveryDavHome(): Promise<void> {
  await clearDavCache(env, "caldav");
  await clearDavCache(envFor(USER_A), "caldav");
  await clearDavCache(envFor(USER_B), "caldav");
}

/**
 * Nothing left over, before every case: an empty bucket, no confirm keys and no
 * cached DAV home. This is what makes the file give the same result in any
 * order.
 */
beforeEach(async () => {
  for (const key of await everyStagedKey()) {
    await env.ATTACHMENT_STAGING.delete(key);
  }
  expect(await everyStagedKey()).toEqual([]);

  for (const key of await everyConfirmKey()) {
    await env.CONFIRM_KV.delete(key);
  }
  expect(await everyConfirmKey()).toEqual([]);

  await forgetEveryDavHome();
});

/** No stubbed `fetch` and no mock outlives the test that installed it. */
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("R2 staging, read: a staged file belongs to the user who staged it", () => {
  it("control: A can attach a file A staged", async () => {
    const now = Date.now();

    const staged = await stageInlineBytes(
      envFor(USER_A),
      { base64: btoa(MARKER_A), filename: "a.txt", mimeType: "text/plain" },
      now,
    );
    expect(staged.staged, "the fixture failed to stage").toBe(true);
    if (!staged.staged) throw new Error("unreachable");

    const resolved = await resolveStagedAttachments(
      envFor(USER_A),
      [staged.id],
      now,
    );

    expect(
      DECODER.decode(resolved.attachments[0]!.content),
      "A did not get back the bytes A staged",
    ).toBe(MARKER_A);
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B received A's file bytes: expected false to be true // Object.is equality
  //
  // B presented the id A was given and was handed A's file. Nothing on this
  // path asks who is calling. When a fix makes B's call refuse, this test goes
  // red with "Expect test to fail": remove the mark then, on purpose, and leave
  // the body exactly as it is.
  it.fails("B cannot attach a file A staged", async () => {
    const now = Date.now();

    const staged = await stageInlineBytes(
      envFor(USER_A),
      { base64: btoa(MARKER_A), filename: "a.txt", mimeType: "text/plain" },
      now,
    );
    if (!staged.staged) return;
    const idFromA = staged.id;

    const outcome = await attempt(() =>
      resolveStagedAttachments(envFor(USER_B), [idFromA], now),
    );

    expect(outcome.refused, "LEAK: B received A's file bytes").toBe(true);
  });
});

describe("R2 staging, delete: only the user who staged a file can remove it", () => {
  it("control: A's own release removes A's object", async () => {
    const now = Date.now();

    const staged = await stageAsA(now);
    expect(staged, "the fixture failed to stage").not.toBeNull();
    if (staged === null) throw new Error("unreachable");
    expect(
      await env.ATTACHMENT_STAGING.head(staged.key),
      "A's object was not in the bucket after staging",
    ).not.toBeNull();

    await releaseStagedAttachments(envFor(USER_A), [staged.key], true);

    expect(
      await env.ATTACHMENT_STAGING.head(staged.key),
      "A's own release left A's object behind",
    ).toBeNull();
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B's release deleted A's staged object: expected null not to be null
  //
  // B named A's key and asked for it to be released, as if an attach of B's had
  // just consumed it. A's file was gone afterwards. Nothing on this path asks
  // whose key it is. The check reads the bucket, not B's result, so it holds
  // whether B's call returns or throws. When a fix leaves A's object in place,
  // this test goes red with "Expect test to fail": remove the mark then, on
  // purpose, and leave the body exactly as it is.
  it.fails("B cannot delete a file A staged", async () => {
    const now = Date.now();

    const staged = await stageAsA(now);
    if (staged === null) return;
    const keyOfA = staged.key;

    await attempt(() =>
      releaseStagedAttachments(envFor(USER_B), [keyOfA], true),
    );

    expect(
      await env.ATTACHMENT_STAGING.head(keyOfA),
      "LEAK: B's release deleted A's staged object",
    ).not.toBeNull();
  });
});

describe("staged id, built by hand: the id proves nothing about who holds it", () => {
  it("control: A can resolve an id A rebuilt for A's own key", async () => {
    const now = Date.now();

    const staged = await stageAsA(now);
    expect(staged, "the fixture failed to stage").not.toBeNull();
    if (staged === null) throw new Error("unreachable");

    const rebuilt = encodeStagedId(
      { key: staged.key, expiresAt: now + STAGED_ID_TTL_MS },
      now,
    );

    const resolved = await resolveStagedAttachments(
      envFor(USER_A),
      [rebuilt],
      now,
    );

    expect(
      DECODER.decode(resolved.attachments[0]!.content),
      "A did not get back the bytes A staged",
    ).toBe(MARKER_A);
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B read A's file bytes with a staged id B built by hand: expected false to be true // Object.is equality
  //
  // **This is the guard against a wrong fix.** The id is not signed, so B can
  // write anything into one. A fix that read the user out of the id being
  // checked would be reading a value B chose, and B would still get A's file.
  // Only a check against the signed-in user refuses this. When such a fix
  // lands, this test goes red with "Expect test to fail": remove the mark then,
  // on purpose, and leave the body exactly as it is.
  it.fails("B cannot read A's file with an id B built by hand", async () => {
    const now = Date.now();

    const staged = await stageAsA(now);
    if (staged === null) return;
    const keyOfA = staged.key;

    // B never saw the id A was given. B writes one from nothing but the key.
    const forged = await attempt(async () =>
      encodeStagedId({ key: keyOfA, expiresAt: now + STAGED_ID_TTL_MS }, now),
    );
    if (forged.refused) return;
    const idFromB = forged.value;

    const outcome = await attempt(() =>
      resolveStagedAttachments(envFor(USER_B), [idFromB], now),
    );

    expect(
      outcome.refused,
      "LEAK: B read A's file bytes with a staged id B built by hand",
    ).toBe(true);
  });
});

// These two are what prove the catch paths work. No other green test reaches
// them today, because nothing B does is refused yet, so nothing B does throws.
describe("fixture", () => {
  it("fixture: a callback that throws gives null", async () => {
    const tools = toolsFor(USER_A, (register) => {
      register("test_throws", () => {
        throw new Error("a callback that throws");
      });
      register("test_rejects", () =>
        Promise.reject(new Error("a callback that rejects")),
      );
    });

    expect(
      await tools.call("test_throws", {}),
      "a callback that threw did not give null",
    ).toBeNull();
    expect(
      await tools.call("test_rejects", {}),
      "a callback that rejected did not give null",
    ).toBeNull();
    expect(
      await tools.call("test_nobody_registered_this", {}),
      "a missing tool did not give null",
    ).toBeNull();

    // The extra tools went onto the same list as the real ones, not in place
    // of them.
    expect(tools.names).toContain("mail_confirm_upload");
    expect(tools.names).toContain("test_throws");
    expect(tools.names).toContain("test_rejects");
  });

  it("fixture: attempt turns a throw into refused", async () => {
    const threw = await attempt(async () => {
      throw new Error("a plain throw");
    });
    expect(threw.refused, "a plain throw was not turned into refused").toBe(true);

    const rejected = await attempt(() =>
      Promise.reject(new Error("a rejected promise")),
    );
    expect(
      rejected.refused,
      "a rejected promise was not turned into refused",
    ).toBe(true);

    const resolved = await attempt(() => Promise.resolve("the value"));
    expect(resolved).toEqual({ refused: false, value: "the value" });
  });

  it("fixture: a registration that throws does not escape toolsFor", async () => {
    const built = await attempt(async () =>
      toolsFor(USER_B, () => {
        throw new Error("a registration that throws");
      }),
    );

    expect(built.refused, "toolsFor let a registration throw escape").toBe(false);
    if (built.refused) throw new Error("unreachable");

    // What was recorded before the throw is still there and still callable.
    expect(built.value.names).toContain("mail_confirm_upload");
    expect(
      await built.value.call("test_nobody_registered_this", {}),
      "a missing tool did not give null",
    ).toBeNull();
  });

  it("fixture: both users reach the mail and calendar tools", () => {
    const names = toolsFor(USER_B).names;
    expect(names).toContain("mail_confirm_upload");
    expect(names).toContain("calendar_update_event");
    expect(names).toContain("calendar_commit");
  });
});

describe("upload ticket: an upload belongs to the user who asked for the grant", () => {
  it("control: A confirms A's own upload", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    expect(upload, "the fixture failed to grant and upload").not.toBeNull();
    if (upload === null) throw new Error("unreachable");

    const result = await toolsFor(USER_A).call("mail_confirm_upload", {
      uploadId: upload.uploadId,
      sizeBytes: UPLOAD_BYTES_A.length,
    });
    expect(result, "the tool is missing or its callback threw").not.toBeNull();
    if (result === null) throw new Error("unreachable");

    expect(
      readToolResult(result).isError,
      "a success result must read as isError false",
    ).toBe(false);

    const trusted = readToolResult(result).trusted;
    expect(trusted?.staged, "A's own confirm was not staged").toBe(true);
    expect(typeof trusted?.id, "A's own confirm gave no staged id").toBe("string");

    // The id is real: it resolves, as A, to the bytes A uploaded.
    const resolved = await resolveStagedAttachments(
      envFor(USER_A),
      [String(trusted?.id)],
      now,
    );
    expect(
      DECODER.decode(resolved.attachments[0]!.content),
      "A's confirmed id did not resolve to the bytes A uploaded",
    ).toBe(UPLOAD_MARKER_A);
  });

  // This says nothing about what the result holds, on purpose. It is green
  // today, when B is handed a staged id, and green after the fix, when B is
  // refused. It goes red only when B's call gives null, which is the one case
  // the leak test beside it passes over by returning early.
  it("control: B's confirm call gives a real result", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    expect(upload, "the fixture failed to grant and upload").not.toBeNull();
    if (upload === null) throw new Error("unreachable");

    const result = await toolsFor(USER_B).call("mail_confirm_upload", {
      uploadId: upload.uploadId,
      sizeBytes: UPLOAD_BYTES_A.length,
    });

    expect(result, "the tool is missing or its callback threw").not.toBeNull();
  });

  // The same job, for the call the hand-built ticket test makes. The control
  // above cannot cover it: that one sends A's real uploadId, so a callback that
  // threw only on a hand-built ticket would leave it green while the leak test
  // returned early and passed.
  it("control: B's hand-built ticket confirm gives a real result", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    expect(upload, "the fixture failed to grant and upload").not.toBeNull();
    if (upload === null) throw new Error("unreachable");

    const ticket = handBuiltTicketFor(upload.key, now);
    expect(ticket, "the hand-built ticket could not be built").not.toBeNull();
    if (ticket === null) throw new Error("unreachable");

    const result = await toolsFor(USER_B).call("mail_confirm_upload", {
      uploadId: ticket,
      sizeBytes: UPLOAD_BYTES_A.length,
    });

    expect(result, "the tool is missing or its callback threw").not.toBeNull();
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B confirmed A's upload and was handed a staged id for A's file: expected false to be true // Object.is equality
  //
  // B presented the uploadId A was given. The tool confirmed it and handed B a
  // staged id for A's file. A null from B's call returns early, which makes this
  // body pass and the mark go red. "control: B's confirm call gives a real
  // result" makes the same call and is red whenever it gives null, so a null
  // here can never be read as "no leak". When a fix makes B's confirm refuse,
  // this test goes red with "Expect test to fail": remove the mark then, on
  // purpose, and leave the body exactly as it is.
  it.fails("B cannot confirm A's upload", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    if (upload === null) return;

    const result = await toolsFor(USER_B).call("mail_confirm_upload", {
      uploadId: upload.uploadId,
      sizeBytes: UPLOAD_BYTES_A.length,
    });
    if (result === null) return;

    expect(
      refusedByTool(result),
      "LEAK: B confirmed A's upload and was handed a staged id for A's file",
    ).toBe(true);
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B's wrong-size confirm deleted A's uploaded object: expected null not to be null
  //
  // B confirmed A's uploadId with a size one byte too big. The size check
  // failed and deleted A's object. On this path the uploaded bytes are the only
  // copy, so A has to upload the file again. When a fix leaves A's object in
  // place, this test goes red with "Expect test to fail": remove the mark then,
  // on purpose, and leave the body exactly as it is.
  it.fails("B's wrong-size confirm cannot delete A's upload", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    if (upload === null) return;
    const keyOfA = upload.key;

    // B's result is not read, so a null needs no early return here. Whether
    // A's object is still there is true evidence either way.
    await toolsFor(USER_B).call("mail_confirm_upload", {
      uploadId: upload.uploadId,
      sizeBytes: UPLOAD_BYTES_A.length + 1,
    });

    expect(
      await env.ATTACHMENT_STAGING.head(keyOfA),
      "LEAK: B's wrong-size confirm deleted A's uploaded object",
    ).not.toBeNull();
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B confirmed A's upload with an upload ticket B built by hand: expected false to be true // Object.is equality
  //
  // **This is the guard against a wrong fix**, like the hand-built staged id
  // above. The ticket is not signed, so a fix that read the user out of the
  // ticket would be reading a value B chose. "control: B's hand-built ticket
  // confirm gives a real result" builds its ticket with the same helper, makes
  // the same call, and is red whenever that call gives null. When a fix makes
  // B's confirm refuse, this test goes red with "Expect test to fail": remove
  // the mark then, on purpose, and leave the body exactly as it is.
  it.fails("B cannot confirm a ticket B built by hand", async () => {
    const now = Date.now();

    const upload = await grantAndUploadAsA(now);
    if (upload === null) return;

    const ticket = handBuiltTicketFor(upload.key, now);
    if (ticket === null) return;

    const result = await toolsFor(USER_B).call("mail_confirm_upload", {
      uploadId: ticket,
      sizeBytes: UPLOAD_BYTES_A.length,
    });
    if (result === null) return;

    expect(
      refusedByTool(result),
      "LEAK: B confirmed A's upload with an upload ticket B built by hand",
    ).toBe(true);
  });
});

describe("DAV_CACHE: a cached home belongs to the account it was resolved for", () => {
  it("DAV_CACHE: A and B resolve to their own homes under their own keys", async () => {
    const stub = twoUserDavStub();
    vi.stubGlobal("fetch", stub.fetch);

    const firstA = await resolveDavAccount(
      envFor(USER_A),
      createDavFetch(envFor(USER_A)),
      "caldav",
    );
    expect(firstA.cacheHit, "A's first resolve was not a cold one").toBe(false);
    expect(firstA.homeUrl, "A did not resolve to A's home").toBe(HOME_A);

    const firstB = await resolveDavAccount(
      envFor(USER_B),
      createDavFetch(envFor(USER_B)),
      "caldav",
    );
    expect(firstB.cacheHit, "B's first resolve was answered from A's entry").toBe(
      false,
    );
    expect(firstB.homeUrl, "B did not resolve to B's home").toBe(HOME_B);

    // Two keys, one per user. The user ids are the literal rows from the
    // vectors file. Nothing is hashed here (D-12): this works because an
    // address that is already trimmed and lowercase hashes today to exactly the
    // user id the spec gives it.
    const listed = await env.DAV_CACHE.list({ prefix: "dav:" });
    const names = listed.keys.map((one) => one.name);
    const keyOfA = `dav:v1:${USER_A.userId}:caldav`;
    const keyOfB = `dav:v1:${USER_B.userId}:caldav`;
    expect(names, "A's home is not stored under A's own key").toContain(keyOfA);
    expect(names, "B's home is not stored under B's own key").toContain(keyOfB);
    expect(keyOfA, "A and B share one cache key").not.toBe(keyOfB);

    // B resolving did not move A's entry.
    const secondA = await resolveDavAccount(
      envFor(USER_A),
      createDavFetch(envFor(USER_A)),
      "caldav",
    );
    expect(secondA.cacheHit, "A's second resolve missed the cache").toBe(true);
    expect(secondA.homeUrl, "A's cached home changed after B resolved").toBe(
      HOME_A,
    );
  });

  it.todo(
    "DAV_CACHE through the registered callbacks: cannot run until Phase 9 threads the principal into the tool callbacks",
  );
});

describe("home-set check: an event id only works under the caller's own home", () => {
  // Without this the zero-request assertion in the next test would pass just as
  // happily on a harness that never sends anything at all.
  it("negative control: A can fetch A's own event", async () => {
    const stub = twoUserDavStub();
    vi.stubGlobal("fetch", stub.fetch);

    const detail = await getEvent(
      envFor(USER_A),
      createDavFetch(envFor(USER_A)),
      decodeEventId(EVENT_A_ID),
    );

    expect(
      JSON.stringify(detail),
      "A did not get A's own event back",
    ).toContain(CANARY_SUMMARY_A);
    expect(
      stub.observed.filter(
        (one) => one.user === "A" && one.url.startsWith(HOME_A),
      ).length,
      "A's own fetch never reached the stub",
    ).toBeGreaterThan(0);
  });

  it("home-set check: B cannot fetch an event under A's home", async () => {
    const stub = twoUserDavStub();
    vi.stubGlobal("fetch", stub.fetch);

    // Whatever B got back: a value, or what the call threw.
    let received: unknown = null;
    let thrown: unknown = null;
    try {
      received = await getEvent(
        envFor(USER_B),
        createDavFetch(envFor(USER_B)),
        decodeEventId(EVENT_A_ID),
      );
    } catch (err) {
      thrown = err;
    }

    expect(thrown, "B was not refused").toBeInstanceOf(DavNotFoundError);
    expect(
      stub.observed.filter((one) => one.url.startsWith(HOME_A)),
      "a request carrying B's credentials reached a URL under A's home",
    ).toEqual([]);
    expect(
      JSON.stringify(received),
      "B received text from A's event",
    ).not.toContain(CANARY_SUMMARY_A);

    // B did reach the stub, as B. So the empty list above is a real refusal and
    // not a harness that sent nothing.
    expect(
      stub.observed.filter((one) => one.user === "B").length,
      "B's call never reached the stub at all",
    ).toBeGreaterThan(0);
  });

  it.todo(
    "home-set check through the registered callbacks: cannot run until Phase 9 threads the principal into the tool callbacks",
  );
});

// ---------------------------------------------------------------------------
// The calendar confirm flow, with two users
//
// A previews a change and is handed a one-time token. B gets hold of the token
// and the change, and tries to commit them.
//
// **Every turn change forgets the cached DAV home first.** Today the calendar
// callbacks key that cache by the pool's own identity, not by the user. Left
// alone, B's commit would find the home A's preview just cached, the home-set
// check would pass for B, and the test would be measuring this fixture instead
// of the code. The warning sign is "B's commit is not refused".
// ---------------------------------------------------------------------------

/** What A's preview handed back: the one-time token and the change it covers. */
interface PreviewOfA {
  readonly confirmToken: string;
  readonly change: Record<string, unknown>;
}

/**
 * A previews a move of A's event by one hour, against the two-home stub.
 *
 * It installs the stub, so every later call in the same test goes to it too.
 * Gives null when the call gave null or the preview carried no token.
 *
 * It holds no assertion and it never throws, so it is safe inside an
 * expected-fail body.
 */
async function previewAsA(stub: TwoUserDavStub): Promise<PreviewOfA | null> {
  try {
    await clearDavCache(env, "caldav");
    vi.stubGlobal("fetch", stub.fetch);

    const result = await toolsFor(USER_A).call("calendar_update_event", {
      id: EVENT_A_ID,
      startLocal: "2026-02-10T16:00:00",
      endLocal: "2026-02-10T17:00:00",
    });
    if (result === null) return null;

    const parsed = readToolResult(result);
    const confirmToken = parsed.trusted?.confirmToken;
    const change = parsed.untrusted?.change;
    if (typeof confirmToken !== "string") return null;
    if (typeof change !== "object" || change === null) return null;
    return { confirmToken, change: change as Record<string, unknown> };
  } catch {
    return null;
  }
}

/**
 * The jti inside a confirm token, or null.
 *
 * The token's first part is plain base64url JSON, so reading it needs no key.
 * Field `j` is the jti. It holds no assertion and it never throws.
 */
function jtiOf(token: string): string | null {
  try {
    const first = token.split(".")[0];
    if (first === undefined) return null;
    const parsed: unknown = JSON.parse(
      TOKEN_DECODER.decode(fromBase64Url(first)),
    );
    if (typeof parsed !== "object" || parsed === null) return null;
    const jti = (parsed as Record<string, unknown>).j;
    return typeof jti === "string" && jti.length > 0 ? jti : null;
  } catch {
    return null;
  }
}

/**
 * Every confirm key that holds `jti`, or null if the store could not be listed.
 *
 * It matches on the jti and not on today's exact key. Phase 10 changes the key
 * shape, and a check tied to today's shape would go quiet that day and start
 * reporting "nothing written" for ever. It holds no assertion and never throws.
 */
async function confirmKeysHolding(jti: string): Promise<string[] | null> {
  try {
    const listed = await env.CONFIRM_KV.list({ prefix: "confirm:" });
    return listed.keys
      .map((one) => one.name)
      .filter((name) => name.includes(jti))
      .sort();
  } catch {
    return null;
  }
}

describe("confirm token: a one-time confirmation belongs to the user who previewed", () => {
  // This is the proof that the slot leak assertion further down CAN pass. It
  // is the same predicate, on the same tool, for a commit nobody interfered
  // with. If this goes red because the flag did not read as false, the fault
  // is in `readToolResult`, which must give a strict boolean. Fix it there.
  it("control: A's own commit succeeds", async () => {
    const stub = twoUserDavStub();

    const preview = await previewAsA(stub);
    expect(preview, "the fixture failed to preview").not.toBeNull();
    if (preview === null) throw new Error("unreachable");

    const jti = jtiOf(preview.confirmToken);
    expect(jti, "the token's jti could not be read").not.toBeNull();
    if (jti === null) throw new Error("unreachable");

    // A preview alone writes nothing. So the store check below CAN come back
    // empty, which is what the CONFIRM_KV leak assertion needs to be able to do.
    expect(
      await confirmKeysHolding(jti),
      "a preview alone wrote the jti into the store",
    ).toEqual([]);

    const resultA = await toolsFor(USER_A).call("calendar_commit", {
      confirmToken: preview.confirmToken,
      change: preview.change,
    });
    expect(resultA, "the tool is missing or its callback threw").not.toBeNull();
    if (resultA === null) throw new Error("unreachable");

    expect(
      readToolResult(resultA).isError,
      "A's own commit was refused",
    ).toBe(false);

    const writes = stub.observed.filter((one) => one.method === "PUT");
    expect(writes.length, "A's commit did not issue exactly one write").toBe(1);
    expect(writes[0]!.user, "A's write did not carry A's credentials").toBe("A");
    expect(
      writes[0]!.url.startsWith(HOME_A),
      "A's write did not go to a URL under A's home",
    ).toBe(true);

    // And the store check can see a jti that IS there.
    expect(
      (await confirmKeysHolding(jti))?.length,
      "A's own commit did not record A's jti",
    ).toBe(1);
  });

  it("control: B's commit with A's token is refused and writes nothing under A's home", async () => {
    const stub = twoUserDavStub();

    const preview = await previewAsA(stub);
    expect(preview, "the fixture failed to preview").not.toBeNull();
    if (preview === null) throw new Error("unreachable");

    await clearDavCache(env, "caldav");
    const resultB = await toolsFor(USER_B).call("calendar_commit", {
      confirmToken: preview.confirmToken,
      change: preview.change,
    });
    expect(resultB, "the tool is missing or its callback threw").not.toBeNull();
    if (resultB === null) throw new Error("unreachable");

    expect(
      readToolResult(resultB).isError,
      "B's commit with A's token was not refused",
    ).toBe(true);

    expect(
      stub.observed.filter(
        (one) =>
          (one.method === "PUT" || one.method === "DELETE") &&
          one.user === "B" &&
          one.url.startsWith(HOME_A),
      ),
      "a write carrying B's credentials reached a URL under A's home",
    ).toEqual([]);
    expect(
      stub.observed.filter(
        (one) => one.method === "PUT" || one.method === "DELETE",
      ),
      "B's refused commit still issued a write somewhere",
    ).toEqual([]);

    // B was refused for the expected reason. A token that failed to verify is
    // refused before any request is made. B's requests are on the list, so the
    // token verified, B's own home was resolved, and the home-set check is what
    // turned B away.
    expect(
      stub.observed.filter((one) => one.user === "B").length,
      "B was refused before B's home was ever resolved",
    ).toBeGreaterThan(0);

    expect(
      JSON.stringify(resultB),
      "B received text from A's event",
    ).not.toContain(CANARY_SUMMARY_A);
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B's refused commit spent A's one-time confirm slot, so A's own commit was refused: expected true to be false // Object.is equality
  //
  // B is refused today, by the home-set check. But the one-time slot is taken
  // BEFORE that check runs, so B's refused call still uses it up, and A has to
  // preview again. Nothing on this path asks who the token was minted for. A
  // null from either commit returns early, which makes this body pass and the
  // mark go red; both controls above make the same calls and are red whenever
  // one gives null. "control: A's own commit succeeds" uses this very predicate
  // on a commit nobody interfered with, so it is known to be able to pass. When
  // a fix leaves A's slot alone, this test goes red with "Expect test to fail":
  // remove the mark then, on purpose, and leave the body exactly as it is.
  it.fails("B's refused commit cannot spend A's confirm slot", async () => {
    const stub = twoUserDavStub();

    const preview = await previewAsA(stub);
    if (preview === null) return;

    // B's turn. Forget the home A's preview cached, or B would be handed it.
    const beforeB = await attempt(() => clearDavCache(env, "caldav"));
    if (beforeB.refused) return;
    const resultB = await toolsFor(USER_B).call("calendar_commit", {
      confirmToken: preview.confirmToken,
      change: preview.change,
    });

    // A's turn again. Forget B's home the same way.
    const beforeA = await attempt(() => clearDavCache(env, "caldav"));
    if (beforeA.refused) return;
    const resultA = await toolsFor(USER_A).call("calendar_commit", {
      confirmToken: preview.confirmToken,
      change: preview.change,
    });
    if (resultB === null || resultA === null) return;

    expect(
      readToolResult(resultA).isError,
      "LEAK: B's refused commit spent A's one-time confirm slot, so A's own commit was refused",
    ).toBe(false);
  });

  // RECORDED 2026-09-19, run as a plain test before this mark was added:
  //
  //   AssertionError: LEAK: B's refused commit wrote A's jti into CONFIRM_KV: expected [ Array(1) ] to deeply equal []
  //
  // The same flaw, seen from the store. After B's refused commit one key held
  // A's jti, and A had taken no second turn, so only B can have written it. The
  // check matches on the jti and not on today's key shape, so it still means
  // something after that shape changes. "control: A's own commit succeeds"
  // shows the same store check comes back empty after a preview alone. When a
  // fix stops B's call reaching the store, this test goes red with "Expect test
  // to fail": remove the mark then, on purpose, and leave the body as it is.
  it.fails("B's refused commit cannot write A's jti into CONFIRM_KV", async () => {
    const stub = twoUserDavStub();

    const preview = await previewAsA(stub);
    if (preview === null) return;
    const jti = jtiOf(preview.confirmToken);
    if (jti === null) return;

    // B's turn. Forget the home A's preview cached, or B would be handed it.
    const beforeB = await attempt(() => clearDavCache(env, "caldav"));
    if (beforeB.refused) return;
    const resultB = await toolsFor(USER_B).call("calendar_commit", {
      confirmToken: preview.confirmToken,
      change: preview.change,
    });
    if (resultB === null) return;

    // A takes no second turn here. The store is read straight away, so the
    // only caller that can have written A's jti is B.
    const held = await confirmKeysHolding(jti);
    if (held === null) return;

    expect(
      held,
      "LEAK: B's refused commit wrote A's jti into CONFIRM_KV",
    ).toEqual([]);
  });
});
