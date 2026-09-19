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
// **Nothing here is faked.** `env.ATTACHMENT_STAGING` is the pool's real local
// bucket, the same one `test/staging.test.ts` uses.
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
import { beforeEach, describe, expect, it } from "vitest";
import {
  STAGED_ID_TTL_MS,
  decodeStagedId,
  encodeStagedId,
} from "../src/mail/ids";
import {
  releaseStagedAttachments,
  resolveStagedAttachments,
  stageInlineBytes,
} from "../src/mcp/tools/mail";
import { USER_A, USER_B, attempt, envFor } from "./fixtures/two-users";

const DECODER = new TextDecoder();

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

/** A bucket with nothing in it, before every case. */
beforeEach(async () => {
  for (const key of await everyStagedKey()) {
    await env.ATTACHMENT_STAGING.delete(key);
  }
  expect(await everyStagedKey()).toEqual([]);
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
