// Today's four key shapes, one pin per store, written out as literals.
//
// Phase 10 changes every pin in this file on purpose.
//
// That is what the file is for. When a change lands, the pin here goes red, and
// whoever is making the change rewrites it to the new shape with their eyes
// open. A key shape that moved without a pin moving would be a change nobody
// decided.
//
// **Three of the four have moved. The fourth did not, and could not.**
//
// | Pin | State |
// |-----|-------|
// | R2, binding side | moved — a user segment sits between the prefix and the name |
// | R2, presigned ingress | moved — the same segment, same place |
// | `CONFIRM_KV` | moved — the version went to 2 and the user id sits between the prefix and the jti |
// | `DAV_CACHE` | unmoved, by design. The key already held a hash of the Apple ID; the change takes that value off the signed-in principal instead of hashing for itself, and the bytes are the same |
//
// The `DAV_CACHE` row is the odd one and it is worth being clear about why an
// unmoved pin is the right outcome there. A pin goes red when a shape changes.
// This change was made specifically so the shape would NOT change — the
// deployed cache holds live entries under those keys, and a key that moved
// would cost the owner a cold cache nobody had predicted. So the evidence the
// pin gives is the evidence that was wanted: it passed before the change and it
// passes after, byte for byte.
//
// The two R2 pins gained `/[0-9a-f]{64}/` in the pattern and went from two
// asserted segments to three. Neither reads the user id back out of the value
// under test: a pin built from the thing it is pinning moves with it and so
// pins nothing, which is the same reason the prefixes below are typed out
// rather than imported.
//
// The `CONFIRM_KV` pin does compare against a user id — `USER_A.userId`, a
// literal row from the vectors file — and that is the DAV pin's habit rather
// than a departure from the R2 pins'. The difference is where the id comes
// from. The R2 builders generate their own key, so a pin reading the id back
// out of it would move with it; here the caller HANDS the id in, so comparing
// the written key against the literal that was passed is comparing two
// independent things.
//
// **Four older pins already exist, and they stay.** Two are in
// `test/staging.test.ts`, one is in `test/confirm.test.ts`, and one is in
// `test/dav-discovery.test.ts`. They are not edited or deleted by this file or
// by the plan that added it.
//
// **These new pins differ from the older ones in one way: they spell each
// prefix out as a literal.** The older pins build their pattern from the
// exported prefix constant. A pin built from the constant moves when the
// constant moves, and so pins nothing: rename the prefix and the old pin still
// passes. Here the prefix is typed out, so the prefix itself is pinned too. For
// that reason this file imports neither exported prefix constant.
//
// **The DAV pin also checks the user id vectors against production code, with
// no hashing in the test (D-12).** It compares the key the production code
// writes against the literal user id from the vectors file. That comparison now
// holds for ANY address, and the caveat that used to sit here is gone.
// `src/dav/discovery.ts` no longer hashes anything: it takes the id off the
// signed-in principal, and that id is `userIdOf`'s output — the one function in
// the repository that turns an address into a user id (D-14). So the pin is
// comparing the vectors file against the very rule the vectors file specifies,
// rather than against a second hash that happened to agree for an address
// needing no normalising.
//
// The recording store is used for the two KV pins ONLY, because the real
// binding cannot show which key a call wrote first. The cross-user tests use
// the real bindings.
//
// Nothing here opens a network connection and nothing authenticates against the
// real Apple ID (D-09). The one DAV conversation goes to a stubbed `fetch`.

import { afterEach, describe, expect, it, vi } from "vitest";
import { reserveConfirmation } from "../src/confirm";
import { resolveDavAccount } from "../src/dav/discovery";
import { createDavFetch } from "../src/dav/transport";
import type { Env } from "../src/env";
import { presignedKeyFor } from "../src/staging/presign";
import { stagingKeyFor } from "../src/staging/r2";
import { HOME_A, HOME_B, twoUserDavStub } from "./fixtures/two-user-dav";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";
import { entryEnv } from "./fixtures/bound-secrets";
import type { TestUser } from "./fixtures/two-users";

/** A fixed instant, so the clock segment of a key can be compared exactly. */
const NOW = 1776000000000;

// ---------------------------------------------------------------------------
// A recording KV, copied from `test/dav-discovery.test.ts`
// ---------------------------------------------------------------------------

interface RecordedPut {
  key: string;
  value: string;
  options?: KVNamespacePutOptions;
}

interface FakeKv {
  binding: KVNamespace;
  puts: RecordedPut[];
  deletes: string[];
  gets: string[];
}

/** A KV binding this suite can see inside: every key it was asked about. */
function fakeKv(): FakeKv {
  const store = new Map<string, string>();
  const state: Partial<FakeKv> = { puts: [], deletes: [], gets: [] };

  const binding = {
    async get(key: string, type?: unknown): Promise<unknown> {
      state.gets!.push(key);
      const raw = store.get(key);
      if (raw === undefined) return null;
      return type === "json" ? JSON.parse(raw) : raw;
    },
    async put(
      key: string,
      value: string,
      putOptions?: KVNamespacePutOptions,
    ): Promise<void> {
      state.puts!.push({ key, value, options: putOptions });
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
      state.deletes!.push(key);
      store.delete(key);
    },
    async list(): Promise<unknown> {
      return {
        keys: [...store.keys()].map((name) => ({ name })),
        list_complete: true,
      };
    },
    async getWithMetadata(): Promise<unknown> {
      return { value: null, metadata: null };
    },
  };

  state.binding = binding as unknown as KVNamespace;
  return state as FakeKv;
}

/** Resolve CalDAV for `user` into a recording store. Gives the first key written. */
async function davKeyWrittenFor(
  user: TestUser,
  expectedHome: string,
): Promise<string> {
  const kv = fakeKv();
  const scoped: Env = { ...entryEnv(), DAV_CACHE: kv.binding };
  // One principal for this user, for the cache key and for the login alike.
  const who = testPrincipal(user);

  vi.stubGlobal("fetch", twoUserDavStub().fetch);
  const resolved = await resolveDavAccount(
    scoped,
    await who,
    createDavFetch(who),
    "caldav",
  );

  expect(resolved.cacheHit, "the resolve was not a cold one").toBe(false);
  expect(resolved.homeUrl, `${user.label} did not resolve to their own home`).toBe(
    expectedHome,
  );
  expect(kv.puts.length, "the resolve wrote nothing to the store").toBe(1);
  return kv.puts[0]!.key;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("key shapes today, one pin per store", () => {
  it("R2, binding side: staging/{user id}/{16 hex}-{name}-{ms}", () => {
    const key = stagingKeyFor(USER_A.userId, "Resume-2026.pdf", NOW);

    expect(key, "no key was built").not.toBeNull();
    expect(String(key)).toMatch(
      /^staging\/[0-9a-f]{64}\/[0-9a-f]{16}-Resume-2026\.pdf-1776000000000$/,
    );
    // Two separators now: the one after the prefix and the one after the user
    // segment. Phase 10 added the second, which is the change this pin records.
    // The middle segment is asserted as 64 hex by the pattern above rather than
    // compared against `USER_A.userId`, because a pin that read the id back out
    // of the value under test would move with it.
    expect(
      String(key).split("/").length,
      "the key holds no user segment between the prefix and the name",
    ).toBe(3);
  });

  it("R2, presigned ingress: staging/{user id}/upload-{16 hex}-{ms}", () => {
    const key = presignedKeyFor(USER_A.userId, NOW);

    expect(key, "no key was built").not.toBeNull();
    expect(String(key)).toMatch(
      /^staging\/[0-9a-f]{64}\/upload-[0-9a-f]{16}-1776000000000$/,
    );
    expect(
      String(key).split("/").length,
      "the key holds no user segment between the prefix and the name",
    ).toBe(3);
  });

  it("CONFIRM_KV: confirm:v3:{user id}:{jti}", async () => {
    const kv = fakeKv();
    const jti = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const soon = Math.floor(Date.now() / 1000) + 300;

    await reserveConfirmation(kv.binding, USER_A.userId, jti, soon);

    expect(kv.puts.length, "the reservation wrote nothing").toBe(1);
    // The literal prefix at version 3, then the user id the caller passed in,
    // then the jti. The prefix is typed out rather than imported so the prefix
    // itself is pinned; the user id is the literal vectors row, which is a
    // different thing from the key it is being compared against.
    expect(kv.puts[0]!.key).toBe(
      "confirm:v3:" + USER_A.userId + ":aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    );
    // Three colon-separated parts after the scheme word, and the middle one is
    // 64 hex. A key with no user in it fails this even if the prefix moved.
    expect(kv.puts[0]!.key).toMatch(
      /^confirm:v3:[0-9a-f]{64}:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee$/,
    );
  });

  it("DAV_CACHE: dav:v2:{user id}:caldav, checked against both vector rows", async () => {
    const keyOfA = await davKeyWrittenFor(USER_A, HOME_A);
    const keyOfB = await davKeyWrittenFor(USER_B, HOME_B);

    // The user ids are literal rows from the vectors file. Nothing is hashed
    // here. Production code did the hashing, and these two lines are what hold
    // it to the spec.
    expect(keyOfA).toBe("dav:v2:" + USER_A.userId + ":caldav");
    expect(keyOfB).toBe("dav:v2:" + USER_B.userId + ":caldav");
    expect(keyOfA, "A and B were given one cache key").not.toBe(keyOfB);

    // The shape, as well as the value: 64 hex and nothing else in the middle.
    expect(keyOfA).toMatch(/^dav:v2:[0-9a-f]{64}:caldav$/);
    expect(keyOfB).toMatch(/^dav:v2:[0-9a-f]{64}:caldav$/);
  });
});
