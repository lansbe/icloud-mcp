// Today's four key shapes, one pin per store, written out as literals.
//
// Phase 10 changes every pin in this file on purpose.
//
// That is what the file is for. The two R2 keys and the confirm key hold no
// user segment today, and Phase 10 adds one. The DAV key already holds a hash
// of the Apple ID, and Phase 10 takes that hash from the signed-in user
// instead. When those changes land, the pins here go red, and whoever is making
// the change rewrites each pin to the new shape with their eyes open. A key
// shape that moved without a pin moving would be a change nobody decided.
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
// writes against the literal user id from the vectors file. That works because
// an address that is already trimmed and lowercase hashes today to exactly the
// ISO-05 user id. Today `src/dav/discovery.ts` hashes the raw Apple ID, not a
// normalised one, so this holds only for an address that needs no
// normalising. Both test users have one.
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
import { USER_A, USER_B, envFor, testPrincipal } from "./fixtures/two-users";
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
  const scoped: Env = { ...envFor(user), DAV_CACHE: kv.binding };
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
  it("R2, binding side: staging/{16 hex}-{name}-{ms}", () => {
    const key = stagingKeyFor(USER_A.userId, "Resume-2026.pdf", NOW);

    expect(key, "no key was built").not.toBeNull();
    expect(String(key)).toMatch(
      /^staging\/[0-9a-f]{16}-Resume-2026\.pdf-1776000000000$/,
    );
    // One separator, the one after the prefix. A user segment would add a
    // second, and that is the change Phase 10 makes.
    expect(String(key).split("/").length, "the key holds a second segment").toBe(
      2,
    );
  });

  it("R2, presigned ingress: staging/upload-{16 hex}-{ms}", () => {
    const key = presignedKeyFor(USER_A.userId, NOW);

    expect(key, "no key was built").not.toBeNull();
    expect(String(key)).toMatch(/^staging\/upload-[0-9a-f]{16}-1776000000000$/);
    expect(String(key).split("/").length, "the key holds a second segment").toBe(
      2,
    );
  });

  it("CONFIRM_KV: confirm:v1:{jti}", async () => {
    const kv = fakeKv();
    const jti = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const soon = Math.floor(Date.now() / 1000) + 300;

    await reserveConfirmation(kv.binding, jti, soon);

    expect(kv.puts.length, "the reservation wrote nothing").toBe(1);
    // The literal prefix, then the jti, and nothing between them. There is no
    // user in this key today.
    expect(kv.puts[0]!.key).toBe(
      "confirm:v1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    );
  });

  it("DAV_CACHE: dav:v1:{user id}:caldav, checked against both vector rows", async () => {
    const keyOfA = await davKeyWrittenFor(USER_A, HOME_A);
    const keyOfB = await davKeyWrittenFor(USER_B, HOME_B);

    // The user ids are literal rows from the vectors file. Nothing is hashed
    // here. Production code did the hashing, and these two lines are what hold
    // it to the spec.
    expect(keyOfA).toBe("dav:v1:" + USER_A.userId + ":caldav");
    expect(keyOfB).toBe("dav:v1:" + USER_B.userId + ":caldav");
    expect(keyOfA, "A and B were given one cache key").not.toBe(keyOfB);

    // The shape, as well as the value: 64 hex and nothing else in the middle.
    expect(keyOfA).toMatch(/^dav:v1:[0-9a-f]{64}:caldav$/);
    expect(keyOfB).toMatch(/^dav:v1:[0-9a-f]{64}:caldav$/);
  });
});
