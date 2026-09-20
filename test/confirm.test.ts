// Direct coverage of the protocol-neutral confirmation module.
//
// This suite drives `src/confirm.ts` directly. The DAV suites cover the same
// code THROUGH the tool boundary — with a real payload, a real change and a
// real write behind it — and that is the coverage which proves the capability
// works. This one proves the primitive is sound in isolation, so the second
// protocol tree that reuses it (V2-MAIL-02's mail delete) inherits assertions
// about the primitive rather than assertions about calendars.
//
// The last describe block is the join between the two. It asserts the
// PARAMETERISED REFUSAL: the neutral module throws a neutral error and each
// protocol tree translates it into its own class at its own boundary. A module
// that started leaking `ConfirmationInvalidError` past that boundary would pass
// every test above it and surface to a caller as `connection_failed` — a
// network diagnosis for a refused confirmation.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONFIRM_KEY_PREFIX,
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  ConfirmationInvalidError,
  canonicalChange,
  changeHashMatches,
  changeHashOf,
  importConfirmationKey,
  mintConfirmation,
  reserveConfirmation,
  verifyConfirmation,
} from "../src/confirm";
import type { ConfirmPayload, NormalizedChange } from "../src/confirm";
import { DavConfirmationError, davToErrorCategory } from "../src/dav/errors";
import { decodeEventId, encodeEventId } from "../src/dav/ids";
import { TOKEN_ENCODER, fromBase64Url, toBase64Url } from "../src/tokens";

const SECRET = "a-test-signing-key-not-real";
const OTHER_SECRET = "a-different-test-signing-key-not-real";

/**
 * The signed-in user every confirmation in this suite is minted for.
 *
 * 64 lowercase hex, the shape `userIdOf` produces, though nothing in
 * `src/confirm.ts` asserts that shape — the module compares the field against
 * the id it was handed and cares about nothing else. A fixed literal rather
 * than a computed hash, so no case here depends on what any address hashes to.
 */
const USER = "1111111111111111111111111111111111111111111111111111111111111111";

/**
 * A DIFFERENT signed-in user. Same shape, and nothing else in common.
 *
 * Used only where a case needs a confirmation minted for somebody other than
 * the caller presenting it — which is the cause the token's user field exists
 * to refuse.
 */
const OTHER_USER =
  "2222222222222222222222222222222222222222222222222222222222222222";

/**
 * Freeze the clock at a whole second.
 *
 * `Date.now` is spied rather than the whole timer set faked, because the module
 * reads exactly that and nothing else — and a full fake-timer install would
 * also intercept the machinery the WebCrypto promises resolve through, for no
 * gain the boundary cases need.
 */
function freezeClockAt(epochSeconds: number): void {
  vi.spyOn(Date, "now").mockReturnValue(epochSeconds * 1000);
}

afterEach(() => {
  vi.restoreAllMocks();
});

/** A whole second comfortably in the future, so no case races the clock. */
function soon(offsetSeconds = 300): number {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

function payload(overrides: Partial<ConfirmPayload> = {}): ConfirmPayload {
  return {
    v: CONFIRM_VERSION,
    k: "update",
    j: "11111111-2222-3333-4444-555555555555",
    c: "https://p00-caldav.icloud.example/1234567890/calendars/work/",
    o: "https://p00-caldav.icloud.example/1234567890/calendars/work/abc.ics",
    r: null,
    e: '"etag-observed-by-the-preview"',
    // The revision the preview observed on the stored resource. A fact about
    // the RESOURCE, on the ETag's own footing — not part of the change the user
    // approved, which is what `h` binds.
    s: 3,
    h: "cGxhY2Vob2xkZXItY2hhbmdlLWhhc2g",
    x: soon(),
    // The user this confirmation was minted for. One edit here covers every
    // case in the file that builds on this helper, which is all twenty of
    // them — and a case that wanted a DIFFERENT user overrides it, so a
    // mismatch has to be written down on purpose rather than reached by
    // forgetting a field.
    u: USER,
    ...overrides,
  };
}

/** Flip one character of a base64url part to a different alphabet member. */
function flip(part: string, index: number): string {
  const replacement = part[index] === "A" ? "B" : "A";
  return part.slice(0, index) + replacement + part.slice(index + 1);
}

/**
 * Seal an arbitrary payload part with a real key.
 *
 * The suite has to be able to forge a VALID seal over an INVALID payload, or
 * the "payload is not JSON" branch is unreachable — any tampering that reaches
 * it would fail the seal check first and never get there. This is the test
 * standing in for a holder of the signing key, which is exactly what it is.
 */
async function sealAs(payloadPart: string, secret: string): Promise<string> {
  const key = await importConfirmationKey(secret);
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    TOKEN_ENCODER.encode(payloadPart),
  );
  return `${payloadPart}.${toBase64Url(new Uint8Array(mac))}`;
}

function change(overrides: Partial<NormalizedChange> = {}): NormalizedChange {
  return {
    kind: "update",
    scope: null,
    summary: "Coffee with Dana",
    startLocal: "2026-09-01T09:00:00",
    startTzid: "America/Chicago",
    endLocal: "2026-09-01T09:30:00",
    endTzid: "America/Chicago",
    allDay: false,
    location: "Ludlow",
    description: null,
    attendees: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// A recording KV, on `test/dav-discovery.test.ts`'s precedent
// ---------------------------------------------------------------------------

interface RecordedPut {
  key: string;
  value: string;
  options?: KVNamespacePutOptions;
}

interface FakeKv {
  binding: KVNamespace;
  puts: RecordedPut[];
  gets: string[];
}

/**
 * A KV binding this suite can see inside.
 *
 * The two properties whose failure is SILENT are the TTL actually passed and a
 * `put` that rejects, and neither is reachable through the real binding: the
 * TTL is not readable back, and Miniflare's namespace does not fail on demand.
 * Hence a recording fake, on the shape `test/dav-discovery.test.ts` already
 * established for exactly this pair of gaps.
 */
function fakeKv(options: { putRejects?: boolean } = {}): FakeKv {
  const store = new Map<string, string>();
  const state: Partial<FakeKv> = { puts: [], gets: [] };

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
      if (options.putRejects) throw new Error("kv write refused");
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
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

// ===========================================================================
// The wire format
// ===========================================================================

describe("the confirmation token's wire format", () => {
  it("is two base64url parts joined by exactly one separator", async () => {
    const token = await mintConfirmation(payload(), SECRET);

    // Exactly one separator, and neither half carries one. Splitting is the
    // first thing the verifier does, so a second separator anywhere would make
    // "which two parts" a question rather than an answer.
    const parts = token.split(".");
    expect(parts).toHaveLength(2);
    expect(parts[0].length).toBeGreaterThan(0);
    expect(parts[1].length).toBeGreaterThan(0);
    expect(parts[0]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(parts[1]).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("cannot be decoded by the shared codec, because the separator is outside its alphabet", async () => {
    const token = await mintConfirmation(payload(), SECRET);

    // The structural half of the cross-use guarantee, read from the SHIPPED
    // codec rather than restated as a character class here. `fromBase64Url`
    // checks its alphabet before the runtime's base64 primitive, and the
    // separator is not a member — so this is the REASON an event id and a
    // confirmation cannot be swapped, not merely evidence that they are not.
    expect(() => fromBase64Url(token)).toThrow();
  });

  it("round-trips every field of the payload", async () => {
    const original = payload();
    const token = await mintConfirmation(original, SECRET);

    expect(await verifyConfirmation(token, SECRET, USER)).toEqual(original);
  });

  it("round-trips a create's null etag and an occurrence's recurrence id", async () => {
    // `e: null` is the create case and `r: string` the recurring one. Both are
    // the shapes most likely to be normalised away by a careless codec, and
    // `e` is the one whose loss is silent — an empty string there turns a
    // conditional write into an unconditional one.
    const created = payload({ k: "create", e: null });
    const occurrence = payload({ r: "2026-09-01T09:00:00" });

    expect(
      await verifyConfirmation(
        await mintConfirmation(created, SECRET),
        SECRET,
        USER,
      ),
    ).toEqual(created);
    expect(
      await verifyConfirmation(
        await mintConfirmation(occurrence, SECRET),
        SECRET,
        USER,
      ),
    ).toEqual(occurrence);
  });
});

// ===========================================================================
// Forgery and tampering
// ===========================================================================

describe("the confirmation token cannot be forged or tampered with", () => {
  it("refuses a token whose payload part was altered by one character", async () => {
    const token = await mintConfirmation(payload(), SECRET);
    const [payloadPart, macPart] = token.split(".");

    await expect(
      verifyConfirmation(`${flip(payloadPart, 4)}.${macPart}`, SECRET, USER),
    ).rejects.toBeInstanceOf(ConfirmationInvalidError);
  });

  it("refuses a token whose MAC part was altered by one character", async () => {
    const token = await mintConfirmation(payload(), SECRET);
    const [payloadPart, macPart] = token.split(".");

    await expect(
      verifyConfirmation(`${payloadPart}.${flip(macPart, 4)}`, SECRET, USER),
    ).rejects.toBeInstanceOf(ConfirmationInvalidError);
  });

  it("refuses a token minted under a different secret", async () => {
    const token = await mintConfirmation(payload(), SECRET);

    await expect(
      verifyConfirmation(token, OTHER_SECRET, USER),
    ).rejects.toBeInstanceOf(ConfirmationInvalidError);
  });

  it.each([
    ["no separator at all", "aGVsbG8"],
    ["two separators", "aGVsbG8.aGVsbG8.aGVsbG8"],
    ["an empty payload part", ".aGVsbG8"],
    ["an empty MAC part", "aGVsbG8."],
    ["the empty string", ""],
    ["a separator and nothing else", "."],
    ["a MAC part outside the alphabet", "aGVsbG8.!!!!"],
  ])("refuses a token with %s", async (_label, token) => {
    await expect(verifyConfirmation(token, SECRET, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it("refuses a well-formed token carrying a version this build does not know", async () => {
    // The hedge the `v` field exists to buy: a future format change is
    // DETECTABLE rather than silently misread as the current shape.
    const token = await mintConfirmation(
      payload({ v: 99 as unknown as typeof CONFIRM_VERSION }),
      SECRET,
    );

    await expect(verifyConfirmation(token, SECRET, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it("refuses a version 1 token outright, whether or not it names a user", async () => {
    // Version 1 is the format this build REPLACED, and the claim being made is
    // sharper than "an old token is refused": a v1 token must never be read as
    // a v2 whose user field happens to be missing, because a confirmation
    // nobody can say belongs to anyone is exactly the thing the field was
    // added to stop.
    //
    // Two tokens, because the realistic one is refused by TWO independent
    // checks and a case resting on whichever runs first would prove less than
    // it looks:
    //
    //   the real v1 shape — ten fields, no user at all. The payload predicate
    //   refuses it on the missing field, and the version check would too.
    //   a v1 that DOES name a user — eleven fields with the version set back.
    //   The predicate passes it, so only the strict version comparison can
    //   refuse it, which is the claim on its own.
    //
    // Sealed by hand rather than minted, because the minter takes a payload of
    // the CURRENT type and a v1 payload is not one.
    const withoutUser: Record<string, unknown> = { ...payload() };
    delete withoutUser.u;
    withoutUser.v = 1;
    const withUser: Record<string, unknown> = { ...payload(), v: 1 };

    for (const stale of [withoutUser, withUser]) {
      const token = await sealAs(
        toBase64Url(TOKEN_ENCODER.encode(JSON.stringify(stale))),
        SECRET,
      );

      await expect(
        verifyConfirmation(token, SECRET, USER),
      ).rejects.toBeInstanceOf(ConfirmationInvalidError);
    }
  });

  it("refuses a token minted for a different user, presented by this one", async () => {
    // The whole point of the field, asserted on its own rather than only
    // inside the table below. The seal verifies, the version is current, the
    // lifetime has not run out and the payload is well formed — the ONLY thing
    // wrong with this token is who it was minted for.
    const token = await mintConfirmation(payload({ u: OTHER_USER }), SECRET);

    await expect(verifyConfirmation(token, SECRET, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
    // And the same token still works for the user it WAS minted for, which is
    // the half that stops the check passing by refusing everybody.
    expect(await verifyConfirmation(token, SECRET, OTHER_USER)).toMatchObject({
      u: OTHER_USER,
    });
  });
});

// ===========================================================================
// The absolute expiry
// ===========================================================================

describe("the confirmation dies at the second its payload names", () => {
  it("verifies a token with one whole second still to run", async () => {
    const now = 1_800_000_000;
    freezeClockAt(now);
    const token = await mintConfirmation(payload({ x: now + 1 }), SECRET);

    expect(await verifyConfirmation(token, SECRET, USER)).toMatchObject({
      x: now + 1,
    });
  });

  it("refuses a token at exactly its expiry second", async () => {
    const now = 1_800_000_000;
    freezeClockAt(now);
    const token = await mintConfirmation(payload({ x: now }), SECRET);

    // `>=` means expired: the boundary second belongs to the dead side, so a
    // token can never be spent in the second it names.
    await expect(verifyConfirmation(token, SECRET, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it("refuses a token one second past its expiry", async () => {
    const now = 1_800_000_000;
    freezeClockAt(now);
    const token = await mintConfirmation(payload({ x: now - 1 }), SECRET);

    await expect(verifyConfirmation(token, SECRET, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it("states a lifetime inside the 2-to-5-minute band the ROADMAP fixed", () => {
    expect(CONFIRM_TTL_SECONDS).toBeGreaterThanOrEqual(120);
    expect(CONFIRM_TTL_SECONDS).toBeLessThanOrEqual(300);
  });
});

// ===========================================================================
// Fail-closed
// ===========================================================================

describe("an unusable signing secret fails closed on BOTH paths", () => {
  const unusable: (string | undefined)[] = [undefined, "", "   "];

  it.each(unusable)("refuses to MINT under %o", async (secret) => {
    await expect(mintConfirmation(payload(), secret)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it.each(unusable)("refuses to VERIFY under %o", async (secret) => {
    // Including a token minted while the secret WAS present: a server that
    // loses its key must refuse everything, not accept what it signed earlier.
    const token = await mintConfirmation(payload(), SECRET);

    await expect(verifyConfirmation(token, secret, USER)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it.each(unusable)("refuses to IMPORT a key from %o", async (secret) => {
    await expect(importConfirmationKey(secret)).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });
});

// ===========================================================================
// The key is write-only
// ===========================================================================

describe("the HMAC key is write-only", () => {
  it("cannot be exported, so it cannot be stringified into an error or a response", async () => {
    const key = await importConfirmationKey(SECRET);

    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
  });
});

// ===========================================================================
// The refusal explains nothing
// ===========================================================================

describe("every refusal on the verify path answers identically", () => {
  /**
   * The seven causes `verifyConfirmation` can raise, LISTED BY NAME.
   *
   * Named rather than generated, on the same non-vacuity discipline
   * `test/dav-tools.test.ts`'s stranger-authored walk uses: a helper that
   * quietly stopped producing one of these would otherwise make the loop below
   * run over six and still pass. The count assertion is what says so.
   *
   * The seventh is the wrong user, and it is on this list rather than only in
   * a case of its own for a reason the others share: a refusal that named its
   * cause would tell whoever probed the format which guess was well formed.
   * The user check is the one most worth proving that about, because it is the
   * one an attacker is actively guessing at.
   *
   * These are the seven the NEUTRAL module owns. The DAV commit handler's own
   * list — which adds a change that does not match and one already spent, and
   * folds several of these together — is a different list reaching the same
   * answer; `reserveConfirmation` is asserted against that answer separately.
   */
  async function sevenCauses(): Promise<[string, Promise<unknown>][]> {
    const now = 1_800_000_000;
    freezeClockAt(now);
    const token = await mintConfirmation(payload(), SECRET);
    const [payloadPart, macPart] = token.split(".");

    return [
      ["an unusable signing key", verifyConfirmation(token, undefined, USER)],
      [
        "a token that is not two encoded parts",
        verifyConfirmation("nodot", SECRET, USER),
      ],
      [
        "a seal that does not verify",
        verifyConfirmation(`${payloadPart}.${flip(macPart, 2)}`, SECRET, USER),
      ],
      [
        "a payload that is not JSON",
        verifyConfirmation(
          await sealAs(toBase64Url(TOKEN_ENCODER.encode("not json")), SECRET),
          SECRET,
          USER,
        ),
      ],
      [
        "a version this build does not know",
        verifyConfirmation(
          await mintConfirmation(
            payload({ v: 99 as unknown as typeof CONFIRM_VERSION }),
            SECRET,
          ),
          SECRET,
          USER,
        ),
      ],
      [
        "a lifetime that has run out",
        verifyConfirmation(
          await mintConfirmation(payload({ x: now - 1 }), SECRET),
          SECRET,
          USER,
        ),
      ],
      [
        "a confirmation minted for a different user",
        verifyConfirmation(
          await mintConfirmation(payload({ u: OTHER_USER }), SECRET),
          SECRET,
          USER,
        ),
      ],
    ];
  }

  it("exercises exactly the seven causes that exist, named one by one", async () => {
    const causes = await causeResults();

    expect(causes.map(([label]) => label)).toEqual([
      "an unusable signing key",
      "a token that is not two encoded parts",
      "a seal that does not verify",
      "a payload that is not JSON",
      "a version this build does not know",
      "a lifetime that has run out",
      "a confirmation minted for a different user",
    ]);
    // Every one of them actually threw. A cause that resolved instead would be
    // a branch this suite believes it covers and does not.
    for (const [, err] of causes) {
      expect(err).toBeInstanceOf(ConfirmationInvalidError);
    }
  });

  it("gives one message, one name and one property set across all seven", async () => {
    const causes = await causeResults();
    const errors = causes.map(([, err]) => err as Error);

    expect(new Set(errors.map((err) => err.message)).size).toBe(1);
    expect(new Set(errors.map((err) => err.name)).size).toBe(1);
    // The one that catches a well-meaning future edit adding a `cause` or a
    // `reason` field to a single branch.
    expect(
      new Set(errors.map((err) => JSON.stringify(Object.keys(err)))).size,
    ).toBe(1);
  });

  async function causeResults(): Promise<[string, unknown][]> {
    const causes = await sevenCauses();
    expect(causes).toHaveLength(7);

    const settled: [string, unknown][] = [];
    for (const [label, attempt] of causes) {
      settled.push([
        label,
        await attempt.then(() => null).catch((err: unknown) => err),
      ]);
    }
    return settled;
  }

  it("names nothing about the check that failed", async () => {
    const err = (await verifyConfirmation("nodot", SECRET, USER).catch(
      (caught: unknown) => caught,
    )) as Error;

    for (const forbidden of [
      "signature",
      "expiry",
      "expired",
      "hash",
      "version",
      "base64",
      "json",
      "separator",
      "secret",
    ]) {
      expect(err.message.toLowerCase()).not.toContain(forbidden);
    }
  });
});

// ===========================================================================
// The canonical change
// ===========================================================================

describe("the canonical change is stable under everything that is not a change", () => {
  it("hashes identically regardless of the caller's key insertion order", async () => {
    // The literal reason `canonicalChange` exists. `JSON.stringify` over a
    // caller-supplied object follows INSERTION order, so the same requested
    // change would hash differently at preview and at commit purely because
    // two call sites built their object in a different sequence.
    const first: NormalizedChange = {
      kind: "update",
      scope: null,
      summary: "Coffee with Dana",
      startLocal: "2026-09-01T09:00:00",
      startTzid: "America/Chicago",
      endLocal: "2026-09-01T09:30:00",
      endTzid: "America/Chicago",
      allDay: false,
      location: "Ludlow",
      description: null,
      attendees: [],
    };
    const second: NormalizedChange = {
      attendees: [],
      description: null,
      location: "Ludlow",
      allDay: false,
      endTzid: "America/Chicago",
      endLocal: "2026-09-01T09:30:00",
      startTzid: "America/Chicago",
      startLocal: "2026-09-01T09:00:00",
      summary: "Coffee with Dana",
      scope: null,
      kind: "update",
    };

    expect(JSON.stringify(first)).not.toBe(JSON.stringify(second));
    expect(await changeHashOf(first)).toBe(await changeHashOf(second));
  });

  it("hashes identically when the same attendees arrive in a different order", async () => {
    const ascending = change({
      attendees: [
        { email: "ana@example.invalid", name: "Ana" },
        { email: "bo@example.invalid", name: "Bo" },
        { email: "cy@example.invalid", name: "Cy" },
      ],
    });
    const shuffled = change({
      attendees: [
        { email: "cy@example.invalid", name: "Cy" },
        { email: "ana@example.invalid", name: "Ana" },
        { email: "bo@example.invalid", name: "Bo" },
      ],
    });

    expect(await changeHashOf(ascending)).toBe(await changeHashOf(shuffled));
  });

  it("hashes identically when an address differs only in case", async () => {
    const lower = change({
      attendees: [{ email: "ana@example.invalid", name: "Ana" }],
    });
    const upper = change({
      attendees: [{ email: "ANA@Example.Invalid", name: "Ana" }],
    });

    expect(await changeHashOf(lower)).toBe(await changeHashOf(upper));
  });

  it("hashes an absent optional field and an explicit null the same", async () => {
    // Normalisation happens BEFORE hashing, so the caller cannot move the hash
    // by omitting a key rather than passing null for it.
    const explicit = change({ description: null });
    const absent = { ...change() } as Record<string, unknown>;
    delete absent.description;

    expect(await changeHashOf(absent as unknown as NormalizedChange)).toBe(
      await changeHashOf(explicit),
    );
  });
});

describe("the canonical change differs on every field it covers", () => {
  // A loop rather than a case per field, so a field added to
  // `NormalizedChange` later without a mutation here shows up as a GAP in the
  // coverage assertion below rather than as silently uncovered surface.
  const mutations: Record<string, Partial<NormalizedChange>> = {
    kind: { kind: "delete" },
    scope: { scope: "this-and-future" },
    summary: { summary: "Coffee with Dana, moved" },
    startLocal: { startLocal: "2026-09-01T10:00:00" },
    startTzid: { startTzid: "America/New_York" },
    endLocal: { endLocal: "2026-09-01T10:30:00" },
    endTzid: { endTzid: "America/New_York" },
    allDay: { allDay: true },
    location: { location: "Somewhere else" },
    description: { description: "Bring the deck" },
    attendees: {
      attendees: [{ email: "ana@example.invalid", name: "Ana" }],
    },
  };

  it("covers every field of a canonical NormalizedChange, with none left out", () => {
    expect(Object.keys(mutations).sort()).toEqual(Object.keys(change()).sort());
  });

  it.each(Object.keys(mutations))(
    "changes the canonical hash when %s changes",
    async (field) => {
      expect(await changeHashOf(change(mutations[field]))).not.toBe(
        await changeHashOf(change()),
      );
    },
  );
});

describe("the canonical change makes two deliberate choices visible", () => {
  it("collapses duplicate addresses FIRST-WINS, keeping the earlier name", async () => {
    const duplicated = change({
      attendees: [
        { email: "ana@example.invalid", name: "Ana Ramirez" },
        { email: "ANA@example.invalid", name: "A. Ramirez" },
      ],
    });
    const single = change({
      attendees: [{ email: "ana@example.invalid", name: "Ana Ramirez" }],
    });

    // The collapsed count is the number CALW-08 reports, because that is how
    // many people are actually told.
    const attendees = JSON.parse(canonicalChange(duplicated)).at(
      -1,
    ) as string[][];
    expect(attendees).toHaveLength(1);
    expect(attendees[0][1]).toBe("Ana Ramirez");
    expect(await changeHashOf(duplicated)).toBe(await changeHashOf(single));
  });

  it("applies NO Unicode normalisation, so NFC and NFD hash differently", async () => {
    // Pinning the decision so a later "fix" goes red. Normalising a person's
    // own name is a repair, and this project refuses repairs on user-authored
    // text as firmly as on stranger-authored text.
    // Written as escapes rather than as literals: the two spellings are
    // indistinguishable in an editor, so a copy-paste would silently leave
    // this case comparing a string with itself.
    const composed = "Ren\u00E9"; // NFC: e-acute as one code point
    const decomposed = "Rene\u0301"; // NFD: e followed by combining acute
    expect(composed).not.toBe(decomposed);
    expect(composed.normalize("NFD")).toBe(decomposed);

    const nfc = change({
      attendees: [{ email: "ana@example.invalid", name: composed }],
    });
    const nfd = change({
      attendees: [{ email: "ana@example.invalid", name: decomposed }],
    });

    expect(await changeHashOf(nfc)).not.toBe(await changeHashOf(nfd));
  });
});

describe("comparing two canonical change hashes", () => {
  it("accepts two hashes of the same change", async () => {
    const hash = await changeHashOf(change());

    expect(await changeHashMatches(hash, hash)).toBe(true);
  });

  it("refuses two hashes of different changes", async () => {
    const a = await changeHashOf(change());
    const b = await changeHashOf(change({ summary: "Something else" }));

    expect(await changeHashMatches(a, b)).toBe(false);
  });

  it("reaches the comparison even for operands of unequal length", async () => {
    // The reason `secretMatches` digests first: the runtime primitive THROWS on
    // inputs of unequal length, and a throw that happens only for the wrong
    // length is itself an oracle. Digesting both sides makes both operands 32
    // bytes, so the comparison is reached unconditionally.
    await expect(
      changeHashMatches(await changeHashOf(change()), "x"),
    ).resolves.toBe(false);
    await expect(changeHashMatches("", "xx")).resolves.toBe(false);
  });
});

// ===========================================================================
// The single-use reservation
// ===========================================================================

describe("the single-use reservation", () => {
  it("succeeds once and refuses every time after", async () => {
    const kv = fakeKv();
    const jti = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    await expect(
      reserveConfirmation(kv.binding, USER, jti, soon()),
    ).resolves.toBeUndefined();
    await expect(
      reserveConfirmation(kv.binding, USER, jti, soon()),
    ).rejects.toBeInstanceOf(ConfirmationInvalidError);

    // Exactly one write. A second `put` would mean the refusal happened after
    // the record had been rewritten, which would extend the record's own life.
    expect(kv.puts).toHaveLength(1);
    expect(kv.puts[0].key).toBe(`${CONFIRM_KEY_PREFIX}${USER}:${jti}`);
  });

  it("reads the key before it writes, so a spent token costs no DAV request", async () => {
    const kv = fakeKv();
    const jti = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeef";

    await reserveConfirmation(kv.binding, USER, jti, soon());

    expect(kv.gets).toEqual([`${CONFIRM_KEY_PREFIX}${USER}:${jti}`]);
  });

  it("writes the record BEFORE returning, so a caller that then fails has spent the token", async () => {
    const kv = fakeKv();

    await reserveConfirmation(kv.binding, USER, "written-first", soon());

    // Fail toward the recoverable side: a spent token with no write costs one
    // re-preview, where an unspent token after a successful write is a second
    // unintended write and is not recoverable at all.
    expect(kv.puts).toHaveLength(1);
  });

  it("FAILS the reservation when the KV write rejects, rather than allowing it", async () => {
    // The one place this module deliberately diverges from the discovery
    // cache's swallow. A failed cache write degrades that call to uncached; a
    // failed reservation write means the single-use guarantee does not hold for
    // this token, so proceeding would be enforcing nothing.
    const kv = fakeKv({ putRejects: true });

    await expect(
      reserveConfirmation(kv.binding, USER, "write-rejects", soon()),
    ).rejects.toBeInstanceOf(ConfirmationInvalidError);
  });

  it("gives the record the token's own remaining life", async () => {
    const kv = fakeKv();
    const now = 1_800_000_000;
    freezeClockAt(now);

    await reserveConfirmation(kv.binding, USER, "far", now + CONFIRM_TTL_SECONDS);

    expect(kv.puts[0].options?.expirationTtl).toBe(CONFIRM_TTL_SECONDS);
  });

  it("floors the record's life at 60 seconds, because KV refuses less", async () => {
    const kv = fakeKv();
    const now = 1_800_000_000;
    freezeClockAt(now);

    await reserveConfirmation(kv.binding, USER, "near", now + 5);

    // The floor extends the RECORD and never the token: the token still dies at
    // `x`, and a record that outlives it is exactly what stops a double spend.
    expect(kv.puts[0].options?.expirationTtl).toBe(60);
  });

  it("stores a key whose presence is the whole datum", async () => {
    const kv = fakeKv();

    await reserveConfirmation(kv.binding, USER, "value-shape", soon());

    expect(kv.puts[0].value).toBe("1");
    expect(CONFIRM_KEY_PREFIX).toBe("confirm:v2:");
  });

  it("refuses a spent token with the same error every other cause raises", async () => {
    // The EIGHTH producer of the class, and it must answer exactly as the
    // seven on the verify path do — a spent confirmation that looked different
    // from a forged one would tell a caller which of the two it had.
    const kv = fakeKv();
    await reserveConfirmation(kv.binding, USER, "same-answer", soon());

    const spent = (await reserveConfirmation(
      kv.binding,
      USER,
      "same-answer",
      soon(),
    ).catch((err: unknown) => err)) as Error;
    const forged = (await verifyConfirmation("nodot", SECRET, USER).catch(
      (err: unknown) => err,
    )) as Error;

    expect(spent.message).toBe(forged.message);
    expect(spent.name).toBe(forged.name);
    expect(Object.keys(spent)).toEqual(Object.keys(forged));
  });
});

// ===========================================================================
// Cross-use disjointness — asserted structurally, not merely observed
// ===========================================================================

describe("a confirmation and an event id cannot be used for one another", () => {
  const ref = {
    calendarUrl: "https://p00-caldav.icloud.example/1234567890/calendars/work/",
    objectUrl:
      "https://p00-caldav.icloud.example/1234567890/calendars/work/abc.ics",
    recurrenceId: null,
  };

  it("refuses a confirmation handed to the event-id decoder", async () => {
    const token = await mintConfirmation(payload(), SECRET);

    expect(() => decodeEventId(token)).toThrow();
  });

  it("refuses a real event id handed to the confirmation verifier", async () => {
    // A real id from the shipped minter rather than a hand-written string, so
    // the case cannot pass because the fixture happened to be malformed.
    const eventId = encodeEventId(ref);

    await expect(
      verifyConfirmation(eventId, SECRET, USER),
    ).rejects.toBeInstanceOf(
      ConfirmationInvalidError,
    );
  });

  it("is STRUCTURAL: the separator is outside the alphabet the shared codec enforces", async () => {
    // The reason, not just the outcome. Read from the SHIPPED codec by calling
    // it, on `DAV_KIND_LETTERS`'s precedent — a guard that restated the
    // character class here would agree with itself rather than with
    // `src/tokens.ts`, and would keep agreeing after the alphabet changed.
    const eventId = encodeEventId(ref);
    const token = await mintConfirmation(payload(), SECRET);

    // An event id passes the alphabet check; a confirmation cannot, because it
    // carries a character the alphabet does not contain. Neither decoder
    // performs a check against the other's format — there is nothing to omit.
    expect(() => fromBase64Url(eventId)).not.toThrow();
    expect(() => fromBase64Url(token)).toThrow();
    expect(token).toContain(".");
    expect(eventId).not.toContain(".");
  });
});

// ===========================================================================
// The translation join — the last block, and the join between two suites
// ===========================================================================

describe("the refusal is translated at the DAV tree's own boundary", () => {
  /**
   * A stand-in for the boundary the DAV tree owes this module.
   *
   * The shipped boundary does not exist yet: `DavConfirmationError` ships and
   * translates, but the handler that verifies a confirmation is a later plan's.
   * So this function is the CONTRACT, written here where it can be measured,
   * and the plan that ships the real boundary inherits both the assertion and
   * the mutation below.
   *
   * That the subject is a stand-in is stated rather than glossed, because a
   * stand-in that quietly stood for shipped code would be a test agreeing with
   * itself. What is NOT a stand-in is the half that matters — the fall-through
   * asserted below runs against the real `davToErrorCategory`.
   */
  async function davBoundary(token: string): Promise<ConfirmPayload> {
    try {
      return await verifyConfirmation(token, SECRET, USER);
    } catch {
      throw new DavConfirmationError();
    }
  }

  it("reports a refused confirmation as confirmation_invalid, end to end", async () => {
    const err = await davBoundary("nodot").catch((caught: unknown) => caught);

    // The CATEGORY is asserted before the class, deliberately. Both would go
    // red if the translation were lost, but only this order reports the wrong
    // ANSWER — `connection_failed` — which is the thing that matters and the
    // thing a reader of the failure needs to see. Asserting the class first
    // reports a type mismatch and buries the consequence.
    expect(davToErrorCategory(err)).toMatchObject({
      category: "confirmation_invalid",
    });
    expect(err).toBeInstanceOf(DavConfirmationError);
  });

  it("still returns the payload for a good confirmation through the same boundary", async () => {
    // The other half of the fence: translating everything would pass the case
    // above while refusing every legitimate commit.
    const live = payload();

    expect(await davBoundary(await mintConfirmation(live, SECRET))).toEqual(
      live,
    );
  });

  it("would report connection_failed if the translation were ever lost", async () => {
    // The mutation, expressed as an assertion against SHIPPED code rather than
    // as an edit that has to be remembered and reverted. `davToErrorCategory`
    // dispatches on TYPE and falls through to a connection diagnosis for
    // anything it does not recognise, so a `ConfirmationInvalidError` that
    // escaped the boundary above would tell the caller the network failed —
    // guidance that is not merely imprecise but points at the wrong remedy,
    // telling a model to retry the thing that will be refused identically.
    //
    // This is exactly the answer the live mutation produced when the
    // catch-and-rethrow was deleted from `davBoundary`; asserting it here means
    // the claim survives without anyone re-running that edit.
    expect(davToErrorCategory(new ConfirmationInvalidError())).toMatchObject({
      category: "connection_failed",
    });
  });
});
