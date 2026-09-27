// The change marker: sealed, bound to one user, and carrying no identifier.
//
// Nothing here opens a connection. The key is the pool's confirmation key, the
// same one the running server seals with.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { MarkerContent } from "../src/change-marker";
import {
  MARKER_VERSION,
  MarkerRefusedError,
  calendarKeyOf,
  classifyVersion,
  readMarker,
  sealMarker,
} from "../src/change-marker";
import { fromBase64Url, toBase64Url, TOKEN_DECODER, TOKEN_ENCODER } from "../src/tokens";
import { ConfirmationInvalidError, verifyConfirmation } from "../src/confirm";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The marker module's own source, for the guard that readMarker classifies
// through classifyVersion. Read at build time by Vite.
// @ts-expect-error — a raw import has no ambient declaration here.
import MARKER_SOURCE from "../src/change-marker.ts?raw";

const OTHER_USER = "b".repeat(64);

const CONTENT: MarkerContent = {
  folders: [
    {
      mailbox: "INBOX",
      uidValidity: 3857529045,
      uidNext: 4392,
      highestModseq: "9223372036854775807",
    },
    { mailbox: "Archive", uidValidity: 1, uidNext: 17, highestModseq: null },
  ],
  calendar: {
    takenAt: 1790000000,
    calendars: [{ key: "AAAAAAAAAAAA", syncToken: "HwoQEgwAAA" }],
  },
  mintedAt: 1790479991,
};

async function refusal(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  return null;
}

describe("the change marker", () => {
  it("is version 1", () => {
    expect(MARKER_VERSION).toBe(1);
  });

  it("round-trips: the same content comes back for the same user", async () => {
    const { userId } = await ownerPrincipal();
    const token = await sealMarker(CONTENT, userId, env.CONFIRM_SECRET);

    expect(await readMarker(token, userId, env.CONFIRM_SECRET)).toEqual({
      kind: "current",
      content: CONTENT,
    });
  });

  it("refuses a marker presented by another user", async () => {
    const { userId } = await ownerPrincipal();
    const token = await sealMarker(CONTENT, userId, env.CONFIRM_SECRET);

    const err = await refusal(readMarker(token, OTHER_USER, env.CONFIRM_SECRET));
    expect(err).toBeInstanceOf(MarkerRefusedError);
    expect((err as Error).message).toBe("marker-refused");
  });

  it("refuses an edited payload with the same one refusal", async () => {
    const { userId } = await ownerPrincipal();
    const token = await sealMarker(CONTENT, userId, env.CONFIRM_SECRET);
    const [payloadPart, seal] = token.split(".");

    // The edit a model would make: move the inbox back to UID 1.
    const payload = JSON.parse(TOKEN_DECODER.decode(fromBase64Url(payloadPart!)));
    payload.f[0][2] = 1;
    const edited = `${toBase64Url(TOKEN_ENCODER.encode(JSON.stringify(payload)))}.${seal}`;

    const err = await refusal(readMarker(edited, userId, env.CONFIRM_SECRET));
    expect(err).toBeInstanceOf(MarkerRefusedError);
    expect((err as Error).message).toBe("marker-refused");
  });

  it("refuses a marker that is not two parts, identically", async () => {
    const { userId } = await ownerPrincipal();
    for (const token of ["", "abc", "a.b.c", ".x", "x."]) {
      const err = await refusal(readMarker(token, userId, env.CONFIRM_SECRET));
      expect(err, token).toBeInstanceOf(MarkerRefusedError);
    }
  });

  it("carries no user id: the decoded payload holds no 64-hex string", async () => {
    const { userId } = await ownerPrincipal();
    expect(userId).toMatch(/^[0-9a-f]{64}$/);
    const token = await sealMarker(CONTENT, userId, env.CONFIRM_SECRET);
    const decoded = TOKEN_DECODER.decode(fromBase64Url(token.split(".")[0]!));

    expect(decoded).not.toMatch(/[0-9a-f]{64}/);
    expect(decoded).not.toContain(userId);
  });

  it("refuses to seal content it would not read back", async () => {
    const { userId } = await ownerPrincipal();
    const tooMany: MarkerContent = {
      ...CONTENT,
      folders: Array.from({ length: 6 }, (_, index) => ({
        mailbox: `F${index}`,
        uidValidity: 1,
        uidNext: 1,
        highestModseq: null,
      })),
    };
    const err = await refusal(sealMarker(tooMany, userId, env.CONFIRM_SECRET));
    expect(err).toBeInstanceOf(MarkerRefusedError);
  });

  it("keys a calendar by twelve base64url characters of its URL digest", async () => {
    const key = await calendarKeyOf("https://p01-caldav.icloud.com/123/calendars/home/");
    expect(key).toMatch(/^[A-Za-z0-9_-]{12}$/);
    expect(await calendarKeyOf("https://p01-caldav.icloud.com/123/calendars/work/")).not.toBe(key);
  });

  it("carries a calendar's own takenAt when it has one, and reads it back (D-16, 23-04)", async () => {
    const { userId } = await ownerPrincipal();
    const content: MarkerContent = {
      folders: [],
      calendar: {
        takenAt: 1790000500,
        calendars: [
          { key: "AAAAAAAAAAAA", syncToken: "t-new" },
          { key: "BBBBBBBBBBBB", syncToken: "t-old", takenAt: 1790000000 },
        ],
      },
      mintedAt: 1790000500,
    };
    const sealed = await sealMarker(content, userId, env.CONFIRM_SECRET);
    const reading = await readMarker(sealed, userId, env.CONFIRM_SECRET);
    expect(reading).toEqual({ kind: "current", content });
  });

  it("refuses a calendar entry whose own takenAt is not whole seconds", async () => {
    const { userId } = await ownerPrincipal();
    const bad: MarkerContent = {
      folders: [],
      calendar: {
        takenAt: 1790000500,
        calendars: [{ key: "AAAAAAAAAAAA", syncToken: "t", takenAt: 1.5 }],
      },
      mintedAt: 1790000500,
    };
    const err = await refusal(sealMarker(bad, userId, env.CONFIRM_SECRET));
    expect(err).toBeInstanceOf(MarkerRefusedError);
  });
});

// ---------------------------------------------------------------------------
// 23-03: the version classifier, cross-use with confirmations, and size
// ---------------------------------------------------------------------------

describe("classifyVersion (D-09, D-13)", () => {
  // Tested with a current version of 3, so the "older" arm is exercised even
  // while the real MARKER_VERSION is 1 and that arm cannot yet be reached.
  it.each([
    [3, "current"],
    [1, "older"],
    [2, "older"],
    [0, "refuse"],
    [-1, "refuse"],
    [1.5, "refuse"],
    [4, "refuse"],
    ["3", "refuse"],
    [null, "refuse"],
    [undefined, "refuse"],
    [Number.NaN, "refuse"],
  ] as const)("version %s against current 3 is %s", (version, expected) => {
    expect(classifyVersion(version, 3)).toBe(expected);
  });

  it("readMarker classifies with MARKER_VERSION through classifyVersion", () => {
    const source = String(MARKER_SOURCE)
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    const start = source.indexOf("export async function readMarker(");
    expect(start).toBeGreaterThan(0);
    const end = source.indexOf("\nexport ", start + 1);
    const body = source.slice(start, end === -1 ? undefined : end);
    expect(body).toMatch(/classifyVersion\(\s*[^,]+,\s*MARKER_VERSION\s*\)/);
  });
});

describe("a marker and a confirmation cannot stand in for each other (T-23-18)", () => {
  it("a marker handed to the confirmation reader is refused", async () => {
    const { userId } = await ownerPrincipal();
    const token = await sealMarker(CONTENT, userId, env.CONFIRM_SECRET);

    const err = await refusal(
      verifyConfirmation(token, env.CONFIRM_SECRET, userId, "dav"),
    );
    expect(err).toBeInstanceOf(ConfirmationInvalidError);
  });
});

describe("the marker's size", () => {
  it("five folders and nine calendars with 40-character tokens seal to at most 1,500 characters", async () => {
    const { userId } = await ownerPrincipal();
    const big: MarkerContent = {
      folders: [
        "INBOX",
        "Archive",
        "Receipts",
        "Job Search/Recruiters",
        "Job Search/Applications",
      ].map((mailbox) => ({
        mailbox,
        uidValidity: 3857529045,
        uidNext: 4294967,
        highestModseq: "9223372036854775807",
      })),
      calendar: {
        takenAt: 1790479991,
        calendars: await Promise.all(
          Array.from({ length: 9 }, async (_, index) => ({
            key: await calendarKeyOf(`https://p01-caldav.icloud.com/1/calendars/c${index}/`),
            syncToken: `HwoQEgwAAA${String(index).padStart(30, "x")}`,
          })),
        ),
      },
      mintedAt: 1790479991,
    };
    expect(big.calendar!.calendars[0]!.syncToken).toHaveLength(40);

    const token = await sealMarker(big, userId, env.CONFIRM_SECRET);
    expect(token.length).toBeLessThanOrEqual(1500);
    expect((await readMarker(token, userId, env.CONFIRM_SECRET)).kind).toBe("current");
  });
});
