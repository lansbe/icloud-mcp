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
  readMarker,
  sealMarker,
} from "../src/change-marker";
import { fromBase64Url, toBase64Url, TOKEN_DECODER, TOKEN_ENCODER } from "../src/tokens";
import { ownerPrincipal } from "./fixtures/bound-secrets";

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
});
