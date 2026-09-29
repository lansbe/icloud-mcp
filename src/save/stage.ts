// Turning a save read into links (Phase 29.1).
//
// The save tool reads each attachment part in one read-only session and closes
// it. Only then does this module run: it decodes each part, hashes it, stores a
// copy under the person's own prefix, and seals a link to that copy. So no
// storage call is ever made while an iCloud mail connection is open, and the
// signature holds that structurally: this module takes parts, never a session.
//
// ONE PART AT A TIME, in a plain loop. Never a concurrent combinator: every
// storage call spends one of the six connections a Worker invocation has, and
// a decoded part is up to about 15 MB, so two held at once would double the
// memory for nothing.
//
// This module contains no logging calls of any kind and must never acquire
// any.

import type { Env } from "../env";
import type { SavePartRead } from "../mail/service";
import { decodeWindows } from "../mail/stream-decode";
import { deleteStaged, putSaved } from "../staging/r2";
import { suggestSaveName } from "./filename";
import { mintSaveLink } from "./link";

/** One part the caller asked for: the caller's own id string and its read. */
export interface SaveItem {
  id: string;
  read: SavePartRead;
}

/**
 * Why one part got no link, from a closed set.
 *
 * The read's own refusals, the decoder's two, and `not-stored`: the copy's key
 * was refused before any write (a bad user id or time), or its link could not
 * be sealed. `not-stored` is unreachable while the tool checks the seal key
 * first and the user id comes from the principal; it exists so that a failure
 * there is a named row rather than a lost id. A storage error is NOT a
 * `not-stored` row: the bucket's own failure is not caught here, so it fails
 * the whole call, and the links already made in it are lost with it (their
 * copies are left for the sweep). `mixed-messages` is the tool's own: ids from
 * more than one message, refused before anything is read.
 */
export type SavePartRefusal =
  | "not-found"
  | "empty"
  | "part-too-large"
  | "part-changed"
  | "malformed-encoding"
  | "encoding-unsupported"
  | "not-stored"
  | "mixed-messages";

/** What happened to one part. Filename and type are a stranger's. */
export type SaveRow =
  | {
      id: string;
      outcome: "linked";
      url: string;
      expiresAtMs: number;
      /** The decoded length: the real size of the file. */
      sizeBytes: number;
      /** Lowercase hex SHA-256 of the decoded file. */
      sha256: string;
      /**
       * A safe name for the person's disk, from `suggestSaveName`. Still
       * derived from a stranger's text, so it travels only inside the fence.
       */
      suggestedFilename: string;
      filename: string | null;
      mimeType: string | null;
    }
  | {
      id: string;
      outcome: "refused";
      refusal: SavePartRefusal;
      sizeBytes: number | null;
      limitBytes: number | null;
      filename: string | null;
      mimeType: string | null;
    }
  | { id: string; outcome: "deferred" };

/** Lowercase hex SHA-256 of some bytes. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A refused row for a part that was found. */
function refusedRow(
  id: string,
  refusal: SavePartRefusal,
  sizeBytes: number | null,
  limitBytes: number | null,
  filename: string | null,
  mimeType: string | null,
): SaveRow {
  return { id, outcome: "refused", refusal, sizeBytes, limitBytes, filename, mimeType };
}

/**
 * Decode, hash, store and seal each fetched part, one at a time, and pass the
 * refused and deferred parts through as rows. One row per item, in order.
 *
 * Call it only after the mail session has closed. `userId` is the signed-in
 * principal's own id; the copies land under that segment and nowhere else.
 */
export async function saveParts(
  env: Env,
  userId: string,
  items: readonly SaveItem[],
  nowMs: number,
): Promise<SaveRow[]> {
  const rows: SaveRow[] = [];
  for (const { id, read } of items) {
    if (read.outcome === "deferred") {
      rows.push({ id, outcome: "deferred" });
      continue;
    }
    if (read.outcome === "refused") {
      rows.push(
        refusedRow(
          id,
          read.refusal,
          read.encodedOctets ?? null,
          read.limitBytes ?? null,
          read.filename ?? null,
          read.mimeType ?? null,
        ),
      );
      continue;
    }

    const decoded = decodeWindows(read.windows, read.encoding);
    // The encoded windows are not needed once decoded. Dropping them here lets
    // the next part's decode run without this one's encoded copy still held.
    read.windows.length = 0;
    if (!decoded.ok) {
      rows.push(refusedRow(id, decoded.refusal, read.encodedOctets, null, read.filename, read.mimeType));
      continue;
    }
    const bytes = decoded.bytes;
    if (bytes.byteLength === 0) {
      rows.push(refusedRow(id, "empty", 0, null, read.filename, read.mimeType));
      continue;
    }

    const sha256 = await sha256Hex(bytes);
    const key = await putSaved(env, userId, bytes, nowMs);
    if (key === null) {
      rows.push(refusedRow(id, "not-stored", bytes.byteLength, null, read.filename, read.mimeType));
      continue;
    }
    const link = await mintSaveLink(env, userId, key, bytes.byteLength, nowMs);
    if (link === null) {
      // A copy nobody can reach is removed at once rather than left for the
      // bucket's sweep.
      await deleteStaged(env, userId, key);
      rows.push(refusedRow(id, "not-stored", bytes.byteLength, null, read.filename, read.mimeType));
      continue;
    }
    rows.push({
      id,
      outcome: "linked",
      url: link.url,
      expiresAtMs: link.expiresAtMs,
      sizeBytes: bytes.byteLength,
      sha256,
      suggestedFilename: suggestSaveName(read.filename),
      filename: read.filename,
      mimeType: read.mimeType,
    });
  }
  return rows;
}
