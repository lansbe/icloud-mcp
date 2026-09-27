// The caller-held marker for the change check: seal, read, version.
//
// A marker is the change check's "last time I looked". The caller carries it
// and hands it back; this server stores nothing. It holds, per mail folder, the
// three numbers iCloud reported for it (validity, next UID, highest
// mod-sequence), and per calendar a short digest of the collection URL plus the
// sync token iCloud gave for it. Nothing here knows what a folder or a calendar
// is beyond those field shapes. This module issues no request and reads no
// resource. It sits beside `./confirm.ts` at the source root because both the
// mail tree and the DAV tree feed it, and a module inside either tree would
// have to be imported across the boundary or copied.
//
// **The server stores nothing, on purpose.** A server-held "last seen" point is
// advanced as a side effect of answering, so a dropped response loses the
// changes it carried. A caller-held one only moves when the caller keeps the
// new one. A server-held marker is a later phase's job, in the per-user object;
// the plain-data state types below are shaped so that phase can store them
// directly, and the seal is only the caller-held wrapper around them.
//
// **Why it is signed.** The model carries the marker, and a model will invent
// one if it can. An unsigned marker would let it write "UIDNEXT 1" and get the
// whole folder back as "new". With a seal, the only markers this module will
// read are ones this server made.
//
// **Why the confirmation key, under its own domain label.** One key import,
// one secret, one empty-key refusal: `importConfirmationKey` is reused, never
// copied. The two signed-byte sets cannot overlap. A confirmation's signed
// bytes are exactly its base64url payload part; a marker's begin with a fixed
// label that contains a colon, which is outside the base64url alphabet. So no
// marker can verify as a confirmation and no confirmation can verify as a
// marker, by construction rather than by a check someone can forget.
//
// **Why the user id is sealed in and not carried.** It goes into the signed
// bytes only. The marker carries no identifier, it is 64 characters shorter,
// and a marker presented by a different user fails the seal with the same one
// refusal a forgery gets.
//
// **Why it does not expire.** Staleness is decided by iCloud's own state: a
// changed folder validity or a refused sync token. A clock would only add a
// second, weaker notion of "too old". A replayed marker is read-only and gives
// the same user what they could ask for anyway.
//
// This module contains no logging calls of any kind and must never acquire any.

import { importConfirmationKey } from "./confirm";
import { TOKEN_DECODER, TOKEN_ENCODER, fromBase64Url, toBase64Url } from "./tokens";

/**
 * The marker format version.
 *
 * A marker whose seal verifies but whose version is lower than this one is
 * "too old": every source starts again, with a plain sentence, and it is never
 * an error. Any other version is refused. Bumping this is a decision, because
 * every marker a caller holds then restarts once.
 */
export const MARKER_VERSION = 1;

/**
 * The most mail folders one marker may hold, checked and carried together.
 *
 * Defined here, once, and imported by the mail service. The marker is where
 * the bound is enforced on the way in, and a second definition would be a
 * second number to drift.
 */
export const MAX_CHANGE_FOLDERS = 5;

/** The most calendars one marker may hold. */
export const MAX_CHANGE_CALENDARS = 64;

/** A sync token longer than this is refused. iCloud's are far shorter. */
const MAX_SYNC_TOKEN_LENGTH = 511;

/** A mailbox name longer than this is refused. */
const MAX_MAILBOX_LENGTH = 1024;

/** The largest value a mod-sequence may hold (RFC 7162: 63 bits). */
const MAX_MODSEQ = 9223372036854775807n;

/** The largest unsigned 32-bit integer. */
const MAX_UINT32 = 0xffffffff;

/**
 * The fixed label the signed bytes open with.
 *
 * It contains a colon, and a colon is outside the base64url alphabet. That is
 * what keeps a marker's signed bytes and a confirmation's apart.
 */
const DOMAIN_LABEL = "icloud-mcp:change-marker:";

/** Between the payload part and the seal, as in a confirmation. */
const SEPARATOR = ".";

/** What the change check knows about one mail folder. Plain data. */
export interface FolderState {
  /** The raw wire mailbox name. */
  mailbox: string;
  uidValidity: number;
  uidNext: number;
  /**
   * The highest mod-sequence, as the digits iCloud sent, or `null` when it
   * sent none. A string because the value is 63-bit and a JS number would make
   * two different values compare equal.
   */
  highestModseq: string | null;
}

/** What the change check knows about one calendar. Plain data. */
export interface CalendarState {
  /** `calendarKeyOf(collectionUrl)`: twelve base64url characters. */
  key: string;
  syncToken: string;
}

/** The calendar half of a marker. */
export interface CalendarBlock {
  /** When the calendar state was taken, in seconds since the epoch. */
  takenAt: number;
  calendars: CalendarState[];
}

/** Everything a marker holds, unsealed. */
export interface MarkerContent {
  folders: FolderState[];
  calendar: CalendarBlock | null;
  /** When this marker was made, in seconds since the epoch. */
  mintedAt: number;
}

/** What reading a marker gives back when it is accepted. */
export type MarkerReading =
  | { kind: "current"; content: MarkerContent }
  | { kind: "older-version" };

/**
 * The refusal, and the only one, whatever the cause.
 *
 * On `ConfirmationInvalidError`'s shape and for its reasons: a fixed label, a
 * `readonly kind`, and no constructor argument, so there is nowhere for a
 * cause, a field name or a quoted marker to ride. A seal that does not verify,
 * a wrong user, a payload that is not JSON, a shape this build will not read,
 * a version it does not know, and an unusable key all raise this, identically.
 * A refusal that said which check failed would teach a model probing the
 * format how the format is built.
 */
export class MarkerRefusedError extends Error {
  readonly kind = "marker-refused" as const;

  constructor() {
    super("marker-refused");
    this.name = "MarkerRefusedError";
  }
}

/** The encoded payload. Single-letter keys and tuples keep the marker short. */
interface WirePayload {
  v: number;
  t: number;
  f: [string, number, number, string | null][];
  c: { t: number; s: [string, string][] } | null;
}

function isUint32(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= MAX_UINT32;
}

function isSeconds(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isModseq(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  if (!/^(?:0|[1-9]\d{0,18})$/.test(value)) return false;
  return BigInt(value) <= MAX_MODSEQ;
}

function isMailboxName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_MAILBOX_LENGTH &&
    !/[\r\n\u0000]/.test(value)
  );
}

function isCalendarKey(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{12}$/.test(value);
}

function isSyncToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_SYNC_TOKEN_LENGTH
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The shape check, used both when reading and when sealing.
 *
 * Returns the content, or `null` for anything this build will not read. One
 * function for both directions, so a marker this server seals is always one it
 * will read back.
 */
function contentOf(wire: unknown): MarkerContent | null {
  if (!isPlainObject(wire)) return null;
  const keys = Object.keys(wire).sort().join(",");
  if (keys !== "c,f,t,v") return null;
  if (wire.v !== MARKER_VERSION) return null;
  if (!isSeconds(wire.t)) return null;

  if (!Array.isArray(wire.f) || wire.f.length > MAX_CHANGE_FOLDERS) return null;
  const folders: FolderState[] = [];
  const seenMailboxes = new Set<string>();
  for (const entry of wire.f) {
    if (!Array.isArray(entry) || entry.length !== 4) return null;
    const [mailbox, uidValidity, uidNext, highestModseq] = entry;
    if (!isMailboxName(mailbox)) return null;
    if (!isUint32(uidValidity) || !isUint32(uidNext)) return null;
    if (!isModseq(highestModseq)) return null;
    if (seenMailboxes.has(mailbox)) return null;
    seenMailboxes.add(mailbox);
    folders.push({ mailbox, uidValidity, uidNext, highestModseq });
  }

  let calendar: CalendarBlock | null = null;
  if (wire.c !== null) {
    if (!isPlainObject(wire.c)) return null;
    if (Object.keys(wire.c).sort().join(",") !== "s,t") return null;
    if (!isSeconds(wire.c.t)) return null;
    const list = wire.c.s;
    if (!Array.isArray(list) || list.length > MAX_CHANGE_CALENDARS) return null;
    const calendars: CalendarState[] = [];
    const seenKeys = new Set<string>();
    for (const entry of list) {
      if (!Array.isArray(entry) || entry.length !== 2) return null;
      const [key, syncToken] = entry;
      if (!isCalendarKey(key) || !isSyncToken(syncToken)) return null;
      if (seenKeys.has(key)) return null;
      seenKeys.add(key);
      calendars.push({ key, syncToken });
    }
    calendar = { takenAt: wire.c.t, calendars };
  }

  return { folders, calendar, mintedAt: wire.t };
}

function wireOf(content: MarkerContent): WirePayload {
  return {
    v: MARKER_VERSION,
    t: content.mintedAt,
    f: content.folders.map((folder) => [
      folder.mailbox,
      folder.uidValidity,
      folder.uidNext,
      folder.highestModseq,
    ]),
    c:
      content.calendar === null
        ? null
        : {
            t: content.calendar.takenAt,
            s: content.calendar.calendars.map((entry) => [
              entry.key,
              entry.syncToken,
            ]),
          },
  };
}

/** The bytes the seal covers: the label, the user id, a colon, the payload part. */
function signedBytes(userId: string, payloadPart: string): Uint8Array {
  return TOKEN_ENCODER.encode(`${DOMAIN_LABEL}${userId}:${payloadPart}`);
}

/**
 * Seal a marker for one user.
 *
 * Refuses content that would not read back, with the same shape check reading
 * uses. Refuses with the confirmation module's own error when the key is
 * unusable, because that is a server fault and not a bad marker.
 */
export async function sealMarker(
  content: MarkerContent,
  userId: string,
  secret: string | undefined,
): Promise<string> {
  const key = await importConfirmationKey(secret);

  const wire = wireOf(content);
  // Round-tripped through JSON, so the check sees exactly what reading will.
  if (contentOf(JSON.parse(JSON.stringify(wire))) === null) {
    throw new MarkerRefusedError();
  }

  const payloadPart = toBase64Url(TOKEN_ENCODER.encode(JSON.stringify(wire)));
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    signedBytes(userId, payloadPart),
  );
  return `${payloadPart}${SEPARATOR}${toBase64Url(new Uint8Array(mac))}`;
}

/**
 * Read a marker back for one user, or refuse it.
 *
 * **The order is fixed.** Two non-empty parts; verify the seal over the rebuilt
 * signed bytes; decode and parse; the version; the shape. Nothing reads a field
 * before the seal has verified. `crypto.subtle.verify`, never a sign followed
 * by a comparison.
 *
 * Every failure is the one `MarkerRefusedError`, with nothing attached. A seal
 * that does not match and a payload that will not decode leave by the same
 * route, inside one `try`.
 */
export async function readMarker(
  token: string,
  userId: string,
  secret: string | undefined,
): Promise<MarkerReading> {
  if (typeof token !== "string") throw new MarkerRefusedError();
  const parts = token.split(SEPARATOR);
  if (parts.length !== 2) throw new MarkerRefusedError();
  const [payloadPart, macPart] = parts;
  if (payloadPart.length === 0 || macPart.length === 0) {
    throw new MarkerRefusedError();
  }

  let parsed: unknown;
  try {
    const key = await importConfirmationKey(secret);
    const verified = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64Url(macPart),
      signedBytes(userId, payloadPart),
    );
    if (!verified) throw new MarkerRefusedError();
    parsed = JSON.parse(TOKEN_DECODER.decode(fromBase64Url(payloadPart)));
  } catch {
    throw new MarkerRefusedError();
  }

  if (!isPlainObject(parsed)) throw new MarkerRefusedError();
  const version = parsed.v;
  if (
    Number.isInteger(version) &&
    (version as number) >= 1 &&
    (version as number) < MARKER_VERSION
  ) {
    return { kind: "older-version" };
  }
  if (version !== MARKER_VERSION) throw new MarkerRefusedError();

  const content = contentOf(parsed);
  if (content === null) throw new MarkerRefusedError();
  return { kind: "current", content };
}

/**
 * The short key a calendar is held under in a marker.
 *
 * SHA-256 of the collection URL, first nine bytes, base64url: twelve
 * characters. The URL itself would make the marker several times longer, and
 * the model has to pass the marker back exactly.
 */
export async function calendarKeyOf(collectionUrl: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    TOKEN_ENCODER.encode(collectionUrl),
  );
  return toBase64Url(new Uint8Array(digest).slice(0, 9));
}
