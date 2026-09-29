// Attachment save links: made by the save tool, spent by the download route
// (Phase 29.1).
//
// A link names one saved copy and nothing else. It is SELF-VALIDATING: its
// token is the copy's user id, the copy's name segment, the link's expiry and
// the copy's size, sealed with AES-GCM under a Worker secret. So nobody can
// read those from the URL, or make a link, without that secret, and a changed
// byte fails to unseal. The URL is the deployed host, `/save/` and the token,
// and carries no user id, storage key or filename in the clear.
//
// THE MARK IS INVERTED (29.1-WORDING.md decision 1). Making a link writes
// nothing to any store. The key-value store holds only SPENT marks, one per
// link that has been downloaded, keyed by the SHA-256 of the token and written
// by the first download BEFORE a byte is sent. A miss means "not spent". So a
// fresh link's first download never depends on the store having reached
// another Cloudflare location. The residual is written into the boundary words
// the owner approved: two downloads from two places at almost the same moment
// can both find no mark. After the first download finishes, the copy itself is
// gone from the bucket, which is strongly consistent, so a later download finds
// nothing either way.
//
// THIS IS THE ONLY MODULE THAT READS THE MARK STORE OR THE SEAL KEY. The tool
// asks `saveLinksConfigured` rather than reading the secret, and the route asks
// `claimSaveLink` rather than reading the store.
//
// The seal is Web Crypto AES-GCM written here, and deliberately not the
// autonomy module's seal: importing that would load agent code into the
// download route, which must reach no mail, agent or sign-in code at all.
//
// This module contains no logging calls of any kind and must never acquire
// any. A caught value is never read.

import { isConfiguredSecret } from "../configured-secret";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import type { Env } from "../env";
import { STAGING_PREFIX, USER_SEGMENT, isSavedName, underStagingPrefix } from "../staging/r2";

/** How long a link works after it is made: five minutes. */
export const SAVE_LINK_TTL_MS = 5 * 60 * 1000;

/**
 * How long a spent mark lives, in seconds: ten minutes.
 *
 * Twice the link's life, so a mark outlives every link it could refuse. After
 * that the sealed expiry refuses the link on its own.
 */
export const SPENT_MARK_TTL_SECONDS = 600;

/** The path every link is served under. The dispatch matches the same text. */
export const SAVE_ROUTE_PATH = "/save/";

/** The version inside the sealed payload and the additional data. */
const LINK_VERSION = 1;

/** A seal key is exactly 32 bytes once decoded. */
const SEAL_KEY_BYTES = 32;

/** A fresh 12-byte IV per link. */
const IV_BYTES = 12;

/** The AES-GCM tag length, in bytes. */
const TAG_BYTES = 16;

/**
 * The fixed additional data: this purpose and this version. A token sealed for
 * anything else under the same key does not open here.
 */
const SEAL_AAD = new TextEncoder().encode("icloud-mcp:save-link:v1");

/**
 * The spent mark's key stem. The key is this stem and the lowercase hex
 * SHA-256 of the token. It has no user segment, by design (decision 1): the
 * download has no signed-in person to key it by.
 */
const SPENT_MARK = "spent:v1:";

/** The URL-safe alphabet a token is written in. */
const TOKEN_ALPHABET = /^[A-Za-z0-9_-]+$/;

/**
 * The fixed length window a token must fall in, in characters. A real token is
 * about 240. Anything outside the window is refused with no store read and no
 * crypto.
 */
const TOKEN_MIN_CHARS = 64;
const TOKEN_MAX_CHARS = 512;

/**
 * Whether `token` has a link's shape: the URL-safe alphabet, inside the length
 * window. Nothing is read and no crypto runs. The route asks this before it
 * reads anything, and `claimSaveLink` asks it again, so the two cannot drift.
 */
export function hasSaveTokenShape(token: unknown): token is string {
  return (
    typeof token === "string" &&
    token.length >= TOKEN_MIN_CHARS &&
    token.length <= TOKEN_MAX_CHARS &&
    TOKEN_ALPHABET.test(token)
  );
}

/** What a link opens to. */
export type SaveClaim =
  | { state: "live"; userId: string; key: string; sizeBytes: number }
  | { state: "expired"; userId: string; key: string };

/** A made link. */
export interface MintedLink {
  /** `https://<deployed host>/save/<token>`. */
  url: string;
  /** When it stops working, in epoch milliseconds. */
  expiresAtMs: number;
}

/** Base64url with no padding. */
function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Bytes from base64url with no padding, or null. */
function bytesFromBase64Url(value: string): Uint8Array | null {
  if (!TOKEN_ALPHABET.test(value)) return null;
  if (value.length % 4 === 1) return null;
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** The seal key's 32 raw bytes, or null when it is unset or the wrong shape. */
function sealKeyBytes(value: unknown): Uint8Array | null {
  if (!isConfiguredSecret(value)) return null;
  const raw = bytesFromBase64Url(value);
  return raw !== null && raw.length === SEAL_KEY_BYTES ? raw : null;
}

/** The seal key as a non-extractable AES-GCM key, or null. */
async function sealKey(env: Env): Promise<CryptoKey | null> {
  const raw = sealKeyBytes(env.SAVE_LINK_SEAL_KEY);
  if (raw === null) return null;
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  } catch {
    return null;
  }
}

/**
 * Whether links can be made: the seal key is set and decodes to exactly 32
 * bytes. A plain boolean, and the only way another module asks about the key.
 */
export function saveLinksConfigured(env: Env): boolean {
  return sealKeyBytes(env.SAVE_LINK_SEAL_KEY) !== null;
}

/** The spent mark's key for one token: the stem and the token's SHA-256. */
export async function spentMarkKey(token: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
  );
  const hex = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${SPENT_MARK}${hex}`;
}

/**
 * Make a link for one saved copy, or null.
 *
 * Null when the key is not a saved copy beneath `userId`'s own segment, when
 * the size or time is not a safe integer, or when the seal key is not usable.
 * MINTING TOUCHES NO STORE: nothing is written anywhere, so the link's first
 * download never waits on one.
 */
export async function mintSaveLink(
  env: Env,
  userId: string,
  key: string,
  sizeBytes: number,
  nowMs: number,
): Promise<MintedLink | null> {
  if (!underStagingPrefix(userId, key)) return null;
  const name = key.slice(STAGING_PREFIX.length + userId.length + 1);
  if (!isSavedName(name)) return null;
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) return null;
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) return null;

  const cryptoKey = await sealKey(env);
  if (cryptoKey === null) return null;

  const expiresAtMs = nowMs + SAVE_LINK_TTL_MS;
  const payload = JSON.stringify({ v: LINK_VERSION, u: userId, k: name, e: expiresAtMs, s: sizeBytes });
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  let sealed: Uint8Array;
  try {
    sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: SEAL_AAD },
        cryptoKey,
        new TextEncoder().encode(payload),
      ),
    );
  } catch {
    return null;
  }

  const joined = new Uint8Array(IV_BYTES + sealed.byteLength);
  joined.set(iv, 0);
  joined.set(sealed, IV_BYTES);
  const token = base64UrlFromBytes(joined);
  return { url: `https://${DEPLOYED_HOSTNAME}${SAVE_ROUTE_PATH}${token}`, expiresAtMs };
}

/** The sealed payload, checked to be exactly the shape a mint writes. */
function parsedPayload(
  text: string,
): { userId: string; name: string; expiresAtMs: number; sizeBytes: number } | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(",") !== "e,k,s,u,v") return null;
  if (record.v !== LINK_VERSION) return null;
  const { u, k, e, s } = record;
  if (typeof u !== "string" || !USER_SEGMENT.test(u)) return null;
  if (!isSavedName(k)) return null;
  if (typeof e !== "number" || !Number.isSafeInteger(e)) return null;
  if (typeof s !== "number" || !Number.isSafeInteger(s) || s < 0) return null;
  return { userId: u, name: k as string, expiresAtMs: e, sizeBytes: s };
}

/**
 * Open a link and, if it is live and unspent, spend it.
 *
 * Null for every bad link, with no reason given: a token outside the alphabet
 * or the length window (no store read and no crypto), an unusable seal key, a
 * token that does not unseal, a payload of any other shape, and a link that is
 * already spent. An expired link answers `expired`, with the copy's user id and
 * key, so the route can delete the copy.
 *
 * Otherwise the spent mark is WRITTEN, and only then is `live` returned. So
 * the mark is in place before any byte is served, and a download that fails
 * part-way still spends the link. That is the recoverable side: the person asks
 * for a new link.
 *
 * A store error is not caught here. The route answers it.
 */
export async function claimSaveLink(
  env: Env,
  token: string,
  nowMs: number,
): Promise<SaveClaim | null> {
  if (!hasSaveTokenShape(token)) return null;

  const cryptoKey = await sealKey(env);
  if (cryptoKey === null) return null;

  const joined = bytesFromBase64Url(token);
  if (joined === null || joined.byteLength <= IV_BYTES + TAG_BYTES) return null;
  // One spelling per link. The decoder ignores the unused bits of the last
  // character, so several tokens name the same bytes, and each would get its
  // own spent mark. Only the spelling a mint writes is accepted.
  if (base64UrlFromBytes(joined) !== token) return null;

  let opened: ArrayBuffer;
  try {
    opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: joined.slice(0, IV_BYTES), additionalData: SEAL_AAD },
      cryptoKey,
      joined.slice(IV_BYTES),
    );
  } catch {
    return null;
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(opened);
  } catch {
    return null;
  }
  const payload = parsedPayload(text);
  if (payload === null) return null;

  const userId = payload.userId;
  const key = `${STAGING_PREFIX}${userId}/${payload.name}`;
  if (!underStagingPrefix(userId, key)) return null;

  if (payload.expiresAtMs <= nowMs) return { state: "expired", userId, key };

  const mark = await spentMarkKey(token);
  if ((await env.SAVE_LINK_KV.get(mark)) !== null) return null;
  await env.SAVE_LINK_KV.put(mark, "1", { expirationTtl: SPENT_MARK_TTL_SECONDS });
  return { state: "live", userId, key, sizeBytes: payload.sizeBytes };
}
