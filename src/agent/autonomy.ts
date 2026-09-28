// The autonomy key, inside the person's own Durable Object (Phase 27).
//
// Autonomy is inherent (owner, 2026-09-27). Every interactive sign-in also
// mints a second grant, for the autonomy client, and hands its one-time code to
// the person's object. The object exchanges the code here, seals the refresh
// token and keeps it under one key, `autonomy`. So every person who has signed
// in since autonomy was set up, and is still connected, has one sealed record
// here. The long-lived token is born inside the object and never exists in the
// sign-in's memory.
//
// WHAT THE KEY IS. The refresh token of the autonomy grant. It opens that one
// grant and nothing else. It is sealed with AES-GCM under a Worker secret, and
// the seal is tied to the person's user id, so a record copied into another
// person's object does not open there. Reading every store this server has
// opens nothing, because the seal key is in no store.
//
// NO TIMER OF ITS OWN (D-33, owner's answers of 2026-09-27). The key lives
// exactly as long as the person's ordinary connection. The record carries no
// expiry, the grant carries none, and no code here sets one. The standing
// check in `withAutonomySession` ends the key with the ordinary connection, at
// the next use at the latest, and `autonomyAlarmJob` asks the same question on
// the object's alarm, so a key nobody uses ends within a day.
//
// THE ORDER OF A SESSION, and why. `withAutonomySession` is the one way to use
// the key (D-31). It asks the allow list FIRST, by user id, from the seed and
// then the store, before the record is read at all (AUTO-05). A person who is
// not admitted is refused, and the record is KEPT: the store reader turns a
// store error into "nobody", so a refusal cannot tell a removal from a blip,
// and deleting on a blip would end every person's key at once. Only then is
// the record read, unsealed and redeemed once at this Worker's own token
// endpoint. What the session hands its caller is a function that calls one
// tool at this Worker's own `/mcp`. The bearer is never handed out.
//
// NOTHING SECRET LEAVES THIS MODULE. No function returns a token or a bearer.
// No token is stored unsealed. Outcomes are small fixed shapes, and the grant
// id is the most any of them carries.
//
// WHAT THIS MODULE NEVER DOES. It never reads a grant's props. It never calls
// the OAuth library's token-unwrapping helper, which hands back decrypted
// props. It never touches the password, never builds a principal, and never
// writes to the sign-in store except through the token endpoint, which is the
// library's own code. It reaches this Worker only through the fetch seam its
// caller hands in, at URLs built from the deployed hostname and exact paths
// (SPIKE-08). It never reads the platform's name for the object and never takes
// a name from a caller: the name is the one the object stored for itself (Phase
// 25, D-22).
//
// Every `catch` below answers a fixed outcome and never reads what it caught.
// This module logs nothing (./.claude/CLAUDE.md §4).

import { parseAllowList, readStoredAllowList, type AllowList } from "../auth/allow-list";
import { isConfiguredSecret } from "../configured-secret";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import type { Env } from "../env";
import { userIdOf } from "../principal";
import {
  AUTONOMY_CLIENT_ID,
  AUTONOMY_REDIRECT_PATH,
  AUTONOMY_TOOLS,
} from "./autonomy-client";
import {
  type KeyStanding,
  keyStandingFor,
  revokeAutonomyGrant,
  sweepAutonomyGrants,
} from "./autonomy-grants";

/** The object's key-value key for the one autonomy record. */
export const AUTONOMY_KEY = "autonomy";

/** The version tag on the seal's additional data. Bumping it opens nothing old. */
const SEAL_AAD_PREFIX = "autonomy:v1:";

/** AES-GCM key length the seal key must decode to, in bytes (256 bits). */
const SEAL_KEY_BYTES = 32;

/** AES-GCM IV length, in bytes (96 bits), fresh for every seal. */
const SEAL_IV_BYTES = 12;

/** This Worker's token endpoint, built from the deployed hostname (SPIKE-08). */
const TOKEN_URL = `https://${DEPLOYED_HOSTNAME}/oauth/token`;

/** This Worker's MCP endpoint. Exactly `/mcp`: a longer path is a 404 (SPIKE-08). */
const MCP_URL = `https://${DEPLOYED_HOSTNAME}/mcp`;

/** The autonomy client's one redirect URI, never served (D-29). */
const AUTONOMY_REDIRECT_URI = `https://${DEPLOYED_HOSTNAME}${AUTONOMY_REDIRECT_PATH}`;

/** The MCP protocol version the tool call is made under, as the door expects. */
const MCP_PROTOCOL_VERSION = "2026-07-28";

/**
 * For this long after a key is armed, in seconds, the standing check is
 * skipped (D-33).
 *
 * The sign-in that armed the key had just made the person's ordinary grant, and
 * the sign-in store's listing can lag behind a fresh write by about a minute. A
 * check made in that window could read "no ordinary grant" and end a key that
 * is fine. Ten minutes is well past the lag, and a key this new was proved to
 * work at arming.
 */
export const STANDING_GRACE_SECONDS = 600;

/**
 * The one stored record (D-10, as revised 2026-09-27).
 *
 * No address, no password, no plaintext token and no expiry. Times are in
 * seconds. `generation` starts at 1 and each arming writes one more than the
 * record it replaced, so a later write can tell whether the record it read is
 * still the one stored (`stillStored` below).
 */
export interface AutonomyRecord {
  readonly v: 1;
  readonly grantId: string;
  readonly sealedRefreshToken: string;
  readonly iv: string;
  readonly armedAt: number;
  readonly generation: number;
}

/** The object's synchronous key-value storage, as much of it as this module uses. */
export interface AutonomyStorage {
  get<T = unknown>(key: string): T | undefined;
  put<T>(key: string, value: T): void;
  delete(key: string): boolean;
}

/** The bindings this module reads. Nothing holding them is ever returned. */
export type AutonomyEnv = Pick<
  Env,
  | "ALLOWED_APPLE_IDS_SEED"
  | "ALLOW_LIST_KV"
  | "AUTONOMY_CLIENT_SECRET"
  | "AUTONOMY_SEAL_KEY"
  | "OAUTH_KV"
>;

/**
 * Everything a session or an arming needs, handed in by the object.
 *
 * `name` is the object's own stored name, which is the person's user id:
 * `rememberOwnName()` in an RPC method, `storedOwnName()` in the alarm.
 * `selfFetch` is the object's one seam to this Worker. `now` answers
 * milliseconds since the epoch.
 *
 * `keyStanding` asks whether the key whose grant is `grantId` still stands
 * (D-33). Left out, it asks the library through `keyStandingFor` over
 * `env.OAUTH_KV`. It exists so tests can answer for the listing.
 *
 * `pendingArms` answers the grant ids whose arm is waiting in the object's
 * queue right now: other sign-ins, still in flight. No sweep revokes one of
 * them (D-27). Left out, nothing is pending.
 */
export interface AutonomyDeps {
  readonly storage: AutonomyStorage;
  readonly name: string;
  readonly env: AutonomyEnv;
  readonly selfFetch: (request: Request) => Promise<Response>;
  readonly now: () => number;
  readonly keyStanding?: (grantId: string) => Promise<KeyStanding>;
  readonly pendingArms?: () => ReadonlySet<string>;
}

/**
 * Runs one autonomy operation at a time (D-27).
 *
 * Each `run` waits for the one before it to settle, then runs. A rejection in
 * one never blocks the next. A second caller waits and then runs its own
 * operation; it never shares the first one's result.
 */
export interface AutonomyQueue {
  run<T>(operation: () => Promise<T>): Promise<T>;
}

/** A fresh, empty queue. The object holds exactly one. */
export function oneAtATime(): AutonomyQueue {
  let tail: Promise<void> = Promise.resolve();
  return {
    run<T>(operation: () => Promise<T>): Promise<T> {
      const result = tail.then(operation);
      tail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
}

/** What one tool call through the key answers. Never the bearer. */
export type AutonomyCallOutcome = { kind: "ok"; result: unknown } | { kind: "failed" };

/** The one function a session hands its caller. */
export type AutonomyCall = (
  tool: string,
  args: Record<string, unknown>,
) => Promise<AutonomyCallOutcome>;

/**
 * What a session answers. Exactly these five kinds, and no expiry kind: the key
 * has no timer (D-15 as revised).
 */
export type AutonomySessionOutcome<T> =
  | { kind: "ok"; value: T }
  | { kind: "not_allowed" }
  | { kind: "off" }
  | { kind: "revoked" }
  | { kind: "failed" };

/** What an arming answers. The grant id is the most it ever carries. */
export type ArmOutcome = { kind: "armed"; grantId: string } | { kind: "not_armed" };

// ------------------------------------------------------------------ the seal

/** Bytes from base64url with no padding, or null for anything else. */
function bytesFromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
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

/** Base64url with no padding. */
function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Whether `value` is a seal key the seal will accept: set, base64url with no
 * padding, and decoding to exactly 32 bytes.
 *
 * The ONE shape check for the seal key (review WR-03). The seal below asks it,
 * and so does the login handler's `autonomyConfigured`, which decides both the
 * sign-in notice and whether a sign-in mints an autonomy grant. Before this,
 * that predicate asked only whether the value was set. A value that was set
 * but the wrong shape (a hand-set value, standard base64, a 16-byte key) then
 * showed the notice, minted a grant on every sign-in, and failed every seal,
 * and each failed arm ended the key the person already had. One decoder for
 * both is what keeps the page and the seal from disagreeing again.
 */
export function sealKeyUsable(value: unknown): value is string {
  if (!isConfiguredSecret(value)) return false;
  const raw = bytesFromBase64Url(value);
  return raw !== null && raw.length === SEAL_KEY_BYTES;
}

/**
 * The seal key as a non-extractable AES-GCM key, or null.
 *
 * Refuses a key that does not decode to exactly 32 bytes. A short key would
 * still import as AES-128 or AES-192 and seal quietly with less than D-06
 * promises, so the length is checked here rather than trusted.
 */
async function sealKeyFrom(sealKey: unknown): Promise<CryptoKey | null> {
  if (!sealKeyUsable(sealKey)) return null;
  const raw = bytesFromBase64Url(sealKey);
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

/** The additional data that binds a sealed value to one person. */
function sealAad(userId: string): Uint8Array {
  return new TextEncoder().encode(`${SEAL_AAD_PREFIX}${userId}`);
}

/**
 * Seal a refresh token for one person (D-06).
 *
 * AES-GCM 256 under the seal key, a fresh 12-byte IV per call, and the
 * additional data `autonomy:v1:<userId>`, so the result opens only in that
 * person's object. Null when the key is unusable or the platform refuses.
 */
export async function seal(
  sealKey: unknown,
  userId: string,
  autonomyRefreshToken: string,
): Promise<{ sealedRefreshToken: string; iv: string } | null> {
  const key = await sealKeyFrom(sealKey);
  if (key === null) return null;
  const iv = crypto.getRandomValues(new Uint8Array(SEAL_IV_BYTES));
  try {
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: sealAad(userId) },
      key,
      new TextEncoder().encode(autonomyRefreshToken),
    );
    return {
      sealedRefreshToken: base64UrlFromBytes(new Uint8Array(sealed)),
      iv: base64UrlFromBytes(iv),
    };
  } catch {
    return null;
  }
}

/**
 * Open a sealed refresh token, or null.
 *
 * Every way this can fail is the same one outcome: a wrong key, another
 * person's additional data, a changed byte, a malformed field. Nothing is
 * thrown to the caller.
 */
export async function unseal(
  sealKey: unknown,
  userId: string,
  sealed: { sealedRefreshToken: string; iv: string },
): Promise<string | null> {
  const key = await sealKeyFrom(sealKey);
  if (key === null) return null;
  const iv = bytesFromBase64Url(sealed.iv);
  const data = bytesFromBase64Url(sealed.sealedRefreshToken);
  if (iv === null || iv.length !== SEAL_IV_BYTES || data === null) return null;
  try {
    const opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: sealAad(userId) },
      key,
      data,
    );
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(opened);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- the record

/**
 * Whether the stored record is still the one read before an `await`: the same
 * generation and the same grant (D-15 step 6, RESEARCH §7).
 *
 * The grant is compared as well as the generation because a record deleted
 * and armed afresh starts again at generation 1, and a new arm always carries
 * a new grant. The sealed token is deliberately NOT compared: a mismatch makes
 * the caller revoke its own fresh token, which revokes that token's whole
 * grant, and when the grant is the stored one that would end the live key.
 */
function stillStored(storage: AutonomyStorage, read: AutonomyRecord): boolean {
  const current = recordOf(storage.get<unknown>(AUTONOMY_KEY));
  return current !== null && current.generation === read.generation && current.grantId === read.grantId;
}

/**
 * Delete the record only if it is still the one read before an `await`.
 * Synchronous: the check and the delete have nothing between them. With
 * nothing read, there is nothing of this caller's to delete.
 */
function deleteIfStill(storage: AutonomyStorage, read: AutonomyRecord | null): void {
  if (read !== null && stillStored(storage, read)) storage.delete(AUTONOMY_KEY);
}

/** `value` as a record, or null when it is not exactly one. */
export function recordOf(value: unknown): AutonomyRecord | null {
  if (typeof value !== "object" || value === null) return null;
  const r = value as Partial<Record<keyof AutonomyRecord, unknown>>;
  if (r.v !== 1) return null;
  if (typeof r.grantId !== "string" || r.grantId.length === 0) return null;
  if (typeof r.sealedRefreshToken !== "string" || typeof r.iv !== "string") return null;
  if (typeof r.armedAt !== "number" || !Number.isFinite(r.armedAt)) return null;
  if (typeof r.generation !== "number" || !Number.isSafeInteger(r.generation)) return null;
  if (r.generation < 1) return null;
  return {
    v: 1,
    grantId: r.grantId,
    sealedRefreshToken: r.sealedRefreshToken,
    iv: r.iv,
    armedAt: r.armedAt,
    generation: r.generation,
  };
}

// ------------------------------------------------------ the token endpoint

/**
 * A request to this Worker's token endpoint, as the autonomy client (D-07).
 *
 * Form-encoded, with `client_secret_basic`: the id and the secret are each
 * form-encoded, joined with a colon, then base64, as RFC 6749 §2.3.1 says and
 * as the library decodes them.
 */
function tokenRequest(clientSecret: string, fields: Record<string, string>): Request {
  const basic = btoa(
    `${encodeURIComponent(AUTONOMY_CLIENT_ID)}:${encodeURIComponent(clientSecret)}`,
  );
  return new Request(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams(fields).toString(),
  });
}

/**
 * What the token endpoint answered, read once.
 *
 * `final` is `invalid_grant` or `invalid_client`: the grant, the token or the
 * client is gone, and no retry can bring it back. `failed` is everything else
 * that is not a success. `ok` carries the parsed body, which holds tokens, so
 * a caller takes what it needs out of it at once and keeps nothing else.
 */
async function readTokenAnswer(
  response: Response,
): Promise<{ kind: "ok"; body: Record<string, unknown> } | { kind: "final" } | { kind: "failed" }> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { kind: "failed" };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { kind: "failed" };
  const parsed = body as Record<string, unknown>;
  if (response.ok) return { kind: "ok", body: parsed };
  if (parsed.error === "invalid_grant" || parsed.error === "invalid_client") return { kind: "final" };
  return { kind: "failed" };
}

/**
 * Revoke one autonomy refresh token at the token endpoint, which revokes its
 * whole grant. Never throws. The endpoint always answers 200 (RFC 7009), so the
 * answer says nothing and is only drained.
 */
async function revokeAtEndpoint(
  deps: AutonomyDeps,
  clientSecret: string,
  autonomyRefreshToken: string,
): Promise<void> {
  try {
    const response = await deps.selfFetch(
      tokenRequest(clientSecret, { token: autonomyRefreshToken, token_type_hint: "refresh_token" }),
    );
    await response.arrayBuffer();
  } catch {
    // Nothing to do. The sign-in also revokes the grant it minted when the
    // arm did not report it armed.
  }
}

// ------------------------------------------------------------ the allow list

/** Whether `list` admits the person whose user id is `name`. Serial, never a combinator. */
async function listAdmits(list: AllowList, name: string): Promise<boolean> {
  if (list.kind === "everybody") return true;
  if (list.kind === "nobody") return false;
  for (const address of list.addresses) {
    if ((await userIdOf(address)) === name) return true;
  }
  return false;
}

/**
 * The allow-list verdict for the object's own user id: the seed first, then
 * the store, and either admitting is enough, the same rule the sign-in page
 * uses. The store is not read when the seed already admits.
 */
async function admitted(deps: AutonomyDeps): Promise<boolean> {
  if (await listAdmits(parseAllowList(deps.env.ALLOWED_APPLE_IDS_SEED), deps.name)) return true;
  return listAdmits(await readStoredAllowList(deps.env.ALLOW_LIST_KV), deps.name);
}

// ------------------------------------------------------- the standing check

/**
 * Whether the key whose grant is `grantId` still stands, through the seam when
 * one was handed in. Anything thrown is `unknown`, which ends nothing.
 */
async function standingOf(deps: AutonomyDeps, grantId: string): Promise<KeyStanding> {
  try {
    if (deps.keyStanding !== undefined) return await deps.keyStanding(grantId);
    return await keyStandingFor(deps.env.OAUTH_KV, deps.name, grantId);
  } catch {
    return "unknown";
  }
}

/** The grant ids whose arm is waiting in the object's queue. */
function pendingOf(deps: AutonomyDeps): ReadonlySet<string> {
  try {
    return deps.pendingArms?.() ?? new Set();
  } catch {
    return new Set();
  }
}

/** Whether a record armed at `armedAt` (seconds) is still inside the grace. */
function insideGrace(deps: AutonomyDeps, armedAt: number): boolean {
  const age = Math.floor(deps.now() / 1000) - armedAt;
  return age >= 0 && age < STANDING_GRACE_SECONDS;
}

// -------------------------------------------------------------- the session

/** The JSON-RPC message with id `id` in an MCP answer, on either lane, or null. */
function rpcMessageWithId(bodyText: string, id: number): Record<string, unknown> | null {
  const trimmed = bodyText.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed) &&
        (parsed as { id?: unknown }).id === id
      ) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  return null;
}

/**
 * Use the autonomy key once (D-15, D-31). The one way to use it.
 *
 * In this order and no other:
 *   1. The allow list, seed then store, by the object's own user id. Not
 *      admitted answers `not_allowed`: the record is not read and not touched.
 *   2. Both autonomy secrets must be set. Not set answers `failed` and keeps
 *      the record: an unset secret is a server fault, not a revocation.
 *   3. The record. Absent answers `off`. Malformed is deleted, `off`.
 *   3a. The standing check (D-33), unless the key was armed less than
 *      `STANDING_GRACE_SECONDS` ago. `revoked` or `connection_ended` sweeps
 *      every autonomy grant, deletes the record and answers `revoked`, with no
 *      token-endpoint call. `unknown` answers `failed` and keeps the record.
 *   4. Unseal. Any failure deletes the record, `off`.
 *   5. One refresh at the token endpoint. `invalid_grant` or `invalid_client`
 *      deletes the record, `revoked`, with no retry. Anything else that is not
 *      a success answers `failed` and keeps the record.
 *   6. The rotated token is sealed and written at once, before the access
 *      token is used for anything, and only if the record is still the one
 *      read in step 3 (same generation, same grant). Otherwise the fresh
 *      token is revoked and the answer is `off`. The seal itself is the one `await` between
 *      the parsed answer and the write, because the platform's cipher has no
 *      synchronous form.
 *   7. `use` is handed one function, `call(tool, args)`. It refuses any tool
 *      not in `AUTONOMY_TOOLS` without making a request, and stops working
 *      once `use` has returned.
 *
 * The bearer lives in one variable, `autonomyAccessToken`, inside this
 * function. It is never returned, stored, or handed to `use`.
 */
export async function withAutonomySession<T>(
  deps: AutonomyDeps,
  use: (call: AutonomyCall) => Promise<T>,
): Promise<AutonomySessionOutcome<T>> {
  try {
    if (!(await admitted(deps))) return { kind: "not_allowed" };

    const clientSecret = deps.env.AUTONOMY_CLIENT_SECRET;
    const sealKey = deps.env.AUTONOMY_SEAL_KEY;
    if (!isConfiguredSecret(clientSecret) || !isConfiguredSecret(sealKey)) {
      return { kind: "failed" };
    }

    const stored = deps.storage.get<unknown>(AUTONOMY_KEY);
    if (stored === undefined) return { kind: "off" };
    const record = recordOf(stored);
    if (record === null) {
      deps.storage.delete(AUTONOMY_KEY);
      return { kind: "off" };
    }

    // THE STANDING CHECK (D-33). The owner's answer is that the key lives
    // exactly as long as the person's ordinary connection. Nothing tells this
    // object when that connection ends: grants are revoked from the owner's
    // terminal or by the person's Claude app, and neither can reach it. So the
    // key asks, here, before it is unsealed, and this is what makes it end at
    // the next use at the latest. Plan 27-05's alarm job asks the same question
    // so that a key nobody uses ends within a day.
    //
    // `unknown` ends nothing: a listing error must not end every person's key
    // at once. It answers `failed`, and the record is kept.
    if (!insideGrace(deps, record.armedAt)) {
      const standing = await standingOf(deps, record.grantId);
      if (standing === "unknown") return { kind: "failed" };
      if (standing !== "standing") {
        await sweepAutonomyGrants(deps.env.OAUTH_KV, deps.name, null, pendingOf(deps));
        deleteIfStill(deps.storage, record);
        return { kind: "revoked" };
      }
    }

    const autonomyRefreshToken = await unseal(sealKey, deps.name, record);
    if (autonomyRefreshToken === null) {
      deleteIfStill(deps.storage, record);
      return { kind: "off" };
    }

    // One at a time (D-27). This function never enters the object's queue
    // itself, because the arm's proof calls it from inside the queue. Every
    // caller outside an arm (plan 27-05's alarm job, Phase 28's job) enters
    // through `autonomyQueue.run` in the object. The generation checks below
    // hold even for a caller that did not.

    let answer: Awaited<ReturnType<typeof readTokenAnswer>>;
    try {
      const response = await deps.selfFetch(
        tokenRequest(clientSecret, {
          grant_type: "refresh_token",
          refresh_token: autonomyRefreshToken,
        }),
      );
      answer = await readTokenAnswer(response);
    } catch {
      return { kind: "failed" };
    }
    if (answer.kind === "final") {
      deleteIfStill(deps.storage, record);
      return { kind: "revoked" };
    }
    if (answer.kind !== "ok") return { kind: "failed" };

    const autonomyAccessToken = answer.body.access_token;
    const rotated = answer.body.refresh_token;
    if (typeof autonomyAccessToken !== "string" || typeof rotated !== "string") {
      return { kind: "failed" };
    }

    const resealed = await seal(sealKey, deps.name, rotated);
    if (resealed === null) return { kind: "failed" };
    // THE GENERATION CHECK (D-15 step 6). The record may have been replaced by
    // a new arm, or deleted, while the refresh was out. Writing the rotated
    // token back then would bring back a key that was ended or replaced. So the
    // write happens only if the record is still the one read above; otherwise
    // the fresh token is revoked and this session answers `off`. The check and
    // the write below are synchronous, with no `await` between them.
    if (!stillStored(deps.storage, record)) {
      await revokeAtEndpoint(deps, clientSecret, rotated);
      return { kind: "off" };
    }
    deps.storage.put<AutonomyRecord>(AUTONOMY_KEY, {
      ...record,
      sealedRefreshToken: resealed.sealedRefreshToken,
      iv: resealed.iv,
    });

    let open = true;
    let nextId = 1;
    const call: AutonomyCall = async (tool, args) => {
      if (!open || !AUTONOMY_TOOLS.includes(tool)) return { kind: "failed" };
      const id = nextId;
      nextId += 1;
      try {
        const response = await deps.selfFetch(
          new Request(MCP_URL, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
              host: DEPLOYED_HOSTNAME,
              "Mcp-Method": "tools/call",
              "Mcp-Name": tool,
              authorization: `Bearer ${autonomyAccessToken}`,
            },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id,
              method: "tools/call",
              params: {
                name: tool,
                arguments: args,
                _meta: {
                  "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                  "io.modelcontextprotocol/clientCapabilities": {},
                },
              },
            }),
          }),
        );
        const text = await response.text();
        if (!response.ok) return { kind: "failed" };
        const message = rpcMessageWithId(text, id);
        if (message === null || !("result" in message)) return { kind: "failed" };
        const result = message.result;
        if (typeof result === "object" && result !== null && (result as { isError?: unknown }).isError === true) {
          return { kind: "failed" };
        }
        return { kind: "ok", result };
      } catch {
        return { kind: "failed" };
      }
    };

    try {
      const value = await use(call);
      return { kind: "ok", value };
    } finally {
      open = false;
    }
  } catch {
    return { kind: "failed" };
  }
}

// ---------------------------------------------------------------- arming

/**
 * Whether an `account_whoami` answer names the person whose user id is `name`.
 * The address is used for this comparison and nothing else.
 */
async function answersAs(result: unknown, name: string): Promise<boolean> {
  try {
    const content = (result as { content?: unknown }).content;
    if (!Array.isArray(content)) return false;
    const text = (content[0] as { text?: unknown } | undefined)?.text;
    if (typeof text !== "string") return false;
    const signedInAs = (JSON.parse(text) as { signedInAs?: unknown }).signedInAs;
    if (typeof signedInAs !== "string") return false;
    return (await userIdOf(signedInAs)) === name;
  } catch {
    return false;
  }
}

/**
 * Arm the key from a one-time code (D-09, D-10, D-11, D-13, D-28).
 *
 * Refuses (`not_armed`), and changes nothing, unless both autonomy secrets are
 * set and the code's user segment is the object's own name, so a wiring
 * mistake refuses rather than arming the wrong person's object. Then: exchange
 * the code at this Worker's token endpoint; take the grant id from the refresh
 * token; seal it; write the record, with `generation` one more than any record
 * it replaces; prove it, with one session that calls `account_whoami` and
 * checks the answer is this person; and sweep every other autonomy grant this
 * person holds.
 *
 * FAILS TOWARD OFF (D-11). Once the input checks have passed, any failure,
 * before or after the exchange, revokes the new token if one exists, deletes
 * the record, and sweeps EVERY autonomy grant, and answers `not_armed`. That
 * ends the key the person already had, too. A key that could not be re-armed
 * at this sign-in is not one to keep trusting, and the person's next sign-in
 * arms again.
 */
export async function armWith(deps: AutonomyDeps, code: string): Promise<ArmOutcome> {
  const clientSecret = deps.env.AUTONOMY_CLIENT_SECRET;
  const sealKey = deps.env.AUTONOMY_SEAL_KEY;
  // A seal key the seal would refuse is an input check too (review WR-03): the
  // arm could only fail at the seal, and failing there would end the key the
  // person already had over a server fault.
  if (!isConfiguredSecret(clientSecret) || !sealKeyUsable(sealKey)) {
    return { kind: "not_armed" };
  }
  const codeParts = code.split(":");
  if (codeParts.length !== 3 || typeof deps.name !== "string" || codeParts[0] !== deps.name) {
    return { kind: "not_armed" };
  }

  // Set once the exchange has handed back a token. Every failure after that
  // revokes it.
  let autonomyRefreshToken: string | null = null;

  // The record as this arm last knew it: the one there before it started, then
  // the one it wrote. A delete after an `await` removes only that record.
  let known = recordOf(deps.storage.get<unknown>(AUTONOMY_KEY));

  // Other sign-ins' arms, waiting in the queue behind this one. The sweeps
  // leave their grants alone, because each is about to be armed (D-27). This
  // arm's own grant is never among them.
  const othersPending = (): ReadonlySet<string> => {
    const others = new Set(pendingOf(deps));
    others.delete(codeParts[1] ?? "");
    return others;
  };

  const fail = async (): Promise<ArmOutcome> => {
    if (autonomyRefreshToken !== null) {
      await revokeAtEndpoint(deps, clientSecret, autonomyRefreshToken);
    }
    deleteIfStill(deps.storage, known);
    await sweepAutonomyGrants(deps.env.OAUTH_KV, deps.name, null, othersPending());
    return { kind: "not_armed" };
  };

  try {
    let answer: Awaited<ReturnType<typeof readTokenAnswer>>;
    try {
      const response = await deps.selfFetch(
        tokenRequest(clientSecret, {
          grant_type: "authorization_code",
          code,
          redirect_uri: AUTONOMY_REDIRECT_URI,
        }),
      );
      answer = await readTokenAnswer(response);
    } catch {
      return await fail();
    }
    if (answer.kind !== "ok") return await fail();
    const exchanged = answer.body.refresh_token;
    if (typeof exchanged !== "string") return await fail();
    autonomyRefreshToken = exchanged;

    const tokenParts = exchanged.split(":");
    const grantId = tokenParts[1];
    if (tokenParts.length !== 3 || tokenParts[0] !== deps.name || grantId !== codeParts[1]) {
      return await fail();
    }
    if (grantId === undefined || grantId.length === 0) return await fail();

    const sealed = await seal(sealKey, deps.name, exchanged);
    if (sealed === null) return await fail();

    const previous = recordOf(deps.storage.get<unknown>(AUTONOMY_KEY));
    const written: AutonomyRecord = {
      v: 1,
      grantId,
      sealedRefreshToken: sealed.sealedRefreshToken,
      iv: sealed.iv,
      armedAt: Math.floor(deps.now() / 1000),
      generation: (previous?.generation ?? 0) + 1,
    };
    deps.storage.put<AutonomyRecord>(AUTONOMY_KEY, written);
    known = written;

    const proof = await withAutonomySession(deps, (call) => call("account_whoami", {}));
    if (proof.kind !== "ok" || proof.value.kind !== "ok") return await fail();
    if (!(await answersAs(proof.value.result, deps.name))) return await fail();

    // The replaced grant, revoked BY ID (review WR-02). The record this arm
    // replaced names it, so no listing is needed to find it, and the listing
    // can lag: under a double-submitted sign-in form, that grant was written
    // about 1.4 seconds ago and is often not listed yet. A grant whose arm is
    // still waiting in the queue is left alone, as the sweep leaves it.
    if (
      previous !== null &&
      previous.grantId !== grantId &&
      !othersPending().has(previous.grantId)
    ) {
      await revokeAutonomyGrant(deps.env.OAUTH_KV, deps.name, previous.grantId);
    }

    // The sweep (D-13, D-28): every other autonomy grant this person holds is
    // revoked, so at most one survives any sign-in. It lists rather than
    // trusting the record it replaced, so a grant minted and never armed is
    // caught too. It is the backstop to the revoke above, not the only way the
    // replaced grant ends. An incomplete sweep does not fail the arm.
    await sweepAutonomyGrants(deps.env.OAUTH_KV, deps.name, grantId, othersPending());
    return { kind: "armed", grantId };
  } catch {
    return await fail();
  }
}

// ------------------------------------------------------------ the alarm job

/** How far ahead the alarm job wants the next run while a key is held: one day. */
export const AUTONOMY_ALARM_INTERVAL_MS = 86400000;

/** When the alarm job wants to run again after it could not finish: one hour. */
export const AUTONOMY_ALARM_RETRY_MS = 3600000;

/**
 * Everything the alarm job needs, handed in by the object.
 *
 * `name` is the object's stored own name, from `storedOwnName()`. The job never
 * looks for a name itself. `keyStanding` is 27-02's `keyStandingFor` over the
 * sign-in store, and `sweep` is 27-02's `sweepAutonomyGrants` keeping no grant.
 * Both are seams on the object, so tests can answer for the listing. `now`
 * answers milliseconds since the epoch.
 */
export interface AutonomyAlarmDeps {
  readonly storage: AutonomyStorage;
  readonly name: string;
  readonly keyStanding: (name: string, grantId: string) => Promise<KeyStanding>;
  readonly sweep: (name: string) => Promise<unknown>;
  readonly now: () => number;
}

/**
 * What the alarm job did, and when it next wants to run.
 *
 * `none`: no record. `kept`: the record stays. `ended`: the record was deleted.
 * `failed`: something threw, and the record was not touched. `wantedAt` is
 * milliseconds since the epoch, or null when the job has nothing left to do.
 */
export interface AutonomyAlarmOutcome {
  readonly kind: "none" | "kept" | "ended" | "failed";
  readonly wantedAt: number | null;
}

/**
 * The autonomy job on the object's one alarm (27-05, D-25, D-33, AUTO-04,
 * AUTO-06 as revised).
 *
 * WHY IT RUNS AT ALL, when every session already asks the same question. The
 * owner's answer is that the key lives exactly as long as the person's ordinary
 * connection. A session asks only when the key is used, and a key nobody uses
 * would then outlive the connection forever. So the alarm asks too, at least
 * once a day while a record exists, and a key nobody uses still ends within a
 * day.
 *
 * WHY IT NEEDS NO ALLOW-LIST CHECK. It reads the record's grant id and
 * `armedAt`, and nothing else. It never unseals the token, never redeems it and
 * never makes a call to this Worker. The allow-list check guards USING the key;
 * this job only decides whether to throw it away.
 *
 * In order:
 *   1. No record: nothing to do, no time wanted. A malformed record is deleted,
 *      the same as a session does.
 *   2. Inside the grace after arming (`STANDING_GRACE_SECONDS`): kept, without
 *      asking. The store's listing can lag behind the sign-in that armed it.
 *   3. Otherwise the standing question (D-33). `revoked` or `connection_ended`
 *      sweeps every autonomy grant this person holds, then deletes the record
 *      only if it is still the one read (D-27), and wants no time. `standing`
 *      or `unknown` keeps it and wants one day from now: a listing error must
 *      not end every person's key at once.
 *
 * There is no expiry and no timer. The key ends only when its grant is gone or
 * the person holds no ordinary grant. Never throws: every `catch` answers a
 * fixed outcome and never reads what it caught. The object runs this inside
 * its one autonomy queue.
 */
export async function autonomyAlarmJob(deps: AutonomyAlarmDeps): Promise<AutonomyAlarmOutcome> {
  let now: number;
  try {
    now = deps.now();
  } catch {
    now = Date.now();
  }
  try {
    const stored = deps.storage.get<unknown>(AUTONOMY_KEY);
    if (stored === undefined) return { kind: "none", wantedAt: null };
    const record = recordOf(stored);
    if (record === null) {
      deps.storage.delete(AUTONOMY_KEY);
      return { kind: "ended", wantedAt: null };
    }

    const age = Math.floor(now / 1000) - record.armedAt;
    if (age >= 0 && age < STANDING_GRACE_SECONDS) {
      return { kind: "kept", wantedAt: now + AUTONOMY_ALARM_INTERVAL_MS };
    }

    let standing: KeyStanding;
    try {
      standing = await deps.keyStanding(deps.name, record.grantId);
    } catch {
      standing = "unknown";
    }
    if (standing === "revoked" || standing === "connection_ended") {
      try {
        await deps.sweep(deps.name);
      } catch {
        // An incomplete sweep still ends the key. A stray autonomy grant opens
        // nothing without the record, and the next arm sweeps again.
      }
      deleteIfStill(deps.storage, record);
      return { kind: "ended", wantedAt: null };
    }
    return { kind: "kept", wantedAt: now + AUTONOMY_ALARM_INTERVAL_MS };
  } catch {
    return { kind: "failed", wantedAt: now + AUTONOMY_ALARM_RETRY_MS };
  }
}

// ---------------------------------------------------------------- disarming

/**
 * End the key from inside the object (D-16 as revised).
 *
 * If a record exists and unseals, its token is revoked at the token endpoint,
 * which revokes the whole grant (best effort: the endpoint answers 200 either
 * way). Then the record is deleted. A record that does not unseal is only
 * deleted. Always answers `off`.
 *
 * A module function and never an RPC method: nothing outside the object turns
 * autonomy off, because there is no user switch (owner, 2026-09-27). Its
 * caller is Phase 28's second-failure rule. The alarm job does not use it: the
 * revoke here is a call to this Worker, and the alarm job makes none. A caller
 * inside the object calls `scheduleAlarm` after it, so the alarm goes when no
 * job is left.
 */
export async function disarmWith(deps: AutonomyDeps): Promise<{ kind: "off" }> {
  try {
    const stored = deps.storage.get<unknown>(AUTONOMY_KEY);
    if (stored === undefined) return { kind: "off" };
    const record = recordOf(stored);
    if (record === null) {
      deps.storage.delete(AUTONOMY_KEY);
      return { kind: "off" };
    }
    const clientSecret = deps.env.AUTONOMY_CLIENT_SECRET;
    const autonomyRefreshToken = await unseal(deps.env.AUTONOMY_SEAL_KEY, deps.name, record);
    if (autonomyRefreshToken !== null && isConfiguredSecret(clientSecret)) {
      await revokeAtEndpoint(deps, clientSecret, autonomyRefreshToken);
    }
    deleteIfStill(deps.storage, record);
  } catch {
    // Nothing to read. The answer is the same.
  }
  return { kind: "off" };
}
