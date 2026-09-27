// The per-person Durable Object (Phase 24, D-01, D-03, D-05).
//
// One object per signed-in person. Phase 24 gave it ONE thing: a connection
// lease record, at storage key `lease`, of the shape `{ token, expiresAt }`.
// Phase 24 also said it holds no user id. That is no longer true, and is
// corrected here rather than left false: see the recall paragraph below. It
// still holds no address and no credential.
//
// It is a lease holder and never a session holder. It never opens a socket, and
// it never imports mail, DAV or tool code. The reason is cost and time, not
// tidiness. An open socket keeps a Durable Object resident and billed for up to
// 15 minutes per connection. And a socket held here would escape the 20-second
// call deadline that bounds every mail conversation in the Worker request
// (ARCHITECTURE §3.2). So the socket stays in the Worker request, and this
// object only records "this person has one conversation open until time T".
//
// Only one place builds a stub for it: `agentFor` in `./lease.ts`, from the
// signed-in principal's user id, through the namespace's by-name accessor. The
// namespace offers three other id helpers — the name-to-id helper, the
// string-to-id helper and the random-id helper. None of them is used under
// `src/`, and they are described here by role only because the scan reads
// comments too.
//
// Since Phase 25 it also holds the person's recall ledger: two SQLite tables
// listing every vector id they own in the recall index, with no text, no ref
// and no address (./recall-ledger.ts says why the ledger is mandatory). And it
// holds a copy of its own name, under `own-name` beside the lease, which is the
// person's user id as the platform gave it to `agentFor`. The alarm needs to
// know whose grants to ask about, and the platform's name is not documented as
// present inside an alarm.
//
// It still never opens a socket and never imports mail, DAV, tool or auth code.
//
// Recall is inherent (owner, 2026-09-27), so there is no switch here: no method
// that turns recall on or off, and no enabled flag. The first record for a
// person needs no earlier call.
//
// ONE ALARM SLOT, SHARED. An object has one alarm. Recall will be its first
// user (plan 25-03). Any later user folds its schedule into the same `alarm()`
// and the same scheduling helper, rather than setting the alarm itself, or one
// job silently drops the other's.
//
// This module logs nothing (./.claude/CLAUDE.md §4).

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { RECALL_MAX_VECTORS, RECALL_TTL_MS } from "../recall/retention";
import {
  countNewIds,
  countVectors,
  ensureRecallSchema,
  type LedgerRowInput,
  recordVectors,
  type RecordRefusal,
} from "./recall-ledger";

/**
 * How long a lease lasts, in milliseconds, from the moment it is granted.
 *
 * 30 000 = the call deadline (20 000) + the drain bound (2 000) + the close
 * bound (3 000) + a 5 000 margin. That is the longest a leased mail call can
 * keep its socket open once the work has started, plus room to spare. A test
 * pins this number to that sum, so raising the deadline forces a decision here.
 *
 * It is a literal, not an import of the three constants, because this module
 * must not import mail code. The test does the import instead.
 *
 * The object sets the expiry. The caller never chooses it, so a stale caller
 * cannot extend a lease.
 */
export const LEASE_TTL_MS = 30000;

/** The storage key of the lease record. */
const LEASE_KEY = "lease";

/** The storage key of the object's own name (Phase 25, D-22). */
const OWN_NAME_KEY = "own-name";

/** 64 lower-case hex characters: the shape of a user id and of a vector id. */
const HEX_64 = /^[0-9a-f]{64}$/;

/** The most rows one record may carry, the same as the store's batch ceiling. */
const MAX_RECORD_ROWS = 1000;

/** The most characters of a mailbox name in a ledger row. */
const MAX_MAILBOX_CHARS = 1024;

/** The answer to a record. Shapes, never throws: an error's class does not survive RPC. */
export type RecordAnswer = { ok: true } | { ok: false; reason: RecordRefusal };

/** `rows` as ledger rows, or null when any part of it is malformed. */
function validRows(rows: unknown): LedgerRowInput[] | null {
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > MAX_RECORD_ROWS) return null;
  const out: LedgerRowInput[] = [];
  for (const row of rows) {
    if (typeof row !== "object" || row === null) return null;
    const r = row as {
      vectorId?: unknown;
      mailbox?: unknown;
      uidValidity?: unknown;
      messageDate?: unknown;
    };
    if (typeof r.vectorId !== "string" || !HEX_64.test(r.vectorId)) return null;
    if (typeof r.mailbox !== "string" || r.mailbox.length < 1) return null;
    if (r.mailbox.length > MAX_MAILBOX_CHARS) return null;
    if (typeof r.uidValidity !== "number" || !Number.isSafeInteger(r.uidValidity)) return null;
    if (r.uidValidity < 0) return null;
    if (typeof r.messageDate !== "number" || !Number.isFinite(r.messageDate)) return null;
    out.push({
      vectorId: r.vectorId,
      mailbox: r.mailbox,
      uidValidity: r.uidValidity,
      messageDate: r.messageDate,
    });
  }
  return out;
}

/** What is stored while a lease is held. */
interface LeaseRecord {
  /** Minted per grant. A release must present it. */
  readonly token: string;
  /** Absolute time, in ms since the epoch, after which the lease is free. */
  readonly expiresAt: number;
}

/** The answer to an acquire that was granted. */
export interface LeaseGrant {
  readonly held: true;
  readonly token: string;
}

/** The answer to an acquire that found the lease already held. */
export interface LeaseRefusal {
  readonly held: false;
}

/** Either answer to an acquire. */
export type LeaseAnswer = LeaseGrant | LeaseRefusal;

/** Whether a stored value is a lease that has not yet expired. */
function isLive(record: unknown, now: number): boolean {
  if (typeof record !== "object" || record === null) return false;
  const expiresAt = (record as { expiresAt?: unknown }).expiresAt;
  return typeof expiresAt === "number" && expiresAt > now;
}

/**
 * One person's connection lease, and their recall ledger.
 *
 * RPC methods only: no `fetch`, no alarm yet, no constructor logic, no
 * location hint. Every method is synchronous on purpose. With no `await`
 * between the read and the write, the read-check-write is atomic under the
 * object's input gate, and the RPC reply is held back until the write is
 * durable.
 *
 * Helpers that must not be callable over RPC are arrow-function instance
 * properties. Workers RPC exposes prototype methods, whatever TypeScript's
 * `private` says, and never an instance property.
 */
export class UserAgent extends DurableObject<Env> {
  /**
   * The object's own name: stored once, then read back (D-22).
   *
   * The name is the person's user id as the platform gave it to the by-name
   * accessor in `agentFor` (src/agent/lease.ts). It never comes from a caller.
   * It is stored because the alarm (plan 25-03) must know whose grants to ask
   * about, and the platform's name is not documented as present inside an
   * alarm. It sits beside `lease` in the key-value storage, not in the recall
   * tables, because it is the object's identity and not recall data: a recall
   * destroy clears those tables and must not clear this. Phases 27 and 28 read
   * the same stored copy.
   *
   * A stored value is never overwritten. When nothing is stored and the
   * platform gives no name of the right shape, nothing is stored and the
   * answer is null. Synchronous, and never throws. This is the only place in
   * this module that reads the platform's id.
   */
  rememberOwnName = (): string | null => {
    const stored = this.ctx.storage.kv.get<unknown>(OWN_NAME_KEY);
    if (typeof stored === "string") return stored;
    const name: unknown = this.ctx.id.name;
    if (typeof name !== "string" || !HEX_64.test(name)) return null;
    this.ctx.storage.kv.put(OWN_NAME_KEY, name);
    return name;
  };

  /**
   * Record vector ids in this person's recall ledger, before they are written
   * to the store (D-07, D-08).
   *
   * Refuses, in this order: `unnamed` when the object has no stored name and
   * the platform gives none, so no ledger row can exist in an object that does
   * not know whose it is; `invalid` unless `rows` is 1 to 1000 well-formed rows;
   * `full` when the rows not yet held would take the ledger past
   * RECALL_MAX_VECTORS. Rows already held can always be re-recorded.
   *
   * The object sets each expiry itself, from the message date clamped to now.
   * No `await` anywhere, so the checks and the write are one atomic step.
   */
  recallRecord(rows: unknown): RecordAnswer {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    if (this.rememberOwnName() === null) return { ok: false, reason: "unnamed" };
    const valid = validRows(rows);
    if (valid === null) return { ok: false, reason: "invalid" };
    const fresh = countNewIds(
      sql,
      valid.map((row) => row.vectorId),
    );
    if (countVectors(sql) + fresh > RECALL_MAX_VECTORS) return { ok: false, reason: "full" };
    recordVectors(sql, valid, Date.now(), RECALL_TTL_MS);
    return { ok: true };
  }

  /**
   * Take the lease, or say it is held.
   *
   * A record that is missing, malformed or past its expiry is free, and is
   * replaced by a new grant with a new token. A live record is left exactly as
   * it was.
   */
  acquire(): LeaseAnswer {
    const now = Date.now();
    const current = this.ctx.storage.kv.get<unknown>(LEASE_KEY);
    if (isLive(current, now)) return { held: false };

    const token = crypto.randomUUID();
    const record: LeaseRecord = { token, expiresAt: now + LEASE_TTL_MS };
    this.ctx.storage.kv.put(LEASE_KEY, record);
    return { held: true, token };
  }

  /**
   * Give the lease back.
   *
   * Deletes the record only when `token` is the current holder's token. Any
   * other value, of any type, changes nothing and does not throw. So a late or
   * duplicate release, or one from a request whose lease already expired and
   * was granted to someone else, cannot free the newer holder's lease.
   */
  release(token: unknown): void {
    if (typeof token !== "string") return;
    const current = this.ctx.storage.kv.get<unknown>(LEASE_KEY);
    if (typeof current !== "object" || current === null) return;
    if ((current as { token?: unknown }).token !== token) return;
    this.ctx.storage.kv.delete(LEASE_KEY);
  }
}
