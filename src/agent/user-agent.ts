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
// ONE ALARM SLOT, SHARED. An object has one alarm, and recall is its first
// user. Its jobs today, in the order `alarm()` runs them: a pending destroy,
// then revocation, then expiry. Every set and every removal goes through one
// helper, `scheduleAlarm`, which removes the alarm only when `anyJobPending()`
// says no job is left and otherwise never moves a set alarm later. Phases 27
// and 28 fold their jobs into the same handler, the same helper and the same
// predicate. A second call that sets the alarm, or a second condition for
// removing it, would silently drop another job's schedule.
//
// This module logs nothing (./.claude/CLAUDE.md §4).

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { type RecallStore, recallStore } from "../recall/index";
import { type LedgerHandle, sweepExpired } from "../recall/lifecycle";
import {
  RECALL_MAX_PAGES_PER_DAY,
  RECALL_MAX_VECTORS,
  RECALL_PAGE_SIZE,
  RECALL_TTL_MS,
} from "../recall/retention";
import {
  clearCursor,
  clearPageSlot,
  countNewIds,
  countPageOn,
  countVectors,
  earliestExpiry,
  ensureRecallSchema,
  expiredIds,
  anyIds,
  forgetVectors,
  idsForMailbox,
  type LedgerRowInput,
  type MailboxRow,
  type PageRefusal,
  pagesOn,
  readCursor,
  readLastPageAt,
  readPageSlot,
  recordVectors,
  type RecordRefusal,
  utcDay,
  writeCursor,
  writeLastPageAt,
  writePageSlot,
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

/**
 * The least time between the start of one recall page and the next, per person
 * (Phase 25, D-15).
 *
 * This is what keeps a build from monopolising the person's one iCloud
 * connection: a page holds that connection for one read, at most once a
 * minute. The object enforces it, so no caller can shorten it; a caller that
 * comes back early is told `paused`.
 */
export const RECALL_PAGE_PAUSE_MS = 60000;

/**
 * How long an in-flight page blocks another, in milliseconds.
 *
 * Longer than the connection lease (30 s) plus an embed call and a store write,
 * so a live page is never overlapped. A page whose engine died stops blocking
 * after this, with no clean-up needed.
 */
export const RECALL_PAGE_TTL_MS = 120000;

/**
 * The latest the alarm is ever set, from now: one day (Phase 25, D-13, D-23).
 *
 * The alarm is also when revocation is noticed, so this is how late a person's
 * lost access can be noticed at most.
 */
export const RECALL_SWEEP_MAX_INTERVAL_MS = 86400000;

/**
 * When the alarm tries again after a failure: one hour.
 *
 * A thrown alarm handler is retried by the platform six times with backoff.
 * This project catches instead, never reads what it caught, and reschedules
 * through the one helper, so an earlier alarm is kept.
 */
export const RECALL_ALARM_RETRY_MS = 3600000;

/** When the alarm comes back while expired rows remain after a full sweep. */
const RECALL_SWEEP_AGAIN_MS = 60000;

/** The most characters of a stored build cursor. The object never decodes it. */
const MAX_CURSOR_CHARS = 2048;

/** The most ledger rows one scope read or one forget may touch. */
const MAX_SCOPE_ROWS = 1000;

/** The answer to a page start. Shapes, never throws. */
export type BeginPageAnswer =
  | { ok: true; pageToken: string; cursor: string | null }
  | { ok: false; reason: PageRefusal | "invalid" | "unnamed" };

/** What to do with a mailbox's cursor when a page ends. */
export type CursorUpdate =
  | { kind: "keep" }
  | { kind: "set"; cursor: string }
  | { kind: "reset" };

/** Whether `value` is a mailbox name the ledger accepts. */
function isMailbox(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= MAX_MAILBOX_CHARS;
}

/** `value` as a cursor update, or null when it is not exactly one. */
function cursorUpdateOf(value: unknown): CursorUpdate | null {
  if (typeof value !== "object" || value === null) return null;
  const u = value as { kind?: unknown; cursor?: unknown };
  if (u.kind === "keep") return { kind: "keep" };
  if (u.kind === "reset") return { kind: "reset" };
  if (u.kind === "set" && typeof u.cursor === "string") {
    if (u.cursor.length < 1 || u.cursor.length > MAX_CURSOR_CHARS) return null;
    return { kind: "set", cursor: u.cursor };
  }
  return null;
}

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
  // Every member below that is not an RPC method is an arrow-function instance
  // property. Workers RPC exposes every prototype method, whatever TypeScript's
  // `private` says, and never an instance property. So the store seam, the
  // scheduling helper, the predicate and the ledger handle cannot be called by
  // any Worker holding a stub.

  /**
   * The recall store this object deletes through. It exists so the object's
   * tests can substitute a fake store; production never overrides it.
   */
  vectorStore = (): RecallStore => recallStore();

  /**
   * Whether the object has any job for its one alarm.
   *
   * THIS IS THE ONE CONDITION FOR KEEPING THE ALARM. Today the job is recall's:
   * a ledger row exists. A later phase with a job on this alarm adds its job
   * here, in this function, and nowhere else (Phases 27 and 28 will). A second
   * condition written beside this one would let one job remove the alarm
   * another job still needs.
   */
  anyJobPending = (): boolean => {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    return countVectors(sql) > 0;
  };

  /**
   * The one scheduling helper, and the only code in this module that sets or
   * removes the alarm (D-23).
   *
   * With no job pending it removes the alarm, if one is set, and stops.
   * Otherwise the target is `wantedAt`, raised to now if it is in the past and
   * lowered to one day from now. The target is set only when no alarm is set,
   * the set one is stale (at or before now), or the set one is later. So
   * nothing here ever moves a set alarm later.
   */
  scheduleAlarm = async (wantedAt: number): Promise<void> => {
    const storage = this.ctx.storage;
    if (!this.anyJobPending()) {
      if ((await storage.getAlarm()) !== null) await storage.deleteAlarm();
      return;
    }
    const now = Date.now();
    const target = Math.min(Math.max(wantedAt, now), now + RECALL_SWEEP_MAX_INTERVAL_MS);
    const current = await storage.getAlarm();
    if (current === null || current <= now || current > target) await storage.setAlarm(target);
  };

  /** Reads and removals over this object's own ledger, for the sweep and the destroy. */
  ledgerHandle = (): LedgerHandle => {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    return {
      expiredIds: (now, limit) => expiredIds(sql, now, limit),
      anyIds: (limit) => anyIds(sql, limit),
      forget: (ids) => {
        forgetVectors(sql, ids);
      },
    };
  };

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
  async recallRecord(rows: unknown): Promise<RecordAnswer> {
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
    // The rows are written above with no await before them. Only now does the
    // method wait, to make sure the alarm will expire them.
    await this.scheduleAlarm(earliestExpiry(sql) ?? Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
    return { ok: true };
  }

  /**
   * The object's one alarm (Phase 25, D-13).
   *
   * Sweeps expired vectors, store first, then sets the alarm again through the
   * helper: one minute out when expired rows remain, else at the next expiry
   * (the helper lowers that to one day). It never throws: on any failure it
   * reschedules one hour out through the same helper, which keeps an earlier
   * alarm and removes the alarm when no job is left. The caught value is never
   * read.
   */
  async alarm(): Promise<void> {
    try {
      const more = await sweepExpired(this.ledgerHandle(), this.vectorStore(), Date.now());
      const next = more
        ? Date.now() + RECALL_SWEEP_AGAIN_MS
        : (earliestExpiry(this.ctx.storage.sql) ?? Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
      await this.scheduleAlarm(next);
    } catch {
      try {
        await this.scheduleAlarm(Date.now() + RECALL_ALARM_RETRY_MS);
      } catch {
        // Nothing left to try; the platform does not retry a handler that returned.
      }
    }
  }

  /**
   * Ask to start one recall page for `mailbox` (Phase 25, D-15, D-24).
   *
   * The object decides, not the caller. Refuses, in this order: `invalid` for a
   * bad mailbox or a kind that is not exactly "build" or "reconcile"; `unnamed`
   * when the object does not know whose it is; `busy` while another page's
   * token has not expired; `paused` within RECALL_PAGE_PAUSE_MS of the last
   * page's start; `quota` once RECALL_MAX_PAGES_PER_DAY pages began today
   * (UTC), reconciles included; and, for a build only, `full` when one more
   * page could take the ledger past RECALL_MAX_VECTORS. A reconcile only
   * removes, so it is never refused as full.
   *
   * Otherwise it mints a page token, records the start, counts the page and
   * answers the stored cursor. No `await`, so the check and the set are one
   * atomic step. There is no `off` refusal: recall is inherent.
   */
  recallBeginPage(mailbox: unknown, kind: unknown): BeginPageAnswer {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    if (this.rememberOwnName() === null) return { ok: false, reason: "unnamed" };
    if (!isMailbox(mailbox)) return { ok: false, reason: "invalid" };
    if (kind !== "build" && kind !== "reconcile") return { ok: false, reason: "invalid" };

    const now = Date.now();
    const slot = readPageSlot(sql);
    if (slot !== null && slot.expiresAt > now) return { ok: false, reason: "busy" };
    const last = readLastPageAt(sql);
    if (last !== null && now - last < RECALL_PAGE_PAUSE_MS) return { ok: false, reason: "paused" };
    const today = utcDay(now);
    if (pagesOn(sql, today) >= RECALL_MAX_PAGES_PER_DAY) return { ok: false, reason: "quota" };
    if (kind === "build" && countVectors(sql) + RECALL_PAGE_SIZE > RECALL_MAX_VECTORS) {
      return { ok: false, reason: "full" };
    }

    const pageToken = crypto.randomUUID();
    writePageSlot(sql, { token: pageToken, expiresAt: now + RECALL_PAGE_TTL_MS });
    writeLastPageAt(sql, now);
    countPageOn(sql, today);
    return { ok: true, pageToken, cursor: readCursor(sql, mailbox) };
  }

  /**
   * End a recall page, and apply its cursor update.
   *
   * Only when `pageToken` is the in-flight page's token: clears the token, then
   * keeps, sets or resets `mailbox`'s cursor. Anything else changes nothing.
   * Answers whether it applied.
   */
  recallEndPage(pageToken: unknown, mailbox: unknown, cursorUpdate: unknown): boolean {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    this.rememberOwnName();
    if (typeof pageToken !== "string" || !isMailbox(mailbox)) return false;
    const update = cursorUpdateOf(cursorUpdate);
    if (update === null) return false;
    const slot = readPageSlot(sql);
    if (slot === null || slot.token !== pageToken) return false;

    clearPageSlot(sql);
    if (update.kind === "set") writeCursor(sql, mailbox, update.cursor);
    if (update.kind === "reset") clearCursor(sql, mailbox);
    return true;
  }

  /**
   * Up to `limit` (1..1000) of `mailbox`'s ledger rows, ordered by id, strictly
   * after `afterId` when it is a string. An invalid mailbox reads as empty.
   */
  recallIdsForMailbox(mailbox: unknown, afterId: unknown, limit: unknown): MailboxRow[] {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    this.rememberOwnName();
    if (!isMailbox(mailbox)) return [];
    const n =
      typeof limit === "number" && Number.isFinite(limit)
        ? Math.min(MAX_SCOPE_ROWS, Math.max(1, Math.floor(limit)))
        : MAX_SCOPE_ROWS;
    return idsForMailbox(sql, mailbox, typeof afterId === "string" ? afterId : null, n);
  }

  /**
   * Remove these ids from the ledger, after the store delete has succeeded.
   *
   * Anything that is not a 64-character lower-case hex string is ignored, and
   * at most 1000 entries are read per call. Answers how many rows went.
   */
  recallForget(ids: unknown): number {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    this.rememberOwnName();
    if (!Array.isArray(ids)) return 0;
    const valid = ids
      .slice(0, MAX_SCOPE_ROWS)
      .filter((id): id is string => typeof id === "string" && HEX_64.test(id));
    return forgetVectors(sql, valid);
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
