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
// Since Phase 27 it also holds, because autonomy is inherent, one sealed
// autonomy record for every person who has signed in since autonomy was set up
// and is still connected: the refresh token of their autonomy grant, sealed
// under a Worker secret and tied to their user id (./autonomy.ts says how). So
// what the object holds is: a lease record, its own stored name, Phase 25's
// recall tables (Phase 26 keeps its folder state there too), its one alarm, and
// that one sealed record. Still no address and no password.
//
// Since Phase 28 it also holds the person's autonomy rules, what the rules job
// did (a ring of the last 100 entries, with no subject, address or text), the
// job's own state (the stored change marker, the next wake, the last run), and
// one "already acted" record per rule, action and message. No grant id is
// stored for the job, and nothing in it reads the autonomy record's fields.
//
// It still never opens a socket and never imports mail, DAV, tool or auth code.
// It reaches this Worker only through `autonomySelfFetch`, its one seam to the
// Worker's own endpoints. The rules job reaches mail that way too: each call it
// makes is a tool call at this Worker's own `/mcp`, where the door takes the
// person's connection lease like any other request.
//
// Recall is inherent (owner, 2026-09-27), so there is no switch here: no method
// that turns recall on or off, and no enabled flag. The first record for a
// person needs no earlier call.
//
// ONE ALARM SLOT, SHARED. An object has one alarm, and recall was its first
// user. Its jobs today, in the order `alarm()` runs them: autonomy first (Phase
// 27: does the key still stand?), then the rules job (Phase 28), then recall's
// revocation (a pending destroy, or no grant left), then recall's expiry. All
// of them keep the alarm through `anyJobPending()`. Every set and every removal
// goes through one helper, `scheduleAlarm`, which removes the alarm only when
// `anyJobPending()` says no job is left and otherwise never moves a set alarm
// later. A second call that sets the alarm, or a second condition for removing
// it, would silently drop another job's schedule.
//
// This module logs nothing (./.claude/CLAUDE.md §4).

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import {
  AUTONOMY_KEY,
  type ArmOutcome,
  type AutonomyQueue,
  armWith,
  autonomyAlarmJob,
  autonomyArmed,
  oneAtATime,
  withAutonomySession,
} from "./autonomy";
import { type ActivityEntry, readActivity } from "./activity";
import { nextWakeAfter } from "./cadence";
import {
  JOB_LAST_RUN_KEY,
  JOB_MARKER_KEY,
  JOB_NEXT_AT_KEY,
  RULES_KEY,
  readRules,
  runAutonomyJob,
} from "./job";
import { MAX_RULES, parseRule, type Rule, RULE_VERSION, type RuleRefusal } from "./rules";
import { type KeyStanding, keyStandingFor, sweepAutonomyGrants } from "./autonomy-grants";
import { type RecallStore, recallStore } from "../recall/index";
import { grantsRemainFor } from "../recall/grant-check";
import { destroyAll, type LedgerHandle, sweepExpired } from "../recall/lifecycle";
import { RECALL_MAX_VECTORS, RECALL_TTL_MS } from "../recall/retention";
import {
  clearCursor,
  clearDestroyPending,
  clearPageSlot,
  clearRecallStateExceptPending,
  destroyPending,
  countNewIds,
  countPageOn,
  countVectors,
  earliestExpiry,
  ensureRecallSchema,
  expiredIds,
  anyIds,
  folderListOf,
  forgetVectors,
  heldIds,
  idsForMailbox,
  markDestroyPending,
  type LedgerRowInput,
  type MailboxRow,
  type PageRefusal,
  pageRefusal,
  RECALL_PAGE_PAUSE_MS,
  readFolders,
  readListedAt,
  readListingFailure,
  readSyncRows,
  type RetryState,
  type SyncRow,
  readCursor,
  readPageSlot,
  recordVectors,
  type RecordRefusal,
  syncRowFor,
  utcDay,
  writeCursor,
  writeFolders,
  writeLastPageAt,
  writeListingFailure,
  writePageSlot,
  writeSyncRow,
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
 * (Phase 25, D-15). Defined beside `pageRefusal`, the one predicate that reads
 * it, and re-exported here where it has always been imported from.
 */
export { RECALL_PAGE_PAUSE_MS };

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

/**
 * What the object says about the build, before any IMAP (Phase 26, D-29).
 *
 * `slot` is the first refusal a deletion sync would get now, or `free`. It is
 * never `full`: a removal is never refused at the vector ceiling. It is
 * `unnamed` when the object does not know whose it is: every write would be
 * refused, a failure could not even be recorded, so a step must open nothing
 * (26-REVIEW-2 IN-02). `full` says
 * whether a page that adds vectors would be refused at that ceiling now
 * (26-REVIEW-2 WR-04). `folders` is the stored folder list, or null before the
 * first listing. `listedAt` is when that list was listed, or null when it is
 * due to be listed again (26-REVIEW-2 WR-02). `listing` is the folder
 * listing's failure record, or null. `sync` is every mailbox's sync row that
 * parses, keyed by mailbox.
 */
export interface RecallSyncState {
  readonly slot: PageRefusal | "unnamed" | "free";
  readonly full: boolean;
  readonly folders: string[] | null;
  readonly listedAt: number | null;
  readonly listing: RetryState | null;
  readonly sync: Record<string, SyncRow>;
}

/**
 * The answer to a build-state write (Phase 26, D-15). Shapes, never throws.
 *
 * `unnamed` when the object does not know whose it is, `invalid` for a value
 * the object will not store, `destroying` while a destroy is running.
 */
export type SetAnswer = { ok: true } | { ok: false; reason: "unnamed" | "invalid" | "destroying" };

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

/** How many activity entries the rules view returns, newest first (D-18). */
const RULES_VIEW_ACTIVITY = 50;

/** Why adding a rule was refused, beyond the parser's own refusals. */
type AddRuleRefusal = RuleRefusal | "unnamed" | "too-many-rules" | "failed";

/** The fixed sentences for the object's own refusals. */
const ADD_RULE_REASONS = Object.freeze({
  unnamed: "This account's rules could not be stored right now. Try again.",
  "too-many-rules": `A person can hold at most ${MAX_RULES} rules. Remove one first.`,
  failed: "The rule could not be stored right now. Try again.",
});

/** The answer to adding a rule. Shapes, never throws. */
export type AddRuleAnswer =
  | { ok: true; id: string; createdAt: number }
  | { ok: false; refusal: AddRuleRefusal; reason: string };

/**
 * What the rules view answers (D-18 as revised). No token, no record field, no
 * marker: the job's state is times and the last run's outcome only.
 */
export interface RulesView {
  readonly rules: Rule[];
  readonly activity: ActivityEntry[];
  readonly job: {
    readonly nextAt: number | null;
    readonly markerAt: number | null;
    readonly lastRun: { readonly at: number; readonly outcome: string } | null;
  };
  readonly armed: boolean;
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
   * THIS IS THE ONE CONDITION FOR KEEPING THE ALARM. A phase with a job on this
   * alarm adds its clause here, in this function, and nowhere else. A second
   * condition written beside this one would let one job remove the alarm
   * another job still needs. The clauses today:
   *   - recall's ledger holds a row (Phase 25);
   *   - recall's destroy has started and not finished (Phase 25);
   *   - an autonomy record is stored (Phase 27). Presence only: the record is
   *     never parsed or unsealed here. So an empty recall ledger on its own
   *     does not remove the alarm while a key is held, and the key's standing
   *     is asked at least once a day.
   *   - the rules job has a rule to run and a key to run it with (Phase 28,
   *     D-27). Both, not either: a person with no rules has no job, and a
   *     person with rules but no key has nothing the job could do. Today the
   *     clause above already holds whenever this one does; it is written out
   *     so the rules job's reason for the alarm does not rest on another job's.
   */
  anyJobPending = (): boolean => {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    return (
      countVectors(sql) > 0 ||
      destroyPending(sql) ||
      this.ctx.storage.kv.get<unknown>(AUTONOMY_KEY) !== undefined ||
      (readRules(this.ctx.storage.kv).length > 0 && autonomyArmed(this.ctx.storage.kv))
    );
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

  /**
   * Whether this person still holds any grant. A seam, so tests can answer for
   * the library; production never overrides it.
   */
  grantsRemain = (userId: string): Promise<"some" | "none" | "unknown"> =>
    grantsRemainFor(this.env.OAUTH_KV, userId);

  /**
   * The one thing this object uses to reach this Worker (Phase 27, D-22).
   *
   * Every autonomy request goes through it: the code exchange, the refresh, the
   * revocation and the one tool call. `./autonomy.ts` builds each URL from the
   * deployed hostname and an exact path, and the binding adds no identity.
   * Tests replace this property through `runInDurableObject`, to record what
   * the object sent; production never overrides it.
   */
  autonomySelfFetch = (request: Request): Promise<Response> => this.env.SELF.fetch(request);

  /**
   * Whether the key whose grant is `grantId` still stands, for the person whose
   * user id is `name` (27-05, D-33). The alarm job asks it. A seam, so tests
   * can answer for the listing; production never overrides it. An instance
   * property, so RPC does not expose it.
   */
  keyStanding = (name: string, grantId: string): Promise<KeyStanding> =>
    keyStandingFor(this.env.OAUTH_KV, name, grantId);

  /**
   * Revoke every autonomy grant the person whose user id is `name` holds,
   * except `keepGrantId` and the grants whose arm is waiting in the queue:
   * those are sign-ins still in flight (D-27). The alarm job calls it keeping
   * none when the key has ended, and keeping the record's grant while the key
   * stands (review R2-WR-02). A seam, like the one above.
   */
  sweepAutonomy = (name: string, keepGrantId: string | null = null): Promise<unknown> =>
    sweepAutonomyGrants(
      this.env.OAUTH_KV,
      name,
      keepGrantId,
      new Set(this.pendingArmGrants.keys()),
      Math.floor(Date.now() / 1000),
    );

  /**
   * The one autonomy queue (Phase 27, D-27). Every autonomy entry point runs
   * through it, one operation at a time: `armAutonomy` today, plan 27-05's
   * alarm job and Phase 28's job later. Those two take the object's name from
   * `storedOwnName()`. Inner calls never re-enter it: the arm's proof calls
   * the session function directly. The lease and every other method never
   * wait on it.
   *
   * Each run hands its operation a ticket, live only while that operation
   * runs, and a session refuses without one (review WR-04). So opening a
   * session from outside this queue is refused at run time, not merely
   * discouraged: Phase 28's job opens its session inside
   * `autonomyQueue.run((ticket) => ...)` and passes that ticket. A ticket
   * opens one session, ever, and the run does not end until that session has
   * settled, even when the operation did not await it (review R2-WR-01). So
   * two sessions in one run are refused too, and a session cannot outlive
   * its run.
   *
   * WHY. The Claude client submits the sign-in form twice, about 1.4 seconds
   * apart (measured 2026-09-21), so every sign-in arms twice. Without one at a
   * time, the two arms interleave at every `await`, sweep each other's grants,
   * and the person ends with no key. It is also what meets D-15's "one
   * redemption at a time": a second caller waits and then runs its own
   * operation, so no two refreshes of one token are ever out at once.
   *
   * An instance property, not a method, so no Worker holding a stub can reach
   * it (the seam above follows the same rule). If the object is evicted, the
   * queue is lost with everything in it. That is safe: the stored token is
   * still the current one or the previous one, and the library accepts both.
   */
  autonomyQueue: AutonomyQueue = oneAtATime();

  /**
   * How many arms are waiting in the queue for each grant id. The sweeps leave
   * these grants alone, because each belongs to a sign-in whose arm has not
   * run yet (D-27). An instance property, for the same reason as the queue.
   */
  pendingArmGrants = new Map<string, number>();

  /**
   * The object's stored own name, when it is a 64-hex user id, else null.
   *
   * Reads only the key-value storage. It never reads the platform's id, which
   * is not documented as present inside an alarm (D-22). The alarm and later
   * phases ask this, never the platform.
   */
  storedOwnName = (): string | null => {
    const stored = this.ctx.storage.kv.get<unknown>(OWN_NAME_KEY);
    return typeof stored === "string" && HEX_64.test(stored) ? stored : null;
  };

  /**
   * Destroy this person's recall index: every vector, every ledger row, every
   * cursor and the page state (D-10). The object's own name is kept.
   *
   * NOT an RPC method, and no prototype method destroys. Recall is inherent and
   * there is no opt-out, so nothing outside the object may start a destroy. In
   * production the alarm is its only caller: when the person's last grant is
   * gone, or to finish a destroy that failed part-way.
   *
   * The pending flag is set FIRST, before any delete. While it is set, a record
   * and a page start are refused as `destroying`, so nothing lands in the
   * ledger while it is being emptied. Store first, then ledger, batch by batch.
   * On success every recall state row goes, the flag last, and the helper
   * removes the alarm when no job is left. On failure the flag stays, the alarm
   * is set about an hour out, and the next alarm finishes the job. The caught
   * value is never read.
   */
  destroyRecall = async (): Promise<{ ok: boolean }> => {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    markDestroyPending(sql);
    clearPageSlot(sql);
    try {
      await destroyAll(this.ledgerHandle(), this.vectorStore());
    } catch {
      await this.scheduleAlarm(Date.now() + RECALL_ALARM_RETRY_MS);
      return { ok: false };
    }
    clearRecallStateExceptPending(sql);
    clearDestroyPending(sql);
    await this.scheduleAlarm(Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
    return { ok: true };
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
    const stored = this.storedOwnName();
    if (stored !== null) return stored;
    if (this.ctx.storage.kv.get<unknown>(OWN_NAME_KEY) !== undefined) return null;
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
    if (destroyPending(sql)) return { ok: false, reason: "destroying" };
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
   * The object's one alarm (Phase 25, D-09, D-13, D-22; Phase 27, D-25).
   *
   * Its jobs, in order: the autonomy job (Phase 27); the rules job (Phase 28);
   * finish a pending destroy; destroy everything when the person holds no
   * grant any more, asked about the object's stored own name; then sweep
   * expired vectors.
   *
   * `alarmInfo` is the platform's; only whether this run is a retry is read,
   * and the rules job acts on no retry. It may be absent, as it is when a test
   * runs the alarm, and absent counts as not a retry.
   *
   * The autonomy job runs FIRST, in its own `try`, through the one autonomy
   * queue (D-27). First, so recall's early returns cannot skip it, and so that
   * when it ends the key, recall's grant check in the same run already sees
   * the person as gone. Its own `try`, so a fault in it cannot starve recall's
   * jobs. It is asked about the name from `storedOwnName()`, exactly as
   * recall's grant check is: the platform's name is not documented as present
   * inside an alarm, and this module reads the platform's name in one place
   * only. With no stored name the job is skipped. The record then stays, and
   * `anyJobPending()` keeps the alarm at most a day away.
   *
   * Recall's jobs then run as before. The sweep deletes store first, then the alarm
   * is set again through the helper: one minute out when expired rows remain, else at the next expiry
   * (the helper lowers that to one day). It never throws: on any failure it
   * reschedules one hour out through the same helper, which keeps an earlier
   * alarm and removes the alarm when no job is left. The caught value is never
   * read.
   */
  async alarm(alarmInfo?: { readonly isRetry?: boolean }): Promise<void> {
    // 0. Autonomy: does the key still stand? Never skipped by what follows.
    try {
      const ownName = this.storedOwnName();
      if (ownName !== null) {
        const outcome = await this.autonomyQueue.run(() =>
          autonomyAlarmJob({
            storage: this.ctx.storage.kv,
            name: ownName,
            keyStanding: (name, grantId) => this.keyStanding(name, grantId),
            sweep: (name, keepGrantId) => this.sweepAutonomy(name, keepGrantId),
            now: () => Date.now(),
          }),
        );
        if (outcome.kind !== "none") {
          await this.scheduleAlarm(outcome.wantedAt ?? Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
        }
      }
    } catch {
      // Recall's jobs below still run, and each ends through the helper.
    }
    // 0b. The rules job (Phase 28, D-27): after the key's own job, so a key
    //     that job just ended is seen as gone; in its own queue run and its own
    //     `try`, so a fault in it cannot starve recall's jobs below, and
    //     recall's early returns cannot skip it. The name is the stored one;
    //     with none, the job is skipped for this alarm. It opens at most one
    //     session, with this run's ticket.
    try {
      const ownName = this.storedOwnName();
      if (ownName !== null) {
        const storage = this.ctx.storage.kv;
        await this.autonomyQueue.run((ticket) =>
          runAutonomyJob({
            storage,
            name: ownName,
            now: () => Date.now(),
            isRetry: alarmInfo?.isRetry === true,
            requestWake: (wantedAt) => this.scheduleAlarm(wantedAt),
            withSession: (use) =>
              withAutonomySession(
                {
                  storage,
                  name: ownName,
                  env: this.env,
                  selfFetch: (request) => this.autonomySelfFetch(request),
                  now: () => Date.now(),
                  ticket,
                },
                use,
              ),
          }),
        );
      }
    } catch {
      // The job never throws. Recall's jobs below still run.
    }
    try {
      // Recall's tables may not exist yet: since Phase 27 an object can hold an
      // alarm for its autonomy record before any recall call. Creating them is
      // idempotent, and without them the read below throws.
      ensureRecallSchema(this.ctx.storage.sql);
      // 1. A destroy that started and did not finish is finished first.
      if (destroyPending(this.ctx.storage.sql)) {
        await this.destroyRecall();
        return;
      }
      // 2. Revocation: asked about the name this object stored for itself,
      //    never the platform's. Only a definite "none" destroys.
      const name = this.storedOwnName();
      if (name !== null && (await this.grantsRemain(name)) === "none") {
        await this.destroyRecall();
        return;
      }
      // 3. Expiry.
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
   * removes, so it is never refused as full. Every check after `unnamed` and
   * `invalid` is `pageRefusal` in ./recall-ledger.ts, the one predicate the
   * sync-state read below shares (Phase 26, D-29).
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
    const refusal = pageRefusal(sql, kind, now);
    if (refusal !== null) return { ok: false, reason: refusal };
    const today = utcDay(now);

    const pageToken = crypto.randomUUID();
    writePageSlot(sql, { token: pageToken, expiresAt: now + RECALL_PAGE_TTL_MS });
    writeLastPageAt(sql, now);
    countPageOn(sql, today);
    return { ok: true, pageToken, cursor: readCursor(sql, mailbox) };
  }

  /**
   * Report the page slot, the folder list and each folder's sync row, for a
   * build step to read before it opens any IMAP session (Phase 26, D-29).
   *
   * The slot is answered by `pageRefusal`, the same predicate the page start
   * above asks. `slot` is its answer for a deletion sync, and `full` whether a
   * build page would also be refused at the vector ceiling (26-REVIEW-2
   * WR-04). A step that reads a refusal in `slot` stops with no lease and no
   * session. `unnamed` is such a refusal: an object that does not know whose it
   * is refuses every write, so nothing a step did could be recorded
   * (26-REVIEW-2 IN-02). A step that reads `full` still does what shrinks or checks the
   * index, and only what would add vectors waits: the index is shrunk by those
   * removals, so stopping them at the ceiling would keep it there.
   *
   * Writes nothing, apart from the one-time copy of the object's own name that
   * every recall method makes (Phase 25, D-22). There is no `off` answer:
   * recall is inherent.
   */
  recallSyncState(): RecallSyncState {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    const named = this.rememberOwnName() !== null;
    const now = Date.now();
    return {
      slot: named ? (pageRefusal(sql, "reconcile", now) ?? "free") : "unnamed",
      full: pageRefusal(sql, "build", now) === "full",
      folders: readFolders(sql),
      listedAt: readListedAt(sql),
      listing: readListingFailure(sql),
      sync: readSyncRows(sql),
    };
  }

  /**
   * Record that the folder listing failed at `at` (26-REVIEW CR-01), so the
   * next step waits before listing again instead of listing on every mail call.
   *
   * Refuses, in this order: `unnamed`; `invalid` unless `at` is a finite
   * number; `destroying` while a destroy is running. Storing a folder list
   * clears the record. No `await`, so the read, the count and the write are one
   * atomic step.
   */
  recallListingFailed(at: unknown): SetAnswer {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    if (this.rememberOwnName() === null) return { ok: false, reason: "unnamed" };
    if (typeof at !== "number" || !Number.isFinite(at)) return { ok: false, reason: "invalid" };
    if (destroyPending(sql)) return { ok: false, reason: "destroying" };
    writeListingFailure(sql, at);
    return { ok: true };
  }

  /**
   * Store the folder list the build covers (Phase 26, D-12, D-15).
   *
   * `listedAt` is when the list was listed, in ms since the epoch: the step
   * lists again once it is a day old (26-REVIEW-2 WR-02). Null stores no time,
   * so the next step lists again, which the step asks for after it dropped a
   * folder as gone. Absent means now, by this object's clock.
   *
   * Refuses, in this order: `unnamed`; `invalid` unless the list is 1 to 4
   * distinct non-empty names of at most 1024 characters, the first exactly
   * `INBOX`, and `listedAt` is absent, null or a finite number; `destroying`
   * while a destroy is running, so a step racing a destroy cannot put the list
   * back. No `await`, so the check and the write are one atomic step. The
   * destroy already clears these rows: they live in the recall state table.
   */
  recallSetFolders(list: unknown, listedAt?: unknown): SetAnswer {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    if (this.rememberOwnName() === null) return { ok: false, reason: "unnamed" };
    const folders = folderListOf(list);
    if (folders === null) return { ok: false, reason: "invalid" };
    const at = listedAt === undefined ? Date.now() : listedAt;
    if (at !== null && (typeof at !== "number" || !Number.isFinite(at))) {
      return { ok: false, reason: "invalid" };
    }
    if (destroyPending(sql)) return { ok: false, reason: "destroying" };
    writeFolders(sql, folders, at);
    return { ok: true };
  }

  /**
   * Store one mailbox's sync row (Phase 26, D-15).
   *
   * `cursor` is optional. Exactly `"reset"` also forgets the mailbox's build
   * cursor, in the same write, and is allowed only with a row at seed: a
   * folder sent back to seed because its validity changed must start its next
   * build from the top (26-REVIEW-2 WR-01). The step does not trust the page
   * slot's end to have done it, because that end changes nothing once the
   * slot's token has expired.
   *
   * Refuses, in this order: `unnamed`; `invalid` for a bad mailbox, a row
   * `parseSyncRow` rejects, a row whose `state` or `seen` names another
   * mailbox, or a `cursor` that is neither absent nor `"reset"` with a seed
   * row; `destroying` while a destroy is running. No `await`, so the check and
   * the writes are one atomic step. The destroy already clears these rows.
   */
  recallSetSync(mailbox: unknown, row: unknown, cursor?: unknown): SetAnswer {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    if (this.rememberOwnName() === null) return { ok: false, reason: "unnamed" };
    if (!isMailbox(mailbox)) return { ok: false, reason: "invalid" };
    const parsed = syncRowFor(mailbox, row);
    if (parsed === null) return { ok: false, reason: "invalid" };
    if (cursor !== undefined && (cursor !== "reset" || parsed.stage !== "seed")) {
      return { ok: false, reason: "invalid" };
    }
    if (destroyPending(sql)) return { ok: false, reason: "destroying" };
    writeSyncRow(sql, mailbox, parsed);
    if (cursor === "reset") clearCursor(sql, mailbox);
    return { ok: true };
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
   * Which of these ids the ledger holds (Phase 26, the dead-ref removal).
   *
   * Anything that is not a 64-character lower-case hex string is ignored, and at
   * most 1000 entries are read per call. Answers only the held subset of the ids
   * it was asked about, so it never lists an id the caller did not name.
   */
  recallHolds(ids: unknown): string[] {
    const sql = this.ctx.storage.sql;
    ensureRecallSchema(sql);
    this.rememberOwnName();
    if (!Array.isArray(ids)) return [];
    const valid = ids
      .slice(0, MAX_SCOPE_ROWS)
      .filter((id): id is string => typeof id === "string" && HEX_64.test(id));
    return heldIds(sql, valid);
  }

  /**
   * Arm the autonomy key from a one-time code (Phase 27, D-09, D-16, D-26).
   *
   * The one RPC method autonomy adds. The sign-in calls it after its answer has
   * gone, through the request's `waitUntil`, with the code of the autonomy grant
   * it just minted. Answers `{ kind: "armed", grantId }` or
   * `{ kind: "not_armed" }`, and nothing else: no token and no bearer ever
   * crosses back out.
   *
   * The name comes from Phase 25's `rememberOwnName()`, called FIRST (25 D-22).
   * An autonomy record can exist before this object ever had a recall call, so
   * arming must store the name itself: the alarm (plan 27-05) reads the stored
   * copy to know whose grants to ask about, and a record in an object with no
   * stored name could never be ended by it. With no name, nothing is armed.
   * This method never reads the platform's name itself; the one reader of it in
   * this module stays inside `rememberOwnName`.
   *
   * The whole arm runs inside `autonomyQueue.run`, after the name is known, so
   * two sign-ins arming at once run one after the other (D-27). While it
   * waits, its grant id is listed in `pendingArmGrants`, so an arm ahead of it
   * does not sweep the grant it is about to arm.
   *
   * Never throws: an error's class does not survive RPC, and the caller must be
   * able to tell "not armed" from nothing at all.
   */
  async armAutonomy(code: unknown): Promise<ArmOutcome> {
    if (typeof code !== "string") return { kind: "not_armed" };
    const name = this.rememberOwnName();
    if (name === null) return { kind: "not_armed" };
    const grantId = code.split(":")[1] ?? "";
    const pending = this.pendingArmGrants;
    pending.set(grantId, (pending.get(grantId) ?? 0) + 1);
    try {
      return await this.autonomyQueue.run(async (ticket) => {
        const outcome = await armWith(
          {
            storage: this.ctx.storage.kv,
            name,
            env: this.env,
            selfFetch: (request) => this.autonomySelfFetch(request),
            now: () => Date.now(),
            pendingArms: () => new Set(pending.keys()),
            // The arm's proof is a session, and a session opens only with the
            // queue's live ticket (review WR-04).
            ticket,
          },
          code,
        );
        // The record was stored, replaced or deleted. The helper keeps an
        // earlier alarm, sets one a day out while a record exists, and removes
        // the alarm when no job is left (27-05, 25 D-23).
        try {
          await this.scheduleAlarm(Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
        } catch {
          // The arm's answer stands. The next alarm or arm schedules again.
        }
        return outcome;
      });
    } catch {
      return { kind: "not_armed" };
    } finally {
      const left = (pending.get(grantId) ?? 1) - 1;
      if (left > 0) pending.set(grantId, left);
      else pending.delete(grantId);
    }
  }

  /**
   * Add one autonomy rule (Phase 28, D-03, D-08, D-11).
   *
   * The rule is parsed again here with `parseRule`, whatever the caller already
   * checked: this object is where a rule starts to act, so this is the check
   * that counts. The object stamps the rule's id and its `createdAt` from its
   * own clock, so no caller chooses a rule's age. Refuses, in this order: any
   * parse refusal; `unnamed` when the object does not know whose it is (the job
   * could never run); `too-many-rules` at `MAX_RULES`. Then asks for the job's
   * next wake, on the person's own offset (`./cadence.ts`), through the one
   * scheduling helper.
   *
   * Its one caller is the rules tool's commit, after the person saw and
   * confirmed the preview (plan 28-04). Never throws: an error's class does not
   * survive RPC.
   */
  async addRule(rule: unknown): Promise<AddRuleAnswer> {
    try {
      const parsed = parseRule(rule);
      if (!parsed.ok) return { ok: false, refusal: parsed.refusal, reason: parsed.reason };
      if (this.rememberOwnName() === null) {
        return { ok: false, refusal: "unnamed", reason: ADD_RULE_REASONS.unnamed };
      }
      const kv = this.ctx.storage.kv;
      const rules = readRules(kv);
      if (rules.length >= MAX_RULES) {
        return { ok: false, refusal: "too-many-rules", reason: ADD_RULE_REASONS["too-many-rules"] };
      }
      const createdAt = Date.now();
      const stored: Rule = { v: RULE_VERSION, id: crypto.randomUUID(), createdAt, ...parsed.rule };
      kv.put(RULES_KEY, [...rules, stored]);
      // The job's next wake on the person's own offset, from the stored name
      // (25 D-22). The helper keeps an earlier alarm.
      const name = this.storedOwnName();
      try {
        if (name !== null) await this.scheduleAlarm(nextWakeAfter(createdAt, name));
      } catch {
        // The rule stands. The next alarm or arm schedules again.
      }
      return { ok: true, id: stored.id, createdAt };
    } catch {
      return { ok: false, refusal: "failed", reason: ADD_RULE_REASONS.failed };
    }
  }

  /**
   * Remove one of this person's rules by id. Answers whether one was removed.
   *
   * It only ever reduces what the job does. After the last rule goes, the rules
   * job's clause in `anyJobPending()` is false, and the one scheduling helper
   * does the rest. Never throws.
   */
  async removeRule(id: unknown): Promise<{ removed: boolean }> {
    try {
      if (typeof id !== "string") return { removed: false };
      const kv = this.ctx.storage.kv;
      const rules = readRules(kv);
      const kept = rules.filter((rule) => rule.id !== id);
      if (kept.length === rules.length) return { removed: false };
      if (kept.length === 0) kv.delete(RULES_KEY);
      else kv.put(RULES_KEY, kept);
      try {
        await this.scheduleAlarm(Date.now() + RECALL_SWEEP_MAX_INTERVAL_MS);
      } catch {
        // The removal stands.
      }
      return { removed: true };
    } catch {
      return { removed: false };
    }
  }

  /**
   * This person's rules, the newest 50 things the job did, the job's state,
   * and whether they hold an autonomy key right now (Phase 28, D-18).
   *
   * `armed` is presence only, through `autonomyArmed`: no token and no field of
   * the record is read or returned. No iCloud connection, and no write.
   */
  rulesView(): RulesView {
    const kv = this.ctx.storage.kv;
    const nextAt = kv.get<unknown>(JOB_NEXT_AT_KEY);
    const marker = kv.get<unknown>(JOB_MARKER_KEY);
    const lastRun = kv.get<unknown>(JOB_LAST_RUN_KEY);
    const markerAt = (marker as { at?: unknown } | undefined)?.at;
    const last = lastRun as { at?: unknown; outcome?: unknown } | undefined;
    return {
      rules: readRules(kv),
      activity: readActivity(kv, RULES_VIEW_ACTIVITY),
      job: {
        nextAt: typeof nextAt === "number" ? nextAt : null,
        markerAt: typeof markerAt === "number" ? markerAt : null,
        lastRun:
          typeof last?.at === "number" && typeof last.outcome === "string"
            ? { at: last.at, outcome: last.outcome }
            : null,
      },
      armed: autonomyArmed(kv),
    };
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
