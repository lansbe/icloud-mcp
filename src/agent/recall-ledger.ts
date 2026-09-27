// The recall ledger: every vector id one person owns (Phase 25, D-07, D-08).
//
// The ledger is mandatory, not a cache. The vector store can delete only by a
// list of ids, and no call deletes a whole partition (SPIKE-09 (1)). So "delete
// everything this person owns" is possible only because something already
// holds every id they own. This is that something. It lives in the person's
// own object (src/agent/user-agent.ts), in its SQLite storage.
//
// THE ONE INVARIANT: the ledger is always a superset of the person's vectors
// in the store.
//
// - Writing: the ids are recorded here FIRST, then written to the store. A
//   failure between the two leaves a row for a vector that never landed, and
//   deleting a missing id is harmless.
// - Deleting: the store delete runs FIRST, then the rows go. A failure between
//   the two leaves rows for vectors already gone, and deleting them again is
//   harmless.
// - Either order reversed leaves a vector no row knows about, and that vector
//   could then never be deleted wholesale.
//
// WHAT IT HOLDS: the vector id, the mailbox, the mailbox's UIDVALIDITY, and an
// expiry the object computed. WHAT IT NEVER HOLDS: text, the message ref, an
// address. The mailbox and validity are there so a changed UIDVALIDITY can drop
// a whole old generation; the expiry is there for the alarm.
//
// There is no enabled flag and no switch of any kind. Recall is inherent
// (owner, 2026-09-27): every person who signs in is indexed.
//
// The object keeps two other things in its key-value storage, beside these
// tables: Phase 24's connection lease under `lease`, and its own name under
// `own-name`. This module never touches either.
//
// Pure functions over the SQL handle. No imports from the mail, DAV, tool or
// auth trees. No logging (./.claude/CLAUDE.md §4).
//
// Queries that read rows are written in lower case, and that is deliberate.
// IMAP and SQL share an upper-case keyword for "open this" and "read rows",
// and the scan counts the one place that builds the IMAP open that can change a
// mailbox by matching that keyword at the start of a string. An upper-case
// query here would count as a second site and fail the commit. The answer is
// at the source, never in the pattern.

/** The reasons a record can be refused. Plan 25-03 appends to this list and nowhere else. */
export const RECORD_REFUSALS = ["invalid", "unnamed", "full", "destroying"] as const;

/** One reason a record was refused. */
export type RecordRefusal = (typeof RECORD_REFUSALS)[number];

/**
 * The reasons a build or reconcile page may be refused, beside the record list.
 * Plan 25-03 appends to this list and nowhere else. The build engine derives its
 * status type from it, so a reason added here needs no change there.
 */
export const PAGE_REFUSALS = ["busy", "paused", "quota", "full", "destroying"] as const;

/** One reason a page was refused. */
export type PageRefusal = (typeof PAGE_REFUSALS)[number];

/** What a page is for. A reconcile only removes, so it is never refused as full. */
export type PageKind = "build" | "reconcile";

/** The in-flight page: a token the object minted, and when it stops blocking. */
export interface PageSlot {
  readonly token: string;
  readonly expiresAt: number;
}

/** One ledger row, as a reconcile reads it. */
export interface MailboxRow {
  readonly vectorId: string;
  readonly uidValidity: number;
}

/** The `recall_state` key of the in-flight page. */
const PAGE_ROW = "page";

/** The `recall_state` key of when the last page began. */
const LAST_PAGE_ROW = "last_page_at";

/** The `recall_state` keys of the current UTC day and its page count. */
const DAY_ROW = "pages_day";
const DAY_COUNT_ROW = "pages_count";

/** The `recall_state` key of the pending-destroy flag. */
const PENDING_DESTROY_ROW = "destroy_pending";

/** The `recall_state` key of one mailbox's build cursor is this plus the mailbox. */
const CURSOR_ROW = "cursor:";

/** One row to record. */
export interface LedgerRowInput {
  readonly vectorId: string;
  readonly mailbox: string;
  readonly uidValidity: number;
  readonly messageDate: number;
}

/** Create the ledger's two tables if they do not exist yet. */
export function ensureRecallSchema(sql: SqlStorage): void {
  sql.exec(
    `CREATE TABLE IF NOT EXISTS recall_vectors (
       vector_id TEXT PRIMARY KEY,
       mailbox TEXT NOT NULL,
       uid_validity INTEGER NOT NULL,
       expires_at INTEGER NOT NULL
     )`,
  );
  sql.exec(`CREATE INDEX IF NOT EXISTS recall_vectors_expires ON recall_vectors (expires_at)`);
  sql.exec(`CREATE INDEX IF NOT EXISTS recall_vectors_mailbox ON recall_vectors (mailbox)`);
  sql.exec(
    `CREATE TABLE IF NOT EXISTS recall_state (
       k TEXT PRIMARY KEY,
       v TEXT NOT NULL
     )`,
  );
}

/**
 * Record `rows`, replacing any row with the same id.
 *
 * The expiry is `min(messageDate, now) + ttlMs`. The caller passes the
 * message's date, and the object clamps a date in the future to now, so a
 * caller cannot keep a vector longer than the window from the moment it was
 * written.
 */
export function recordVectors(
  sql: SqlStorage,
  rows: readonly LedgerRowInput[],
  now: number,
  ttlMs: number,
): void {
  for (const row of rows) {
    const expiresAt = Math.min(row.messageDate, now) + ttlMs;
    sql.exec(
      `INSERT INTO recall_vectors (vector_id, mailbox, uid_validity, expires_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (vector_id) DO UPDATE SET
         mailbox = excluded.mailbox,
         uid_validity = excluded.uid_validity,
         expires_at = excluded.expires_at`,
      row.vectorId,
      row.mailbox,
      row.uidValidity,
      expiresAt,
    );
  }
}

/** How many vector ids the ledger holds. */
export function countVectors(sql: SqlStorage): number {
  const row = sql.exec<{ n: number }>(`select count(*) as n from recall_vectors`).one();
  return row.n;
}

/** How many of `ids` the ledger does not hold yet. Duplicates count once. */
export function countNewIds(sql: SqlStorage, ids: readonly string[]): number {
  let fresh = 0;
  for (const id of new Set(ids)) {
    const row = sql
      .exec<{ n: number }>(`select count(*) as n from recall_vectors where vector_id = ?`, id)
      .one();
    if (row.n === 0) fresh += 1;
  }
  return fresh;
}

/** The value stored under `k` in `recall_state`, or null. */
export function readState(sql: SqlStorage, k: string): string | null {
  const rows = sql.exec<{ v: string }>(`select v from recall_state where k = ?`, k).toArray();
  return rows.length === 0 ? null : rows[0]!.v;
}

/** Store `v` under `k` in `recall_state`. */
export function writeState(sql: SqlStorage, k: string, v: string): void {
  sql.exec(
    `insert into recall_state (k, v) values (?, ?)
     on conflict (k) do update set v = excluded.v`,
    k,
    v,
  );
}

/** Remove `k` from `recall_state`. */
export function clearState(sql: SqlStorage, k: string): void {
  sql.exec(`delete from recall_state where k = ?`, k);
}

/** The in-flight page, or null when there is none or it is malformed. */
export function readPageSlot(sql: SqlStorage): PageSlot | null {
  const raw = readState(sql, PAGE_ROW);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as { token?: unknown; expiresAt?: unknown };
  if (typeof p.token !== "string" || typeof p.expiresAt !== "number") return null;
  return { token: p.token, expiresAt: p.expiresAt };
}

/** Store the in-flight page. */
export function writePageSlot(sql: SqlStorage, slot: PageSlot): void {
  writeState(sql, PAGE_ROW, JSON.stringify({ token: slot.token, expiresAt: slot.expiresAt }));
}

/** Clear the in-flight page. */
export function clearPageSlot(sql: SqlStorage): void {
  clearState(sql, PAGE_ROW);
}

/** When the last page began, in ms since the epoch, or null. */
export function readLastPageAt(sql: SqlStorage): number | null {
  const raw = readState(sql, LAST_PAGE_ROW);
  if (raw === null) return null;
  const at = Number(raw);
  return Number.isFinite(at) ? at : null;
}

/** Record that a page began at `now`. */
export function writeLastPageAt(sql: SqlStorage, now: number): void {
  writeState(sql, LAST_PAGE_ROW, String(now));
}

/** The UTC day of `now`, as YYYY-MM-DD. */
export function utcDay(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** How many pages began on `day` (UTC). Zero when the stored day is another. */
export function pagesOn(sql: SqlStorage, day: string): number {
  if (readState(sql, DAY_ROW) !== day) return 0;
  const count = Number(readState(sql, DAY_COUNT_ROW) ?? "0");
  return Number.isFinite(count) ? count : 0;
}

/** Count one more page on `day`, starting from zero on a new day. */
export function countPageOn(sql: SqlStorage, day: string): void {
  const next = pagesOn(sql, day) + 1;
  writeState(sql, DAY_ROW, day);
  writeState(sql, DAY_COUNT_ROW, String(next));
}

/** The stored build cursor for `mailbox`, or null. Opaque: never decoded here. */
export function readCursor(sql: SqlStorage, mailbox: string): string | null {
  return readState(sql, CURSOR_ROW + mailbox);
}

/** Store the build cursor for `mailbox`. */
export function writeCursor(sql: SqlStorage, mailbox: string, cursor: string): void {
  writeState(sql, CURSOR_ROW + mailbox, cursor);
}

/** Forget the build cursor for `mailbox`, so its build starts again from the top. */
export function clearCursor(sql: SqlStorage, mailbox: string): void {
  clearState(sql, CURSOR_ROW + mailbox);
}

/**
 * Up to `limit` of `mailbox`'s rows, ordered by id, strictly after `afterId`
 * when it is given.
 */
export function idsForMailbox(
  sql: SqlStorage,
  mailbox: string,
  afterId: string | null,
  limit: number,
): MailboxRow[] {
  const rows =
    afterId === null
      ? sql
          .exec<{ vector_id: string; uid_validity: number }>(
            `select vector_id, uid_validity from recall_vectors
             where mailbox = ? order by vector_id limit ?`,
            mailbox,
            limit,
          )
          .toArray()
      : sql
          .exec<{ vector_id: string; uid_validity: number }>(
            `select vector_id, uid_validity from recall_vectors
             where mailbox = ? and vector_id > ? order by vector_id limit ?`,
            mailbox,
            afterId,
            limit,
          )
          .toArray();
  return rows.map((row) => ({ vectorId: row.vector_id, uidValidity: row.uid_validity }));
}

/** Remove the rows with these ids. Returns how many were removed. */
export function forgetVectors(sql: SqlStorage, ids: readonly string[]): number {
  let removed = 0;
  for (const id of ids) {
    removed += sql.exec(`delete from recall_vectors where vector_id = ?`, id).rowsWritten;
  }
  return removed;
}

/** Up to `limit` ids whose expiry is at or before `now`, oldest expiry first. */
export function expiredIds(sql: SqlStorage, now: number, limit: number): string[] {
  return sql
    .exec<{ vector_id: string }>(
      `select vector_id from recall_vectors where expires_at <= ? order by expires_at limit ?`,
      now,
      limit,
    )
    .toArray()
    .map((row) => row.vector_id);
}

/** Up to `limit` ids of any kind. */
export function anyIds(sql: SqlStorage, limit: number): string[] {
  return sql
    .exec<{ vector_id: string }>(`select vector_id from recall_vectors limit ?`, limit)
    .toArray()
    .map((row) => row.vector_id);
}

/** The earliest expiry in the ledger, or null when it is empty. */
export function earliestExpiry(sql: SqlStorage): number | null {
  const row = sql
    .exec<{ m: number | null }>(`select min(expires_at) as m from recall_vectors`)
    .one();
  return typeof row.m === "number" ? row.m : null;
}

/** Whether a destroy has started and not finished. */
export function destroyPending(sql: SqlStorage): boolean {
  return readState(sql, PENDING_DESTROY_ROW) !== null;
}

/** Mark a destroy as started. Set BEFORE the first delete. */
export function markDestroyPending(sql: SqlStorage): void {
  writeState(sql, PENDING_DESTROY_ROW, "1");
}

/** Mark the destroy as finished. */
export function clearDestroyPending(sql: SqlStorage): void {
  clearState(sql, PENDING_DESTROY_ROW);
}

/**
 * Clear every recall state row except the pending-destroy flag: every cursor,
 * the page token, the last page time and the day's page count. The object's
 * own name is not a recall state row, so it survives.
 */
export function clearRecallStateExceptPending(sql: SqlStorage): void {
  sql.exec(`delete from recall_state where k != ?`, PENDING_DESTROY_ROW);
}
