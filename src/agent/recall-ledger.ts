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
export const RECORD_REFUSALS = ["invalid", "unnamed", "full"] as const;

/** One reason a record was refused. */
export type RecordRefusal = (typeof RECORD_REFUSALS)[number];

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
