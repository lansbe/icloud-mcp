// The recall page source over IMAP (Phase 26, D-11, D-17b, RCLL-08).
//
// Phase 25's build engine reads mail through an injected `RecallSource`. This
// is the real one. It reads one page of the retention window at a time, newest
// first, through the listing path that already exists (`searchMessages` with a
// start day). So it opens the mailbox read-only and every fetch item it sends
// is the peeking one (./.claude/CLAUDE.md §5). It adds no fetch item, opens
// nothing in the mutating form, and never reads a whole message.
//
// WHAT IS KEPT. The stored snippet is the subject line and nothing else (Phase
// 25 D-06). The listing's body preview is only embedded: it goes into the text
// the embedding model reads, and that text is thrown away after. Phase 25's
// pipeline caps both.
//
// DATES. A row's date is its INTERNALDATE, the time iCloud received it, parsed
// strictly. A row whose date does not parse is left out, never given a guessed
// date, because a guessed date would move the vector's expiry.
//
// WHERE IT RUNS. Only inside the person's connection lease, because Phase 25's
// engine calls it there. It imports nothing from the object tree.
//
// No logging, and no caught value is ever read (./.claude/CLAUDE.md §4).

import { ImapValidityChangedError } from "../errors";
import { decodeCursor, decodeMessageId, encodeCursor, type PageCursor } from "../mail/ids";
import {
  type MessageSummary,
  type SearchPage,
  type SessionGate,
  searchMessages,
  summariesInRange,
  windowUids,
} from "../mail/service";
import type { Principal } from "../principal";
import { RECALL_PAGE_SIZE, type RecallPage, type RecallSource } from "./build";
import type { RecallItem } from "./pipeline";
import { RECALL_TTL_MS } from "./retention";

/** The first day of the retention window, as `YYYY-MM-DD` in UTC. */
export function windowStartDay(now: number = Date.now()): string {
  return new Date(now - RECALL_TTL_MS).toISOString().slice(0, 10);
}

/**
 * The month names the protocol uses: fixed, English, three letters, and
 * matched case-sensitively. A table, never a locale-aware parser.
 */
const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
] as const;

/**
 * RFC 3501's date-time, without its quotes: a one- or two-digit day (a
 * one-digit day may be space-padded), a month from the table, a four-digit
 * year, `HH:MM:SS`, and a signed four-digit zone.
 */
const INTERNAL_DATE =
  /^( ?\d|\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;

/**
 * An INTERNALDATE as ms since the epoch, or null when it is not exactly one.
 *
 * Strict. The round-trip check refuses an impossible date such as 31 February,
 * which `Date.UTC` would otherwise roll into March, the way the listing's own
 * day reader refuses one. A missing zone, a lower-case month and an empty
 * string are all refused.
 */
export function parseInternalDate(value: string | null): number | null {
  if (value === null) return null;
  const match = INTERNAL_DATE.exec(value);
  if (match === null) return null;

  const day = Number(match[1]!.trim());
  const month = MONTHS.indexOf(match[2] as (typeof MONTHS)[number]);
  if (month === -1) return null;
  const year = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zoneHours = Number(match[8]);
  const zoneMinutes = Number(match[9]);
  if (zoneHours > 23 || zoneMinutes > 59) return null;

  const local = Date.UTC(year, month, day, hour, minute, second);
  const check = new Date(local);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month ||
    check.getUTCDate() !== day ||
    check.getUTCHours() !== hour ||
    check.getUTCMinutes() !== minute ||
    check.getUTCSeconds() !== second
  ) {
    return null;
  }

  const offset = (zoneHours * 60 + zoneMinutes) * 60 * 1000;
  return match[7] === "+" ? local - offset : local + offset;
}

/**
 * One listing row as an item to index, or null when it must be left out.
 *
 * THE ONE ROW-TO-ITEM FUNCTION. The snippet is the subject and nothing else.
 * The text is the subject, the sender's name and the body preview, the
 * non-empty ones joined by a newline. A row whose date does not parse, or
 * whose id does not decode, is left out.
 */
export function recallItemOf(row: MessageSummary): RecallItem | null {
  const messageDate = parseInternalDate(row.internalDate);
  if (messageDate === null) return null;
  let ref: RecallItem["ref"];
  try {
    ref = decodeMessageId(row.id);
  } catch {
    return null;
  }
  const subject = row.subject ?? "";
  const text = [subject, row.fromName ?? "", row.snippet]
    .filter((part) => part.length > 0)
    .join("\n");
  return { ref, text, snippet: subject, messageDate };
}

/** Every row that makes an item, in the rows' order. */
function itemsOf(rows: readonly MessageSummary[]): RecallItem[] {
  const items: RecallItem[] = [];
  for (const row of rows) {
    const item = recallItemOf(row);
    if (item !== null) items.push(item);
  }
  return items;
}

/** One page of new mail as items to index, and where the next page starts. */
export interface NewMailPage {
  readonly items: RecallItem[];
  readonly nextFrom: number;
}

/**
 * One page of the new mail in `[fromUid, toUidExclusive)`, oldest first
 * (Phase 26, D-16).
 *
 * The read is `summariesInRange`: read-only, bounded at both ends, and the
 * listing's own peeking rows. Each row goes through `recallItemOf`, the same
 * function the window's pages use, so the subject is stored, the body preview
 * is only embedded, and a row whose date does not parse is left out.
 * `nextFrom` is the read's own, unchanged: a row left out here was still read,
 * and is not read again.
 */
export async function newMailPage(
  gate: SessionGate,
  principal: Principal,
  mailbox: string,
  uidValidity: number,
  fromUid: number,
  toUidExclusive: number,
): Promise<NewMailPage> {
  const page = await summariesInRange(
    principal,
    gate,
    mailbox,
    uidValidity,
    fromUid,
    toUidExclusive,
  );
  return { items: itemsOf(page.rows), nextFrom: page.nextFrom };
}

/** The validity of the first row that decodes, or null. */
function validityOfRows(rows: readonly MessageSummary[]): number | null {
  for (const row of rows) {
    try {
      return decodeMessageId(row.id).uidValidity;
    } catch {
      // Minted by the listing, so this does not happen; the next row is tried.
    }
  }
  return null;
}

/** One listing page of the window, below `cursor` when one is given. */
function readWindowPage(
  gate: SessionGate,
  principal: Principal,
  mailbox: string,
  cursor: PageCursor | null,
): Promise<SearchPage> {
  return searchMessages(
    principal,
    gate,
    mailbox,
    { startDate: windowStartDay() },
    {
      pageSize: RECALL_PAGE_SIZE,
      cursor: cursor === null ? undefined : encodeCursor(cursor),
    },
  );
}

/** Phase 25's page source, over the person's own IMAP mailbox. */
export const mailRecallSource: RecallSource = {
  /**
   * One page of the window, newest first, below `cursor` when one is given.
   *
   * A cursor whose validity the mailbox no longer has is refused by the
   * listing. The page is then read once more from the top, so the answer
   * carries the mailbox's current validity and the engine resets. Only that
   * refusal is retried (26-REVIEW WR-02): any other not-found, such as a
   * transient refusal to open the mailbox, propagates, so the build keeps its
   * cursor and is not sent back to the newest mail. The page's validity is
   * the first row's; with no row, the cursor's when it was accepted; otherwise
   * the window's UID snapshot is asked for it.
   */
  async page(gate, principal, mailbox, cursor): Promise<RecallPage> {
    let accepted = cursor;
    let listing: SearchPage;
    try {
      listing = await readWindowPage(gate, principal, mailbox, cursor);
    } catch (error) {
      if (cursor === null || !(error instanceof ImapValidityChangedError)) throw error;
      accepted = null;
      listing = await readWindowPage(gate, principal, mailbox, null);
    }

    const items = itemsOf(listing.messages);
    const next = listing.nextCursor === null ? null : decodeCursor(listing.nextCursor);

    let uidValidity = validityOfRows(listing.messages);
    if (uidValidity === null && accepted !== null) uidValidity = accepted.uidValidity;
    if (uidValidity === null) {
      uidValidity = (await windowUids(principal, gate, mailbox, windowStartDay())).uidValidity;
    }
    return { uidValidity, items, next };
  },

  /** Every UID in the window, and the mailbox's validity. */
  uids(gate, principal, mailbox) {
    return windowUids(principal, gate, mailbox, windowStartDay());
  },
};
