// The retention and cost terms for semantic recall (Phase 25, D-06, D-24).
//
// These are the terms PROJECT.md must record, in the owner's words, BEFORE the
// recall index is created. The values below are the recommended ones. The owner
// may change any of them in plan 25-05, and a change lands here, before any
// vector exists. After the index exists, a change still only takes effect for
// vectors written from then on.
//
// Recall is inherent (owner, 2026-09-27). Every person who signs in has their
// recent mail indexed, with no switch to turn it on or off. So these numbers are
// not a setting a person picks. They are the whole of what bounds what this
// server keeps, and what it costs, per person.
//
// What each one bounds:
//
// - RECALL_TTL_MS: how long a vector is kept. 90 days from the message's date,
//   and never more than 90 days from when it was indexed. The person's object
//   computes the expiry itself, so a caller cannot extend it.
// - SNIPPET_MAX_CHARS: the one piece of plain text stored per message. It is
//   meant to be the subject line, so a person can recognise a result. No body
//   text is ever stored.
// - EMBED_TEXT_MAX_CHARS: how much text is sent to the embedding model for one
//   message. That text is embedded and thrown away, never stored.
// - RECALL_MAX_VECTORS: the most vectors one person can hold.
// - RECALL_MAX_PAGES_PER_DAY: the most build pages one person can run in one
//   UTC day. A reconcile counts as a page.
// - RECALL_PAGE_SIZE: messages per build page. It lives here and not in the
//   build engine because the object needs it to leave room for one page under
//   the vector ceiling, and the object must not import the engine.
// - RECALL_BACKFILL_MAX_PAGES_PER_DAY: the most backfill pages one person can
//   run in one UTC day (Phase 29.1.1). A backfill page is one the person asked
//   for, from the backfill tool, while they watch. It skips the one-minute pause
//   and the ordinary day count, and counts here instead. The number is
//   RECALL_MAX_VECTORS / RECALL_PAGE_SIZE: exactly enough pages to fill the
//   ceiling once, so a runaway backfill costs at most what filling the ceiling
//   costs, about $0.12 of embedding per person per day.
//
// What this costs per person, from the live price pages: Vectorize bills about
// $0.01 per million queried dimensions (stored vectors plus queries, counted
// once a month) and $0.05 per 100 million stored dimensions; the embedding model
// costs about $0.0118 per million input tokens. Assuming at most 1,000 tokens
// per embedded message and 300 recall queries a month, and before the account's
// included allowances:
//
// - a typical person with 1,500 vectors costs about $0.02 once to embed, and
//   about $0.02 a month to hold and query;
// - a person at the vector ceiling costs about $0.12 once, and about $0.11 a
//   month;
// - the daily page cap holds a runaway build to about $0.06 of embedding per
//   person per day.
//
// Constants only. Nothing else belongs in this file.

/** How long a vector is kept: 90 days, in milliseconds. */
export const RECALL_TTL_MS = 90 * 24 * 60 * 60 * 1000;

/** The most characters of the stored snippet (the subject line). */
export const SNIPPET_MAX_CHARS = 160;

/** The most characters of text embedded for one message. Never stored. */
export const EMBED_TEXT_MAX_CHARS = 2000;

/** The most vectors one person may hold. */
export const RECALL_MAX_VECTORS = 10000;

/** The most build pages (reconciles included) one person may run in a UTC day. */
export const RECALL_MAX_PAGES_PER_DAY = 200;

/** Messages per build page. */
export const RECALL_PAGE_SIZE = 25;

/**
 * The most backfill pages one person may run in a UTC day (Phase 29.1.1).
 *
 * It bounds a backfill the way RECALL_MAX_PAGES_PER_DAY bounds ordinary pages:
 * exactly enough pages to fill the vector ceiling once. Decided by Claude,
 * 2026-09-28; the owner may revise it.
 */
export const RECALL_BACKFILL_MAX_PAGES_PER_DAY = RECALL_MAX_VECTORS / RECALL_PAGE_SIZE;
