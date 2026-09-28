// FND-05: the closed error vocabulary and the single translation boundary.
//
// Four of the categories below are the four FND-05 names. Two more —
// `stale_resource` and `confirmation_invalid` — ARRIVED in Phase 5 with
// CALW-05 and CALW-04, the requirements that made them raisable: the first
// from a 412 on a conditional write, the second from a rejected commit
// confirmation. They landed in ONE edit rather than in the plan that needed
// each, because growing the union twice would open a window in which a
// category existed that nothing could raise.
//
// The classes below map to the categories. `MailConfirmationError` joined them
// in Phase 21: the mail tree's translation of a refused confirmation, the twin
// of `DavConfirmationError` in `src/dav/errors.ts`.
//
// ARCHITECTURE.md Q7 lists four that have NOT arrived (operation_rejected,
// protocol_error, forbidden, service_unavailable); those arrive with the
// phases that can actually produce them, on exactly the footing the two above
// stood on until Phase 5. Inventing one here would put a category in the
// model's vocabulary that no code path can reach.

/**
 * Every error category a tool in this repository may report.
 *
 * - `auth_failed` — iCloud rejected the stored credentials.
 * - `connection_failed` — could not establish or maintain the TLS socket.
 * - `rate_limited` — iCloud is throttling or refusing connections.
 * - `not_found` — the addressed mail resource cannot be reached. Reserved and
 *   unreachable in Phase 1; **reachable from Phase 2** via `ImapNotFoundError`.
 *   Three conditions raise it, and they are deliberately indistinguishable to
 *   the caller: a token that is undecodable or of the wrong kind
 *   (`src/mail/ids.ts`), a UIDVALIDITY carried in a token that no longer
 *   matches the one the session reports, and a `NO` response to a mailbox
 *   selection. All three mean the same thing operationally — the message or
 *   folder the caller named is not addressable now — and collapsing them keeps
 *   the vocabulary closed rather than growing one category per cause.
 * - `stale_resource` — the addressed resource changed between the preview and
 *   the commit, so the write was refused rather than applied over the change.
 *   Reserved and unreachable before Phase 5; **reachable from Phase 5** via
 *   `DavStaleResourceError`, which `src/dav/transport.ts` raises on a 412.
 *   The RFC 6638 §3.2.10 consequence is stated here as well as in the safe
 *   message, because a reader of the type is a different reader from a reader
 *   of the string: an event carrying attendees has its ETag changed by the
 *   SERVER when an attendee replies, so this category is reachable without
 *   anyone having edited anything. That is a known cost of preferring
 *   `If-Match` over the merging alternative the RFC recommends, and it is a
 *   deliberate choice rather than an oversight.
 * - `confirmation_invalid` — the confirmation supplied with a commit was not
 *   accepted. Reserved and unreachable before Phase 5; **reachable from Phase
 *   5** via `DavConfirmationError`. Six conditions raise it and they are
 *   deliberately indistinguishable to the caller: a confirmation that is not
 *   two encoded parts, one whose seal does not verify, one whose lifetime has
 *   run out, one naming a kind the handler does not know, one that does not
 *   match the re-supplied change, and one already spent. All six mean the same
 *   thing operationally — this confirmation does not authorise this write now
 *   — and collapsing them is what keeps the commit endpoint from being an
 *   oracle for the confirmation's internal structure. This is `not_found`'s
 *   own argument, one module over.
 * - `subscription_unreadable` — a `CS:subscribed` calendar's events could not
 *   be read. Reserved and unreachable before this quick task; **reachable**
 *   via `DavSubscriptionError`. This is the one category whose reason is about
 *   what the alternative would have said rather than about what happened —
 *   every other category reports a visible failure, this one reports a
 *   SUCCESS that would have been misread as an answer: the CalDAV request
 *   this server sent came back correctly, and it correctly said the
 *   collection holds no calendar object resources, because a subscription's
 *   events live only in the feed at its `CS:source`. Deliberately NOT
 *   `not_found` — the calendar exists and `calendar_list_calendars` lists it,
 *   so telling the model it does not exist trades one confident falsehood for
 *   another.
 * - `request_unsendable` — THIS SERVER could not express the request at all,
 *   so nothing was sent and no server saw it. Reserved and unreachable before
 *   Phase 14; **reachable from Phase 14** via `DavUnsendableError`, which
 *   `src/dav/transport.ts` raises when the runtime refuses to build the
 *   request. It exists because of a measured failure rather than a
 *   hypothetical one: workerd accepts `PROPFIND`, `PROPPATCH`, `REPORT`,
 *   `MKCOL` and every other method this project sends, and refuses the RFC
 *   4791 calendar-creation method — so tsdav's collection-creation helper,
 *   which hardcodes that one, threw before any
 *   byte left the Worker, and the throw arrived at `connection_failed`, which
 *   told the reader that a connection to iCloud had failed and that a retry
 *   was safe. Both halves of that sentence were false, and the result was a
 *   report that looked like a measurement of iCloud's behaviour. That is the
 *   same argument `stale_resource` already rests on one category up — a
 *   failure no retry can fix must not be dressed as a transient one — with a
 *   second claim on top: this category is the only one in the union that says
 *   the remote end was never involved, so it is the only one that can stop a
 *   platform limit being written down as a server's answer.
 * - `connection_busy` — another request on this same account already holds
 *   the account's mail connection lease, so this one was refused before it
 *   started. Arrived in Phase 24 (D-06, owner-accepted 2026-09-27), reachable
 *   from the day it arrived via `ConnectionBusyError`, which
 *   `src/agent/lease.ts` raises. Not a duplicate of `rate_limited`: that one
 *   says iCloud is refusing, and here iCloud refused nothing. The cause is the
 *   person's own other request, and the next step differs with it.
 */
export type ErrorCategory =
  | "auth_failed"
  | "connection_failed"
  | "rate_limited"
  | "not_found"
  | "stale_resource"
  | "confirmation_invalid"
  | "subscription_unreadable"
  | "request_unsendable"
  | "connection_busy";

/**
 * Thrown when the server rejects the credentials.
 *
 * Constructed with a fixed internal label and never with server-supplied
 * text. The reason is specific rather than stylistic: on the credential path
 * the nearest available "context" is the command line that was just written,
 * and IMAP puts the password inline in that line.
 */
export class ImapAuthError extends Error {
  readonly kind = "auth" as const;

  constructor() {
    super("imap-credentials-rejected");
    this.name = "ImapAuthError";
  }
}

/** Thrown when the transport fails to establish, read, or stay open. */
export class ImapConnectError extends Error {
  readonly kind = "connect" as const;

  constructor() {
    super("imap-transport-failed");
    this.name = "ImapConnectError";
  }
}

/**
 * Thrown when the server signals it is refusing or throttling connections.
 *
 * **The one class in this file that takes a constructor argument, and the
 * reason it is safe here is specific rather than general.** `detail` is the
 * server's own reply text, read from a PARSED REPLY at the point of knowledge —
 * never from a caught value's `.message` or `.stack`. The credential travels in
 * the command this client SENT, not in the reply it received, so echoing a
 * reply cannot echo the credential. That is a structural fact rather than a
 * likely one: `src/mail/credentials.ts` refuses an Apple ID or password
 * containing CR, LF or NUL outright, so no credential byte can terminate a
 * command line early and reappear inside what the server quotes back.
 *
 * It is the same justification `authFailureDetail` already rests on, which is
 * why the two fields are on the same footing and neither is on the footing of
 * an exception's own text.
 *
 * **`ImapConnectError` deliberately stays context-free and must not follow this
 * precedent.** That one is raised from a `catch` where the bytes in flight can
 * be the LOGIN command; there is no parsed reply to read from, only the caught
 * value, and reading it is exactly what the discipline forbids.
 *
 * `null` whenever the server said nothing usable, or when the refusal came from
 * a path with no reply to quote — the single-slot session gate in
 * `src/mail/service.ts` raises this class with no server involved at all.
 *
 * `detail` NEVER reaches `message`. The fixed internal label is unchanged, so
 * `toErrorCategory` produces the same category and the same fixed safe message
 * whether a detail is present or not; the text rides in a dedicated field that
 * only the tool boundary surfaces, and only after a type check.
 */
export class ImapThrottleError extends Error {
  readonly kind = "throttle" as const;

  /** The server's own refusal text, already bounded, or `null`. */
  readonly detail: string | null;

  constructor(detail: string | null = null) {
    super("imap-throttled");
    this.name = "ImapThrottleError";
    this.detail = detail;
  }
}

/**
 * Thrown when the addressed mail resource cannot be reached.
 *
 * This is the class that makes `not_found` reachable. It is NOT a fifth
 * category — the entry it maps to has existed in `SAFE_MESSAGES` since Phase 1
 * and was reserved for exactly this arrival.
 *
 * Constructed with a fixed internal label and never with server-supplied text,
 * for the same reason as the three classes above. It carries a second reason of
 * its own: the commonest way to reach it is a token the model supplied, and a
 * diagnosis quoting the offending token back — or explaining which field of it
 * failed to parse — would teach the model the token's internal structure. The
 * opaque identifier layer exists precisely so the model never constructs one,
 * and an error message is the easiest place to give that away for free.
 */
export class ImapNotFoundError extends Error {
  readonly kind = "not-found" as const;

  constructor() {
    super("imap-resource-not-found");
    this.name = "ImapNotFoundError";
  }
}

/**
 * The one not-found that says WHY: the mailbox's UIDVALIDITY is not the one
 * the caller expected (26-REVIEW WR-02).
 *
 * Thrown only by the open's validity gate, when the caller named a validity
 * and the server reported another. Every other not-found cause — a refused
 * open, a missing validity, a fetch with no row — stays the plain class, so a
 * caller that treats this one as "the mailbox was recreated" never mistakes a
 * transient refusal for it. The recall page source relies on that: it reads
 * the window again from the top only on this class.
 *
 * A subclass of `ImapNotFoundError`, so `toErrorCategory` answers `not_found`
 * through the parent's branch, and every answer the model is given is exactly
 * what it was before. Fixed label, no constructor argument, as above.
 */
export class ImapValidityChangedError extends ImapNotFoundError {
  constructor() {
    super();
    this.name = "ImapValidityChangedError";
  }
}

/**
 * Thrown when the confirmation supplied with a mail commit was not accepted.
 *
 * The mail tree's twin of `DavConfirmationError`, and here for the same
 * contract. `src/confirm.ts` is protocol-neutral and throws its own
 * `ConfirmationInvalidError`; the mail tools catch that at their own boundary
 * and rethrow this, because `toErrorCategory` dispatches on TYPE and would
 * otherwise report a refused confirmation as a failed connection, telling the
 * model to retry something that will be refused the same way every time.
 *
 * Every cause answers the same way, and it takes no constructor argument, so
 * there is nowhere for a cause to ride even by accident.
 */
export class MailConfirmationError extends Error {
  readonly kind = "confirmation" as const;

  constructor() {
    super("mail-confirmation-rejected");
    this.name = "MailConfirmationError";
  }
}

/**
 * Thrown when another request on the same account holds the connection lease.
 *
 * Raised by `withConnectionLease` in `src/agent/lease.ts` BEFORE any socket is
 * opened, so nothing was started and nothing was changed. No server is
 * involved at all, which is why this is not `ImapThrottleError`: that class
 * maps to a sentence blaming iCloud, and iCloud said nothing here.
 *
 * Fixed internal label, no constructor argument, the same as the classes
 * above, so there is nowhere for a cause to ride.
 */
export class ConnectionBusyError extends Error {
  readonly kind = "busy" as const;

  constructor() {
    super("mail-connection-lease-held");
    this.name = "ConnectionBusyError";
  }
}

/**
 * Fixed, human-readable text for each category, including retry guidance.
 *
 * These strings are the ONLY error prose that ever reaches a caller. They are
 * constants, so no server response and no exception message can influence
 * them.
 *
 * Three of the first four name "iCloud Mail", which is a small inaccuracy on a
 * calendar call. It is accepted deliberately — `src/dav/errors.ts` records the
 * argument — and the three strings that arrived after Phase 1 (the two from
 * Phase 5, plus `subscription_unreadable`) are written protocol-neutral so they
 * do not extend it. `auth_failed` joined them when Phase 11 reworded it: the
 * recovery it now describes is a fresh sign-in, which is the same recovery on
 * every tool.
 */
export const SAFE_MESSAGES: Record<ErrorCategory, string> = {
  // The fallback for a client that does not act on the door's 401. That door
  // answers a grant with no usable credentials with a real challenge, and a
  // client that honours it drops its token and starts a fresh login without
  // the person ever seeing this string. How clients actually behave on a dead
  // login is rated low confidence, so this text is the recovery that works
  // either way: it reaches the person through the model's own answer.
  //
  // It names no protocol and no mailbox, because the same string is served on
  // a calendar or a contacts call and a sentence naming mail would be wrong
  // two thirds of the time. It also names no owner and no Worker secret: after
  // Phase 11 the credential belongs to the signed-in person, and the only
  // person who can fix it is the one reading this.
  auth_failed:
    "iCloud rejected the password saved for this connection. Reconnect " +
    "this server in your Claude app and sign in again; retrying will not " +
    "help.",
  // The floor, and the one entry in this table whose old wording was measured
  // wrong rather than argued wrong.
  //
  // It used to end "This may be transient — safe to retry once." Phase 14's
  // collection write was refused by the runtime before any byte left the
  // Worker; the throw landed in the DAV transport's catch, fell through to
  // this default, and the probe reported that sentence for a failure that was
  // neither transient nor retryable. The report then read as a measurement of
  // what iCloud does with collection writes. It was a measurement of what the
  // platform this server runs on does with a method string, and it was on its
  // way into a written verdict that would have reshaped a later phase.
  //
  // `request_unsendable` closed that particular hole by adding a CLASS. This
  // wording closes what is left of it: every unclassified value still arrives
  // here — a thrown string, a plain `Error`, a tsdav error this layer refuses
  // to read — and most of them are not connection failures at all. So the
  // entry now says what this server can actually tell, which is nothing, and
  // offers a single retry instead of certifying one as safe.
  //
  // **The CATEGORY did not change, and that was decided rather than
  // defaulted.** A server asking the caller to wait already has its own entry
  // in this table, `rate_limited`, and that entry already says to wait and not
  // to loop. The gap was never a missing category; it was a floor that
  // promised more than it knew, and a ninth member beside a shipped eighth
  // that already answers the question would put a duplicate in the model's
  // vocabulary.
  //
  // The first clause still names iCloud Mail, which is the small inaccuracy on
  // a calendar call that `src/dav/errors.ts` records as deliberately accepted.
  // Rewording it would touch shipped Phase 1 and 2 responses for a cosmetic
  // gain; that is a separate decision and this is not it.
  connection_failed:
    "Could not establish a secure connection to iCloud Mail. This is what " +
    "this server reports when it cannot tell what went wrong, so it may or " +
    "may not be transient. Retry once at most — if it happens again, the " +
    "cause is not transient and retrying will not help.",
  rate_limited:
    "iCloud is temporarily refusing connections. Wait before retrying; do " +
    "not retry in a loop.",
  not_found: "The requested mail resource does not exist.",
  // Three things, and the third is the one that has to be here rather than in
  // a comment. Without the attendee sentence, the first genuine occurrence
  // reads as a bug and gets "fixed" by dropping the conditional header — which
  // is the one change that would make a lost update possible again.
  stale_resource:
    "The event changed after the preview, so nothing was overwritten. " +
    "Preview the change again before committing; repeating this commit will " +
    "not succeed. An attendee replying to an invitation also changes the " +
    "event, so this can happen when nobody edited anything.",
  // Names no cause, no field, no encoding and no lifetime. Six checks can
  // produce this and the caller learns which one only by learning the
  // confirmation's internal structure, which is exactly what it must not.
  confirmation_invalid:
    "The confirmation supplied with this request was not accepted, and " +
    "nothing was changed. Preview the change again and commit the new " +
    "confirmation.",
  // States the negative explicitly, because the harm this category exists to
  // prevent is exactly the sentence it forbids: a calendar that is a
  // subscription to a feed published elsewhere is not the same as a calendar
  // with nothing on it today.
  subscription_unreadable:
    "This calendar is a subscription to a feed published elsewhere, and " +
    "this server could not read its events. That is NOT the same as the " +
    "calendar being empty — do not report it as having no events. " +
    "Retrying will not help; the user can see these events in their own " +
    "Calendar app.",
  // Says the remote end was never involved, in the first sentence, because
  // that is the whole reason the category exists. Every other string in this
  // table describes something iCloud did; a reader who skimmed this one and
  // filed it beside them would record a platform limit as a measurement of
  // Apple's behaviour, which is the exact mistake it was added to prevent.
  request_unsendable:
    "This server could not build the request, so nothing was sent and " +
    "iCloud never saw it. This says nothing about your account or about " +
    "iCloud. Retrying will not help — it is a limit of the platform this " +
    "server runs on, and it needs a code change.",
  // Its own entry rather than a reuse of `rate_limited`, decided by the owner
  // on 2026-09-27 (D-06). `rate_limited` says iCloud is refusing connections,
  // and here iCloud refused nothing: another request of the person's own holds
  // the one mail connection this account is allowed at a time. The guidance
  // overlaps (wait, do not loop), the cause does not, and the cause is what
  // tells the person where to look — another Claude app or window running a
  // mail call right now. The last sentence is true because the lease carries
  // an absolute 30-second expiry (`LEASE_TTL_MS`).
  connection_busy:
    "Another request on this account is already using its iCloud mail " +
    "connection, so this request was not started and nothing was changed. " +
    "Wait a few seconds before retrying, and do not retry in a loop. A " +
    "request that stopped part-way clears itself within half a minute.",
};

/**
 * The ONLY function in this repository permitted to produce a tool-visible
 * error.
 *
 * It dispatches on the error's *type* and never reads `.message` or `.stack`
 * from the caught value, because a caught value on the credential path can
 * carry a raw IMAP command line and IMAP puts the password inline in it.
 *
 * Anything unrecognised — including `null`, `undefined`, a string, or a
 * plain object — falls through to `connection_failed`, which is both the
 * safest default and the most common real cause.
 */
export function toErrorCategory(err: unknown): {
  category: ErrorCategory;
  message: string;
} {
  let category: ErrorCategory = "connection_failed";

  if (err instanceof ImapAuthError) category = "auth_failed";
  else if (err instanceof ImapThrottleError) category = "rate_limited";
  else if (err instanceof ImapNotFoundError) category = "not_found";
  else if (err instanceof ImapConnectError) category = "connection_failed";
  else if (err instanceof MailConfirmationError) category = "confirmation_invalid";
  else if (err instanceof ConnectionBusyError) category = "connection_busy";

  return { category, message: SAFE_MESSAGES[category] };
}
