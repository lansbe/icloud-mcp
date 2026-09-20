// D-57: the DAV tree's typed error classes and its translation boundary.
//
// A parallel to `src/errors.ts`, not a subclass of it. Every class below
// mirrors the `Imap*` classes in shape — fixed internal label, `readonly kind`
// discriminant, no server-supplied text — and shares nothing with them at
// runtime. Four came from Phase 3; the last two arrived in Phase 5 and have no
// `Imap*` counterpart, because nothing on the mail path can raise them.
//
// What IS shared is the vocabulary: `ErrorCategory` and `SAFE_MESSAGES` are
// imported from `src/errors.ts`. Since Phase 9 one class comes with them: the
// auth error the principal module raises, which the translation function below
// has to recognise by type (D-10). Nothing else is imported. That import is legal
// under ARCHITECTURE Q1's zero-import boundary because `src/errors.ts` sits at
// the source root beside `src/env.ts` — it is not `src/mail/`, and it has no
// knowledge of either protocol tree. Importing the vocabulary is what keeps the
// two trees from growing two vocabularies; copying the strings instead would
// produce two tables that agree today and disagree in a year. The count is
// stated in exactly one place, `src/errors.ts`, and is deliberately not
// restated here — a number written down twice goes stale on one side silently.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { ErrorCategory } from "../errors";
import { ImapAuthError, SAFE_MESSAGES } from "../errors";

/**
 * Thrown when iCloud rejects the credentials, or when a credential is absent.
 *
 * Constructed with a fixed internal label and never with server-supplied text,
 * for the same reason `ImapAuthError` is: nothing on this path may echo
 * anything a server said about a request that carried the credential.
 *
 * The absent-secret case maps here rather than to a transport category on
 * `src/mail/credentials.ts`'s own reasoning — the fixed safe message already
 * says a human needs to check the app-specific password and that retrying will
 * not help, which is exactly true of a binding that was never provisioned,
 * where `connection_failed` says the opposite.
 */
export class DavAuthError extends Error {
  readonly kind = "auth" as const;

  constructor() {
    super("dav-credentials-rejected");
    this.name = "DavAuthError";
  }
}

/** Thrown when the DAV request could not be made, or came back unusable. */
export class DavConnectError extends Error {
  readonly kind = "connect" as const;

  constructor() {
    super("dav-transport-failed");
    this.name = "DavConnectError";
  }
}

/**
 * Thrown when the server signals it is throttling or temporarily refusing.
 *
 * Deliberately context-free, unlike `ImapThrottleError`. That class takes the
 * server's own reply text because IMAP hands back a parsed reply at the point
 * of knowledge and the credential structurally cannot appear in it. There is no
 * equivalent here: what a DAV server sends back on a refusal is a response
 * body, and a body is exactly what T-03-04 says must not travel.
 */
export class DavThrottleError extends Error {
  readonly kind = "throttle" as const;

  constructor() {
    super("dav-throttled");
    this.name = "DavThrottleError";
  }
}

/**
 * Thrown when the addressed DAV resource cannot be reached.
 *
 * **The one class in this file that takes a constructor argument, and the
 * reason it is safe is specific rather than general.** `rediscoverable` is a
 * classification of an HTTP STATUS NUMBER, read at the point of knowledge — the
 * fetch boundary in `./transport.ts`, where the number is a number in a field —
 * and never from a caught value's `.message` or `.stack`. It is the same
 * footing `ImapThrottleError.detail` rests on: a fact read from a parsed reply
 * rather than from an exception's own text.
 *
 * It carries no URL, no status line, no server body, and no `DAVResponse.raw`.
 * A boolean cannot carry any of those, which is why the field is a boolean and
 * not the status number itself — the number would be one small step from being
 * reported, and nothing downstream needs it.
 *
 * `true` means D-60 permits exactly one re-discovery and one retry: the cached
 * host may simply be stale. `false` means the server answered a question about
 * its own CAPABILITIES rather than about a resource, so re-discovery cannot
 * help and must not be attempted.
 */
export class DavNotFoundError extends Error {
  readonly kind = "not-found" as const;

  /** Whether D-60 permits one re-discovery and one retry for this failure. */
  readonly rediscoverable: boolean;

  constructor(rediscoverable = false) {
    super("dav-resource-not-found");
    this.name = "DavNotFoundError";
    this.rediscoverable = rediscoverable;
  }
}

/**
 * Thrown when the addressed resource changed between the preview and the write.
 *
 * The 412 branch in `./transport.ts` is the only place this is raised, and it is
 * what makes CALW-05 fail CLOSED: a conditional write whose precondition the
 * server refused is reported as the refusal it is, rather than as a transport
 * fault the model is told to retry.
 *
 * **It takes no constructor argument, where `DavNotFoundError` takes one, and
 * the asymmetry is the point rather than an inconsistency.** That class's
 * `rediscoverable` is a classification of a status NUMBER read at the point of
 * knowledge — 415 and 501 mean something different from 404 and 410, and only
 * the fetch boundary knows which arrived. This class needs no such
 * classification because the answer is fixed: there is no host to re-resolve. A
 * precondition failure is a statement about the RESOURCE'S current state, not
 * about where the account lives, so making it re-discovery eligible would spend
 * a real PROPFIND and a second write to arrive at the identical 412.
 *
 * It therefore carries no URL, no status line, no server body and no etag —
 * there is no field for one to ride in.
 */
export class DavStaleResourceError extends Error {
  readonly kind = "stale-resource" as const;

  constructor() {
    super("dav-resource-changed");
    this.name = "DavStaleResourceError";
  }
}

/**
 * Thrown when the confirmation supplied with a commit was not accepted.
 *
 * **This class exists to satisfy a translation contract, and the contract is
 * the whole reason it is here rather than in the neutral module.**
 * `src/confirm.ts` is protocol-neutral and throws its own
 * `ConfirmationInvalidError`; this tree catches that at its own boundary and
 * rethrows this class, because `davToErrorCategory` dispatches on TYPE and
 * falls through to a connection diagnosis for anything it does not recognise. A
 * neutral error that escaped untranslated would tell the caller the network
 * failed when what actually happened is that a confirmation was refused —
 * guidance that is not merely imprecise but points at the wrong remedy.
 *
 * That is `TokenDecodeError`'s contract restated for a second neutral module,
 * and the reason is the same one `src/dav/ids.ts` records for its own single
 * `catch`.
 *
 * **Six conditions raise it and they all answer the same way.** Not two encoded
 * parts; a seal that does not verify; a lifetime that has run out; a kind the
 * handler does not know; a change that does not match what was confirmed; and
 * one already spent. A seventh check added later maps here too, and names
 * nothing — the refusal must stay indistinguishable, or the commit endpoint
 * becomes an oracle for the confirmation's internal structure. Like the class
 * above it takes no constructor argument, so there is nowhere for a cause to
 * ride even by accident.
 */
export class DavConfirmationError extends Error {
  readonly kind = "confirmation" as const;

  constructor() {
    super("dav-confirmation-rejected");
    this.name = "DavConfirmationError";
  }
}

/**
 * Thrown when a `CS:subscribed` collection cannot be read.
 *
 * **The one class in this file raised on a request that SUCCEEDED.** A
 * `CS:subscribed` collection is a pointer record holding zero calendar object
 * resources — proven four independent ways live against the account
 * (`.planning/debug/subscribed-cal-events-empty.md`): PROPFIND depth 1 returns
 * only the collection's own href; a filtered calendar-query returns an empty
 * multistatus; an unfiltered one still returns no member; sync-collection
 * returns the collection and a sync-token and no member. The CalDAV report
 * this server sends is well formed, and iCloud's empty answer to it is
 * correct. Reporting that as `eventCount: 0` reads as "nothing on your
 * calendar today," confidently and wrongly — so this raises instead.
 *
 * **Raised ONLY when `collection.source === null`.** A subscription WITH a
 * readable `CS:source` is read via `../feed/subscription-feed.ts` and
 * `./icalendar.ts`'s `splitSubscriptionFeed` instead of being refused here —
 * see `pagedEvents` and `collectFrom` in `./calendar.ts`.
 *
 * No constructor argument, unlike `DavNotFoundError`. The `CS:source` href is
 * a URL on a third-party host, and the error boundary is the last place a URL
 * like that should ride out; the collection that carried it is the caller's to
 * hold, not this error's.
 */
export class DavSubscriptionError extends Error {
  readonly kind = "subscription" as const;

  constructor() {
    super("dav-subscription-not-readable");
    this.name = "DavSubscriptionError";
  }
}

/**
 * The ONLY function in the DAV tree permitted to produce a tool-visible error.
 *
 * Mirrors `toErrorCategory` exactly: dispatch on the error's *type*, default to
 * `connection_failed`, and never read `.message` or `.stack` from the caught
 * value.
 *
 * **The DAV-specific reason that discipline matters is worth stating, because
 * it is not the IMAP one.** tsdav throws bare `Error` objects whose message
 * embeds a server URL — `Invalid credentials: PROPFIND <rootUrl> returned 401
 * Unauthorized` is verbatim from its source. Reading `.message` here would
 * therefore leak the resolved shard host into a tool response, which is exactly
 * what the discovery layer exists to prevent: the model must never learn where
 * the account physically lives. A tsdav error arriving here falls through to
 * `connection_failed` and says nothing.
 *
 * That fall-through is a floor, not the plan. The classification that actually
 * happens is done in `./transport.ts` by status NUMBER, before tsdav ever sees
 * the response — so by the time a `Dav*` error reaches here it already carries
 * its category in its type.
 *
 * **The chain is seven branches, and its ORDER is a constraint rather than an
 * accident.** `DavConnectError` is last because it is the explicit statement of
 * the same answer the default already gives, and a branch appended after it
 * would sit below the floor while looking like a peer of the others. The two
 * Phase 5 branches, and now `DavSubscriptionError`, are therefore inserted
 * before it, and any eighth goes in the same place. The first branch also
 * answers for the principal module's refusal, because a DAV callback awaits the
 * promise of the principal and a bad secret must read `auth_failed` and not a
 * connection fault.
 *
 * The safe messages name "iCloud Mail" on the connection branch, which is a
 * small inaccuracy on a calendar call. It is accepted deliberately, on the same
 * footing `createSessionGate`'s refusal text already stands on: the operational
 * guidance is the part a model acts on, and it is correct. Rewording the shared
 * table to be protocol-neutral would touch shipped Phase 1 and 2 responses for
 * a cosmetic gain.
 */
export function davToErrorCategory(err: unknown): {
  category: ErrorCategory;
  message: string;
} {
  let category: ErrorCategory = "connection_failed";

  if (err instanceof DavAuthError || err instanceof ImapAuthError) {
    category = "auth_failed";
  } else if (err instanceof DavThrottleError) category = "rate_limited";
  else if (err instanceof DavNotFoundError) category = "not_found";
  else if (err instanceof DavStaleResourceError) category = "stale_resource";
  else if (err instanceof DavConfirmationError) {
    category = "confirmation_invalid";
  } else if (err instanceof DavSubscriptionError) {
    category = "subscription_unreadable";
  } else if (err instanceof DavConnectError) category = "connection_failed";

  return { category, message: SAFE_MESSAGES[category] };
}
