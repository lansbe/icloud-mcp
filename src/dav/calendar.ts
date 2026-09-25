// The calendar service layer: collections, a bounded expanded range, a total
// order, and keyset paging (CAL-01, CAL-02, CAL-05).
//
// This module owns SHAPE and COST. It decides how many round trips a listing
// makes, what a row is allowed to carry, and where a page ends. It does not own
// meaning: every byte of iCalendar goes to `./icalendar.ts`, every identifier
// and every ordering decision comes from `./ids.ts`, and every outbound request
// goes through the injected fetch built in `./transport.ts`. Three separations,
// and each one exists because the alternative was a second implementation that
// agreed with the first only until someone edited one of them.
//
// **There is no multi-collection operation here at all any more, and that is a
// safety property rather than a tidying.** ./.claude/CLAUDE.md §3 records the
// budget: production allows six simultaneous connections per Worker invocation,
// KV reads and outbound fetches count against the same six, and iCloud's own
// per-account ceiling is lower, undocumented, and deliberately unmeasured —
// because exhausting it does not fail politely, it locks the user out of their
// own mail in Mail.app on their own devices. The account-wide listing was where
// a fan-out was genuinely tempting, and it was withdrawn: `calendarId` is
// required, so every read here touches exactly one calendar. The two bans
// remain in force over what is left — structurally by the request-scoped queue
// in `./transport.ts`, detectively by the `dav-concurrent-request` scan rule
// that reads this file — because re-adding the sweep must be a decision that
// trips them rather than a change that slips past.
//
// This module contains no logging calls of any kind and must never acquire any.

import {
  calendarMultiGet,
  createCalendarObject,
  davRequest,
  deleteCalendarObject,
  fetchCalendarObjects,
  fetchCalendarUserAddresses,
  propfind,
  updateCalendarObject,
} from "tsdav";
import type { DAVResponse } from "tsdav";
import type { Env } from "../env";
import { fetchSubscriptionFeed } from "../feed/subscription-feed";
import { assertUnderHome, davAccountFor, withRediscovery } from "./discovery";
import type { ResolvedDavAccount } from "./discovery";
import {
  DavAuthError,
  DavConnectError,
  DavNotFoundError,
  DavSubscriptionError,
  DavThrottleError,
} from "./errors";
import {
  applyEventChange,
  applyExdate,
  applyOccurrenceOverride,
  buildVEvent,
  countOccurrences,
  dropOverride,
  expandWithinBudget,
  findOccurrence,
  isRecurringResource,
  isSupportedTimezone,
  localTimeToUtc,
  newStepBudget,
  nextSequence,
  pinnedOccurrencesAfter,
  removedStartsOf,
  sequenceOfResource,
  serializeCalendarResource,
  serializeOccurrenceResource,
  splitSubscriptionFeed,
  truncateSeries,
  utcToLocalTime,
  withParsedResource,
} from "./icalendar";
import type {
  BuildEventInput,
  BuildParticipants,
  EventParticipant,
  Occurrence,
  OccurrenceCounts,
  OverrideRange,
  ParsedCalendarResource,
  PinnedOccurrences,
  StepBudget,
  WriteScope,
} from "./icalendar";
import {
  clampPageSize,
  compareEventOrder,
  decodeCalendarCursor,
  decodeCalendarId,
  decodeSlotCursor,
  encodeCalendarCursor,
  encodeCalendarId,
  encodeEventId,
  encodeSlotCursor,
  isAfterCalendarCursor,
  isAfterSlotCursor,
  sortInstantOf,
} from "./ids";
import type {
  CalendarCursor,
  EventOrderKey,
  EventRef,
  SlotCursor,
} from "./ids";
import type { DavFetch } from "./transport";
import type { Principal } from "../principal";

const SECONDS_PER_DAY = 86400;

/**
 * The widest date range one call may ask for.
 *
 * **The cap is about the COST OF REACHING the range, not the size of the
 * answer.** A recurrence iterator begins at the series' own start rather than
 * at the requested range, so a daily event begun a decade ago costs thousands
 * of steps before the first in-range occurrence appears — and a sub-daily rule,
 * which an invitation may legally carry, costs hundreds of millions. The
 * occurrence cap in `./icalendar.ts` cannot see any of that: it counts only
 * results that land inside the range, which is why a second cap on the walk
 * exists there and why this third one exists here.
 *
 * A year and a day, so "the next twelve months" and "this whole year" both fit
 * with a day to spare rather than failing on an off-by-one at the boundary.
 *
 * Refusing on the range is the CHEAPEST possible refusal — the same argument
 * the null-byte check in the mail search tool already makes. It is enforced
 * twice, deliberately: once in the zod schema of `src/mcp/tools/calendar.ts`,
 * before the handler body runs, and once here, before the KV read that
 * discovery would otherwise perform. Both spend none of the connection budget,
 * and the service-layer copy is what makes the property true for a caller that
 * did not arrive through MCP.
 */
export const MAX_RANGE_DAYS = 366;

/**
 * One calendar collection, named without its contents (CAL-01).
 *
 * Two rows sharing a display name are two rows. They are distinguished by
 * `id`, and merging them on the name would silently hide one of the user's
 * calendars — the failure mode a de-duplicating listing produces on exactly the
 * account most likely to have it, one with a personal and a shared calendar
 * both called the same thing.
 */
export interface CalendarSummary {
  /** The opaque token that names this collection. Minted here, so trusted. */
  id: string;
  /**
   * The collection's display name. **Stranger-authored.**
   *
   * A shared calendar's name is chosen by whoever shared it, which puts it in
   * the same class as a mail folder's display name — a short,
   * authoritative-looking string an instruction hides well in. The tool layer
   * fences it.
   */
  displayName: string;
  /** The colour the collection declares, or null. Stranger-authored. */
  color: string | null;
  /**
   * True when this collection carries the `CS:subscribed` resourcetype.
   *
   * **This server's own reading of a protocol resourcetype value — trusted,
   * unlike `displayName` and `color` beside it.** Nobody chose it, and a
   * boolean hides nothing. It rides on every row rather than only the true
   * ones, so it is a field the model learns to check before calling the event
   * tools rather than one it never notices: `calendar_list_events` and
   * `calendar_search` refuse a subscribed calendar with no readable source
   * instead of answering a false empty.
   */
  subscribed: boolean;
}

/** Every calendar collection the account has, plus where discovery came from. */
export interface CalendarListing {
  calendars: CalendarSummary[];
  /**
   * True when discovery answered from cache and no request was made for it.
   *
   * This server's own statement about its own work, on the same footing
   * `hasMore` sits on — so the tool layer puts it in the trusted half. It is
   * reported on every normal call rather than only through the diagnostic,
   * because a namespace that has quietly stopped serving hits is otherwise
   * invisible outside a deliberate diagnosis.
   */
  cacheHit: boolean;
}

/**
 * One occurrence, as a listing row (CAL-02, CAL-05).
 *
 * **There is no field on this type for the event's long free-text body, and
 * that is the point.** This is the calendar form of the argument `MessageSummary`
 * already makes one protocol over: the reliable way to keep a metadata-only
 * contract true against a later edit is for the shape to be unable to express
 * the violation. A description cannot be added to a row by accident; it can
 * only be added by changing this interface, which shows up in a diff.
 *
 * Each field is annotated with which half of the two-block response it belongs
 * to, because that mapping lives in `src/mcp/tools/calendar.ts` and a reader
 * arriving here should not have to open that file to know which values a
 * stranger wrote.
 */
export interface EventSummary {
  /** The opaque token that names this occurrence. Minted here, so trusted. */
  id: string;
  /** The opaque token of the collection it lives in. Minted here, so trusted. */
  calendarId: string;
  /** True when this is a date rather than an instant. This server's reading. */
  allDay: boolean;
  /** The start wall clock a person would read off the invitation. Trusted. */
  startLocal: string;
  /**
   * The zone `startLocal` is expressed in, or the one that failed.
   * **Stranger-authored on the unresolved path, so it rides in the FENCED half.**
   *
   * It was annotated `Trusted` here until 03-09, and the mistake is worth
   * keeping visible because it is an easy one to make twice. A `TZID` almost
   * always holds an IANA registry name, which reads exactly like a protocol
   * value — but when the resource NAMES a zone it never DEFINES, this field
   * carries the identifier the resource asked for, verbatim, because that
   * string is the only evidence there is. RFC 5545 admits a double-quoted
   * parameter value carrying any text, so on that path this is prose whoever
   * sent the invitation typed.
   *
   * The fence's test is *"did a stranger choose it"*, not *"does it look like a
   * protocol value"* — the same test that puts `partstat`, `role` and a shared
   * calendar's colour inside it. `timezoneUnresolved` below stays in the
   * TRUSTED half: the boolean is this server's own reading of what happened,
   * and it is what keeps the error vocabulary closed at four values. The two
   * read like one fact and are two.
   */
  startTzid: string;
  /**
   * Seconds since the epoch — **absent, not zero, when there is no instant.**
   *
   * An all-day date and a time whose zone the resource never defined both have
   * no instant, and both keep this field ABSENT. The derived key that made such
   * a row sortable is a different number and never appears here: publishing it
   * would hand the caller a plausible instant nobody computed while
   * `timezoneUnresolved` said, in a field they might not read, that there was a
   * question. See `sortInstantOf`.
   */
  startUtc?: number;
  /** The end wall clock. Trusted. */
  endLocal: string;
  /**
   * The zone `endLocal` is expressed in.
   * **Stranger-authored on the unresolved path, so it rides in the FENCED half.**
   *
   * Same reasoning as `startTzid` above, and it reaches here by the same route:
   * when `DTEND` carries no zone the end falls back to the start's, so an
   * identifier a stranger typed on `DTSTART` arrives on both fields.
   * `timezoneUnresolved` stays trusted for both.
   */
  endTzid: string;
  /** Seconds since the epoch, absent on the same two shapes as `startUtc`. */
  endUtc?: number;
  /** True when the event carries a recurrence rule. This server's reading. */
  isRecurring: boolean;
  /** True when a human edited THIS occurrence away from the series. Trusted. */
  isOverride: boolean;
  /** The master series' key for this occurrence, in iCalendar form. Trusted. */
  recurrenceId: string | null;
  /** True when the resource named a zone it never defined. Trusted. */
  timezoneUnresolved: boolean;
  /**
   * How many people are on it. **The count, never the identities.**
   *
   * An attendee's `CN` and address are stranger-authored and belong to the
   * detail call in CAL-04, not to a listing: a page of twenty-five events would
   * otherwise carry a hundred stranger-chosen display names into the model's
   * context before the caller had asked about a single one of them.
   */
  attendeeCount: number;
  /** The event's title, verbatim. **Stranger-authored.** */
  summary: string | null;
  /** Where it is, verbatim. **Stranger-authored.** */
  location: string | null;
}

/** One page of a listing. */
export interface EventPage {
  events: EventSummary[];
  /**
   * Whether more rows exist past this page.
   *
   * Two separately named fields rather than "a null cursor means the end", for
   * the reason `MessagePage` records: a model reading a false `hasMore` stops
   * without having to reason about what an absent cursor means.
   */
  hasMore: boolean;
  /** The token that continues this listing, or null at the end. Minted here. */
  nextCursor: string | null;
  /**
   * True when an expansion cap stopped a walk before the range was exhausted.
   *
   * A flag rather than a silently short list, and rather than a fifth error
   * category. This server's own statement about what it did, so it rides in the
   * trusted half beside `hasMore`.
   */
  truncated: boolean;
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
}

/**
 * One occurrence, in full (CAL-03).
 *
 * **Deliberately an EXTENSION of the listing row rather than a parallel
 * shape.** Every trusted field a row carries means the same thing here, and two
 * independently-declared shapes would agree today and drift the first time
 * either grew a field — silently, because both would still serialise into a
 * plausible response. Extending makes the drift impossible: a field added to
 * the row appears here by construction.
 *
 * The four fields below are what a DETAIL adds, and three of the four are the
 * reason this type exists at all — they are the stranger-authored surface a
 * listing deliberately refuses to carry.
 */
export interface EventDetail extends EventSummary {
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
  /**
   * The event's long free-text body, verbatim. **Stranger-authored.**
   *
   * It appears on this call and on no other. `EventSummary` has nowhere to put
   * one, which is what keeps a page of twenty-five rows from carrying
   * twenty-five of them.
   */
  description: string | null;
  /**
   * Whoever sent the invitation. **Stranger-authored, every field.**
   *
   * Returned as DATA. Nothing in this phase issues a resource write, a
   * participation-status change or an invitation reply, and the scheduling
   * surface is outside this project's write path entirely. This note is here
   * rather than only in the plan because a list of addresses on a read tool is
   * exactly where a later session would reach for a reply feature.
   */
  organizer: EventParticipant | null;
  /** Everyone on it, in document order. **Stranger-authored, every field.** */
  attendees: EventParticipant[];
}

/** What one listing call asks for. */
export interface EventListOptions {
  /**
   * One opaque calendar id. REQUIRED — there is no account-wide form.
   *
   * It was optional, and omitting it listed every calendar on the account. The
   * live UAT run recorded that path failing on the real account: repeated
   * `connection_failed`, consistent with a nineteen-round-trip serial sweep
   * exceeding the request budget, while every scoped call succeeded first time.
   * The fan-out could not be repaired by making it faster — ./.claude/CLAUDE.md
   * §3 forbids parallelising it, and for a reason that costs the user their own
   * mail — so the fix was to do LESS work rather than the same work sooner.
   */
  calendarId: string;
  /** The range start, in SECONDS since the epoch. */
  rangeStart: number;
  /** The range end, in SECONDS since the epoch. Half-open: this instant is out. */
  rangeEnd: number;
  /** Rows per page. Clamped rather than refused — see `clampPageSize`. */
  pageSize?: number;
  /** The `nextCursor` of a previous page, or absent for page one. */
  cursor?: string;
}

/** One calendar collection, as this module carries it internally. */
interface Collection {
  url: string;
  displayName: string;
  color: string | null;
  /**
   * This server's own reading of whether the resourcetype named
   * `CS:subscribed`.
   *
   * Never stranger-chosen — see `CalendarSummary.subscribed`, which this
   * feeds directly.
   */
  subscribed: boolean;
  /**
   * The `CS:source` href, or null when absent or unusable.
   *
   * **A URL a SERVER supplied naming an arbitrary third-party host.**
   * Deliberately never resolved against the home URL — unlike a collection
   * href, which names iCloud's own shard — and deliberately never surfaced
   * past this module: it stops at `Collection` and must not reach
   * `CalendarSummary`. A caller holding the credential-attaching `davFetch`
   * and a URL naming a host outside the account is exactly the shape CR-01
   * closed.
   */
  source: string | null;
}

/**
 * One occurrence with its ordering key, before an identifier has been minted.
 *
 * The whole in-range set is built as these, sorted, cut to a page, and only
 * THEN turned into rows. That ordering is deliberate: minting an opaque token
 * costs a JSON encode and a base64 encode per row, and a rule that trips the
 * expansion cap produces two thousand of them for a page that will show
 * twenty-five.
 */
interface PendingOccurrence {
  key: EventOrderKey;
  calendarUrl: string;
  objectUrl: string;
  occurrence: Occurrence;
}

/**
 * Read a display name the library will not promise is a string.
 *
 * `DAVCollection.displayName` is declared as either a string or an object,
 * because the XML layer yields an object for an EMPTY element — and the string
 * conversion of an empty object is the nine characters `[object Object]`, which
 * reads as a real name at every call site downstream and is impossible to tell
 * from one a user actually chose.
 *
 * **The compiler is not watching the rest of that object either.** The same
 * type declares `reports` as `any`, and `any` on one field widens what type
 * inference can promise about anything reached through the value — so every
 * property read off a collection response in this module is narrowed by hand
 * rather than trusted.
 */
function narrowDisplayName(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/**
 * Read a `CS:source` href the library will not promise is a string, or even
 * present.
 *
 * The XML layer yields `{}` for an empty `<CS:source/>` element, on the same
 * pattern `narrowDisplayName` already reads: an empty object stringifies to
 * `[object Object]`, which would read as a real URL if this indexed `.href`
 * without checking it first. Parsed with `new URL(href).href` and NO base —
 * only an ABSOLUTE url survives, because a relative one has no host to name
 * and this field's whole reason for existing is naming a third-party host
 * explicitly. Nothing is read from a caught value.
 */
function sourceHrefOf(value: unknown): string | null {
  if (value === null || typeof value !== "object") return null;
  const href = (value as { href?: unknown }).href;
  if (typeof href !== "string" || href.length === 0) return null;
  try {
    return new URL(href).href;
  } catch {
    return null;
  }
}

/** The `comp` names a collection declares, however many it carries. */
function componentNamesOf(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  const comp = (value as { comp?: unknown }).comp;
  const entries = Array.isArray(comp) ? comp : [comp];

  const names: string[] = [];
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    const name = (entry as { _attributes?: { name?: unknown } })._attributes?.name;
    if (typeof name === "string" && name.length > 0) names.push(name);
  }
  return names;
}

/** The `resourcetype` children, as names. */
function resourceTypesOf(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  return Object.keys(value as Record<string, unknown>);
}

/**
 * Turn one multi-status into the calendar collections it describes.
 *
 * The resourcetype filter admits either `calendar` OR `subscribed`, and this
 * is where this diverges from the library's own calendar-listing helper — that
 * helper's own resourcetype filter has the same gap this fixes. Per Apple's
 * CalendarServer extensions to CalDAV (ccs-calendarserver,
 * doc/Extensions/caldav-sharing.txt), an owned collection's resourcetype
 * carries `CALDAV:calendar`, while a collection the user subscribed to (an ICS
 * feed subscription added via "Subscribe to Calendar") carries `CS:subscribed`
 * instead and never includes `CALDAV:calendar`. A check requiring the literal
 * `calendar` string silently drops every subscription the account holds, so
 * this admits either marker and leaves the component-set filter below to
 * apply unchanged to both. An empty component set is ADMITTED rather than
 * refused: a collection that declares no restriction accepts every component
 * type, so refusing it would drop a real calendar on a server that simply did
 * not answer that property.
 */
function collectionsFrom(
  responses: DAVResponse[],
  homeUrl: string,
): Collection[] {
  const collections: Collection[] = [];

  for (const response of responses) {
    const props = response.props ?? {};
    const resourceTypes = resourceTypesOf(props.resourcetype);
    const isCalendar = resourceTypes.includes("calendar");
    const isSubscribed = resourceTypes.includes("subscribed");
    if (!isCalendar && !isSubscribed) continue;

    const components = componentNamesOf(props.supportedCalendarComponentSet);
    if (components.length > 0 && !components.includes("VEVENT")) continue;

    const href = response.href;
    if (typeof href !== "string" || href.length === 0) continue;

    let url: string;
    try {
      url = new URL(href, homeUrl).href;
    } catch {
      // A collection this module cannot address is a collection it must not
      // pretend to have. Nothing is read from the caught value.
      continue;
    }

    const color = props.calendarColor;
    collections.push({
      url,
      displayName: narrowDisplayName(props.displayname),
      color: typeof color === "string" && color.length > 0 ? color : null,
      // `isSubscribed` alone, NOT `isSubscribed && !isCalendar` — a
      // collection declaring both markers is one this server cannot read
      // events from either way, so it is marked a subscription regardless.
      subscribed: isSubscribed,
      source: sourceHrefOf(props.source),
    });
  }

  // Ascending by URL, so two identical calls agree. Code units rather than a
  // collating comparison, for the reason `compareEventOrder` gives: a locale-
  // dependent order is one a second request may compute differently.
  collections.sort((a, b) => (a.url === b.url ? 0 : a.url < b.url ? -1 : 1));
  return collections;
}

/**
 * Enumerate the account's calendar collections in ONE request.
 *
 * **One request for the whole listing, never one per calendar**, and the
 * distinction is measured rather than theoretical. The library's own
 * calendar-listing helper issues an extra request per collection to read each
 * one's supported report set, which the transport's queue would serialise into
 * nine sequential round trips on this account — for a property no tool in this
 * project reads. So this calls the property-find directly, against the home set
 * at depth one, asking for the four properties a row actually needs.
 *
 * The credential is NOT passed here. `./transport.ts` attaches it per call and
 * is the only place that may: building a header object here would mean this
 * module held a string carrying the app-specific password across an await, for
 * no benefit at all. `./discovery.ts` passes an empty header set for the same
 * reason, and this follows it.
 *
 * IT TAKES NEITHER THE ENVIRONMENT NOR THE PRINCIPAL (code review WR-05). It
 * used to take both and read neither. `noUnusedParameters` is off, so nothing
 * said so, and a reader had to open the body to learn the principal meant
 * nothing here — while the CardDAV twin, `fetchBooks` in `./contacts.ts`, took
 * neither. Two halves of one job disagreeing about their own signature is what
 * makes this one read as principal-scoped when it is not. It is not: the
 * request is made for whoever `davFetch` was built for.
 *
 * **Collection enumeration is not cached, deliberately.** The KV entry holds
 * discovery only — the root, principal and home URLs — and PROJECT.md's "local
 * caching is not a product feature" constraint is what keeps it that way. The
 * cost is real and worth stating: on a warm call this one request is the
 * dominant share of the wall clock, and every `listEvents` call pays it.
 */
async function fetchCollections(
  davFetch: DavFetch,
  resolved: ResolvedDavAccount,
): Promise<Collection[]> {
  const responses = await propfind({
    url: resolved.homeUrl,
    props: {
      "d:displayname": {},
      "d:resourcetype": {},
      "c:supported-calendar-component-set": {},
      "ca:calendar-color": {},
      // Free: this is one request either way, and a server that does not
      // know the property simply omits it from the response rather than
      // refusing the whole PROPFIND.
      "cs:source": {},
    },
    depth: "1",
    headers: {},
    fetch: davFetch,
  });

  return collectionsFrom(responses, resolved.homeUrl);
}

/**
 * List the account's calendar collections (CAL-01).
 *
 * Wrapped in `withRediscovery` so a failure against a cached shard host takes
 * D-60's single-retry path rather than surfacing as a dead account.
 */
export async function listCalendars(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<CalendarListing> {
  return withRediscovery(env, principal, davFetch, "caldav", async (resolved) => {
    const collections = await fetchCollections(davFetch, resolved);

    return {
      calendars: collections.map((one) => ({
        id: encodeCalendarId({ collectionUrl: one.url }),
        displayName: one.displayName,
        color: one.color,
        subscribed: one.subscribed,
      })),
      cacheHit: resolved.cacheHit,
    };
  });
}

// ---------------------------------------------------------------------------
// CALM-04 — creating a calendar collection
// ---------------------------------------------------------------------------

/**
 * What one `calendar_create_calendar` call supplies.
 *
 * Two values, both the USER's own rather than anything this server read, and
 * both already refused at the tool boundary if they are the wrong shape. No
 * URL, no identifier and no reference of any kind crosses this boundary, which
 * is what makes the request target below unaimable rather than merely checked.
 */
export interface CreateCalendarInput {
  /** The calendar's name, verbatim. */
  displayName: string;
  /** `#RRGGBB`, already matched against the anchored pattern at the tool (D-08). */
  color: string;
}

/** A calendar that now exists, named by the token every other calendar tool takes. */
export interface CreatedCalendar {
  /** The opaque id `calendar_list_calendars` would mint for the same collection. */
  id: string;
  /** What was asked for, echoed. */
  displayName: string;
  /** The `#RRGGBB` that was asked for, NOT the eight-digit form the wire carries. */
  color: string;
}

/**
 * The method a calendar collection is created with, and why it is not the
 * obvious one.
 *
 * RFC 4791 defines a method whose entire purpose is creating a calendar, and
 * the DAV library ships a helper that issues it. **Neither can be used from
 * here: this runtime refuses to build a request carrying that method string at
 * all**, and the refusal is a `TypeError` raised before any I/O — see
 * `assertSendableMethod` in `./transport.ts` for the measured failure that
 * settled it. Both are named by ROLE and never spelled, here and everywhere
 * else in this tree, because both are banned tokens in every scanned root; see
 * `./../../.claude/CLAUDE.md` § Enforcement.
 *
 * So the create issues RFC 5689 extended `MKCOL` instead: the same intent,
 * expressed with a method this platform will send. The body sets the calendar
 * resource type alongside the collection one, which is what makes the result a
 * calendar rather than an ordinary WebDAV collection.
 *
 * **The request shape below is SPIKE-04's, lifted rather than re-derived.**
 * That probe ran against the owner's real account on 2026-09-24 and iCloud
 * answered `201` to exactly these bytes. A second derivation of a shape that is
 * already measured is a second thing to get wrong.
 */
const CREATE_COLLECTION_METHOD = "MKCOL";

/**
 * The method a calendar's own properties are changed with (CALM-05).
 *
 * RFC 4918 § 9.2, and unremarkable where the create's method is not: this
 * runtime builds a request carrying it without complaint, and SPIKE-04 sent one
 * to the owner's real account on 2026-09-24 and got a `207` back. Named rather
 * than written inline only so the create and the update read as a pair.
 */
const UPDATE_COLLECTION_METHOD = "PROPPATCH";

/**
 * The opaque alpha pair every colour this server writes carries.
 *
 * Uppercase, and the case is a CHOICE rather than a fact about the protocol.
 * This repository's own listing fixture spells a colour `#1f77b4` and SPIKE-04's
 * live probe sent `#7F7F7FFF`; iCloud accepted the second, neither case means
 * anything on the wire, and exactly one of them has to be picked or it drifts
 * between call sites. The measured one is picked, and a test pins it.
 */
const OPAQUE_ALPHA = "FF";

/**
 * The eight-digit colour iCloud stores, from the six-digit one a person types.
 *
 * APPEND ONLY. The six digits go back out in whatever case the CALLER chose,
 * because re-casing somebody's value is a change to it that nobody asked for.
 * Only the alpha pair is this server's, and it is a constant.
 *
 * **It validates nothing, deliberately.** The anchored `^#[0-9A-Fa-f]{6}$`
 * lives at the tool boundary (D-08), so a malformed colour is refused before
 * any request leaves the Worker; a second check here would be a second
 * mitigation of the same thing, drifting from the first the day either is
 * edited.
 *
 * Apple's `symbolic-color` attribute is NOT emitted beside it. This server has
 * no swatch vocabulary, and inventing one would put a claim on the resource the
 * user never made — the same argument `addParticipants` makes for not inventing
 * an organiser `CN`.
 *
 * Nothing normalises colour on the READ side to match. `collectionsFrom`
 * publishes whatever string the server sent, marked stranger-authored, so a
 * listing reports eight digits for a calendar this server created and six for
 * one Apple created. That asymmetry is iCloud's, not this server's.
 */
export function calendarColorForWire(rgb: string): string {
  return `${rgb}${OPAQUE_ALPHA}`;
}

/**
 * Whether the create's own status means the calendar exists (D-06).
 *
 * **`207` is the trap, and it sits INSIDE the success range.** RFC 5689 § 3
 * makes an extended `MKCOL` all-or-nothing: a server that cannot satisfy every
 * property in the body MUST fail the whole request and MUST NOT create the
 * collection, and the body of that refusal is a `DAV:mkcol-response` naming the
 * property it rejected. The specification's own § 3.5 example carries that body
 * under `403` and names no `207` for the case at all — so this rule is
 * CONSERVATIVE rather than spec-quoting, and it is conservative in the only
 * direction that matters. A `207` is definitionally an envelope rather than an
 * answer, so reading one as a refusal can only ever under-report a success,
 * while reading one as a success would record a creation that did not happen.
 * "The tool said your calendar was made and it is on none of your devices" is
 * the one error on this path that cannot be walked back.
 *
 * Narrow on purpose: every 2xx is accepted EXCEPT `207`. Demanding `201`
 * exactly would be the mirror-image mistake — a server answering `200` to a
 * genuine creation would be recorded as having refused.
 *
 * It lives HERE and not in `./transport.ts`, and that is forced rather than
 * chosen: `throwForStatus` returns for the whole 2xx range, so a `207` reaches
 * this layer as a success and the refusal cannot be hoped for from below.
 *
 * **What it cannot see, written down rather than left to be discovered.** The
 * status handed to it is the library's, and the library reports the ENVELOPE's
 * status only when the body is not a `DAV:multistatus`. RFC 5689 gives the
 * refusal a `DAV:mkcol-response` body, which is not one — so the real shape is
 * caught. A server answering `207` with a `multistatus` instead would have its
 * inner per-response status reported here and could slip through. That shape is
 * undefined for `MKCOL` by every specification involved and unmeasured against
 * iCloud, and refusing it would mean inventing a rule that could also refuse a
 * genuine success. The limit is recorded; it is not closed.
 */
function collectionCreatedBy(status: number | null): boolean {
  if (status === null) return false;
  if (status === 207) return false;
  return status >= 200 && status < 300;
}

/**
 * Create one calendar collection on this account (CALM-04).
 *
 * ## The target is not the caller's, and cannot be made to be
 *
 * `CreateCalendarInput` carries a name and a colour and nothing else. The
 * collection URL is `crypto.randomUUID()` resolved against the home set
 * discovery just returned, so the only free component is generated on that line
 * rather than accepted from anywhere. `assertUnderHome` still runs before the
 * request — defence in depth rather than the authorisation it is on the paths
 * that decode an id, because `./transport.ts` attaches the Apple ID and the
 * app-specific password to whatever URL it is handed and a future edit to the
 * two lines above is precisely what this catches.
 *
 * **The trailing slash is on the SEGMENT.** A collection URL without one is a
 * different URL, and `assertUnderHome` compares pathname prefixes.
 *
 * ## Three properties, and no fourth
 *
 * `d:resourcetype`, `d:displayname` and `ca:calendar-color` — exactly what
 * SPIKE-04 measured. `c:supported-calendar-component-set` is deliberately NOT
 * sent: § 3's all-or-nothing rule means one property iCloud declines kills the
 * whole create, and whether iCloud accepts that element inside an extended
 * `MKCOL` is unmeasured in either direction. It costs the listing nothing —
 * `collectionsFrom` already admits a collection declaring an empty component
 * set.
 *
 * ## No retry, and this one is sharper than the event create's
 *
 * `allowRediscovery` is `false`. `createEvent` passes `false` because a retried
 * write can be reported as a failure that actually landed; here the retry would
 * mint a FRESH uuid, so a first attempt that landed and then reported a
 * rediscoverable failure leaves TWO calendars on the account and no way to say
 * which one the user asked for. The cost is stated rather than hidden: a stale
 * cached shard host makes this tool fail until the discovery entry expires,
 * which is one refusal the user can retry by hand against a duplicate nobody
 * can clean up automatically.
 *
 * ## Serial, because every one of these is a socket
 *
 * One request, one calendar. `dav-concurrent-request` names this function, so a
 * combinator wrapped around it is a commit-time rejection: an account with many
 * calendars invites "make all of these", and iCloud's per-account connection
 * ceiling is lower than the platform's, undocumented, and deliberately
 * unmeasured — exhausting it locks the user out of their own mail in Mail.app
 * on their own devices.
 *
 * Nothing here is logged. This module contains no logging calls of any kind.
 */
export async function createCalendarCollection(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  input: CreateCalendarInput,
): Promise<CreatedCalendar> {
  return withRediscovery(
    env,
    principal,
    davFetch,
    "caldav",
    async (resolved) => {
      const collectionUrl = new URL(
        `${crypto.randomUUID()}/`,
        resolved.homeUrl,
      ).href;
      assertUnderHome(collectionUrl, resolved.homeUrl);

      const responses = await davRequest({
        url: collectionUrl,
        init: {
          method: CREATE_COLLECTION_METHOD,
          // Never a credential from here. `./transport.ts` attaches it per call
          // and is the only place that may: building a header object here would
          // mean this module held the app-specific password across an await,
          // for nothing at all.
          headers: {},
          namespace: "d",
          body: {
            "d:mkcol": {
              _attributes: {
                "xmlns:d": "DAV:",
                "xmlns:c": "urn:ietf:params:xml:ns:caldav",
                "xmlns:ca": "http://apple.com/ns/ical/",
              },
              "d:set": {
                "d:prop": {
                  // The PAIR is what makes the result a calendar collection
                  // rather than a plain one. Without the second element this
                  // creates an ordinary WebDAV collection, which is a different
                  // thing answered by accident.
                  "d:resourcetype": {
                    "d:collection": {},
                    "c:calendar": {},
                  },
                  "d:displayname": input.displayName,
                  "ca:calendar-color": calendarColorForWire(input.color),
                },
              },
            },
          },
        },
        fetch: davFetch,
      });

      const answered = responses[0]?.status;
      if (
        !collectionCreatedBy(typeof answered === "number" ? answered : null)
      ) {
        // `DavConnectError` is the honest floor for "the server answered
        // something this layer cannot act on", and it needs no fifth error
        // category: `davToErrorCategory`'s vocabulary is closed at four values
        // and this class is last in that chain precisely because it is the
        // explicit statement of the default. Nothing about the answer is read
        // or carried — not its status, not its body, not the URL.
        throw new DavConnectError();
      }

      return {
        // The same encoder a listing row goes through, so the calendar is
        // addressable by every other calendar tool the moment it exists.
        id: encodeCalendarId({ collectionUrl }),
        displayName: input.displayName,
        color: input.color,
      };
    },
    // See the docstring. A retry mints a fresh uuid, so this is the whole of
    // the "two calendars, one request" mitigation.
    false,
  );
}

// ---------------------------------------------------------------------------
// CALM-05 — renaming and recolouring a calendar collection
// ---------------------------------------------------------------------------

/**
 * A calendar property this server knows how to change, in THIS server's words.
 *
 * A closed two-value vocabulary, and closed on purpose. Every sentence the tool
 * layer composes about a half-completed change names one of these two strings,
 * so the answer a user reads is built from names chosen here rather than from
 * anything the server sent back. `./../../.claude/CLAUDE.md` § 4 is the reason:
 * no diagnostic field may echo a server status line, a body or a URL, and
 * "which property failed" is exactly the field somebody would otherwise answer
 * by quoting the server's own propstat.
 */
export type CalendarProperty = "displayName" | "color";

/**
 * Each property's key in the parsed property region the DAV library returns.
 *
 * The library camel-cases every element name and strips the namespace prefix,
 * so `D:displayname` arrives as `displayname` and `ca:calendar-color` arrives
 * as `calendarColor`. `collectionsFrom` above already reads the same two keys
 * off a listing, which is why these spellings are not a guess.
 */
const CALENDAR_PROPERTY_KEYS: Readonly<Record<CalendarProperty, string>> =
  Object.freeze({
    displayName: "displayname",
    color: "calendarColor",
  });

/** How a property update went, property by property. */
export interface CalendarPropertyOutcomes {
  /** Properties this server asked to set and the server reported set. */
  changed: CalendarProperty[];
  /** Properties this server asked to set and the server did NOT report set. */
  unchanged: CalendarProperty[];
}

/** A calendar that has been asked to change, and what actually changed. */
export interface UpdatedCalendar extends CalendarPropertyOutcomes {
  /** The opaque id for the collection the request ACTUALLY addressed. */
  id: string;
}

/** What one `calendar_update_calendar` call supplies. */
export interface UpdateCalendarInput {
  /** The collection URL, decoded from an opaque id this server minted. */
  collectionUrl: string;
  /** The new name, when a rename was asked for. ABSENT means leave it alone. */
  displayName?: string;
  /** `#RRGGBB`, already matched at the tool (D-08). ABSENT means leave it alone. */
  color?: string;
}

/**
 * Read the per-property outcome out of a property update's answer (CALM-05).
 *
 * ## The `207` here means the OPPOSITE of the `207` one function up
 *
 * `collectionCreatedBy` treats a `207` on the create as a REFUSAL, because RFC
 * 5689 § 3 makes an extended `MKCOL` all-or-nothing and gives its failure a
 * `DAV:mkcol-response` body. A property update is the other shape entirely: RFC
 * 4918 § 9.2 makes it a PER-PROPERTY operation whose only defined successful
 * answer is a `207` carrying one `propstat` per property. **Do not "make these
 * two consistent."** They are different methods with different specifications,
 * and the agreement would have to be a lie about one of them.
 *
 * ## What the library actually hands over, MEASURED
 *
 * Research left this open as assumption A7 and it was verified against
 * `node_modules/tsdav/dist/tsdav.js` before this reader was written, because
 * the obvious implementation depends entirely on the answer. What the library
 * does with a multistatus is REDUCE every `propstat` into ONE flat property
 * region — and it DROPS, silently and entirely, any `propstat` whose status
 * line parses outside the 2xx range. No per-property status survives the parse.
 *
 * That measurement turns the plan's first rule from a defensive precaution into
 * the only mechanism available: **ABSENCE IS THE SIGNAL.** A property this
 * server asked to set and the answer does not carry was either refused with its
 * own status or never mentioned at all, and from here those two are the same
 * observation. So the reader asks one question per property — is it present —
 * and a property that is missing is reported UNCHANGED.
 *
 * Three ways the obvious reader gets this wrong, all closed above:
 *
 * 1. **A property the request set and the answer omits is a FAILURE.** A reader
 *    that only inspects what is present reports success for a property the
 *    server silently dropped, which is why `asked` is a parameter.
 * 2. **Only a 2xx propstat is a success.** A `424 Failed Dependency` is not a
 *    success, and neither is the `403` RFC 5689 § 3.5 itself uses for a refused
 *    property set. The library's own filter already removes both, and this
 *    reader inherits that rather than restating it — see the limit below.
 * 3. **It does not throw.** The collection still exists and half the change may
 *    have landed; throwing would hand the caller a category and no way to learn
 *    WHICH half. The outcome is returned and the tool composes the sentence.
 *
 * ## What it cannot see, written down rather than left to be discovered
 *
 * The 2xx filter is the LIBRARY's, and the library applies it only when the
 * status line parses. A `propstat` carrying no status element, or one this
 * parser cannot read, is KEPT — so its properties would arrive in the region
 * below and be reported changed. RFC 4918 § 14.22 requires the status element,
 * so that shape is malformed rather than merely unusual, and it is unmeasured
 * against iCloud. Restating the range check here would not close it either:
 * the status is gone by the time this function is handed the value. The limit
 * is recorded; it is not closed.
 *
 * A non-multistatus answer — a bare `200` with no body — arrives with no
 * property region at all, and every asked property is then reported unchanged.
 * That is conservative in the direction this module has already chosen once:
 * under-reporting a change the user can verify beats telling them a calendar
 * was renamed when it was not.
 *
 * Narrowed BY HAND throughout. The property region is typed `any` by the
 * library, and `any` on one field widens what inference can promise about
 * everything reached through the value.
 */
export function propstatOutcomes(
  responses: DAVResponse[],
  asked: readonly CalendarProperty[],
): CalendarPropertyOutcomes {
  const reported = new Set<string>();
  for (const response of responses) {
    const props: unknown = response.props;
    if (props === null || typeof props !== "object") continue;
    for (const key of Object.keys(props as Record<string, unknown>)) {
      reported.add(key);
    }
  }

  const changed: CalendarProperty[] = [];
  const unchanged: CalendarProperty[] = [];
  for (const property of asked) {
    if (reported.has(CALENDAR_PROPERTY_KEYS[property])) changed.push(property);
    else unchanged.push(property);
  }
  return { changed, unchanged };
}

/**
 * Rename and recolour one calendar, in one request (CALM-05).
 *
 * ## The target IS the caller's here, and that is the difference from the create
 *
 * `createCalendarCollection` above is exempt from the home-containment gate
 * because its input carries no URL at all. This one is the first collection
 * write in the project whose target is genuinely caller-influenced: the URL
 * arrives inside an opaque id the model may have read out of an event
 * description a stranger wrote, and `./transport.ts` attaches the Apple ID and
 * the app-specific password to whatever URL it is handed. So `assertUnderHome`
 * runs BEFORE the request and is the authorisation rather than defence in
 * depth. Its refusal is deliberately byte-identical to a genuine miss, so this
 * endpoint is not a collection-existence oracle.
 *
 * ## Absent means LEAVE ALONE
 *
 * A property the caller did not supply is not in the body at all. That is this
 * project's settled convention and it is also the only way to recolour without
 * renaming: an element present with an empty value is a request to blank the
 * property, which nobody asked for.
 *
 * A call naming NEITHER property is refused before the request, with
 * `DavNotFoundError(false)` on `assertRange`'s precedent below — a change this
 * server declines to make is the same class of answer as an identifier it
 * declines to resolve. Sending an empty `d:prop` would spend a round trip
 * asking iCloud to do nothing.
 *
 * ## A total refusal THROWS; a partial one does not
 *
 * If the answer reports nothing changed, this throws rather than returning an
 * outcome with an empty `changed` list. "A partial success with zero parts" is
 * not a sentence the tool layer should have to compose, and the alternative is
 * a response saying a change succeeded partially while naming no part of it
 * that did. A PARTIAL outcome comes back as a value, because the caller needs
 * to learn which half landed and a thrown category cannot carry that.
 *
 * ## No retry, and the reason differs from the create's
 *
 * `allowRediscovery` is `false`, matching every other write in this module. The
 * create's reason — a retry mints a fresh uuid and could leave two calendars —
 * does not apply, because a property update is idempotent against a fixed URL.
 * The reason that does apply is narrower and still decisive: re-discovery
 * re-resolves the account's home set, and the caller's collection URL was
 * minted against the home this server resolved EARLIER. If the shard host moved,
 * the retry's only possible outcome is the containment refusal above — so the
 * retry would buy a real PROPFIND against iCloud and spend it on a request that
 * cannot succeed.
 *
 * ## Serial, because every one of these is a socket
 *
 * `dav-concurrent-request` names this function, so a combinator wrapped around
 * it is a commit-time rejection. "Tidy up my calendars" is one sentence that
 * means N of these, and iCloud's per-account connection ceiling is lower than
 * the platform's, undocumented, and deliberately unmeasured — exhausting it
 * locks the user out of their own mail in Mail.app on their own devices.
 *
 * Nothing here is logged. This module contains no logging calls of any kind.
 */
export async function updateCalendarCollection(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  input: UpdateCalendarInput,
): Promise<UpdatedCalendar> {
  return withRediscovery(
    env,
    principal,
    davFetch,
    "caldav",
    async (resolved) => {
      const collectionUrl = input.collectionUrl;
      // FIRST, and before the credential can be attached to anything. The URL
      // came out of a caller-supplied token.
      assertUnderHome(collectionUrl, resolved.homeUrl);

      const asked: CalendarProperty[] = [];
      const prop: Record<string, string> = {};
      if (input.displayName !== undefined) {
        asked.push("displayName");
        prop["d:displayname"] = input.displayName;
      }
      if (input.color !== undefined) {
        asked.push("color");
        prop["ca:calendar-color"] = calendarColorForWire(input.color);
      }
      // See the docstring: a change naming no property is refused rather than
      // sent. `DavNotFoundError(false)` keeps the four-value error vocabulary
      // closed and cannot be re-tried into existence.
      if (asked.length === 0) throw new DavNotFoundError(false);

      const responses = await davRequest({
        url: collectionUrl,
        init: {
          method: UPDATE_COLLECTION_METHOD,
          // Never a credential from here. `./transport.ts` attaches it per call
          // and is the only place that may.
          headers: {},
          namespace: "d",
          body: {
            "d:propertyupdate": {
              // TWO namespaces, exactly what SPIKE-04's probe declared on the
              // request iCloud answered `207` to. The CalDAV namespace is not
              // among them because no property here is in it.
              _attributes: {
                "xmlns:d": "DAV:",
                "xmlns:ca": "http://apple.com/ns/ical/",
              },
              "d:set": { "d:prop": prop },
            },
          },
        },
        fetch: davFetch,
      });

      const outcomes = propstatOutcomes(responses, asked);
      if (outcomes.changed.length === 0) {
        // Nothing landed. `DavConnectError` is the same honest floor the create
        // uses for "the server answered something this layer cannot act on",
        // and nothing about the answer is read or carried — not its status, not
        // its body, not the URL.
        throw new DavConnectError();
      }

      return {
        // Minted from the URL the request ACTUALLY addressed rather than echoed
        // from the caller's token, so an id that named something else would be
        // visible instead of agreeing with itself.
        id: encodeCalendarId({ collectionUrl }),
        ...outcomes,
      };
    },
    // See the docstring. A retry could only ever reach the containment refusal.
    false,
  );
}

/**
 * Refuse a range this server will not walk, before anything is opened.
 *
 * `DavNotFoundError` rather than a fifth error category: the four-value
 * vocabulary is closed, and a range the server declines to serve is the same
 * class of answer as an identifier it declines to resolve — the caller asked
 * for something that is not available. `rediscoverable` stays at its default of
 * false, because re-resolving the account's home URLs cannot make a range
 * narrower.
 */
function assertRange(rangeStart: number, rangeEnd: number): void {
  if (!Number.isInteger(rangeStart) || !Number.isInteger(rangeEnd)) {
    throw new DavNotFoundError();
  }
  if (rangeEnd <= rangeStart) throw new DavNotFoundError();
  if (rangeEnd - rangeStart > MAX_RANGE_DAYS * SECONDS_PER_DAY) {
    throw new DavNotFoundError();
  }
}

/**
 * Seconds since the epoch as the ISO instant the library's range filter takes.
 *
 * The runtime's date type appears here and nowhere else in this module, and it
 * is safe for one specific reason: `toISOString` is defined to render UTC
 * whatever the host's zone is, so this conversion produces the same string in
 * the vitest pool as it does in a production isolate. That is precisely the
 * property the `ical-jsdate` rule protects — it bans the parsed-time conversion
 * whose answer DOES depend on the host zone, not arithmetic on an absolute
 * instant that never had a wall clock in the first place.
 */
function isoInstant(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/** One occurrence, as the row a caller reads. */
function summaryFor(pending: PendingOccurrence): EventSummary {
  const { occurrence, calendarUrl, objectUrl } = pending;

  const row: EventSummary = {
    id: encodeEventId({
      calendarUrl,
      objectUrl,
      recurrenceId: occurrence.recurrenceId,
    }),
    calendarId: encodeCalendarId({ collectionUrl: calendarUrl }),
    allDay: occurrence.start.allDay,
    startLocal: occurrence.start.local,
    startTzid: occurrence.start.tzid,
    endLocal: occurrence.end.local,
    endTzid: occurrence.end.tzid,
    isRecurring: occurrence.isRecurring,
    isOverride: occurrence.isOverride,
    recurrenceId: occurrence.recurrenceId,
    timezoneUnresolved:
      occurrence.start.timezoneUnresolved || occurrence.end.timezoneUnresolved,
    attendeeCount: occurrence.attendees.length,
    summary: occurrence.summary,
    location: occurrence.location,
  };

  // Assigned rather than spread, so an absent instant leaves the key genuinely
  // MISSING rather than present and undefined. Those are different claims, and
  // the second one serialises to nothing while still answering `in` with true.
  if (occurrence.start.utc !== undefined) row.startUtc = occurrence.start.utc;
  if (occurrence.end.utc !== undefined) row.endUtc = occurrence.end.utc;

  return row;
}

/**
 * One occurrence, as the full detail a caller reads (CAL-03).
 *
 * Built ON TOP of the listing row rather than beside it, so the two cannot
 * disagree about a field they share. The four additions are the ones a listing
 * deliberately refuses to carry, and three of them are stranger-authored.
 *
 * The absent instant is preserved by construction: `summaryFor` assigns rather
 * than spreads, and spreading its result copies only the keys that are actually
 * there. An all-day date and an unresolved zone both arrive here with no
 * instant and leave with none.
 */
function detailFor(pending: PendingOccurrence, cacheHit: boolean): EventDetail {
  const { occurrence } = pending;

  return {
    ...summaryFor(pending),
    cacheHit,
    description: occurrence.description,
    organizer: occurrence.organizer,
    attendees: occurrence.attendees,
  };
}

/**
 * A synthetic per-UID object url for a feed-sourced occurrence.
 *
 * A feed has no per-object href at all — it is one flat `VCALENDAR`, not a
 * set of addressable DAV resources — but `PendingOccurrence.objectUrl` feeds
 * `EventOrderKey` and, downstream, `EventRef`, both of which need SOME stable
 * per-object identity to sort and cursor-page on. This mints one deterministic
 * per call for the same UID, absolute and https by construction (satisfies
 * `ids.ts`'s `assertUrl`), and scoped to the collection so it cannot collide
 * across two different subscribed calendars sharing a UID by coincidence.
 *
 * The fragment form (`#feed/<uid>`) is deliberate: it can never collide with a
 * real DAV object path, which is always a `.ics`-suffixed resource under the
 * collection, so a feed-sourced id and a real one are visibly different kinds
 * of thing to anything that inspects the URL rather than merely comparing it.
 */
function feedObjectUrl(collectionUrl: string, uid: string): string {
  return new URL(`#feed/${encodeURIComponent(uid)}`, collectionUrl).href;
}

/**
 * Fetch a subscribed calendar's `CS:source` feed and expand it, appending to
 * the set.
 *
 * The read-side twin of `collectFrom` below, for a collection with no DAV
 * object children at all. Same loop shape, same budget discipline, same
 * per-resource parse-and-release scope — only the SOURCE of the resource text
 * differs: a feed fetch plus a per-UID split, rather than a DAV multi-get.
 *
 * Defensively refuses with `DavSubscriptionError` when `collection.source` is
 * null. This function must never be reached that way — `pagedEvents` refuses
 * before it gets here — but a defensive refusal is what stops a future call
 * site regressing into fetching the literal string `"null"`.
 */
async function collectFromFeed(
  collection: Collection,
  rangeStart: number,
  rangeEnd: number,
  into: PendingOccurrence[],
  budget: StepBudget,
): Promise<boolean> {
  if (collection.source === null) throw new DavSubscriptionError();

  const feedText = await fetchSubscriptionFeed(collection.source);
  const entries = splitSubscriptionFeed(feedText);

  let truncated = false;

  for (const { uid, icsText } of entries) {
    // Checked BEFORE the parse, exactly mirroring `collectFrom`'s own
    // pre-parse budget check below.
    if (budget.remaining <= 0) {
      truncated = true;
      break;
    }

    const result = withParsedResource(icsText, (resource) =>
      expandWithinBudget(resource, rangeStart, rangeEnd, budget),
    );
    if (result.truncated) truncated = true;

    const objectUrl = feedObjectUrl(collection.url, uid);
    for (const occurrence of result.occurrences) {
      into.push({
        key: {
          sortInstant: sortInstantOf(occurrence.start),
          calendarUrl: collection.url,
          objectUrl,
          recurrenceId: occurrence.recurrenceId,
        },
        calendarUrl: collection.url,
        objectUrl,
        occurrence,
      });
    }
  }

  return truncated;
}

/**
 * Fetch one calendar's bounded range and expand it, appending to the set.
 *
 * **The server-side expansion flag is never passed**, and the reason is not
 * caution. iCloud's behaviour for it is unverified and the only primary report
 * is of non-determinism; worse, RFC 4791 §9.6.5 defines that expansion as
 * converting every time to a single zone and dropping the resource's timezone
 * definitions — destroying exactly the information CAL-03 exists to return.
 * Client-side expansion in `./icalendar.ts` is not a fallback here, it is the
 * correct path.
 *
 * Returns whether a cap truncated the walk. Truncation is a property of the
 * PAGE rather than of one resource, so it is accumulated by the caller — and
 * `budget` is the same statement about cost: one allowance for the whole page,
 * spent by whichever resources reach it first (WR-01).
 *
 * **Routes a subscribed collection to `collectFromFeed` before any DAV
 * request.** A `CS:subscribed` collection is a pointer record holding zero
 * calendar object resources — proven live, see `DavSubscriptionError`'s own
 * docstring — so `fetchCalendarObjects` against it would cost a real round
 * trip to learn nothing. `davFetch` stays an unused parameter on that branch,
 * which is fine: the non-subscribed branch below still needs it.
 */
async function collectFrom(
  collection: Collection,
  davFetch: DavFetch,
  rangeStart: number,
  rangeEnd: number,
  into: PendingOccurrence[],
  budget: StepBudget,
): Promise<boolean> {
  if (collection.subscribed) {
    return collectFromFeed(collection, rangeStart, rangeEnd, into, budget);
  }

  const objects = await fetchCalendarObjects({
    calendar: { url: collection.url },
    timeRange: { start: isoInstant(rangeStart), end: isoInstant(rangeEnd) },
    headers: {},
    fetch: davFetch,
  });

  let truncated = false;

  for (const object of objects) {
    const data = object.data;
    // The library types this as `any`. A resource that came back without a
    // body is skipped rather than repaired: there is nothing to read.
    if (typeof data !== "string" || data.length === 0) continue;

    // Checked BEFORE the parse, not only inside the expansion. `withParsedResource`
    // registers the resource's timezones and builds its component tree before
    // any step is spent, and once the page's allowance is gone every remaining
    // object would pay that for an expansion already decided to be empty.
    if (budget.remaining <= 0) {
      truncated = true;
      break;
    }

    // Parse and expand inside ONE scope, so the resource's inline timezones
    // are withdrawn from the process-global service before the next object in
    // this loop is parsed (CR-03). Without that boundary the first resource to
    // claim a zone NAME owns it for the isolate, and a stranger's invitation
    // silently re-anchors the user's own meetings in every later request.
    const result = withParsedResource(data, (resource) =>
      expandWithinBudget(resource, rangeStart, rangeEnd, budget),
    );
    if (result.truncated) truncated = true;

    for (const occurrence of result.occurrences) {
      into.push({
        key: {
          // The DERIVED sort key, never the occurrence's published instant.
          // Two of the three shapes a parsed time can take have no instant at
          // all, and comparing a cursor's recorded key against a row's `utc`
          // would resume page two at a position page one never occupied.
          sortInstant: sortInstantOf(occurrence.start),
          calendarUrl: collection.url,
          objectUrl: object.url,
          recurrenceId: occurrence.recurrenceId,
        },
        calendarUrl: collection.url,
        objectUrl: object.url,
        occurrence,
      });
    }
  }

  return truncated;
}

/**
 * List the occurrences in a bounded range, paged (CAL-02, CAL-05).
 *
 * ## The order, and why it is imported rather than written here
 *
 * Rows are sorted by `compareEventOrder` and resumed by
 * `isAfterCalendarCursor`, both from `./ids.ts`. Neither is reimplemented, and
 * that is the whole defence: the resume predicate over there is expressed
 * THROUGH the comparator, so the order a page is cut on and the order a cursor
 * resumes at cannot disagree by even one component. A hand-rolled comparison
 * chain here would agree with them today and drift the first time either
 * changed — silently, and only in the rows where the components tie, which is
 * the hardest kind of bug to see in a calendar.
 *
 * ## What the page costs
 *
 * One request enumerates the collections. The one named calendar then costs the
 * library's calendar-object call, which is two reports — one for the object
 * hrefs in range, one to fetch their data. Three serial round trips, on every
 * account, whatever its calendar count.
 *
 * **That number used to depend on the account, and withdrawing the unscoped
 * form is why it no longer does.** Omitting the calendar listed all of them:
 * nineteen serial round trips on this account's nine calendars, which the live
 * UAT run recorded FAILING — repeated `connection_failed`, while every scoped
 * call succeeded first time. It is not reduced by fanning out, because §3's
 * connection budget is the binding constraint rather than the wall clock, so
 * the only fix available was to stop asking for the sweep at all.
 *
 * ## What the cursor guarantees, and what it does not
 *
 * Page two re-runs the reports, re-expands, re-sorts, and resumes strictly
 * after the recorded position: nothing already returned comes back, and nothing
 * behind the cursor is skipped. It does NOT guarantee that page one plus page
 * two equals the set that existed when page one was built — an event created
 * while the caller is paging can land at a start time already passed and will
 * not appear. The tool description says so, because a boolean this server
 * cannot compute would be worse than saying it.
 */
export async function listEvents(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: EventListOptions,
): Promise<EventPage> {
  // No filter. A plain listing and a search differ by exactly one predicate,
  // and that is the whole reason they share a body: a second implementation
  // here would agree with this one today and drift the first time either
  // changed, silently, and only in the rows where the two disagree.
  return pagedEvents(env, principal, davFetch, options, null, LISTING_TERMS);
}

/**
 * A predicate over one occurrence, applied before the page is cut.
 *
 * **Before the sort and before the cut, not after.** Filtering a finished page
 * would return pages of one or two rows and a has-more that meant nothing —
 * the page size would describe how many rows were CONSIDERED rather than how
 * many were returned, and the cursor would resume at a position in the
 * unfiltered set.
 */
type OccurrenceFilter = (occurrence: Occurrence) => boolean;

/**
 * The folded terms a page was cut under, pinned into its cursor.
 *
 * Travels beside the filter rather than being derived from it, because a
 * predicate is a closure and cannot be compared: two searches under different
 * terms produce two functions that are equally opaque to an equality check.
 * The terms are the only thing about a filter that a token can carry.
 */
interface CursorTerms {
  keywordTerm: string | null;
  attendeeTerm: string | null;
}

/**
 * What a plain listing pins on both axes: nothing, on either.
 *
 * `null` is "this axis was not searched", which is a different claim from a
 * term of zero length — and the difference is what keeps a listing cursor and a
 * search cursor from comparing equal. `searchEvents` refuses a call supplying
 * neither term, so a search always pins at least one and this value is
 * unreachable from it.
 */
const LISTING_TERMS: CursorTerms = {
  keywordTerm: null,
  attendeeTerm: null,
};

/**
 * The body both the listing and the search run in.
 *
 * `listEvents`'s own docstring above owns the order, the cost and the cursor's
 * guarantees; this function is where they are implemented. Splitting them this
 * way is what keeps `searchEvents` inside `withRediscovery` without a second
 * wrapper: the invariant is that no operation in this file reaches the network
 * outside it, and there is exactly one place here that reaches the network.
 */
async function pagedEvents(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: EventListOptions,
  matches: OccurrenceFilter | null,
  terms: CursorTerms,
): Promise<EventPage> {
  const { rangeStart, rangeEnd } = options;

  // Everything below runs BEFORE `withRediscovery`, and therefore before the
  // KV read discovery performs and before any outbound request. A malformed
  // token, a stale cursor and an over-wide range are all refused without
  // spending one unit of the connection budget.
  assertRange(rangeStart, rangeEnd);

  // Never null. The calendar is required, so every page is scoped to exactly
  // one collection and there is no branch here for "all of them".
  const scope = decodeCalendarId(options.calendarId).collectionUrl;

  let cursor: CalendarCursor | null = null;
  if (options.cursor !== undefined) {
    cursor = decodeCalendarCursor(options.cursor, rangeStart, rangeEnd);
    // The decoder pins the RANGE and validates that the scope NAMES a calendar,
    // but it has no requested scope to compare against. Comparing it here is
    // what stops a position recorded against one calendar's listing being
    // resumed against another's: the cursor would still decode, the resume
    // predicate would still run, and the caller would get a page from the
    // middle of a listing they never asked for.
    //
    // This comparison no longer carries the in-flight case as well. A cursor
    // minted before the unscoped listing was withdrawn records no calendar at
    // all, and `decodeCalendarCursor` refuses it above rather than leaving it to
    // fail here by never matching — see `CalendarCursor.scope`.
    if (cursor.scope !== scope) throw new DavNotFoundError();

    // The same argument one discriminator over, and the gap 03-07 identified
    // and left open by its own contract. A cursor records a POSITION IN AN
    // ORDERED SET, and a different search is a different set: the token still
    // decodes, the resume predicate still runs, and the caller receives
    // plausible rows from the middle of a result set they never asked for,
    // silently missing every match that sorts before the recorded position.
    // There is no error for them to notice, which is what makes the refusal
    // worth more here than almost anywhere else in this file.
    //
    // Both axes, separately, because they narrow separately: adding an attendee
    // term to a keyword search is a different set, and so is dropping one.
    // Compared by CODE UNIT against the folded terms — see `fold` below for why
    // the fold is `toLowerCase` and what would go wrong with its locale-aware
    // sibling.
    if (
      cursor.keywordTerm !== terms.keywordTerm ||
      cursor.attendeeTerm !== terms.attendeeTerm
    ) {
      throw new DavNotFoundError();
    }
  }

  const pageSize = clampPageSize(options.pageSize);

  return withRediscovery(env, principal, davFetch, "caldav", async (resolved) => {
    const collections = await fetchCollections(davFetch, resolved);

    // The INTERSECTION of the decoded id with the account's own enumeration,
    // and it is the reason `collectFrom`'s request needs no separate containment
    // assertion: the URL it is handed is one `fetchCollections` produced from
    // `resolved.homeUrl`, never one the token named. A token naming a foreign
    // origin does not fail containment here, it fails membership — which is the
    // stronger refusal of the two, and `test/dav-home-containment.test.ts`
    // records it as this site's standing exemption.
    const collection = collections.find((one) => one.url === scope);

    // A named calendar this account does not have is a refusal, not an empty
    // page. An empty RANGE is a legitimate answer; a calendar that is not there
    // is a question about something that does not exist, and answering it with
    // silence would read as "you have nothing on Tuesday".
    if (collection === undefined) throw new DavNotFoundError();

    // Fires BEFORE the request, so a calendar this server cannot read costs
    // no round trip at all — and specifically when there is no READABLE
    // source. A subscription WITH a source is not pre-empted here; it is
    // handled by `collectFrom`'s own branch into `collectFromFeed` below.
    if (collection.subscribed && collection.source === null) {
      throw new DavSubscriptionError();
    }

    const pending: PendingOccurrence[] = [];

    // ONE allowance for the whole page, created here because this is the widest
    // scope the cost actually has (WR-01). Per resource the walk was already
    // capped; per PAGE it was not, and a page is what the caller pays for. A
    // cursor-paged listing gets a fresh budget per page, which is right: each
    // page is its own request with its own CPU budget to spend.
    const budget = newStepBudget();

    // ONE calendar, so there is no iteration here and no fan-out to be tempted
    // by. That is what withdrawing the unscoped listing actually bought: the
    // multi-collection sweep ./.claude/CLAUDE.md §3 bans a combinator around is
    // no longer merely serial, it is absent. The ban still stands — the scan
    // rule still reads this file, and `fetchCollections` above is still a
    // request — but the shape it was written against cannot be written here any
    // more without first re-adding an account-wide form.
    const truncated = await collectFrom(
      collection,
      davFetch,
      rangeStart,
      rangeEnd,
      pending,
      budget,
    );

    // Filtered BEFORE the sort and before the identifiers are minted. Minting
    // an opaque token costs a JSON encode and a base64 encode per row, and a
    // rule that trips the expansion cap produces two thousand of them for a
    // page that will show twenty-five — of which a search may keep none.
    const kept =
      matches === null
        ? pending
        : pending.filter((one) => matches(one.occurrence));

    kept.sort((a, b) => compareEventOrder(a.key, b.key));

    const after =
      cursor === null
        ? kept
        : kept.filter((one) => isAfterCalendarCursor(one.key, cursor));

    // One more row than the page holds. The PRESENCE of that extra row is
    // has-more — there is no count to be wrong about — and it is dropped
    // before the cursor is minted, so the next page begins at the row after
    // the last one actually returned rather than after the one that only
    // proved there was more.
    const window = after.slice(0, pageSize + 1);
    const hasMore = window.length > pageSize;
    const rows = hasMore ? window.slice(0, pageSize) : window;
    const last = rows[rows.length - 1];

    return {
      events: rows.map(summaryFor),
      hasMore,
      nextCursor:
        hasMore && last !== undefined
          ? encodeCalendarCursor({
              rangeStart,
              rangeEnd,
              scope,
              keywordTerm: terms.keywordTerm,
              attendeeTerm: terms.attendeeTerm,
              lastSortInstant: last.key.sortInstant,
              lastCalendarUrl: last.key.calendarUrl,
              lastObjectUrl: last.key.objectUrl,
              lastRecurrenceId: last.key.recurrenceId,
            })
          : null,
      truncated,
      cacheHit: resolved.cacheHit,
    };
  });
}

// ---------------------------------------------------------------------------
// Find free slots (SCHED-01)
//
// The multi-calendar free/busy aggregation and gap-finding engine. It lives
// HERE rather than in a new `calendar-service.ts` because this module already
// owns every DAV read and write in the project, and the whole subject of D-84's
// risk — the connection budget across a multi-calendar sweep — must not be
// split across two files (06-RESEARCH.md). The sweep is entirely SERIAL: a
// plain `for...of` over the collections, never a combinator, exactly as
// ./.claude/CLAUDE.md §3 requires and `scripts/forbidden-tokens.mjs`'s
// `dav-concurrent-request` rule enforces over both `findFreeSlots` and the
// `collectFrom` it now calls in a loop.
// ---------------------------------------------------------------------------

/**
 * The widest range a find-slots call may ask for — narrower than
 * `MAX_RANGE_DAYS` on purpose (06-RESEARCH.md Pitfall 4).
 *
 * A scheduling ask is days to weeks — an interview slot, per PROJECT.md — not
 * "sometime in the next year", so ninety days is a generous ceiling for the
 * actual use case. It also bounds the cost of the multi-calendar sweep this tool
 * performs on EVERY call: a wider range does not reduce the per-calendar request
 * count but does increase each calendar's response size and parse cost.
 */
export const MAX_SLOT_RANGE_DAYS = 90;

/**
 * The fixed increment candidate start times snap to (06-RESEARCH.md Open
 * Question 3).
 *
 * Thirty minutes matches the convention every Calendly-style scheduler uses and
 * is the simplest rule to explain. Candidates align to this increment from each
 * working day's OWN start, not from a gap's own start, so two adjacent days
 * offer the same wall-clock slots regardless of where a meeting happened to end.
 */
export const SLOT_GRANULARITY_MINUTES = 30;

/**
 * Refuse a find-slots range this server will not walk, before anything opens.
 *
 * Mirrors `assertRange` exactly — same integer and ordering checks — but bounds
 * against `MAX_SLOT_RANGE_DAYS` rather than `MAX_RANGE_DAYS`. `DavNotFoundError`
 * with `rediscoverable` at its default false, for the reason `assertRange`
 * gives: re-resolving the account's home URLs cannot make a range narrower.
 */
function assertSlotRange(rangeStart: number, rangeEnd: number): void {
  if (!Number.isInteger(rangeStart) || !Number.isInteger(rangeEnd)) {
    throw new DavNotFoundError();
  }
  if (rangeEnd <= rangeStart) throw new DavNotFoundError();
  if (rangeEnd - rangeStart > MAX_SLOT_RANGE_DAYS * SECONDS_PER_DAY) {
    throw new DavNotFoundError();
  }
}

/**
 * The civil date one day after `date`, as `YYYY-MM-DD`.
 *
 * Pure calendar arithmetic on a date string: decompose, construct at UTC
 * midnight, round-trip-validate to catch a date the regex admits but the
 * calendar rolls forward (`2026-02-31`), then step one day. Operating at UTC
 * midnight is what makes the `+ SECONDS_PER_DAY` step exact — there is no DST in
 * UTC to shift the boundary. Used both by the day-walk in `findFreeSlots` and by
 * the tool layer's `slotRangeOf`.
 */
export function nextCivilDate(date: string): string {
  const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (parts === null) throw new DavNotFoundError();

  const year = Number(parts[1]);
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  const at = new Date(Date.UTC(year, month - 1, day));

  if (
    at.getUTCFullYear() !== year ||
    at.getUTCMonth() !== month - 1 ||
    at.getUTCDate() !== day
  ) {
    throw new DavNotFoundError();
  }

  const next = new Date(at.getTime() + SECONDS_PER_DAY * 1000);
  const pad = (value: number, width = 2): string =>
    String(value).padStart(width, "0");
  return `${pad(next.getUTCFullYear(), 4)}-${pad(next.getUTCMonth() + 1)}-${pad(next.getUTCDate())}`;
}

/**
 * Fold a working-days array into a canonical string that pins by equality.
 *
 * Sorted, deduplicated, joined digits (`[5,1,2,3,4]` → `"12345"`). It lives here
 * rather than beside the cursor codec because it is computed both when minting a
 * cursor and when comparing one, and it belongs next to the function that owns
 * `workDays`'s meaning. The digits are 0–6, matching `Date#getUTCDay`.
 */
function workDaysKeyOf(workDays: readonly number[]): string {
  return [...new Set(workDays)].sort((a, b) => a - b).join("");
}

/** What one find-slots call asks for. Every field a resolved, concrete value. */
export interface FindSlotsOptions {
  /** The range start, in SECONDS since the epoch. */
  rangeStart: number;
  /** The range end, in SECONDS since the epoch. Half-open: this instant is out. */
  rangeEnd: number;
  /** The slot length, in minutes. Positive. */
  durationMinutes: number;
  /** The IANA zone the working hours and candidates are read in. Required (D-85). */
  tzid: string;
  /** The working-day start wall clock, `HH:MM`. */
  workDayStartLocal: string;
  /** The working-day end wall clock, `HH:MM`. */
  workDayEndLocal: string;
  /** The days of the week that count as working days. 0 = Sunday … 6 = Saturday. */
  workDays: readonly number[];
  /** Rows per page. Clamped rather than refused — see `clampPageSize`. */
  pageSize?: number;
  /** The `nextCursor` of a previous page, or absent for page one. */
  cursor?: string;
}

/**
 * One free slot, in the exact shape `calendar_create_event` already takes (D-88).
 *
 * `startLocal`/`endLocal`/`tzid` are byte-for-byte what the create tool's
 * `inputSchema` validates, so booking a candidate is copying these three values
 * straight into that call — "book it without re-stating it".
 */
export interface SlotCandidate {
  startLocal: string;
  endLocal: string;
  tzid: string;
}

/** One page of find-slots candidates. A single trusted-only object (Pattern 3). */
export interface SlotPage {
  candidates: SlotCandidate[];
  hasMore: boolean;
  nextCursor: string | null;
  /**
   * True when the sweep could not read every calendar's busy time in full —
   * a cap stopped an expansion, or a calendar could not be swept at all.
   *
   * **For THIS tool the flag means the OPPOSITE of what it means on a listing,
   * and the difference is a safety property rather than a nuance (CR-01,
   * T-06-04).** On `EventPage` a truncated result is a SHORT list — fewer rows
   * than exist, which is safe. Here the free/busy picture is built by
   * SUBTRACTING busy intervals from a working-hours window, so a calendar whose
   * busy time was under-counted turns real commitments into free slots a caller
   * would book over. Under-counting busy is the one direction this tool must
   * never fail in.
   *
   * So `truncated: true` here is fail-closed: `candidates` is ALWAYS empty when
   * it is set, with `hasMore: false` and `nextCursor: null`. The flag says "the
   * free/busy picture is incomplete, so no candidates are returned" — never
   * "here are some slots, but the picture was incomplete." A caller can never
   * read a free-slot claim built on an under-counted busy set.
   */
  truncated: boolean;
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
  /** The unsupported zone, echoed back, or null. Never a thrown error (D-85). */
  unsupportedTimezone: string | null;
}

/** A busy interval, half-open: `[start, end)` in seconds since the epoch. */
interface BusyInterval {
  start: number;
  end: number;
}

/**
 * Derive the busy interval one occurrence contributes, or `null` when it
 * contributes none.
 *
 * **The must-never-be-wrong direction is UNDER-counting busy time** — a false
 * "you are free". An occurrence with a resolved UTC instant on both ends yields
 * that instant interval directly. An occurrence WITHOUT one — an all-day date,
 * or a time whose zone this server could not resolve, the only two cases
 * `EventTime.utc` is absent for — is NOT dropped: it blocks the whole named
 * local day (or days) in the CALLER's own tzid, since neither an all-day date
 * nor an unresolved foreign zone identifies one of this server's five zones to
 * convert against.
 *
 * For an all-day event iCloud's `DTEND` is already the exclusive day after the
 * last busy day, so the raw end date is used as-is; for a timed occurrence whose
 * zone did not resolve the end date IS the last busy day, so one civil day is
 * added to make it exclusive. Either way the block is never shorter than the
 * single named start day — a zero-length or reversed occurrence still blocks its
 * own day rather than vanishing, which is the whole point of not dropping it.
 */
function busyIntervalOf(occurrence: Occurrence, tzid: string): BusyInterval | null {
  const start = occurrence.start;
  const end = occurrence.end;

  if (start.utc !== undefined && end.utc !== undefined) {
    return end.utc <= start.utc ? null : { start: start.utc, end: end.utc };
  }

  const startDate = start.local.slice(0, 10);
  const rawEndDate = end.local.slice(0, 10);
  const exclusiveEnd = start.allDay ? rawEndDate : nextCivilDate(rawEndDate);
  // Never block fewer than the single named day: an all-day event with no DTEND
  // reports end === start, and a same-day unresolved-zone occurrence has one end
  // date — both would otherwise derive an empty interval and drop the occurrence,
  // which is the false "you are free" this whole branch exists to prevent.
  const endDate = exclusiveEnd > startDate ? exclusiveEnd : nextCivilDate(startDate);

  const from = localTimeToUtc(`${startDate}T00:00:00`, tzid);
  const to = localTimeToUtc(`${endDate}T00:00:00`, tzid);
  if (from === null || to === null || to <= from) return null;
  return { start: from, end: to };
}

/**
 * Sort busy intervals and merge those that touch or overlap into continuous
 * blocks.
 *
 * Touching counts as overlapping — `next.start <= mergedEnd` merges — which is
 * the adjacency rule stated once for this whole tool: a candidate may legitimately
 * start the instant a busy interval ends, so two abutting busy intervals are one
 * continuous block for gap-finding rather than a gap between them.
 */
function mergeBusy(intervals: BusyInterval[]): BusyInterval[] {
  const sorted = [...intervals].sort((a, b) => a.start - b.start);
  const merged: BusyInterval[] = [];
  for (const interval of sorted) {
    const last = merged[merged.length - 1];
    if (last !== undefined && interval.start <= last.end) {
      last.end = Math.max(last.end, interval.end);
    } else {
      merged.push({ start: interval.start, end: interval.end });
    }
  }
  return merged;
}

/**
 * Subtract the merged busy blocks overlapping a window from it, yielding the
 * free gaps inside `[windowStart, windowEnd)`.
 *
 * `merged` is sorted by start. Standard interval subtraction: walk a cursor from
 * the window start, emit the space before each block that begins after it, and
 * advance past the block.
 */
function freeGaps(
  windowStart: number,
  windowEnd: number,
  merged: BusyInterval[],
): BusyInterval[] {
  const gaps: BusyInterval[] = [];
  let cursor = windowStart;
  for (const block of merged) {
    if (block.end <= cursor) continue;
    if (block.start >= windowEnd) break;
    if (block.start > cursor) gaps.push({ start: cursor, end: block.start });
    cursor = Math.max(cursor, block.end);
    if (cursor >= windowEnd) break;
  }
  if (cursor < windowEnd) gaps.push({ start: cursor, end: windowEnd });
  return gaps;
}

/**
 * Find free slots across every calendar the account has, paged (SCHED-01, D-84).
 *
 * ## The order of refusals
 *
 * An unsupported `tzid` returns the cheapest possible response — an empty page
 * carrying the zone back — BEFORE `assertSlotRange`, mirroring `createEvent`'s
 * early return. Then the range is refused if over-wide, then a supplied cursor
 * is decoded and every pinned axis compared, all BEFORE `withRediscovery` and so
 * before any KV read or request. A malformed token, a stale cursor and an
 * over-wide range each cost nothing.
 *
 * ## The sweep
 *
 * ONE PROPFIND enumerates every calendar (D-84's "full stop"). A plain `for...of`
 * loop then calls the existing `collectFrom` once per calendar, SERIALLY — never
 * a combinator — accumulating every occurrence into one shared list under one
 * shared step budget for the whole sweep. Busy intervals are derived (all-day and
 * unresolved-zone occurrences block whole named days rather than being dropped),
 * merged, and subtracted from each working day's window to produce candidate gaps.
 *
 * ## Fail closed on an incomplete sweep (CR-01, T-06-04)
 *
 * If the sweep could not read every calendar's busy time in full — a step-budget
 * truncation, or a calendar that could not be swept at all (CR-02) — this returns
 * NO candidates, with `truncated: true`. Under-counting busy time is the one
 * direction this tool must never fail in, so a partial busy set never produces a
 * free-slot claim. This is a DELIBERATE OVERRIDE of the plan's original
 * flag-and-return design (06-01-PLAN.md T-06-04), made on the phase-6 review's
 * recommendation; see `SlotPage.truncated` for the inverted safety valence.
 *
 * ## The order the cursor rides
 *
 * Candidates are collected across every day and then EXPLICITLY sorted by start
 * ascending — not trusted to fall out of the day-walk in order, because the
 * cursor's resume predicate depends on that total order the same way
 * `compareEventOrder` underwrites the calendar cursor. The page is cut to one
 * more than the page size; the presence of that extra row is `hasMore`.
 *
 * The response carries NO stranger-authored calendar content — no event title,
 * location, attendee or organiser name — by construction: every field is a value
 * this server computed. That is why it needs no untrusted fence (Pattern 3).
 */
export async function findFreeSlots(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: FindSlotsOptions,
): Promise<SlotPage> {
  // Cheapest possible response, before the range check and before any request,
  // mirroring `createEvent`. A zone this server holds no definition for is
  // reported back rather than raised (D-85).
  if (!isSupportedTimezone(options.tzid)) {
    return {
      candidates: [],
      hasMore: false,
      nextCursor: null,
      truncated: false,
      cacheHit: false,
      unsupportedTimezone: options.tzid,
    };
  }

  assertSlotRange(options.rangeStart, options.rangeEnd);

  const workDaysKey = workDaysKeyOf(options.workDays);

  let cursor: SlotCursor | null = null;
  if (options.cursor !== undefined) {
    // The decoder pins and validates the RANGE; the remaining axes are compared
    // here, mirroring `pagedEvents`'s scope-and-terms comparison ordering. A
    // cursor minted under a different duration, zone or working-hours window
    // records a position in a DIFFERENT set of candidate gaps, so it is refused
    // — before the network read — rather than resumed against the wrong set.
    cursor = decodeSlotCursor(options.cursor, options.rangeStart, options.rangeEnd);
    if (
      cursor.durationMinutes !== options.durationMinutes ||
      cursor.tzid !== options.tzid ||
      cursor.workDayStartLocal !== options.workDayStartLocal ||
      cursor.workDayEndLocal !== options.workDayEndLocal ||
      cursor.workDaysKey !== workDaysKey
    ) {
      throw new DavNotFoundError();
    }
  }

  const pageSize = clampPageSize(options.pageSize);
  const workDaySet = new Set(options.workDays);
  const durationSeconds = options.durationMinutes * 60;
  const stepSeconds = SLOT_GRANULARITY_MINUTES * 60;

  return withRediscovery(env, principal, davFetch, "caldav", async (resolved) => {
    const collections = await fetchCollections(davFetch, resolved);

    // ONE allowance for the WHOLE multi-calendar sweep (WR-01, widened from "one
    // per page" to "one per sweep"): the cost the caller pays is the sweep, and a
    // per-calendar budget would let one pathological calendar starve the rest.
    const budget = newStepBudget();
    const pending: PendingOccurrence[] = [];
    let truncated = false;

    // The SERIAL sweep. A plain `for...of`, each iteration fully awaited before
    // the next begins — NEVER `Promise.all` or any sibling combinator. This is
    // the shape ./.claude/CLAUDE.md §3 bans a fan-out around and the scan rule
    // enforces over `findFreeSlots` and `collectFrom` alike. `collectFrom` is
    // reused unmodified: it already fetches one calendar's bounded range and
    // expands it, which is exactly what each calendar needs here.
    for (const collection of collections) {
      // A subscribed calendar with no readable source cannot be swept (CR-02).
      // `collectFrom` would route it to `collectFromFeed`, whose defensive throw
      // on a null source would abort the ENTIRE sweep — breaking the feature on
      // any account holding one unreadable subscription (a holiday feed, a
      // shared read-only ICS). `pagedEvents` guards this same shape one layer up
      // for a single-calendar read; here the guard must not take the whole
      // account down with one calendar. It is NOT skipped as "zero busy":
      // skipping a calendar this server cannot read is itself an under-count of
      // busy time, the false-free direction CR-01 closes. A source-less
      // subscription has no feed to resolve, so the safe disposition is the same
      // fail-closed one truncation takes — mark the sweep incomplete and let the
      // fail-closed return above emit no candidates.
      if (collection.subscribed && collection.source === null) {
        truncated = true;
        continue;
      }
      const collectionTruncated = await collectFrom(
        collection,
        davFetch,
        options.rangeStart,
        options.rangeEnd,
        pending,
        budget,
      );
      if (collectionTruncated) truncated = true;
    }

    // FAIL CLOSED on an incomplete sweep (CR-01, T-06-04). A truncation here is
    // not a partial answer, it is an UNSAFE one: any calendar whose busy time
    // was under-counted turns real commitments into free slots a caller would
    // book over. Unlike `listEvents`, where `truncated` means "fewer rows"
    // (safe), for this tool it means "some busy time was not counted" — the
    // inverted safety valence `SlotPage.truncated` documents. So the DELIBERATE
    // OVERRIDE of the plan's original flag-and-return design (06-01-PLAN.md
    // T-06-04): rather than return candidates computed from an incomplete busy
    // set alongside the flag, return NO candidates. The caller learns the
    // free/busy picture is untrustworthy and can never read a free-slot claim
    // built on under-counted busy time. Reachable adversarially — a stranger's
    // invitation carrying a high-frequency rule can exhaust the shared step
    // budget — which is exactly why the safe disposition is refusal, not a
    // confident-looking partial answer.
    if (truncated) {
      return {
        candidates: [],
        hasMore: false,
        nextCursor: null,
        truncated: true,
        cacheHit: resolved.cacheHit,
        unsupportedTimezone: null,
      };
    }

    const busy: BusyInterval[] = [];
    for (const one of pending) {
      const interval = busyIntervalOf(one.occurrence, options.tzid);
      if (interval !== null) busy.push(interval);
    }
    const merged = mergeBusy(busy);

    // The whole in-range candidate set, built before the sort and the cut.
    const candidates: number[] = [];

    const startCivil = utcToLocalTime(options.rangeStart, options.tzid)!.slice(0, 10);
    const endCivil = utcToLocalTime(options.rangeEnd, options.tzid)!.slice(0, 10);

    for (let date = startCivil; date < endCivil; date = nextCivilDate(date)) {
      const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date)!;
      const weekday = new Date(
        Date.UTC(Number(parts[1]), Number(parts[2]) - 1, Number(parts[3])),
      ).getUTCDay();
      if (!workDaySet.has(weekday)) continue;

      const dayStart = localTimeToUtc(`${date}T${options.workDayStartLocal}:00`, options.tzid);
      const dayEnd = localTimeToUtc(`${date}T${options.workDayEndLocal}:00`, options.tzid);
      if (dayStart === null || dayEnd === null || dayEnd <= dayStart) continue;

      // Clip the working window to the requested range, so a range boundary that
      // falls mid-day cannot produce a candidate outside it.
      const windowStart = Math.max(dayStart, options.rangeStart);
      const windowEnd = Math.min(dayEnd, options.rangeEnd);
      if (windowEnd <= windowStart) continue;

      for (const gap of freeGaps(windowStart, windowEnd, merged)) {
        // Candidate starts align to the increment from the working day's OWN
        // start, never the gap's start, so the offered times are stable across
        // days. Advance to the first grid point at or after the gap start.
        const stepsIn = Math.ceil((gap.start - dayStart) / stepSeconds);
        const firstK = Math.max(0, stepsIn);
        for (
          let candidate = dayStart + firstK * stepSeconds;
          candidate + durationSeconds <= gap.end;
          candidate += stepSeconds
        ) {
          if (candidate < gap.start) continue;
          candidates.push(candidate);
        }
      }
    }

    // Explicitly sorted, not trusted to the day-walk: the cursor's resume
    // predicate rides this total order. A comment stating so, mirroring
    // `compareEventOrder`'s role for the calendar cursor.
    candidates.sort((a, b) => a - b);

    const after =
      cursor === null
        ? candidates
        : candidates.filter((start) => isAfterSlotCursor(start, cursor));

    // One more row than the page holds; its PRESENCE is has-more, dropped before
    // the cursor is minted so the next page begins after the last row RETURNED.
    const window = after.slice(0, pageSize + 1);
    const hasMore = window.length > pageSize;
    const rows = hasMore ? window.slice(0, pageSize) : window;
    const last = rows[rows.length - 1];

    return {
      candidates: rows.map((start) => ({
        startLocal: utcToLocalTime(start, options.tzid)!,
        endLocal: utcToLocalTime(start + durationSeconds, options.tzid)!,
        tzid: options.tzid,
      })),
      hasMore,
      nextCursor:
        hasMore && last !== undefined
          ? encodeSlotCursor({
              rangeStart: options.rangeStart,
              rangeEnd: options.rangeEnd,
              durationMinutes: options.durationMinutes,
              tzid: options.tzid,
              workDayStartLocal: options.workDayStartLocal,
              workDayEndLocal: options.workDayEndLocal,
              workDaysKey,
              lastCandidateStart: last,
            })
          : null,
      truncated,
      cacheHit: resolved.cacheHit,
      unsupportedTimezone: null,
    };
  });
}

/**
 * Read one resource's body out of a multi-status, addressed by its own URL.
 *
 * The href is resolved against the collection before it is compared, because a
 * server may answer with a path where the request carried one. Comparing the
 * raw strings would miss on exactly the shape iCloud actually sends.
 *
 * `null` when the resource is absent from the answer or came back without a
 * body — there is nothing to read, and a partial object is worse than a
 * refusal (T-03-16).
 */
function bodyFor(
  responses: DAVResponse[],
  calendarUrl: string,
  objectUrl: string,
): string | null {
  for (const response of responses) {
    const href = response.href;
    if (typeof href !== "string" || href.length === 0) continue;

    let resolved: string;
    try {
      resolved = new URL(href, calendarUrl).href;
    } catch {
      // Nothing is read from the caught value.
      continue;
    }
    if (resolved !== objectUrl) continue;

    // The library types this as `any` and hands back either the CDATA wrapper
    // or the bare value, depending on how the XML layer read the element.
    const raw = response.props?.calendarData;
    const data =
      raw !== null && typeof raw === "object"
        ? (raw as { _cdata?: unknown })._cdata
        : raw;
    if (typeof data === "string" && data.length > 0) return data;
  }
  return null;
}

/**
 * Read one resource's ETag out of the SAME multi-status the body came from.
 *
 * The double read is `bodyFor`'s exactly — the library types the prop as `any`
 * and hands back either the CDATA wrapper or the bare value depending on how
 * the XML layer read the element — and the href is resolved against the
 * collection before it is compared for the same reason: a server may answer
 * with a path where the request carried an absolute URL.
 *
 * **Returned BYTE-EXACT, quotes and weak prefix included.** An ETag is an
 * opaque quoted string; stripping the quotes to re-add them is a normalisation
 * that eventually meets a `W/"..."` and gets it wrong. tsdav's own object
 * mapping does `String(res.props.getetag)` with no unquoting, and this matches
 * it deliberately rather than by coincidence.
 */
function etagFor(
  responses: DAVResponse[],
  calendarUrl: string,
  objectUrl: string,
): string | null {
  for (const response of responses) {
    const href = response.href;
    if (typeof href !== "string" || href.length === 0) continue;

    let resolved: string;
    try {
      resolved = new URL(href, calendarUrl).href;
    } catch {
      // Nothing is read from the caught value.
      continue;
    }
    if (resolved !== objectUrl) continue;

    const raw = response.props?.getetag;
    const value =
      raw !== null && typeof raw === "object"
        ? (raw as { _cdata?: unknown })._cdata
        : raw;
    if (typeof value === "string" && value.length > 0) return value;
  }
  return null;
}

/**
 * Fetch one occurrence in full, by the opaque id a listing returned (CAL-03).
 *
 * ## Why the whole body is inside `withRediscovery`
 *
 * Every operation in this module resolves through that wrapper — `listCalendars`
 * and `listEvents` already did, and this is the first one added since it was
 * written, which is precisely when the invariant is easiest to lose. D-60's
 * single-retry policy is a property of the CALDAV SERVICE LAYER rather than of
 * whichever operation happened to be written first: an operation added outside
 * the wrapper is a path on which a moved shard host surfaces to the user as
 * not-found instead of being re-resolved.
 *
 * One honest limitation, stated rather than discovered. The reference carries
 * ABSOLUTE URLs minted when the listing ran, so a re-discovery here does not
 * repoint this attempt at a new host the way it repoints an operation built
 * from `resolved.homeUrl`. What it does buy is real and is the same on both
 * paths: the stale entry is deleted, so the next call resolves live, and the
 * retry is a genuine second attempt. Rewriting the token's host from a freshly
 * resolved home would be a different design and a larger one — it is recorded
 * as an open question rather than smuggled in here.
 *
 * ## Why re-expanding is safe
 *
 * The resource is re-parsed and re-expanded, and the occurrence whose
 * recurrence id matches is selected locally. **Re-expansion is deterministic
 * given the same bytes**, which is the whole property that lets an occurrence
 * identifier be a POSITION IN A SERIES rather than a stored row — no table, no
 * migration, and no identifier that can be orphaned by a rule the organiser
 * edited.
 *
 * ## Cost
 *
 * ONE request. The calendar URL and the object URL both live inside the token,
 * so addressing the resource costs no lookup and no collection enumeration —
 * the argument that chose this identifier shape in the first place. Compare
 * `listEvents`, which pays three: one to enumerate the collections, then the
 * library's two reports against the one calendar it was told to read.
 */
export async function getEvent(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
): Promise<EventDetail> {
  return (await readEvent(env, principal, davFetch, ref)).detail;
}

/**
 * Why this server would refuse to REWRITE a resource it can happily read.
 *
 * A closed vocabulary this server chooses from, on `matchPath`'s footing: it
 * describes a decision this server made about its own capability, admits no
 * free text, and carries nothing a stranger wrote. That is what lets it ride in
 * the TRUSTED half of a preview — the identifier of an unsupported zone, which
 * a stranger DID write, is deliberately not reported beside it (03-09).
 *
 * **The reason there is a list at all is that a commit deliberately does not
 * re-read the resource.** It has exactly one outbound request, the write, so
 * the body it sends is BUILT from the confirmed change rather than patched into
 * the bytes that are there. Anything on the resource that this server's own
 * builder cannot reproduce would therefore be silently deleted by a commit —
 * and a preview whose whole promise is "exactly what would change" must not
 * omit "and your reminder disappears".
 *
 * So this is a floor that later plans raise rather than a permanent limit. Each
 * member names a capability that arrives with a plan:
 *
 *   - `recurring` — 05-10, 05-11 and 05-12 own the three write scopes. Until
 *     then a rewrite of a series would flatten it to one event, which is the
 *     exact "rewritten by omission" failure the phase's assumption-delta names.
 *   - `scheduling` — CALW-06 owns attendees. Rewriting a resource that carries
 *     them without carrying them back is not merely lossy: dropping an
 *     `ATTENDEE` makes iCloud send a CANCELLATION to that person.
 *   - `unsupported-properties` — a reminder, a category, a status, an `X-`
 *     property. Ordinary rather than exotic; every event a person set a
 *     reminder on carries a `VALARM`.
 *   - `unnamed-resource` — the resource's own UID is not what its URL names, so
 *     the commit cannot derive the UID to write back. See `uidFromObjectUrl`.
 *   - `unsupported-timezone` — the zone the event is anchored to is one this
 *     server holds no `VTIMEZONE` for, so it could not re-anchor the rewritten
 *     resource to it. `VTIMEZONE_ALLOWLIST` is where that is widened.
 */
export type UnsupportedTarget =
  | "recurring"
  | "scheduling"
  | "unsupported-properties"
  | "unnamed-resource"
  | "unsupported-timezone";

/**
 * One event read together with the ETag a confirmation must bind to.
 *
 * **A wrapper rather than a field on `EventDetail`, and the reason is about
 * what gets PUBLISHED.** `EventDetail` is a published response shape, and an
 * ETag is not a value any tool response carries — it exists to be signed into a
 * confirmation and sent back on a header. Putting it on the detail would
 * publish it, and the two fence gates would then have to decide which half it
 * rides in for a value that should ride in neither.
 *
 * `unsupportedTarget` is the third field and it was not in the plan's sketch of
 * this type. It is here because the classification is a property of the RAW
 * RESOURCE — the property names on the `VEVENT`, its subcomponents, and whether
 * its URL names its UID — none of which survives into `EventDetail`. Computing
 * it anywhere else would mean reading the resource twice, which is the one
 * thing this function exists to avoid.
 */
export interface EventWithEtag {
  detail: EventDetail;
  /** The ETag exactly as the server spelled it, quotes included. */
  etag: string;
  /**
   * The resource's own bytes, exactly as the server sent them.
   *
   * **Here because a PATCH cannot be built without them, and this read is the
   * only place they exist.** A rebuild assembles its body from the confirmed
   * change and needs nothing from the stored resource; an occurrence-scoped
   * write clones the resource and changes one component, so it needs the whole
   * thing. Carrying the bytes on this shape is what lets the commit leg use the
   * SAME contained, ETag-bearing read the preview leg uses rather than growing
   * a second entry point that would need its own containment assertions.
   *
   * UNTRUSTED and never published. Like the ETag beside it, this is not a value
   * any tool response carries — see the note above on why the ETag is here
   * rather than on `EventDetail`, which applies to this with more force.
   */
  body: string;
  /**
   * Whether the resource is a SERIES rather than a single event.
   *
   * The question that decides whether a write scope is required, asked here
   * because it is a property of the raw resource's component tree and nothing
   * about it survives into `EventDetail`. `Occurrence.isRecurring` is a
   * different claim — it describes the one occurrence that was selected, and a
   * masterless resource of pure overrides reports it true for every component
   * while carrying no rule at all.
   */
  isRecurring: boolean;
  /**
   * How many occurrences the resource produces, in total and from the one
   * named.
   *
   * Counted inside the same parse scope the selection runs in, so it costs no
   * second parse and no second request. It is what lets a preview state a
   * number and a later assertion check that number against the write.
   */
  counts: OccurrenceCounts;
  /** Why a rewrite is refused, or null when the resource is rewritable. */
  unsupportedTarget: UnsupportedTarget | null;
  /**
   * Whether the resource is a scheduling object resource — it carries people.
   *
   * **A FACT rather than a blocker, and it replaced one.** Until plan 05-14 this
   * slot held `unsupportedOccurrenceTarget`, whose one verdict was `scheduling`;
   * once a patching writer existed for such a resource the verdict stopped being
   * a refusal and became a routing question. See `isSchedulingResource`, which
   * owns the argument, and `hasSeriesMaster` above, which is the same
   * verdict-to-fact move made two plans earlier.
   *
   * What reads it: the commit, to choose between PATCHING the stored bytes and
   * REBUILDING them. Read here because it is a property of the component tree
   * and nothing about it survives into `EventDetail` — `EventDetail.attendees`
   * is the parsed guest list of the ONE occurrence that was selected, which is a
   * different question and answers null for a resource carrying only an opaque
   * principal-href `ORGANIZER`.
   */
  isScheduling: boolean;
  /**
   * Whether the resource carries a component with no recurrence identifier.
   *
   * **This replaced a fourth blocker field, and the replacement is a correction
   * rather than a simplification.** `narrowBlockerOf` answered "what about these
   * bytes stops a NARROWING" and had exactly one verdict: a resource with no
   * master carries no rule to narrow. Plan 05-12 gave that shape an operation —
   * one of its edited dates can be dropped outright — so the verdict became
   * false for one scope and true for the other two, which is a question about
   * the REQUEST rather than about the bytes. A bytes-level field cannot see the
   * scope, so the fact moved out here and the judgement moved to the tool
   * boundary, where the scope is known and where every other scope refusal
   * already lives.
   *
   * False is the shape a user would describe as *a set of individually edited
   * dates with no repeating rule behind them* — see the tool layer's
   * `noRepeatingRule`, which is the sentence this boolean turns into.
   */
  hasSeriesMaster: boolean;
  /**
   * Why a DELETE is refused, or null when the resource may be removed.
   *
   * **A second field rather than a second reading of the first, because the
   * two questions have different answers and only one of them is about a
   * rebuild.** See `deleteBlockerOf`, which owns the argument.
   */
  unsupportedDeleteTarget: UnsupportedTarget | null;
  /**
   * The revision the FETCHED resource carried, or null when it carried none.
   *
   * **Read here because here is the only place it can be read for free.** A
   * commit has one outbound request — the write — so it never sees the
   * resource's bytes; this multi-get is the last moment the stored revision
   * exists in this server's hands. It travels to the commit inside the SIGNED
   * confirmation (`ConfirmPayload.s`), on the ETag's own footing: a fact about
   * the resource at read time, sealed so a caller cannot move it.
   *
   * Null and zero are kept apart rather than collapsed. `nextSequence` maps
   * both to one, so nothing downstream depends on the difference today — but
   * "the resource said zero" and "the resource said nothing" are two claims,
   * and this field reports the one that was true.
   */
  sequence: number | null;
}

/**
 * Every property `buildVEvent` emits, plus the two the server re-derives.
 *
 * `created` and `last-modified` are tolerated rather than reproduced: they are
 * the server's own bookkeeping about the resource and iCloud sets them on the
 * write. Everything else absent from this set is a value the user or the
 * organiser put there, so a rewrite that dropped it would be data loss.
 *
 * `sequence` is on the list and is CARRIED FORWARD by the rebuild rather than
 * reset — `updateEventBody` emits `nextSequence` of what the fetched resource
 * held. It was reset to zero until 05-09, which was inert only because a
 * resource carrying scheduling properties is refused two lines below; the fix
 * is here rather than deferred to whoever lifts that refusal, because a
 * revision that goes backwards is silent at every layer and a latent landmine
 * is a poor thing to hand forward.
 */
const REWRITABLE_EVENT_PROPERTIES: ReadonlySet<string> = new Set([
  "uid",
  "dtstamp",
  "sequence",
  "summary",
  "location",
  "description",
  "dtstart",
  "dtend",
  "created",
  "last-modified",
]);

/** The properties that make a resource a series rather than an event. */
const RECURRENCE_PROPERTIES: ReadonlySet<string> = new Set([
  "rrule",
  "rdate",
  "exdate",
  "recurrence-id",
]);

/** The properties that make a resource a SCHEDULING object (RFC 6638). */
const SCHEDULING_PROPERTIES: ReadonlySet<string> = new Set([
  "attendee",
  "organizer",
]);

/**
 * The UID a resource's own URL names, or null when the URL does not name one.
 *
 * **The commit leg has one outbound request and it is the write, so it never
 * sees the resource's bytes.** The UID it must write back therefore has to come
 * from the only thing it holds: the object URL inside the signed confirmation.
 * CalDAV's convention — and Apple's practice — is that an object resource is
 * named for its UID with a `.ics` suffix, and `createEvent` in this very module
 * follows it when it mints a filename.
 *
 * A convention is not a guarantee, which is why this is DERIVE-AND-VERIFY
 * rather than derive: the preview compares this against the UID the resource
 * actually carries and refuses to mint a confirmation when the two disagree.
 * Writing a resource under a UID this server guessed would be worse than
 * refusing, because a UID is how every other client on the account recognises
 * the same event.
 *
 * The decode is what makes it work on a real account rather than only on a tidy
 * fixture: every UID iCloud mints carries an `@`, so the href naming it is
 * percent-encoded.
 *
 * **Exported for the commit leg of a gated CREATE, and for nothing else.** That
 * leg holds a signed object URL and must write the resource the preview named,
 * so it needs the same derivation this module already performs twice. Reading
 * the UID out of the signed URL rather than re-minting one is what makes "the
 * resource that was previewed is the resource that is created" true rather than
 * merely likely.
 */
export function uidFromObjectUrl(objectUrl: string): string | null {
  let path: string;
  try {
    path = new URL(objectUrl).pathname;
  } catch {
    // Nothing is read from the caught value — the URL may be attacker-chosen.
    return null;
  }

  const last = path.slice(path.lastIndexOf("/") + 1);
  if (!last.toLowerCase().endsWith(".ics")) return null;

  try {
    return decodeURIComponent(last.slice(0, -".ics".length));
  } catch {
    // A stray `%` is not a UID. Nothing is read from the caught value.
    return null;
  }
}

/**
 * What about the RESOURCE'S OWN BYTES would stop a rewrite, or null.
 *
 * Read inside the parse scope, because it walks the component tree. The order
 * is recurrence, then scheduling, then everything else — a series carrying
 * attendees is reported as a series, which is the larger of the two facts and
 * the one whose plan lands first.
 *
 * **Three passes rather than one, and that is a FIX rather than a style
 * choice** (`.planning/WINDOWS.md` entry 57). A single pass reports the first
 * matching property in DOCUMENT order, so a `VEVENT` whose `ATTENDEE` happens
 * to be written above its `RRULE` came back `scheduling` while the docstring
 * above promised `recurring`. An invited recurring series is exactly that
 * shape, and document order is the organiser's client's choice rather than a
 * fact about the resource — so the classification depended on which app created
 * the event. `deleteBlockerOf` below already checked every property before
 * classifying, for the same reason; this now matches it.
 *
 * ## `scheduling` is no longer one of the verdicts, and the narrowing is the
 * whole subject of plan 05-14
 *
 * It was, from 05-06 until 05-14, and it was RIGHT for as long as a scopeless
 * update had only one way to write a resource. 05-RESEARCH § F-1 recorded it as
 * measured necessary — *"Do not relax that refusal"* — on three hazards a
 * rebuild causes and none of which has gone away: the opaque principal-href
 * `ORGANIZER` iCloud substitutes (probe P-1 (d)) re-emitted as a plain
 * `mailto:`, every `SCHEDULE-STATUS` dropped, and every `PARTSTAT` reset from
 * `ACCEPTED` to `NEEDS-ACTION` — which erases a reply rather than merely failing
 * to carry it.
 *
 * What changed is not the argument but the ALTERNATIVE. 05-10 built a commit
 * that reads the resource and PATCHES it, and `applyEventChange` is that
 * discipline applied to a one-off event: the bytes are the stored resource's own
 * and only the confirmed fields are asserted over them. So a resource carrying
 * `ATTENDEE` or `ORGANIZER` is not refused here — it is written by a different
 * writer, and `EventWithEtag.isScheduling` is the fact the commit routes on.
 *
 * **The three verdicts BELOW this line are skipped for such a resource, and that
 * is deliberate rather than a shortcut.** Each of them exists because a rebuild
 * cannot reproduce something, and a patch reproduces nothing — it keeps the
 * bytes. `unsupported-properties` is a `VALARM` or an `X-` property the patch
 * leaves where it found it; `unnamed-resource` is a UID the rebuild must derive
 * from the object URL and write back, which the patch never derives at all. It
 * is the same argument the occurrence-scoped patch path has always made.
 *
 * `recurring` is checked FIRST and still fires for an invited series, so a
 * scopeless rewrite of one is refused exactly as it was. `unsupported-timezone`
 * is not this function's verdict at all — `readEvent` applies `timezoneBlockerOf`
 * as the fallback, and it still applies to a scheduling resource, because the
 * patch re-anchors `DTSTART` and `DTEND` to the zone the change names.
 */
function structuralBlockerOf(
  resource: ParsedCalendarResource,
  objectUrl: string,
): UnsupportedTarget | null {
  // A master plus its overrides is more than one component, and it is a series
  // whether or not this particular component carries the rule.
  if (resource.components.length !== 1) return "recurring";

  const names: string[] = [];
  for (const component of resource.components) {
    for (const property of component.getAllProperties()) {
      names.push(property.name);
    }
  }

  if (names.some((name) => RECURRENCE_PROPERTIES.has(name))) return "recurring";
  // Written by PATCH rather than by rebuild, so none of the three rebuild
  // verdicts below describes it. See the docstring, which carries the argument
  // and the three hazards the patch is what answers.
  if (names.some((name) => SCHEDULING_PROPERTIES.has(name))) return null;
  if (names.some((name) => !REWRITABLE_EVENT_PROPERTIES.has(name))) {
    return "unsupported-properties";
  }

  for (const component of resource.components) {
    // A `VALARM` is the ordinary case here, not an exotic one.
    if (component.getAllSubcomponents().length > 0) {
      return "unsupported-properties";
    }
  }

  if (resource.uid === null || uidFromObjectUrl(objectUrl) !== resource.uid) {
    return "unnamed-resource";
  }

  return null;
}

/**
 * Whether the resource is a SCHEDULING object resource (RFC 6638).
 *
 * **A FACT rather than a verdict, and the difference is the whole of plan
 * 05-14's tool-layer change.** It used to be a blocker —
 * `unsupportedOccurrenceTarget`, computed by an `occurrenceBlockerOf` whose one
 * surviving verdict was `scheduling` — and the reason it stopped being one is
 * the same reason `narrowBlockerOf` stopped being one two plans earlier: the
 * answer is no longer a refusal, so a field shaped like a refusal would be a
 * docstring promising something the code no longer does.
 *
 * What it decides now is WHICH WRITER, not whether to write. A resource carrying
 * `ATTENDEE` or `ORGANIZER` is patched — its own bytes with the confirmed fields
 * asserted over them — because iCloud rewrote it on the way in and a rebuild
 * would destroy what iCloud put there: the opaque principal-href `ORGANIZER`
 * (probe P-1 (d)), every `SCHEDULE-STATUS`, and every `PARTSTAT`. See
 * `applyEventChange`, which owns that argument, and `structuralBlockerOf` above,
 * which records why the refusal narrowed rather than disappeared.
 *
 * Checked over EVERY property of EVERY component rather than stopping at the
 * first hit, so document order — the organiser's client's choice — cannot change
 * the answer. It is deliberately true for a SERIES carrying attendees as well:
 * an occurrence-scoped patch of one clones every `ATTENDEE` line byte for byte
 * and asserts a fresh revision on the override alone, and the preview names
 * every recipient before any of it happens (CALW-08).
 */
function isSchedulingResource(resource: ParsedCalendarResource): boolean {
  for (const component of resource.components) {
    for (const property of component.getAllProperties()) {
      if (SCHEDULING_PROPERTIES.has(property.name)) return true;
    }
  }
  return false;
}

// A NOTE ON THE TWO BLOCKERS THAT NO LONGER EXIST.
//
// `occurrenceBlockerOf` was the second of them, retired by plan 05-14 for the
// reason `isSchedulingResource` above records: its one surviving verdict,
// `scheduling`, stopped being a refusal once a patching writer existed for a
// resource carrying attendees. What was left was a fact about the bytes with no
// judgement attached, so the fact is what the shape publishes.
//
// The first is below.
//
// A NOTE ON THE FOURTH BLOCKER, WHICH NO LONGER EXISTS.
//
// A scoped delete is the one operation that is a patch AND a removal at once,
// so for three plans it had a blocker of its own. Read the other two with
// that in mind and every one of their verdicts falls away:
//
//   - `structuralBlockerOf`'s rebuild verdicts evaporate for exactly the reason
//     a patch has none of them: a narrowing clones the resource and changes one
//     thing, so there is nothing for it to drop, derive or re-anchor.
//   - `deleteBlockerOf`'s one verdict, `recurring`, evaporates too — and that
//     is the whole point. It exists because a scopeless removal takes every
//     occurrence while the preview describes one, and a scoped delete is the
//     mechanism that makes "just this Tuesday" sayable.
//
// What survived until plan 05-12 was one verdict the other three never had to
// ask: there must be a rule to narrow. That is no longer true of every scope. A
// resource carrying only edited dates can have one of them DROPPED — see
// `dropOverride` — while a request to narrow it from a date onward, or as a
// whole series, still has nothing to narrow. One shape, two answers, chosen by
// the SCOPE: a question about the REQUEST rather than about the bytes, and a
// blocker computed inside the parse scope cannot see it.
//
// So the fact is published as `EventWithEtag.hasSeriesMaster` and the judgement
// moved to the tool boundary, beside every other scope refusal. Keeping a
// bytes-level field that was right for two scopes out of three would have been
// the WINDOWS-57 defect in a new place: a docstring promising something the
// code no longer does.

/**
 * What about the resource's own bytes would stop a DELETE, or null.
 *
 * **The delete's answer is deliberately NARROWER than `structuralBlockerOf`'s,
 * and the divergence is the decision this plan had to make rather than an
 * inconsistency to be tidied away.** Four of that function's five verdicts exist
 * for one reason: a commit REBUILDS the resource from the confirmed change and
 * never sees its current bytes, so anything the builder cannot reproduce would
 * be silently dropped by an update. Read them back with that in mind and every
 * one of them evaporates here:
 *
 *   - `scheduling` — a rewrite that dropped an `ATTENDEE` makes iCloud send
 *     that person a cancellation nobody asked for. A delete removes the whole
 *     resource at the user's explicit request; there is no dropped attendee,
 *     only a deletion the preview names the recipients of. Refusing here would
 *     additionally make CALW-08's "name everyone who will be told" unreachable,
 *     because an event with attendees is exactly this case.
 *   - `unsupported-properties` — a `VALARM` a rebuild would take away. A delete
 *     takes the event away, reminder included, which is what was asked for.
 *   - `unnamed-resource` — the UID a rebuild must write back. A delete writes
 *     no body and derives no UID; it addresses the resource by its own URL.
 *   - `unsupported-timezone` — the zone a rebuild must re-anchor to. Nothing is
 *     re-anchored.
 *
 * **`recurring` survives, and it survives for the opposite reason to the four
 * above.** A resource carrying a rule holds every occurrence of the series, so
 * a scopeless `DELETE` removes all of them — while the preview, which describes
 * the ONE occurrence the caller's identifier named, says a single meeting is
 * disappearing. That is not a lossy write; it is a preview that lies about what
 * it is about to do, on the one operation in this phase that cannot be undone.
 * `EventPreview.scope` is null until 05-10, 05-11 and 05-12 introduce the write
 * scopes that let "just this Tuesday" be said at all, so until then the honest
 * answer is a refusal that still shows what was asked about.
 *
 * Read inside the parse scope, because it walks the component tree. Both arms
 * are checked over EVERY property rather than stopping at the first
 * classification, so a `VEVENT` whose `ATTENDEE` happens to be written above
 * its `RRULE` is still reported as a series — document order is the organiser's
 * choice, not a fact about the resource.
 */
function deleteBlockerOf(
  resource: ParsedCalendarResource,
): UnsupportedTarget | null {
  // A master plus its overrides is more than one component, and it is a series
  // whether or not this particular component carries the rule.
  if (resource.components.length !== 1) return "recurring";

  for (const component of resource.components) {
    for (const property of component.getAllProperties()) {
      if (RECURRENCE_PROPERTIES.has(property.name)) return "recurring";
    }
  }

  return null;
}

/**
 * Whether this server could re-anchor a rewritten resource to the same zone.
 *
 * Read off the DETAIL rather than off the bytes, because that is where the
 * parse has already resolved which zone each end is expressed in — including
 * the case where the resource NAMED a zone it never defined, which comes back
 * as the identifier the resource asked for and is by definition not one this
 * server holds a definition for.
 *
 * An all-day date is anchored to nothing by definition and needs no zone, so it
 * is not asked the question.
 */
function timezoneBlockerOf(detail: EventDetail): UnsupportedTarget | null {
  if (detail.allDay) return null;
  if (!isSupportedTimezone(detail.startTzid)) return "unsupported-timezone";
  if (!isSupportedTimezone(detail.endTzid)) return "unsupported-timezone";
  return null;
}

/** One resource read once: the detail, its ETag if it carried one, and the blocker. */
interface ReadEvent {
  detail: EventDetail;
  etag: string | null;
  body: string;
  isRecurring: boolean;
  counts: OccurrenceCounts;
  unsupportedTarget: UnsupportedTarget | null;
  unsupportedDeleteTarget: UnsupportedTarget | null;
  isScheduling: boolean;
  hasSeriesMaster: boolean;
  sequence: number | null;
}

/**
 * The body `getEvent` and `getEventWithEtag` SHARE.
 *
 * Factored rather than duplicated, on the same argument `EventDetail extends
 * EventSummary` makes one layer up: two independently-written copies of the
 * containment, the multi-get and the occurrence selection would agree today and
 * drift the first time either changed — silently, because both would still
 * return a plausible detail.
 *
 * `getEvent` drops the ETag and the blocker on the way out. It does not assert
 * on the ETag, deliberately: a detail call has no use for one, and refusing a
 * readable event because the server omitted a property this caller never wanted
 * would be a regression in a shipped tool.
 */
async function readEvent(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
): Promise<ReadEvent> {
  return withRediscovery(env, principal, davFetch, "caldav", async (resolved) => {
    // BEFORE the multi-get, because everything after this line reaches the
    // network and `./transport.ts` attaches the credential to whatever URL it is
    // handed. Inside the callback rather than above it, because `resolved.homeUrl`
    // does not exist until discovery has run (03-REVIEW.md CR-01).
    assertUnderHome(ref.calendarUrl, resolved.homeUrl);
    // BOTH URLs, because each independently names what the server is asked for:
    // the object URL is read separately below as the multi-get's `objectUrls`
    // entry, so checking the collection alone is not checking the call.
    assertUnderHome(ref.objectUrl, resolved.homeUrl);

    const responses = await calendarMultiGet({
      url: ref.calendarUrl,
      props: { "d:getetag": {}, "c:calendar-data": {} },
      // The path only, matching the form the library's own object fetch sends.
      objectUrls: [new URL(ref.objectUrl).pathname],
      depth: "1",
      // Never a credential from here. `./transport.ts` attaches it per call and
      // is the only place that may.
      headers: {},
      fetch: davFetch,
    });

    const body = bodyFor(responses, ref.calendarUrl, ref.objectUrl);
    // A resource the server did not return, or returned empty. Not
    // rediscoverable: the host answered, and it answered about this resource.
    if (body === null) throw new DavNotFoundError(false);

    // From the SAME multi-status the body came from. Reading it in a second
    // call would open a race between the ETag and the body that a confirmation
    // then pins as though the two were consistent — which is the precise
    // failure `If-Match` exists to prevent, reintroduced one layer up.
    const etag = etagFor(responses, ref.calendarUrl, ref.objectUrl);

    // Re-parsed and re-expanded to the ONE occurrence named, rather than to a
    // range. A detail call has no range and no honest way to invent one — see
    // `findOccurrence`, which stops the walk at the match instead of at a
    // horizon for exactly that reason.
    //
    // One scope again, for the reason `collectFrom` gives: the selection reads
    // times off the components, so the timezones must still be registered
    // while it runs and gone the moment it returns (CR-03). The structural
    // classification rides inside the same scope because it walks the same
    // component tree, and doing it here is what keeps the resource read once.
    const read = withParsedResource(body, (resource) => {
      const isRecurring = isRecurringResource(resource);
      return {
        found: findOccurrence(resource, ref.recurrenceId),
        structural: structuralBlockerOf(resource, ref.objectUrl),
        // Computed in the SAME scope and over the same component tree, so the
        // second classification costs no second parse and no second request —
        // which is the property `getEventWithEtag` exists to hold.
        deletable: deleteBlockerOf(resource),
        // Not a third classification but a FACT, on `hasSeriesMaster`'s footing
        // below: it decides WHICH WRITER the commit uses rather than whether one
        // may run at all. See `isSchedulingResource`.
        scheduling: isSchedulingResource(resource),
        // Not a fourth classification but a FACT, and the difference is the
        // subject of the note above `deleteBlockerOf`: whether a resource with
        // no rule may be narrowed depends on the scope, which this scope cannot
        // see. Read here because it is a property of the component tree and
        // nothing about it survives into `EventDetail`.
        hasSeriesMaster: resource.master !== null,
        isRecurring,
        // A one-off event produces exactly one occurrence and needs no walk to
        // establish it. Skipping the walk there is not an optimisation for its
        // own sake — it is what keeps the ordinary read, which is most reads,
        // costing what it did before this plan.
        counts: isRecurring
          ? countOccurrences(resource, ref.recurrenceId)
          : { total: 1, fromNamed: 1, bounded: true },
        // And the revision, from the same tree for the same reason. This is the
        // last moment the STORED value is in this server's hands: the commit has
        // one request and it is the write, so a rewrite that did not take the
        // revision from here would have nowhere else to take it from.
        sequence: sequenceOfResource(resource),
      };
    });

    // A recurrence the resource no longer produces — the organiser deleted that
    // occurrence, or changed the rule. Refused rather than answered with the
    // nearest one: a silently substituted meeting is a worse answer than none
    // (T-03-39).
    //
    // `rediscoverable` FALSE. This is a local selection failure over bytes
    // already in hand, not a moved shard host, and marking it otherwise would
    // spend a discovery round trip and a retry on every lookup of a deleted
    // occurrence to arrive at the identical answer.
    if (read.found === null) throw new DavNotFoundError(false);

    const detail = detailFor(
      {
        key: {
          sortInstant: sortInstantOf(read.found.start),
          calendarUrl: ref.calendarUrl,
          objectUrl: ref.objectUrl,
          recurrenceId: read.found.recurrenceId,
        },
        calendarUrl: ref.calendarUrl,
        objectUrl: ref.objectUrl,
        occurrence: read.found,
      },
      resolved.cacheHit,
    );

    return {
      detail,
      etag,
      body,
      isRecurring: read.isRecurring,
      counts: read.counts,
      unsupportedTarget: read.structural ?? timezoneBlockerOf(detail),
      // No `timezoneBlockerOf` fallback, and its absence is the point: that
      // check asks whether this server could RE-ANCHOR a rewritten resource,
      // and a delete rewrites nothing.
      unsupportedDeleteTarget: read.deletable,
      isScheduling: read.scheduling,
      hasSeriesMaster: read.hasSeriesMaster,
      sequence: read.sequence,
    };
  });
}

/**
 * Read one occurrence AND the ETag a confirmation must bind to (CALW-02).
 *
 * ONE outbound request, and the count is the property rather than a side note.
 * It is `getEvent`'s own multi-get — which already ASKED for the ETag and threw
 * it away — reading both values out of the one multi-status.
 *
 * A resource that came back with a body and no ETag is refused, through the
 * same `DavNotFoundError(false)` the absent-body path uses. That is not
 * fastidiousness: the caller of this function is about to sign the ETag into a
 * capability to write, and a missing one would travel as `undefined` into a
 * header builder that DROPS falsy entries — producing an unconditional write
 * that the server answers 200 to.
 */
export async function getEventWithEtag(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
): Promise<EventWithEtag> {
  const read = await readEvent(env, principal, davFetch, ref);
  assertEtag(read.etag);

  return {
    detail: read.detail,
    etag: read.etag,
    body: read.body,
    isRecurring: read.isRecurring,
    counts: read.counts,
    unsupportedTarget: read.unsupportedTarget,
    unsupportedDeleteTarget: read.unsupportedDeleteTarget,
    isScheduling: read.isScheduling,
    hasSeriesMaster: read.hasSeriesMaster,
    sequence: read.sequence,
  };
}

/**
 * Refuse an ETag that would silently make a conditional write unconditional.
 *
 * `assertProvisioned`'s shape exactly — an assertion signature rather than a
 * boolean predicate, so it NARROWS at the call site and the alternative is not
 * a choice between a failing typecheck and a forbidden cast.
 *
 * **The concrete failure it guards, because a reader will otherwise assume the
 * type system already covers it.** tsdav's `updateObject` and `deleteObject`
 * build their headers through a helper that drops any entry whose value is
 * falsy, so an `undefined`, `""` or `null` ETag produces an UNCONDITIONAL
 * write — with no error, no warning, and a 200 from the server. CALW-05 fails
 * silently and the failure looks exactly like success. A comment saying "the
 * ETag is always present here" is precisely the claim `assertProvisioned` warns
 * against: a green typecheck is not evidence the check is redundant.
 *
 * `DavNotFoundError(false)`: the vocabulary is closed, a resource this server
 * declines to write is the same class of answer as one it declines to resolve,
 * and re-resolving the account's home URLs cannot make an absent ETag present.
 */
export function assertEtag(
  value: string | null | undefined,
): asserts value is string {
  if (value === undefined || value === null || value.length === 0) {
    throw new DavNotFoundError(false);
  }
}

/**
 * The `.ics` a commit writes back, built rather than patched.
 *
 * **Built, and that is a consequence of the request budget rather than a
 * preference.** A commit has exactly one outbound request — the write — so it
 * never sees the resource's current bytes and has nothing to patch INTO. The
 * body is therefore assembled from the confirmed change, which is why the
 * preview carries the whole end state rather than a delta, and why
 * `getEventWithEtag` refuses to confirm a resource carrying anything this
 * builder cannot reproduce.
 *
 * The UID comes from the object URL and is asserted rather than assumed: a
 * write under a UID this server guessed would be worse than a refusal, because
 * a UID is how every other client on the account recognises the same event.
 * That check ran once already at preview time; this is the second, at the last
 * moment before the bytes exist.
 *
 * `DavNotFoundError(false)` on a URL that names no UID, on `assertEtag`'s
 * reasoning: the vocabulary is closed, and re-resolving the account's home URLs
 * cannot make a URL name something it does not.
 *
 * Lives here rather than at the tool boundary because every byte of iCalendar
 * in this project goes through `./icalendar.ts`, and this module is the one
 * that calls it. It takes the BUILDER's own input type rather than a
 * confirmation's change, so the DAV tree stays ignorant of confirmations.
 *
 * ## The participants are forced to null, and that is a boundary rather than a
 * default
 *
 * A REWRITE may not carry a person, in either direction, and both directions
 * are real:
 *
 *   - **Outward.** An attendee list this server READ — off an event description,
 *     off the stored resource, off anywhere — must not survive into a resource
 *     it WROTE. That is PITFALLS #12 and Conventions §2 point 5: an attendee
 *     list the user supplies is a request, and one derived from content this
 *     server read is the autonomous-schedule shape the rule forbids. The
 *     override below makes it unspeakable rather than merely unwritten: there
 *     is no value a caller can put in `input.participants` that reaches the
 *     bytes.
 *   - **Inward.** iCloud REWRITES a scheduling resource on the way in (probe
 *     P-1 (d)): it replaces the organiser's `mailto:` with an opaque
 *     per-account principal href and stamps `SCHEDULE-STATUS` onto every
 *     attendee. A rebuild that emitted a plain `mailto:` organiser would
 *     therefore DESTROY the identity iCloud assigned. That is not reachable
 *     today, because `structuralBlockerOf` refuses any resource carrying
 *     `ATTENDEE` or `ORGANIZER` before a confirmation is ever minted, and
 *     05-RESEARCH.md § F-1 records that refusal as MEASURED necessary rather
 *     than merely cautious — *"Do not relax that refusal."* This override is
 *     the second layer under it, not a substitute for it.
 *
 * ## The revision is taken from the RESOURCE, and that override is the second
 * hazard F-1 named
 *
 * This function used to emit whatever `buildVEvent` minted, which is zero —
 * correct for a new event and wrong for a replacement of an old one. A
 * `SEQUENCE` that goes BACKWARDS makes every other calendar client treat the
 * update as stale and ignore it, and it raises nothing anywhere: not here, not
 * at iCloud, not in the receiving client. So the value is read off the FETCHED
 * resource — the same multi-get `getEventWithEtag` already made, so it costs no
 * extra request — carried to this leg inside the SIGNED confirmation, and
 * advanced by `nextSequence`.
 *
 * `carriedSequence` is a PARAMETER rather than a field on `input` for the same
 * reason `participants` is overridden below: there must be no value a caller
 * can put in the builder's own input that reaches the wire. Whatever
 * `input.sequence` holds is discarded here.
 */
export function updateEventBody(
  ref: EventRef,
  input: BuildEventInput,
  carriedSequence: number | null,
): string {
  const uid = uidFromObjectUrl(ref.objectUrl);
  if (uid === null) throw new DavNotFoundError(false);

  // Both overridden rather than trusted. See the docstring: a rewrite may not
  // carry a person, and it may not carry a revision the caller chose — so
  // neither field is the caller's to set on this path.
  const vevent = buildVEvent({
    ...input,
    participants: null,
    sequence: nextSequence(carriedSequence),
  });
  // `buildVEvent` mints a fresh UID, which is what makes a CREATE
  // non-idempotent and is exactly wrong for a replacement. Updated rather than
  // added, so there is one `UID` property and it is the resource's own.
  vevent.updatePropertyWithValue("uid", uid);

  return serializeCalendarResource(vevent, input.allDay ? null : input.tzid);
}

/**
 * The `.ics` an OCCURRENCE-scoped commit writes back, PATCHED rather than built.
 *
 * ## Patched, and that is the difference this whole plan turns on
 *
 * `updateEventBody` above assembles a resource from the confirmed change and
 * therefore drops everything the change does not mention — which is correct for
 * a one-off event and catastrophic for a series, where "everything the change
 * does not mention" is the rule and every other occurrence's override. So this
 * one starts from the resource's own bytes, changes exactly one component, and
 * leaves the rest where they were. The master is read and never written, which
 * `test/dav-icalendar.test.ts` asserts by serialising it before and after.
 *
 * ## Where the bytes come from, and why that is a SECOND request
 *
 * From `EventWithEtag.body` — the same contained, single-request read the
 * preview leg makes, made again on the commit leg. The plan sketched this as
 * "no second read", over the resource `getEventWithEtag` already returned; that
 * is not reachable, and the reason is worth stating rather than leaving to be
 * rediscovered. The preview and the commit are two separate tool calls with a
 * human decision between them, so nothing survives from one to the other except
 * what the signed confirmation carries — and what a patch needs is the whole
 * resource, which cannot be sealed into a token. A commit that skipped the read
 * would have to rebuild, and a rebuild is the thing this function exists not to
 * do. It is the same read-then-patch shape 05-09 named when it declined to lift
 * the `scheduling` refusal, arrived at from the other direction.
 *
 * The cost is one serial extra multi-get on a path already gated behind a human
 * confirmation, which is `observeDelivery`'s precedent exactly. It is never a
 * fan-out: the two requests are awaited in order, and `updateEvent` itself
 * still issues exactly one.
 *
 * ## The staleness guarantee is unchanged
 *
 * The `If-Match` header still carries the ETag the PREVIEW observed, sealed in
 * the confirmation — never the one this second read returned. Using the fresh
 * one would silently convert "nothing has changed since you looked" into
 * "nothing has changed since a moment ago", which is the guarantee CALW-05
 * exists to provide. The caller additionally compares the two before building
 * anything, so a resource that moved under the confirmation costs zero writes
 * rather than one refused one.
 *
 * ## Null, rather than a throw
 *
 * `null` means the series no longer produces that occurrence. The caller maps
 * it to not-found, which is the same answer the read leg gives for the same
 * condition — see `applyOccurrenceOverride`, which owns the argument.
 *
 * ## `range`, which is how far forward the patch reaches
 *
 * `"this-and-future"` is the whole of plan 05-12's write path, and it is the
 * SAME operation as an occurrence-scoped patch with one parameter added: one
 * resource, one conditional request, the master byte-identical, the rule
 * untouched. Probe P-8 half B is why it needs nothing more than that, and
 * `applyOccurrenceOverride`'s docstring quotes the measurement in full — along
 * with the two-write series SPLIT that was NOT built and the reason it was not.
 */
export function updateOccurrenceBody(
  ref: EventRef,
  icsText: string,
  input: BuildEventInput,
  range: OverrideRange = "this-only",
): string | null {
  // A slot with no recurrence identifier names nothing in a series. Refused
  // here rather than by handing the builder a null it would have to interpret.
  if (ref.recurrenceId === null) return null;

  return withParsedResource(icsText, (resource) => {
    const components = applyOccurrenceOverride(
      resource,
      ref.recurrenceId!,
      {
        summary: input.summary,
        startLocal: input.startLocal,
        endLocal: input.endLocal,
        tzid: input.allDay ? null : input.tzid,
        allDay: input.allDay,
        location: input.location,
        description: input.description,
      },
      range,
    );
    if (components === null) return null;

    return serializeOccurrenceResource(
      resource,
      components,
      input.allDay ? null : input.tzid,
    );
  });
}

/**
 * The `.ics` a scopeless commit writes back for an INVITED event, PATCHED.
 *
 * ## The third writer, and why there had to be one
 *
 * `updateEventBody` rebuilds and `updateOccurrenceBody` patches one date of a
 * series. Neither can write a one-off event that carries people: the rebuild
 * destroys what iCloud put on the resource, and the occurrence patch needs a
 * recurrence identifier a non-repeating event does not have. So the whole update
 * half of CALW-07 shipped REFUSED from 05-06 until this existed
 * (`.planning/WINDOWS.md` entry 61).
 *
 * What survives, byte for byte, is everything the change does not name — and on
 * this path that list is the point rather than a nicety. `applyEventChange`
 * enumerates it: the opaque principal-href `ORGANIZER` iCloud substituted (probe
 * P-1 (d)), every `SCHEDULE-STATUS` parameter, and every `PARTSTAT`, including
 * an `ACCEPTED` a rebuild would overwrite with `NEEDS-ACTION` and thereby ERASE.
 *
 * ## Where the bytes come from, and why that is a SECOND request
 *
 * `updateOccurrenceBody`'s answer exactly, and it applies here unchanged: a
 * patch needs the whole resource, the preview and the commit are two tool calls
 * with a human decision between them, and nothing crosses that gap but the
 * signed confirmation — which cannot carry a resource. Read that docstring
 * rather than a second copy of the argument here.
 *
 * The `If-Match` still carries the ETag the PREVIEW observed, and the caller
 * compares the re-read's ETag against it before building anything, so a resource
 * that moved under the confirmation costs zero writes.
 *
 * ## Null, rather than a throw
 *
 * `null` means these bytes are not a single non-repeating event — a series, or a
 * lone override belonging to a master stored elsewhere. The caller maps it to
 * not-found, which is `updateOccurrenceBody`'s own rule for the same shape of
 * answer.
 *
 * No `ref` parameter, and the absence is the difference from the rebuild. A
 * rebuild must DERIVE the UID from the object URL and write it back, which is
 * what `unnamed-resource` refuses when the URL names something else; a patch
 * keeps the resource's own `UID` property and addresses the resource by its own
 * URL, so there is nothing for it to derive and nothing to get wrong.
 */
export function patchEventBody(
  icsText: string,
  input: BuildEventInput,
): string | null {
  return withParsedResource(icsText, (resource) => {
    const components = applyEventChange(resource, {
      summary: input.summary,
      startLocal: input.startLocal,
      endLocal: input.endLocal,
      tzid: input.allDay ? null : input.tzid,
      allDay: input.allDay,
      location: input.location,
      description: input.description,
    });
    if (components === null) return null;

    return serializeOccurrenceResource(
      resource,
      components,
      input.allDay ? null : input.tzid,
    );
  });
}

/**
 * What a SCOPED delete would do to the resource: narrow it, or remove it.
 *
 * **One shape carrying both answers, because the two must never be predicted
 * separately from being performed.** The preview runs this over the body it
 * already fetched and publishes `removesResource`; the commit runs the same
 * function over its own re-read and acts on `body`. Two code paths that predict
 * and perform are two paths that can disagree — one path run twice cannot.
 */
export interface ScopedDeletePlan {
  /**
   * The bytes to write back, or null when the resource must be removed instead.
   *
   * Null and `removesResource` are the same fact said twice, deliberately: the
   * boolean is what a PREVIEW publishes and the bytes are what a COMMIT needs,
   * and a caller reading either one is reading the same decision.
   */
  body: string | null;
  /** True when nothing would remain, so the write is a removal rather than one. */
  removesResource: boolean;
  /**
   * The occurrence starts this narrowing takes away, as local wall clocks.
   *
   * Differenced off the narrowing's own output rather than predicted beside it
   * — see `removedStartsOf`, which owns that argument — and capped, because a
   * truncation of an endless rule removes more dates than any response should
   * carry. The authoritative COUNT is the walk the preview publishes in its
   * trusted half; this is the list of dates that rides beside it.
   *
   * Empty when the resource is removed entire: the whole event is going, and
   * enumerating its dates would describe a narrowing that is not happening.
   */
  removedStarts: string[];
}

/**
 * Work out what a scoped delete would do, without doing any of it.
 *
 * **Pure, socket-free, and the single source of truth for both legs.** It is
 * the whole of this plan's answer to "the preview said one thing and the write
 * did another": that divergence is unreachable rather than unlikely, because
 * there is only one implementation and both legs call it.
 *
 * A narrowing is a `PUT` of the resource's own bytes with one date or one tail
 * removed — never a `DELETE`. The only case that removes the resource is the
 * one where nothing would remain, and the preview says so before the write goes
 * out.
 *
 * `null` means the operation does not apply to this target: a slot with no
 * recurrence identifier names nothing in a series, a scope this plan builds no
 * narrowing for, or a resource carrying no rule to narrow. The caller maps it
 * to not-found, which is the answer the read leg gives for the same condition.
 *
 * The zone argument to the serialiser is null on purpose. A narrowing
 * introduces no time this server chose, so there is no new zone to define — and
 * the resource's own `VTIMEZONE`s survive because the wrapper is CLONED rather
 * than rebuilt, which is the same property `updateOccurrenceBody` rests on.
 */
export function planScopedDelete(
  icsText: string,
  recurrenceId: string | null,
  scope: WriteScope,
): ScopedDeletePlan | null {
  if (recurrenceId === null) return null;

  return withParsedResource(icsText, (resource) => {
    const narrowing =
      scope === "occurrence"
        ? // A resource with no rule is narrowed by DROPPING the component, not
          // by excluding a date from a rule that is not there — an exclusion
          // beside no rule is a legal property that changes nothing, which is
          // the silent shape this tree works hardest to avoid. See
          // `dropOverride`, which owns the argument.
          resource.master === null
          ? dropOverride(resource, recurrenceId)
          : applyExdate(resource, recurrenceId)
        : scope === "this-and-future"
          ? truncateSeries(resource, recurrenceId)
          : null;

    if (narrowing === null || narrowing.kind === "not-a-series") return null;
    if (narrowing.kind === "no-occurrences") {
      return { body: null, removesResource: true, removedStarts: [] };
    }

    // The narrowed master, found by the one property that distinguishes it. The
    // dates are differenced against it rather than worked out again from the
    // scope, so the list and the bytes cannot describe two different removals.
    const narrowedMaster =
      narrowing.components.find(
        (component) => !component.hasProperty("recurrence-id"),
      ) ?? null;

    return {
      body: serializeOccurrenceResource(resource, narrowing.components, null),
      removesResource: false,
      // EMPTY for a masterless resource, and that is the right answer rather
      // than a gap: there is no rule to expand, so there is nothing to
      // difference — and the one date that went away is the occurrence the
      // preview is already describing field by field. Repeating it here would
      // be a second copy of one claim, which is the argument `removedDates`
      // makes for a one-off event.
      removedStarts:
        narrowedMaster === null || resource.master === null
          ? []
          : removedStartsOf(resource.master, narrowedMaster),
    };
  });
}

/**
 * The later dates a forward-reaching change will NOT move, over one body.
 *
 * `planScopedDelete`'s shape exactly — pure, socket-free, and run over the
 * bytes a read already returned — and here for the same reason: the preview
 * needs the answer and must not pay a request for it.
 *
 * The count it carries is SUBTRACTED from the number the preview publishes, so
 * a series with a hand-edited later date promises what it will actually move
 * rather than one more than that. See `pinnedOccurrencesAfter`, which owns the
 * argument for why those dates keep their own arrangement.
 */
export function pinnedOccurrencesFor(
  icsText: string,
  recurrenceId: string | null,
): PinnedOccurrences {
  if (recurrenceId === null) return { count: 0, starts: [] };
  return withParsedResource(icsText, (resource) =>
    pinnedOccurrencesAfter(resource, recurrenceId),
  );
}

/** What a conditional write reports about the resource it just replaced. */
export interface UpdatedEvent {
  /** The opaque id the event is still addressable by. Minted here, so trusted. */
  id: string;
  /** The opaque calendar id it lives in, for join-by-identity. Trusted. */
  calendarId: string;
  /**
   * Whether the change reached the account.
   *
   * A FIELD rather than the difference between a return and a throw, on
   * `CreatedEvent.created`'s precedent — so a later plan that gains a
   * non-throwing refusal on this path has somewhere to put it, and so the tool
   * layer reads one shape whichever plan it came from. Today the only way out
   * of this function other than `true` is a throw.
   */
  applied: boolean;
}

/**
 * Replace one event's resource, conditionally (CALW-02, CALW-05).
 *
 * ## The ETag is asserted FIRST, before anything else at all
 *
 * Before discovery, before containment, before the request. The assertion is
 * what makes "a write without a precondition is unrepresentable" true rather
 * than merely intended, and putting it after any awaited call would leave a
 * path on which an unconditional write goes out and the caller is told it
 * succeeded. The parameter is typed to ADMIT the falsy values precisely so the
 * assertion has something to narrow — a `string` parameter would let a reader
 * conclude the check was redundant.
 *
 * ## Containment, and the single attempt
 *
 * Both in `withContainedTarget`, which this function and `deleteEvent` share.
 * That is where the argument for checking BOTH urls inside the callback lives,
 * and where `allowRediscovery = false` is fixed so that no caller can re-open
 * it — including the reason a retried `PUT` reports `stale_resource` for a
 * write that actually landed. Read it there rather than here; two copies of a
 * security argument is how one of them stops being true.
 */
/**
 * Resolve the account, refuse a target that is not this account's, then write.
 *
 * **The containment lives HERE and in one place, for both writers that address
 * an existing resource.** Two hand-written copies of a security check is how one
 * of them ends up with a single `assertUnderHome` — and the URL that would go
 * unchecked is the one the request is actually aimed at, since the object URL
 * travels separately from its collection and each independently names what the
 * server is asked for. `./transport.ts` attaches the Apple ID and the
 * app-specific password to whatever URL it is handed (T-05-06, 03-REVIEW.md
 * CR-01), so an unchecked token-borne URL sends the credential wherever the
 * token said.
 *
 * Inside the callback rather than above it, because `resolved.homeUrl` does not
 * exist until discovery has run.
 *
 * **`allowRediscovery` is false and is not a parameter**, so no caller can
 * re-open the question. `withRediscovery` re-runs its operation once on a
 * rediscoverable failure when the account came from cache; for a read that is
 * right, and for a write it means the request goes out TWICE. Both writers pay
 * a different half of the same cost, and both halves are the same wrong answer
 * arriving through different doors:
 *
 *   - The update's second `PUT` fails its `If-Match` because the first landed,
 *     and it is the RETRY's failure the caller sees — a write that succeeded,
 *     reported as `stale_resource`.
 *   - The delete's second `DELETE` finds nothing and reports `not_found` for an
 *     event that was successfully deleted.
 *
 * The preview leg immediately before either one resolved the same account
 * successfully, so a genuinely-moved host is not the likely cause of a failure
 * here. This is the whole of Pitfall 8's mitigation.
 *
 * `test/dav-home-containment.test.ts` reads this function by name: its checked
 * call sites declare it as the helper the assertion lives in, and assert
 * lexically that both `assertUnderHome` calls precede the delegation below and
 * that each caller's own request follows its call to this function.
 */
async function withContainedTarget<T>(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
  write: (resolved: ResolvedDavAccount) => Promise<T>,
): Promise<T> {
  return withRediscovery(
    env,
    principal,
    davFetch,
    "caldav",
    async (resolved) => {
      assertUnderHome(ref.calendarUrl, resolved.homeUrl);
      assertUnderHome(ref.objectUrl, resolved.homeUrl);
      return write(resolved);
    },
    false,
  );
}

export async function updateEvent(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
  icsBody: string,
  etag: string | null | undefined,
): Promise<UpdatedEvent> {
  // FIRST. See the docstring — everything below this line can reach the wire.
  assertEtag(etag);

  return withContainedTarget(env, principal, davFetch, ref, async () => {
    await updateCalendarObject({
      calendarObject: { url: ref.objectUrl, data: icsBody, etag },
      // Never a credential from here. `./transport.ts` attaches it per call
      // and is the only place that may. The library supplies the content type
      // and the `If-Match` that makes this write conditional.
      headers: {},
      fetch: davFetch,
    });

    return {
      id: encodeEventId({
        calendarUrl: ref.calendarUrl,
        objectUrl: ref.objectUrl,
        recurrenceId: ref.recurrenceId,
      }),
      calendarId: encodeCalendarId({ collectionUrl: ref.calendarUrl }),
      applied: true,
    };
  });
}

/** What a conditional delete reports about the resource it just removed. */
export interface DeletedEvent {
  /**
   * The opaque id the event WAS addressable by.
   *
   * Returned so the caller can join this outcome to the preview it approved by
   * identity rather than by position — the same reason every other write
   * outcome carries one. It addresses nothing after this call, by construction,
   * which is what `applied` says.
   */
  id: string;
  /** The opaque calendar id it lived in, for join-by-identity. Trusted. */
  calendarId: string;
  /**
   * Whether the removal reached the account.
   *
   * A FIELD rather than the difference between a return and a throw, on
   * `UpdatedEvent.applied`'s precedent. Today the only way out of this function
   * other than `true` is a throw — and the two throws that matter are the ones
   * this field must never be confused with: a 412 says the resource changed,
   * and a 404 says it was already gone. Neither is a delete this server
   * performed, and neither returns.
   */
  applied: boolean;
}

/**
 * Remove one event's resource, conditionally (CALW-03, CALW-05).
 *
 * `updateEvent` with the verb changed and the body dropped, and every argument
 * that function's docstring makes applies here one degree more sharply.
 *
 * ## The ETag is asserted FIRST, before anything else at all
 *
 * Before discovery, before containment, before the request. **This is not
 * defensive duplication of a check the type system already does.** tsdav's
 * `deleteObject` builds its headers through the same falsy-dropping helper
 * `updateObject` does, so an `undefined`, `""` or `null` ETag produces an
 * UNCONDITIONAL delete — with no error, no warning, and a 204 from the server.
 * On the update path that is a lost edit. Here it is a lost event, and the
 * failure looks exactly like success.
 *
 * The parameter is typed to ADMIT the falsy values precisely so the assertion
 * has something to narrow; a `string` parameter would let a reader conclude the
 * check was redundant.
 *
 * ## What it costs
 *
 * ONE request, and the count is the property rather than a side note. See
 * `withContainedTarget` for why no retry is permitted and for what the delete's
 * own version of that failure looks like.
 *
 * ## The form, and it is a MEASUREMENT rather than a reading of the RFC
 *
 * One request, plain, with no cancellation written first. That is probe P-4's
 * recorded answer and not an inference: RFC 6638 describes a server sending a
 * cancellation on delete, implementations differ, and the question cannot be
 * decided from documentation. It was decided by running both halves against the
 * live account on 2026-08-22. Verbatim, from `05-UAT.md` § P-4:
 *
 * > **A plain `DELETE` sends the cancellation. The `STATUS:CANCELLED` pre-step
 * > is NOT required, and adding it does NOT double-send.**
 *
 * | Step | HTTP | Cancellation in invitee's mailbox |
 * |---|---|---|
 * | A — plain `DELETE` of a live invited event | 204 | yes |
 * | B1 — `PUT` with `STATUS:CANCELLED` + `SEQUENCE:1` | 204 | yes |
 * | B2 — `DELETE` of the already-cancelled resource | 204 | no |
 *
 * Both routes send exactly ONE cancellation, so the two-step route buys nothing
 * and costs a second write. The same single form is used whether or not the
 * resource carries anybody: there is nobody to tell on an uninvited event, and
 * a cancelled-but-present resource left on the user's own calendar is a worse
 * outcome than a deleted one.
 *
 * ## What it does NOT do, and what the B2 row means for that
 *
 * It sends no cancellation itself and asks iCloud for nothing: the outbound
 * byte stream is one `DELETE` to the account's own CalDAV shard and nothing
 * else. iCloud does the sending, from state this server cannot see — and the B2
 * row is the proof that it is state rather than a rule. Deleting an
 * already-cancelled resource sent NOTHING, so iCloud tracks what an attendee
 * has already been told and suppresses a redundant notice.
 *
 * Two consequences, and both are load-bearing one layer up. **A `DELETE` is not
 * unconditionally a send**, so any claim of the form "this delete will notify N
 * people" is a prediction rather than a fact — which is why the preview reports
 * in the OVER-WARNING direction and must not later be "corrected" into a
 * precise count it cannot know. And **a retried `DELETE` will not re-notify**,
 * because the already-cancelled state makes the second attempt silent.
 */
export async function deleteEvent(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: EventRef,
  etag: string | null | undefined,
): Promise<DeletedEvent> {
  // FIRST. See the docstring — everything below this line can reach the wire.
  assertEtag(etag);

  return withContainedTarget(env, principal, davFetch, ref, async () => {
    await deleteCalendarObject({
      calendarObject: { url: ref.objectUrl, etag },
      // Never a credential from here. `./transport.ts` attaches it per call
      // and is the only place that may. The library supplies the `If-Match`
      // that makes this removal conditional.
      headers: {},
      fetch: davFetch,
    });

    return {
      id: encodeEventId({
        calendarUrl: ref.calendarUrl,
        objectUrl: ref.objectUrl,
        recurrenceId: ref.recurrenceId,
      }),
      calendarId: encodeCalendarId({ collectionUrl: ref.calendarUrl }),
      applied: true,
    };
  });
}

// ---------------------------------------------------------------------------
// CALW-08 — what the server said about telling someone
// ---------------------------------------------------------------------------

/**
 * What this server is willing to SAY about an invitation, as a closed set.
 *
 * **A vocabulary rather than a passthrough, and that is the whole design.** The
 * `SCHEDULE-STATUS` parameter is a string somebody else wrote; publishing it in
 * a trusted block is the 03-09 defect repeating. So the value is MATCHED
 * against the table below and the TABLE'S OWN CONSTANT is published. An
 * unmatched value lands on `unreported` and the raw string is never published
 * anywhere outside the fence.
 *
 * `unreported` covers three genuinely different situations and deliberately
 * does not tell them apart: the server wrote nothing, the server wrote
 * something this table does not recognise, or this server could not read the
 * resource back at all. All three are the same claim to a user — *nobody told
 * us anything* — and splitting them would invite reading a diagnosis into a
 * field whose whole point is the absence of one.
 */
export type DeliveryStatus = "unreported" | "pending" | "sent" | "delivered";

/**
 * The status codes this server recognises, and nothing else.
 *
 * Three entries, from RFC 6638 §3.2.9's scheduling status codes. `1.1` is the
 * one that matters in practice: probe P-1 measured iCloud writing exactly that
 * back after an attendee-carrying write, and §3.2.9 defines it as **sent**.
 *
 * **`1.2` is on the table and this server never synthesises it.** Leaving it
 * off would mean under-reporting a real server claim if iCloud ever made one —
 * an unmatched `1.2` would fall to `unreported`, which is a weaker statement
 * than the server actually made. The rule this project is holding is *claim no
 * more than the source does*, in both directions. Today the source says sent.
 *
 * **A `Map` rather than an object literal, and that is a correctness fix rather
 * than a taste one (05-REVIEW.md WR-02).** An object literal inherits
 * `Object.prototype`, so `codes[value] ?? "unreported"` did not close the
 * vocabulary at all: `??` fires only on `undefined`/`null`, and an inherited
 * member is neither. A `SCHEDULE-STATUS` of `__proto__`, `constructor` or
 * `toString` therefore returned an object or a function, which is not
 * `=== "unreported"` — so `deliveryReportOf` left `confirmed` at TRUE and this
 * server reported a delivery claim the server never made. The lookup key is read
 * verbatim out of bytes iCloud wrote (`firstParameter(property,
 * "schedule-status")`), which is the whole reason this table matches rather than
 * quotes. A `Map` has no prototype chain on `get`, so the closure is structural
 * rather than a check somebody has to remember.
 */
const DELIVERY_STATUS_CODES: ReadonlyMap<string, DeliveryStatus> = new Map([
  ["1.0", "pending"],
  ["1.1", "sent"],
  ["1.2", "delivered"],
] as const);

/** Weakest first. A report over several people takes the FLOOR, not the best. */
const DELIVERY_STATUS_ORDER: readonly DeliveryStatus[] = [
  "unreported",
  "pending",
  "sent",
  "delivered",
];

/** What this server can say about one write, after reading the resource back. */
export interface DeliveryReport {
  /** The matched constant. Never a string the server wrote. */
  status: DeliveryStatus;
  /**
   * Whether the server reported ANYTHING this table recognises, for EVERYONE.
   *
   * A separate boolean from the status rather than derivable from it, because
   * the two answer different questions and a caller must be able to tell "the
   * server said sent" from "the server said nothing and we are reporting the
   * request we made". Collapsing them is how a response ends up implying
   * delivery it never observed.
   */
  confirmed: boolean;
}

/** The report a write can make when it observed nothing at all. */
export const UNOBSERVED_DELIVERY: DeliveryReport = Object.freeze({
  status: "unreported",
  confirmed: false,
});

/**
 * One code, matched against the table. Never the string that was read.
 *
 * The value may carry a description after the code and may be a comma-separated
 * list, so the leading code is taken before matching. Anything unmatched — an
 * unknown code, a description with no code, an empty parameter — is
 * `unreported`, which is this server declining to repeat a stranger's string
 * rather than declining to answer.
 *
 * The lookup goes through the table's `get` rather than an index, so a code
 * naming an inherited member of the object prototype cannot escape the four
 * values — see `DELIVERY_STATUS_CODES`, which carries that argument.
 */
function deliveryStatusOf(value: string | null): DeliveryStatus {
  if (value === null) return "unreported";
  const code = value.split(";")[0].split(",")[0].trim();
  return DELIVERY_STATUS_CODES.get(code) ?? "unreported";
}

/**
 * What the server said about telling this event's people, folded to one answer.
 *
 * **The FLOOR across everyone, not the best case.** A response carries one
 * status and several recipients; reporting the strongest would let one
 * confirmed recipient speak for a second the server said nothing about. The
 * weakest true claim is the one this project reports, which is the same
 * instinct behind reporting intent rather than outcome one layer up.
 *
 * `confirmed` requires a recognised status for EVERY participant AND at least
 * one participant. An empty list confirms nothing: there is nobody the server
 * could have reported on, so there is nothing it confirmed.
 *
 * Pure, and takes participants rather than a request. The re-read is the
 * caller's — `getEventWithEtag`, which is one multi-get and is already the read
 * every other leg of this gate uses — so this function adds no entry point that
 * reaches the network.
 */
export function deliveryReportOf(
  participants: readonly EventParticipant[],
): DeliveryReport {
  if (participants.length === 0) return UNOBSERVED_DELIVERY;

  let floor: DeliveryStatus = "delivered";
  let confirmed = true;
  for (const participant of participants) {
    const status = deliveryStatusOf(participant.scheduleStatus);
    if (status === "unreported") confirmed = false;
    if (
      DELIVERY_STATUS_ORDER.indexOf(status) <
      DELIVERY_STATUS_ORDER.indexOf(floor)
    ) {
      floor = status;
    }
  }

  return { status: floor, confirmed };
}

/**
 * The scheme every calendar user address this server will send as must carry.
 *
 * Read as a prefix rather than parsed as a URI, because the only question being
 * asked is whether the value is an address a person receives mail at. Probe
 * P-1's answer records the alternatives this account actually advertises — a
 * principal path and a `urn:uuid:` form — and both are legitimate calendar user
 * addresses in the protocol's own terms while being useless as a `mailto:`.
 */
const MAILTO_SCHEME = "mailto:";

/**
 * The account's OWN address, chosen from the set its principal advertises.
 *
 * ## Why this exists at all
 *
 * RFC 6638 requires an `ORGANIZER` to match one of the calendar user addresses
 * of the collection owner. A resource whose organiser does not match is not an
 * *organizer scheduling object resource*, so the server will not send on its
 * behalf — and it declines SILENTLY: the `PUT` still returns 2xx, the event
 * still appears on the calendar, and no invitation is ever sent. A meeting
 * nobody was told about, reported as a success, is the worst outcome this path
 * has, and it is the one this function exists to make unreachable.
 *
 * ## The selection rule, and what it was written against
 *
 * Prefer the first `mailto:` entry whose address equals the account's login;
 * otherwise the first `mailto:` entry; otherwise REFUSE. Stated as a rule rather
 * than "take element zero", because probe P-1 measured what this account
 * actually advertises and the set is not a tidy list of addresses. Verbatim,
 * from `05-UAT.md` § P-1 (c):
 *
 * ```
 * mailto:user@mac.com      (preferred="1")
 * mailto:user@icloud.com
 * mailto:user@me.com
 * mailto:user@example.com
 * ```
 *
 * plus a principal path, a `urn:uuid:` form, and one opaque per-account
 * principal href. **Four mail addresses, not one** — so any later code deciding
 * "is this attendee the account owner" must match all four, or it will treat
 * the user as a stranger on their own meetings.
 *
 * What P-1 answered for THIS account and for no other: whether an alias works,
 * and whether the principal form is accepted. Neither is established, which is
 * why the fallback is the first `mailto:` rather than the principal href, and
 * why a set with no `mailto:` form at all is refused rather than guessed at.
 *
 * ## Why the refusal, rather than a fallback to the login
 *
 * Falling back to the login address when the set advertises no usable entry would
 * produce a resource that looks correct, writes successfully and returns 2xx —
 * and that iCloud silently declines to send from, for exactly the reason above.
 * A refusal costs the user a puzzled error; the fallback costs them a meeting
 * nobody was told about. `DavNotFoundError(false)`: the vocabulary is closed, an
 * address this server cannot find is the same class of answer as a resource it
 * cannot find, and re-resolving the account's home URLs cannot conjure a
 * `mailto:` entry the principal does not advertise.
 *
 * ## What it does NOT take
 *
 * **No caller input of any kind.** That is 04-03's decision one protocol over —
 * *the draft From identity is fixed and never a parameter, because a
 * caller-supplied From is a caller-supplied identity* — and the consequence here
 * is worse than a mislabelled draft: an invitation sent under somebody else's
 * name, to a real person, which cannot be unsent.
 *
 * ## What it costs, and why it is paid twice
 *
 * ONE `PROPFIND` at the principal, on a warm discovery cache. It is called only
 * on a path that carries at least one attendee — a create that reaches nobody
 * pays nothing — and it is resolved on BOTH legs of the gate rather than cached
 * or carried in the confirmation. Caching it beside discovery would change the
 * shape of an already-shipped cache entry, which is a migration on live data to
 * save one request on an already-gated path; putting it in the confirmation
 * payload would bind the identity into the signature, which is genuinely
 * attractive, but grows a payload whose size is deliberately independent of its
 * content. The cost is a serial +1 on each leg, not a fan-out.
 */
export async function resolveOrganizerAddress(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<string> {
  return withRediscovery(env, principal, davFetch, "caldav", async (resolved) => {
    let advertised: string[];
    try {
      advertised = await fetchCalendarUserAddresses({
        account: davAccountFor("caldav", resolved),
        // Never a credential from here. `./transport.ts` attaches it per call
        // and is the only place that may.
        headers: {},
        fetch: davFetch,
      });
    } catch (err) {
      // The same wrapper `discoverAccount` puts around its own chain, for the
      // same reason: tsdav throws a BARE `Error` when a perfectly well-formed
      // 207 simply carries no address-set href, and an untyped error falls
      // through `davToErrorCategory` to a connection diagnosis — telling the
      // user their network failed about a server that answered promptly. A
      // `Dav*` error passes through UNCHANGED, because it was classified at the
      // fetch boundary by status number, which is strictly better information
      // than anything recoverable here.
      if (
        err instanceof DavAuthError ||
        err instanceof DavThrottleError ||
        err instanceof DavNotFoundError ||
        err instanceof DavConnectError
      ) {
        throw err;
      }
      // Nothing is read from the caught value. tsdav's messages embed the
      // resolved principal URL verbatim, which carries the account DSID.
      throw new DavNotFoundError(false);
    }

    const addresses = advertised
      .filter((one) => one.toLowerCase().startsWith(MAILTO_SCHEME))
      .map((one) => one.slice(MAILTO_SCHEME.length))
      .filter((one) => one.length > 0);

    // The login FIRST, by a fold rather than by identity: an address set is
    // returned by a server and its case is not the user's to control.
    //
    // The login is the signed-in principal's Apple ID (Phase 9, D-13). It is
    // the same identity the DAV fetch logs in as and the cache is keyed by. It
    // is always a string: a principal cannot be built without one, so the old
    // branch for an unset login is gone.
    // `fold` here lowercases and nothing else -- no trim, no ASCII gate, unlike
    // the one folding function the door and the login share. That is SAFE ONLY
    // BECAUSE of something invisible at this line: a principal cannot exist
    // carrying an untrimmed or non-ASCII address, because its constructor
    // refuses one (D-18). This match is leaning on that refusal. If the
    // constructor is ever widened to accept more, this comparison starts
    // silently selecting a different address rather than failing, so widening
    // it is a decision that has to come back here.
    //
    // Nothing folded here reaches a key, a token or a store, which is why this
    // is a second folding of the same field without being an ISO-05 breach.
    const folded = fold(principal.appleId);
    const own = addresses.find((one) => fold(one) === folded);
    if (own !== undefined) return own;

    // Then the first advertised address, and a refusal if there is none. Never
    // the login itself: an address the principal does not advertise is one
    // iCloud will not send for, and it fails silently when it declines.
    const first = addresses[0];
    if (first === undefined) throw new DavNotFoundError(false);
    return first;
  });
}

/** The resource name a UID takes inside a collection, percent-encoded. */
function objectNameFor(uid: string): string {
  return `${encodeURIComponent(uid)}.ics`;
}

/**
 * Where a create WOULD write, decided before anything is sent (CALW-06).
 *
 * **The gated create needs a target before it has written anything**, because
 * the confirmation binds the resource the preview described: `ConfirmPayload.o`
 * says the commit reads its target from there, and a create whose `o` was a
 * collection URL rather than an object URL would quietly make that docstring
 * false for one of the three kinds. So the UID is minted HERE, at preview time,
 * and the commit derives it back out of the signed URL through
 * `uidFromObjectUrl` rather than minting a second one.
 *
 * That buys a second, independent replay defence for free. A commit replayed
 * after the KV reservation has propagated away still carries the ORIGINAL
 * object URL, so its `PUT` meets `If-None-Match: *` against a resource that now
 * exists and is refused by the server — which is the layer `src/confirm.ts`'s
 * header says `If-Match` provides for the other two kinds, arriving here in the
 * only form a create can have one.
 *
 * **It reaches no network and asserts no containment**, and both are correct:
 * nothing is requested, so there is nothing to contain. `createEvent` runs the
 * containment on both URLs at the moment the write actually happens, which is
 * the only moment at which `resolved.homeUrl` exists.
 *
 * Minting here is also what keeps a create NON-IDEMPOTENT: two previews of
 * byte-identical input plan two different resources, and confirming both leaves
 * two events behind. That is the property `buildVEvent` already had, moved one
 * step earlier so the preview can name what it is about to make.
 */
export function planCreateTarget(calendarId: string): EventRef {
  const ref = decodeCalendarId(calendarId);
  const uid = `${crypto.randomUUID()}@icloud-mcp`;

  return {
    calendarUrl: ref.collectionUrl,
    objectUrl: new URL(objectNameFor(uid), ref.collectionUrl).href,
    recurrenceId: null,
  };
}

/**
 * What one `calendar_create_event` call supplies (CALW-01).
 *
 * The calendar is named by its OPAQUE id rather than by a URL, exactly as every
 * read tool names one. That is not symmetry for its own sake: a collection URL
 * taken straight from a caller is a request target, and `./transport.ts`
 * attaches the Apple ID and the app-specific password to whatever URL it is
 * handed.
 */
export interface CreateEventInput {
  /** The opaque id `calendar_list_calendars` minted. */
  calendarId: string;
  /** The title, verbatim. */
  summary: string;
  /** `YYYY-MM-DDTHH:MM:SS`, read in `tzid`. */
  startLocal: string;
  /** `YYYY-MM-DDTHH:MM:SS`, read in `tzid`. */
  endLocal: string;
  /** The IANA zone the two wall clocks are expressed in. Unused when `allDay`. */
  tzid: string;
  /** True for a date-only event, which carries no zone at all. */
  allDay?: boolean;
  /** Verbatim, or absent. */
  location?: string | null;
  /** Verbatim, or absent. */
  description?: string | null;
  /**
   * Who is inviting and who is invited, or absent for an event reaching nobody.
   *
   * Only ever supplied by the COMMIT leg of the attendee gate, from a
   * confirmation the user approved. The tool's own ungated path passes nothing,
   * so a create that carries no attendee cannot acquire an organiser.
   */
  participants?: BuildParticipants | null;
  /**
   * The UID this write must land on, or absent to mint a fresh one.
   *
   * **Supplied only from a SIGNED confirmation**, never from a tool parameter —
   * there is no schema anywhere that admits one. The gated create's preview
   * planned a target through `planCreateTarget` and put its object URL inside
   * the sealed payload; the commit derives the UID back out of that URL, so the
   * resource the user approved is the resource that gets written.
   *
   * Absent is the ordinary case and is what makes a create non-idempotent: two
   * calls with byte-identical input mint two UIDs and leave two events behind.
   */
  uid?: string;
}

/**
 * What a create returns, whether or not it wrote anything.
 *
 * **`created` is a FIELD rather than the difference between a return and a
 * throw**, and that is the `unsupportedCharset` precedent rather than a
 * looseness. A zone this server holds no definition for is not a failure of the
 * request, the account or the network — it is a statement about what this
 * server can anchor to, there is nothing the caller can do differently, and
 * inventing a fifth error category for it would spend the closed vocabulary on
 * a case that already reports itself.
 *
 * `summary` and `location` are carried back so the tool boundary can echo the
 * caller's own text inside the fence without being handed the input twice. They
 * are the caller's, not the server's, and they are fenced for that reason.
 */
export interface CreatedEvent {
  /** The opaque id the new event is addressable by, or null when nothing was written. */
  id: string | null;
  /** The opaque calendar id the caller supplied, echoed for join-by-identity. */
  calendarId: string;
  /** The resource UID this server minted, or null when nothing was written. */
  uid: string | null;
  /** Whether an event actually reached the account. */
  created: boolean;
  /** The zone that was refused, or null when none was. */
  unsupportedTimezone: string | null;
  /** The title, as the caller supplied it. Untrusted on the way back out. */
  summary: string;
  /** The location, as the caller supplied it. Untrusted on the way back out. */
  location: string | null;
}

/**
 * Put one event on one calendar (CALW-01). The first DAV write in this project.
 *
 * ## What it costs
 *
 * ONE request, and the count is asserted rather than inferred. There is no
 * read leg: the collection URL is inside the opaque id, so addressing the
 * target costs no lookup, and the object URL is CONSTRUCTED from a UID this
 * server just minted rather than discovered.
 *
 * ## Why `allowRediscovery` is false, which is the least obvious line here
 *
 * `withRediscovery` re-runs its operation once on a rediscoverable failure when
 * the account came from cache. For a read that is exactly right. For a write it
 * means the `PUT` goes out twice — and `If-None-Match: *` then makes the second
 * attempt fail BECAUSE THE FIRST ONE LANDED. The data is safe either way, which
 * is the argument for keeping the conditional header regardless; what is not
 * safe is the REPORT, because the caller sees the retry's failure for a create
 * that succeeded. "The tool said it failed and the event is on my calendar" is
 * the single worst outcome this path has, so the retry is refused rather than
 * paid for.
 *
 * ## Containment, on BOTH urls, INSIDE the callback
 *
 * `assertUnderHome` runs on the decoded collection URL and again on the object
 * URL built from it. Both, because each independently names what the server is
 * asked for, and the second matters more here than it does on the read path:
 * that URL is constructed rather than decoded, so no earlier check has ever
 * seen it. Inside the callback rather than above it, because `resolved.homeUrl`
 * does not exist until discovery has run (03-REVIEW.md CR-01).
 */
export async function createEvent(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  input: CreateEventInput,
): Promise<CreatedEvent> {
  // Decoded FIRST, before the KV read discovery performs and before any
  // outbound request — the same order `calendar_get_event` uses, and the
  // cheapest possible refusal of a forged id.
  const ref = decodeCalendarId(input.calendarId);

  const allDay = input.allDay ?? false;
  const summary = input.summary;
  const location = input.location ?? null;

  // The zone check is second and is equally free. An all-day event skips it
  // because it carries no zone at all: refusing one over a `tzid` the resource
  // will never mention would be a refusal with no subject.
  if (!allDay && !isSupportedTimezone(input.tzid)) {
    return {
      id: null,
      calendarId: input.calendarId,
      uid: null,
      created: false,
      unsupportedTimezone: input.tzid,
      summary,
      location,
    };
  }

  const zone = allDay ? null : input.tzid;
  const vevent = buildVEvent({
    summary,
    startLocal: input.startLocal,
    endLocal: input.endLocal,
    tzid: zone,
    allDay,
    location,
    description: input.description ?? null,
    participants: input.participants ?? null,
    // ZERO, and a literal rather than a parameter. RFC 5545 §3.8.7.4 defines
    // zero as a new event's first revision, and there is nothing to advance
    // past: this resource does not exist yet. The rewrite path is the one that
    // reads a stored value; see `updateEventBody`.
    sequence: 0,
  });
  // `buildVEvent` mints a UID, which is what makes an UNGATED create
  // non-idempotent. A GATED one arrives carrying the UID its own preview
  // planned and put inside the signed confirmation, so the resource the user
  // approved is the one that gets written. Updated rather than added, exactly
  // as `updateEventBody` does it, so there is one `UID` property either way.
  if (input.uid !== undefined) {
    vevent.updatePropertyWithValue("uid", input.uid);
  }
  const uid = String(vevent.getFirstPropertyValue("uid"));
  const iCalString = serializeCalendarResource(vevent, zone);
  // Percent-encoded, so the `@` in the UID cannot be read as anything but a
  // path character, and so the name this server computes is byte-identical to
  // the one tsdav resolves against the collection — and, on the gated path,
  // to the one `planCreateTarget` already signed into the confirmation.
  const filename = objectNameFor(uid);

  return withRediscovery(
    env,
    principal,
    davFetch,
    "caldav",
    async (resolved) => {
      assertUnderHome(ref.collectionUrl, resolved.homeUrl);
      const objectUrl = new URL(filename, ref.collectionUrl).href;
      assertUnderHome(objectUrl, resolved.homeUrl);

      await createCalendarObject({
        calendar: { url: ref.collectionUrl },
        filename,
        iCalString,
        // Never a credential from here. `./transport.ts` attaches it per call
        // and is the only place that may. The library supplies the content type
        // and the `If-None-Match: *` that makes this write conditional.
        headers: {},
        fetch: davFetch,
      });

      return {
        // Minted through the existing encoder with a null recurrence id, so the
        // event is addressable by `calendar_get_event` the moment it exists.
        id: encodeEventId({
          calendarUrl: ref.collectionUrl,
          objectUrl,
          recurrenceId: null,
        }),
        calendarId: input.calendarId,
        uid,
        created: true,
        unsupportedTimezone: null,
        summary,
        location,
      };
    },
    // See the docstring. This is the whole of Pitfall 8's mitigation.
    false,
  );
}

/**
 * Fold one side of a comparison for matching.
 *
 * `toLowerCase` and NOT the locale-aware form, and the difference is a real bug
 * rather than a style preference. The locale-aware fold gives a different answer
 * under a Turkish locale — a dotted capital I folds to a dotless one — so a
 * search for "Interview" would stop matching "interview" on a host whose
 * ambient locale happened to differ. The vitest pool inherits the developer's
 * locale while production runs its own, which is the same silent, host-dependent
 * divergence `displayNameKeyOf` in `./ids.ts` rejects the locale-aware form for
 * and the same one the `ical-jsdate` scan rule exists to prevent on the time
 * side. This module follows that precedent rather than starting a second one.
 */
function fold(value: string): string {
  return value.toLowerCase();
}

/**
 * Whether one occurrence carries a keyword (CAL-04).
 *
 * **Substring, not prefix**, across the summary, the location and the
 * description — someone searching for a word should find an event whose summary
 * merely ends with it. The description is searched even though no list row can
 * carry one: the row shape's refusal is about what LEAVES this server, not about
 * what it may read.
 *
 * Exported so the semantics stated on the tool's parameter and the semantics
 * that ship are the same code rather than two descriptions of it.
 */
export function matchesKeyword(occurrence: Occurrence, term: string): boolean {
  const needle = fold(term);
  for (const field of [
    occurrence.summary,
    occurrence.location,
    occurrence.description,
  ]) {
    if (field !== null && fold(field).includes(needle)) return true;
  }
  return false;
}

/**
 * Whether one occurrence names a person (CAL-04).
 *
 * The same containment rule as the keyword, against each participant's display
 * name and against their address — which the parser has already stripped to the
 * address itself, so the local part and the domain are both reachable as
 * substrings of one value without this function having to split anything.
 *
 * **The organiser counts as an attendee, deliberately.** For the job search this
 * project exists to serve, the person who SENT the invitation is the person
 * being searched for at least as often as a listed participant — a recruiter
 * books the call, and asking "find every meeting with that recruiter" must
 * return it.
 */
export function matchesAttendee(occurrence: Occurrence, term: string): boolean {
  const needle = fold(term);
  const parties =
    occurrence.organizer === null
      ? occurrence.attendees
      : [occurrence.organizer, ...occurrence.attendees];

  for (const party of parties) {
    for (const field of [party.name, party.email]) {
      if (field !== null && fold(field).includes(needle)) return true;
    }
  }
  return false;
}

/** What one search call asks for, on top of everything a listing asks for. */
export interface EventSearchOptions extends EventListOptions {
  /** Matched against the summary, the location and the description. */
  keyword?: string;
  /** Matched against every attendee's name and address, and the organiser's. */
  attendee?: string;
}

/**
 * A term that is present but empty, as opposed to absent.
 *
 * The distinction is the whole check. An absent term means "do not filter on
 * this axis"; a term of spaces means the caller asked for something and this
 * server would match every event on the account — which reads as an answer
 * rather than as the mistake it is.
 */
function usableTerm(term: string | undefined): string | null {
  if (term === undefined) return null;
  const trimmed = term.trim();
  // Supplied and empty. `DavNotFoundError` rather than a fifth error category:
  // the four-value vocabulary is closed, and a term this server declines to
  // search on is the same class of answer as an identifier it declines to
  // resolve. `rediscoverable` stays false — re-resolving home URLs cannot make
  // a blank term searchable.
  if (trimmed.length === 0) throw new DavNotFoundError();
  return trimmed;
}

/**
 * Search the occurrences in a bounded range, paged (CAL-04, CAL-05).
 *
 * ## A search result IS a listing
 *
 * Same total order, same cursor, same page shape, same range cap, same
 * truncation and cache flags — the model should not have to learn a second
 * contract, which is the argument `searchPageToolResult` already makes on the
 * mail side. The only difference is a predicate applied before the page is cut.
 *
 * ## Why the matching is client-side, when the protocol offers server-side
 *
 * Recorded rather than left to be re-derived, because the next session will
 * otherwise rediscover the temptation from the fact that the protocol has the
 * feature:
 *
 *   1. **The specification makes text matching on event properties OPTIONAL,
 *      and only RECOMMENDS — rather than requires — that a server report which
 *      filters it does not support.** So a server may simply return fewer rows
 *      with no signal at all, which reads to the model as "you have no such
 *      meeting". That is the same silent-partial-support failure the contacts
 *      side rejects server-side-only matching for, and on this account it is
 *      not hypothetical: the CalDAV supported-report property came back null,
 *      so report support here is UNCONFIRMED rather than confirmed absent.
 *   2. **A server-side match returns the wrong granularity anyway.** The query
 *      matches RESOURCES, so a hit on a recurring master returns the whole
 *      series — which still needs client-side expansion and then client-side
 *      re-filtering to find which occurrences fall in range. The round trip
 *      buys nothing.
 *   3. **Attendee matching is worse still.** It needs a parameter-level filter
 *      on a property this code already reads for free once the event is parsed,
 *      doubling the unverified surface for no gain.
 *
 * ## What it costs, and what it cannot answer
 *
 * Exactly what the equivalent listing costs — three serial round trips, since
 * the calendar is required here too — because it fetches the same set and
 * then filters it. It is therefore bounded by the range fetched and CANNOT
 * answer a question about all of time. That limit is stated in the tool's
 * description rather than left to be discovered, mirroring the way the mail
 * search tool is scoped to a folder.
 *
 * ## What the cursor pins, and what it deliberately gave up
 *
 * All three discriminators the position depends on: the range, the calendar
 * scope, and BOTH search terms. A cursor minted under one search and resumed
 * under another is refused before any request rather than silently answered.
 *
 * 03-07 shipped this without the term pin, and said so rather than hiding it,
 * because its own acceptance criteria required a search cursor and a listing
 * cursor to be INTERCHANGEABLE and `CalendarCursor` had no field for a term.
 * The user reviewed that and chose to close it: interchangeability is the thing
 * that gives, because pinning the terms is precisely what makes a search cursor
 * not a listing cursor — which is the correct semantics rather than a
 * regression against the older contract.
 *
 * So a listing cursor handed to a search is now refused, and a search cursor
 * handed to the listing is too. What survives is the part that was actually
 * worth having: the same token KIND, the same total order, the same page shape,
 * the same range cap. The model still learns one contract.
 *
 * The one thing the cursor still cannot pin is the same one the listing cannot:
 * it does not guarantee that page one plus page two equals the set that existed
 * when page one was built. An event created while the caller is paging can land
 * at a start time already passed and will not appear. That is a fact about the
 * world rather than about the token, and it is stated on the tool's own cursor
 * parameter.
 */
export async function searchEvents(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: EventSearchOptions,
): Promise<EventPage> {
  // Both refusals happen BEFORE `pagedEvents`, and therefore before the range
  // check, the KV read discovery performs, and any outbound request.
  const keyword = usableTerm(options.keyword);
  const attendee = usableTerm(options.attendee);

  // Neither axis supplied. A search for nothing is not a listing with extra
  // steps — the caller asked a question this function cannot read, and
  // answering it with every event would be a wrong answer rather than a wide
  // one.
  if (keyword === null && attendee === null) throw new DavNotFoundError();

  // AND, not OR. Two supplied terms narrow.
  const filter: OccurrenceFilter = (occurrence) => {
    if (keyword !== null && !matchesKeyword(occurrence, keyword)) return false;
    if (attendee !== null && !matchesAttendee(occurrence, attendee)) return false;
    return true;
  };

  // WHICH field matched is deliberately not reported. It would be a second
  // contract for the model to reason about, and it would put a stranger-authored
  // field NAME into the trusted half of a response to say so.
  //
  // The terms are pinned FOLDED, through the same `fold` the matching uses, so
  // the cursor discriminates exactly what changes the answer and nothing more.
  // "Interview" and "interview" return the identical ordered set, so refusing
  // between them would be a false refusal; "interview" and "offer" do not, and
  // that is the refusal.
  return pagedEvents(env, principal, davFetch, options, filter, {
    keywordTerm: keyword === null ? null : fold(keyword),
    attendeeTerm: attendee === null ? null : fold(attendee),
  });
}
