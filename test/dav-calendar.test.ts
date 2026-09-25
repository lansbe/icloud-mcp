// CAL-01, CAL-02 and CAL-05 at the service layer, driven by a stub fetch.
//
// No network and no real credentials (D-09). The seam is the one production
// uses: tsdav resolves `fetchOverride ?? fetch`, and `davFetch` is that
// override, so every assertion below runs the shipped code path rather than a
// parallel one written for the test.
//
// Three properties here fail SILENTLY rather than loudly, and each has cases
// written to make the silence audible:
//
//   1. The round-trip COUNT. A listing that costs one request per calendar and
//      one that costs one request total return identical rows; only a counter
//      can tell them apart, and on an account with nine calendars the
//      difference is the whole user-visible latency of the call.
//   2. The paging walk. A keyset cursor that drops or repeats a row still
//      returns a plausible page. The walk below collects every id across every
//      page and asserts the multiset, over a set carrying deliberate ties on
//      the first TWO order components — which is the only shape that can
//      distinguish a total order from one that merely looks total.
//   3. The absent instant. An occurrence whose zone did not resolve carries no
//      instant, and the SORT KEY that made it sortable is a different number
//      that must never reach a row. Both halves are asserted, because a row
//      carrying the derived key would look completely normal.

import ICAL from "ical.js";
import { env } from "cloudflare:workers";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

// Hoisted by vitest above every import below, including the one two lines
// down that resolves through `../src/dav/calendar.ts`'s own import of the
// same module — so `collectFromFeed`'s call reaches this mock too, not the
// real network. `fetchSubscriptionFeed`'s own choke-point guarantees (no
// credential, https-only, size-capped) are Task 1's job, proven in
// `test/feed-subscription.test.ts`; this file only ever exercises the
// INTEGRATION — that the mock receives exactly `collection.source` and
// nothing else, and that the feed host never leaks into a tool response.
vi.mock("../src/feed/subscription-feed", () => ({
  fetchSubscriptionFeed: vi.fn(),
}));

import { fetchSubscriptionFeed } from "../src/feed/subscription-feed";
import {
  MAX_RANGE_DAYS,
  MAX_SLOT_RANGE_DAYS,
  assertEtag,
  calendarColorForWire,
  createCalendarCollection,
  createEvent,
  deleteEvent,
  findFreeSlots,
  getEvent,
  getEventWithEtag,
  listCalendars,
  listEvents,
  matchesAttendee,
  matchesKeyword,
  nextCivilDate,
  patchEventBody,
  pinnedOccurrencesFor,
  planCreateTarget,
  propstatOutcomes,
  resolveOrganizerAddress,
  searchEvents,
  updateCalendarCollection,
  updateEvent,
  updateEventBody,
  updateOccurrenceBody,
} from "../src/dav/calendar";
import type {
  CreateEventInput,
  EventDetail,
  EventSummary,
  FindSlotsOptions,
  UpdatedCalendar,
} from "../src/dav/calendar";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import {
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavSubscriptionError,
} from "../src/dav/errors";
import {
  MAX_EXPANDED_OCCURRENCES,
  VTIMEZONE_ALLOWLIST,
  expandOccurrences,
  withParsedResource,
} from "../src/dav/icalendar";
import type { BuildEventInput, Occurrence } from "../src/dav/icalendar";
import {
  DAV_TOKEN_VERSION,
  decodeCalendarCursor,
  decodeCalendarId,
  decodeEventId,
  encodeCalendarCursor,
  encodeCalendarId,
  encodeEventId,
  encodeSlotCursor,
} from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import {
  ALL_DAY_RECURRING_ICS,
  DEFINED_TZID,
  NO_END_TIME_ICS,
  UNDEFINED_TIMEZONE_ICS,
  WEEKLY_SERIES_DESCRIPTION,
  WEEKLY_SERIES_OVERRIDE_SUMMARY,
  WEEKLY_SERIES_SUMMARY,
  WEEKLY_SERIES_WITH_OVERRIDE_ICS,
} from "./fixtures/dav-bytes";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
  calendarListToolResult,
  eventPageToolResult,
  eventToolResult,
  registerCalendarTools,
} from "../src/mcp/tools/calendar";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import { assertMethodIsBuildable } from "./fixtures/sendable-method";
import type { Principal } from "../src/principal";

// The owner's principal, as the PROMISE the real env constructor returns over
// the pool's ambient environment. The DAV fetch builder and the registrars take
// the promise. The no-op handler means a file that builds it and awaits it
// nowhere leaves no rejection unheard. Everyone who does await it still sees
// the refusal.
const owner = ownerPrincipal();
owner.catch(() => {});

// What that promise resolves to. Resolved once, and the very same object is
// handed to every call: the password reader answers only the object a
// constructor built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await owner;
});

// ---------------------------------------------------------------------------
// The account this fixture describes
// ---------------------------------------------------------------------------

const CALDAV_SERVER = "https://caldav.icloud.com";
const PRINCIPAL_PATH = "/1234567890/principal/";
const CALDAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";

const WORK_PATH = "/1234567890/calendars/work/";
const HOME_PATH = "/1234567890/calendars/home/";
const NOTES_PATH = "/1234567890/calendars/notes/";
const TODO_PATH = "/1234567890/calendars/reminders/";
const INBOX_PATH = "/1234567890/calendars/inbox/";
const SUBSCRIBED_PATH = "/1234567890/calendars/subscribed/";

const WORK_URL = `https://p42-caldav.icloud.com${WORK_PATH}`;
const HOME_URL = `https://p42-caldav.icloud.com${HOME_PATH}`;
const NOTES_URL = `https://p42-caldav.icloud.com${NOTES_PATH}`;
const SUBSCRIBED_URL = `https://p42-caldav.icloud.com${SUBSCRIBED_PATH}`;

/**
 * The opaque id of each calendar the fixture serves.
 *
 * Every listing and every search below names one of these, because `calendarId`
 * is REQUIRED — the account-wide form was withdrawn after the live UAT run
 * recorded it failing on the real account. That is also why the counts in this
 * file are per calendar rather than per account: the default fixture puts the
 * weekly series in work, the all-day series in home and the floating-zone
 * resource in notes, so twelve, three and one are the three answers a listing
 * can now give over it.
 */
const WORK_ID = encodeCalendarId({ collectionUrl: WORK_URL });
const HOME_ID = encodeCalendarId({ collectionUrl: HOME_URL });
const NOTES_ID = encodeCalendarId({ collectionUrl: NOTES_URL });
const SUBSCRIBED_ID = encodeCalendarId({ collectionUrl: SUBSCRIBED_URL });

/** The display name BOTH the work and home collections carry. */
const SHARED_NAME = "Shared";

/**
 * A `CS:source` href shaped after the real one the debug session recorded
 * live: `https://sm-cal.apple.com/cal/<hex>`.
 *
 * **Deliberately NOT a tidy `example.invalid` URL.** "It is on Apple's own
 * domain" is exactly the reasoning that would make routing this fetch
 * through the credential-attaching `davFetch` feel safe — sm-cal.apple.com
 * is Apple's infrastructure, but it is not THIS ACCOUNT's CalDAV shard, and
 * `fetchSubscriptionFeed` must never learn the difference. Using the real
 * shape here is what keeps that distinction live in the fixture rather than
 * papered over by an obviously-fake host.
 */
const FEED_URL = "https://sm-cal.apple.com/cal/5fdfa7c8d27442fd8ee139d66429fc4d";

/**
 * The Work collection, exactly as probe (1) recorded its live shape:
 * `resourcetype = <D:collection/><CS:subscribed/>`, `VEVENT`-only, with a
 * readable `CS:source`.
 */
const SUBSCRIBED_COLLECTION: CollectionSpec = {
  href: SUBSCRIBED_PATH,
  displayName: "Work",
  resourceType: ["collection", "subscribed"],
  components: ["VEVENT"],
  source: FEED_URL,
};

/**
 * The Apple ID the test pool binds, and the addresses the principal advertises.
 *
 * Shaped after probe P-1's verbatim answer rather than after a tidy list: the
 * real account's `calendar-user-address-set` carries FOUR `mailto:` entries
 * beside a principal path and a `urn:uuid:` form, and the login address is not
 * the only one. So the fixture puts a non-`mailto:` entry first, an alias ahead
 * of the login, and another alias after it — which is the arrangement that
 * makes "prefer the login, else the first mailto" a real choice rather than a
 * synonym for "take element zero".
 */
const LOGIN_ADDRESS = "test@example.invalid";
const ALIAS_BEFORE_LOGIN = "alias.one@example.invalid";
const USER_ADDRESSES: string[] = [
  "/1234567890/principal/",
  "urn:uuid:00000000",
  `mailto:${ALIAS_BEFORE_LOGIN}`,
  `mailto:${LOGIN_ADDRESS}`,
  "mailto:alias.two@example.invalid",
];

const XML_HEADERS = { "content-type": "text/xml; charset=utf-8" };

/** Seconds since the epoch for an explicitly UTC instant. */
function at(iso: string): number {
  const parsed = Date.parse(iso);
  expect(Number.isNaN(parsed)).toBe(false);
  return Math.floor(parsed / 1000);
}

/** The range every listing case below asks for unless it says otherwise. */
const RANGE_START = at("2026-01-01T00:00:00Z");
const RANGE_END = at("2026-04-01T00:00:00Z");

// ---------------------------------------------------------------------------
// Synthesised bodies
//
// Every byte below is invented. Nothing here is copied from a real account,
// and every address is under `.invalid`, matching the provenance rule
// `test/fixtures/dav-bytes.ts` states for the parser corpus.
// ---------------------------------------------------------------------------

function ics(...lines: string[]): string {
  return `${lines.join("\r\n")}\r\n`;
}

const ICS_HEAD = [
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "PRODID:-//Example Org//Synthesised Fixture//EN",
  "CALSCALE:GREGORIAN",
];

/**
 * Two resources starting at the SAME instant in the SAME calendar.
 *
 * This is the only shape that exercises the third component of the total
 * order. A comparator that stops after the instant and the calendar URL
 * returns these two in whatever order the fetch happened to yield them, which
 * is stable within one process and therefore invisible to every other case
 * here — and a keyset cursor riding a non-total order drops or repeats exactly
 * at this boundary.
 */
const TIE_A_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  "UID:tie-alpha-0001@example.invalid",
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Tie alpha",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  "SEQUENCE:0",
  "END:VEVENT",
  "END:VCALENDAR",
);

const TIE_B_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  "UID:tie-beta-0002@example.invalid",
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Tie beta",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  "SEQUENCE:0",
  "END:VEVENT",
  "END:VCALENDAR",
);

/**
 * A rule that produces more occurrences in two days than the expansion cap
 * admits.
 *
 * A minute-by-minute rule is legal iCalendar and an invitation can carry one.
 * Two days of it is 2,880 nominal occurrences against a 2,000 ceiling, so the
 * cap trips on a range well inside the 366-day limit — which is the point: the
 * truncation flag has to be reachable without asking for an illegal range.
 */
const MINUTELY_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  "UID:minutely-0003@example.invalid",
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Every minute",
  "DTSTART:20260101T000000Z",
  "DTEND:20260101T000100Z",
  "RRULE:FREQ=MINUTELY",
  "SEQUENCE:0",
  "END:VEVENT",
  "END:VCALENDAR",
);

/**
 * A rule that spends its whole per-resource step allowance REACHING the range
 * and never arrives (03-REVIEW.md WR-01).
 *
 * Minute by minute from June 2025, against a range in January 2026: about three
 * hundred and eight thousand steps to the range start, against a quarter-million
 * ceiling. So each of these costs exactly its cap, yields NOTHING, and — before
 * the listing budget existed — handed the next resource a completely fresh
 * quarter-million of its own. That is the axis the aggregate cap bounds: not one
 * runaway rule, which `MAX_ITERATOR_STEPS` already stopped, but their product.
 *
 * The UID differs per copy so the fixtures are distinguishable in a failure.
 */
function starverIcs(n: number): string {
  return ics(
    ...ICS_HEAD,
    "BEGIN:VEVENT",
    `UID:starver-000${n}@example.invalid`,
    "DTSTAMP:20250601T120000Z",
    `SUMMARY:Starver ${n}`,
    "DTSTART:20250601T000000Z",
    "DTEND:20250601T000100Z",
    "RRULE:FREQ=MINUTELY",
    "SEQUENCE:0",
    "END:VEVENT",
    "END:VCALENDAR",
  );
}

/** One ordinary event inside the starvers' range, costing a single step. */
const ORDINARY_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  "UID:ordinary-0007@example.invalid",
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Ordinary",
  "DTSTART:20260101T090000Z",
  "DTEND:20260101T100000Z",
  "SEQUENCE:0",
  "END:VEVENT",
  "END:VCALENDAR",
);

function multistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/" xmlns:CA="http://apple.com/ns/ical/">${body}</multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

interface CollectionSpec {
  href: string;
  /** Omitted entirely means the element arrives EMPTY, which yields an object. */
  displayName?: string;
  /** The `resourcetype` children, without their namespace prefixes. */
  resourceType: string[];
  /** The `comp` names the collection declares support for. */
  components: string[];
  color?: string;
  /**
   * The `CS:source` href.
   *
   * Undefined means the property is absent entirely — the shape most owned
   * and shared collections carry. The empty string renders an EMPTY
   * `<CS:source/>` element, which the XML layer turns into `{}` rather than
   * `{ href: ... }`, exactly `sourceHrefOf`'s own empty-element case one
   * module over.
   */
  source?: string;
  /**
   * The `CS:getctag` binding.
   *
   * Undefined means the property is absent entirely, and that is a real answer
   * rather than a gap in the fixture: CALM-06 has to REFUSE a collection that
   * offers no binding rather than write it unbound, and a spec that could not
   * express the absence could not test the refusal. The `CS` prefix is already
   * bound on `multistatus()`'s root element.
   */
  ctag?: string;
  /**
   * The `C:schedule-default-calendar-URL` href.
   *
   * RFC 6638 § 9.2 puts this on the scheduling INBOX collection rather than on
   * the principal, and the depth-1 home PROPFIND already traverses the inbox,
   * so the property rides along for zero extra requests — D-11 as corrected on
   * 2026-09-25.
   *
   * Undefined means absent, and absent is what the inbox row below carries BY
   * DEFAULT, on purpose. Whether iCloud actually populates the property is
   * unmeasured until the phase's live probe, and a fixture that assumed the
   * answer would make that probe redundant.
   */
  scheduleDefaultCalendar?: string;
}

function collectionBody(spec: CollectionSpec): string {
  const resourceType = spec.resourceType
    .map((one) => (one === "collection" ? "<collection/>" : `<C:${one}/>`))
    .join("");
  const components = spec.components
    .map((one) => `<C:comp name="${one}"/>`)
    .join("");
  const displayName =
    spec.displayName === undefined
      ? "<displayname/>"
      : `<displayname>${spec.displayName}</displayname>`;
  const color = spec.color === undefined ? "" : `<CA:calendar-color>${spec.color}</CA:calendar-color>`;
  const source =
    spec.source === undefined
      ? ""
      : spec.source === ""
        ? "<CS:source/>"
        : `<CS:source><href>${spec.source}</href></CS:source>`;
  const ctag =
    spec.ctag === undefined ? "" : `<CS:getctag>${spec.ctag}</CS:getctag>`;
  const scheduleDefault =
    spec.scheduleDefaultCalendar === undefined
      ? ""
      : `<C:schedule-default-calendar-URL><href>${spec.scheduleDefaultCalendar}</href></C:schedule-default-calendar-URL>`;

  return (
    `<response><href>${spec.href}</href><propstat>` +
    `<status>HTTP/1.1 200 OK</status><prop>` +
    `${displayName}<resourcetype>${resourceType}</resourcetype>` +
    `<C:supported-calendar-component-set>${components}</C:supported-calendar-component-set>` +
    `${color}${source}${ctag}${scheduleDefault}` +
    `</prop></propstat></response>`
  );
}

/**
 * The `CS:getctag` the work calendar answers unless a case names another.
 *
 * Opaque and unquoted, which is what a ctag is on the wire — unlike an ETag it
 * carries no quoting convention, so a fixture that quoted it would let an
 * implementation that strips quotes pass. The value means nothing; that it is
 * compared byte for byte is the whole point.
 */
const WORK_CTAG = "ctag-work-1";

/**
 * The calendar home's own pathname.
 *
 * The one thing that tells a depth-1 PROPFIND against the HOME apart from a
 * depth-1 PROPFIND against a COLLECTION inside it — both are the same method
 * against a URL on the same host, and until the stub could tell them apart it
 * answered the home listing to both.
 */
const HOME_SET_PATH = new URL(CALDAV_HOME).pathname;

/**
 * The home set this account serves, in DOCUMENT order.
 *
 * Deliberately not in URL order: the ordering case below would pass on an
 * implementation that returned rows exactly as the server listed them if the
 * two orders agreed.
 */
const COLLECTIONS: CollectionSpec[] = [
  // The home collection itself. Not a calendar, and filtered on resource type.
  { href: "/1234567890/calendars/", resourceType: ["collection"], components: [] },
  {
    href: WORK_PATH,
    displayName: SHARED_NAME,
    resourceType: ["collection", "calendar"],
    components: ["VEVENT"],
    color: "#1f77b4",
    // The binding CALM-06 seals into a confirmation and re-reads at commit.
    // Measured present and non-empty on a live iCloud collection — see
    // `.planning/debug/resolved/subscribed-cal-events-empty.md`.
    ctag: WORK_CTAG,
  },
  {
    href: NOTES_PATH,
    // No display name element content at all: the XML layer yields an OBJECT.
    // No `ctag` either, and that is the OTHER half of CALM-06: a collection
    // answering no binding must be refused rather than written unbound, and
    // the refusal needs a collection that answers none to be tested against.
    resourceType: ["collection", "calendar"],
    components: ["VEVENT"],
  },
  {
    href: HOME_PATH,
    displayName: SHARED_NAME,
    resourceType: ["collection", "calendar"],
    components: ["VEVENT"],
  },
  // A calendar collection that holds only reminders. Filtered on components.
  {
    href: TODO_PATH,
    displayName: "Reminders",
    resourceType: ["collection", "calendar"],
    components: ["VTODO"],
  },
  // The scheduling inbox. Not a calendar collection at all, and the row
  // CALM-07 has to find: RFC 6638 § 9.2 puts `schedule-default-calendar-URL`
  // HERE and not on the principal, and the depth-1 home PROPFIND already
  // traverses it. `scheduleDefaultCalendar` is deliberately UNSET — whether
  // iCloud populates the property is unmeasured, and a fixture that assumed
  // the answer would pre-empt the probe that settles it.
  //
  // The element name is `schedule-inbox` because this is the XML on the wire;
  // D-11's live reading records `scheduleInbox`, which is tsdav's camel-cased
  // form of the same element after parsing.
  {
    href: INBOX_PATH,
    displayName: "Inbox",
    resourceType: ["collection", "schedule-inbox"],
    components: [],
  },
];

/**
 * The ETag a resource carries unless a case names a different one.
 *
 * Quoted, because an ETag is an opaque QUOTED string on the wire and the whole
 * point of the byte-exact assertions below is that this server never unwraps
 * one. A fixture holding a bare `etag-1` would let a stripping implementation
 * pass.
 */
const DEFAULT_ETAG = '"etag-1"';

/**
 * A depth-1 `PROPFIND` answer for ONE collection: the container, then its members.
 *
 * **The collection's own row is first and it is there ON PURPOSE.** A depth-1
 * PROPFIND against a collection returns a response element for the collection
 * itself alongside every member, which was measured live against this account:
 * a calendar holding zero objects came back with *"exactly ONE href returned:
 * the collection's own URL"*
 * (`.planning/debug/resolved/subscribed-cal-events-empty.md`). So an empty
 * calendar answers one row and a calendar holding nine events answers ten.
 * Counting the rows gives a number one too high — including the number in the
 * sentence the user agrees to before a delete, which is the whole reason
 * CALM-06 exists. A fixture that omitted the container could not prove the
 * exclusion, because there would be nothing to exclude.
 *
 * **At least one default member href has no `.ics` suffix**, and that is the
 * second hazard rather than a stray. tsdav's `fetchCalendarObjects` filters on
 * `url.includes(".ics")` by default, so routing the count through it would
 * silently drop that member and report a count that is quietly short — on the
 * one operation where a short count means events disappear that the user was
 * never told about. The count must be taken from `propfind` directly, and this
 * fixture is what fails if it is not.
 *
 * `ctag` rides on the container's row when supplied, because that is where a
 * real server puts it and where the binding is read from.
 */
function memberListingBody(
  collectionHref: string,
  memberHrefs: string[],
  ctag?: string,
): string {
  const binding = ctag === undefined ? "" : `<CS:getctag>${ctag}</CS:getctag>`;
  const container =
    `<response><href>${collectionHref}</href><propstat>` +
    `<status>HTTP/1.1 200 OK</status><prop>` +
    `<displayname>Work</displayname>` +
    `<resourcetype><collection/><C:calendar/></resourcetype>` +
    `${binding}</prop></propstat></response>`;
  return (
    container + memberHrefs.map((href) => objectHrefBody(href)).join("")
  );
}

/**
 * The members each collection answers on a depth-1 `PROPFIND`, by href.
 *
 * The work calendar's list carries three members and the THIRD has no `.ics`
 * suffix — see `memberListingBody` for why that one is load-bearing rather
 * than untidy.
 */
const MEMBERS: Record<string, string[]> = {
  [WORK_PATH]: [
    `${WORK_PATH}weekly.ics`,
    `${WORK_PATH}allday.ics`,
    `${WORK_PATH}a-resource-with-no-suffix`,
  ],
};

function objectHrefBody(href: string, etag: string = DEFAULT_ETAG): string {
  return (
    `<response><href>${href}</href><propstat>` +
    `<status>HTTP/1.1 200 OK</status><prop><getetag>${etag}</getetag></prop>` +
    `</propstat></response>`
  );
}

function objectDataBody(
  href: string,
  data: string,
  etag: string = DEFAULT_ETAG,
): string {
  return (
    `<response><href>${href}</href><propstat>` +
    `<status>HTTP/1.1 200 OK</status><prop><getetag>${etag}</getetag>` +
    `<C:calendar-data><![CDATA[${data}]]></C:calendar-data>` +
    `</prop></propstat></response>`
  );
}

// ---------------------------------------------------------------------------
// The stub
// ---------------------------------------------------------------------------

interface Observed {
  url: string;
  method: string;
  /**
   * The OUTGOING request headers, lower-cased and flattened.
   *
   * Added for the write path, and it is a prerequisite rather than a
   * convenience: a write test that asserts the write SUCCEEDED passes just as
   * happily against an unconditional write, because the server answers 201
   * either way. The only thing that distinguishes a conditional `PUT` from an
   * unconditional one is the header it carried, and until this field existed
   * that assertion could not be written at all.
   *
   * Normalised through `Headers` so a `Record`, an array of pairs and a
   * `Headers` all read the same here — tsdav builds its own header object and
   * this test must not depend on which of the three it happened to choose.
   */
  headers: Record<string, string>;
  /**
   * The OUTGOING request body, or null when there was none.
   *
   * The round-trip assertion needs the exact bytes this server sent, parsed
   * back through the shipped reader. Asserting the built `.ics` against a
   * separately-constructed expectation would prove the test's idea of the
   * format; parsing what actually went out proves the two halves of this
   * project agree.
   */
  body: string | null;
  start: number;
  end: number;
}

interface Stub {
  observed: Observed[];
  overlapped: boolean;
  fetch: typeof globalThis.fetch;
}

interface StubOptions {
  /** The calendar collections the home set advertises. */
  collections?: CollectionSpec[];
  /** `{ [calendarPath]: { [objectHref]: icsBody } }`. */
  objects?: Record<string, Record<string, string>>;
  /**
   * `{ [collectionHref]: memberHrefs }` for the depth-1 collection listing.
   *
   * A collection a case does not name answers an EMPTY listing — its own href
   * and nothing else, which is the real answer for an empty calendar and is
   * also what keeps every existing case untouched by this field's arrival.
   */
  members?: Record<string, string[]>;
  /**
   * `{ [objectHref]: etag }`, VERBATIM — quotes, weak prefix and all.
   *
   * A case that does not name one gets `DEFAULT_ETAG`. The value is spliced
   * into the multi-status untouched rather than quoted here, so a weak ETag
   * fixture can carry its own `W/` prefix and the byte-exactness assertions
   * are about what the server actually sent.
   */
  etags?: Record<string, string>;
  /**
   * The hrefs the principal's `calendar-user-address-set` advertises.
   *
   * Answered VERBATIM, in the order given, so a case can present the shapes the
   * real account actually returns — probe P-1 recorded four `mailto:` entries
   * beside a principal path and a `urn:uuid:` form, and the selection rule has
   * to pick from that mixture rather than from a tidy list of addresses. An
   * empty array is a real answer too: it is the account that advertises none.
   */
  userAddresses?: string[];
  /** Answer this request instead of the canned conversation. `null` defers. */
  onRequest?: (url: string, method: string) => Response | null;
}

/** The objects each calendar holds unless a case says otherwise. */
const OBJECTS: Record<string, Record<string, string>> = {
  [WORK_PATH]: {
    [`${WORK_PATH}weekly.ics`]: WEEKLY_SERIES_WITH_OVERRIDE_ICS,
  },
  [HOME_PATH]: {
    [`${HOME_PATH}allday.ics`]: ALL_DAY_RECURRING_ICS,
  },
  [NOTES_PATH]: {
    [`${NOTES_PATH}floating.ics`]: UNDEFINED_TIMEZONE_ICS,
  },
};

/**
 * All three resources in ONE calendar.
 *
 * A listing now spans exactly one collection, so a case that needs rows of
 * every shape at once — a resolved instant, an all-day date, and a wall clock
 * whose zone did not resolve — has to put them in the same calendar rather than
 * relying on the sweep to gather them. That is a fixture change and not a
 * weakening: the property under test is a total order over rows two thirds of
 * which have no instant to sort by, and it is still exactly that.
 *
 * The tie-break on the CALENDAR URL is the one component this layer can no
 * longer reach, because every row of a page now shares one. It is covered
 * directly in `test/dav-ids.test.ts`, over `compareEventOrder` itself.
 */
const MIXED_OBJECTS: Record<string, Record<string, string>> = {
  [WORK_PATH]: {
    [`${WORK_PATH}weekly.ics`]: WEEKLY_SERIES_WITH_OVERRIDE_ICS,
    [`${WORK_PATH}allday.ics`]: ALL_DAY_RECURRING_ICS,
    [`${WORK_PATH}floating.ics`]: UNDEFINED_TIMEZONE_ICS,
  },
};

/**
 * A stub answering a realistic iCloud CalDAV conversation.
 *
 * It yields between entry and exit so the sequential-walk assertion means
 * something: without the yield every call looks atomic, and a fan-out is
 * indistinguishable from a queue.
 */
function davStub(options: StubOptions = {}): Stub {
  const collections = options.collections ?? COLLECTIONS;
  const objects = options.objects ?? OBJECTS;
  const etags = options.etags ?? {};
  const members = options.members ?? MEMBERS;

  const state: Stub = {
    observed: [],
    overlapped: false,
    fetch: async () => new Response(null, { status: 500 }),
  };

  let tick = 0;
  let open = 0;

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET");
    // Through `Headers` rather than read off `init` directly, so the three
    // shapes `HeadersInit` admits all flatten to one lower-cased record.
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    // Before the record push, and the whole argument for why is in
    // `test/fixtures/sendable-method.ts`.
    assertMethodIsBuildable(url, method);

    const record: Observed = {
      url,
      method,
      headers,
      body: init?.body === undefined || init?.body === null
        ? null
        : String(init.body),
      start: (tick += 1),
      end: -1,
    };
    state.observed.push(record);

    open += 1;
    if (open > 1) state.overlapped = true;
    await new Promise((resolve) => setTimeout(resolve, 0));
    open -= 1;
    record.end = tick += 1;

    const override = options.onRequest?.(url, method);
    if (override) return override;

    if (url.includes("/.well-known/")) return new Response(null, { status: 404 });

    // --- discovery -------------------------------------------------------
    if (url.startsWith(CALDAV_SERVER)) {
      // The address-set PROPFIND and the home-set PROPFIND go to the SAME
      // principal URL, so the request BODY is the only thing that tells them
      // apart — exactly as the etag REPORT and the multi-get REPORT are told
      // apart below. Answered before the home-set branch, because that branch
      // matches on the URL alone and would otherwise swallow this one.
      if (String(init?.body ?? "").includes("calendar-user-address-set")) {
        const hrefs = (options.userAddresses ?? USER_ADDRESSES)
          .map((one) => `<href>${one}</href>`)
          .join("");
        return multistatus(
          `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-user-address-set>${hrefs}</C:calendar-user-address-set></prop></propstat></response>`,
        );
      }
      if (url.endsWith(PRINCIPAL_PATH)) {
        return multistatus(
          `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${CALDAV_HOME}</href></C:calendar-home-set></prop></propstat></response>`,
        );
      }
      return multistatus(
        `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`,
      );
    }

    // --- one collection's members ----------------------------------------
    // Answered BEFORE the home-set branch, because that branch matches on the
    // method alone and would otherwise swallow this one — the same ordering
    // argument the address-set branch above makes for itself.
    //
    // A depth-1 PROPFIND against a COLLECTION is a different question from the
    // depth-1 PROPFIND against the HOME, and until now this stub answered both
    // with the home listing. The count CALM-06 puts in front of the user comes
    // from this answer.
    if (method === "PROPFIND" && new URL(url).pathname !== HOME_SET_PATH) {
      const path = new URL(url).pathname;
      const spec = collections.find((one) => one.href === path);
      return multistatus(
        memberListingBody(path, members[path] ?? [], spec?.ctag),
      );
    }

    // --- the home set ----------------------------------------------------
    if (method === "PROPFIND") {
      return multistatus(collections.map(collectionBody).join(""));
    }

    // --- a write ----------------------------------------------------------
    // 201 with no body, which is what a CalDAV server answers to a create it
    // accepted. The header the request CARRIED is what the write cases assert;
    // this branch exists so there is a success to assert it against.
    if (method === "PUT") {
      return new Response(null, { status: 201, headers: { etag: '"etag-2"' } });
    }

    // 204 with no body, which is what a CalDAV server answers to a conditional
    // delete it accepted. Present for the same reason the `PUT` branch is: the
    // header the request CARRIED is what the delete cases assert, and there has
    // to be a success for them to assert it against.
    if (method === "DELETE") return new Response(null, { status: 204 });

    // --- one calendar's objects -----------------------------------------
    if (method === "REPORT") {
      const path = new URL(url).pathname;
      const held = objects[path] ?? {};
      const body = String(init?.body ?? "");
      // The first report asks for etags only; the multi-get that follows asks
      // for the data. Both are REPORTs against the same collection URL, so the
      // body is the only thing that tells them apart.
      const entries = Object.entries(held);
      return multistatus(
        body.includes("calendar-multiget")
          ? entries
              .map(([href, data]) => objectDataBody(href, data, etags[href]))
              .join("")
          : entries.map(([href]) => objectHrefBody(href, etags[href])).join(""),
      );
    }

    return new Response(null, { status: 500 });
  }) as typeof globalThis.fetch;

  return state;
}

/**
 * Resolve CalDAV into the real KV binding so later calls are cache hits.
 *
 * Every count assertion below is about what a WARM call costs. Leaving
 * discovery in the count would measure the discovery chain instead, which
 * `test/dav-discovery.test.ts` already owns.
 */
async function warm(stub: Stub): Promise<void> {
  vi.stubGlobal("fetch", stub.fetch);
  // Cleared first. The pool's storage is not reset between cases in this
  // suite, and a `warm` that silently found an entry already there would
  // assert a miss that cannot happen — which is a failing test rather than a
  // wrong one, but only because the miss is asserted.
  await clearDavCache(env, principal, "caldav");
  const resolved = await resolveDavAccount(env, principal, createDavFetch(owner), "caldav");
  expect(resolved.cacheHit).toBe(false);
  stub.observed.length = 0;
}

/**
 * Swap in a differently-configured stub WITHOUT re-running discovery.
 *
 * The cache is already warm from `beforeEach`, and re-warming would assert a
 * miss that cannot happen — so a case that needs different collections or
 * different objects replaces only the conversation, never the cache state.
 */
function restub(options: StubOptions): Stub {
  const next = davStub(options);
  vi.stubGlobal("fetch", next.fetch);
  return next;
}

/** Run something and hand back whatever it threw. */
async function capture(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw, got a resolution");
}

let stub: Stub;

beforeEach(async () => {
  stub = davStub();
  await warm(stub);
  vi.mocked(fetchSubscriptionFeed).mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// CAL-01 — the collection listing
// ---------------------------------------------------------------------------

describe("listCalendars", () => {
  it("costs exactly ONE request on a warm call, not one per calendar", async () => {
    // The library's own calendar-listing helper issues an extra request per
    // collection to read each one's supported report set. On this account that
    // is nine round trips for information no tool here reads.
    await listCalendars(env, principal, createDavFetch(owner));

    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PROPFIND");
  });

  it("returns one row per calendar collection and filters the rest", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));

    // The home collection, the reminders-only calendar and the scheduling
    // inbox are all absent.
    expect(listing.calendars.length).toBe(3);
    expect(
      listing.calendars.map((one) => decodeCalendarId(one.id).collectionUrl),
    ).toEqual([HOME_URL, NOTES_URL, WORK_URL]);
  });

  it("orders rows by collection URL, so two identical calls agree", async () => {
    const first = await listCalendars(env, principal, createDavFetch(owner));
    const second = await listCalendars(env, principal, createDavFetch(owner));

    // Document order is work, notes, home — deliberately not URL order, so an
    // implementation that simply passed the server's order through would fail.
    expect(first.calendars.map((one) => one.id)).toEqual(
      second.calendars.map((one) => one.id),
    );
    expect(first.calendars.map((one) => one.displayName)).toEqual([
      SHARED_NAME,
      "",
      SHARED_NAME,
    ]);
  });

  it("yields an EMPTY display name for one that arrives as an object", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));
    const notes = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === NOTES_URL,
    );

    expect(notes).toBeDefined();
    expect(notes!.displayName).toBe("");
    // The failure this exists to catch is the string form of an object, which
    // reads as a real name at every call site downstream.
    expect(notes!.displayName).not.toContain("object");
  });

  it("keeps two identically-named calendars as two rows with different ids", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));
    const shared = listing.calendars.filter(
      (one) => one.displayName === SHARED_NAME,
    );

    expect(shared.length).toBe(2);
    expect(shared[0].id).not.toBe(shared[1].id);
    // Merging them would silently hide one of the user's calendars.
    expect(new Set(shared.map((one) => one.id)).size).toBe(2);
  });

  it("admits a subscribed (CS:subscribed) collection alongside owned calendars", async () => {
    stub = restub({
      collections: [
        ...COLLECTIONS,
        {
          href: SUBSCRIBED_PATH,
          displayName: "Work",
          resourceType: ["collection", "subscribed"],
          components: ["VEVENT"],
        },
      ],
    });

    const listing = await listCalendars(env, principal, createDavFetch(owner));

    expect(listing.calendars.length).toBe(4);
    const subscribed = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === SUBSCRIBED_URL,
    );
    expect(subscribed).toBeDefined();
    expect(subscribed!.displayName).toBe("Work");
  });

  it("still excludes a subscribed collection with no VEVENT support and a non-calendar collection", async () => {
    stub = restub({
      collections: [
        ...COLLECTIONS,
        {
          // Subscribed, but restricted to VTODO — proves the component-set
          // filter still binds on the subscribed path.
          href: "/1234567890/calendars/subscribed-todo/",
          displayName: "Subscribed Todo",
          resourceType: ["collection", "subscribed"],
          components: ["VTODO"],
        },
        {
          // Neither "calendar" nor "subscribed" — proves the widened check
          // does not over-admit.
          href: "/1234567890/calendars/addressbook-shaped/",
          displayName: "Not a calendar",
          resourceType: ["collection", "addressbook"],
          components: [],
        },
      ],
    });

    const listing = await listCalendars(env, principal, createDavFetch(owner));

    expect(listing.calendars.length).toBe(3);
    const urls = listing.calendars.map(
      (one) => decodeCalendarId(one.id).collectionUrl,
    );
    expect(urls).not.toContain(
      "https://p42-caldav.icloud.com/1234567890/calendars/subscribed-todo/",
    );
    expect(urls).not.toContain(
      "https://p42-caldav.icloud.com/1234567890/calendars/addressbook-shaped/",
    );
  });

  it("returns an empty array for a home set holding no calendar", async () => {
    stub = restub({
      collections: [
        {
          href: "/1234567890/calendars/",
          resourceType: ["collection"],
          components: [],
        },
      ],
    });

    const listing = await listCalendars(env, principal, createDavFetch(owner));

    expect(listing.calendars).toEqual([]);
  });

  it("reports whether discovery came from cache", async () => {
    const warmListing = await listCalendars(env, principal, createDavFetch(owner));
    expect(warmListing.cacheHit).toBe(true);
  });

  it("carries the colour when the collection declares one", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));
    const work = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === WORK_URL,
    );

    expect(work!.color).toBe("#1f77b4");
    const notes = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === NOTES_URL,
    );
    expect(notes!.color).toBeNull();
  });

  it("puts no hostname in any row", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));

    expect(JSON.stringify(listing)).not.toContain("p42-caldav");
    expect(JSON.stringify(listing)).not.toContain("icloud.com");
  });
});

// ---------------------------------------------------------------------------
// CAL-02 and CAL-05 — the bounded expanded range
// ---------------------------------------------------------------------------

/** Every event across every page, walked to exhaustion. */
async function walk(pageSize: number): Promise<EventSummary[]> {
  const collected: EventSummary[] = [];
  let cursor: string | undefined;
  // Bounded so a cursor that fails to advance fails the test rather than
  // hanging the suite.
  for (let page = 0; page < 50; page += 1) {
    const result = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize,
      cursor,
    });
    collected.push(...result.events);
    if (!result.hasMore) return collected;
    expect(result.nextCursor).not.toBeNull();
    cursor = result.nextCursor!;
  }
  throw new Error("the cursor never reached the end of the listing");
}

/**
 * A page-one cursor in the shape the account-wide listing used to mint.
 *
 * Hand-built, because `encodeCalendarCursor` refuses this shape now — a cursor
 * must name its one calendar, and this one records `null`. That is precisely
 * what makes it the IN-FLIGHT case: a model handed such a token before
 * `calendarId` became required may still be holding it.
 *
 * Every other field is what a live token carries, so a case using it fails for
 * the scope and for nothing else. `test/dav-ids.test.ts` proves that at the
 * codec by decoding the identical payload with a calendar in the slot.
 */
function legacyUnscopedCursor(): string {
  const payload = JSON.stringify({
    v: DAV_TOKEN_VERSION,
    k: "q",
    rs: RANGE_START,
    re: RANGE_END,
    s: null,
    kt: null,
    at: null,
    ls: RANGE_START,
    lc: WORK_URL,
    lo: `${WORK_URL}weekly.ics`,
    lr: null,
  });
  const bytes = new TextEncoder().encode(payload);
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// The events path against a subscribed calendar (quick task 260822-h1c).
//
// Two halves, mirroring the plan's own split: the REFUSAL, when a subscribed
// collection has no readable CS:source, and the FEED-BACKED path, when it
// does. The refusal cases use the stub's real collection enumeration
// (SUBSCRIBED_COLLECTION carries no `source`); the feed-backed cases mock
// `fetchSubscriptionFeed` directly, so `collectFromFeed`'s own call is
// exercised without a second network layer underneath it.
// ---------------------------------------------------------------------------

const AUG_22_2026 = at("2026-08-22T00:00:00Z");
const AUG_23_2026 = at("2026-08-23T00:00:00Z");

/** One VEVENT block for the mocked subscription feed. */
function feedVevent(event: {
  uid: string;
  summary: string;
  dtstart: string;
  dtend: string;
  tzid: string;
}): string {
  return [
    "BEGIN:VEVENT",
    `UID:${event.uid}`,
    "DTSTAMP:20260801T000000Z",
    `SUMMARY:${event.summary}`,
    `DTSTART;TZID=${event.tzid}:${event.dtstart}`,
    `DTEND;TZID=${event.tzid}:${event.dtend}`,
    "END:VEVENT",
  ].join("\r\n");
}

/**
 * A small mocked feed: four independent VEVENTs, distinct UIDs, one whose
 * summary is the reported live event, one carrying a zone this project
 * cannot resolve — the two shapes the debug session measured live.
 */
const MOCKED_FEED_EVENTS = [
  {
    uid: "r003-bellevue-square@sm-cal.apple.com",
    summary: "R003 - Bellevue Square",
    dtstart: "20260822T130000",
    dtend: "20260822T220000",
    tzid: "US/Pacific",
  },
  {
    uid: "weekly-standup@sm-cal.apple.com",
    summary: "Weekly standup",
    dtstart: "20260822T090000",
    dtend: "20260822T093000",
    tzid: "US/Pacific",
  },
  {
    uid: "untranslatable-zone@sm-cal.apple.com",
    summary: "Interview follow-up",
    dtstart: "20260822T160000",
    dtend: "20260822T170000",
    tzid: "Fictional/Zone",
  },
  {
    uid: "quarterly-review@sm-cal.apple.com",
    summary: "Quarterly review",
    dtstart: "20260822T110000",
    dtend: "20260822T120000",
    tzid: "US/Pacific",
  },
];

const MOCKED_FEED_ICS = `${[
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "CALSCALE:GREGORIAN",
  "METHOD:PUBLISH",
  "X-CALENDARSERVER-ACCESS:PUBLIC",
  ...MOCKED_FEED_EVENTS.map(feedVevent),
  "END:VCALENDAR",
].join("\r\n")}\r\n`;

describe("the events path against a subscribed calendar", () => {
  describe("the refusal, when there is no readable source", () => {
    beforeEach(() => {
      stub = restub({
        collections: [
          ...COLLECTIONS,
          { ...SUBSCRIBED_COLLECTION, source: undefined },
        ],
      });
    });

    it("listEvents throws DavSubscriptionError, never DavNotFoundError", async () => {
      const error = await capture(() =>
        listEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          rangeStart: RANGE_START,
          rangeEnd: RANGE_END,
        }),
      );

      expect(error).toBeInstanceOf(DavSubscriptionError);
      expect(error).not.toBeInstanceOf(DavNotFoundError);
    });

    it("searchEvents throws the same refusal", async () => {
      const error = await capture(() =>
        searchEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          keyword: "anything",
          rangeStart: RANGE_START,
          rangeEnd: RANGE_END,
        }),
      );

      expect(error).toBeInstanceOf(DavSubscriptionError);
      expect(error).not.toBeInstanceOf(DavNotFoundError);
    });

    it("fires BEFORE any calendar-query REPORT — one request, the enumeration only", async () => {
      await capture(() =>
        listEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          rangeStart: RANGE_START,
          rangeEnd: RANGE_END,
        }),
      );

      expect(stub.observed.length).toBe(1);
      expect(stub.observed[0]!.method).toBe("PROPFIND");
      expect(stub.observed.some((one) => one.method === "REPORT")).toBe(false);
    });

    it("refuses identically for a narrow range and a wide one — this is about the collection, not the answer's size", async () => {
      // Both VALID ranges (assertRange refuses a zero-width or over-cap span
      // before this ever runs) — narrow enough to hold nothing and wide
      // enough to hold everything, and the refusal does not tell them apart.
      const narrow = await capture(() =>
        listEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          rangeStart: RANGE_START,
          rangeEnd: RANGE_START + 1,
        }),
      );
      const wide = await capture(() =>
        listEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          rangeStart: RANGE_START,
          rangeEnd: RANGE_END,
        }),
      );

      expect(narrow).toBeInstanceOf(DavSubscriptionError);
      expect(wide).toBeInstanceOf(DavSubscriptionError);
    });

    it("leaves an owned calendar in the SAME account answering normally — the differential control", async () => {
      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
      });

      expect(page.events.length).toBeGreaterThan(0);
    });
  });

  describe("the feed-backed path, when the source is readable", () => {
    beforeEach(() => {
      stub = restub({ collections: [...COLLECTIONS, SUBSCRIBED_COLLECTION] });
      vi.mocked(fetchSubscriptionFeed).mockResolvedValue(MOCKED_FEED_ICS);
    });

    it("returns one row per VEVENT, each with a distinct id", async () => {
      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
        pageSize: 100,
      });

      expect(page.events.length).toBe(MOCKED_FEED_EVENTS.length);
      expect(new Set(page.events.map((one) => one.id)).size).toBe(
        MOCKED_FEED_EVENTS.length,
      );
      expect(new Set(page.events.map((one) => one.summary)).size).toBe(
        MOCKED_FEED_EVENTS.length,
      );
    });

    it("resolves the reported event to the correct Pacific instant", async () => {
      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
        pageSize: 100,
      });

      const reported = page.events.find(
        (one) => one.summary === "R003 - Bellevue Square",
      );
      expect(reported).toBeDefined();
      expect(reported!.timezoneUnresolved).toBe(false);
      // 2026-08-22T20:00:00Z -- 13:00 US/Pacific in August is PDT, UTC-7.
      expect(reported!.startUtc).toBe(1787428800);
    });

    it("leaves the untranslatable zone honestly unresolved, never a guessed instant", async () => {
      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
        pageSize: 100,
      });

      const untranslatable = page.events.find(
        (one) => one.summary === "Interview follow-up",
      );
      expect(untranslatable).toBeDefined();
      expect(untranslatable!.timezoneUnresolved).toBe(true);
      expect("startUtc" in untranslatable!).toBe(false);
    });

    it("resumes correctly across pages — no row repeated, none skipped, has-more accurate", async () => {
      const ids: string[] = [];
      let cursor: string | undefined;
      let sawFinalPage = false;

      for (let guard = 0; guard < 20; guard += 1) {
        const page = await listEvents(env, principal, createDavFetch(owner), {
          calendarId: SUBSCRIBED_ID,
          rangeStart: AUG_22_2026,
          rangeEnd: AUG_23_2026,
          pageSize: 1,
          cursor,
        });
        for (const row of page.events) ids.push(row.id);
        if (!page.hasMore) {
          sawFinalPage = true;
          break;
        }
        expect(page.nextCursor).not.toBeNull();
        cursor = page.nextCursor!;
      }

      expect(sawFinalPage).toBe(true);
      expect(ids.length).toBe(MOCKED_FEED_EVENTS.length);
      expect(new Set(ids).size).toBe(MOCKED_FEED_EVENTS.length);
    });

    it("searchEvents with a keyword returns only the matching row", async () => {
      const page = await searchEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        keyword: "Bellevue",
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
        pageSize: 100,
      });

      expect(page.events.length).toBe(1);
      expect(page.events[0]!.summary).toBe("R003 - Bellevue Square");
    });

    it("calls the mock with collection.source and nothing else — no credential-bearing argument", async () => {
      await listEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
      });

      expect(vi.mocked(fetchSubscriptionFeed)).toHaveBeenCalledTimes(1);
      expect(vi.mocked(fetchSubscriptionFeed)).toHaveBeenCalledWith(FEED_URL);
    });

    it("never leaks the feed host into a calendar_list_calendars-shaped listing or an events page", async () => {
      const listing = await listCalendars(env, principal, createDavFetch(owner));
      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: SUBSCRIBED_ID,
        rangeStart: AUG_22_2026,
        rangeEnd: AUG_23_2026,
        pageSize: 100,
      });

      // Both the raw service-layer shapes and the tool-shaped results the
      // model actually receives -- the single most safety-critical assertion
      // this task adds, now that the feed is actually being read from.
      for (const serialized of [
        JSON.stringify(listing),
        JSON.stringify(page),
        JSON.stringify(calendarListToolResult(listing)),
        JSON.stringify(eventPageToolResult(page)),
      ]) {
        expect(serialized).not.toContain(FEED_URL);
        expect(serialized).not.toContain("sm-cal.apple.com");
      }
    });
  });
});

describe("listEvents", () => {
  it("refuses a range wider than the cap without touching the network", async () => {
    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_START + (MAX_RANGE_DAYS + 1) * 86400,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    // The cheapest refusal is the one that spends none of the connection
    // budget — not one KV read, not one request.
    expect(stub.observed.length).toBe(0);
  });

  it("admits a range exactly at the cap", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_START + MAX_RANGE_DAYS * 86400,
    });

    expect(page.events.length).toBeGreaterThan(0);
  });

  it("returns an empty page for a range holding nothing", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: at("2019-01-01T00:00:00Z"),
      rangeEnd: at("2019-02-01T00:00:00Z"),
    });

    expect(page.events).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    expect(page.truncated).toBe(false);
  });

  it("expands a recurring series to the occurrences it actually has", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    const work = page.events.filter(
      (one) => decodeEventId(one.id).calendarUrl === WORK_URL,
    );

    // Twelve Mondays fall in the quarter; the nineteenth of January is
    // excluded and is simply absent.
    expect(work.length).toBe(12);
    expect(work.map((one) => one.startLocal)).not.toContain("2026-01-19T09:00:00");

    // The moved occurrence appears ONCE, at its moved time, under its own
    // summary — and keeps the master series' recurrence id.
    const moved = work.filter((one) => one.summary === WEEKLY_SERIES_OVERRIDE_SUMMARY);
    expect(moved.length).toBe(1);
    expect(moved[0].startLocal).toBe("2026-01-26T11:30:00");
    expect(moved[0].isOverride).toBe(true);
    expect(moved[0].recurrenceId).toBe("20260126T090000");

    const ordinary = work.filter((one) => one.summary === WEEKLY_SERIES_SUMMARY);
    expect(ordinary.length).toBe(11);
    expect(ordinary.every((one) => one.isRecurring)).toBe(true);
    expect(ordinary.every((one) => one.isOverride)).toBe(false);
  });

  it("orders occurrences by instant, then object, then recurrence", async () => {
    // One calendar holding all three resource shapes. The order used to be
    // exercised across the account's three calendars; a listing is scoped to
    // one now, so the mixture has to live inside it — see `MIXED_OBJECTS`. The
    // calendar component of the order is unreachable from any page and is
    // asserted over the comparator itself in `test/dav-ids.test.ts`.
    stub = restub({ objects: MIXED_OBJECTS });

    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    // Every row that HAS an instant is non-decreasing. The all-day and
    // unresolved rows have none, which is exactly why the order rides a
    // derived key rather than this field.
    const instants = page.events
      .map((one) => one.startUtc)
      .filter((one): one is number => one !== undefined);
    expect([...instants].sort((a, b) => a - b)).toEqual(instants);

    // Non-vacuity for the line above: the rows WITHOUT an instant are the
    // reason the order cannot ride `startUtc`, so a fixture that produced none
    // of them would leave that assertion proving nothing.
    expect(
      page.events.filter((one) => one.startUtc === undefined).length,
    ).toBe(4);

    // Sixteen occurrences: twelve from the series, three all-day, one floating.
    expect(page.events.length).toBe(16);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  it("pages every occurrence exactly once, with no duplicate and no gap", async () => {
    const single = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });
    const walked = await walk(5);

    expect(walked.map((one) => one.id)).toEqual(single.events.map((one) => one.id));
    expect(new Set(walked.map((one) => one.id)).size).toBe(walked.length);
  });

  it("pages across a TIE on the first two order components exactly once", async () => {
    stub = restub({
      objects: {
        [WORK_PATH]: {
          [`${WORK_PATH}tie-a.ics`]: TIE_A_ICS,
          [`${WORK_PATH}tie-b.ics`]: TIE_B_ICS,
        },
      },
    });

    const single = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });
    expect(single.events.length).toBe(2);
    expect(single.events[0].startUtc).toBe(single.events[1].startUtc);

    // One row per page, so the cursor is minted from — and resumed across —
    // the tie boundary itself.
    const walked = await walk(1);
    expect(walked.map((one) => one.id)).toEqual(single.events.map((one) => one.id));
    expect(new Set(walked.map((one) => one.id)).size).toBe(2);
  });

  it("computes has-more from one extra row and mints the cursor from the last returned", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 5,
    });

    expect(page.events.length).toBe(5);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).not.toBeNull();

    const cursor = decodeCalendarCursor(page.nextCursor!, RANGE_START, RANGE_END);
    const last = decodeEventId(page.events[4].id);
    // Minted from row five, never from the sixth row that only proved there
    // was more.
    expect(cursor.lastObjectUrl).toBe(last.objectUrl);
    expect(cursor.lastCalendarUrl).toBe(last.calendarUrl);
    expect(cursor.lastRecurrenceId).toBe(last.recurrenceId);
  });

  it("costs THREE serial round trips, whatever the account holds", async () => {
    // This case used to assert nineteen round trips issued one at a time across
    // the account's calendars. That listing was withdrawn: `calendarId` is
    // required, so a page reaches exactly one collection and the count no
    // longer depends on how many calendars the account has. The fixture still
    // advertises several, which is what makes the count below a measurement
    // rather than a restatement of the stub.
    await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.observed.length; index += 1) {
      expect(stub.observed[index].start).toBeGreaterThan(
        stub.observed[index - 1].end,
      );
    }
    // One collection listing plus the library's two reports against the single
    // named calendar. Three, on an account advertising five collections.
    expect(stub.observed.filter((one) => one.method === "PROPFIND").length).toBe(1);
    expect(stub.observed.filter((one) => one.method === "REPORT").length).toBe(2);
    expect(stub.observed.length).toBe(3);

    // And the two other calendars holding events were never asked at all —
    // which is the whole saving, and the assertion that would have failed
    // before the account-wide form was withdrawn.
    const reported = new Set(
      stub.observed
        .filter((one) => one.method === "REPORT")
        .map((one) => new URL(one.url).pathname),
    );
    expect(reported).toEqual(new Set([WORK_PATH]));
  });

  it("has NOWHERE to put a long free-text body", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 1,
    });

    const keys = Object.keys(JSON.parse(JSON.stringify(page.events[0])));
    expect(keys).not.toContain("description");
    expect(keys).not.toContain("body");
    expect(keys).not.toContain("notes");
    // The row type cannot express the violation, so a later edit cannot
    // introduce one without changing the type.
    expect(JSON.stringify(page)).not.toContain("Standing sync for the team");
  });

  it("reports the attendee COUNT and no attendee identity", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });
    const ordinary = page.events.find(
      (one) => one.summary === WEEKLY_SERIES_SUMMARY,
    );

    expect(ordinary!.attendeeCount).toBe(1);
    expect(JSON.stringify(page)).not.toContain("dev.whitaker");
    expect(JSON.stringify(page)).not.toContain("priya.raman");
  });

  it("keeps the instant ABSENT when the zone did not resolve", async () => {
    // The notes calendar, because that is where the fixture's floating-zone
    // resource lives and a listing no longer sweeps the account to find it.
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: NOTES_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });
    const unresolved = page.events.find((one) => one.timezoneUnresolved);

    expect(unresolved).toBeDefined();
    // Absent, not zero and not the derived sort key. `in` rather than an
    // undefined comparison, because those are different claims.
    expect("startUtc" in unresolved!).toBe(false);
    expect("endUtc" in unresolved!).toBe(false);
    expect(unresolved!.startTzid).toBe("Australia/Sydney");
  });

  it("never publishes the derived sort key on a row", async () => {
    // Notes again: the unresolved row is the one whose sort key is a number
    // this server invented, so it is the only row that can leak one.
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: NOTES_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    for (const one of page.events) {
      expect(Object.keys(one)).not.toContain("sortInstant");
    }
    // The unresolved row's sort key is the wall clock read as if UTC. If it
    // leaked into the row it would appear as a plausible instant.
    const leaked = at("2026-03-10T14:00:00Z");
    const unresolved = page.events.find((one) => one.timezoneUnresolved);
    expect(JSON.stringify(unresolved)).not.toContain(String(leaked));
  });

  it("keeps an all-day occurrence date-only with no instant", async () => {
    // The home calendar holds the all-day series.
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: HOME_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });
    const allDay = page.events.filter((one) => one.allDay);

    expect(allDay.length).toBe(3);
    expect(allDay.map((one) => one.startLocal)).toEqual([
      "2026-03-02",
      "2026-03-03",
      "2026-03-04",
    ]);
    expect(allDay.every((one) => !("startUtc" in one))).toBe(true);
  });

  it("reports truncation as a flag rather than a silently short list", async () => {
    stub = restub({
      objects: { [WORK_PATH]: { [`${WORK_PATH}minutely.ics`]: MINUTELY_ICS } },
    });

    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: at("2026-01-01T00:00:00Z"),
      rangeEnd: at("2026-01-03T00:00:00Z"),
      pageSize: 5,
    });

    expect(page.truncated).toBe(true);
    expect(page.events.length).toBe(5);
    expect(page.hasMore).toBe(true);
  });

  it("leaves truncation false when nothing was cut", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    expect(page.truncated).toBe(false);
    expect(MAX_EXPANDED_OCCURRENCES).toBeGreaterThan(page.events.length);
  });

  /**
   * The aggregate axis (03-REVIEW.md WR-01).
   *
   * The two fixtures below are identical except for four resources, and that
   * is the whole experiment: the control proves the page reaches every ordinary
   * resource and returns all three events, and the case proves that four
   * resources which return NOTHING stop it — which can only happen if the
   * allowance is shared. With a per-resource cap alone the case's rows all come
   * back, having cost a million wasted steps on the way.
   *
   * **The axis used to be measured across the account's three calendars and is
   * now measured across one calendar's three resources.** That is forced rather
   * than chosen: a listing is scoped to a single collection since `calendarId`
   * became required, so there is no longer a second calendar for an exhausted
   * budget to skip. What survives is the property that actually distinguishes
   * the two designs — an allowance spent by earlier resources starves later
   * ones on the SAME page — and it survives intact, because the per-resource
   * cap alone would parse every ordinary resource here regardless.
   *
   * This case is the one test in this file that spends real CPU — about a
   * million iterator steps, three seconds of it. That is not incidental, it is
   * the measurement: the cap is a CPU ceiling, and the only honest way to prove
   * a ceiling binds is to reach it. The old behaviour on this same fixture is
   * `4 × 250,000` in the one calendar, which is where the isolate dies with no
   * flag set and no rows returned.
   */
  const CONTROL_OBJECTS = {
    [WORK_PATH]: {
      [`${WORK_PATH}ordinary-a.ics`]: ORDINARY_ICS,
      [`${WORK_PATH}ordinary-b.ics`]: ORDINARY_ICS,
      [`${WORK_PATH}ordinary-c.ics`]: ORDINARY_ICS,
    },
  };

  const STARVED_RANGE = {
    rangeStart: at("2026-01-01T00:00:00Z"),
    rangeEnd: at("2026-01-02T00:00:00Z"),
  };

  it("returns every ordinary resource's event when nothing exhausts the allowance", async () => {
    // The control. Non-vacuity for the case below: without it, a fixture that
    // simply never produced rows would satisfy every assertion there.
    stub = restub({ objects: CONTROL_OBJECTS });

    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      ...STARVED_RANGE,
      pageSize: 25,
    });

    expect(page.truncated).toBe(false);
    expect(page.events).toHaveLength(3);
  });

  it(
    "holds ONE step allowance across the whole page rather than one per resource",
    async () => {
      // Four starvers at a quarter-million each is the million-step ceiling, so
      // the allowance is gone before the fifth object of the page.
      //
      // Only the named calendar is loaded, and that is not a simplification of
      // the old three-calendar fixture — it is the whole account a scoped
      // listing can reach. The enumeration-order caveat the old fixture carried
      // (which calendar the page visits first is a property of the stub, not of
      // the code) is gone with it: there is one collection, and the order that
      // matters now is the object order INSIDE it, which the stub preserves.
      const starved: Record<string, Record<string, string>> = { [WORK_PATH]: {} };
      const held = starved[WORK_PATH];
      for (let n = 1; n <= 4; n += 1) held[`${WORK_PATH}starver-${n}.ics`] = starverIcs(n);
      // Inserted LAST, and the insertion order is load-bearing: the stub
      // answers a multi-get in `Object.entries` order, which for these
      // non-numeric keys is insertion order, and these events are here to be
      // the resources the exhausted budget refuses to parse. Three of them,
      // matching the control exactly, so the two runs differ by the starvers
      // and by nothing else.
      for (const suffix of ["a", "b", "c"]) {
        held[`${WORK_PATH}ordinary-${suffix}.ics`] = ORDINARY_ICS;
      }

      stub = restub({ objects: starved });

      const page = await listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        ...STARVED_RANGE,
        pageSize: 25,
      });

      // Truncated rather than merely short. The flag is the entire difference
      // between this and the failure WR-01 describes, where the isolate is
      // killed and the caller is told nothing at all.
      expect(page.truncated).toBe(true);

      // The control returns three of these over the identical three resources.
      // Here none is parsed at all, because four earlier resources on the SAME
      // page spent the page's whole allowance — so the page is empty and says
      // so. This is the assertion that separates a shared allowance from a
      // per-resource one: under a per-resource cap each starver would be cut at
      // its own quarter-million and all three ordinary events would still come
      // back, a million wasted steps later.
      expect(page.events).toEqual([]);
    },
    30_000,
  );

  it("scopes to one calendar when given one", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));
    const work = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === WORK_URL,
    );
    stub.observed.length = 0;

    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: work!.id,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    expect(page.events.length).toBe(12);
    expect(
      page.events.every((one) => decodeEventId(one.id).calendarUrl === WORK_URL),
    ).toBe(true);
    // One collection listing plus the two reports for the single calendar.
    expect(stub.observed.filter((one) => one.method === "REPORT").length).toBe(2);
  });

  it("refuses a calendar id this account does not have", async () => {
    const foreign = encodeCalendarId({
      collectionUrl: "https://p42-caldav.icloud.com/1234567890/calendars/gone/",
    });

    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: foreign,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
  });

  it("refuses a malformed calendar id before any request", async () => {
    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: "not-a-token",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a cursor minted for a different range before any request", async () => {
    const first = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 5,
    });
    stub.observed.length = 0;

    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END - 86400,
        pageSize: 5,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a cursor minted for a different calendar scope", async () => {
    const scoped = encodeCalendarCursor({
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      scope: WORK_URL,
      keywordTerm: null,
      attendeeTerm: null,
      lastSortInstant: RANGE_START,
      lastCalendarUrl: WORK_URL,
      lastObjectUrl: `${WORK_URL}weekly.ics`,
      lastRecurrenceId: null,
    });
    stub.observed.length = 0;

    // A position recorded against the work calendar's listing means nothing
    // against the home calendar's, and the decoder cannot see the difference:
    // it pins the range and checks the scope NAMES a calendar, but it has no
    // requested calendar to compare against. This is the comparison that
    // catches it, and it runs before any request.
    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: HOME_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: scoped,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses an IN-FLIGHT cursor from before the calendar became required", async () => {
    // The published-contract half of this change, asserted at the seam a user
    // is actually exposed through. `calendar_list_events` was optional-calendar
    // until today; a page-one token minted then records NO calendar, and a
    // model may be holding one right now. It fails CLOSED — refused at the
    // codec, before the scope comparison above and before any request — rather
    // than being silently reinterpreted as a page of whatever calendar the
    // caller names next.
    //
    // Hand-minted, because `encodeCalendarCursor` can no longer produce the
    // shape. `test/dav-ids.test.ts` carries the non-vacuity: the identical
    // payload with a calendar in the slot decodes cleanly.
    const inFlight = legacyUnscopedCursor();
    stub.observed.length = 0;

    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: inFlight,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    // Non-rediscoverable: re-resolving the account's home URLs cannot repair a
    // token minted for a listing this server no longer performs, so a retry
    // would spend a real PROPFIND to reach the identical answer.
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
    expect(stub.observed.length).toBe(0);
  });

  it("clamps an oversized page size rather than refusing it", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100000,
    });

    // Twelve: the work calendar's whole quarter, not the account's sixteen.
    expect(page.events.length).toBe(12);
    expect(page.hasMore).toBe(false);
  });

  it("reports whether discovery came from cache", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
    });

    expect(page.cacheHit).toBe(true);
  });

  it("puts no hostname on any row", async () => {
    const page = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
    });

    expect(JSON.stringify(page.events)).not.toContain("p42-caldav");
    expect(JSON.stringify(page.events)).not.toContain("icloud.com");
  });
});

// ---------------------------------------------------------------------------
// CAL-03 — one event's full detail
//
// Three properties here are silent failures and each has a case built to make
// the silence audible:
//
//   1. The round-trip COUNT. A detail fetch that enumerates the account's
//      collections first and one that addresses the resource directly return
//      identical output; only a counter tells them apart, and on this account
//      the difference is one request against nineteen.
//   2. The SUBSTITUTED occurrence. A recurrence id the resource no longer
//      produces has a nearest neighbour, and returning it looks completely
//      normal — a meeting, at a plausible time, that the user never asked
//      about. Only an explicit refusal case can see the difference.
//   3. The ABSENT instant. An all-day date and an unresolved zone both have no
//      instant, and a midnight guess reads as a fact. `in` rather than an
//      undefined comparison throughout, because those are different claims.
// ---------------------------------------------------------------------------

/** The range holding `NO_END_TIME_ICS`, which starts after the default one. */
const APRIL_START = at("2026-04-01T00:00:00Z");
const APRIL_END = at("2026-05-01T00:00:00Z");

/**
 * One opaque id, taken from a real listing.
 *
 * Round-tripping through the listing is the contract CAL-03 actually states —
 * "by the opaque id a listing returned" — and it is also what keeps these cases
 * from hard-coding a recurrence-id spelling the expander owns.
 */
async function idFromListing(
  match: (row: EventSummary) => boolean,
  options: Partial<{
    rangeStart: number;
    rangeEnd: number;
    /** Defaults to work, which holds the weekly series most cases want. */
    calendarId: string;
  }> = {},
): Promise<string> {
  const page = await listEvents(env, principal, createDavFetch(owner), {
    calendarId: options.calendarId ?? WORK_ID,
    rangeStart: options.rangeStart ?? RANGE_START,
    rangeEnd: options.rangeEnd ?? RANGE_END,
    pageSize: 100,
  });
  const row = page.events.find(match);
  expect(row, "no listing row matched").toBeDefined();
  return row!.id;
}

describe("getEvent", () => {
  it("costs exactly ONE request, addressing the resource directly", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);
    stub.observed.length = 0;

    await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    // One multi-get. No collection enumeration: the calendar URL is inside the
    // token, so resolving it costs no lookup — the argument that chose this
    // identifier shape over the resource's own internal one.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("REPORT");
  });

  it("returns the wall clock, the zone the organiser chose, and the instant", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    // The zone is carried ON the start and the end rather than as a separate
    // top-level field — the value a user actually needs, and precisely the one
    // server-side expansion would have destroyed.
    expect(detail.startTzid).toBe("America/Chicago");
    expect(detail.endTzid).toBe("America/Chicago");
    expect(detail.startLocal).toBe("2026-01-05T09:00:00");
    expect(detail.endLocal).toBe("2026-01-05T09:30:00");
    // 09:00 America/Chicago on 2026-01-05 is 15:00 UTC.
    expect(detail.startUtc).toBe(at("2026-01-05T15:00:00Z"));
    expect(detail.allDay).toBe(false);
  });

  it("returns the description, the organiser and every attendee as data", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    expect(detail.description).toBe(WEEKLY_SERIES_DESCRIPTION);
    expect(detail.organizer).toEqual({
      name: "Priya Raman",
      scheduleStatus: null,
      email: "priya.raman@example.invalid",
      partstat: null,
      role: null,
    });
    expect(detail.attendees).toEqual([
      {
        name: "Dev Whitaker",
        email: "dev.whitaker@example.invalid",
        partstat: "ACCEPTED",
        role: "REQ-PARTICIPANT",
        // Nobody's server has said anything about this one. Null is what a
        // resource that carries no delivery-status parameter reports, and it is
        // what `deliveryReportOf` reads as `unreported`.
        scheduleStatus: null,
      },
    ]);
    expect(detail.attendeeCount).toBe(1);
  });

  it("preserves the zone the resource ASKED for and flags it unresolved", async () => {
    const id = await idFromListing((one) => one.timezoneUnresolved, {
      calendarId: NOTES_ID,
    });

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    expect(detail.timezoneUnresolved).toBe(true);
    // The requested identifier is the only evidence there is, so it is what
    // gets reported rather than a zone this server guessed.
    expect(detail.startTzid).toBe("Australia/Sydney");
    expect("startUtc" in detail).toBe(false);
    expect("endUtc" in detail).toBe(false);
  });

  it("never publishes the derived sort key on a detail", async () => {
    const id = await idFromListing((one) => one.timezoneUnresolved, {
      calendarId: NOTES_ID,
    });

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    // The unresolved row's sort key is its wall clock read as if UTC. Published
    // as an instant it would look entirely plausible.
    const leaked = at("2026-03-10T14:00:00Z");
    expect(JSON.stringify(detail)).not.toContain(String(leaked));
    expect(Object.keys(detail)).not.toContain("sortInstant");
  });

  it("keeps an all-day event's dates with NO instant field at all", async () => {
    const id = await idFromListing((one) => one.allDay, {
      calendarId: HOME_ID,
    });

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    expect(detail.allDay).toBe(true);
    expect(detail.startLocal).toBe("2026-03-02");
    // Exclusive: 03-02 through 03-03 is ONE day, not two.
    expect(detail.endLocal).toBe("2026-03-03");
    const serialised = JSON.parse(JSON.stringify(detail)) as Record<string, unknown>;
    expect("startUtc" in serialised).toBe(false);
    expect("endUtc" in serialised).toBe(false);
  });

  it("returns an end equal to the start when the event carries none", async () => {
    const next = restub({
      objects: { [WORK_PATH]: { [`${WORK_PATH}noend.ics`]: NO_END_TIME_ICS } },
    });
    const id = await idFromListing((one) => one.summary === "Reminder with no end time", {
      rangeStart: APRIL_START,
      rangeEnd: APRIL_END,
    });
    next.observed.length = 0;

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    expect(detail.startLocal).toBe("2026-04-15T13:00:00");
    expect(detail.endLocal).toBe(detail.startLocal);
    expect(detail.endUtc).toBe(detail.startUtc);
  });

  it("returns the MOVED time and the MOVED summary under the master's key", async () => {
    const id = await idFromListing((one) => one.isOverride);

    const ref = decodeEventId(id);
    const detail = await getEvent(env, principal, createDavFetch(owner), ref);

    // The recurrence id is the slot the occurrence was moved OUT of, which is
    // what makes it stable across the edit.
    expect(ref.recurrenceId).toBe("20260126T090000");
    expect(detail.recurrenceId).toBe("20260126T090000");
    expect(detail.summary).toBe(WEEKLY_SERIES_OVERRIDE_SUMMARY);
    expect(detail.startLocal).toBe("2026-01-26T11:30:00");
    expect(detail.isOverride).toBe(true);
  });

  it("refuses a recurrence the resource no longer produces, with no nearest match", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);
    const ref = decodeEventId(id);
    const gone = encodeEventId({ ...ref, recurrenceId: "20260107T090000" });
    stub.observed.length = 0;

    const error = await capture(() =>
      getEvent(env, principal, createDavFetch(owner), decodeEventId(gone)),
    );

    // A silently substituted meeting is a worse answer than none.
    expect(error).toBeInstanceOf(DavNotFoundError);
  });

  it("marks the recurrence-absent refusal NON-rediscoverable", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);
    const ref = decodeEventId(id);
    const gone = encodeEventId({ ...ref, recurrenceId: "20260107T090000" });
    stub.observed.length = 0;

    const error = await capture(() =>
      getEvent(env, principal, createDavFetch(owner), decodeEventId(gone)),
    );

    // A local selection failure over bytes already in hand. Marking it
    // rediscoverable would spend a discovery round trip and a retry on every
    // lookup of a deleted occurrence and arrive at the identical answer.
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
    // Exactly the one multi-get, and nothing after it.
    expect(stub.observed.length).toBe(1);
  });

  it("returns deep-equal output twice against unchanged bytes", async () => {
    const id = await idFromListing((one) => one.isOverride);

    const first = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));
    const second = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    // Re-expansion is deterministic given the same bytes, which is the property
    // that lets an occurrence id be a POSITION in a series rather than a stored
    // row.
    expect(second).toEqual(first);
  });

  it("re-discovers ONCE and retries ONCE against a cached host, then stops", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);
    const ref = decodeEventId(id);

    let reports = 0;
    const next = restub({
      onRequest: (_url, method) => {
        if (method !== "REPORT") return null;
        reports += 1;
        return new Response(null, { status: 404 });
      },
    });

    const error = await capture(() => getEvent(env, principal, createDavFetch(owner), ref));

    // Two attempts, never three. `allowRediscovery` is a parameter that is
    // false on the retry and is read before the error is classified, so there
    // is no branch from the retry to a third attempt.
    expect(reports).toBe(2);
    expect(error).toBeInstanceOf(DavNotFoundError);
    // And discovery actually re-ran between them, rather than the operation
    // simply being called twice.
    expect(
      next.observed.filter((one) => one.url.startsWith(CALDAV_SERVER)).length,
    ).toBeGreaterThan(0);
  });

  it("puts no hostname anywhere in the detail", async () => {
    const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);

    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    expect(JSON.stringify(detail)).not.toContain("p42-caldav");
    expect(JSON.stringify(detail)).not.toContain("icloud.com");
  });

  // -------------------------------------------------------------------------
  // 03-REVIEW.md CR-01 — a forged id must reach no network at all
  //
  // The request COUNT is the assertion that carries the property here. The
  // error type alone would pass even if the request had been made and had
  // failed, and a request that was made is a request that carried
  // `Basic base64(APPLE_ID:APPLE_APP_PASSWORD)` — `./transport.ts` attaches it
  // unconditionally, for any URL. Zero observed requests is the only shape that
  // says the credential never travelled.
  //
  // `attacker.example` rather than a plausible-looking host, and deliberately:
  // `.example` is reserved, so no future reader of this fixture can mistake it
  // for somewhere real.
  // -------------------------------------------------------------------------

  it("refuses a forged id naming a foreign origin, spending NO request", async () => {
    const forged = encodeEventId({
      calendarUrl: "https://attacker.example/1234567890/calendars/work/",
      objectUrl: "https://attacker.example/1234567890/calendars/work/steal.ics",
      recurrenceId: null,
    });

    const error = await capture(() =>
      getEvent(env, principal, createDavFetch(owner), decodeEventId(forged)),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    // The credential never left. The discovery cache is warm from `beforeEach`,
    // so a legitimate call here would have cost exactly one REPORT.
    expect(stub.observed.length).toBe(0);
    // And no discovery retry was spent on it either — a forged id must not be
    // an amplifier against D-60's budget.
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
  });

  it("refuses a LEGITIMATE calendar URL carrying a forged object URL", async () => {
    // The load-bearing case. A collection-only check passes this id: the
    // calendar URL is genuinely this account's, and the object URL is read
    // separately as the multi-get's `objectUrls` entry, so it independently
    // names what the server is asked for.
    const forged = encodeEventId({
      calendarUrl: WORK_URL,
      objectUrl: "https://attacker.example/1234567890/calendars/work/steal.ics",
      recurrenceId: null,
    });

    const error = await capture(() =>
      getEvent(env, principal, createDavFetch(owner), decodeEventId(forged)),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
    expect(stub.observed.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// The detail response's trusted/untrusted split
// ---------------------------------------------------------------------------

/** The two content blocks of a result, as raw text. */
function blocksOf(result: { content: { text: string }[] }): {
  trusted: string;
  untrusted: string;
} {
  expect(result.content.length).toBe(2);
  return { trusted: result.content[0].text, untrusted: result.content[1].text };
}

async function weeklyDetail(): Promise<EventDetail> {
  const id = await idFromListing((one) => one.summary === WEEKLY_SERIES_SUMMARY);
  return getEvent(env, principal, createDavFetch(owner), decodeEventId(id));
}

describe("the event detail response", () => {
  it("puts the attendee and organiser names and addresses INSIDE the fence", async () => {
    const { trusted, untrusted } = blocksOf(eventToolResult(await weeklyDetail()));

    // A display name and an address on an invitation are chosen by whoever
    // sent it, which is the whole test — not whether they look dangerous.
    for (const value of [
      "Priya Raman",
      "priya.raman@example.invalid",
      "Dev Whitaker",
      "dev.whitaker@example.invalid",
      "ACCEPTED",
      "REQ-PARTICIPANT",
    ]) {
      expect(untrusted, `${value} is not fenced`).toContain(value);
      expect(trusted, `${value} escaped the fence`).not.toContain(value);
    }
  });

  it("puts the description, the title and the location INSIDE the fence", async () => {
    const { trusted, untrusted } = blocksOf(eventToolResult(await weeklyDetail()));

    // The longest free-text field in the phase, and it appears only here.
    expect(untrusted).toContain(WEEKLY_SERIES_DESCRIPTION);
    expect(untrusted).toContain(WEEKLY_SERIES_SUMMARY);
    expect(untrusted).toContain("Meeting room two");
    expect(trusted).not.toContain(WEEKLY_SERIES_DESCRIPTION);
    expect(trusted).not.toContain("Meeting room two");
  });

  it("keeps this server's own observations OUTSIDE the fence", async () => {
    const parsed = JSON.parse(blocksOf(eventToolResult(await weeklyDetail())).trusted);

    expect(parsed.cacheHit).toBe(true);
    expect(parsed.attendeeCount).toBe(1);
    expect(parsed.timezoneUnresolved).toBe(false);
    expect(parsed.allDay).toBe(false);
    // The zone identifier used to be asserted HERE, and that expectation was
    // the defect written down as an expectation. It moved to the case below
    // rather than being deleted — an assertion deleted rather than moved is
    // coverage lost silently. `timezoneUnresolved` deliberately stayed: the
    // BOOLEAN is this server's own reading, the IDENTIFIER is the resource's.
    expect("startTzid" in parsed).toBe(false);
    expect("endTzid" in parsed).toBe(false);
  });

  it("puts the zone identifier the resource NAMED inside the fence", async () => {
    // Migrated from the case above (03-09 Task 1, option-a). A TZID is almost
    // always an IANA registry name and reads exactly like a protocol value —
    // but on the unresolved path it is a string the resource asked for and this
    // server could not confirm, which is a stranger's choice. The fence's own
    // test is "did a stranger choose it", so it applies uniformly rather than
    // per-value, and the resolved path rides in the same block as the
    // unresolved one for the same reason `partstat` and `role` do.
    const detail = await weeklyDetail();
    const { trusted, untrusted } = blocksOf(eventToolResult(detail));

    expect(detail.startTzid).toBe("America/Chicago");
    expect(untrusted).toContain("America/Chicago");
    expect(trusted).not.toContain("America/Chicago");
  });

  it("repeats the opaque id on BOTH sides so the halves join by identity", async () => {
    const detail = await weeklyDetail();
    const { trusted, untrusted } = blocksOf(eventToolResult(detail));

    expect(trusted).toContain(detail.id);
    expect(untrusted).toContain(detail.id);
  });

  it("keeps an absent instant ABSENT in the response", async () => {
    const id = await idFromListing((one) => one.timezoneUnresolved, {
      calendarId: NOTES_ID,
    });
    const detail = await getEvent(env, principal, createDavFetch(owner), decodeEventId(id));

    const parsed = JSON.parse(blocksOf(eventToolResult(detail)).trusted);

    expect("startUtc" in parsed).toBe(false);
    expect("endUtc" in parsed).toBe(false);
    expect(parsed.timezoneUnresolved).toBe(true);
  });

  it("is ONE fence per response, and puts no hostname in either block", async () => {
    const result = eventToolResult(await weeklyDetail());
    const { untrusted } = blocksOf(result);

    expect(untrusted.match(/---BEGIN UNTRUSTED /g)?.length).toBe(1);
    expect(JSON.stringify(result)).not.toContain("p42-caldav");
    expect(JSON.stringify(result)).not.toContain("icloud.com");
  });
});

// ---------------------------------------------------------------------------
// CAL-04 — search, which is a LISTING with a filter
//
// The default fixture set is what makes these cases discriminating, so it is
// worth stating what is in it. `weekly.ics` produces twelve occurrences in the
// default range: eleven from the master, which carries the description, the
// organiser and the one attendee, and ONE override, which carries its own
// summary and location and carries none of the three. So a term matching the
// master's people returns eleven and a term matching the override's location
// returns one — two disjoint answers over the same resource, which is the only
// shape that can tell a per-occurrence filter from a per-resource one.
// ---------------------------------------------------------------------------

/** Every occurrence a search returns, walked one small page at a time. */
async function searchWalk(
  options: { keyword?: string; attendee?: string },
  pageSize = 3,
): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | undefined;

  for (let guard = 0; guard < 50; guard += 1) {
    const page = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      ...options,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize,
      cursor,
    });
    for (const row of page.events) ids.push(row.id);
    if (!page.hasMore) return ids;
    expect(page.nextCursor).not.toBeNull();
    cursor = page.nextCursor!;
  }
  throw new Error("the paging walk did not terminate");
}

async function search(options: {
  keyword?: string;
  attendee?: string;
}): Promise<EventSummary[]> {
  const page = await searchEvents(env, principal, createDavFetch(owner), {
    calendarId: WORK_ID,
    ...options,
    rangeStart: RANGE_START,
    rangeEnd: RANGE_END,
    pageSize: 100,
  });
  return page.events;
}

describe("searchEvents", () => {
  it("matches a keyword as a SUBSTRING of the summary, not a prefix", async () => {
    // Someone searching for a word should find an event whose summary merely
    // contains it.
    const rows = await search({ keyword: "standup" });

    expect(rows.length).toBe(12);
    expect(rows.every((one) => one.summary!.includes("standup"))).toBe(true);
  });

  it("matches case-insensitively", async () => {
    const shouting = await search({ keyword: "WEEKLY STANDUP" });

    expect(shouting.length).toBe(12);
  });

  it("matches a keyword found ONLY in the description", async () => {
    // Nothing in any summary or location carries this, and the row type has
    // nowhere to put a description — so a filter reading only the row's own
    // fields returns nothing here.
    const rows = await search({ keyword: "two-sentence" });

    expect(rows.length).toBe(11);
    expect(rows.every((one) => one.isOverride === false)).toBe(true);
  });

  it("matches a keyword found ONLY in the location", async () => {
    const rows = await search({ keyword: "room five" });

    expect(rows.length).toBe(1);
    expect(rows[0].isOverride).toBe(true);
  });

  it("matches an attendee by display name", async () => {
    const rows = await search({ attendee: "whitaker" });

    expect(rows.length).toBe(11);
  });

  it("matches a SUBSTRING of an address's local part", async () => {
    const rows = await search({ attendee: "dev.whit" });

    expect(rows.length).toBe(11);
  });

  it("matches the ORGANISER, who is searched as an attendee", async () => {
    // Deliberate: for the job search this project exists to serve, the person
    // who SENT the invitation is the person being searched for at least as
    // often as a listed participant.
    const rows = await search({ attendee: "priya" });

    expect(rows.length).toBe(11);
    // And it is genuinely the organiser rather than the one attendee.
    expect(await search({ attendee: "raman" })).toHaveLength(11);
  });

  it("requires BOTH to match when both are supplied", async () => {
    // The keyword matches only the override; the attendee matches only the
    // eleven that are not it. An OR would return twelve.
    const rows = await search({ keyword: "room five", attendee: "priya" });

    expect(rows.length).toBe(0);

    const both = await search({ keyword: "standup", attendee: "priya" });
    expect(both.length).toBe(11);
  });

  it("returns an EMPTY page for a term matching nothing, never an error", async () => {
    const page = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "no event anywhere says this",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
    });

    expect(page.events).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  it("refuses an empty and a whitespace-only term before any request", async () => {
    for (const options of [
      { keyword: "" },
      { keyword: "   " },
      { attendee: "" },
      { attendee: "\t\n " },
    ]) {
      stub.observed.length = 0;
      const error = await capture(() =>
        searchEvents(env, principal, createDavFetch(owner), {
          calendarId: WORK_ID,
          ...options,
          rangeStart: RANGE_START,
          rangeEnd: RANGE_END,
        }),
      );

      expect(error).toBeInstanceOf(DavNotFoundError);
      expect(stub.observed.length).toBe(0);
    }
  });

  it("refuses a call supplying neither term", async () => {
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("applies the range cap identically to the listing", async () => {
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_START + (MAX_RANGE_DAYS + 1) * 86400,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("returns every match exactly once across a paging walk", async () => {
    const walked = await searchWalk({ keyword: "standup" });
    const whole = (await search({ keyword: "standup" })).map((one) => one.id);

    expect(walked.length).toBe(whole.length);
    expect(new Set(walked).size).toBe(walked.length);
    expect([...walked].sort()).toEqual([...whole].sort());
  });

  it("rides the SAME cursor KIND as the plain listing", async () => {
    // A search result IS a listing: the same token kind, the same total order,
    // the same page shape. That is unchanged. What a cursor is not is
    // INTERCHANGEABLE across queries — see the terms block below, which is the
    // half 03-07 left open and the user authorised closing.
    const listed = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    const searched = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });

    expect(listed.nextCursor).not.toBeNull();
    expect(searched.nextCursor).not.toBeNull();
    // Both decode through the SAME decoder against the same range, so neither
    // is a second cursor type the model would have to learn.
    expect(() =>
      decodeCalendarCursor(listed.nextCursor!, RANGE_START, RANGE_END),
    ).not.toThrow();
    expect(() =>
      decodeCalendarCursor(searched.nextCursor!, RANGE_START, RANGE_END),
    ).not.toThrow();
  });

  it("refuses a cursor pinned to a different range, exactly as the listing does", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END - 86400,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a cursor pinned to a different calendar scope", async () => {
    const listing = await listCalendars(env, principal, createDavFetch(owner));
    const work = listing.calendars.find(
      (one) => decodeCalendarId(one.id).collectionUrl === WORK_URL,
    );
    const scoped = await searchEvents(env, principal, createDavFetch(owner), {
      keyword: "standup",
      calendarId: work!.id,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    expect(scoped.nextCursor).not.toBeNull();
    stub.observed.length = 0;

    // D-67: the token decodes cleanly and the resume predicate would run, so
    // without this check the caller receives a page from the middle of a
    // result set they never asked for. The resumed call names a DIFFERENT
    // calendar — which is the only way the two scopes can now disagree, since
    // there is no account-wide form left to resume a scoped cursor against.
    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: HOME_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: scoped.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses an IN-FLIGHT cursor from before the calendar became required", async () => {
    // The search half of the published-contract change; the listing half is the
    // matching case above. A cursor minted under the old account-wide form
    // records no calendar, cannot match the one the caller must now supply, and
    // is refused at the codec before any request rather than resumed against a
    // set it never described.
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: legacyUnscopedCursor(),
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
    expect(stub.observed.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // The cursor pins its TERMS (gap closure on 03-07, authorised by the user)
  //
  // 03-07 identified this and deliberately did not fix it, because its own
  // criteria required a search cursor and a listing cursor to be
  // interchangeable and `CalendarCursor` had no field for a term. The user
  // reviewed that and chose to close it: interchangeability is the thing that
  // gives, because pinning the terms is precisely what makes a search cursor
  // NOT a listing cursor, which is the correct semantics.
  //
  // Every case below asserts the REFUSAL rather than the happy path, and the
  // fetch count is asserted at zero on each, because the entire signature of
  // this bug is that it returns plausible rows instead of an error. A test that
  // only proved a same-terms resume still works would have passed before the
  // fix as well as after it.
  // -------------------------------------------------------------------------

  it("refuses a cursor minted under a DIFFERENT keyword, before any request", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    expect(first.nextCursor).not.toBeNull();
    stub.observed.length = 0;

    // Without the pin this decodes cleanly, the resume predicate runs against
    // the OTHER term's ordered set, and every match sorting before the recorded
    // position vanishes with no signal at all.
    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "two-sentence",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("marks the wrong-terms refusal NON-rediscoverable", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "two-sentence",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: first.nextCursor!,
      }),
    );

    // Re-discovery re-resolves the account's home URLs, and no amount of
    // re-resolving repairs a cursor minted for another query. `true` would
    // spend a real PROPFIND out of D-60's retry budget to reach the identical
    // answer.
    expect((error as DavNotFoundError).rediscoverable).toBe(false);
  });

  it("refuses a cursor minted under a DIFFERENT attendee term", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      attendee: "priya",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    expect(first.nextCursor).not.toBeNull();
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        attendee: "whitaker",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a cursor when the OTHER axis is added, which narrows the set", async () => {
    // Both axes are pinned separately because they narrow separately: adding an
    // attendee term to a keyword search is a different result set, and a
    // one-field pin would miss it.
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        attendee: "priya",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a cursor when an axis is DROPPED, which widens the set", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      attendee: "priya",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    expect(first.nextCursor).not.toBeNull();
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: first.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a LISTING cursor handed to a search", async () => {
    // The interchangeability 03-07's criteria required, deliberately given up.
    // A listing pins neither term; a search pins at least one; so the two can
    // never compare equal, and a position in the unfiltered set can no longer
    // be resumed against a filtered one.
    const listed = await listEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    stub.observed.length = 0;

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: listed.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a SEARCH cursor handed to the plain listing", async () => {
    const searched = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });
    expect(searched.nextCursor).not.toBeNull();
    stub.observed.length = 0;

    const error = await capture(() =>
      listEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
        cursor: searched.nextCursor!,
      }),
    );

    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("resumes across a CASE change, because the matching is case-insensitive", async () => {
    // The pin is the FOLDED term, not the raw one, and folding is exactly what
    // makes the pin discriminate the thing that actually changes the answer.
    // "STANDUP" and "standup" return the identical set, so refusing between
    // them would be a false refusal rather than a safe one.
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });

    const resumed = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "STANDUP",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
      cursor: first.nextCursor!,
    });

    expect(resumed.events.length).toBeGreaterThan(0);
  });

  it("resumes across surrounding WHITESPACE, which the term normaliser strips", async () => {
    const first = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 3,
    });

    const resumed = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "  standup  ",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 100,
      cursor: first.nextCursor!,
    });

    expect(resumed.events.length).toBeGreaterThan(0);
  });

  it("does not report WHICH field matched, only that a row did", async () => {
    const page = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
      pageSize: 1,
    });

    for (const key of ["matched", "matchedFields", "matchedOn", "score"]) {
      expect(Object.keys(page)).not.toContain(key);
      expect(Object.keys(page.events[0])).not.toContain(key);
    }
  });

  it("re-discovers ONCE and retries ONCE against a cached host, then stops", async () => {
    let reports = 0;
    const next = restub({
      onRequest: (_url, method) => {
        if (method !== "REPORT") return null;
        reports += 1;
        return new Response(null, { status: 404 });
      },
    });

    const error = await capture(() =>
      searchEvents(env, principal, createDavFetch(owner), {
        calendarId: WORK_ID,
        keyword: "standup",
        rangeStart: RANGE_START,
        rangeEnd: RANGE_END,
      }),
    );

    // The search inherits D-60's policy rather than re-implementing or
    // bypassing it, because it reaches the network through the listing's
    // already-wrapped body.
    expect(reports).toBe(2);
    expect(error).toBeInstanceOf(DavNotFoundError);
    expect(
      next.observed.filter((one) => one.url.startsWith(CALDAV_SERVER)).length,
    ).toBeGreaterThan(0);
  });

  it("reports truncation and cache state exactly as the listing does", async () => {
    const page = await searchEvents(env, principal, createDavFetch(owner), {
      calendarId: WORK_ID,
      keyword: "standup",
      rangeStart: RANGE_START,
      rangeEnd: RANGE_END,
    });

    expect(page.truncated).toBe(false);
    expect(page.cacheHit).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The two match predicates, driven directly
// ---------------------------------------------------------------------------

/** One occurrence, shaped by hand so a predicate case names its own inputs. */
function party(name: string | null, email: string | null) {
  return { name, email, partstat: null, role: null };
}

function occurrence(overrides: Record<string, unknown> = {}) {
  return {
    uid: "u",
    recurrenceId: null,
    isRecurring: false,
    isOverride: false,
    start: {
      allDay: false,
      local: "2026-01-05T09:00:00",
      tzid: "UTC",
      utc: 0,
      timezoneUnresolved: false,
    },
    end: {
      allDay: false,
      local: "2026-01-05T09:30:00",
      tzid: "UTC",
      utc: 0,
      timezoneUnresolved: false,
    },
    summary: null,
    location: null,
    description: null,
    organizer: null,
    attendees: [],
    ...overrides,
  } as Parameters<typeof matchesKeyword>[0];
}

describe("matchesKeyword", () => {
  it("searches the summary, the location and the description", () => {
    expect(matchesKeyword(occurrence({ summary: "Interview" }), "view")).toBe(true);
    expect(matchesKeyword(occurrence({ location: "Room 2" }), "room")).toBe(true);
    expect(matchesKeyword(occurrence({ description: "Bring the deck" }), "deck")).toBe(
      true,
    );
  });

  it("is case-insensitive in both directions", () => {
    expect(matchesKeyword(occurrence({ summary: "INTERVIEW" }), "interview")).toBe(
      true,
    );
    expect(matchesKeyword(occurrence({ summary: "interview" }), "INTERVIEW")).toBe(
      true,
    );
  });

  it("is false when nothing carries the term, and on an occurrence with no text", () => {
    expect(matchesKeyword(occurrence({ summary: "Interview" }), "standup")).toBe(
      false,
    );
    expect(matchesKeyword(occurrence(), "anything")).toBe(false);
  });
});

describe("matchesAttendee", () => {
  it("searches every attendee's display name and address", () => {
    const one = occurrence({
      attendees: [party("Dev Whitaker", "dev.whitaker@example.invalid")],
    });

    expect(matchesAttendee(one, "whitaker")).toBe(true);
    expect(matchesAttendee(one, "dev.whit")).toBe(true);
    expect(matchesAttendee(one, "example.invalid")).toBe(true);
    expect(matchesAttendee(one, "priya")).toBe(false);
  });

  it("searches the ORGANISER as well", () => {
    const one = occurrence({
      organizer: party("Priya Raman", "priya.raman@example.invalid"),
    });

    expect(matchesAttendee(one, "raman")).toBe(true);
    expect(matchesAttendee(one, "priya.raman@example.invalid")).toBe(true);
  });

  it("is false on an occurrence naming nobody", () => {
    expect(matchesAttendee(occurrence(), "anyone")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CALW-01 — the first DAV write in this repository
//
// Every case below asserts the OUTGOING REQUEST rather than the outcome, and
// Pitfall 2 is why: a create that asserts only "it succeeded" passes just as
// happily against an unconditional write, because the server answers 201 either
// way. The conditional header and the request COUNT are the two properties that
// cannot be inferred from a successful result.
// ---------------------------------------------------------------------------

/** The input every create case below starts from. */
function createInput(
  overrides: Partial<CreateEventInput> = {},
): CreateEventInput {
  return {
    calendarId: WORK_ID,
    summary: "Interview with Northwind",
    startLocal: "2026-09-03T14:00:00",
    endLocal: "2026-09-03T15:00:00",
    tzid: DEFINED_TZID,
    ...overrides,
  };
}

/** The single `.ics` body a create put on the wire. */
function sentBody(one: Stub): string {
  const writes = one.observed.filter((request) => request.method === "PUT");
  expect(writes.length, "no write reached the stub").toBe(1);
  expect(writes[0].body, "the write carried no body").not.toBeNull();
  return writes[0].body!;
}

/** September 2026, the month every create case above puts its event in. */
const SEP_01 = at("2026-09-01T00:00:00Z");
const SEP_30 = at("2026-09-30T00:00:00Z");

/** The one occurrence a freshly-built resource expands to. */
function onlyOccurrence(icsText: string): Occurrence {
  const expanded = withParsedResource(icsText, (resource) =>
    expandOccurrences(resource, SEP_01, SEP_30),
  );
  expect(expanded.occurrences.length, "the built resource expanded to nothing")
    .toBe(1);
  return expanded.occurrences[0];
}

describe("createEvent", () => {
  it("issues exactly ONE conditional PUT, under the account's own home set", async () => {
    await createEvent(env, principal, createDavFetch(owner), createInput());

    // ONE. `withRediscovery` retries a read on a rediscoverable failure, and a
    // write leg that inherited that behaviour would send the PUT twice
    // (Pitfall 8) — so the count is the assertion, not a side note.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PUT");
    // The header, not the outcome. Without this the create is unconditional
    // and nothing in the response says so.
    expect(stub.observed[0].headers["if-none-match"]).toBe("*");
    // Under the home set discovery resolved, never a URL the caller chose.
    expect(stub.observed[0].url.startsWith(CALDAV_HOME)).toBe(true);
  });

  it("round-trips through this server's OWN reader with the zone resolved", async () => {
    await createEvent(env, principal, createDavFetch(owner), createInput());

    // The bytes that actually went out, read back through the shipped parser.
    // A resource this server would itself flag as broken is a self-inflicted
    // defect, and `timezoneUnresolved` is the field that would say so.
    const occurrence = onlyOccurrence(sentBody(stub));

    expect(occurrence.start.local).toBe("2026-09-03T14:00:00");
    expect(occurrence.start.tzid).toBe(DEFINED_TZID);
    expect(occurrence.start.timezoneUnresolved).toBe(false);
    expect(occurrence.end.local).toBe("2026-09-03T15:00:00");
    expect(occurrence.summary).toBe("Interview with Northwind");
  });

  it("refuses a zone it holds no definition for WITHOUT reaching the network", async () => {
    const result = await createEvent(
      env, principal,
      createDavFetch(owner),
      createInput({ tzid: "Mars/Olympus_Mons" }),
    );

    // Zero, not "an error". A refusal that reached the network is a failure of
    // this case even if the reported field is right: the whole argument for a
    // bounded allow-list is that the refusal is free.
    expect(stub.observed.length).toBe(0);
    expect(result.created).toBe(false);
    // A returned field on a SUCCESSFUL result, never a fifth error category —
    // the `unsupportedCharset` precedent.
    expect(result.unsupportedTimezone).toBe("Mars/Olympus_Mons");
    expect(result.id).toBeNull();
  });

  it("writes an all-day event as a DATE with no zone at all", async () => {
    await createEvent(
      env, principal,
      createDavFetch(owner),
      createInput({ allDay: true, endLocal: "2026-09-04T00:00:00" }),
    );

    const body = sentBody(stub);
    expect(body).toContain("DTSTART;VALUE=DATE:20260903");
    // A date is anchored to nothing BY DEFINITION, so a zone parameter would
    // be a claim the event does not make, and a VTIMEZONE would be dead weight.
    expect(body).not.toContain("TZID");
    expect(body).not.toContain("BEGIN:VTIMEZONE");
    expect(onlyOccurrence(body).start.allDay).toBe(true);
  });

  it("escapes a title the library's own rules cover, byte for byte", async () => {
    // A comma, a semicolon, a backslash and a non-ASCII character. Every one of
    // these is something a hand-rolled writer gets wrong on the first real
    // event and right on the developer's test one.
    const summary = "Review: costs, risks; the \\ plan — café";
    await createEvent(env, principal, createDavFetch(owner), createInput({ summary }));

    const body = sentBody(stub);
    // The escapes are present in the SERIALISED form...
    expect(body).toContain("costs\\, risks\\; the \\\\ plan");
    // ...and the value survives a round trip unchanged.
    expect(onlyOccurrence(body).summary).toBe(summary);
  });

  it("is NOT idempotent: two identical calls mint two different UIDs", async () => {
    const first = await createEvent(env, principal, createDavFetch(owner), createInput());
    const bodyOne = sentBody(stub);
    stub.observed.length = 0;
    const second = await createEvent(env, principal, createDavFetch(owner), createInput());
    const bodyTwo = sentBody(stub);

    expect(first.uid).not.toBe(second.uid);
    expect(bodyOne).not.toBe(bodyTwo);
    // And each event is separately addressable, which is what makes the second
    // one a second event rather than a lost write.
    expect(first.id).not.toBe(second.id);
  });

  it("leaves the process-global timezone registry exactly as it found it", async () => {
    // Behavioural, not a source grep. A grep for the registration call would
    // fire on the comment explaining why there is no registration call, which
    // makes it unreachable by anyone who documents the rule (CR-03, Pitfall 7).
    const registered = (): boolean[] =>
      Object.keys(VTIMEZONE_ALLOWLIST).map((zone) =>
        ICAL.TimezoneService.has(zone),
      );
    const before = registered();

    await createEvent(env, principal, createDavFetch(owner), createInput());

    expect(registered()).toEqual(before);
  });

  it("refuses a collection URL that is not this account's own", async () => {
    // The write-path arrival of 03-REVIEW.md CR-01. The read path's fix does
    // not automatically cover a new call site, and this one additionally
    // CONSTRUCTS a URL rather than decoding one.
    const foreign = encodeCalendarId({
      collectionUrl: "https://attacker.example/1234567890/calendars/work/",
    });

    const err = await capture(() =>
      createEvent(env, principal, createDavFetch(owner), createInput({ calendarId: foreign })),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    // Nothing reached the network: `./transport.ts` attaches the Apple ID and
    // the app-specific password to whatever URL it is handed.
    expect(stub.observed.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CALW-06 — who this account IS, and the people it invites
//
// RFC 6638 requires the `ORGANIZER` to match one of the calendar user addresses
// of the collection owner. A resource whose organiser does not is not an
// organizer scheduling object resource, and the server will not send on its
// behalf — which fails SILENTLY, with a 2xx on the write and no invitation. So
// the address is resolved from the account's own advertised set rather than
// assumed, and every case below is about that resolution or about what the
// resolved value ends up in.
// ---------------------------------------------------------------------------

describe("resolveOrganizerAddress", () => {
  it("costs exactly ONE request, a PROPFIND at the principal", async () => {
    await resolveOrganizerAddress(env, principal, createDavFetch(owner));

    // ONE, on a warm discovery cache. This runs on a path that is already
    // gated behind a human confirmation, and it runs on BOTH legs of it — so a
    // second request here is four across a preview and a commit rather than
    // two, against the tightest budget this project has.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PROPFIND");
    expect(stub.observed[0].url).toBe(`${CALDAV_SERVER}${PRINCIPAL_PATH}`);
    expect(String(stub.observed[0].body)).toContain("calendar-user-address-set");
  });

  it("prefers the account's own login over an alias listed before it", async () => {
    // The fixture deliberately lists an alias FIRST, so "take the first
    // mailto" and "prefer the login" give different answers. Sending an
    // invitation from an alias is not wrong in the way a stranger's address
    // would be, but it is an identity the user did not choose, and 04-03
    // already decided this question one protocol over: the From identity is
    // fixed and never a parameter.
    expect(await resolveOrganizerAddress(env, principal, createDavFetch(owner))).toBe(
      LOGIN_ADDRESS,
    );
  });

  it("falls back to the FIRST mailto when the login is not in the set", async () => {
    // A real possibility rather than a hypothetical: probe P-1 recorded this
    // account advertising four addresses, and this project's own notes record
    // that the Apple ID is not necessarily any of the obvious ones. An account
    // whose login is absent from its own address set still has to be able to
    // organise a meeting.
    restub({
      userAddresses: [
        "/1234567890/principal/",
        `mailto:${ALIAS_BEFORE_LOGIN}`,
        "mailto:alias.two@example.invalid",
      ],
    });

    expect(await resolveOrganizerAddress(env, principal, createDavFetch(owner))).toBe(
      ALIAS_BEFORE_LOGIN,
    );
  });

  it("REFUSES rather than falling back to the login when no mailto is advertised", async () => {
    // The direction that matters. Falling back to the login here would produce
    // a resource that looks correct, writes successfully, returns 2xx — and
    // that iCloud silently declines to send from, because the organiser is not
    // one of the collection owner's calendar user addresses. A refusal costs
    // the user a puzzled error; the fallback costs them a meeting nobody was
    // told about.
    const next = restub({
      userAddresses: ["/1234567890/principal/", "urn:uuid:00000000"],
    });

    const err = await capture(() =>
      resolveOrganizerAddress(env, principal, createDavFetch(owner)),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    // The PROPFIND happened; nothing else did. In particular no write followed
    // the refusal.
    expect(next.observed.filter((one) => one.method === "PUT").length).toBe(0);
  });

  it("REFUSES an address set that is empty", async () => {
    restub({ userAddresses: [] });

    expect(
      await capture(() => resolveOrganizerAddress(env, principal, createDavFetch(owner))),
    ).toBeInstanceOf(DavNotFoundError);
  });

  it("never returns a principal path or a urn form", async () => {
    // Both are in the default fixture, both come BEFORE every mailto entry, and
    // both are legitimate calendar user addresses in the protocol's own terms.
    // They are not addresses a person receives mail at, which is what an
    // invitation needs.
    const resolved = await resolveOrganizerAddress(env, principal, createDavFetch(owner));

    expect(resolved.startsWith("/")).toBe(false);
    expect(resolved.startsWith("urn:")).toBe(false);
    expect(resolved.startsWith("mailto:")).toBe(false);
  });
});

describe("createEvent with people on it", () => {
  const INVITEE = "dev.whitaker@example.invalid";

  it("writes the organiser and the attendees, in ONE conditional PUT", async () => {
    await createEvent(
      env, principal,
      createDavFetch(owner),
      createInput({
        participants: {
          organizer: LOGIN_ADDRESS,
          attendees: [{ email: INVITEE, name: "Dev Whitaker" }],
        },
      }),
    );

    // Still ONE. Resolving the organiser is the CALLER's request to make, and
    // it is made once per leg rather than folded in here — a create with nobody
    // on it must not pay for a lookup it has no use for.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PUT");
    expect(stub.observed[0].headers["if-none-match"]).toBe("*");

    const body = sentBody(stub);
    expect(body).toContain(`ORGANIZER:mailto:${LOGIN_ADDRESS}`);
    expect(body).toContain(`mailto:${INVITEE}`);
    expect(body).toContain("PARTSTAT=NEEDS-ACTION");
  });

  it("writes no scheduling property at all when nobody is invited", async () => {
    await createEvent(env, principal, createDavFetch(owner), createInput());

    const body = sentBody(stub);
    expect(body).not.toContain("ORGANIZER");
    expect(body).not.toContain("ATTENDEE");
  });

  it("lands on the UID it was given, rather than minting a fresh one", async () => {
    // The commit leg's whole target comes from the SIGNED confirmation, so the
    // resource a confirmed create writes must be the one the preview named. A
    // freshly-minted UID here would mean the preview described a resource that
    // never existed and the commit created a different one.
    const target = planCreateTarget(WORK_ID);
    const uid = "planned-0042@icloud-mcp";
    const planned = planCreateTarget(WORK_ID);

    // Two calls, two UIDs: the planner mints, which is what keeps a create
    // non-idempotent when nobody supplies one.
    expect(target.objectUrl).not.toBe(planned.objectUrl);

    const written = await createEvent(
      env, principal,
      createDavFetch(owner),
      createInput({ uid }),
    );

    expect(written.uid).toBe(uid);
    expect(stub.observed[0].url).toBe(
      `${WORK_URL}${encodeURIComponent(uid)}.ics`,
    );
    expect(sentBody(stub)).toContain(`UID:${uid}`);
  });

  it("plans a target under the named collection, addressable before it exists", async () => {
    const target = planCreateTarget(WORK_ID);

    expect(target.calendarUrl).toBe(WORK_URL);
    expect(target.objectUrl.startsWith(WORK_URL)).toBe(true);
    expect(target.objectUrl.endsWith(".ics")).toBe(true);
    expect(target.recurrenceId).toBeNull();

    // And the plan is what the write honours: a create told to land on the
    // planned UID writes to the planned URL, byte for byte.
    const uid = decodeURIComponent(
      target.objectUrl.slice(WORK_URL.length, -".ics".length),
    );
    await createEvent(env, principal, createDavFetch(owner), createInput({ uid }));
    expect(stub.observed[0].url).toBe(target.objectUrl);
  });
});

describe("the rewrite body cannot carry a person", () => {
  it("emits no ORGANIZER and no ATTENDEE, whatever the resource held", async () => {
    // The laundering direction, at the layer where the bytes are made. A
    // rewrite REBUILDS the resource from the confirmed change and never sees
    // the stored bytes, so an attendee the read side found could only reach a
    // written resource by being passed in here — and there is no participants
    // value the update path can supply, because it supplies null.
    const body = updateEventBody(
      SIMPLE_REF,
      {
        summary: "Interview with Northwind",
        startLocal: "2026-09-03T14:00:00",
        endLocal: "2026-09-03T15:00:00",
        tzid: DEFINED_TZID,
        allDay: false,
        location: null,
        description: null,
        participants: null,
        sequence: 0,
      },
      null,
    );

    expect(body).not.toContain("ORGANIZER");
    expect(body).not.toContain("ATTENDEE");
  });

  it("emits no ORGANIZER even when the caller hands one in", async () => {
    // The other direction, and the one the type system cannot refuse: the field
    // EXISTS on the builder's input, so a rewrite that merely forgot to pass
    // null would compile. `updateEventBody` overrides it, so there is no value
    // a caller can put here that reaches the wire — which is what keeps the
    // server-assigned organiser iCloud writes onto a scheduling resource (probe
    // P-1 (d)) safe from a rebuild that would replace it with a plain address.
    const body = updateEventBody(
      SIMPLE_REF,
      {
        summary: "Interview with Northwind",
        startLocal: "2026-09-03T14:00:00",
        endLocal: "2026-09-03T15:00:00",
        tzid: DEFINED_TZID,
        allDay: false,
        location: null,
        description: null,
        participants: {
          organizer: "user@example.invalid",
          attendees: [{ email: "dev.whitaker@example.invalid", name: "Dev" }],
        },
        sequence: 0,
      },
      null,
    );

    expect(body).not.toContain("ORGANIZER");
    expect(body).not.toContain("ATTENDEE");
    expect(body).not.toContain("dev.whitaker@example.invalid");
  });
});

// ---------------------------------------------------------------------------
// The calendar_search registration
// ---------------------------------------------------------------------------

interface Recorded {
  name: string;
  options: Record<string, unknown>;
  /**
   * The handler itself.
   *
   * Recorded so the write path's error backstop can be exercised through the
   * shipped handler rather than through a re-implementation of it — the same
   * reason `test/dav-tools.test.ts` records callbacks.
   */
  callback: (args: Record<string, unknown>) => Promise<{
    isError?: boolean;
    content: { text: string }[];
  }>;
}

/** Every registration `registerCalendarTools` performs, without an MCP server. */
function calendarRegistrations(): Recorded[] {
  const recorded: Recorded[] = [];
  const server = {
    registerTool(
      name: string,
      options: Record<string, unknown>,
      callback: Recorded["callback"],
    ) {
      recorded.push({ name, options, callback });
    },
  };
  registerCalendarTools(server as unknown as McpServer, createDavFetch(owner), owner);
  return recorded;
}

describe("the calendar_create_event handler", () => {
  it("reports a transport failure through the fixed vocabulary and says nothing else", async () => {
    // The stub answers every write with a 500, which `throwForStatus` turns
    // into a `DavConnectError` — the branch that carries no status and no text.
    restub({ onRequest: (_url, method) => (method === "PUT" ? new Response("caldav-p42 said: object PUT failed at /1234567890/", { status: 500 }) : null) });

    const tool = calendarRegistrations().find(
      (one) => one.name === "calendar_create_event",
    );
    expect(tool, "calendar_create_event is not registered").toBeDefined();

    const result = await tool!.callback({ ...createInput() });

    expect(result.isError).toBe(true);
    // ONE block, the error shape, not the two-block success shape.
    expect(result.content.length).toBe(1);
    const whole = result.content[0].text;
    expect(JSON.parse(whole).category).toBe("connection_failed");
    // tsdav's own errors embed the resolved shard host. Nothing of the caught
    // value escapes: not the URL, not the server's text.
    expect(whole).not.toContain("p42");
    expect(whole).not.toContain("icloud.com");
    expect(whole).not.toContain("1234567890");
  });
});

describe("the calendar registrations", () => {
  it("records exactly the ten calendar tools", () => {
    // Named explicitly rather than counted, so neither the description loop in
    // `test/dav-tools.test.ts` nor this case can pass by the registrar having
    // been called and registered nothing.
    //
    // `calendar_commit` is ONE tool rather than one per operation, and that is
    // what this list is really pinning: a second commit endpoint appearing here
    // would be a second handler that could be the one missing the check.
    // `calendar_find_free_slots` (SCHED-01) is the ninth, added in phase 6.
    // `calendar_create_calendar` (CALM-04) is the tenth, added in phase 17 —
    // and it is the one tool on this list that deliberately does NOT reach
    // `calendar_commit`, because a create is reversible and D-07 declines to
    // spend the user's attention on a gate that does not need spending.
    expect(calendarRegistrations().map((one) => one.name).sort()).toEqual([
      "calendar_commit",
      "calendar_create_calendar",
      "calendar_create_event",
      "calendar_delete_event",
      "calendar_find_free_slots",
      "calendar_get_event",
      "calendar_list_calendars",
      "calendar_list_events",
      "calendar_search",
      "calendar_update_event",
    ]);
  });

  it("states the range-bounded limit in the search description", () => {
    const description = String(
      calendarRegistrations().find((one) => one.name === "calendar_search")!
        .options.description,
    );

    // The caveat a user would otherwise have to DISCOVER: client-side search is
    // bounded by the range fetched, so this tool cannot answer a question about
    // all of time.
    expect(description).toContain("range");
    expect(description).toContain("all of time");
  });

  it("states the matching semantics on the two term parameters", () => {
    const shape = (
      calendarRegistrations().find((one) => one.name === "calendar_search")!.options
        .inputSchema as z.ZodObject<z.ZodRawShape>
    ).shape;

    // A fact about ONE parameter goes on that parameter, not in the description.
    const keyword = String((shape.keyword as z.ZodType).description);
    expect(keyword).toContain("summary");
    expect(keyword).toContain("location");
    expect(keyword).toContain("description");

    const attendee = String((shape.attendee as z.ZodType).description);
    expect(attendee).toContain("organiser");
  });

  it("takes both terms, the range, a page size and a cursor", () => {
    const shape = (
      calendarRegistrations().find((one) => one.name === "calendar_search")!.options
        .inputSchema as z.ZodObject<z.ZodRawShape>
    ).shape;

    expect(Object.keys(shape).sort()).toEqual([
      "attendee",
      "calendarId",
      "cursor",
      "end",
      "keyword",
      "pageSize",
      "start",
    ]);
  });

  it("copies the page-size and cursor wording from the listing tool byte for byte", () => {
    const of = (name: string, param: string): string => {
      const shape = (
        calendarRegistrations().find((one) => one.name === name)!.options
          .inputSchema as z.ZodObject<z.ZodRawShape>
      ).shape;
      return String((shape[param] as z.ZodType).description);
    };

    expect(of("calendar_search", "pageSize")).toBe(
      of("calendar_list_events", "pageSize"),
    );
    expect(of("calendar_search", "cursor")).toContain(
      "The nextCursor from a previous page. Omit for page one.",
    );
  });
});

// ---------------------------------------------------------------------------
// CALW-02, CALW-05 — the etag read and the first CONDITIONAL write
//
// Every case here asserts the OUTGOING REQUEST or its COUNT rather than the
// outcome, for the reason the create section already states one layer up and
// which is sharper on an update: tsdav's header builder DROPS a falsy
// `If-Match`, so an update called with an absent etag is an UNCONDITIONAL
// write that the server answers 200 to. It looks exactly like success. The
// header and the count are the only two things that can tell the two apart.
// ---------------------------------------------------------------------------

/**
 * A plain event: one occurrence, nobody invited, nothing this server's own
 * builder cannot reproduce.
 *
 * The `.ics` filename is the UID, which is not decoration. The commit leg
 * deliberately does not re-read the resource, so the UID it writes back has to
 * come from the object URL — and `getEventWithEtag` refuses a resource whose
 * URL does not name its UID rather than writing a resource under a UID it
 * guessed.
 */
const SIMPLE_UID = "simple-0009";
const SIMPLE_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  `UID:${SIMPLE_UID}`,
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Interview with Northwind",
  "LOCATION:Room nine",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  "SEQUENCE:0",
  "END:VEVENT",
  "END:VCALENDAR",
);

const SIMPLE_HREF = `${WORK_PATH}${SIMPLE_UID}.ics`;
const SIMPLE_URL = `https://p42-caldav.icloud.com${SIMPLE_HREF}`;
const SIMPLE_REF = {
  calendarUrl: WORK_URL,
  objectUrl: SIMPLE_URL,
  recurrenceId: null,
};
const SIMPLE_OBJECTS: Record<string, Record<string, string>> = {
  [WORK_PATH]: { [SIMPLE_HREF]: SIMPLE_ICS },
};

/** The `.ics` body a conditional write put on the wire, with its count asserted. */
function sentUpdateBody(one: Stub): string {
  const writes = one.observed.filter((request) => request.method === "PUT");
  expect(writes.length, "no write reached the stub").toBe(1);
  expect(writes[0].body, "the write carried no body").not.toBeNull();
  return writes[0].body!;
}

describe("the etag read", () => {
  it("reads the body and the etag from ONE multi-get", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF);

    // ONE. Reading the etag in a second call would open a race between the
    // etag and the body that the confirmation then pins as though the two were
    // consistent — the precise failure `If-Match` exists to prevent,
    // reintroduced one layer up.
    expect(one.observed.length).toBe(1);
    expect(read.detail.summary).toBe("Interview with Northwind");
    expect(read.etag).toBe('"etag-1"');
  });

  it("returns the etag byte-exact, with its quotes still on it", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF);

    expect(one.observed.length).toBe(1);
    expect(read.etag.startsWith('"')).toBe(true);
    expect(read.etag.endsWith('"')).toBe(true);
  });

  it("returns a WEAK etag verbatim, prefix intact and not unwrapped", async () => {
    // Stripping the quotes to re-add them is a normalisation that eventually
    // meets one of these and gets it wrong.
    restub({
      objects: SIMPLE_OBJECTS,
      etags: { [SIMPLE_HREF]: 'W/"abc"' },
    });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF);

    expect(read.etag).toBe('W/"abc"');
  });

  it("refuses a resource that came back with a body and NO etag", async () => {
    // The same construction the absent-body path already uses, and NOT
    // rediscoverable: the host answered, and it answered about this resource.
    restub({
      onRequest: (_url, method) =>
        method === "REPORT"
          ? multistatus(
              `<response><href>${SIMPLE_HREF}</href><propstat>` +
                `<status>HTTP/1.1 200 OK</status><prop>` +
                `<C:calendar-data><![CDATA[${SIMPLE_ICS}]]></C:calendar-data>` +
                `</prop></propstat></response>`,
            )
          : null,
    });

    const err = await capture(() =>
      getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect((err as DavNotFoundError).rediscoverable).toBe(false);
  });

  it("leaves the plain detail read unchanged, etag and all", async () => {
    // `getEvent` and `getEventWithEtag` share one body; this is the assertion
    // that the sharing did not change what the older caller sees.
    const one = restub({ objects: SIMPLE_OBJECTS });

    const detail = await getEvent(env, principal, createDavFetch(owner), SIMPLE_REF);

    expect(one.observed.length).toBe(1);
    expect(detail.summary).toBe("Interview with Northwind");
    expect("etag" in detail).toBe(false);
  });

  it("reports a rewritable resource as carrying no blocker at all", async () => {
    restub({ objects: SIMPLE_OBJECTS });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF);

    expect(read.unsupportedTarget).toBeNull();
  });
});

describe("what the etag read refuses to let a rewrite touch", () => {
  /**
   * Read one hand-built resource, served under a UID-named href.
   *
   * `recurrenceId` is a parameter because a series' occurrences are addressed
   * by their slot: passing null against a resource carrying a rule is a
   * genuine not-found, and a helper that hardcoded it would test the selection
   * failure rather than the classification.
   */
  async function readWith(
    uid: string,
    body: string,
    recurrenceId: string | null = null,
  ) {
    const href = `${WORK_PATH}${uid}.ics`;
    restub({ objects: { [WORK_PATH]: { [href]: body } } });
    return getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId,
    });
  }

  async function readBody(
    uid: string,
    body: string,
    recurrenceId: string | null = null,
  ): Promise<string | null> {
    return (await readWith(uid, body, recurrenceId)).unsupportedTarget;
  }

  it("classifies a recurrence rule as recurring", async () => {
    const uid = "recurs-0010";
    expect(
      await readBody(
        uid,
        ics(
          ...ICS_HEAD,
          "BEGIN:VEVENT",
          `UID:${uid}`,
          "DTSTAMP:20260101T120000Z",
          "SUMMARY:Standup",
          "DTSTART:20260210T150000Z",
          "DTEND:20260210T151500Z",
          "RRULE:FREQ=WEEKLY;COUNT=4",
          "END:VEVENT",
          "END:VCALENDAR",
        ),
        "20260210T150000Z",
      ),
    ).toBe("recurring");
  });

  it("classifies an attendee list as SCHEDULING, which routes it to the patch", async () => {
    // The verdict moved from `unsupportedTarget` to `isScheduling` in plan
    // 05-14, and the pair below is what says the refusal NARROWED rather than
    // disappeared: the resource is still recognised as one iCloud sends mail
    // for, and what changed is that recognising it now selects a writer instead
    // of declining to write. Asserting only the null would pass equally well
    // against a build where the recognition itself had been deleted — which is
    // the failure this pair exists to tell apart.
    const uid = "invited-0011";
    const read = await readWith(
      uid,
      ics(
        ...ICS_HEAD,
        "BEGIN:VEVENT",
        `UID:${uid}`,
        "DTSTAMP:20260101T120000Z",
        "SUMMARY:Interview",
        "DTSTART:20260210T150000Z",
        "DTEND:20260210T160000Z",
        "ORGANIZER;CN=Priya Raman:mailto:priya.raman@example.invalid",
        "ATTENDEE;CN=Dev Whitaker:mailto:dev.whitaker@example.invalid",
        "END:VEVENT",
        "END:VCALENDAR",
      ),
    );

    expect(read.isScheduling).toBe(true);
    expect(read.unsupportedTarget).toBeNull();
  });

  it("routes a SEQUENCE:3 resource whose attendee ACCEPTED to the patch, not the rebuild", async () => {
    // **This case was `STILL refuses a scheduling resource, which is what
    // protects the ORGANIZER`, pinned by 05-08 to fail loudly at the moment
    // somebody lifted the refusal. Plan 05-14 lifted it, and this is the
    // deliberate rewrite that 05-08's own comment asked for rather than a
    // deletion.** The three hazards it named are unchanged and every one of them
    // is still real; what changed is that the rebuild is no longer the writer
    // this resource reaches.
    //
    // 05-06's commit REBUILDS a resource from the confirmed change, and three
    // hazards follow from that:
    //
    //   1. **SEQUENCE.** The rebuild used to emit `SEQUENCE:0`, taking the
    //      resource below from revision three to zero — and a revision that goes
    //      backwards is discarded as stale by every receiving client with
    //      nothing reporting a problem anywhere. 05-09 closed this at the
    //      source: `updateEventBody` emits `nextSequence` of what the fetched
    //      resource carried. The patch advances it too, from the component's own
    //      stored value.
    //   2. **ORGANIZER.** Probe P-1 (d) measured iCloud replacing the
    //      organiser's `mailto:` with an opaque per-account principal href and
    //      stamping `SCHEDULE-STATUS` onto every attendee. A rebuild cannot
    //      preserve any of it, because it never sees the stored bytes.
    //   3. **PARTSTAT.** Resetting a status somebody already set to `ACCEPTED`
    //      would ERASE their reply rather than merely fail to carry it.
    //
    // 05-RESEARCH.md § "Settled by measurement" F-1 — *"Do not relax that
    // refusal"* — was a statement about the REBUILD, and it still is. The answer
    // 05-14 built is the read-then-patch commit that section itself describes as
    // what lifting the refusal would require: `patchEventBody` keeps the stored
    // bytes and asserts only the confirmed fields over them, so all three
    // hazards are answered rather than accepted.
    //
    // What this case now pins is the ROUTING, which is the property that keeps
    // those answers reachable: the resource is recognised as one iCloud sends
    // mail for, and a build that stopped recognising it would send it to the
    // rebuild and lose all three. The byte-level preservation is asserted
    // directly in "an invited event is PATCHED rather than rebuilt" below.
    const uid = "invited-0031";
    const read = await readWith(
      uid,
      ics(
        ...ICS_HEAD,
        "BEGIN:VEVENT",
        `UID:${uid}`,
        "DTSTAMP:20260101T120000Z",
        "SUMMARY:Interview",
        "DTSTART:20260210T150000Z",
        "DTEND:20260210T160000Z",
        // Revision three: this meeting has already been moved twice, and
        // every attendee's client knows it as revision three.
        "SEQUENCE:3",
        "ORGANIZER;CN=Priya Raman:mailto:priya.raman@example.invalid",
        "ATTENDEE;CN=Dev Whitaker;PARTSTAT=ACCEPTED:mailto:dev.whitaker@example.invalid",
        "END:VEVENT",
        "END:VCALENDAR",
      ),
    );

    expect(read.isScheduling).toBe(true);
    expect(read.unsupportedTarget).toBeNull();
    // The stored revision, so whichever writer runs has a number to advance
    // FROM rather than a zero to fall back to.
    expect(read.sequence).toBe(3);
  });

  it("recognises a resource carrying ONLY an ORGANIZER, with nobody invited", async () => {
    // The gap the two cases above leave: both carry an ATTENDEE as well, so
    // either would still pass if the recognition only saw attendees. This is the
    // organiser on its own — and it is the property that actually protects what
    // probe P-1 (d) measured, because the opaque principal href iCloud assigns
    // lives on the ORGANIZER line and a rebuild would replace it with a plain
    // address regardless of who else is on the event.
    //
    // **It is also the case that rules out keying the commit's routing on the
    // change's own recipient list.** This resource has NOBODY whose address this
    // server can report — the organiser is an opaque href, so `recipientsOf`
    // yields an empty list — and yet it is exactly the resource a rebuild would
    // destroy. A router that asked "does the change name anyone" would send it
    // to the rebuild. This one asks the bytes.
    const uid = "organised-0032";
    const read = await readWith(
      uid,
      ics(
        ...ICS_HEAD,
        "BEGIN:VEVENT",
        `UID:${uid}`,
        "DTSTAMP:20260101T120000Z",
        "SUMMARY:Interview",
        "DTSTART:20260210T150000Z",
        "DTEND:20260210T160000Z",
        "SEQUENCE:2",
        // As iCloud stores it: an opaque href, not a mailto.
        "ORGANIZER;CN=Organizer;EMAIL=user@example.invalid:/1234567890/principal/",
        "END:VEVENT",
        "END:VCALENDAR",
      ),
    );

    expect(read.isScheduling).toBe(true);
    expect(read.unsupportedTarget).toBeNull();
    // Nobody this server could name, on the very resource the patch protects.
    expect(read.detail.attendees).toEqual([]);
  });

  it("classifies a reminder this server cannot rebuild as unsupported", async () => {
    // A VALARM is the ordinary case, not an exotic one: every event a person
    // sets a reminder on carries one, and a rewrite that dropped it would take
    // the reminder away without ever saying so.
    const uid = "alarmed-0012";
    expect(
      await readBody(
        uid,
        ics(
          ...ICS_HEAD,
          "BEGIN:VEVENT",
          `UID:${uid}`,
          "DTSTAMP:20260101T120000Z",
          "SUMMARY:Interview",
          "DTSTART:20260210T150000Z",
          "DTEND:20260210T160000Z",
          "BEGIN:VALARM",
          "ACTION:DISPLAY",
          "DESCRIPTION:Reminder",
          "TRIGGER:-PT15M",
          "END:VALARM",
          "END:VEVENT",
          "END:VCALENDAR",
        ),
      ),
    ).toBe("unsupported-properties");
  });

  it("classifies a resource whose URL does not name its UID", async () => {
    const href = `${WORK_PATH}not-the-uid.ics`;
    restub({ objects: { [WORK_PATH]: { [href]: SIMPLE_ICS } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId: null,
    });

    expect(read.unsupportedTarget).toBe("unnamed-resource");
  });

  it("accepts a UID whose href is PERCENT-ENCODED, which is the real shape", async () => {
    // Every UID iCloud mints carries an `@`, so the href that names it is
    // percent-encoded. A derivation that did not decode would refuse every
    // real event on the account while passing on the tidy fixture above.
    const uid = "d1e2f3a4@example.invalid";
    const href = `${WORK_PATH}${encodeURIComponent(uid)}.ics`;
    const body = ics(
      ...ICS_HEAD,
      "BEGIN:VEVENT",
      `UID:${uid}`,
      "DTSTAMP:20260101T120000Z",
      "SUMMARY:Interview",
      "DTSTART:20260210T150000Z",
      "DTEND:20260210T160000Z",
      "END:VEVENT",
      "END:VCALENDAR",
    );
    restub({ objects: { [WORK_PATH]: { [href]: body } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId: null,
    });

    expect(read.unsupportedTarget).toBeNull();
  });
});

describe("the etag assertion", () => {
  it("refuses undefined, an empty string and null", () => {
    // Three values and one reason: tsdav's header builder drops a falsy
    // `If-Match`, so all three produce an UNCONDITIONAL write that the server
    // answers 200 to. The failure looks exactly like success.
    for (const value of [undefined, "", null]) {
      let thrown: unknown;
      try {
        assertEtag(value);
      } catch (err) {
        thrown = err;
      }
      expect(thrown, `${String(value)} was admitted`).toBeInstanceOf(
        DavNotFoundError,
      );
    }
  });

  it("returns for a real etag", () => {
    expect(() => assertEtag('"abc"')).not.toThrow();
  });
});

describe("updateEvent and its conditional etag header", () => {
  it("issues exactly ONE PUT carrying the etag byte-exact as If-Match", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    await updateEvent(
      env, principal,
      createDavFetch(owner),
      SIMPLE_REF,
      SIMPLE_ICS,
      'W/"abc"',
    );

    // ONE. `withRediscovery` retries a read on a rediscoverable failure, and a
    // write leg that inherited it would send the PUT twice — and it is the
    // RETRY's failure the caller sees, so a write that landed reports stale.
    expect(one.observed.length).toBe(1);
    expect(one.observed[0].method).toBe("PUT");
    // The header, not the outcome. A weak etag round-trips unaltered.
    expect(one.observed[0].headers["if-match"]).toBe('W/"abc"');
    expect(one.observed[0].url).toBe(SIMPLE_URL);
    expect(sentUpdateBody(one)).toBe(SIMPLE_ICS);
  });

  it("throws BEFORE any request when the etag is an empty string", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      updateEvent(env, principal, createDavFetch(owner), SIMPLE_REF, SIMPLE_ICS, ""),
    );

    // The COUNT, not just the throw. The throw alone passes on an
    // implementation that sends first and validates after, and that
    // implementation has already made an unconditional write.
    expect(one.observed.length).toBe(0);
    expect(err).toBeInstanceOf(DavNotFoundError);
  });

  it("reports a 412 as a stale resource in exactly ONE request", async () => {
    const one = restub({
      objects: SIMPLE_OBJECTS,
      onRequest: (_url, method) =>
        method === "PUT" ? new Response(null, { status: 412 }) : null,
    });

    const err = await capture(() =>
      updateEvent(
        env, principal,
        createDavFetch(owner),
        SIMPLE_REF,
        SIMPLE_ICS,
        '"etag-1"',
      ),
    );

    expect(err).toBeInstanceOf(DavStaleResourceError);
    // ONE, so no re-discovery retry fired. Two would mean the caller is told
    // about the retry's failure rather than about the first attempt's.
    expect(one.observed.length).toBe(1);
  });

  it("refuses a collection URL that is not this account's own", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      updateEvent(
        env, principal,
        createDavFetch(owner),
        {
          calendarUrl: "https://attacker.example/1234567890/calendars/work/",
          objectUrl:
            "https://attacker.example/1234567890/calendars/work/simple-0009.ics",
          recurrenceId: null,
        },
        SIMPLE_ICS,
        '"etag-1"',
      ),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect(one.observed.length).toBe(0);
  });

  it("refuses a LEGITIMATE collection carrying a forged object URL", async () => {
    // BOTH urls, because each independently names what the server is asked
    // for: the object URL is the request target here, so checking the
    // collection alone is not checking the call.
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      updateEvent(
        env, principal,
        createDavFetch(owner),
        {
          calendarUrl: WORK_URL,
          objectUrl: "https://attacker.example/steal.ics",
          recurrenceId: null,
        },
        SIMPLE_ICS,
        '"etag-1"',
      ),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect(one.observed.length).toBe(0);
  });

  it("reports the ATTENDEE-REPLY race as stale too, and shows the reply afterwards", async () => {
    // The race criterion 4's wording does not name and production will
    // actually produce. RFC 6638 §3.2.10 exists because of it: an attendee
    // hitting Accept changes the resource with no client action at all, the
    // ETag moves, and a commit taken across that window 412s. Nobody edited
    // anything and nobody's work is at risk — which is exactly why the tool
    // says so on its `confirmToken` parameter, and why that disclosure is
    // checkable rather than decorative.
    //
    // Asserted at the SERVICE layer rather than through the two tools, and the
    // reason is a real property of this plan rather than convenience: a
    // resource carrying an attendee list is classified `scheduling` and the
    // preview mints no confirmation for it, because a rewrite that dropped an
    // ATTENDEE would make iCloud send that person a CANCELLATION. So this is
    // the layer at which the race can be expressed at all until CALW-06 lands.
    const uid = "invited-0014";
    const href = `${WORK_PATH}${uid}.ics`;
    const url = `https://p42-caldav.icloud.com${href}`;
    const ref = { calendarUrl: WORK_URL, objectUrl: url, recurrenceId: null };

    const invitation = (partstat: string): string =>
      ics(
        ...ICS_HEAD,
        "BEGIN:VEVENT",
        `UID:${uid}`,
        "DTSTAMP:20260101T120000Z",
        "SUMMARY:Interview with Northwind",
        "DTSTART:20260210T150000Z",
        "DTEND:20260210T160000Z",
        "ORGANIZER;CN=Priya Raman:mailto:priya.raman@example.invalid",
        `ATTENDEE;CN=Dev Whitaker;PARTSTAT=${partstat}:mailto:dev.whitaker@example.invalid`,
        "END:VEVENT",
        "END:VCALENDAR",
      );

    // 1. Read. Etag "A", and the attendee has not answered.
    const before = restub({
      objects: { [WORK_PATH]: { [href]: invitation("NEEDS-ACTION") } },
      etags: { [href]: '"etag-A"' },
    });
    const read = await getEventWithEtag(env, principal, createDavFetch(owner), ref);
    expect(before.observed.length).toBe(1);
    expect(read.etag).toBe('"etag-A"');
    expect(read.detail.attendees[0].partstat).toBe("NEEDS-ACTION");

    // 2. Somebody replies. The body differs ONLY in a participation status,
    //    and the next write is answered 412.
    const after = restub({
      objects: { [WORK_PATH]: { [href]: invitation("ACCEPTED") } },
      etags: { [href]: '"etag-B"' },
      onRequest: (_url, method) =>
        method === "PUT" ? new Response(null, { status: 412 }) : null,
    });

    // 3. The same refusal as an edit race, in the same one request.
    const err = await capture(() =>
      updateEvent(env, principal, createDavFetch(owner), ref, invitation("NEEDS-ACTION"), read.etag),
    );
    expect(err).toBeInstanceOf(DavStaleResourceError);
    expect(after.observed.length).toBe(1);
    expect(after.observed[0].headers["if-match"]).toBe('"etag-A"');

    // 4. And a fresh read shows the reply, which is what the user is told to
    //    go and look at.
    after.observed.length = 0;
    const again = await getEventWithEtag(env, principal, createDavFetch(owner), ref);
    expect(again.etag).toBe('"etag-B"');
    expect(again.detail.attendees[0].partstat).toBe("ACCEPTED");
  });

  it("mints an id that addresses the same resource afterwards", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const result = await updateEvent(
      env, principal,
      createDavFetch(owner),
      SIMPLE_REF,
      SIMPLE_ICS,
      '"etag-1"',
    );

    expect(one.observed.length).toBe(1);
    expect(result.applied).toBe(true);
    expect(decodeEventId(result.id).objectUrl).toBe(SIMPLE_URL);
    expect(decodeCalendarId(result.calendarId).collectionUrl).toBe(WORK_URL);
  });
});

// ---------------------------------------------------------------------------
// CALW-03 — the conditional DELETE
//
// Every case here asserts the OUTGOING REQUEST or its COUNT rather than the
// outcome, and the argument is the update section's carried one verb further.
// tsdav's `deleteObject` builds its headers through the SAME falsy-dropping
// helper `updateObject` does, so a delete called with an absent etag is an
// UNCONDITIONAL delete that the server answers 204 to. On the update path that
// is a lost edit. Here it is a lost event.
// ---------------------------------------------------------------------------

describe("deleteEvent and its conditional etag header", () => {
  it("issues exactly ONE DELETE carrying the etag byte-exact as If-Match", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    await deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, 'W/"abc"');

    expect(one.observed.length).toBe(1);
    expect(one.observed[0].method).toBe("DELETE");
    // The header, not the outcome. A weak etag round-trips unaltered.
    expect(one.observed[0].headers["if-match"]).toBe('W/"abc"');
    expect(one.observed[0].url).toBe(SIMPLE_URL);
    // A delete carries no body. The commit rebuilds nothing, which is the whole
    // reason the rewrite blockers do not apply to this path.
    expect(one.observed[0].body).toBeNull();
  });

  it("throws BEFORE any request when the etag is an empty string", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, ""),
    );

    // The COUNT, not just the throw. The throw alone passes on an
    // implementation that sends first and validates after, and that
    // implementation has already deleted the event unconditionally.
    expect(one.observed.length).toBe(0);
    expect(err).toBeInstanceOf(DavNotFoundError);
  });

  it("reports a 412 as a stale resource in exactly ONE request", async () => {
    const one = restub({
      objects: SIMPLE_OBJECTS,
      onRequest: (_url, method) =>
        method === "DELETE" ? new Response(null, { status: 412 }) : null,
    });

    const err = await capture(() =>
      deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, '"etag-1"'),
    );

    expect(err).toBeInstanceOf(DavStaleResourceError);
    expect(one.observed.length).toBe(1);
  });

  it("reports a 404 as not-found in exactly ONE request — already gone", async () => {
    // 404 IS re-discovery eligible in the shipped classification, so this is
    // the one place on the delete path where `allowRediscovery = false` is
    // doing visible work: remove it and the count becomes two, and the caller
    // is told about the RETRY's failure rather than about the first attempt's.
    const one = restub({
      objects: SIMPLE_OBJECTS,
      onRequest: (_url, method) =>
        method === "DELETE" ? new Response(null, { status: 404 }) : null,
    });

    const err = await capture(() =>
      deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, '"etag-1"'),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect(one.observed.length).toBe(1);
  });

  it("refuses a collection URL that is not this account's own", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      deleteEvent(
        env, principal,
        createDavFetch(owner),
        {
          calendarUrl: "https://attacker.example/1234567890/calendars/work/",
          objectUrl:
            "https://attacker.example/1234567890/calendars/work/simple-0009.ics",
          recurrenceId: null,
        },
        '"etag-1"',
      ),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect(one.observed.length).toBe(0);
  });

  it("refuses a LEGITIMATE collection carrying a forged object URL", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const err = await capture(() =>
      deleteEvent(
        env, principal,
        createDavFetch(owner),
        {
          calendarUrl: WORK_URL,
          objectUrl: "https://attacker.example/steal.ics",
          recurrenceId: null,
        },
        '"etag-1"',
      ),
    );

    expect(err).toBeInstanceOf(DavNotFoundError);
    expect(one.observed.length).toBe(0);
  });

  it("reports what it removed by the id and calendar it was given", async () => {
    const one = restub({ objects: SIMPLE_OBJECTS });

    const result = await deleteEvent(
      env, principal,
      createDavFetch(owner),
      SIMPLE_REF,
      '"etag-1"',
    );

    expect(one.observed.length).toBe(1);
    expect(result.applied).toBe(true);
    expect(decodeEventId(result.id).objectUrl).toBe(SIMPLE_URL);
    expect(decodeCalendarId(result.calendarId).collectionUrl).toBe(WORK_URL);
  });
});

// ---------------------------------------------------------------------------
// CALW-07 — the revision a rewrite emits, and the form a cancellation takes
//
// Both halves of this section are DECIDED ANSWERS rather than discoveries. The
// sequence half is arithmetic the format defines; the cancellation half is
// probe P-4's recorded measurement, and the RFC's description of what a server
// ought to do is explicitly not the authority for it.
// ---------------------------------------------------------------------------

/**
 * The same plain event, already revised twice by whoever edited it before.
 *
 * No attendee and no organiser, so it is a resource a rewrite is ALLOWED to
 * touch — which is what makes the sequence assertions reachable at all. The
 * scheduling refusal is asserted separately and is unchanged.
 */
const REVISED_UID = "revised-0009";
const REVISED_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  `UID:${REVISED_UID}`,
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Interview with Northwind",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  // Revision three: this meeting has been moved twice already.
  "SEQUENCE:3",
  "END:VEVENT",
  "END:VCALENDAR",
);

const REVISED_HREF = `${WORK_PATH}${REVISED_UID}.ics`;
const REVISED_URL = `https://p42-caldav.icloud.com${REVISED_HREF}`;
const REVISED_REF = {
  calendarUrl: WORK_URL,
  objectUrl: REVISED_URL,
  recurrenceId: null,
};

/** The same event with no sequence property at all — absent, not zero. */
const UNREVISED_UID = "unrevised-0009";
const UNREVISED_ICS = ics(
  ...ICS_HEAD,
  "BEGIN:VEVENT",
  `UID:${UNREVISED_UID}`,
  "DTSTAMP:20260101T120000Z",
  "SUMMARY:Interview with Northwind",
  "DTSTART:20260210T150000Z",
  "DTEND:20260210T160000Z",
  "END:VEVENT",
  "END:VCALENDAR",
);

const UNREVISED_HREF = `${WORK_PATH}${UNREVISED_UID}.ics`;
const UNREVISED_URL = `https://p42-caldav.icloud.com${UNREVISED_HREF}`;
const UNREVISED_REF = {
  calendarUrl: WORK_URL,
  objectUrl: UNREVISED_URL,
  recurrenceId: null,
};

/** One rewrite's worth of build input, with the sequence the caller is testing. */
function rewriteInput(sequence: number) {
  return {
    summary: "Interview with Northwind",
    startLocal: "2026-02-10T16:00:00",
    endLocal: "2026-02-10T17:00:00",
    tzid: "UTC",
    allDay: false,
    location: null,
    description: null,
    participants: null,
    sequence,
  };
}

/**
 * One property, PARSED off a resource rather than matched as a substring.
 *
 * A string match on the whole body cannot tell `SEQUENCE:4` on the event from
 * the same characters inside a folded description, and it reads the emitted
 * bytes rather than the value a client would actually resolve.
 */
function parsedProperty(icsText: string, name: string): unknown {
  return withParsedResource(icsText, (resource) => {
    expect(resource.components.length, "not a single-component resource").toBe(1);
    return resource.components[0].getFirstPropertyValue(name);
  });
}

describe("the revision a rewrite emits", () => {
  it("reports the sequence the FETCHED resource carried", async () => {
    restub({ objects: { [WORK_PATH]: { [REVISED_HREF]: REVISED_ICS } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), REVISED_REF);

    // Read off the resource, so the value costs no extra request — it comes
    // out of the same multi-get the etag does.
    expect(read.sequence).toBe(3);
  });

  it("reports an ABSENT sequence as absent, never as zero", async () => {
    restub({ objects: { [WORK_PATH]: { [UNREVISED_HREF]: UNREVISED_ICS } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), UNREVISED_REF);

    // Null rather than zero, so a reader can tell "the resource said zero" from
    // "the resource said nothing". Both take the next revision to one; the
    // distinction is kept because collapsing it here would be this module
    // deciding on the builder's behalf.
    expect(read.sequence).toBeNull();
  });

  it("takes a stored SEQUENCE:3 to SEQUENCE:4 on the wire", async () => {
    const one = restub({
      objects: { [WORK_PATH]: { [REVISED_HREF]: REVISED_ICS } },
    });

    await updateEvent(
      env, principal,
      createDavFetch(owner),
      REVISED_REF,
      updateEventBody(REVISED_REF, rewriteInput(0), 3),
      '"etag-1"',
    );

    // PARSED off the captured body. A resource whose revision went from three
    // back to zero is discarded as stale by every receiving client, and nothing
    // anywhere reports a problem.
    expect(parsedProperty(sentUpdateBody(one), "sequence")).toBe(4);
  });

  it("takes an ABSENT sequence to SEQUENCE:1, not SEQUENCE:0", async () => {
    const one = restub({
      objects: { [WORK_PATH]: { [UNREVISED_HREF]: UNREVISED_ICS } },
    });

    await updateEvent(
      env, principal,
      createDavFetch(owner),
      UNREVISED_REF,
      updateEventBody(UNREVISED_REF, rewriteInput(0), null),
      '"etag-1"',
    );

    expect(parsedProperty(sentUpdateBody(one), "sequence")).toBe(1);
  });

  it("IGNORES a sequence the caller put in the build input", async () => {
    // The rewrite path takes its revision from the FETCHED resource and from
    // nowhere else. A build input carrying a different one must not reach the
    // wire, or "read from the resource, never counted locally" would be true of
    // the arithmetic and false of the plumbing.
    const one = restub({
      objects: { [WORK_PATH]: { [REVISED_HREF]: REVISED_ICS } },
    });

    await updateEvent(
      env, principal,
      createDavFetch(owner),
      REVISED_REF,
      updateEventBody(REVISED_REF, rewriteInput(99), 3),
      '"etag-1"',
    );

    expect(parsedProperty(sentUpdateBody(one), "sequence")).toBe(4);
  });

  it("preserves the resource's own UID byte-exact", async () => {
    const one = restub({
      objects: { [WORK_PATH]: { [REVISED_HREF]: REVISED_ICS } },
    });

    await updateEvent(
      env, principal,
      createDavFetch(owner),
      REVISED_REF,
      updateEventBody(REVISED_REF, rewriteInput(0), 3),
      '"etag-1"',
    );

    // A changed UID is a DIFFERENT EVENT to every receiving client, which turns
    // an update into a second invitation and leaves the first one live in the
    // attendee's calendar. Byte-exact against the fetched resource's own value.
    expect(parsedProperty(sentUpdateBody(one), "uid")).toBe(
      parsedProperty(REVISED_ICS, "uid"),
    );
    expect(parsedProperty(sentUpdateBody(one), "uid")).toBe(REVISED_UID);
  });

  it("emits SEQUENCE:0 on a CREATE, which is a new event's first revision", async () => {
    const one = restub({});

    await createEvent(env, principal, createDavFetch(owner), {
      calendarId: encodeCalendarId({ collectionUrl: WORK_URL }),
      summary: "Interview with Northwind",
      startLocal: "2026-02-10T15:00:00",
      endLocal: "2026-02-10T16:00:00",
      tzid: "UTC",
    });

    const writes = one.observed.filter((request) => request.method === "PUT");
    expect(writes.length).toBe(1);
    expect(parsedProperty(writes[0].body!, "sequence")).toBe(0);
  });
});

describe("the form a cancellation takes, from probe P-4", () => {
  /**
   * An event with one person on it, live rather than already cancelled.
   *
   * Half A of P-4 was run against exactly this shape: a live invited event,
   * deleted in one step.
   */
  const INVITED_UID = "invited-0041";
  const INVITED_ICS = ics(
    ...ICS_HEAD,
    "BEGIN:VEVENT",
    `UID:${INVITED_UID}`,
    "DTSTAMP:20260101T120000Z",
    "SUMMARY:Interview",
    "DTSTART:20260210T150000Z",
    "DTEND:20260210T160000Z",
    "ORGANIZER;CN=Priya Raman:mailto:priya.raman@example.invalid",
    "ATTENDEE;CN=Dev Whitaker;PARTSTAT=ACCEPTED:mailto:dev.whitaker@example.invalid",
    "END:VEVENT",
    "END:VCALENDAR",
  );
  const INVITED_HREF = `${WORK_PATH}${INVITED_UID}.ics`;
  const INVITED_REF = {
    calendarUrl: WORK_URL,
    objectUrl: `https://p42-caldav.icloud.com${INVITED_HREF}`,
    recurrenceId: null,
  };

  it("cancels an ATTENDEE-CARRYING event with ONE plain DELETE and no PUT", async () => {
    // **This is P-4's recorded answer expressed as an assertion, and the RFC is
    // deliberately not the authority for it.** RFC 6638 describes a server
    // sending a cancellation on delete and implementations differ, so the
    // question was measured: a plain DELETE of a live invited event produced a
    // cancellation in the invitee's mailbox. The two-step route produced
    // exactly one cancellation as well, so it buys nothing and costs a second
    // write.
    //
    // The assertion is on the observed REQUEST SEQUENCE rather than on the
    // outcome, because both routes end with the resource gone and only the
    // request log can tell them apart.
    const one = restub({
      objects: { [WORK_PATH]: { [INVITED_HREF]: INVITED_ICS } },
    });

    await deleteEvent(env, principal, createDavFetch(owner), INVITED_REF, '"etag-1"');

    expect(one.observed.map((request) => request.method)).toEqual(["DELETE"]);
    // No cancellation body was written first. A PUT here would be the two-step
    // route, which P-4 measured as no better and one request worse.
    expect(one.observed[0].body).toBeNull();
  });

  it("cancels a NO-ATTENDEE event with the same single DELETE", async () => {
    // The same form on both paths, so there is no second code path to keep in
    // step. There is nobody to tell here, and a cancelled-but-present resource
    // left on the user's own calendar is a worse outcome than a deleted one.
    const one = restub({ objects: SIMPLE_OBJECTS });

    await deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, '"etag-1"');

    expect(one.observed.map((request) => request.method)).toEqual(["DELETE"]);
  });

  it("records P-4's answer in the shipped function's own docstring", () => {
    // The measurement ships beside the code that rests on it, on 04-07's
    // precedent. A probe answer that lives only in a planning artefact is one a
    // later session re-derives from the RFC and gets wrong.
    const source = Object.values(CALENDAR_SOURCE_GLOB)[0];
    const start = source.indexOf("export async function deleteEvent");
    expect(start, "deleteEvent is not in the shipped module").toBeGreaterThan(0);

    // The comment's own framing is stripped before matching, so the assertion
    // is about the WORDS rather than about where the block wraps. A test that
    // matched the wrapped form would go red on a reflow that changed nothing.
    const docstring = source
      .slice(0, start)
      .replace(/^[ \t]*\*[ \t]?/gm, "")
      .replace(/^[ \t]*>[ \t]?/gm, "")
      .replace(/\s+/g, " ");

    expect(docstring).toContain("P-4");
    // The verbatim answer, not a paraphrase of it.
    expect(docstring).toContain(
      "A plain `DELETE` sends the cancellation. The `STATUS:CANCELLED` pre-step is NOT required, and adding it does NOT double-send.",
    );
  });
});

// ---------------------------------------------------------------------------
// The standing unconditional-write gate
//
// A table over the SET of writers rather than an assertion per writer, so a
// writer added in a later plan of this phase is caught by OMISSION rather than
// by somebody remembering. The per-writer cases above stay: this one cannot
// tell a correct writer from a wrongly-tabulated one, and those can.
//
// 05-RESEARCH.md Pitfall 2 names the warning sign this exists for — *"a test
// that asserts the write succeeded but not that the request carried
// `If-Match`"* — and the reason it is a warning sign rather than a gap is that
// tsdav's header builder DROPS a falsy conditional header. The server then
// answers a success to the unconditional write, so the outcome is identical and
// only the header and the request count can tell the two apart.
// ---------------------------------------------------------------------------

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// `test/dav-home-containment.test.ts` carries the full argument for it.
const CALENDAR_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/dav/calendar.ts",
  { query: "?raw", import: "default", eager: true },
);

const CALENDAR_SOURCE: string = Object.values(CALENDAR_SOURCE_GLOB)[0] ?? "";

/** The tsdav primitives that mutate a calendar object. */
const WRITE_PRIMITIVES = [
  "createCalendarObject",
  "updateCalendarObject",
  "deleteCalendarObject",
];

/** A top-level function declaration, remembering whether it was exported. */
const TOP_LEVEL_DECLARATION = /^(export\s+)?(?:async\s+)?function\s+(\w+)/;

/**
 * Every EXPORTED function in the shipped module that reaches a write primitive.
 *
 * **Derived from the module rather than restated here, which is the whole
 * point.** A table compared against a literal array in this same file has two
 * sides that both live in the test: a writer added to `src/dav/calendar.ts` and
 * never mentioned changes neither, so the comparison passes and the new writer
 * ships unwatched. That is exactly what happened to the create shaper in the
 * fence audit, and `SHIPPED_SHAPERS` over there is the fix this mirrors.
 *
 * Keyed on the write PRIMITIVE rather than on a name shape, so plan 05-10's
 * `applyOccurrenceOverride` or 05-12's `truncateSeries` are caught by what they
 * do rather than by what they are called.
 *
 * Whole-line comments are blanked first, so a primitive discussed in prose —
 * and this module discusses all three at length — is not read as a call.
 */
function exportedWritersOf(source: string): string[] {
  const found = new Set<string>();
  let enclosing: string | null = null;

  for (const raw of source.split("\n")) {
    const trimmed = raw.trim();
    const line =
      trimmed.startsWith("//") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("*/") ||
      trimmed.startsWith("*")
        ? ""
        : raw;

    const declaration = TOP_LEVEL_DECLARATION.exec(line);
    // A non-exported top-level function CLEARS the enclosing name rather than
    // being ignored: the shared containment helper is one, and attributing its
    // body to whatever exported function happened to precede it would credit
    // that function with a call it does not make.
    if (declaration) {
      enclosing = declaration[1] === undefined ? null : declaration[2];
    }
    if (enclosing === null) continue;

    for (const primitive of WRITE_PRIMITIVES) {
      // The `(` is what keeps the import statement at the top of the module
      // from matching all three names at once.
      if (new RegExp(`\\b${primitive}\\s*\\(`).test(line)) found.add(enclosing);
    }
  }

  return [...found].sort();
}

/** The etag every tabulated conditional write is driven with. Weak, on purpose. */
const GATE_ETAG = 'W/"gate-etag"';

interface WriterCase {
  /** The conditional header this writer is REQUIRED to carry. */
  header: string;
  /** Its exact expected value. */
  value: string;
  /** Drive the writer through the stub. */
  drive: (etag: string | null | undefined) => Promise<unknown>;
  /**
   * Whether the conditional value is an ETag the caller supplies.
   *
   * `createEvent`'s is the literal `*` — "only if nothing is there" — which no
   * caller supplies and no caller can drop, so there is no falsy case for it.
   */
  etagBearing: boolean;
}

/**
 * Every write entry point, with the conditional header it must carry.
 *
 * A row missing from here is caught by the set equality below rather than by
 * being quietly unasserted, which is the difference between this table and
 * three separate `it` blocks.
 */
const CONDITIONAL_WRITE_GATE: Record<string, WriterCase> = {
  createEvent: {
    header: "if-none-match",
    value: "*",
    drive: () => createEvent(env, principal, createDavFetch(owner), createInput()),
    etagBearing: false,
  },
  updateEvent: {
    header: "if-match",
    value: GATE_ETAG,
    drive: (etag) =>
      updateEvent(env, principal, createDavFetch(owner), SIMPLE_REF, SIMPLE_ICS, etag),
    etagBearing: true,
  },
  deleteEvent: {
    header: "if-match",
    value: GATE_ETAG,
    drive: (etag) => deleteEvent(env, principal, createDavFetch(owner), SIMPLE_REF, etag),
    etagBearing: true,
  },
};

describe("no writer in this module can ship unconditional", () => {
  it("read the shipped module as text", () => {
    // Non-vacuity first. A `?raw` that resolved to nothing would leave the
    // derivation below producing an empty set, and an empty set compared
    // against an empty table passes while proving nothing at all.
    expect(
      CALENDAR_SOURCE.length,
      "the ?raw import of src/dav/calendar.ts loaded nothing",
    ).toBeGreaterThan(1000);
  });

  it("tabulates exactly the write entry points the module exports", () => {
    const derived = exportedWritersOf(CALENDAR_SOURCE);

    expect(
      derived.length,
      "the derivation found no exported writers at all, so the comparison below is between two empty sets",
    ).toBeGreaterThan(0);
    expect(
      Object.keys(CONDITIONAL_WRITE_GATE).sort(),
      [
        "The write entry points in src/dav/calendar.ts no longer match this table.",
        "",
        "If a writer was ADDED: give it a row naming the conditional header it must",
        "carry, and drive it below. tsdav DROPS a falsy conditional header, so an",
        "untabulated writer can ship unconditional and the server will answer it a",
        "success — which is indistinguishable from the write the caller wanted.",
        "",
        "If a writer was REMOVED: work out where it went before deleting the row.",
      ].join("\n"),
    ).toEqual(derived);
  });

  it("carries the required conditional header, with the exact value, on the wire", async () => {
    for (const [name, one] of Object.entries(CONDITIONAL_WRITE_GATE)) {
      const stub = restub({ objects: SIMPLE_OBJECTS });
      await one.drive(GATE_ETAG);

      const writes = stub.observed.filter(
        (request) => request.method === "PUT" || request.method === "DELETE",
      );
      expect(writes.length, `${name} issued no write`).toBe(1);
      expect(
        writes[0].headers[one.header],
        `${name} sent no ${one.header}, so its write is UNCONDITIONAL and the server answered it a success anyway`,
      ).toBe(one.value);
    }
  });

  it("throws with ZERO requests when the etag it was given is falsy", async () => {
    // Three falsy values and one reason: all three are dropped by the header
    // builder, so all three produce an unconditional write. The COUNT is the
    // assertion — a throw alone passes on an implementation that sends first
    // and validates after, and that implementation has already written.
    let driven = 0;
    for (const [name, one] of Object.entries(CONDITIONAL_WRITE_GATE)) {
      if (!one.etagBearing) continue;
      for (const value of [undefined, "", null]) {
        const stub = restub({ objects: SIMPLE_OBJECTS });
        const err = await capture(() => one.drive(value) as Promise<unknown>);

        expect(
          stub.observed.length,
          `${name} reached the network with a falsy etag (${String(value)})`,
        ).toBe(0);
        expect(err, `${name} admitted ${String(value)}`).toBeInstanceOf(
          DavNotFoundError,
        );
        driven += 1;
      }
    }

    // Non-vacuity: a table whose rows all claimed to bear no etag would skip
    // every iteration and pass.
    expect(driven, "no etag-bearing writer was driven").toBeGreaterThan(0);
  });
});

describe("what the etag read refuses to let a DELETE touch", () => {
  /**
   * The delete classification for one hand-built resource.
   *
   * A sibling of the rewrite one above, and the two answer differently ON
   * PURPOSE. Four of the five rewrite blockers exist to stop a REBUILD dropping
   * something by omission, and a delete rebuilds nothing — the whole resource
   * goes, so there is nothing left behind to have lost a reminder or an
   * attendee. Only the series case survives, and for the opposite reason: a
   * scopeless delete removes EVERY occurrence while the preview describes one.
   */
  async function deleteBlockerFor(
    uid: string,
    body: string,
    recurrenceId: string | null = null,
  ): Promise<string | null> {
    const href = `${WORK_PATH}${uid}.ics`;
    restub({ objects: { [WORK_PATH]: { [href]: body } } });
    const read = await getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId,
    });
    return read.unsupportedDeleteTarget;
  }

  it("refuses a series, because a scopeless delete removes all of it", async () => {
    const uid = "recurs-0020";
    expect(
      await deleteBlockerFor(
        uid,
        ics(
          ...ICS_HEAD,
          "BEGIN:VEVENT",
          `UID:${uid}`,
          "DTSTAMP:20260101T120000Z",
          "SUMMARY:Standup",
          "DTSTART:20260210T150000Z",
          "DTEND:20260210T151500Z",
          "RRULE:FREQ=WEEKLY;COUNT=4",
          "END:VEVENT",
          "END:VCALENDAR",
        ),
        "20260210T150000Z",
      ),
    ).toBe("recurring");
  });

  it("ADMITS an event carrying attendees, and so does the rewrite since 05-14", async () => {
    // The two classifications used to DISAGREE here, and this case existed to
    // pin the disagreement: a rewrite that dropped an `ATTENDEE` would make
    // iCloud send that person a cancellation nobody asked for, while a delete
    // removing the whole resource is the operation the user actually requested.
    //
    // They now agree, and the agreement is what plan 05-14 built. The rewrite
    // stopped dropping attendees — it PATCHES such a resource instead of
    // rebuilding it — so the reason for the divergence went away. What is
    // asserted below is that BOTH paths admit it and that the resource is still
    // recognised as one iCloud sends mail for, which is what selects the
    // patching writer. A build where the recognition was deleted would satisfy
    // both nulls and destroy the organiser on the next write.
    const uid = "invited-0021";
    const body = ics(
      ...ICS_HEAD,
      "BEGIN:VEVENT",
      `UID:${uid}`,
      "DTSTAMP:20260101T120000Z",
      "SUMMARY:Interview",
      "DTSTART:20260210T150000Z",
      "DTEND:20260210T160000Z",
      "ORGANIZER;CN=Priya Raman:mailto:priya.raman@example.invalid",
      "ATTENDEE;CN=Dev Whitaker:mailto:dev.whitaker@example.invalid",
      "END:VEVENT",
      "END:VCALENDAR",
    );
    const href = `${WORK_PATH}${uid}.ics`;
    restub({ objects: { [WORK_PATH]: { [href]: body } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId: null,
    });

    expect(read.unsupportedDeleteTarget).toBeNull();
    expect(read.unsupportedTarget).toBeNull();
    // The recognition that routes the rewrite to the patch. Without this line
    // the two nulls above are indistinguishable from a build that forgot the
    // resource carries people at all.
    expect(read.isScheduling).toBe(true);
  });

  it("ADMITS a reminder, a foreign UID and a zone it cannot anchor to", async () => {
    // Three rewrite blockers in one case, all of them absent on the delete
    // path. Each is a "the rebuild would silently drop this" argument, and a
    // delete drops the resource entire — deliberately, and at the user's
    // request.
    const uid = "alarmed-0022";
    const href = `${WORK_PATH}not-the-uid-0022.ics`;
    const body = ics(
      ...ICS_HEAD,
      "BEGIN:VEVENT",
      `UID:${uid}`,
      "DTSTAMP:20260101T120000Z",
      "SUMMARY:Interview",
      "DTSTART:20260210T150000Z",
      "DTEND:20260210T160000Z",
      "BEGIN:VALARM",
      "ACTION:DISPLAY",
      "DESCRIPTION:Reminder",
      "TRIGGER:-PT15M",
      "END:VALARM",
      "END:VEVENT",
      "END:VCALENDAR",
    );
    restub({ objects: { [WORK_PATH]: { [href]: body } } });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), {
      calendarUrl: WORK_URL,
      objectUrl: `https://p42-caldav.icloud.com${href}`,
      recurrenceId: null,
    });

    expect(read.unsupportedDeleteTarget).toBeNull();
    expect(read.unsupportedTarget).toBe("unsupported-properties");
  });

  it("reports NO delete blocker on the plain event, so the case above is not vacuous", async () => {
    restub({ objects: SIMPLE_OBJECTS });

    const read = await getEventWithEtag(env, principal, createDavFetch(owner), SIMPLE_REF);

    expect(read.unsupportedDeleteTarget).toBeNull();
    expect(read.unsupportedTarget).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The two builders the this-and-future write is assembled from
//
// Driven DIRECTLY rather than only through the tool boundary, on 02-08's MUT-M2
// reasoning: both carry an arm the shipped surface cannot reach, and a guard
// that is dead code until something later gives it work is invisible to every
// assertion around it.
// ---------------------------------------------------------------------------

/** A weekly series of four Mondays from 2026-04-06, in UTC. */
const ONWARD_SERIES_ICS = [
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "PRODID:-//Example Org//Synthesised Fixture//EN",
  "BEGIN:VEVENT",
  "UID:one-to-one-0041",
  "DTSTAMP:20260401T120000Z",
  "SUMMARY:One-to-one",
  "DTSTART:20260406T150000Z",
  "DTEND:20260406T153000Z",
  "RRULE:FREQ=WEEKLY;COUNT=4",
  "SEQUENCE:2",
  "END:VEVENT",
  "END:VCALENDAR",
  "",
].join("\r\n");

/** The change a this-and-future move of the third Monday asserts. */
const ONWARD_INPUT: BuildEventInput = {
  summary: "One-to-one (from the 20th at 16:00)",
  startLocal: "2026-04-20T16:00:00",
  endLocal: "2026-04-20T16:30:00",
  tzid: "UTC",
  allDay: false,
  location: null,
  description: null,
  participants: null,
  sequence: 0,
};

const ONWARD_REF = {
  calendarUrl: "https://p42-caldav.icloud.com/1234567890/calendars/work/",
  objectUrl:
    "https://p42-caldav.icloud.com/1234567890/calendars/work/one-to-one-0041.ics",
  recurrenceId: "20260420T150000Z",
};

describe("updateOccurrenceBody carries the reach (this-and-future)", () => {
  it("marks the identifier when the reach is forward, and not when it is not", () => {
    const onward = updateOccurrenceBody(
      ONWARD_REF,
      ONWARD_SERIES_ICS,
      ONWARD_INPUT,
      "this-and-future",
    );
    const single = updateOccurrenceBody(
      ONWARD_REF,
      ONWARD_SERIES_ICS,
      ONWARD_INPUT,
    );

    expect(onward).toContain("RANGE=THISANDFUTURE");
    expect(single).not.toContain("RANGE=THISANDFUTURE");
    // Both are ONE resource carrying master plus override, and both leave the
    // rule alone: the difference between them is a parameter, not a shape.
    for (const body of [onward, single]) {
      expect(body!.match(/BEGIN:VEVENT/g)?.length).toBe(2);
      expect(body).toContain("RRULE:FREQ=WEEKLY;COUNT=4");
      expect(body).not.toContain("UNTIL=");
    }
  });

  it("declines a target with no occurrence identifier", () => {
    // Unreachable through the tools — a scope is refused for a one-off event
    // before any body is built — so it is driven here or it is driven nowhere.
    expect(
      updateOccurrenceBody(
        { ...ONWARD_REF, recurrenceId: null },
        ONWARD_SERIES_ICS,
        ONWARD_INPUT,
        "this-and-future",
      ),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// patchEventBody — the one arm the tool boundary CANNOT reach
//
// Every path through the shipped tools refuses a series before a scopeless
// confirmation is minted, so this builder's null arm is unreachable from
// outside. Driven directly on 02-08's MUT-M2 reasoning: a guard nothing can
// reach is invisible to every assertion around it, and the day something CAN
// reach it is the day it has to already work.
// ---------------------------------------------------------------------------

describe("patchEventBody refuses anything that is not one plain event", () => {
  it("declines a SERIES, rather than patching whichever component came first", () => {
    // The hazard this arm exists for, stated as bytes: a master plus overrides
    // is one resource holding several events, and "the event this resource
    // holds" is not a thing it has. Patching component zero would move a date
    // nobody named, and the resource would still look well-formed afterwards.
    expect(patchEventBody(ONWARD_SERIES_ICS, ONWARD_INPUT)).toBeNull();
  });

  it("declines a lone override belonging to a master stored elsewhere", () => {
    // One component, so the count check alone passes — and it is still not this
    // resource's own event. The recurrence identifier is what says so.
    const orphan = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:-//Example Org//Synthesised Fixture//EN",
      "BEGIN:VEVENT",
      "UID:one-to-one-0041",
      "DTSTAMP:20260401T120000Z",
      "RECURRENCE-ID:20260420T150000Z",
      "SUMMARY:One-to-one",
      "DTSTART:20260420T150000Z",
      "DTEND:20260420T153000Z",
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    ].join("\r\n");

    expect(patchEventBody(orphan, ONWARD_INPUT)).toBeNull();
  });

  it("patches a plain one-off event, which is the control", () => {
    // Without this, both refusals above are satisfied by a builder that returns
    // null for everything.
    const plain = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:-//Example Org//Synthesised Fixture//EN",
      "BEGIN:VEVENT",
      "UID:one-to-one-0041",
      "DTSTAMP:20260401T120000Z",
      "SUMMARY:One-to-one",
      "DTSTART:20260420T150000Z",
      "DTEND:20260420T153000Z",
      "SEQUENCE:2",
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    ].join("\r\n");

    const body = patchEventBody(plain, ONWARD_INPUT);
    expect(body).not.toBeNull();
    expect(body).toContain("DTSTART;TZID=UTC:20260420T160000");
    // Advanced from the stored two by exactly one.
    expect(body).toContain("SEQUENCE:3");
    // And the UID is the resource's own, never derived and never re-minted.
    expect(body).toContain("UID:one-to-one-0041");
  });
});

describe("pinnedOccurrencesFor (this-and-future)", () => {
  it("finds nothing on a series nobody has edited by hand", () => {
    expect(
      pinnedOccurrencesFor(ONWARD_SERIES_ICS, ONWARD_REF.recurrenceId),
    ).toEqual({ count: 0, starts: [] });
  });

  it("names a later date somebody DID edit, and counts it", () => {
    const edited = updateOccurrenceBody(
      ONWARD_REF,
      ONWARD_SERIES_ICS,
      ONWARD_INPUT,
    )!;
    // Asked from the SECOND Monday, so the third — the one just edited — is a
    // later date with an arrangement of its own.
    expect(pinnedOccurrencesFor(edited, "20260413T150000Z")).toEqual({
      count: 1,
      starts: ["2026-04-20T15:00:00"],
    });
  });

  it("answers nothing for a target with no occurrence identifier", () => {
    // The other unreachable arm, and the same reason: a scope never reaches a
    // write against a one-off event, so nothing on the shipped surface can ask
    // this question.
    expect(pinnedOccurrencesFor(ONWARD_SERIES_ICS, null)).toEqual({
      count: 0,
      starts: [],
    });
  });
});

// ---------------------------------------------------------------------------
// SCHED-01 — finding free slots across every calendar
//
// The multi-calendar free/busy sweep and gap-finding engine. Every fixture is
// invented, tzid is UTC unless a case says otherwise (so a wall clock and its
// instant are the same string of digits and every candidate is predictable),
// and the working window is deliberately narrow — 09:00 to 11:00 with a 60-
// minute duration yields exactly three candidate starts a day (09:00, 09:30,
// 10:00), which is small enough to write the whole expected list down.
//
// The account this describes has three READABLE calendars, one of which is a
// read-only SUBSCRIPTION with a CS:source feed — the concrete D-84 example (the
// account's "Work" calendar, confirmed unwritable in phase 5). Its feed is
// served through the same mocked `fetchSubscriptionFeed` the listing tests use.
// ---------------------------------------------------------------------------

/** A subscription feed carrying no events — the zero-busy shape. */
const EMPTY_FEED = ics(...ICS_HEAD, "END:VCALENDAR");

/** The three readable calendars: two ordinary, one read-only subscription. */
const FS_COLLECTIONS: CollectionSpec[] = [
  {
    href: WORK_PATH,
    displayName: "Work",
    resourceType: ["collection", "calendar"],
    components: ["VEVENT"],
  },
  {
    href: HOME_PATH,
    displayName: "Home",
    resourceType: ["collection", "calendar"],
    components: ["VEVENT"],
  },
  {
    href: SUBSCRIBED_PATH,
    displayName: "Subscribed",
    resourceType: ["collection", "subscribed"],
    components: ["VEVENT"],
    source: FEED_URL,
  },
];

/** A timed VEVENT at explicit UTC instants, in its own resource. */
function timedEventIcs(uid: string, dtstart: string, dtend: string): string {
  return ics(
    ...ICS_HEAD,
    "BEGIN:VEVENT",
    `UID:${uid}@example.invalid`,
    "DTSTAMP:20260101T120000Z",
    `SUMMARY:Busy ${uid}`,
    `DTSTART:${dtstart}`,
    `DTEND:${dtend}`,
    "SEQUENCE:0",
    "END:VEVENT",
    "END:VCALENDAR",
  );
}

/** An all-day VEVENT, whose DTEND is the exclusive day after the last busy day. */
function allDayEventIcs(uid: string, startDate: string, endDate: string): string {
  return ics(
    ...ICS_HEAD,
    "BEGIN:VEVENT",
    `UID:${uid}@example.invalid`,
    "DTSTAMP:20260101T120000Z",
    `SUMMARY:All day ${uid}`,
    `DTSTART;VALUE=DATE:${startDate}`,
    `DTEND;VALUE=DATE:${endDate}`,
    "SEQUENCE:0",
    "END:VEVENT",
    "END:VCALENDAR",
  );
}

// Monday 2026-01-05, Tuesday the 6th, Wednesday the 7th. The range end is the
// following midnight, so all three weekdays are inside a half-open range.
const FS_RANGE_START = at("2026-01-05T00:00:00Z");
const FS_RANGE_END = at("2026-01-08T00:00:00Z");
const FS_ONE_DAY_END = at("2026-01-06T00:00:00Z");

function fsOptions(overrides: Partial<FindSlotsOptions> = {}): FindSlotsOptions {
  return {
    rangeStart: FS_RANGE_START,
    rangeEnd: FS_RANGE_END,
    durationMinutes: 60,
    tzid: "UTC",
    workDayStartLocal: "09:00",
    workDayEndLocal: "11:00",
    workDays: [1, 2, 3, 4, 5],
    ...overrides,
  };
}

/**
 * Point the sweep at the find-slots account and give the subscription its feed.
 *
 * The default `beforeEach` warmed discovery against the default stub; this only
 * swaps the conversation, never the cache state, exactly as the listing cases do.
 */
function setupFindSlots(
  opts: {
    collections?: CollectionSpec[];
    objects?: Record<string, Record<string, string>>;
    feed?: string;
  } = {},
): Stub {
  const next = restub({
    collections: opts.collections ?? FS_COLLECTIONS,
    objects: opts.objects ?? {},
  });
  vi.mocked(fetchSubscriptionFeed).mockResolvedValue(opts.feed ?? EMPTY_FEED);
  return next;
}

/** The local start strings of a page's candidates, in order. */
function startsOf(candidates: { startLocal: string }[]): string[] {
  return candidates.map((one) => one.startLocal);
}

describe("findFreeSlots across every calendar", () => {
  it("returns the full working-hours window for every working day when nothing is busy", () => {
    setupFindSlots();

    return findFreeSlots(env, principal, createDavFetch(owner), fsOptions()).then((page) => {
      // Three candidates a day (09:00, 09:30, 10:00), three working days, in
      // ascending order — a subscribed calendar with an empty feed still counts.
      expect(startsOf(page.candidates)).toEqual([
        "2026-01-05T09:00:00",
        "2026-01-05T09:30:00",
        "2026-01-05T10:00:00",
        "2026-01-06T09:00:00",
        "2026-01-06T09:30:00",
        "2026-01-06T10:00:00",
        "2026-01-07T09:00:00",
        "2026-01-07T09:30:00",
        "2026-01-07T10:00:00",
      ]);
      expect(page.candidates.every((one) => one.tzid === "UTC")).toBe(true);
      expect(page.candidates[0].endLocal).toBe("2026-01-05T10:00:00");
      expect(page.hasMore).toBe(false);
      expect(page.nextCursor).toBeNull();
      expect(page.unsupportedTimezone).toBeNull();
    });
  });

  it("treats a busy interval that abuts a slot as free, and an overlapping one as busy", async () => {
    // Busy 09:00–10:00 on Monday. A candidate starting the instant it ends is
    // NOT a conflict; one whose span overlaps any part of it IS.
    setupFindSlots({
      objects: {
        [WORK_PATH]: {
          [`${WORK_PATH}busy.ics`]: timedEventIcs(
            "abut",
            "20260105T090000Z",
            "20260105T100000Z",
          ),
        },
      },
    });

    const page = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ rangeEnd: FS_ONE_DAY_END }),
    );

    // 09:00 and 09:30 both overlap [09:00,10:00); 10:00 abuts its end and is kept.
    expect(startsOf(page.candidates)).toEqual(["2026-01-05T10:00:00"]);
  });

  it("blocks the whole named local day for an all-day event on any calendar", async () => {
    // An all-day event on Tuesday, on the HOME calendar, blocks every working
    // hour that day across the aggregate — never silently dropped for lacking an
    // instant, which would be a false 'you are free'.
    setupFindSlots({
      objects: {
        [HOME_PATH]: {
          [`${HOME_PATH}holiday.ics`]: allDayEventIcs(
            "holiday",
            "20260106",
            "20260107",
          ),
        },
      },
    });

    const page = await findFreeSlots(env, principal, createDavFetch(owner), fsOptions());

    expect(startsOf(page.candidates)).toEqual([
      "2026-01-05T09:00:00",
      "2026-01-05T09:30:00",
      "2026-01-05T10:00:00",
      "2026-01-07T09:00:00",
      "2026-01-07T09:30:00",
      "2026-01-07T10:00:00",
    ]);
    // Nothing on the blocked day.
    expect(
      page.candidates.some((one) => one.startLocal.startsWith("2026-01-06")),
    ).toBe(false);
  });

  it("pages a result larger than the page, resuming with no candidate repeated or skipped", async () => {
    setupFindSlots();

    const first = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ pageSize: 4 }),
    );
    expect(first.candidates.length).toBe(4);
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).not.toBeNull();

    const second = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ pageSize: 4, cursor: first.nextCursor! }),
    );

    // The next window begins exactly after the last row of the first page.
    expect(startsOf(second.candidates)).toEqual([
      "2026-01-06T09:30:00",
      "2026-01-06T10:00:00",
      "2026-01-07T09:00:00",
      "2026-01-07T09:30:00",
    ]);
    // No candidate on both pages.
    for (const start of startsOf(first.candidates)) {
      expect(startsOf(second.candidates)).not.toContain(start);
    }
  });

  it("refuses a cursor resumed against a different duration, before any request", async () => {
    const stubbed = setupFindSlots();
    stubbed.observed.length = 0;

    // Minted under a 60-minute duration; resumed asking for 90. The service
    // compares the pinned axes AFTER the range pin and BEFORE the network read.
    const cursor = encodeSlotCursor({
      rangeStart: FS_RANGE_START,
      rangeEnd: FS_RANGE_END,
      durationMinutes: 60,
      tzid: "UTC",
      workDayStartLocal: "09:00",
      workDayEndLocal: "11:00",
      workDaysKey: "12345",
      lastCandidateStart: FS_RANGE_START + 9 * 3600,
    });

    const err = await capture(() =>
      findFreeSlots(
        env, principal,
        createDavFetch(owner),
        fsOptions({ durationMinutes: 90, cursor }),
      ),
    );
    expect(err).toBeInstanceOf(DavNotFoundError);
    // Refused before the network read: not one request was made.
    expect(stubbed.observed.length).toBe(0);
  });

  it("reports an unsupported timezone with no candidates and makes NO request", async () => {
    // The warm stub from beforeEach; its observed log was cleared by `warm`.
    stub.observed.length = 0;

    const page = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ tzid: "Mars/Olympus" }),
    );

    expect(page.unsupportedTimezone).toBe("Mars/Olympus");
    expect(page.candidates).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    // The zone check is the cheapest possible refusal — before discovery, before
    // enumeration, before any REPORT.
    expect(stub.observed.length).toBe(0);
  });

  // ------------------------------------------------------------------------
  // Task 3 edge cases — the shapes the seven behaviours above do not cover.
  // ------------------------------------------------------------------------

  it("returns the full working window when the account has ZERO calendars", async () => {
    // Distinct from the zero-busy case above: there is nothing to sweep at all,
    // so the free/busy set is empty by a different route and the window is whole.
    setupFindSlots({ collections: [] });

    const page = await findFreeSlots(env, principal, createDavFetch(owner), fsOptions());

    expect(startsOf(page.candidates)).toEqual([
      "2026-01-05T09:00:00",
      "2026-01-05T09:30:00",
      "2026-01-05T10:00:00",
      "2026-01-06T09:00:00",
      "2026-01-06T09:30:00",
      "2026-01-06T10:00:00",
      "2026-01-07T09:00:00",
      "2026-01-07T09:30:00",
      "2026-01-07T10:00:00",
    ]);
  });

  it("merges OVERLAPPING busy intervals from two DIFFERENT calendars into one block", async () => {
    // Work is busy 09:00–10:00, Home 09:30–10:30 — overlapping, on two separate
    // calendars. They merge into one blocked span [09:00,10:30), so the first
    // free candidate on a 09:00–12:00 window is 10:30, not 10:00.
    setupFindSlots({
      objects: {
        [WORK_PATH]: {
          [`${WORK_PATH}a.ics`]: timedEventIcs(
            "work-a",
            "20260105T090000Z",
            "20260105T100000Z",
          ),
        },
        [HOME_PATH]: {
          [`${HOME_PATH}b.ics`]: timedEventIcs(
            "home-b",
            "20260105T093000Z",
            "20260105T103000Z",
          ),
        },
      },
    });

    const page = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ rangeEnd: FS_ONE_DAY_END, workDayEndLocal: "12:00" }),
    );

    // Grid anchored at 09:00: 10:30 and 11:00 fit a 60-minute slot before 12:00.
    expect(startsOf(page.candidates)).toEqual([
      "2026-01-05T10:30:00",
      "2026-01-05T11:00:00",
    ]);
  });

  it("walks every page and returns exactly the one-page multiset, no gap and no duplicate", async () => {
    setupFindSlots();

    const whole = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({ pageSize: 100 }),
    );
    const wholeStarts = startsOf(whole.candidates);
    expect(whole.hasMore).toBe(false);

    // The same result, gathered one candidate at a time through the cursor.
    const walked: string[] = [];
    let cursor: string | undefined;
    for (let guard = 0; guard < 100; guard += 1) {
      const page: import("../src/dav/calendar").SlotPage = await findFreeSlots(
        env, principal,
        createDavFetch(owner),
        fsOptions({ pageSize: 1, cursor }),
      );
      walked.push(...startsOf(page.candidates));
      if (!page.hasMore || page.nextCursor === null) break;
      cursor = page.nextCursor;
    }

    expect(walked).toEqual(wholeStarts);
    expect(new Set(walked).size).toBe(walked.length);
  });

  it("fails closed on a truncated sweep: zero candidates, not candidates-with-a-flag (CR-01)", async () => {
    // A minute-by-minute rule over the three-day range trips the expansion cap,
    // so at least one calendar's busy time is under-counted. Under-counted busy
    // must NEVER surface as a free slot: the response returns an EMPTY candidate
    // set with `truncated: true`, rather than candidates computed from an
    // incomplete busy set. This is the inverted safety valence `SlotPage`
    // documents — for this tool a truncated result carries NO candidates.
    setupFindSlots({
      objects: { [WORK_PATH]: { [`${WORK_PATH}minutely.ics`]: MINUTELY_ICS } },
    });

    const page = await findFreeSlots(env, principal, createDavFetch(owner), fsOptions());

    expect(page.truncated).toBe(true);
    expect(page.candidates).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    expect(page.unsupportedTimezone).toBeNull();
  });

  it("does not abort on a source-less subscribed calendar; fails closed instead (CR-02)", async () => {
    // A subscribed calendar whose CS:source is absent cannot be read. It must
    // not throw and abort the whole sweep (the CR-02 bug), and it must not be
    // silently dropped as zero-busy (an under-count, CR-01's false-free
    // direction). It counts as an incomplete sweep, so the response fails
    // closed: no candidates, `truncated: true` — even though the readable Work
    // calendar is empty and would otherwise offer the full window.
    setupFindSlots({
      collections: [
        {
          href: WORK_PATH,
          displayName: "Work",
          resourceType: ["collection", "calendar"],
          components: ["VEVENT"],
        },
        {
          href: SUBSCRIBED_PATH,
          displayName: "Holidays",
          resourceType: ["collection", "subscribed"],
          components: ["VEVENT"],
          // No `source` — the CS:source property is absent entirely, so the
          // parsed collection carries `source: null`.
        },
      ],
      objects: {},
    });

    const page = await findFreeSlots(env, principal, createDavFetch(owner), fsOptions());

    expect(page.truncated).toBe(true);
    expect(page.candidates).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
  });

  // ------------------------------------------------------------------------
  // WR-01 — the non-UTC, DST and unresolved-zone paths every case above skips.
  //
  // Every other find-slots case runs in UTC, which has no offset and no DST
  // transition — so the per-day offset math, the day-walk across a DST boundary,
  // and the whole-day block anchored to LOCAL rather than UTC midnight are all
  // unexercised. These two drive them in America/New_York, whose spring-forward
  // is 2026-03-08 (EST -0500 before, EDT -0400 after).
  // ------------------------------------------------------------------------

  it("anchors the working-hours window per day across a DST transition (WR-01)", async () => {
    // Friday 2026-03-06 is EST (-0500); Monday 2026-03-09 is EDT (-0400), the
    // first working day after spring-forward. A busy event at 09:00–10:00 LOCAL
    // on each day sits at a DIFFERENT UTC instant either side of the boundary —
    // 14:00–15:00Z on the Friday, 13:00–14:00Z on the Monday. If the offset were
    // not recomputed per day, one of the two busy hours would land on the wrong
    // local slot and the assertion would break.
    setupFindSlots({
      objects: {
        [WORK_PATH]: {
          // Friday 09:00–10:00 EST.
          [`${WORK_PATH}fri.ics`]: timedEventIcs(
            "fri",
            "20260306T140000Z",
            "20260306T150000Z",
          ),
          // Monday 09:00–10:00 EDT.
          [`${WORK_PATH}mon.ics`]: timedEventIcs(
            "mon",
            "20260309T130000Z",
            "20260309T140000Z",
          ),
        },
      },
    });

    const page = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({
        // Fri 2026-03-06 00:00 EST … Tue 2026-03-10 00:00 EDT — the Friday and
        // the Monday are the only two working days inside it.
        rangeStart: at("2026-03-06T05:00:00Z"),
        rangeEnd: at("2026-03-10T04:00:00Z"),
        tzid: "America/New_York",
      }),
    );

    // 09:00 and 09:30 overlap the busy hour on each day; 10:00 abuts its end and
    // fits a 60-minute slot before 11:00. The SAME local wall clocks on both
    // days, which is the anchoring property — even though the UTC instants of the
    // day boundaries and the busy hour differ across the transition.
    expect(startsOf(page.candidates)).toEqual([
      "2026-03-06T10:00:00",
      "2026-03-09T10:00:00",
    ]);
    expect(page.candidates.every((one) => one.tzid === "America/New_York")).toBe(
      true,
    );
    expect(page.truncated).toBe(false);
  });

  it("blocks the whole named LOCAL day for an unresolved-zone occurrence (WR-01)", async () => {
    // A timed occurrence whose TZID this server never resolves has no instant
    // (EventTime.utc absent), so it blocks its whole named local day rather than
    // being dropped — the must-never-be-wrong direction. UNDEFINED_TIMEZONE_ICS
    // names Tuesday 2026-03-10 (in Australia/Sydney, which is not allowlisted).
    // Read against a caller tzid of America/New_York — where local midnight is
    // NOT UTC midnight — the block must span the local Tuesday, leaving Monday
    // and Wednesday whole.
    setupFindSlots({
      objects: {
        [WORK_PATH]: {
          [`${WORK_PATH}floating.ics`]: UNDEFINED_TIMEZONE_ICS,
        },
      },
    });

    const page = await findFreeSlots(
      env, principal,
      createDavFetch(owner),
      fsOptions({
        // Mon 2026-03-09 00:00 EDT … Thu 2026-03-12 00:00 EDT — Mon, Tue, Wed.
        rangeStart: at("2026-03-09T04:00:00Z"),
        rangeEnd: at("2026-03-12T04:00:00Z"),
        tzid: "America/New_York",
      }),
    );

    expect(startsOf(page.candidates)).toEqual([
      "2026-03-09T09:00:00",
      "2026-03-09T09:30:00",
      "2026-03-09T10:00:00",
      "2026-03-11T09:00:00",
      "2026-03-11T09:30:00",
      "2026-03-11T10:00:00",
    ]);
    // Nothing on the blocked local Tuesday.
    expect(
      page.candidates.some((one) => one.startLocal.startsWith("2026-03-10")),
    ).toBe(false);
    expect(page.truncated).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CALM-04 — creating a calendar collection
//
// The tracer slice, at the service layer. These cases can tell a buildable
// method from an unbuildable one, because 17-01 made every stub in this
// repository construct a real `Request` before recording that it was sent —
// so a create reaching for the RFC 4791 method this runtime refuses would
// throw out of the stub rather than look green.
// ---------------------------------------------------------------------------

/**
 * A server's refusal to create the collection, in the shape RFC 5689 gives it.
 *
 * `DAV:mkcol-response` and deliberately NOT a `DAV:multistatus`: the library
 * reports the ENVELOPE's status only for a body that is not a multistatus, and
 * this is the shape the specification actually defines for the case. § 3.5's
 * own example carries it under `403`; the `207` here is the status that matters
 * to D-06, because it is the one sitting inside the range every other layer
 * reads as success.
 */
const MKCOL_REFUSAL_BODY =
  '<?xml version="1.0" encoding="UTF-8"?>' +
  '<d:mkcol-response xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">' +
  "<d:propstat><d:prop><c:supported-calendar-component-set/></d:prop>" +
  "<d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat>" +
  "</d:mkcol-response>";

/** Answer every collection create with one status, and everything else normally. */
function creatingStub(answer: () => Response): Stub {
  return davStub({
    onRequest: (_url, method) => (method === "MKCOL" ? answer() : null),
  });
}

/** The one create this suite drives, with the fixture's own name and colour. */
function createOne(): Promise<{ id: string; displayName: string; color: string }> {
  return createCalendarCollection(env, principal, createDavFetch(owner), {
    displayName: "Job search",
    color: "#1f77b4",
  });
}

describe("the wire form of a calendar colour", () => {
  it("appends the alpha pair and changes nothing else", () => {
    // The CASE is pinned, and it is pinned because neither case means anything
    // on the wire and exactly one of them has to be chosen or it drifts between
    // call sites. Uppercase, matching SPIKE-04's live probe value; the six
    // digits are handed back in whatever case the CALLER wrote them in, because
    // re-casing somebody's value is a change to it nobody asked for.
    expect(calendarColorForWire("#1f77b4")).toBe("#1f77b4FF");
    expect(calendarColorForWire("#1F77B4")).toBe("#1F77B4FF");
  });

  it("emits eight hex digits and no Apple swatch attribute", () => {
    const wire = calendarColorForWire("#7f7f7f");

    expect(wire).toMatch(/^#[0-9A-Fa-f]{8}$/);
    // This server has no swatch vocabulary, and inventing one would put a claim
    // on the resource the user never made.
    expect(wire).not.toContain("symbolic");
  });
});

describe("creating a calendar collection (CALM-04)", () => {
  it("issues ONE extended MKCOL, at a URL under the resolved home", async () => {
    const stub = creatingStub(() => new Response(null, { status: 201 }));
    await warm(stub);

    const created = await createOne();

    // ONE. A collection create is one round trip against an account whose
    // connection ceiling is lower than the platform's and undocumented.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("MKCOL");

    const target = stub.observed[0].url;
    expect(target.startsWith(CALDAV_HOME)).toBe(true);
    // The trailing slash is ON THE SEGMENT. A collection URL without one is a
    // different URL, and `assertUnderHome` compares pathname prefixes.
    expect(target.endsWith("/")).toBe(true);
    // The only free component is generated locally. Nothing a caller supplies
    // reaches this URL — `CreateCalendarInput` carries a name and a colour.
    expect(target.slice(CALDAV_HOME.length)).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/$/,
    );

    // The returned id round-trips to the URL the request actually targeted, so
    // the calendar is addressable by every other calendar tool the moment it
    // exists — and the id names the collection that was made rather than one
    // this test named.
    expect(decodeCalendarId(created.id).collectionUrl).toBe(target);
    expect(created.displayName).toBe("Job search");
    // The six-digit form the caller supplied, NOT the eight-digit wire form.
    expect(created.color).toBe("#1f77b4");
  });

  it("sends the three properties SPIKE-04 measured, and no fourth", async () => {
    const stub = creatingStub(() => new Response(null, { status: 201 }));
    await warm(stub);

    await createOne();
    const body = String(stub.observed[0].body);

    // The PAIR is what makes the result a calendar collection rather than a
    // plain WebDAV one. Both children, asserted separately, because dropping
    // the second silently creates the wrong kind of thing.
    expect(body).toContain("<d:resourcetype>");
    expect(body).toContain("<d:collection/>");
    expect(body).toContain("<c:calendar/>");
    expect(body).toContain("<d:displayname>Job search</d:displayname>");
    expect(body).toContain(
      "<ca:calendar-color>#1f77b4FF</ca:calendar-color>",
    );

    // NOT sent, and this is the assertion that keeps it that way. RFC 5689 § 3
    // is all-or-nothing: one property iCloud declines kills the whole create,
    // and whether iCloud accepts this element inside an extended MKCOL is
    // unmeasured in either direction. `collectionsFrom` already admits a
    // collection declaring an empty component set, so omitting it costs the
    // listing nothing.
    expect(body).not.toContain("supported-calendar-component-set");

    // The three namespaces the measured request declared, all on the one root.
    expect(body).toContain('xmlns:d="DAV:"');
    expect(body).toContain('xmlns:c="urn:ietf:params:xml:ns:caldav"');
    expect(body).toContain('xmlns:ca="http://apple.com/ns/ical/"');
  });

  it("carries a credential built by the transport and by nothing else", async () => {
    const stub = creatingStub(() => new Response(null, { status: 201 }));
    await warm(stub);

    await createOne();

    // The service module passes `headers: {}`. What arrives is the transport's,
    // and only the transport's: `createDavFetch` is the single place a
    // credential may be attached, which the scan holds as a COUNT rather than a
    // prohibition. This case pins the observable half — the credential is
    // present and is the Basic form that seam builds — and the structural half
    // is that there is nowhere else it could have come from.
    expect(stub.observed[0].headers.authorization.startsWith("Basic ")).toBe(
      true,
    );
    expect(stub.observed[0].headers["content-type"]).toContain("xml");
  });

  it("accepts a 200 as readily as a 201, so `=== 201` is not the predicate", async () => {
    // The mirror-image error D-06 is narrow to avoid: demanding 201 exactly
    // would record a server answering 200 to a genuine creation as having
    // refused, and the user would be told nothing was made when something was.
    for (const status of [200, 201, 204] as const) {
      const stub = creatingStub(() => new Response(null, { status }));
      await warm(stub);

      const created = await createOne();
      expect(created.id.length, `a ${status} was not treated as a success`).toBeGreaterThan(0);
      expect(decodeCalendarId(created.id).collectionUrl).toBe(
        stub.observed[0].url,
      );
    }
  });

  it("treats a 207 as a REFUSAL and reports nothing as created", async () => {
    const stub = creatingStub(
      () =>
        new Response(MKCOL_REFUSAL_BODY, {
          status: 207,
          headers: { "content-type": "text/xml; charset=utf-8" },
        }),
    );
    await warm(stub);

    // It throws rather than returning something with a caveat on it. There is
    // no shape in which a refused create comes back as a value: `CreatedCalendar`
    // has no `created` field to be false, deliberately, because a field that can
    // only ever say `true` is one nobody can read an answer out of.
    let outcome: unknown = "no refusal";
    try {
      outcome = await createOne();
    } catch (err) {
      outcome = err;
    }

    expect(
      outcome,
      "a 207 came back as a created calendar — RFC 5689 § 3 says nothing was created",
    ).toBeInstanceOf(DavConnectError);
    // The request WAS issued; it is the ANSWER that is refused. Asserted so the
    // case cannot pass by failing earlier than the status classification.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("MKCOL");
  });

  it("refuses a 207 whether or not the transport would have let it through", async () => {
    // The layering claim, made checkable. `throwForStatus` in
    // `src/dav/transport.ts` RETURNS for the whole 2xx range, so a 207 reaches
    // the service layer looking exactly like a success — which is why D-06's
    // refusal has to live there. If the transport ever started refusing 207
    // this case would still pass, and if the service layer stopped refusing it
    // this case goes red on its own.
    const stub = creatingStub(
      () =>
        new Response(MKCOL_REFUSAL_BODY, {
          status: 207,
          headers: { "content-type": "text/xml; charset=utf-8" },
        }),
    );
    await warm(stub);

    await expect(createOne()).rejects.toBeInstanceOf(DavConnectError);
    // Nothing about the server's answer is carried out of this layer: no
    // status, no body, no URL. `davToErrorCategory` dispatches on the TYPE.
    await expect(createOne()).rejects.not.toHaveProperty("status");
  });
});

// ---------------------------------------------------------------------------
// CALM-05 — renaming and recolouring a calendar collection
//
// **The `207` here means the OPPOSITE of the `207` in the block above, and
// that is the whole point of these cases.** A `207` on the create is a refusal
// (RFC 5689 § 3, all-or-nothing). A `207` on a property update is the ONLY
// successful answer RFC 4918 § 9.2 defines — and it is a success only if every
// `propstat` inside it carries a 2xx status. SPIKE-04's probe read the outer
// `207` and nothing else, which was enough to answer "does iCloud allow this at
// all" and is not enough to tell a user their calendar was renamed.
// ---------------------------------------------------------------------------

/** One `d:response` wrapper, so each fixture below is only its own propstats. */
function propertyUpdateAnswer(propstats: string): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<d:multistatus xmlns:d="DAV:" xmlns:ca="http://apple.com/ns/ical/">' +
    `<d:response><d:href>${WORK_PATH}</d:href>${propstats}</d:response>` +
    "</d:multistatus>"
  );
}

/** Both properties accepted, in ONE propstat — the ordinary success. */
const BOTH_SET_BODY = propertyUpdateAnswer(
  "<d:propstat><d:prop><d:displayname/><ca:calendar-color/></d:prop>" +
    "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>",
);

/**
 * The name accepted and the colour REFUSED — the case the probe could not see.
 *
 * Two propstats, which is the shape RFC 4918 § 9.2 defines for exactly this:
 * one status line per group of properties that shared an outcome. The outer
 * envelope is still `207`, and a reader that stops there reports this as a
 * complete success.
 */
const COLOUR_REFUSED_BODY = propertyUpdateAnswer(
  "<d:propstat><d:prop><d:displayname/></d:prop>" +
    "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>" +
    "<d:propstat><d:prop><ca:calendar-color/></d:prop>" +
    "<d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat>",
);

/**
 * The colour SILENTLY DROPPED — mentioned nowhere in the answer.
 *
 * Not refused with a status, not acknowledged: absent. A reader that inspects
 * only the propstats present has nothing to report about it and reports success
 * by omission, which is the second of the three ways the obvious implementation
 * is wrong.
 */
const COLOUR_OMITTED_BODY = propertyUpdateAnswer(
  "<d:propstat><d:prop><d:displayname/></d:prop>" +
    "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>",
);

/** Both properties refused — nothing landed at all. */
const NOTHING_SET_BODY = propertyUpdateAnswer(
  "<d:propstat><d:prop><d:displayname/><ca:calendar-color/></d:prop>" +
    "<d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat>",
);

/** Answer every property update with one body, and everything else normally. */
function updatingStub(body: string, status = 207): Stub {
  return davStub({
    onRequest: (_url, method) =>
      method === "PROPPATCH"
        ? new Response(body, {
            status,
            headers: { "content-type": "text/xml; charset=utf-8" },
          })
        : null,
  });
}

/** The one update this suite drives, with whatever the case asks to change. */
function updateOne(
  change: { displayName?: string; color?: string },
  collectionUrl = WORK_URL,
): Promise<UpdatedCalendar> {
  return updateCalendarCollection(env, principal, createDavFetch(owner), {
    collectionUrl,
    ...change,
  });
}

describe("renaming and recolouring a calendar collection (CALM-05)", () => {
  it("issues ONE property update at the collection the id named", async () => {
    const stub = updatingStub(BOTH_SET_BODY);
    await warm(stub);

    const updated = await updateOne({
      displayName: "Job search 2026",
      color: "#1f77b4",
    });

    // ONE. A rename and a recolour are one request, not two.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PROPPATCH");
    expect(stub.observed[0].url).toBe(WORK_URL);
    // The id names what was actually addressed rather than echoing the caller's
    // token, so an id naming something else would be visible here.
    expect(decodeCalendarId(updated.id).collectionUrl).toBe(WORK_URL);
  });

  it("reports BOTH properties changed when both propstats are 2xx", async () => {
    const stub = updatingStub(BOTH_SET_BODY);
    await warm(stub);

    const updated = await updateOne({
      displayName: "Job search 2026",
      color: "#1f77b4",
    });

    expect(updated.changed.sort()).toEqual(["color", "displayName"]);
    expect(updated.unchanged).toEqual([]);
  });

  it("reports the colour NOT changed when its propstat is 403, and does not throw", async () => {
    // **This is the case SPIKE-04's probe could not see, and the point of the
    // whole plan.** The envelope is `207`, which the create one block up treats
    // as a refusal and which RFC 4918 § 9.2 makes the ONLY successful answer
    // here. Reading it alone reports "renamed and recoloured" to a user whose
    // calendar is still the old colour.
    const stub = updatingStub(COLOUR_REFUSED_BODY);
    await warm(stub);

    const updated = await updateOne({
      displayName: "Job search 2026",
      color: "#1f77b4",
    });

    expect(updated.changed).toEqual(["displayName"]);
    expect(updated.unchanged).toEqual(["color"]);
    // It came back as a VALUE. Throwing would hand the caller a category and no
    // way to learn which half landed.
    expect(stub.observed.length).toBe(1);
  });

  it("treats a property the answer OMITS as not changed", async () => {
    // Omission is not an implicit success. A reader that inspects only what is
    // present has nothing to say about a property the server silently dropped,
    // and saying nothing reads as "it worked" at every layer above.
    const stub = updatingStub(COLOUR_OMITTED_BODY);
    await warm(stub);

    const updated = await updateOne({
      displayName: "Job search 2026",
      color: "#1f77b4",
    });

    expect(updated.changed).toEqual(["displayName"]);
    expect(updated.unchanged).toEqual(["color"]);
  });

  it("refuses outright when NOTHING changed, rather than reporting an empty partial", async () => {
    const stub = updatingStub(NOTHING_SET_BODY);
    await warm(stub);

    await expect(
      updateOne({ displayName: "Job search 2026", color: "#1f77b4" }),
    ).rejects.toBeInstanceOf(DavConnectError);
    // The request WAS issued; it is the ANSWER that is refused.
    expect(stub.observed.length).toBe(1);
    expect(stub.observed[0].method).toBe("PROPPATCH");
  });

  it("sends no colour element at all on a rename with no colour", async () => {
    const stub = updatingStub(
      propertyUpdateAnswer(
        "<d:propstat><d:prop><d:displayname/></d:prop>" +
          "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>",
      ),
    );
    await warm(stub);

    const updated = await updateOne({ displayName: "Job search 2026" });
    const body = String(stub.observed[0].body);

    expect(body).toContain("<d:displayname>Job search 2026</d:displayname>");
    // ABSENT, not empty. An element present with no value is a request to BLANK
    // the property, which is not what "leave the colour alone" means.
    expect(body).not.toContain("calendar-color");
    // Only the property that was asked for is reported on.
    expect(updated.changed).toEqual(["displayName"]);
    expect(updated.unchanged).toEqual([]);
  });

  it("sends no displayname element at all on a recolour with no rename", async () => {
    const stub = updatingStub(
      propertyUpdateAnswer(
        "<d:propstat><d:prop><ca:calendar-color/></d:prop>" +
          "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>",
      ),
    );
    await warm(stub);

    const updated = await updateOne({ color: "#1F77B4" });
    const body = String(stub.observed[0].body);

    expect(body).not.toContain("displayname");
    // The eight-digit wire form, through the same helper the create uses, with
    // the caller's own case on the six digits.
    expect(body).toContain("<ca:calendar-color>#1F77B4FF</ca:calendar-color>");
    expect(updated.changed).toEqual(["color"]);
  });

  it("declares two namespaces and carries the transport's credential only", async () => {
    const stub = updatingStub(BOTH_SET_BODY);
    await warm(stub);

    await updateOne({ displayName: "Job search 2026", color: "#1f77b4" });
    const body = String(stub.observed[0].body);

    expect(body).toContain('xmlns:d="DAV:"');
    expect(body).toContain('xmlns:ca="http://apple.com/ns/ical/"');
    // The CalDAV namespace is NOT declared: no property here lives in it, and
    // this is the pair SPIKE-04's measured probe sent.
    expect(body).not.toContain("urn:ietf:params:xml:ns:caldav");

    // The service module passes `headers: {}`. What arrives is the transport's
    // and only the transport's.
    expect(stub.observed[0].headers.authorization.startsWith("Basic ")).toBe(
      true,
    );
  });

  it("refuses a change naming NEITHER property, with nothing sent", async () => {
    const stub = updatingStub(BOTH_SET_BODY);
    await warm(stub);

    await expect(updateOne({})).rejects.toBeInstanceOf(DavNotFoundError);
    // ZERO. Sending an empty `d:prop` would spend a round trip asking iCloud to
    // do nothing, against a connection budget this project counts.
    expect(stub.observed.length).toBe(0);
  });

  it("refuses a collection URL outside the resolved home, with nothing sent", async () => {
    // The first collection write whose target is genuinely caller-supplied. The
    // URL arrives inside an opaque id, and `src/dav/transport.ts` attaches the
    // Apple ID and the app-specific password to whatever URL it is handed.
    const stub = updatingStub(BOTH_SET_BODY);
    await warm(stub);

    await expect(
      updateOne(
        { displayName: "Job search 2026" },
        "https://evil.example/1234567890/calendars/work/",
      ),
    ).rejects.toBeInstanceOf(DavNotFoundError);
    expect(stub.observed.length).toBe(0);
  });

  it("reports nothing changed when the answer carries no multistatus at all", async () => {
    // A bare `200` with no body. The library hands back a response with no
    // property region, so every asked property is absent and the change is
    // refused — conservative in the direction this module already chose once on
    // the create: under-reporting a change the user can verify beats telling
    // them a calendar was renamed when it was not.
    const stub = updatingStub("", 200);
    await warm(stub);

    await expect(
      updateOne({ displayName: "Job search 2026" }),
    ).rejects.toBeInstanceOf(DavConnectError);
    expect(stub.observed.length).toBe(1);
  });
});

describe("propstatOutcomes, read directly", () => {
  it("splits what was asked into what the answer mentions and what it does not", () => {
    // The reader in isolation, over the shape the library actually produces:
    // ONE flat property region per response, because the library reduces every
    // propstat into it and DROPS any whose status parses outside 2xx. Absence
    // is therefore the only signal available, which is why `asked` is a
    // parameter rather than something inferred from the answer.
    const responses = [
      {
        status: 207,
        statusText: "Multi-Status",
        ok: true,
        props: { displayname: {} },
      },
    ];

    expect(propstatOutcomes(responses, ["displayName", "color"])).toEqual({
      changed: ["displayName"],
      unchanged: ["color"],
    });
  });

  it("reports everything unchanged when there is no property region", () => {
    const responses = [
      { status: 200, statusText: "OK", ok: true },
    ];

    expect(propstatOutcomes(responses, ["displayName", "color"])).toEqual({
      changed: [],
      unchanged: ["displayName", "color"],
    });
  });

  it("asks about nothing when nothing was asked", () => {
    // Non-vacuity in the other direction: an empty `asked` must not invent a
    // property to report on. The entry point refuses this call before the
    // request, so this pins the reader's own behaviour rather than a reachable
    // path.
    expect(
      propstatOutcomes([{ status: 207, statusText: "", ok: true, props: {} }], []),
    ).toEqual({ changed: [], unchanged: [] });
  });
});
