// A fake iCloud with two homes, one for user A and one for user B.
//
// **This file holds no real value.** Both accounts are made up. The account
// numbers, the shard hosts, the calendar and the event do not exist anywhere.
// Nothing here reaches Apple: every request a test makes is answered by the
// function below, which never forwards anything (D-09 of v1.0).
//
// **What is new here is one thing: the stub works out who is asking.** Every
// other DAV stub in this suite serves one account. This one reads the Basic
// header on each request, matches it against the two test users, and answers
// with THAT user's principal and THAT user's home. A request for a URL under one
// user's home that carries the other user's header gets a 403, the way the real
// server would refuse it.
//
// **It records a label, never a header.** Each observed request says "A", "B"
// or "unknown". The header value itself is read, compared and dropped. So a test
// can ask "did a request carrying B's credentials reach a URL under A's home?"
// without any credential-shaped string ever being stored or printed.
//
// A and B differ in both shard host and account number, on purpose. A shortcut
// that derived the second home from the first could not pass anything here (the
// reason `test/dav-discovery.test.ts` gives for its own two partitions).

import { encodeEventId } from "../../src/dav/ids";
import { USER_A, USER_B } from "./two-users";
import type { TestUser } from "./two-users";

/** The CalDAV discovery entry point. A stub must answer it. */
export const CALDAV_ENTRY = "https://caldav.icloud.com";

export const PRINCIPAL_PATH_A = "/1111111111/principal/";
export const PRINCIPAL_PATH_B = "/2222222222/principal/";

export const HOME_A = "https://p42-caldav.icloud.com/1111111111/calendars/";
export const HOME_B = "https://p77-caldav.icloud.com/2222222222/calendars/";

/** The one calendar each user has. */
export const CALENDAR_A = `${HOME_A}work/`;
export const CALENDAR_B = `${HOME_B}work/`;

/** The one event in the fixture. It belongs to A. */
export const EVENT_A_URL = `${CALENDAR_A}event-a-0001.ics`;

/** The id A would be given for A's event. */
export const EVENT_A_ID = encodeEventId({
  calendarUrl: CALENDAR_A,
  objectUrl: EVENT_A_URL,
  recurrenceId: null,
});

/**
 * The title of A's event, as a string nothing else in the suite could produce
 * by accident. If it ever turns up in something B received, that is a leak.
 */
export const CANARY_SUMMARY_A = "CANARY-A-event-9b41d7";

/** The etag the stub reports for A's event until something writes to it. */
const ETAG_A = '"etag-a-0001"';

const XML_HEADERS = { "content-type": "text/xml; charset=utf-8" };

/** One request the stub saw. `user` is a label. No header value is kept. */
export interface ObservedDavRequest {
  readonly url: string;
  readonly method: string;
  readonly user: "A" | "B" | "unknown";
  readonly body: string | null;
}

export interface TwoUserDavStub {
  fetch: typeof globalThis.fetch;
  observed: ObservedDavRequest[];
  /**
   * Every PUT and DELETE, filed under the home its URL falls in, WHOEVER sent
   * it. Filed before the stub decides whether to refuse it, so a write that
   * reached B's home with A's header is on `writesUnder.B` even though the stub
   * answered it 403. "B's copy was never written" is `writesUnder.B` empty.
   */
  writesUnder: Record<"A" | "B", ObservedDavRequest[]>;
}

/**
 * Whose Basic header is this? "A", "B", or "unknown".
 *
 * It strips the scheme, decodes the rest, and compares the pair against each
 * test user's own pair. It never throws: a value that will not decode is
 * "unknown". The decoded pair does not leave this function.
 */
export function userOfBasicHeader(
  value: string | null | undefined,
): "A" | "B" | "unknown" {
  try {
    if (typeof value !== "string" || !value.startsWith("Basic ")) {
      return "unknown";
    }
    const pair = atob(value.slice("Basic ".length));
    const pairOf = (user: TestUser): string =>
      `${user.appleId}:${user.appPassword}`;
    if (pair === pairOf(USER_A)) return "A";
    if (pair === pairOf(USER_B)) return "B";
    return "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * A's event as raw iCalendar. A plain event: one occurrence, nobody invited,
 * nothing the builder cannot reproduce. The canary is its title.
 */
export function eventIcsForA(): string {
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Example Org//Synthesised Fixture//EN",
    "CALSCALE:GREGORIAN",
    "BEGIN:VEVENT",
    "UID:event-a-0001",
    "DTSTAMP:20260101T120000Z",
    `SUMMARY:${CANARY_SUMMARY_A}`,
    "LOCATION:Room nine",
    "DTSTART:20260210T150000Z",
    "DTEND:20260210T160000Z",
    "SEQUENCE:0",
    "END:VEVENT",
    "END:VCALENDAR",
  ];
  return `${lines.join("\r\n")}\r\n`;
}

// ---------------------------------------------------------------------------
// One invitation, with a copy in each home (RSVP-04, plan 18-06)
//
// Somebody who is neither A nor B invites them both to the same meeting. iCloud
// then holds TWO resources: A's copy in A's home and B's copy in B's home, with
// one UID and the same attendee lines. Answering is a write to one copy, and the
// question these fixtures exist to ask is whether A's answer can ever move B's
// line, or reach B's copy at all.
//
// Opt-in, through `twoUserDavStub({ invitationListing })`. Without that option
// the stub is byte-for-byte what it was, so no earlier test sees a second
// object in A's calendar.
// ---------------------------------------------------------------------------

/** The meeting's UID, the same in both copies. */
export const INVITATION_UID = "shared-invitation-0001@example.invalid";

/** The meeting's title. */
export const INVITATION_SUMMARY = "Panel interview for A and B";

/** The organiser: neither test user, so neither can be refused as the organiser. */
export const INVITATION_ORGANIZER = "organiser.shared@example.invalid";

/** A's copy, in A's home. */
export const INVITATION_A_URL = `${CALENDAR_A}shared-invitation-0001.ics`;

/** B's copy, in B's home. */
export const INVITATION_B_URL = `${CALENDAR_B}shared-invitation-0001.ics`;

/** The id A would be given for A's copy. */
export const INVITATION_A_ID = encodeEventId({
  calendarUrl: CALENDAR_A,
  objectUrl: INVITATION_A_URL,
  recurrenceId: null,
});

/** The etag each copy carries until something writes to it. */
const INVITATION_ETAGS: Record<"A" | "B", string> = {
  A: '"etag-invitation-a-0001"',
  B: '"etag-invitation-b-0001"',
};

/**
 * One user's attendee line: that user's login as a `mailto:` value, waiting
 * for an answer. The stub's address-set answer for that user carries exactly
 * this `mailto:`, and the other user's answer does not.
 */
function attendeeLineFor(user: "A" | "B"): string {
  const appleId = user === "A" ? USER_A.appleId : USER_B.appleId;
  return (
    `ATTENDEE;CN=User ${user};CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION;` +
    `ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:${appleId}`
  );
}

/**
 * The invitation as raw iCalendar, listing the named users as attendees.
 *
 * A one-off meeting in UTC, so no zone definition rides along. It overlaps
 * A's plain event by half an hour on purpose: A's conflict sweep then has
 * something in A's own home to find, which shows the sweep ran against that
 * home rather than degrading to "failed".
 *
 * The lines are short enough that none folds, so an unfolded comparison and a
 * plain one read the same.
 */
export function invitationIcs(listing: readonly ("A" | "B")[]): string {
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Example Org//Synthesised Fixture//EN",
    "CALSCALE:GREGORIAN",
    "BEGIN:VEVENT",
    `UID:${INVITATION_UID}`,
    "DTSTAMP:20260101T120000Z",
    "SEQUENCE:0",
    `SUMMARY:${INVITATION_SUMMARY}`,
    "DTSTART:20260210T153000Z",
    "DTEND:20260210T163000Z",
    `ORGANIZER;CN=Shared Organiser:mailto:${INVITATION_ORGANIZER}`,
    `ATTENDEE;CN=Shared Organiser;CUTYPE=INDIVIDUAL;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:${INVITATION_ORGANIZER}`,
    ...listing.map(attendeeLineFor),
    "END:VEVENT",
    "END:VCALENDAR",
  ];
  return `${lines.join("\r\n")}\r\n`;
}

/** Options for `twoUserDavStub`. */
export interface TwoUserDavOptions {
  /**
   * Put the invitation into BOTH homes, listing these users as attendees.
   * Absent: no invitation anywhere, which is the stub every earlier test uses.
   */
  readonly invitationListing?: readonly ("A" | "B")[];
}

function multistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/" xmlns:CA="http://apple.com/ns/ical/">${body}</multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

/** What the stub knows about one user. */
interface Account {
  readonly label: "A" | "B";
  readonly appleId: string;
  readonly principalPath: string;
  readonly home: string;
  readonly calendar: string;
  /** `{ [objectPath]: icsBody }`. B's calendar is empty unless the invitation option is set. */
  readonly objects: Record<string, string>;
}

/**
 * The two-home stub. Install its `fetch` with `vi.stubGlobal` before any DAV
 * call, and read `observed` afterwards.
 *
 * Routing, in order:
 *
 * 1. A well-known URL gets 404, so discovery falls through to the entry point.
 * 2. A URL at the discovery entry gets that user's principal answer, or that
 *    user's home-set answer when the URL ends with that user's principal path.
 *    A header that is neither A's nor B's gets 401.
 * 3. A URL under a user's own home gets the object conversation: the collection
 *    answer, the multi-get carrying an etag and the event body, and 204 with a
 *    fresh etag for a write.
 * 4. A URL under one user's home carrying the OTHER user's header gets 403.
 * 5. Anything else gets 404. The stub answers nothing it does not know.
 */
export function twoUserDavStub(options: TwoUserDavOptions = {}): TwoUserDavStub {
  const objectsA: Record<string, string> = {
    [new URL(EVENT_A_URL).pathname]: eventIcsForA(),
  };
  const objectsB: Record<string, string> = {};
  const etags: Record<string, string> = {
    [new URL(EVENT_A_URL).pathname]: ETAG_A,
  };

  // The same invitation in both homes, each copy under its own etag. Symmetric
  // on purpose: B's home answers every read A's home does, so a request of A's
  // that strayed into B's home would be answered by the rule below (a 403 on a
  // foreign header) and not by a 404 that looked like an empty calendar.
  if (options.invitationListing !== undefined) {
    const ics = invitationIcs(options.invitationListing);
    const pathA = new URL(INVITATION_A_URL).pathname;
    const pathB = new URL(INVITATION_B_URL).pathname;
    objectsA[pathA] = ics;
    objectsB[pathB] = ics;
    etags[pathA] = INVITATION_ETAGS.A;
    etags[pathB] = INVITATION_ETAGS.B;
  }

  const accounts: Record<"A" | "B", Account> = {
    A: {
      label: "A",
      appleId: USER_A.appleId,
      principalPath: PRINCIPAL_PATH_A,
      home: HOME_A,
      calendar: CALENDAR_A,
      objects: objectsA,
    },
    B: {
      label: "B",
      appleId: USER_B.appleId,
      principalPath: PRINCIPAL_PATH_B,
      home: HOME_B,
      calendar: CALENDAR_B,
      objects: objectsB,
    },
  };

  let writes = 0;

  const state: TwoUserDavStub = {
    observed: [],
    writesUnder: { A: [], B: [] },
    fetch: async () => new Response(null, { status: 500 }),
  };

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET");
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    const user = userOfBasicHeader(headers["authorization"]);
    const body =
      init?.body === undefined || init?.body === null
        ? null
        : String(init.body);

    // The label only. The header value stops here.
    state.observed.push({ url, method, user, body });

    if (url.includes("/.well-known/")) return new Response(null, { status: 404 });

    if (url.startsWith(CALDAV_ENTRY)) {
      if (user === "unknown") return new Response(null, { status: 401 });
      const account = accounts[user];

      // The address-set question and the home-set question go to the SAME
      // principal URL, so the request body is what tells them apart. Answered
      // first, because the home-set branch matches on the URL alone.
      if ((body ?? "").includes("calendar-user-address-set")) {
        return multistatus(
          `<response><href>${account.principalPath}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-user-address-set><href>${account.principalPath}</href><href>mailto:${account.appleId}</href></C:calendar-user-address-set></prop></propstat></response>`,
        );
      }
      if (url.endsWith(account.principalPath)) {
        return multistatus(
          `<response><href>${account.principalPath}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${account.home}</href></C:calendar-home-set></prop></propstat></response>`,
        );
      }
      return multistatus(
        `<response><href>${account.principalPath}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${account.principalPath}</href></current-user-principal></prop></propstat></response>`,
      );
    }

    const owner: Account | null = url.startsWith(HOME_A)
      ? accounts.A
      : url.startsWith(HOME_B)
        ? accounts.B
        : null;

    if (owner === null) return new Response(null, { status: 404 });

    // Filed by the home it aimed at, before the refusal below, so a write that
    // is about to be turned away is still counted against the home it tried.
    if (method === "PUT" || method === "DELETE") {
      state.writesUnder[owner.label].push({ url, method, user, body });
    }

    // Somebody else's home. The real server would refuse this too. It is
    // already on `observed` with the asker's label, so a leak is visible.
    if (user !== owner.label) return new Response(null, { status: 403 });

    if (method === "PROPFIND") {
      return multistatus(
        `<response><href>${new URL(owner.calendar).pathname}</href><propstat>` +
          `<status>HTTP/1.1 200 OK</status><prop>` +
          `<displayname>Work</displayname>` +
          `<resourcetype><collection/><C:calendar/></resourcetype>` +
          `<C:supported-calendar-component-set><C:comp name="VEVENT"/></C:supported-calendar-component-set>` +
          `</prop></propstat></response>`,
      );
    }

    if (method === "PUT" || method === "DELETE") {
      writes += 1;
      const fresh = `"etag-written-${writes}"`;
      etags[new URL(url).pathname] = fresh;
      return new Response(null, { status: 204, headers: { etag: fresh } });
    }

    if (method === "REPORT") {
      return multistatus(
        Object.entries(owner.objects)
          .map(([href, data]) => {
            const etag = etags[href] ?? ETAG_A;
            const payload = (body ?? "").includes("calendar-multiget")
              ? `<getetag>${etag}</getetag><C:calendar-data><![CDATA[${data}]]></C:calendar-data>`
              : `<getetag>${etag}</getetag>`;
            return (
              `<response><href>${href}</href><propstat>` +
              `<status>HTTP/1.1 200 OK</status><prop>${payload}</prop>` +
              `</propstat></response>`
            );
          })
          .join(""),
      );
    }

    return new Response(null, { status: 404 });
  }) as typeof globalThis.fetch;

  return state;
}
