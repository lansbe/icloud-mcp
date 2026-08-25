// The DAV opaque identifier and page-cursor layer: round-trip fidelity, refusal
// of everything this codec did not mint, and the two properties that make a
// cursor mean anything — a pinned range and a total order.
//
// Pure units. No sockets, no session, no network — the module under test is
// attached to nothing but one error class and the neutral byte-level codec.

import { describe, expect, it } from "vitest";
import type { EventTime } from "../src/dav/icalendar";
import { DavNotFoundError, davToErrorCategory } from "../src/dav/errors";
import type {
  CalendarCursor,
  ContactOrderKey,
  ContactsCursor,
  EventOrderKey,
  SlotCursor,
} from "../src/dav/ids";
import {
  DAV_KIND_LETTERS,
  DAV_TOKEN_VERSION,
  PAGE_SIZE_DEFAULT,
  PAGE_SIZE_MAX,
  clampPageSize,
  compareContactOrder,
  compareEventOrder,
  decodeAddressBookId,
  decodeCalendarCursor,
  decodeCalendarId,
  decodeContactId,
  decodeContactsCursor,
  decodeEventId,
  decodeSlotCursor,
  displayNameKeyOf,
  encodeAddressBookId,
  encodeCalendarCursor,
  encodeCalendarId,
  encodeContactId,
  encodeContactsCursor,
  encodeEventId,
  encodeSlotCursor,
  isAfterCalendarCursor,
  isAfterContactsCursor,
  isAfterSlotCursor,
  sortInstantOf,
} from "../src/dav/ids";
import { encodeCursor, encodeFolderId, encodeMessageId } from "../src/mail/ids";

/**
 * Base64url of an arbitrary value, re-implemented here on purpose.
 *
 * The negative cases below must be built WITHOUT the encoders under test,
 * because a bug shared between encoder and test helper would cancel out and
 * leave the refusal cases green against a broken codec.
 */
function mint(value: unknown): string {
  return mintRaw(new TextEncoder().encode(JSON.stringify(value)));
}

/**
 * Base64url of arbitrary BYTES, for the cases that cannot be expressed as a
 * JavaScript string at all.
 *
 * `mint` goes through `JSON.stringify`, which can only produce well-formed
 * UTF-8. The decoder-strictness cases below need deliberately malformed bytes,
 * so they are built at this level instead.
 */
function mintRaw(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Read a token's payload WITHOUT the decoders under test.
 *
 * Two jobs. It reads the kind letter out of a token the MAIL tree minted, which
 * is what lets the namespace-disjointness guard fail for the right reason. And
 * it is the honest demonstration of T-03-21: the shard host really is
 * recoverable by anyone who base64-decodes a token, which is opacity in
 * ordinary use rather than secrecy.
 */
function readPayload(token: string): Record<string, unknown> {
  const padding = "=".repeat((4 - (token.length % 4)) % 4);
  const binary = atob(token.replace(/-/g, "+").replace(/_/g, "/") + padding);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

/**
 * Everything a caller could possibly read off a thrown refusal.
 *
 * The message, every own property whether or not `JSON.stringify` would reach
 * it, and the tool-visible category. An error path is the easiest place to leak
 * a format for free, so the assertion has to look everywhere rather than at the
 * one field that happens to be convenient.
 */
function surfacedText(error: unknown): string {
  const err = error as Error & Record<string, unknown>;
  const fields = Object.getOwnPropertyNames(err).map(
    (name) => `${name}=${String(err[name])}`,
  );
  return [
    err.message,
    ...fields,
    JSON.stringify(davToErrorCategory(error)),
  ].join("|");
}

/**
 * Everything a CALLER could read, which is `surfacedText` minus the stack.
 *
 * The stack is excluded deliberately and the reason is not convenience: it is
 * not a caller-visible field. D-57's categoriser dispatches on the error's TYPE
 * and never reads `.message` or `.stack`, and a tool response carries only the
 * category and its fixed safe message — so a stack differs between two refusals
 * (it records the throw site) without either refusal telling a caller anything.
 * Asserting indistinguishability over it would be asserting that two different
 * lines of this file are the same line.
 */
function callerVisibleText(error: unknown): string {
  const err = error as Error & Record<string, unknown>;
  const fields = Object.getOwnPropertyNames(err)
    .filter((name) => name !== "stack")
    .map((name) => `${name}=${String(err[name])}`);
  return [
    err.message,
    ...fields,
    JSON.stringify(davToErrorCategory(error)),
  ].join("|");
}

// --------------------------------------------------------------- fixtures
//
// Apple-shaped, sharded hosts and all. The hostnames are legal HERE and banned
// under `src/`: the scan collects the host literal from the source tree only,
// because a fixture URL is not a code path and the ban is on a shipped
// constant.

const CAL_A = "https://p52-caldav.icloud.com/123456789/calendars/work/";
const CAL_B = "https://p52-caldav.icloud.com/123456789/calendars/home/";
const BOOK = "https://p52-contacts.icloud.com/123456789/carddavhome/card/";

const OBJ_1 = `${CAL_A}1111-2222.ics`;
const OBJ_2 = `${CAL_B}3333-4444.ics`;
const OBJ_3 = `${CAL_A}5555-6666.ics`;
const OBJ_4 = `${CAL_A}7777-8888.ics`;
const OBJ_5 = `${CAL_B}9999-0000.ics`;
const CARD_1 = `${BOOK}aaaa-bbbb.vcf`;
const CARD_2 = `${BOOK}cccc-dddd.vcf`;
const CARD_3 = `${BOOK}eeee-ffff.vcf`;

/** 2026-03-01T00:00:00Z, computed in UTC so no host zone can reach it. */
const MARCH_1_UTC = Date.UTC(2026, 2, 1) / 1000;
/** 2026-04-01T00:00:00Z. */
const APRIL_1_UTC = Date.UTC(2026, 3, 1) / 1000;

/** A resolved timed event: `utc` is present, so it IS the sort key. */
const RESOLVED_TIME: EventTime = {
  allDay: false,
  local: "2026-03-01T09:00:00",
  tzid: "America/New_York",
  utc: MARCH_1_UTC + 14 * 3600,
  timezoneUnresolved: false,
};

/** An all-day event: a date, with no instant at all. */
const ALL_DAY_TIME: EventTime = {
  allDay: true,
  local: "2026-03-01",
  tzid: "floating",
  timezoneUnresolved: false,
};

/** A wall clock anchored to a zone this server could not resolve. */
const UNRESOLVED_TIME: EventTime = {
  allDay: false,
  local: "2026-03-01T09:00:00",
  tzid: "Mars/Olympus",
  timezoneUnresolved: true,
};

const BASE_CURSOR: CalendarCursor = {
  rangeStart: MARCH_1_UTC,
  rangeEnd: APRIL_1_UTC,
  // Always a calendar, never null. A listing is scoped to exactly one
  // collection since the account-wide form was withdrawn, so there is no page
  // this field cannot name — and a cursor carrying null is an IN-FLIGHT token
  // from before that change, refused by the case below rather than round-tripped.
  scope: CAL_A,
  // Two nulls is a LISTING cursor: neither axis was searched. A search pins at
  // least one of them, which is what makes the two distinguishable rather than
  // accidentally equal.
  keywordTerm: null,
  attendeeTerm: null,
  lastSortInstant: MARCH_1_UTC + 3600,
  lastCalendarUrl: CAL_A,
  lastObjectUrl: OBJ_1,
  lastRecurrenceId: null,
};

/** A cursor minted by a search rather than by a listing. */
const SEARCH_CURSOR: CalendarCursor = {
  ...BASE_CURSOR,
  keywordTerm: "standup",
  attendeeTerm: "ada",
};

const BASE_CONTACTS_CURSOR: ContactsCursor = {
  term: "recruiter",
  lastDisplayNameKey: "ada lovelace",
  lastObjectUrl: CARD_1,
};

/**
 * A find-slots cursor pinning every axis that changes the answer.
 *
 * Deliberately NOT a `CalendarCursor` shape: it has no single-calendar scope,
 * its position is a real published instant (`lastCandidateStart`), and it pins
 * the duration, zone and working-hours window a candidate set is a function of.
 */
const BASE_SLOT_CURSOR: SlotCursor = {
  rangeStart: MARCH_1_UTC,
  rangeEnd: APRIL_1_UTC,
  durationMinutes: 30,
  tzid: "America/Chicago",
  workDayStartLocal: "09:00",
  workDayEndLocal: "17:00",
  workDaysKey: "12345",
  lastCandidateStart: MARCH_1_UTC + 3600,
};

describe("round trips", () => {
  it("round-trips a calendar reference", () => {
    expect(decodeCalendarId(encodeCalendarId({ collectionUrl: CAL_A }))).toEqual(
      { collectionUrl: CAL_A },
    );
  });

  it("round-trips an address book reference", () => {
    expect(
      decodeAddressBookId(encodeAddressBookId({ collectionUrl: BOOK })),
    ).toEqual({ collectionUrl: BOOK });
  });

  it("round-trips a non-recurring event occurrence", () => {
    const ref = { calendarUrl: CAL_A, objectUrl: OBJ_1, recurrenceId: null };

    expect(decodeEventId(encodeEventId(ref))).toEqual(ref);
  });

  it("round-trips a recurring event occurrence", () => {
    // The master series' key, which is stable across an edit — an occurrence
    // someone moved keeps the id of the slot it was moved OUT of, which is
    // exactly what makes it the right discriminator.
    const ref = {
      calendarUrl: CAL_A,
      objectUrl: OBJ_1,
      recurrenceId: "20260301T090000Z",
    };

    expect(decodeEventId(encodeEventId(ref))).toEqual(ref);
  });

  it("round-trips a contact reference", () => {
    const ref = { addressBookUrl: BOOK, objectUrl: CARD_1 };

    expect(decodeContactId(encodeContactId(ref))).toEqual(ref);
  });

  it("round-trips a calendar cursor when the range matches", () => {
    const token = encodeCalendarCursor(BASE_CURSOR);

    expect(decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC)).toEqual(
      BASE_CURSOR,
    );
  });

  it("round-trips a calendar cursor carrying a calendar scope", () => {
    const scoped = { ...BASE_CURSOR, scope: CAL_B };
    const token = encodeCalendarCursor(scoped);

    expect(decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC)).toEqual(
      scoped,
    );
  });

  it("round-trips a contacts cursor when the term matches", () => {
    const token = encodeContactsCursor(BASE_CONTACTS_CURSOR);

    expect(decodeContactsCursor(token, "recruiter")).toEqual(
      BASE_CONTACTS_CURSOR,
    );
  });

  it("round-trips a slot cursor when the range matches", () => {
    const token = encodeSlotCursor(BASE_SLOT_CURSOR);

    expect(decodeSlotCursor(token, MARCH_1_UTC, APRIL_1_UTC)).toEqual(
      BASE_SLOT_CURSOR,
    );
  });

  it("does not spell a collection URL out as a readable substring", () => {
    // Not a security property — base64 is not encryption — but the reason the
    // model is handed a token rather than a URL is that a URL it can read is a
    // URL it can construct.
    expect(encodeCalendarId({ collectionUrl: CAL_A })).not.toContain(CAL_A);
    expect(encodeCalendarId({ collectionUrl: CAL_A })).not.toContain(
      "p52-caldav",
    );
  });

  it("carries the shard host in decodable form, which T-03-21 accepts", () => {
    // Recorded as an assertion rather than only as prose, because the honest
    // statement of the mitigation is "opaque in ordinary use", not "secret". A
    // future session that reads the threat register should find the property
    // it describes actually asserted.
    const payload = readPayload(encodeCalendarId({ collectionUrl: CAL_A }));

    expect(String(payload.c)).toContain("p52-caldav");
  });

  it("carries no credential material in any token", () => {
    // The other half of T-03-21: the host may travel, nothing else may.
    const tokens = [
      encodeCalendarId({ collectionUrl: CAL_A }),
      encodeAddressBookId({ collectionUrl: BOOK }),
      encodeEventId({
        calendarUrl: CAL_A,
        objectUrl: OBJ_1,
        recurrenceId: null,
      }),
      encodeContactId({ addressBookUrl: BOOK, objectUrl: CARD_1 }),
      encodeCalendarCursor(BASE_CURSOR),
      encodeContactsCursor(BASE_CONTACTS_CURSOR),
    ];

    for (const token of tokens) {
      const fields = Object.keys(readPayload(token)).sort();

      expect(fields).not.toContain("password");
      expect(fields).not.toContain("auth");
      expect(fields).not.toContain("authorization");
      expect(JSON.stringify(readPayload(token))).not.toContain("Basic ");
    }
  });
});

describe("the six DAV kinds are not interchangeable", () => {
  const CAL_TOKEN = encodeCalendarId({ collectionUrl: CAL_A });
  const BOOK_TOKEN = encodeAddressBookId({ collectionUrl: BOOK });
  const EVENT_TOKEN = encodeEventId({
    calendarUrl: CAL_A,
    objectUrl: OBJ_1,
    recurrenceId: null,
  });
  const CONTACT_TOKEN = encodeContactId({
    addressBookUrl: BOOK,
    objectUrl: CARD_1,
  });
  const CAL_CURSOR_TOKEN = encodeCalendarCursor(BASE_CURSOR);
  const CONTACTS_CURSOR_TOKEN = encodeContactsCursor(BASE_CONTACTS_CURSOR);

  it("refuses an address book id handed to the calendar decoder", () => {
    // The two payloads are structurally IDENTICAL — one collection URL each —
    // so the kind letter is the only thing standing between them. Without it
    // this decode would succeed and address the wrong collection silently.
    expect(() => decodeCalendarId(BOOK_TOKEN)).toThrow(DavNotFoundError);
  });

  it("refuses a calendar id handed to the address book decoder", () => {
    expect(() => decodeAddressBookId(CAL_TOKEN)).toThrow(DavNotFoundError);
  });

  it("refuses a contact id handed to the event decoder", () => {
    expect(() => decodeEventId(CONTACT_TOKEN)).toThrow(DavNotFoundError);
  });

  it("refuses an event id handed to the contact decoder", () => {
    expect(() => decodeContactId(EVENT_TOKEN)).toThrow(DavNotFoundError);
  });

  it("refuses a calendar cursor handed to the contacts cursor decoder", () => {
    expect(() =>
      decodeContactsCursor(CAL_CURSOR_TOKEN, "recruiter"),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a contacts cursor handed to the calendar cursor decoder", () => {
    expect(() =>
      decodeCalendarCursor(CONTACTS_CURSOR_TOKEN, MARCH_1_UTC, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
  });

  it("refuses an event id handed to the calendar cursor decoder", () => {
    expect(() =>
      decodeCalendarCursor(EVENT_TOKEN, MARCH_1_UTC, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
  });
});

describe("the DAV and mail kind namespaces are disjoint", () => {
  // A REGRESSION GUARD ON THE LETTER NAMESPACE, not a test of new logic. The
  // cross-tree refusal below passes BY CONSTRUCTION: mail's three letters
  // cannot collide with the six DAV ones, and after the codec extraction both
  // trees decode through one `fromBase64Url`. That is precisely why the guard
  // is worth keeping — a future session adding a seventh DAV kind is the only
  // way it can break, and this is what would tell them.
  const MAIL_TOKENS = [
    encodeMessageId({ mailbox: "INBOX", uidValidity: 1, uid: 4711 }),
    encodeFolderId({ mailbox: "INBOX" }),
    encodeCursor({ mailbox: "INBOX", uidValidity: 1, lastUid: 4711 }),
  ];

  it("uses seven distinct letters", () => {
    expect(new Set(DAV_KIND_LETTERS).size).toBe(DAV_KIND_LETTERS.length);
    expect(DAV_KIND_LETTERS).toHaveLength(7);
  });

  it("shares no letter with any kind the mail tree mints", () => {
    // Read out of real mail tokens rather than copied from the mail tree's
    // source, so the guard tracks what that tree actually emits.
    const mailLetters = MAIL_TOKENS.map((token) =>
      String(readPayload(token).k),
    );

    expect(mailLetters).toHaveLength(3);
    for (const letter of mailLetters) {
      expect(DAV_KIND_LETTERS).not.toContain(letter);
    }
  });

  it("refuses every mail token at every DAV decoder", () => {
    for (const token of MAIL_TOKENS) {
      expect(() => decodeCalendarId(token)).toThrow(DavNotFoundError);
      expect(() => decodeAddressBookId(token)).toThrow(DavNotFoundError);
      expect(() => decodeEventId(token)).toThrow(DavNotFoundError);
      expect(() => decodeContactId(token)).toThrow(DavNotFoundError);
      expect(() =>
        decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC),
      ).toThrow(DavNotFoundError);
      expect(() => decodeContactsCursor(token, "recruiter")).toThrow(
        DavNotFoundError,
      );
    }
  });
});

describe("the decoder refuses rather than repairs", () => {
  const REFUSED_INPUTS: Array<[string, string]> = [
    ["the empty string", ""],
    ["a token of only padding", "===="],
    ["a character outside the base64url alphabet", "abc$def"],
    ["standard base64's own alphabet", "ab+cd/ef"],
    ["leading whitespace", " abcd"],
    ["a length that cannot be a base64 quantum", "a"],
    ["valid base64url that is not JSON", mintRaw(new TextEncoder().encode("{"))],
  ];

  for (const [label, token] of REFUSED_INPUTS) {
    it(`refuses ${label}`, () => {
      expect(() => decodeCalendarId(token)).toThrow(DavNotFoundError);
    });
  }

  it("refuses a non-string input", () => {
    expect(() =>
      decodeCalendarId(undefined as unknown as string),
    ).toThrow(DavNotFoundError);
    expect(() => decodeCalendarId(42 as unknown as string)).toThrow(
      DavNotFoundError,
    );
    expect(() => decodeCalendarId(null as unknown as string)).toThrow(
      DavNotFoundError,
    );
  });

  it("refuses a truncated token", () => {
    const whole = encodeCalendarId({ collectionUrl: CAL_A });

    expect(() => decodeCalendarId(whole.slice(0, whole.length - 4))).toThrow(
      DavNotFoundError,
    );
  });

  it("refuses bytes that are valid base64 but not valid UTF-8", () => {
    // `fatal: true` on the decoder is what makes this a refusal rather than a
    // repair: the lenient default would substitute U+FFFD and hand back a token
    // naming a DIFFERENT collection.
    expect(() =>
      decodeCalendarId(mintRaw(new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]))),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a BOM-prefixed payload", () => {
    // `ignoreBOM: true` is the STRICTER reading despite the name: the mark is
    // kept as a code point, where JSON.parse refuses it.
    const body = new TextEncoder().encode(
      JSON.stringify({ v: DAV_TOKEN_VERSION, k: "k", c: CAL_A }),
    );
    const withBom = new Uint8Array(body.length + 3);
    withBom.set([0xef, 0xbb, 0xbf], 0);
    withBom.set(body, 3);

    expect(() => decodeCalendarId(mintRaw(withBom))).toThrow(DavNotFoundError);
  });

  it("refuses a payload that decodes to a JSON array", () => {
    expect(() => decodeCalendarId(mint([DAV_TOKEN_VERSION, "k", CAL_A]))).toThrow(
      DavNotFoundError,
    );
  });

  it("refuses a payload that decodes to a JSON scalar", () => {
    expect(() => decodeCalendarId(mint("k"))).toThrow(DavNotFoundError);
    expect(() => decodeCalendarId(mint(7))).toThrow(DavNotFoundError);
    expect(() => decodeCalendarId(mint(null))).toThrow(DavNotFoundError);
  });

  it("refuses a version that does not match", () => {
    expect(() =>
      decodeCalendarId(mint({ v: DAV_TOKEN_VERSION + 1, k: "k", c: CAL_A })),
    ).toThrow(DavNotFoundError);
    expect(() =>
      decodeCalendarId(mint({ k: "k", c: CAL_A })),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a well-formed payload whose URL field is missing or empty", () => {
    expect(() =>
      decodeCalendarId(mint({ v: DAV_TOKEN_VERSION, k: "k" })),
    ).toThrow(DavNotFoundError);
    expect(() =>
      decodeCalendarId(mint({ v: DAV_TOKEN_VERSION, k: "k", c: "" })),
    ).toThrow(DavNotFoundError);
    expect(() =>
      decodeCalendarId(mint({ v: DAV_TOKEN_VERSION, k: "k", c: 7 })),
    ).toThrow(DavNotFoundError);
  });

  it("refuses an event payload whose recurrence id is neither string nor null", () => {
    expect(() =>
      decodeEventId(
        mint({
          v: DAV_TOKEN_VERSION,
          k: "e",
          c: CAL_A,
          o: OBJ_1,
          r: 7,
        }),
      ),
    ).toThrow(DavNotFoundError);
  });

  it("reaches the caller as not_found", () => {
    try {
      decodeCalendarId("not-a-token-this-codec-minted");
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      expect(davToErrorCategory(error).category).toBe("not_found");
    }
  });

  it("never permits a re-discovery for a refusal minted here", () => {
    // `rediscoverable: false` on every refusal in this layer, deliberately. A
    // re-discovery cannot repair a malformed token, and `true` would spend a
    // wasted PROPFIND out of D-60's retry budget on every mistyped id.
    try {
      decodeCalendarId("not-a-token-this-codec-minted");
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      expect(error).toBeInstanceOf(DavNotFoundError);
      expect((error as DavNotFoundError).rediscoverable).toBe(false);
    }
  });

  it("says nothing that would teach a caller how to build a token", () => {
    const offending = mint({
      v: 99,
      k: "k",
      c: "https://p52-caldav.icloud.com/SECRET-SHARD/calendars/private/",
    });

    try {
      decodeCalendarId(offending);
      expect.unreachable("the decoder should have refused");
    } catch (error) {
      const surfaced = surfacedText(error);

      expect(surfaced).not.toContain("SECRET-SHARD");
      expect(surfaced).not.toContain("p52-caldav");
      expect(surfaced).not.toContain(offending);
      expect(surfaced).not.toContain("base64");
      expect(surfaced).not.toContain("version");
      expect(surfaced).not.toContain("collectionUrl");
      expect(surfaced).not.toContain("recurrence");
    }
  });

  it("says the same nothing whichever check failed", () => {
    // Every refusal is one category with one fixed message, so the failures
    // are indistinguishable from outside — a caller cannot binary-search the
    // format by watching which input produces which diagnosis.
    const surfaces = [
      "",
      "abc$def",
      mint([1, 2, 3]),
      mint({ v: 99, k: "k", c: CAL_A }),
      mint({ v: DAV_TOKEN_VERSION, k: "b", c: CAL_A }),
    ].map((token) => {
      try {
        decodeCalendarId(token);
        return "no-refusal";
      } catch (error) {
        return callerVisibleText(error);
      }
    });

    expect(new Set(surfaces).size).toBe(1);
  });
});

describe("minting refuses what it could not read back", () => {
  // A token that cannot survive its own decoder must never be handed out: the
  // failure would surface arbitrarily far from the code that built it, against
  // a token that by then looks like the model's fault.
  it("refuses an empty collection URL at encode time", () => {
    expect(() => encodeCalendarId({ collectionUrl: "" })).toThrow(
      DavNotFoundError,
    );
    expect(() => encodeAddressBookId({ collectionUrl: "" })).toThrow(
      DavNotFoundError,
    );
  });

  it("refuses a relative URL at encode time", () => {
    expect(() =>
      encodeCalendarId({ collectionUrl: "/123456789/calendars/work/" }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a non-https URL at encode time", () => {
    expect(() =>
      encodeCalendarId({ collectionUrl: CAL_A.replace("https:", "http:") }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a non-string URL at encode time", () => {
    expect(() =>
      encodeCalendarId({ collectionUrl: 7 as unknown as string }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a recurrence id that is neither a string nor null", () => {
    expect(() =>
      encodeEventId({
        calendarUrl: CAL_A,
        objectUrl: OBJ_1,
        recurrenceId: 7 as unknown as string,
      }),
    ).toThrow(DavNotFoundError);
    expect(() =>
      encodeEventId({
        calendarUrl: CAL_A,
        objectUrl: OBJ_1,
        recurrenceId: undefined as unknown as string,
      }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses an empty recurrence id, which is neither absent nor a key", () => {
    expect(() =>
      encodeEventId({ calendarUrl: CAL_A, objectUrl: OBJ_1, recurrenceId: "" }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a non-integer or unbounded range pin at encode time", () => {
    expect(() =>
      encodeCalendarCursor({ ...BASE_CURSOR, rangeStart: 1.5 }),
    ).toThrow(DavNotFoundError);
    expect(() =>
      encodeCalendarCursor({ ...BASE_CURSOR, rangeEnd: Number.NaN }),
    ).toThrow(DavNotFoundError);
    expect(() =>
      encodeCalendarCursor({
        ...BASE_CURSOR,
        lastSortInstant: Number.POSITIVE_INFINITY,
      }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a non-string contacts sort key at encode time", () => {
    expect(() =>
      encodeContactsCursor({
        ...BASE_CONTACTS_CURSOR,
        lastDisplayNameKey: 7 as unknown as string,
      }),
    ).toThrow(DavNotFoundError);
  });
});

describe("the calendar cursor pins its range", () => {
  it("refuses a cursor supplied with a different range start", () => {
    const token = encodeCalendarCursor(BASE_CURSOR);

    expect(() =>
      decodeCalendarCursor(token, MARCH_1_UTC + 1, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a cursor supplied with a different range end", () => {
    const token = encodeCalendarCursor(BASE_CURSOR);

    expect(() =>
      decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC + 1),
    ).toThrow(DavNotFoundError);
  });

  it("accepts a range pinned at the epoch, which a falsy check would break", () => {
    // The pin is EPOCH SECONDS and is compared by equality, so zero has to be
    // a legitimate value. A `!rangeStart` guard would reject the epoch itself
    // and nothing else, which is the shape of bug that survives a review.
    const atEpoch = { ...BASE_CURSOR, rangeStart: 0, lastSortInstant: 60 };
    const token = encodeCalendarCursor(atEpoch);

    expect(decodeCalendarCursor(token, 0, APRIL_1_UTC)).toEqual(atEpoch);
  });

  it("accepts a range pinned before the epoch", () => {
    const historic = {
      ...BASE_CURSOR,
      rangeStart: -86_400,
      rangeEnd: 0,
      lastSortInstant: -3600,
    };
    const token = encodeCalendarCursor(historic);

    expect(decodeCalendarCursor(token, -86_400, 0)).toEqual(historic);
  });

  it("refuses a cursor whose pinned range is a string rather than seconds", () => {
    // Correction (b): the pin is compared by EQUALITY, and two ISO spellings of
    // the same instant compare unequal. Seconds are the only representation
    // that makes the equality check mean what it says, and a string in the slot
    // must therefore be refused rather than coerced.
    expect(() =>
      decodeCalendarCursor(
        mint({
          v: DAV_TOKEN_VERSION,
          k: "q",
          rs: "2026-03-01T00:00:00Z",
          re: APRIL_1_UTC,
          // A real calendar, so this case fails for the RANGE and only the
          // range. A null here is refused too now, and a fixture carrying one
          // would pass while proving the wrong thing.
          s: CAL_A,
          kt: null,
          at: null,
          ls: MARCH_1_UTC,
          lc: CAL_A,
          lo: OBJ_1,
          lr: null,
        }),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ),
    ).toThrow(DavNotFoundError);
  });
});

describe("the slot cursor pins every axis its answer depends on", () => {
  it("refuses a cursor supplied with a different range", () => {
    const token = encodeSlotCursor(BASE_SLOT_CURSOR);

    expect(() =>
      decodeSlotCursor(token, MARCH_1_UTC + 1, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
    expect(() =>
      decodeSlotCursor(token, MARCH_1_UTC, APRIL_1_UTC + 1),
    ).toThrow(DavNotFoundError);
  });

  it("carries the duration, zone and working-hours window for the service to compare", () => {
    // The decoder pins the RANGE and validates every field's shape; the other
    // axes are compared one layer up in `findFreeSlots`, exactly as the calendar
    // cursor's scope and terms are compared in `pagedEvents`. This proves they
    // survive the round trip intact so that comparison has something to read.
    const token = encodeSlotCursor(BASE_SLOT_CURSOR);
    const decoded = decodeSlotCursor(token, MARCH_1_UTC, APRIL_1_UTC);

    expect(decoded.durationMinutes).toBe(30);
    expect(decoded.tzid).toBe("America/Chicago");
    expect(decoded.workDayStartLocal).toBe("09:00");
    expect(decoded.workDayEndLocal).toBe("17:00");
    expect(decoded.workDaysKey).toBe("12345");
  });

  it("refuses a slot cursor handed to the calendar cursor decoder, and the reverse", () => {
    // The "g" kind letter is the only thing between them, and both payloads
    // decode through one codec — so without it a find-slots position could
    // resume a calendar listing, or the reverse, silently.
    const slotToken = encodeSlotCursor(BASE_SLOT_CURSOR);
    const calToken = encodeCalendarCursor(BASE_CURSOR);

    expect(() =>
      decodeCalendarCursor(slotToken, MARCH_1_UTC, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
    expect(() =>
      decodeSlotCursor(calToken, MARCH_1_UTC, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
  });

  it("resumes STRICTLY after the recorded candidate, never on it", () => {
    // The row the cursor was minted from must not come back — `isAfterSlotCursor`
    // is a strict `>`, so the recorded instant itself is excluded and the one
    // after it is kept.
    expect(isAfterSlotCursor(BASE_SLOT_CURSOR.lastCandidateStart, BASE_SLOT_CURSOR)).toBe(
      false,
    );
    expect(
      isAfterSlotCursor(BASE_SLOT_CURSOR.lastCandidateStart + 1, BASE_SLOT_CURSOR),
    ).toBe(true);
    expect(
      isAfterSlotCursor(BASE_SLOT_CURSOR.lastCandidateStart - 1, BASE_SLOT_CURSOR),
    ).toBe(false);
  });
});

describe("the calendar cursor names a calendar, and an in-flight one is refused", () => {
  // Making `calendarId` required on `calendar_list_events` and `calendar_search`
  // is a PUBLISHED contract change: a model has already been taught these tools,
  // and a cursor is the one part of that contract a caller can be holding
  // halfway through. A page-one token minted under the old account-wide form
  // records `s: null`, and there is no scope the caller can now supply that it
  // could ever match.
  //
  // The decision is that it FAILS CLOSED, at the codec, and these cases are the
  // proof rather than the claim. The alternative that had to be excluded is far
  // worse than an error: a null scope silently reinterpreted as a page of
  // whatever calendar the caller names next returns entirely plausible rows,
  // with every row sorting before the recorded position missing and no signal
  // at all.

  it("refuses an IN-FLIGHT cursor minted before the calendar became required", () => {
    // Hand-minted, because `encodeCalendarCursor` can no longer produce this
    // shape — which is itself half the property. Every other field is exactly
    // what a live page-one token carries.
    const inFlight = mint({
      v: DAV_TOKEN_VERSION,
      k: "q",
      rs: MARCH_1_UTC,
      re: APRIL_1_UTC,
      s: null,
      kt: null,
      at: null,
      ls: MARCH_1_UTC + 3600,
      lc: CAL_A,
      lo: OBJ_1,
      lr: null,
    });

    expect(() =>
      decodeCalendarCursor(inFlight, MARCH_1_UTC, APRIL_1_UTC),
    ).toThrow(DavNotFoundError);
  });

  it("proves that token is otherwise WELL FORMED, so the scope is what refused it", () => {
    // Non-vacuity, and this is the case that makes the one above mean anything.
    // Swap the null for a calendar and the identical payload decodes cleanly —
    // so the refusal is the scope field and not a typo in the fixture, a wrong
    // kind letter, or a range that never matched.
    const repaired = mint({
      v: DAV_TOKEN_VERSION,
      k: "q",
      rs: MARCH_1_UTC,
      re: APRIL_1_UTC,
      s: CAL_A,
      kt: null,
      at: null,
      ls: MARCH_1_UTC + 3600,
      lc: CAL_A,
      lo: OBJ_1,
      lr: null,
    });

    expect(decodeCalendarCursor(repaired, MARCH_1_UTC, APRIL_1_UTC)).toEqual(
      BASE_CURSOR,
    );
  });

  it("refuses BEFORE the range pin, so an in-flight token cannot be repaired by re-asking", () => {
    // The order matters to a caller. Were the range checked first, a caller
    // holding an in-flight cursor could be told "wrong range" and would retry
    // with a different range forever. The scope assertion runs first, so every
    // retry gets the same answer.
    const inFlight = mint({
      v: DAV_TOKEN_VERSION,
      k: "q",
      rs: MARCH_1_UTC,
      re: APRIL_1_UTC,
      s: null,
      kt: null,
      at: null,
      ls: MARCH_1_UTC + 3600,
      lc: CAL_A,
      lo: OBJ_1,
      lr: null,
    });

    for (const [start, end] of [
      [MARCH_1_UTC, APRIL_1_UTC],
      [MARCH_1_UTC + 1, APRIL_1_UTC],
      [0, APRIL_1_UTC],
    ]) {
      expect(() => decodeCalendarCursor(inFlight, start, end)).toThrow(
        DavNotFoundError,
      );
    }
  });

  it("refuses to MINT a cursor that names no calendar", () => {
    // The encoder validates on the way out as well as the way in, so a token
    // that could not survive its own decoder is never handed to a caller. Cast
    // rather than typed, because the type no longer admits this value at all —
    // which is the point: the runtime refusal is the backstop under a compile
    // -time guarantee, not a substitute for one.
    expect(() =>
      encodeCalendarCursor({ ...BASE_CURSOR, scope: null } as unknown as CalendarCursor),
    ).toThrow(DavNotFoundError);
  });

  it("says nothing about WHICH field refused it", () => {
    // The same fixed refusal every other undecodable token gets. A message
    // naming the scope would hand back the legibility the opaque identifier
    // layer gave up on purpose, and would tell a caller the wire field names.
    const inFlight = mint({
      v: DAV_TOKEN_VERSION,
      k: "q",
      rs: MARCH_1_UTC,
      re: APRIL_1_UTC,
      s: null,
      kt: null,
      at: null,
      ls: MARCH_1_UTC + 3600,
      lc: CAL_A,
      lo: OBJ_1,
      lr: null,
    });
    const truncated = encodeCalendarCursor(BASE_CURSOR).slice(0, 8);

    let fromScope: unknown;
    let fromGarbage: unknown;
    try {
      decodeCalendarCursor(inFlight, MARCH_1_UTC, APRIL_1_UTC);
    } catch (err) {
      fromScope = err;
    }
    try {
      decodeCalendarCursor(truncated, MARCH_1_UTC, APRIL_1_UTC);
    } catch (err) {
      fromGarbage = err;
    }

    expect(callerVisibleText(fromScope)).toBe(callerVisibleText(fromGarbage));
    // The CALLER-visible surface, not `surfacedText`: the stack records the
    // throw site and so names `decodeCalendarCursor` by construction, which
    // would make a substring check here assert the file's own function names
    // rather than the property.
    expect(callerVisibleText(fromScope)).not.toContain("scope");
    expect(callerVisibleText(fromScope)).not.toContain("calendar");
  });
});

describe("the calendar cursor pins its search terms", () => {
  // The gap 03-07 identified and deliberately left open, closed on the user's
  // own authorisation. Its whole signature is that it LOOKS like it worked: a
  // cursor minted under one search decodes cleanly under another, the resume
  // predicate runs, and the caller receives plausible rows from the middle of a
  // result set they never asked for. There is no error to notice.
  //
  // The pin lives on the token; the COMPARISON against what the caller asked
  // for lives in the service layer beside the scope check, because that is
  // where the requested terms exist. These cases are the token half.

  it("round-trips both terms a search pinned", () => {
    const token = encodeCalendarCursor(SEARCH_CURSOR);

    expect(decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC)).toEqual(
      SEARCH_CURSOR,
    );
  });

  it("round-trips one axis pinned and the other absent", () => {
    // A search may supply either term alone. `null` on the unsupplied axis is
    // "this axis was not searched", which is a different claim from "searched
    // for nothing".
    const keywordOnly = { ...BASE_CURSOR, keywordTerm: "standup" };
    const attendeeOnly = { ...BASE_CURSOR, attendeeTerm: "ada" };

    expect(
      decodeCalendarCursor(
        encodeCalendarCursor(keywordOnly),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ),
    ).toEqual(keywordOnly);
    expect(
      decodeCalendarCursor(
        encodeCalendarCursor(attendeeOnly),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ),
    ).toEqual(attendeeOnly);
  });

  it("keeps a listing cursor and a search cursor distinguishable", () => {
    // The whole point of choosing null-for-absent over empty-string-for-absent.
    // Were the empty string the absent marker, a listing cursor and a cursor
    // from a search for "" would be byte-identical, and the refusal this field
    // exists for would not fire between them.
    expect(encodeCalendarCursor(BASE_CURSOR)).not.toBe(
      encodeCalendarCursor(SEARCH_CURSOR),
    );
    expect(
      decodeCalendarCursor(
        encodeCalendarCursor(BASE_CURSOR),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ).keywordTerm,
    ).toBeNull();
  });

  it("refuses an EMPTY term at encode time, on either axis", () => {
    // The empty string is neither "not searched" nor a term. Admitting it would
    // give the absent marker a second spelling, and two spellings of absent is
    // exactly how a discriminator stops discriminating.
    expect(() =>
      encodeCalendarCursor({ ...BASE_CURSOR, keywordTerm: "" }),
    ).toThrow(DavNotFoundError);
    expect(() =>
      encodeCalendarCursor({ ...BASE_CURSOR, attendeeTerm: "" }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a non-string term at encode time, on either axis", () => {
    expect(() =>
      encodeCalendarCursor({
        ...BASE_CURSOR,
        keywordTerm: 7 as unknown as string,
      }),
    ).toThrow(DavNotFoundError);
    expect(() =>
      encodeCalendarCursor({
        ...BASE_CURSOR,
        attendeeTerm: 7 as unknown as string,
      }),
    ).toThrow(DavNotFoundError);
  });

  it("refuses a token minted BEFORE the term fields existed", () => {
    // A pre-field token carries no `kt` and no `at`. It is refused outright
    // rather than read as a listing cursor, which is the detectability the
    // version field exists to provide — reached here by the field assertion
    // instead, so the five token kinds this change does not touch keep working.
    expect(() =>
      decodeCalendarCursor(
        mint({
          v: DAV_TOKEN_VERSION,
          k: "q",
          rs: MARCH_1_UTC,
          re: APRIL_1_UTC,
          s: null,
          ls: MARCH_1_UTC,
          lc: CAL_A,
          lo: OBJ_1,
          lr: null,
        }),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ),
    ).toThrow(DavNotFoundError);
  });

  it("refuses an empty term arriving on the wire", () => {
    expect(() =>
      decodeCalendarCursor(
        mint({
          v: DAV_TOKEN_VERSION,
          k: "q",
          rs: MARCH_1_UTC,
          re: APRIL_1_UTC,
          s: null,
          kt: "",
          at: null,
          ls: MARCH_1_UTC,
          lc: CAL_A,
          lo: OBJ_1,
          lr: null,
        }),
        MARCH_1_UTC,
        APRIL_1_UTC,
      ),
    ).toThrow(DavNotFoundError);
  });
});

describe("the contacts cursor pins its search term", () => {
  it("refuses a cursor supplied with a different term", () => {
    const token = encodeContactsCursor(BASE_CONTACTS_CURSOR);

    expect(() => decodeContactsCursor(token, "recruiters")).toThrow(
      DavNotFoundError,
    );
  });

  it("pins the term verbatim, so a case change is a different search", () => {
    const token = encodeContactsCursor(BASE_CONTACTS_CURSOR);

    expect(() => decodeContactsCursor(token, "Recruiter")).toThrow(
      DavNotFoundError,
    );
  });

  it("permits the empty string as a display-name sort key", () => {
    // Correction (d), and the reason is a real card rather than a hypothetical:
    // the contacts parser returns "" for a card carrying neither FN nor N,
    // which is Apple's documented empty-FN behaviour. Refusing the empty key
    // here would make that card unpageable.
    const anonymous: ContactsCursor = {
      term: "recruiter",
      lastDisplayNameKey: "",
      lastObjectUrl: CARD_1,
    };
    const token = encodeContactsCursor(anonymous);

    expect(decodeContactsCursor(token, "recruiter")).toEqual(anonymous);
  });

  it("still refuses an empty object URL on the same cursor", () => {
    // The non-empty requirement applies to the URL fields ONLY. The two rules
    // live on one payload and must not be applied uniformly.
    expect(() =>
      encodeContactsCursor({ ...BASE_CONTACTS_CURSOR, lastObjectUrl: "" }),
    ).toThrow(DavNotFoundError);
  });
});

describe("the derived sort key", () => {
  it("uses the resolved instant when the occurrence has one", () => {
    expect(sortInstantOf(RESOLVED_TIME)).toBe(MARCH_1_UTC + 14 * 3600);
  });

  it("reads an all-day date as midnight UTC", () => {
    expect(sortInstantOf(ALL_DAY_TIME)).toBe(MARCH_1_UTC);
  });

  it("reads an unresolved wall clock AS IF it were UTC", () => {
    expect(sortInstantOf(UNRESOLVED_TIME)).toBe(MARCH_1_UTC + 9 * 3600);
  });

  it("is host-zone independent", () => {
    // The whole reason the key is derived by hand rather than by the runtime's
    // date parser: `Date.parse` reads a date-time with no offset in the HOST's
    // zone, so the vitest pool (the developer's zone) and production (UTC)
    // would disagree — silently, and only about times.
    expect(sortInstantOf(ALL_DAY_TIME)).toBe(Date.UTC(2026, 2, 1) / 1000);
    expect(sortInstantOf(UNRESOLVED_TIME)).toBe(
      Date.UTC(2026, 2, 1, 9, 0, 0) / 1000,
    );
  });

  it("is a pure function of the parsed bytes, so page two recomputes it", () => {
    // The property the whole cursor rests on. If the key were not reproducible,
    // page two would resume against a position page one never occupied.
    const first = sortInstantOf(UNRESOLVED_TIME);
    const recomputed = sortInstantOf({ ...UNRESOLVED_TIME });

    expect(recomputed).toBe(first);
  });

  it("is total: every shape of parsed time yields a number", () => {
    for (const time of [RESOLVED_TIME, ALL_DAY_TIME, UNRESOLVED_TIME]) {
      expect(Number.isFinite(sortInstantOf(time))).toBe(true);
    }
  });

  it("NEVER becomes the occurrence's published instant", () => {
    // The single highest-risk misreading in this design. `ls` is a SORT KEY,
    // not an instant: the occurrence's `utc` stays absent and the tool still
    // reports `timezoneUnresolved`. Computing the key must not fill either in.
    const time: EventTime = { ...UNRESOLVED_TIME };

    sortInstantOf(time);

    expect(time.utc).toBeUndefined();
    expect(time.timezoneUnresolved).toBe(true);
    expect(ALL_DAY_TIME.utc).toBeUndefined();
  });

  it("refuses a wall clock that is not the shape the parser promises", () => {
    expect(() =>
      sortInstantOf({ ...ALL_DAY_TIME, local: "the first of March" }),
    ).toThrow();
  });
});

describe("the total order the calendar cursor rides", () => {
  const ROWS: EventOrderKey[] = [
    { sortInstant: 1000, calendarUrl: CAL_A, objectUrl: OBJ_1, recurrenceId: null },
    {
      sortInstant: 1000,
      calendarUrl: CAL_A,
      objectUrl: OBJ_1,
      recurrenceId: "20260301T090000Z",
    },
    { sortInstant: 1000, calendarUrl: CAL_B, objectUrl: OBJ_2, recurrenceId: null },
    { sortInstant: 2000, calendarUrl: CAL_A, objectUrl: OBJ_3, recurrenceId: null },
    { sortInstant: 2000, calendarUrl: CAL_A, objectUrl: OBJ_4, recurrenceId: null },
    { sortInstant: 3000, calendarUrl: CAL_B, objectUrl: OBJ_5, recurrenceId: null },
  ];

  function labelOf(row: EventOrderKey): string {
    return `${row.sortInstant}|${row.objectUrl}|${row.recurrenceId ?? "-"}`;
  }

  it("orders by the instant first", () => {
    expect(compareEventOrder(ROWS[0], ROWS[3])).toBeLessThan(0);
    expect(compareEventOrder(ROWS[3], ROWS[0])).toBeGreaterThan(0);
  });

  it("breaks an instant tie on the calendar URL", () => {
    // CAL_B ends `/home/` and CAL_A ends `/work/`, so the home calendar sorts
    // first by code unit. The assertion names the fixtures rather than an
    // alphabet, because a reader who assumes A-before-B from the names alone is
    // making exactly the mistake this order does not make.
    expect(compareEventOrder(ROWS[2], ROWS[0])).toBeLessThan(0);
    expect(compareEventOrder(ROWS[0], ROWS[2])).toBeGreaterThan(0);
  });

  it("breaks a calendar tie on the OBJECT URL, never on the UID", () => {
    // Correction (c). Both `uid` fields the parsers produce are `string | null`,
    // and a null in a tie-break slot breaks the totality the ordering claims.
    // The object URL is non-null by construction — it is how the resource was
    // addressed in the first place.
    expect(compareEventOrder(ROWS[3], ROWS[4])).toBeLessThan(0);
  });

  it("sorts a null recurrence id first", () => {
    expect(compareEventOrder(ROWS[0], ROWS[1])).toBeLessThan(0);
  });

  it("is antisymmetric and reflexive on every pair", () => {
    for (const a of ROWS) {
      expect(compareEventOrder(a, a)).toBe(0);
      for (const b of ROWS) {
        // Summed rather than negated and compared: `Math.sign(0)` is `+0` and
        // its negation is `-0`, which `toBe` distinguishes and which has
        // nothing to do with the property being asserted.
        expect(
          Math.sign(compareEventOrder(a, b)) +
            Math.sign(compareEventOrder(b, a)),
        ).toBe(0);
      }
    }
  });

  it("is total: no two distinct rows compare equal", () => {
    for (let i = 0; i < ROWS.length; i += 1) {
      for (let j = i + 1; j < ROWS.length; j += 1) {
        expect(compareEventOrder(ROWS[i], ROWS[j])).not.toBe(0);
      }
    }
  });

  it("returns every row exactly once across pages, with ties present", () => {
    const sorted = [...ROWS].sort(compareEventOrder);
    const seen: string[] = [];
    let cursor: CalendarCursor | null = null;

    for (let page = 0; page < 10; page += 1) {
      const available =
        cursor === null
          ? sorted
          : sorted.filter((row) => isAfterCalendarCursor(row, cursor!));
      const rows = available.slice(0, 2);
      if (rows.length === 0) break;

      seen.push(...rows.map(labelOf));

      const last = rows[rows.length - 1];
      const token = encodeCalendarCursor({
        rangeStart: MARCH_1_UTC,
        rangeEnd: APRIL_1_UTC,
        scope: CAL_A,
        keywordTerm: null,
        attendeeTerm: null,
        lastSortInstant: last.sortInstant,
        lastCalendarUrl: last.calendarUrl,
        lastObjectUrl: last.objectUrl,
        lastRecurrenceId: last.recurrenceId,
      });
      cursor = decodeCalendarCursor(token, MARCH_1_UTC, APRIL_1_UTC);
    }

    // Equality against the sorted list asserts all three at once: every row
    // present, no row twice, and in the order the cursor claims to ride.
    expect(seen).toEqual(sorted.map(labelOf));
    expect(new Set(seen).size).toBe(ROWS.length);
  });

  it("excludes the row the cursor was minted from", () => {
    const row = ROWS[0];
    const cursor: CalendarCursor = {
      rangeStart: MARCH_1_UTC,
      rangeEnd: APRIL_1_UTC,
      scope: CAL_A,
      keywordTerm: null,
      attendeeTerm: null,
      lastSortInstant: row.sortInstant,
      lastCalendarUrl: row.calendarUrl,
      lastObjectUrl: row.objectUrl,
      lastRecurrenceId: row.recurrenceId,
    };

    expect(isAfterCalendarCursor(row, cursor)).toBe(false);
    expect(isAfterCalendarCursor(ROWS[1], cursor)).toBe(true);
  });
});

describe("the total order the contacts cursor rides", () => {
  const ROWS: ContactOrderKey[] = [
    { displayNameKey: "", objectUrl: CARD_1 },
    { displayNameKey: "ada lovelace", objectUrl: CARD_2 },
    { displayNameKey: "ada lovelace", objectUrl: CARD_3 },
  ];

  function labelOf(row: ContactOrderKey): string {
    return `${row.displayNameKey}|${row.objectUrl}`;
  }

  it("lower-cases the display name with the locale-independent form", () => {
    // Correction (d). `toLocaleLowerCase` folds differently under a Turkish
    // locale, and a key that depends on the runtime's locale is a key page two
    // may compute differently from page one.
    for (const name of ["ISTANBUL", "Ada Lovelace", "ÄÖÜ", ""]) {
      expect(displayNameKeyOf(name)).toBe(name.toLowerCase());
    }
  });

  it("orders by code unit rather than by collation", () => {
    // `localeCompare` puts "ä" before "b" in most locales; code units put it
    // after, because U+00E4 is above U+0062. Either answer is defensible as an
    // ORDER — only one is reproducible across pages without pinning a locale.
    expect(
      compareContactOrder(
        { displayNameKey: "ä", objectUrl: CARD_1 },
        { displayNameKey: "b", objectUrl: CARD_2 },
      ),
    ).toBeGreaterThan(0);
  });

  it("sorts the empty display name first rather than refusing it", () => {
    expect(compareContactOrder(ROWS[0], ROWS[1])).toBeLessThan(0);
  });

  it("breaks a name tie on the object URL", () => {
    expect(compareContactOrder(ROWS[1], ROWS[2])).toBeLessThan(0);
  });

  it("returns every contact exactly once across pages", () => {
    const sorted = [...ROWS].sort(compareContactOrder);
    const seen: string[] = [];
    let cursor: ContactsCursor | null = null;

    for (let page = 0; page < 10; page += 1) {
      const available =
        cursor === null
          ? sorted
          : sorted.filter((row) => isAfterContactsCursor(row, cursor!));
      const rows = available.slice(0, 2);
      if (rows.length === 0) break;

      seen.push(...rows.map(labelOf));

      const last = rows[rows.length - 1];
      const token = encodeContactsCursor({
        term: "recruiter",
        lastDisplayNameKey: last.displayNameKey,
        lastObjectUrl: last.objectUrl,
      });
      cursor = decodeContactsCursor(token, "recruiter");
    }

    expect(seen).toEqual(sorted.map(labelOf));
    expect(new Set(seen).size).toBe(ROWS.length);
  });
});

describe("the page-size contract", () => {
  it("defaults to twenty-five and ceilings at one hundred", () => {
    expect(PAGE_SIZE_DEFAULT).toBe(25);
    expect(PAGE_SIZE_MAX).toBe(100);
  });

  it("clamps rather than refuses", () => {
    expect(clampPageSize(undefined)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(1000)).toBe(PAGE_SIZE_MAX);
    expect(clampPageSize(0)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(-5)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(Number.NaN)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(10)).toBe(10);
    expect(clampPageSize(10.9)).toBe(10);
  });
});
