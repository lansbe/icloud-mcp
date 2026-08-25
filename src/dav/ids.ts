// The DAV opaque identifier layer. Every calendar, address book, event
// occurrence, contact and page position in this phase is addressed by a token
// minted here and by nothing else.
//
// This is D-11's zero-parameter `connectImap()` reasoning applied one protocol
// over. The goal is not that a partition host paired with the wrong protocol is
// *rejected* — it is that the pairing is unspeakable, because no caller ever
// holds a bare URL to pair. The collection URL and the object URL travel
// together, inside one token, or not at all.
//
// Pure, and attached to nothing but two error classes and the neutral
// byte-level codec in `../tokens`: no transport module, no network, no runtime
// dependency. It therefore unit-tests against literal strings with nothing
// stood up, the same shape the parsers beside it keep.
//
// Nothing here is imported from the mail tree, in either direction. The SHAPES
// below are copied from that tree's identifier layer deliberately — the module
// is not. What IS shared is the byte-level codec, because the cross-use refusal
// is a single rule and a rule living in two decoders is a rule that drifts.
// What is NOT shared is the refusal a caller sees: `fromBase64Url` throws a
// neutral `TokenDecodeError`, and translating it into this tree's
// `DavNotFoundError` is this module's own responsibility. See
// `decodeDavPayload` for where that happens and why it is the only place it
// needs to.
//
// This module contains no logging calls of any kind and must never acquire any.

import { DavConnectError, DavNotFoundError } from "./errors";
import type { EventTime } from "./icalendar";
import {
  TOKEN_DECODER,
  TOKEN_ENCODER,
  fromBase64Url,
  toBase64Url,
} from "../tokens";

/**
 * The wire format version, written into every token and checked on every
 * decode.
 *
 * Bumping this is a DECISION, not a refactor. **D-64 and D-65 are both rated
 * one-way, and this constant is why the rating is worth recording here rather
 * than in a commit message.** The moment a tool returns an identifier or a
 * cursor it has left the building: it is in the model's context, it is in a
 * client transcript, and a format change stops it working with no migration
 * path. That is the same property the mail tree's own version field records,
 * and it holds more strongly here because a cursor in flight is a page the
 * caller is halfway through.
 *
 * The field exists from day one as the cheapest possible hedge on that. It buys
 * one property and it is worth the bytes: a future format change becomes
 * *detectable* — an old token is refused outright — rather than silently
 * misread as the new shape and resolved against the wrong resource.
 */
export const DAV_TOKEN_VERSION = 1;

/**
 * The seven kind discriminators, chosen so they cannot collide with the three
 * the mail tree mints.
 *
 * One codec serves every token type in this project, so this is what keeps them
 * from being interchangeable. Without it a calendar id and an address-book id
 * would decode into each other *successfully* — the two payloads are
 * structurally identical, one collection URL each — and the caller would
 * address the wrong collection with no signal at all.
 *
 * The letters live in ONE namespace, across both protocol trees, for the reason
 * the shared codec exists: the cross-use refusal is a single rule, and a rule
 * living in two decoders is a rule that drifts. Because both trees now decode
 * through one `fromBase64Url`, a mail identifier handed to a DAV decoder fails
 * the kind check here rather than decoding into a nonsense reference. That
 * holds BY CONSTRUCTION rather than by care, which is exactly why the test
 * suite asserts it instead of assuming it — an eighth DAV kind that reused a
 * mail letter is the one way it can break, and the assertion is what would say
 * so.
 */
const KIND_CALENDAR = "k";
const KIND_EVENT = "e";
const KIND_ADDRESS_BOOK = "b";
const KIND_CONTACT = "p";
const KIND_CALENDAR_CURSOR = "q";
const KIND_CONTACTS_CURSOR = "r";
/**
 * The find-slots pagination cursor (SCHED-01, D-89).
 *
 * `"g"` for "gap" — a find-slots page orders candidate GAPS, not events, which
 * is exactly why it cannot reuse `KIND_CALENDAR_CURSOR`: that cursor pins ONE
 * calendar scope and resumes through an ordering over events, and a find-slots
 * page has neither. Disjoint from the six letters above and from the five the
 * mail tree mints.
 */
const KIND_SLOT_CURSOR = "g";

/**
 * The seven letters as a value, exported for one purpose only.
 *
 * The namespace-disjointness guard needs something to compare the mail tree's
 * letters against, and deriving it from a copied list in the test would make
 * the guard agree with itself rather than with this file. Nothing in the
 * running server reads it.
 */
export const DAV_KIND_LETTERS: readonly string[] = Object.freeze([
  KIND_CALENDAR,
  KIND_EVENT,
  KIND_ADDRESS_BOOK,
  KIND_CONTACT,
  KIND_CALENDAR_CURSOR,
  KIND_CONTACTS_CURSOR,
  KIND_SLOT_CURSOR,
]);

/**
 * The bounds on every seconds-since-epoch field.
 *
 * `0001-01-01T00:00:00Z` and `9999-12-31T23:59:59Z`, which is the range a
 * four-digit iCalendar year can express. The bound is asserted rather than left
 * as a comment because the failure it guards against is silent: an out-of-range
 * number sitting in the sort-key slot of a cursor does not error, it reorders a
 * page — and a caller reading the second page has no way to notice.
 *
 * Negative values are inside the range on purpose. A range start before 1970 is
 * an ordinary thing to ask a calendar for, and a guard that treated the epoch as
 * a floor would refuse it.
 */
const MIN_EPOCH_SECONDS = -62_135_596_800;
const MAX_EPOCH_SECONDS = 253_402_300_799;

/**
 * The default page size (D-65, mirroring D-22 for mail).
 *
 * REDECLARED here rather than imported, and that is the zero-import boundary
 * doing its job rather than an oversight. The two ceilings happen to agree on a
 * number today and they bound different things: mail's bounds MIME parsing and
 * snippet round trips, this one bounds recurrence expansion and response size.
 * Tying them together would mean a future change to one silently moved the
 * other for a reason that does not apply to it.
 *
 * Twenty-five occurrences is a readable screenful at a modest context cost —
 * enough to answer "what is on my calendar next week" without paging.
 */
export const PAGE_SIZE_DEFAULT = 25;

/**
 * The page-size ceiling (D-65).
 *
 * A hundred rows bounds the two costs that actually scale with the page here:
 * how many occurrences a recurring series is expanded into before the page is
 * cut, and how many bytes of untrusted summary and location text land in the
 * response. Neither is the cost mail's identical ceiling bounds.
 *
 * A request above it is CLAMPED rather than refused — see `clampPageSize`. A
 * refusal would turn an over-eager number into a failed call, which teaches the
 * model nothing it can act on.
 */
export const PAGE_SIZE_MAX = 100;

/** A calendar collection, named without its contents. */
export interface CalendarRef {
  /** The collection's absolute URL, as discovery resolved it. */
  collectionUrl: string;
}

/** An address book collection, named without its contents. */
export interface AddressBookRef {
  /** The collection's absolute URL, as discovery resolved it. */
  collectionUrl: string;
}

/**
 * One occurrence of one event, named completely.
 *
 * The calendar URL and the object URL are together exactly what a multi-get
 * report needs to address a resource, so resolving this token back to a
 * resource costs no lookup — which is the argument that chose it over the
 * resource's own internal identifier.
 */
export interface EventRef {
  /** The calendar collection the object lives in. */
  calendarUrl: string;
  /** The object's own absolute URL within that collection. */
  objectUrl: string;
  /**
   * The MASTER SERIES' key for this occurrence, or null for a non-recurring
   * event.
   *
   * Stable across an edit — an occurrence someone moved keeps the id of the
   * slot it was moved OUT of — which is what makes it the right discriminator
   * rather than the moved start time.
   */
  recurrenceId: string | null;
}

/** One contact card, named completely. */
export interface ContactRef {
  /** The address book collection the card lives in. */
  addressBookUrl: string;
  /** The card's own absolute URL within that collection. */
  objectUrl: string;
}

/**
 * A position in a paged calendar listing, with the range, the scope and the
 * search terms it was minted for.
 *
 * **`lastSortInstant` is a SORT KEY, not an instant, and the distinction is the
 * single highest-risk misreading in this design.** It is `sortInstantOf`'s
 * output — a total, derived, purely-computed ordering value — and for an
 * all-day event or an occurrence whose zone could not be resolved it is a
 * number this server invented in order to have something to sort by. It is NOT
 * the occurrence's published instant, it is not what a row's `startUtc` field
 * carries, and a caller that compared it against one would resume page two at a
 * position page one never occupied: every unresolved-zone row would silently
 * shift by the whole zone offset, some rows repeating and some vanishing. Read
 * `sortInstantOf`'s docstring before touching this field.
 *
 * The tie-break is the OBJECT URL rather than the resource's own unique
 * identifier, deliberately. Both parsers in this tree return that identifier as
 * `string | null`, and a null in a tie-break slot breaks the totality the whole
 * ordering claims. An object URL is non-null by construction: it is how the
 * resource was addressed in the first place.
 */
export interface CalendarCursor {
  /**
   * The requested range, in seconds since the epoch, PINNED into the cursor.
   *
   * Seconds rather than an ISO spelling, because the pin is checked by
   * EQUALITY and two ISO spellings of the same instant compare unequal — a
   * trailing `Z` against a `+00:00`, a fractional second, a lower-case `t`.
   * Seconds are canonical, and they are the same units the expansion function
   * beside this module already takes.
   */
  rangeStart: number;
  /** The requested range end, in seconds since the epoch. */
  rangeEnd: number;
  /**
   * The single calendar the listing was scoped to. Never null.
   *
   * **It was `string | null` until the unscoped listing was withdrawn, and the
   * null is not merely unused — it is now refused on the way in and on the way
   * out.** A listing spans exactly one calendar, so there is no page this field
   * cannot name, and a type that could still express "all of them" would be a
   * type describing a page this server can no longer produce.
   *
   * **A cursor minted before that change carries `s: null` and is refused.**
   * That is a deliberate fail-closed: `decodeCalendarCursor` asserts this field
   * is a URL before it returns, so an in-flight token from the unscoped era
   * throws `DavNotFoundError` at the codec rather than reaching the service
   * layer with a scope that could not possibly match the one the caller now has
   * to supply. The alternative — leaving the field nullable and relying on the
   * `cursor.scope !== scope` comparison one layer up — refuses the same tokens
   * by the same error, but it does so by ACCIDENT of a comparison rather than
   * by a stated rule, and it leaves a null in a field nothing can produce.
   */
  scope: string;
  /**
   * The keyword the page was searched under, FOLDED, or null if it was not
   * searched on that axis.
   *
   * **`null` means "this axis was not filtered" and is not the same claim as a
   * term of zero length**, which is refused outright. Two spellings of absent
   * is exactly how a discriminator stops discriminating: were the empty string
   * the absent marker, a plain listing's cursor and a cursor from a search for
   * `""` would be byte-identical, and the refusal this field exists for would
   * never fire between them. A plain listing therefore carries null on BOTH
   * axes and a search carries at least one term, which is what makes the two
   * kinds of page distinguishable rather than accidentally equal.
   *
   * **Folded, not verbatim, and that is the opposite of the contacts cursor's
   * choice on purpose.** The calendar's matching is case-insensitive — see
   * `fold` in `./calendar.ts` — so "Interview" and "interview" return the
   * IDENTICAL ordered set, and refusing between them would be a false refusal
   * rather than a safe one. Contacts pins its term verbatim because it is
   * carried into a server-side query where the server decides how to compare
   * it. Each pins whatever actually changes its own answer.
   *
   * The fold is `toLowerCase` and the comparison is by code unit, for the
   * reason `displayNameKeyOf` gives immediately below: the locale-aware fold
   * answers differently under a Turkish locale, and a cursor that depends on
   * the runtime's ambient locale is a cursor page two may read differently from
   * page one.
   */
  keywordTerm: string | null;
  /** The attendee term the page was searched under, FOLDED, or null. */
  attendeeTerm: string | null;
  /** The derived SORT KEY of the last row returned. Never an instant. */
  lastSortInstant: number;
  /** The calendar URL of the last row returned. */
  lastCalendarUrl: string;
  /** The object URL of the last row returned. */
  lastObjectUrl: string;
  /** The recurrence id of the last row returned, or null. */
  lastRecurrenceId: string | null;
}

/** A position in a paged contacts listing, with the search it was minted for. */
export interface ContactsCursor {
  /** The search term, PINNED into the cursor and compared verbatim. */
  term: string;
  /**
   * The lower-cased display name of the last row returned.
   *
   * **The empty string is a PERMITTED value here, and the reason is a real card
   * rather than a hypothetical.** The contact parser beside this module returns
   * an empty display name for a card carrying neither a formatted name nor a
   * structured one, which is Apple's own documented behaviour rather than a
   * parse failure. Refusing the empty key would make exactly those cards
   * unpageable. The non-empty requirement applies to the URL fields on this same
   * payload and must not be spread to this one.
   */
  lastDisplayNameKey: string;
  /** The object URL of the last row returned. */
  lastObjectUrl: string;
}

/**
 * A position in a paged find-slots listing, with every axis that changes the
 * answer pinned into it (SCHED-01, D-89).
 *
 * **Not a `CalendarCursor`, and the difference is structural rather than
 * cosmetic.** That cursor pins ONE calendar `scope` and resumes through
 * `compareEventOrder`, an ordering over events; a find-slots page orders
 * candidate GAPS across every calendar the account has, with no single-calendar
 * scope at all. Reusing it would either always fail its `scope` check or need
 * that check special-cased away — weakening the exact protection it exists for.
 *
 * Every field below is pinned by EQUALITY, because a find-slots answer is a
 * function of ALL of them: change the duration, the zone, the range or the
 * working-hours window and the set of candidate gaps is a different set, so a
 * position recorded against one means nothing against another. The range is
 * compared in `decodeSlotCursor` (which is handed it); the rest are compared in
 * `findFreeSlots`, mirroring how `pagedEvents` compares scope and search terms
 * after `decodeCalendarCursor` validates the range.
 */
export interface SlotCursor {
  /** The requested range start, in seconds since the epoch. Pinned by equality. */
  rangeStart: number;
  /** The requested range end, in seconds since the epoch. */
  rangeEnd: number;
  /** The slot duration the page was cut for, in minutes. */
  durationMinutes: number;
  /**
   * The zone the candidates were computed in, VERBATIM.
   *
   * Not folded, unlike a search keyword: two spellings of a zone are two
   * different answers, because the wall-clock-to-instant conversion depends on
   * the exact identifier. `America/Chicago` and a different spelling of it are
   * a different result set, so the pin is on the exact string.
   */
  tzid: string;
  /** The working-day start wall clock, `HH:MM`. */
  workDayStartLocal: string;
  /** The working-day end wall clock, `HH:MM`. */
  workDayEndLocal: string;
  /**
   * A canonical string built from the requested working days — sorted,
   * deduplicated, joined digits (`[1,2,3,4,5]` → `"12345"`).
   *
   * An array cannot be compared with `!==`, so the days are folded to one string
   * that CAN, which is what lets the working-day set be pinned by equality like
   * every other axis.
   */
  workDaysKey: string;
  /**
   * The UTC start of the last candidate returned, in seconds since the epoch.
   *
   * Unlike `CalendarCursor.lastSortInstant`, this IS a real published instant:
   * every find-slots candidate has one by construction, because the output side
   * has no all-day or unresolved-zone case the way a calendar listing's input
   * side does.
   */
  lastCandidateStart: number;
}

/** The four components of the calendar listing's total order, in order. */
export interface EventOrderKey {
  /** `sortInstantOf`'s output. A sort key, never a published instant. */
  sortInstant: number;
  calendarUrl: string;
  objectUrl: string;
  recurrenceId: string | null;
}

/** The two components of the contacts listing's total order, in order. */
export interface ContactOrderKey {
  /** `displayNameKeyOf`'s output. The empty string is legitimate. */
  displayNameKey: string;
  objectUrl: string;
}

// --------------------------------------------------------------- assertions
//
// Every refusal below constructs `DavNotFoundError` with `rediscoverable`
// left at its default of FALSE, and the reason is specific rather than
// conservative: a re-discovery re-resolves the account's home URLs, and no
// amount of re-resolving repairs a token that was truncated, forged, or minted
// for another kind. Passing `true` would spend one of D-60's two permitted
// retries — a real PROPFIND against iCloud — on every mistyped identifier the
// model ever hands back.

/**
 * Refuse a field that is not an absolute https URL.
 *
 * Absolute, because every URL that reaches this module came from discovery or
 * from a report response, both of which are absolute; a relative one is a value
 * this project never produces and therefore a value something else constructed.
 * https, because there is no path in this project that legitimately addresses a
 * DAV resource any other way, and a token carrying an http URL would be a token
 * that could later be resolved over cleartext.
 */
function assertUrl(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new DavNotFoundError();
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    // Relative, or not a URL at all.
    throw new DavNotFoundError();
  }

  if (parsed.protocol !== "https:") throw new DavNotFoundError();
}

/** Refuse a wire field that is absent, empty, or not a string. */
function assertWireString(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new DavNotFoundError();
  }
}

/**
 * Refuse a sort key that is not a string — but ADMIT the empty string.
 *
 * A separate helper rather than a flag on `assertWireString`, because the two
 * answers are not interchangeable and the caller is not choosing a style. A
 * URL field that is empty names nothing and is always a bug; a display-name
 * sort key that is empty names a real card with no name on it. Collapsing the
 * two would make the second unpageable to buy nothing.
 */
function assertPageKey(value: unknown): asserts value is string {
  if (typeof value !== "string") throw new DavNotFoundError();
}

/** Refuse a recurrence id that is neither a non-empty string nor null. */
function assertRecurrenceId(value: unknown): asserts value is string | null {
  if (value === null) return;
  // The empty string is neither "absent" nor a key, so it is refused rather
  // than read as either.
  assertWireString(value);
}

/**
 * Refuse a pinned search term that is neither a non-empty string nor null.
 *
 * Structurally identical to `assertRecurrenceId` above and deliberately not
 * merged with it. The two admit the same values for entirely different reasons
 * — one is a slot in a recurrence key, the other is a query discriminator — and
 * a single shared helper would make a later change to either silently move the
 * other. The comment each one carries is the actual content.
 */
function assertSearchTerm(value: unknown): asserts value is string | null {
  if (value === null) return;
  // The empty string is neither "this axis was not searched" nor a term to
  // search for, so it is refused rather than read as either.
  assertWireString(value);
}

/**
 * Refuse a seconds-since-epoch field outside the representable range.
 *
 * `Number.isInteger` rejects `NaN`, both infinities, and every fractional
 * value, so the three checks together admit only a whole second inside the
 * bounds above.
 */
function assertEpochSeconds(value: unknown): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < MIN_EPOCH_SECONDS ||
    value > MAX_EPOCH_SECONDS
  ) {
    throw new DavNotFoundError();
  }
}

// ------------------------------------------------------------------- codec

/**
 * Decode a token to its payload object, refusing rather than repairing.
 *
 * Every failure below throws the same error and there is no path that returns a
 * partially-decoded value — no "best effort" reference, no defaulted field, no
 * null the caller might forget to check. A refusal is the honest diagnosis:
 * repairing around a malformed identifier does not recover the resource the
 * caller wanted, it addresses a different one and reports it as the one asked
 * for, which is worse than any error and is undetectable from outside.
 *
 * **Refuse, never repair, and never explain.** Nothing thrown from here names
 * the check that failed, quotes the token back, or mentions a field name, a
 * version or an encoding. Legibility is the property the opaque identifier
 * layer deliberately gave up, and an error path is the cheapest place to hand
 * it back for free.
 *
 * The version and kind are checked BEFORE any field is read, so a token of the
 * wrong shape never reaches the field extraction at all.
 *
 * **This is also this tree's translation boundary for the neutral codec**, and
 * it is the ONLY one it needs. `fromBase64Url` throws `TokenDecodeError`, which
 * is an internal signal rather than a caller-visible outcome; the `catch` below
 * turns it — along with a `fatal` UTF-8 failure and a JSON syntax error, which
 * are the two other ways the same expression can throw — into the one error
 * this module is allowed to raise. That the boundary is a single `catch` is not
 * luck: `fromBase64Url` and the strict decoder are each reached from exactly
 * one place in this file, and it is this one. A second call site outside this
 * `try` would let a neutral error escape to a caller, where the shared
 * categoriser would report a malformed identifier as a connection failure.
 */
function decodeDavPayload(
  token: string,
  kind: string,
): Record<string, unknown> {
  if (typeof token !== "string" || token.length === 0) {
    throw new DavNotFoundError();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(TOKEN_DECODER.decode(fromBase64Url(token)));
  } catch {
    // A refused base64url token, bytes that are not valid UTF-8, or valid UTF-8
    // that is not valid JSON. A single flipped character reaches here by one
    // route or another, and all three surface identically.
    throw new DavNotFoundError();
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new DavNotFoundError();
  }

  const payload = parsed as Record<string, unknown>;
  if (payload.v !== DAV_TOKEN_VERSION) throw new DavNotFoundError();
  if (payload.k !== kind) throw new DavNotFoundError();
  return payload;
}

/** Base64url of a payload object. The one place a token is actually minted. */
function mintToken(payload: Record<string, unknown>): string {
  return toBase64Url(TOKEN_ENCODER.encode(JSON.stringify(payload)));
}

// -------------------------------------------------------------- identifiers
//
// Every encoder validates on the way OUT as well as on the way in. A token that
// could not survive its own decoder must never be handed to a caller: the
// failure would surface arbitrarily far from the code that built it, against a
// token that by then looks like the model's fault.

/** Mint the token that names a calendar collection. */
export function encodeCalendarId(ref: CalendarRef): string {
  assertUrl(ref.collectionUrl);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_CALENDAR,
    c: ref.collectionUrl,
  });
}

/** Read a calendar token back, or refuse it. Never returns a partial result. */
export function decodeCalendarId(token: string): CalendarRef {
  const payload = decodeDavPayload(token, KIND_CALENDAR);

  const collectionUrl = payload.c;
  assertUrl(collectionUrl);

  return { collectionUrl };
}

/** Mint the token that names an address book collection. */
export function encodeAddressBookId(ref: AddressBookRef): string {
  assertUrl(ref.collectionUrl);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_ADDRESS_BOOK,
    c: ref.collectionUrl,
  });
}

/**
 * Read an address book token back, or refuse it.
 *
 * The payload is structurally IDENTICAL to a calendar's, which is precisely why
 * the kind letter is load-bearing rather than decorative: it is the only thing
 * that stops a calendar id resolving here into a plausible-looking address book
 * reference that addresses the wrong collection.
 */
export function decodeAddressBookId(token: string): AddressBookRef {
  const payload = decodeDavPayload(token, KIND_ADDRESS_BOOK);

  const collectionUrl = payload.c;
  assertUrl(collectionUrl);

  return { collectionUrl };
}

/** Mint the token that names one occurrence of one event. */
export function encodeEventId(ref: EventRef): string {
  assertUrl(ref.calendarUrl);
  assertUrl(ref.objectUrl);
  assertRecurrenceId(ref.recurrenceId);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_EVENT,
    c: ref.calendarUrl,
    o: ref.objectUrl,
    r: ref.recurrenceId,
  });
}

/** Read an occurrence token back, or refuse it. Never returns a partial result. */
export function decodeEventId(token: string): EventRef {
  const payload = decodeDavPayload(token, KIND_EVENT);

  const calendarUrl = payload.c;
  const objectUrl = payload.o;
  const recurrenceId = payload.r;
  assertUrl(calendarUrl);
  assertUrl(objectUrl);
  assertRecurrenceId(recurrenceId);

  return { calendarUrl, objectUrl, recurrenceId };
}

/** Mint the token that names one contact card. */
export function encodeContactId(ref: ContactRef): string {
  assertUrl(ref.addressBookUrl);
  assertUrl(ref.objectUrl);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_CONTACT,
    c: ref.addressBookUrl,
    o: ref.objectUrl,
  });
}

/** Read a contact token back, or refuse it. Never returns a partial result. */
export function decodeContactId(token: string): ContactRef {
  const payload = decodeDavPayload(token, KIND_CONTACT);

  const addressBookUrl = payload.c;
  const objectUrl = payload.o;
  assertUrl(addressBookUrl);
  assertUrl(objectUrl);

  return { addressBookUrl, objectUrl };
}

// ----------------------------------------------------------------- ordering

/** The wall-clock shapes the calendar parser promises, and nothing else. */
const WALL_CLOCK = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2}))?$/;

/**
 * The DERIVED SORT KEY for one occurrence. Total, pure, and never published.
 *
 * **Read this before using the value it returns.** A calendar listing has to be
 * sorted by *something*, and two of the three shapes a parsed time can take
 * have no instant at all: an all-day event is a date, and an occurrence whose
 * zone the resource never defined is a wall clock anchored to nothing. The
 * parser is right to omit the seconds-since-epoch field in both cases —
 * publishing a number nobody computed is exactly how a user acts on a time that
 * is wrong by a whole zone offset without ever being told there was a question.
 *
 * So the ordering needs a key the parser will not give it, and this function
 * defines one:
 *
 *   - a resolved timed occurrence sorts by its actual instant;
 *   - an all-day occurrence sorts by midnight of its date, read as UTC;
 *   - an unresolved-zone occurrence sorts by its wall clock, read AS IF UTC.
 *
 * Two properties make that safe, and both are load-bearing. It is **total** —
 * every shape yields a number, so no row is unsortable. And it is a **pure
 * function of the `EventTime` it is handed** — no clock, no host zone, no
 * ambient state read here — so page two recomputes the identical key for the
 * identical row, which is the entire basis on which the keyset cursor can
 * resume.
 *
 * **That second property is a claim about this function AND about how its
 * input is produced, and the second half is not free (CR-03).** The purity
 * here is real but shallow: the branch above returns `time.utc`, and whether
 * an occurrence HAS a `utc` — and what it is — depends on whether the parser
 * could resolve the zone the resource named. `ICAL.TimezoneService` is a
 * process-global registry whose lifetime is the isolate's, so for a resource
 * that names a zone without defining it, that answer once depended on which
 * resources a warm isolate had already seen. Page one served by a cold isolate
 * and page two by a warm one would then compute different keys for the same
 * row, and `lastSortInstant` would name a position the recomputed order never
 * occupies — the cursor silently dropping or repeating rows, arriving through
 * the one input the token cannot pin because it is not a field.
 *
 * What closes that is `withParsedResource` in `./icalendar.ts`, which bounds a
 * resource's inline timezone registrations to its own parse. It is named here
 * rather than merely relied on, because the reproducibility this docstring
 * promises rests on that boundary holding: a future caller that parses a
 * resource outside the scope reopens this hole, and it would reopen it
 * silently, in the ordering rather than in any value anyone can see.
 *
 * **The key NEVER becomes a response field.** The occurrence's own instant
 * stays absent and the tool still reports that the zone was unresolved; this
 * number exists only to put rows in an order. A row's published instant and its
 * sort key are different things and must stay different things — see
 * `CalendarCursor.lastSortInstant` for what goes wrong when they are confused.
 *
 * The dispatch is STRUCTURAL — on the presence of the instant — rather than on
 * the all-day or unresolved flags, on the same reasoning the expansion function
 * beside this module uses to pick its path: a structural check answers the
 * question being asked, while a flag answers a question about how the resource
 * was reported.
 *
 * The wall clock is decomposed by hand and reassembled through UTC accessors
 * rather than handed to the runtime's date parser, and that is not fussiness.
 * A date-time string with no offset is defined to be read in the HOST's zone,
 * so the test pool (the developer's zone) and production (UTC) would disagree —
 * silently, and only about times, which is the worst shape a bug can have in a
 * calendar. A wall clock this module cannot read at all is a resource that came
 * back unusable rather than an identifier that was refused, so it raises the
 * transport class the parsers beside it raise.
 */
export function sortInstantOf(time: EventTime): number {
  if (time.utc !== undefined) return time.utc;

  const parts = WALL_CLOCK.exec(time.local);
  if (parts === null) throw new DavConnectError();

  const year = Number(parts[1]);
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  const hour = parts[4] === undefined ? 0 : Number(parts[4]);
  const minute = parts[5] === undefined ? 0 : Number(parts[5]);
  // Sixty is admitted: RFC 5545 permits a leap second, and normalising one
  // forward by a second is the only reading available.
  const second = parts[6] === undefined ? 0 : Number(parts[6]);

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 60
  ) {
    throw new DavConnectError();
  }

  // Built from the epoch and moved with UTC accessors only, so no host zone can
  // reach the answer. `setUTCFullYear` rather than the static UTC constructor
  // because that constructor maps a two-digit year into the twentieth century,
  // which would silently relocate an event in the first hundred years AD.
  const at = new Date(0);
  at.setUTCFullYear(year, month - 1, day);
  at.setUTCHours(hour, minute, second, 0);

  // A rollover — the thirtieth of February becoming the second of March — is a
  // repair, and this module does not repair.
  if (
    at.getUTCFullYear() !== year ||
    at.getUTCMonth() !== month - 1 ||
    at.getUTCDate() !== day
  ) {
    throw new DavConnectError();
  }

  return Math.floor(at.getTime() / 1000);
}

/**
 * The contacts listing's sort key: the display name, folded to lower case.
 *
 * `toLowerCase` rather than its locale-aware sibling, deliberately. The
 * locale-aware fold gives a different answer under a Turkish locale — a dotted
 * capital I folds to a dotless one — and a key that depends on the runtime's
 * ambient locale is a key page two may compute differently from page one. The
 * locale-aware form is the right answer for DISPLAYING a name and the wrong
 * answer for ordering one across two requests.
 *
 * The empty string in, the empty string out. See `ContactsCursor`.
 */
export function displayNameKeyOf(displayName: string): string {
  return displayName.toLowerCase();
}

/**
 * Code-unit comparison, not collation.
 *
 * The same reasoning `displayNameKeyOf` gives: a collating comparison sorts by
 * the runtime's locale rules, and this order has to be reproducible across two
 * separate requests without pinning a locale anywhere. Code units are an
 * arbitrary order and a stable one, and stability is the property the cursor
 * actually needs.
 */
function compareCodeUnits(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Code-unit comparison with null sorting first. */
function compareNullableCodeUnits(
  a: string | null,
  b: string | null,
): number {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  return compareCodeUnits(a, b);
}

/**
 * The TOTAL ORDER the calendar cursor rides. The cursor is meaningless without
 * it, so it is code rather than a docstring.
 *
 * Sort key ascending, then calendar URL ascending, then object URL ascending,
 * then recurrence id ascending with null first.
 *
 * **Total**, because the last three components cannot all collide: two rows
 * sharing an object URL are two occurrences of one resource, and those are
 * distinguished by their recurrence ids by construction. **Deterministic**,
 * because every component is a pure function of the fetched bytes — see
 * `sortInstantOf` for the one component that had to be derived to make that
 * true.
 *
 * Exported so the listing that pages and the cursor that resumes are the SAME
 * order rather than two implementations that agree today.
 */
export function compareEventOrder(a: EventOrderKey, b: EventOrderKey): number {
  if (a.sortInstant !== b.sortInstant) {
    return a.sortInstant < b.sortInstant ? -1 : 1;
  }

  const byCalendar = compareCodeUnits(a.calendarUrl, b.calendarUrl);
  if (byCalendar !== 0) return byCalendar;

  const byObject = compareCodeUnits(a.objectUrl, b.objectUrl);
  if (byObject !== 0) return byObject;

  return compareNullableCodeUnits(a.recurrenceId, b.recurrenceId);
}

/**
 * The total order the contacts cursor rides: name key, then object URL.
 *
 * Total because the object URL is unique within an account and non-null by
 * construction, which is why it is the tie-break rather than the card's own
 * internal identifier — that field is nullable, and a null in a tie-break slot
 * is a hole in the totality the ordering claims.
 */
export function compareContactOrder(
  a: ContactOrderKey,
  b: ContactOrderKey,
): number {
  const byName = compareCodeUnits(a.displayNameKey, b.displayNameKey);
  if (byName !== 0) return byName;

  return compareCodeUnits(a.objectUrl, b.objectUrl);
}

/**
 * Whether a row belongs on the page AFTER the one this cursor ends.
 *
 * Strictly after, so the row the cursor was minted from is excluded and no row
 * is returned twice. The predicate is expressed through `compareEventOrder`
 * rather than as its own chain of comparisons on purpose: a resume predicate
 * that disagreed with the sort by even one component is exactly how a keyset
 * cursor silently drops or repeats rows.
 */
export function isAfterCalendarCursor(
  key: EventOrderKey,
  cursor: CalendarCursor,
): boolean {
  return (
    compareEventOrder(key, {
      sortInstant: cursor.lastSortInstant,
      calendarUrl: cursor.lastCalendarUrl,
      objectUrl: cursor.lastObjectUrl,
      recurrenceId: cursor.lastRecurrenceId,
    }) > 0
  );
}

/** Whether a contact belongs on the page AFTER the one this cursor ends. */
export function isAfterContactsCursor(
  key: ContactOrderKey,
  cursor: ContactsCursor,
): boolean {
  return (
    compareContactOrder(key, {
      displayNameKey: cursor.lastDisplayNameKey,
      objectUrl: cursor.lastObjectUrl,
    }) > 0
  );
}

/**
 * Whether a candidate belongs on the page AFTER the one this cursor ends.
 *
 * Strictly after, so the candidate the cursor was minted from is never returned
 * twice. A find-slots candidate is ordered by its UTC start alone — every
 * candidate has one, and the service sorts them into a total order before the
 * page is cut — so the resume predicate is a single comparison rather than the
 * four-component chain a calendar listing needs.
 */
export function isAfterSlotCursor(
  candidateStart: number,
  cursor: SlotCursor,
): boolean {
  return candidateStart > cursor.lastCandidateStart;
}

// ------------------------------------------------------------------ cursors

/** Mint the token that continues a paged calendar listing. */
export function encodeCalendarCursor(cursor: CalendarCursor): string {
  assertEpochSeconds(cursor.rangeStart);
  assertEpochSeconds(cursor.rangeEnd);
  // Unconditional. A page is always scoped to one calendar, so a cursor that
  // could not name one is a cursor for a listing this server cannot produce.
  assertUrl(cursor.scope);
  assertSearchTerm(cursor.keywordTerm);
  assertSearchTerm(cursor.attendeeTerm);
  assertEpochSeconds(cursor.lastSortInstant);
  assertUrl(cursor.lastCalendarUrl);
  assertUrl(cursor.lastObjectUrl);
  assertRecurrenceId(cursor.lastRecurrenceId);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_CALENDAR_CURSOR,
    rs: cursor.rangeStart,
    re: cursor.rangeEnd,
    s: cursor.scope,
    kt: cursor.keywordTerm,
    at: cursor.attendeeTerm,
    ls: cursor.lastSortInstant,
    lc: cursor.lastCalendarUrl,
    lo: cursor.lastObjectUrl,
    lr: cursor.lastRecurrenceId,
  });
}

/**
 * Read a calendar cursor back against the range the caller asked for, or refuse
 * it.
 *
 * **The range pin is a REFUSAL, not a hint.** A caller supplying this cursor
 * with a different range is refused as not-found — the existing reading for a
 * token that is undecodable or of the wrong kind — because without the pin a
 * changed range silently reinterprets the recorded position against a different
 * set: the cursor still decodes, the resume predicate still runs, and the
 * caller gets a page from the middle of a listing it never asked for. The range
 * is compared as seconds by equality, which is the whole reason it is stored as
 * seconds; see `CalendarCursor.rangeStart`.
 *
 * ## The three discriminators, and which layer compares each
 *
 * A cursor must COMPARE every discriminator its position depends on, not merely
 * carry one. There are three, and only the first is compared here:
 *
 *   - the **range**, compared above, because this function is handed the
 *     requested range and can;
 *   - the **scope**, carried here and compared in `pagedEvents` in
 *     `./calendar.ts` — but VALIDATED here, because since the unscoped listing
 *     was withdrawn a cursor that names no calendar is malformed rather than
 *     merely mismatched;
 *   - the **search terms**, carried here and compared in the same place, for
 *     the same reason — the requested terms exist at that layer and not at
 *     this one.
 *
 * Both service-layer comparisons run BEFORE the network read, so a mismatched
 * cursor costs no request. Splitting them this way is not ideal and it is
 * recorded rather than hidden: adding a parameter per discriminator to this
 * signature would put the whole check in one place, at the cost of making every
 * caller pass values the decoder cannot validate anyway.
 *
 * ## The cursor in flight when the unscoped listing was withdrawn
 *
 * Making `calendarId` required on the two calendar tools is a published
 * contract change, and a cursor is the one part of that contract a caller may
 * be holding halfway through. A page-one token minted under the old unscoped
 * form records `s: null`, and there is no scope the caller can now supply that
 * it could match.
 *
 * It is refused, by the unconditional `assertUrl` below, and the refusal is the
 * whole design decision: the token fails CLOSED, at the codec, with the same
 * `DavNotFoundError` every other undecodable token gets, before the range pin
 * and before any request. It cannot be silently reinterpreted as a page of
 * whatever calendar the caller names next — which is the failure that would
 * matter, because the rows would look entirely plausible and every row sorting
 * before the recorded position would be missing with no signal at all.
 *
 * ## What the cursor guarantees, and what it honestly does not
 *
 * Page two re-runs the report, re-expands, re-sorts by `compareEventOrder` and
 * resumes at the first key strictly after the recorded position. Nothing
 * already returned is returned again, and nothing behind the cursor is skipped.
 *
 * It does NOT guarantee that a page-one listing plus a page-two listing equals
 * the set that existed when page one was built, and the difference from the
 * mail half of this surface is worth stating plainly rather than hiding. A mail
 * cursor is *naturally* stable because new mail always sorts ahead of page one,
 * so a keyset can never miss it. A calendar has no such property: an event
 * created while the caller is on page two can land at a start time already
 * passed, and that occurrence will not appear. **The listing tool should lift
 * that sentence into its own description** — it is a limit a caller can reason
 * about, and a boolean this server cannot actually compute would be worse than
 * saying so.
 *
 * This is strictly better than an offset cursor, which would additionally
 * duplicate and drop rows the caller already holds, and it is the best
 * available without server-side state, which is deferred.
 *
 * ## Why the collection synchronisation primitives are not used here
 *
 * Recorded so a later session does not re-derive the temptation. A collection
 * tag answers "has this collection changed"; a sync token answers "what changed
 * since this token". Neither answers "where was I in this range" — a page built
 * on the second would return whatever changed since page one, which is a
 * different question from the one the caller asked. Both are also
 * collection-scoped, so neither composes across a listing that spans several
 * calendars. They belong to a future synchronisation feature, not to this
 * cursor.
 */
export function decodeCalendarCursor(
  token: string,
  requestedRangeStart: number,
  requestedRangeEnd: number,
): CalendarCursor {
  const payload = decodeDavPayload(token, KIND_CALENDAR_CURSOR);

  const rangeStart = payload.rs;
  const rangeEnd = payload.re;
  const scope = payload.s;
  const keywordTerm = payload.kt;
  const attendeeTerm = payload.at;
  const lastSortInstant = payload.ls;
  const lastCalendarUrl = payload.lc;
  const lastObjectUrl = payload.lo;
  const lastRecurrenceId = payload.lr;

  assertEpochSeconds(rangeStart);
  assertEpochSeconds(rangeEnd);
  // Unconditional, and this is the line that refuses an IN-FLIGHT cursor from
  // the unscoped era. Such a token carries `s: null`, which is a shape this
  // encoder can no longer mint, so it is refused here — before the range pin,
  // before the service layer's scope comparison, and before any request. Fails
  // closed by a stated rule rather than by the accident of a comparison that
  // could never have matched; see `CalendarCursor.scope`.
  assertUrl(scope);
  // A token minted before these fields existed carries neither, so it is
  // refused here rather than read as a listing cursor. That is the
  // detectability `DAV_TOKEN_VERSION` exists to provide, reached by the field
  // assertion instead of by a bump — a bump would additionally invalidate the
  // five token kinds this change does not touch, for no gain.
  assertSearchTerm(keywordTerm);
  assertSearchTerm(attendeeTerm);
  assertEpochSeconds(lastSortInstant);
  assertUrl(lastCalendarUrl);
  assertUrl(lastObjectUrl);
  assertRecurrenceId(lastRecurrenceId);

  if (rangeStart !== requestedRangeStart || rangeEnd !== requestedRangeEnd) {
    throw new DavNotFoundError();
  }

  return {
    rangeStart,
    rangeEnd,
    scope: scope as string,
    keywordTerm: keywordTerm as string | null,
    attendeeTerm: attendeeTerm as string | null,
    lastSortInstant,
    lastCalendarUrl,
    lastObjectUrl,
    lastRecurrenceId,
  };
}

/** Mint the token that continues a paged contacts listing. */
export function encodeContactsCursor(cursor: ContactsCursor): string {
  assertPageKey(cursor.term);
  assertPageKey(cursor.lastDisplayNameKey);
  assertUrl(cursor.lastObjectUrl);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_CONTACTS_CURSOR,
    t: cursor.term,
    ln: cursor.lastDisplayNameKey,
    lo: cursor.lastObjectUrl,
  });
}

/**
 * Read a contacts cursor back against the term the caller asked for, or refuse
 * it.
 *
 * The term pin is the contacts analogue of the calendar cursor's range pin, and
 * it is a refusal for the same reason: a position recorded against one result
 * set means nothing against another. Compared VERBATIM, so a change of case is
 * a different search — the folding that happens for ORDERING is a separate
 * thing from the term the caller typed, and conflating them here would let two
 * genuinely different searches share a cursor.
 *
 * The term itself is not required to be non-empty. An empty term is a
 * legitimate pin for a listing that filters nothing, and deciding otherwise is
 * a policy that belongs to the tool rather than to the identifier layer.
 *
 * **What this cursor cannot pin, stated rather than discovered later.** A
 * contacts search may be served either by a server-side query or by a
 * client-side fallback when the server does not report support for it, and
 * those two paths can return different result sets. This layer has no way to
 * know which one served a page, so a cursor minted from a server-side page and
 * resumed against a fallback page is not detectable here. It is not fixable at
 * this layer either — the fact lives at the search boundary, not in the token —
 * so the honest home for it is the search tool's own description.
 */
export function decodeContactsCursor(
  token: string,
  requestedTerm: string,
): ContactsCursor {
  const payload = decodeDavPayload(token, KIND_CONTACTS_CURSOR);

  const term = payload.t;
  const lastDisplayNameKey = payload.ln;
  const lastObjectUrl = payload.lo;

  assertPageKey(term);
  assertPageKey(lastDisplayNameKey);
  assertUrl(lastObjectUrl);

  if (term !== requestedTerm) throw new DavNotFoundError();

  return { term, lastDisplayNameKey, lastObjectUrl };
}

/** Mint the token that continues a paged find-slots listing (SCHED-01). */
export function encodeSlotCursor(cursor: SlotCursor): string {
  assertEpochSeconds(cursor.rangeStart);
  assertEpochSeconds(cursor.rangeEnd);
  // The duration and the position are whole seconds/minutes inside the same
  // representable range every other epoch field sits in, so the epoch-seconds
  // assertion is the right shape for both — reused rather than a fourth inline
  // integer check, on the same extraction-over-duplication ground the search
  // helpers stand on.
  assertEpochSeconds(cursor.durationMinutes);
  assertWireString(cursor.tzid);
  assertWireString(cursor.workDayStartLocal);
  assertWireString(cursor.workDayEndLocal);
  assertWireString(cursor.workDaysKey);
  assertEpochSeconds(cursor.lastCandidateStart);

  return mintToken({
    v: DAV_TOKEN_VERSION,
    k: KIND_SLOT_CURSOR,
    rs: cursor.rangeStart,
    re: cursor.rangeEnd,
    d: cursor.durationMinutes,
    tz: cursor.tzid,
    ws: cursor.workDayStartLocal,
    we: cursor.workDayEndLocal,
    wd: cursor.workDaysKey,
    lc: cursor.lastCandidateStart,
  });
}

/**
 * Read a find-slots cursor back against the range the caller asked for, or
 * refuse it.
 *
 * **The range pin is a REFUSAL, mirroring `decodeCalendarCursor`.** A cursor
 * resumed against a different range silently reinterprets its recorded position
 * against a different set of candidate gaps, so a changed range is refused as
 * not-found — before any request — rather than answered plausibly and wrongly.
 *
 * The OTHER pinned axes — duration, zone, working-hours window — are carried
 * here and compared in `findFreeSlots`, for the same reason the calendar cursor
 * splits its scope and search-term comparisons out to `pagedEvents`: the
 * requested values live at that layer and not at this one. Both comparisons run
 * before the network read, so a mismatched cursor costs no request.
 */
export function decodeSlotCursor(
  token: string,
  requestedRangeStart: number,
  requestedRangeEnd: number,
): SlotCursor {
  const payload = decodeDavPayload(token, KIND_SLOT_CURSOR);

  const rangeStart = payload.rs;
  const rangeEnd = payload.re;
  const durationMinutes = payload.d;
  const tzid = payload.tz;
  const workDayStartLocal = payload.ws;
  const workDayEndLocal = payload.we;
  const workDaysKey = payload.wd;
  const lastCandidateStart = payload.lc;

  assertEpochSeconds(rangeStart);
  assertEpochSeconds(rangeEnd);
  assertEpochSeconds(durationMinutes);
  assertWireString(tzid);
  assertWireString(workDayStartLocal);
  assertWireString(workDayEndLocal);
  assertWireString(workDaysKey);
  assertEpochSeconds(lastCandidateStart);

  if (rangeStart !== requestedRangeStart || rangeEnd !== requestedRangeEnd) {
    throw new DavNotFoundError();
  }

  return {
    rangeStart,
    rangeEnd,
    durationMinutes,
    tzid,
    workDayStartLocal,
    workDayEndLocal,
    workDaysKey,
    lastCandidateStart,
  };
}

/**
 * Bring a requested page size inside the contract, clamping rather than
 * refusing.
 *
 * An absent, unreadable, or nonsensical value becomes the default rather than
 * an error, and an oversized one becomes the ceiling. The model asking for a
 * thousand rows has told this server what it wants clearly enough; answering
 * with a hundred is a better response than answering with a failure it has to
 * work out how to retry.
 */
export function clampPageSize(requested: number | undefined): number {
  if (requested === undefined || !Number.isFinite(requested)) {
    return PAGE_SIZE_DEFAULT;
  }
  const whole = Math.floor(requested);
  if (whole < 1) return PAGE_SIZE_DEFAULT;
  return Math.min(whole, PAGE_SIZE_MAX);
}
