// The contacts service layer: address books, one match rule reachable by two
// routes, a total order, and keyset paging (CONT-01, CONT-02).
//
// This module owns SHAPE, COST and — uniquely in this phase — the one genuinely
// branching control flow. It does not own meaning: every byte of vCard goes to
// `./vcard.ts`, every identifier and every ordering decision comes from
// `./ids.ts`, and every outbound request goes through the injected fetch built
// in `./transport.ts`. The same three separations `./calendar.ts` keeps beside
// it, for the same reason: the alternative was a second implementation that
// agreed with the first only until someone edited one of them.
//
// **The branch is D-62, and it is not defensive over-engineering.** The
// protocol lets a server advertise a report and still refuse the filter inside
// it; Apple's own forums document iCloud returning contacts with an empty
// formatted name, which a server-side match on that property cannot find at
// all; and plan 03-01's live diagnostic against the real account measured this
// address book advertising exactly `syncCollection` and `addressbookMultiget`
// — the query report is ABSENT. So on this account the local route is not a
// fallback, it is the only route. Which one ran is reported on every search,
// because "no results" and "this route cannot see this contact" are different
// answers and nothing else lets a reader tell them apart.
//
// **Every multi-collection operation here is SERIAL, and that is a safety
// property rather than a style.** ./.claude/CLAUDE.md §3 records the budget:
// production allows six simultaneous connections per Worker invocation, KV
// reads and outbound fetches count against the same six, and iCloud's own
// per-account ceiling is lower, undocumented, and deliberately unmeasured —
// because exhausting it does not fail politely, it locks the user out of their
// own mail in Mail.app on their own devices. Banned twice: structurally by the
// request-scoped queue in `./transport.ts`, and detectively by the
// `dav-concurrent-request` scan rule that reads this file.
//
// This module contains no logging calls of any kind and must never acquire any.

import { addressBookMultiGet, addressBookQuery, fetchAddressBooks, propfind } from "tsdav";
import type { DAVResponse } from "tsdav";
import type { Env } from "../env";
import { assertUnderHome, davAccountFor, withRediscovery } from "./discovery";
import type { ResolvedDavAccount } from "./discovery";
import { DavNotFoundError } from "./errors";
import {
  clampPageSize,
  compareContactOrder,
  decodeContactsCursor,
  displayNameKeyOf,
  encodeAddressBookId,
  encodeContactId,
  encodeContactsCursor,
  isAfterContactsCursor,
} from "./ids";
import type { ContactOrderKey, ContactRef, ContactsCursor } from "./ids";
import type { DavFetch } from "./transport";
import { displayNameFor, parseVCard } from "./vcard";
import type {
  ContactAddress,
  ContactEmail,
  ContactName,
  ContactTel,
  ParsedContact,
} from "./vcard";
import type { Principal } from "../principal";

/**
 * The report name that decides the route, as the library spells it.
 *
 * The library camel-cases element names and strips the namespace prefix, so
 * the protocol's `addressbook-query` arrives here as `addressbookQuery`. The
 * spelling is pinned in one constant rather than written at the comparison
 * because it is the single string that decides which of two routes a search
 * takes, and a typo in it would silently make every search take the fallback —
 * which returns correct rows, so nothing would ever fail.
 */
const ADDRESS_BOOK_QUERY_REPORT = "addressbookQuery";

/**
 * The longest search term this server will carry.
 *
 * It bounds two different costs at once. On the server route the term is
 * carried into a filter document sent to Apple; on the local route it is
 * compared against the display name and every email address of every card in
 * the book. Refusing at the top is the CHEAPEST possible refusal and the one
 * that spends none of the connection budget — the same argument the range cap
 * in `./calendar.ts` and the null-byte check in the mail search tool both make.
 *
 * Two hundred characters is far beyond any real name and beyond the longest
 * address a mail server will accept, so the ceiling cannot be reached by a
 * genuine question. It exists for the term that is not a question.
 */
export const CONTACT_TERM_MAX_LENGTH = 200;

/** Which route produced a page of matches (D-62). */
export type MatchPath = "server" | "local" | "mixed";

/**
 * One address book collection, named without its contents.
 *
 * `reports` is the value this listing exists for: it is what the route
 * pre-check reads, and it is the only thing that lets a book that cannot
 * filter cost no failed request at all.
 */
export interface AddressBookSummary {
  /** The opaque token that names this collection. Minted here, so trusted. */
  id: string;
  /**
   * The collection's display name. **Stranger-authored.**
   *
   * A shared address book is named by whoever shared it, which puts it in the
   * same class as a calendar name and a mail folder name — a short,
   * authoritative-looking string an instruction hides well in.
   */
  displayName: string;
  /** The report names the collection advertises. This server's reading. */
  reports: string[];
}

/** Every address book the account has, plus where discovery came from. */
export interface AddressBookListing {
  addressBooks: AddressBookSummary[];
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
}

/**
 * One contact, as a search row (CONT-01, D-65).
 *
 * **There is no field on this type for a phone number, a postal address, an
 * organisation or a note, and that is the point.** It is the contacts form of
 * the argument `MessageSummary` and `EventSummary` already make: the reliable
 * way to keep a metadata-only contract true against a later edit is for the
 * shape to be unable to express the violation. A note cannot be added to a row
 * by accident; it can only be added by changing this interface, which shows up
 * in a diff.
 *
 * **The email addresses ARE here, and that is the deliberate trade.** The
 * overwhelmingly common question is what someone's address is, and returning it
 * in the search that found them makes that one call rather than two — at a cost
 * below the snippet a mail row already carries.
 *
 * Each field is annotated with which half of the two-block response it belongs
 * to, because that mapping lives in `src/mcp/tools/contacts.ts` and a reader
 * arriving here should not have to open that file to know which values a
 * stranger wrote.
 */
export interface ContactSummary {
  /** The opaque token that names this card. Minted here, so trusted. */
  id: string;
  /** The opaque token of the book it lives in. Minted here, so trusted. */
  addressBookId: string;
  /**
   * The name to show. **Stranger-authored, and possibly the empty string.**
   *
   * `displayNameFor`'s output: the formatted name when the card carries a
   * non-blank one, the structured name otherwise, and the empty string for a
   * card carrying neither. The empty case is a real record rather than a
   * failure — see `./vcard.ts` — and it sorts and pages like any other.
   */
  displayName: string;
  /** Every address on the card, with its labels. **Stranger-authored.** */
  emails: ContactEmail[];
}

/** One page of a contacts search. */
export interface ContactPage {
  contacts: ContactSummary[];
  /**
   * Whether more rows exist past this page.
   *
   * Two separately named fields rather than "a null cursor means the end", for
   * the reason `MessagePage` records: a model reading a false `hasMore` stops
   * without having to reason about what an absent cursor means.
   */
  hasMore: boolean;
  /** The token that continues this search, or null at the end. Minted here. */
  nextCursor: string | null;
  /**
   * Which route produced these rows (D-62).
   *
   * **Trusted.** It is this server's own statement about what it did, on
   * exactly the same footing as `hasMore` — not a claim anybody else made. It
   * is reported on every search rather than only when it is surprising,
   * because the two routes can see different sets and a reader with no way to
   * tell them apart reads a fallback's empty page as "you have no such
   * contact".
   */
  matchPath: MatchPath;
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
}

/**
 * One contact, in full (CONT-02).
 *
 * **Deliberately an EXTENSION of the search row rather than a parallel shape.**
 * Every field a row carries means the same thing here, and two independently
 * declared shapes would agree today and drift the first time either grew a
 * field — silently, because both would still serialise into a plausible
 * response. Extending makes the drift impossible.
 *
 * Everything added below is what a DETAIL adds, and every one of them is
 * stranger-authored surface a search row deliberately refuses to carry.
 */
export interface ContactDetail extends ContactSummary {
  /** True when discovery answered from cache. This server's own statement. */
  cacheHit: boolean;
  /** The card's own identifier, as whoever wrote the card set it. Untrusted. */
  uid: string | null;
  /** `FN` verbatim, including when present and empty. **Untrusted.** */
  formattedName: string | null;
  /** The structured name's five components. **Untrusted.** */
  name: ContactName | null;
  /** `ORG`'s components in order. **Untrusted.** */
  organisation: string[];
  /** The postal address's seven components. **Untrusted.** */
  address: ContactAddress | null;
  /**
   * The card's free-text note, verbatim. **Untrusted, and the highest-risk
   * field on this type.**
   *
   * A note is long, free-form and read by nobody until it is needed, which
   * makes it the classic carrier for instruction-shaped text on a contact
   * card. It appears on this call and on no other: `ContactSummary` has
   * nowhere to put one, which is what keeps a page of twenty-five rows from
   * carrying twenty-five of them.
   */
  note: string | null;
  /** Every telephone number, with its labels. **Untrusted.** */
  tels: ContactTel[];
}

/** What one search call asks for. */
export interface ContactSearchOptions {
  /** Matched against the display name and every email address. */
  term: string;
  /** Rows per page. Clamped rather than refused — see `clampPageSize`. */
  pageSize?: number;
  /** The `nextCursor` of a previous page, or absent for page one. */
  cursor?: string;
}

/** One address book collection, as this module carries it internally. */
interface AddressBook {
  url: string;
  displayName: string;
  reports: string[];
}

/** One parsed card with the URLs that address it, before an id is minted. */
interface PendingContact {
  key: ContactOrderKey;
  addressBookUrl: string;
  objectUrl: string;
  contact: ParsedContact;
}

/**
 * The report names one collection advertises, narrowed by hand.
 *
 * **`DAVCollection.reports` is typed `any` by the library, so the compiler is
 * not watching this boundary** — and `any` on one field widens what inference
 * can promise about anything reached through the value. Narrowing to non-empty
 * strings here is what stops an unexpected object shape reaching the route
 * pre-check, where a truthy non-string would compare unequal to every report
 * name and silently send every search down the fallback.
 */
function reportNamesOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names: string[] = [];
  for (const name of value as unknown[]) {
    if (typeof name === "string" && name.length > 0) names.push(name);
  }
  return names;
}

/**
 * Re-anchor a collection URL onto the SHARD host the home set resolved to.
 *
 * The library builds each address book's URL by resolving the response href
 * against the account's ROOT url — the unpartitioned entry point discovery
 * started from — rather than against the home url, which discovery resolved to
 * this account's own `pXX-` partition. (The literal host is deliberately not
 * written here; `./discovery.ts` is the only module permitted to name one, and
 * the scan enforces that on prose as readily as on code, which is what stops a
 * copied constant starting its life in a comment.)
 * When iCloud answers with a path rather than an absolute href, that produces a
 * collection URL on the wrong host: every later request against it addresses a
 * server that has to redirect, and `./transport.ts` forces manual redirects
 * precisely so a 3xx is observed rather than transparently followed with the
 * credential attached. The result would be a listing that works and a search
 * that does not.
 *
 * Re-anchoring on the home url is safe in both directions. An href the server
 * returned as absolute already names the shard, so taking its path and
 * resolving it against the home url is the identity; an href returned as a
 * path is repaired. Every address book lives under the home set by definition,
 * so there is no collection this could move to a host it does not belong on.
 *
 * `null` for a URL this module cannot address — a collection it cannot address
 * is one it must not pretend to have.
 */
function anchorToHome(rawUrl: unknown, homeUrl: string): string | null {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return null;
  try {
    return new URL(new URL(rawUrl, homeUrl).pathname, homeUrl).href;
  } catch {
    // Nothing is read from the caught value.
    return null;
  }
}

/**
 * Enumerate the account's address books, WITH their advertised report sets.
 *
 * **This uses the library helper where `./calendar.ts` deliberately does not,
 * and the divergence is a decision rather than an inconsistency.** The helper
 * costs `1 + N` requests — one property find over the home set, then one per
 * collection to read its supported report set. On the calendar side N is nine
 * on this account and the report set is a value no tool reads, so the calendar
 * module issues the property find directly and stops. Here N is one, and the
 * report set is the exact value the route pre-check needs: without it there is
 * no way to skip a query the server cannot serve, and the pre-check is what
 * makes a non-filtering book cost no failed request at all.
 *
 * The helper fans out internally over the collections it found. That fan-out
 * is serialised regardless by the request-scoped queue in `./transport.ts`,
 * which is the structural half of §3's guarantee; nothing in this module
 * writes a combinator, which is the detective half.
 *
 * The credential is NOT passed here. `./transport.ts` attaches it per call and
 * is the only place that may — building a header object here would mean this
 * module held a string carrying the app-specific password across an await, for
 * no benefit at all.
 */
async function fetchBooks(
  davFetch: DavFetch,
  resolved: ResolvedDavAccount,
): Promise<AddressBook[]> {
  const found = await fetchAddressBooks({
    account: davAccountFor("carddav", resolved),
    headers: {},
    fetch: davFetch,
  });

  const books: AddressBook[] = [];
  for (const one of found) {
    const url = anchorToHome(one.url, resolved.homeUrl);
    if (url === null) continue;
    books.push({
      url,
      displayName: typeof one.displayName === "string" ? one.displayName : "",
      reports: reportNamesOf(one.reports),
    });
  }

  // Ascending by URL, so two identical calls agree. Code units rather than a
  // collating comparison, for the reason `compareContactOrder` gives: a
  // locale-dependent order is one a second request may compute differently.
  books.sort((a, b) => (a.url === b.url ? 0 : a.url < b.url ? -1 : 1));
  return books;
}

/**
 * List the account's address books, with what each one can do.
 *
 * Wrapped in `withRediscovery` so a failure against a cached shard host takes
 * D-60's single-retry path rather than surfacing as a dead account.
 */
export async function listAddressBooks(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<AddressBookListing> {
  return withRediscovery(env, principal, davFetch, "carddav", async (resolved) => {
    const books = await fetchBooks(davFetch, resolved);

    return {
      addressBooks: books.map((one) => ({
        id: encodeAddressBookId({ collectionUrl: one.url }),
        displayName: one.displayName,
        reports: one.reports,
      })),
      cacheHit: resolved.cacheHit,
    };
  });
}

/**
 * The server-side filter document, in the library's compact-element form.
 *
 * A filter that matches when the formatted name, the STRUCTURED name, or an
 * email address contains the term. The three-way disjunction is the closest
 * expressible image of `matchesContact`, which tests the term against the
 * DISPLAY name — a value that is the formatted name when the card carries a
 * non-blank one and the structured name otherwise.
 *
 * **The structured-name filter is load-bearing rather than belt-and-braces.**
 * Apple's own forums document iCloud returning cards with an empty formatted
 * name and a populated structured one, and `./vcard.ts` records that finding as
 * the concrete argument for the local route existing at all. A filter naming
 * only the formatted name and the address cannot see those people — so a
 * server route built that way would return an empty page for a contact who is
 * demonstrably there, which is the exact failure `matchPath` exists to make
 * legible rather than a failure to design around.
 *
 * **Exact set-equality between the two routes is NOT achievable, and must not
 * be claimed.** The local rule matches a display name this server DERIVES by
 * joining the structured name's given and family components; the wire carries
 * that value only as `Family;Given;;;`, so a term spanning the join — a full
 * name typed the way a person reads it — matches locally and cannot match any
 * property filter. The routes agree on the RULE and on every term either side
 * can see in a single property; the residual divergence is asserted explicitly
 * in the tests rather than hidden behind a claim of equality.
 *
 * **The collation and the match type are set EXPLICITLY even though both are
 * the protocol's defaults.** A default that is correct today is a default that
 * changes silently, and these two values are also the written specification of
 * the local route — so they have to be legible in one place rather than
 * inferred from a specification's omission.
 *
 * **The term is carried as element TEXT, never concatenated into markup.** The
 * library escapes on serialisation, so a term containing angle brackets or
 * quotes becomes text rather than structure (T-03-44). It is additionally
 * length-bounded and refused when blank, before this function is reached.
 *
 * The exact element nesting below is marked `[ASSUMED]` in the phase research
 * and was never verified against a live iCloud response — and it cannot be
 * verified on this account, which does not advertise the report at all. A
 * filter this server built wrongly and a server that does not support the
 * report look identical from here: both end on the local route. The recorded
 * live observation of `matchPath` against `dav_diagnose`'s advertised report
 * list is what tells them apart.
 */
export function contactFilter(term: string): Record<string, unknown> {
  const textMatch = {
    _attributes: {
      collation: "i;unicode-casemap",
      "match-type": "contains",
    },
    _text: term,
  };

  return {
    _attributes: { test: "anyof" },
    "prop-filter": [
      { _attributes: { name: "FN" }, "text-match": textMatch },
      { _attributes: { name: "N" }, "text-match": textMatch },
      { _attributes: { name: "EMAIL" }, "text-match": textMatch },
    ],
  };
}

/**
 * Fold one side of a comparison for matching.
 *
 * `toLowerCase` and NOT the locale-aware form, and the difference is a real bug
 * rather than a style preference. The locale-aware fold gives a different
 * answer under a Turkish locale — a dotted capital I folds to a dotless one —
 * so a search for "Ibrahim" would stop matching "ibrahim" on a host whose
 * ambient locale happened to differ. The vitest pool inherits the developer's
 * locale while production runs its own, which is the same silent host-dependent
 * divergence `displayNameKeyOf` in `./ids.ts` rejects the locale-aware form
 * for, the same one `./calendar.ts` rejects it for, and the same class the
 * `ical-jsdate` scan rule exists to prevent on the time side. This module
 * follows that precedent rather than starting a second one.
 */
function fold(value: string): string {
  return value.toLowerCase();
}

/**
 * Whether one contact carries a term (CONT-01).
 *
 * **The one match rule.** The local route runs it and the server route is
 * documented as intending it, and a test asserts the two return the same set
 * for the same term against the same cards. That agreement is the whole reason
 * `matchPath` is worth reporting: telling a reader which route ran only helps
 * if the routes were supposed to agree.
 *
 * Substring rather than prefix, across the display name and the full email
 * address. The display name is already the structured-name fallback when the
 * formatted name is empty, which is what makes a card iCloud returned blank
 * findable here — and unfindable on a server-side match against the formatted
 * name. The full address is tested rather than its parts, so the local part and
 * the domain are both reachable as substrings of one value without this
 * function having to split anything.
 *
 * The note, the organisation and the postal address are deliberately NOT
 * searched. CONT-01 asks for name and address lookup; searching a free-text
 * note would make a search for a common word return half the address book, and
 * would put the highest-volume stranger-authored field on the card into the
 * predicate that decides which rows a caller sees.
 *
 * Exported so the semantics stated on the tool's parameter and the semantics
 * that ship are the same code rather than two descriptions of it.
 */
export function matchesContact(contact: ParsedContact, term: string): boolean {
  const needle = fold(term);

  if (fold(displayNameFor(contact)).includes(needle)) return true;

  for (const email of contact.emails) {
    if (email.value !== null && fold(email.value).includes(needle)) return true;
  }
  return false;
}

/**
 * Bring a term inside the contract, or refuse it.
 *
 * The length is checked against the RAW value before the trim, because the
 * trim is work and the refusal is meant to be the cheapest thing that happens.
 *
 * `DavNotFoundError` rather than a fifth error category: the four-value
 * vocabulary is closed, and a term this server declines to search on is the
 * same class of answer as an identifier it declines to resolve.
 * `rediscoverable` stays at its default of false — re-resolving the account's
 * home URLs cannot make a blank term searchable.
 */
function normaliseTerm(term: string): string {
  if (typeof term !== "string") throw new DavNotFoundError();
  if (term.length > CONTACT_TERM_MAX_LENGTH) throw new DavNotFoundError();

  const trimmed = term.trim();
  // A term of spaces is not "search for everything" — it is a caller who asked
  // for something this server cannot read, and matching every card would read
  // as an answer rather than as the mistake it is.
  if (trimmed.length === 0) throw new DavNotFoundError();
  return trimmed;
}

/**
 * Turn one multi-status into the cards it carries.
 *
 * A response with no body is skipped rather than repaired: there is nothing to
 * read, and a partial contact is worse than an absent one (T-03-16).
 */
function cardsFrom(
  responses: DAVResponse[],
  bookUrl: string,
): Array<{ url: string; body: string }> {
  const cards: Array<{ url: string; body: string }> = [];

  for (const response of responses) {
    const href = response.href;
    if (typeof href !== "string" || href.length === 0) continue;

    let url: string;
    try {
      url = new URL(href, bookUrl).href;
    } catch {
      // Nothing is read from the caught value.
      continue;
    }
    // The collection itself comes back in a depth-one answer and is not a card.
    if (url === bookUrl) continue;

    const body = addressDataOf(response);
    if (body === null) continue;
    cards.push({ url, body });
  }

  return cards;
}

/**
 * One response's address data, however the XML layer read the element.
 *
 * The library types this as `any` and hands back either the CDATA wrapper or
 * the bare value depending on how the body was written.
 */
function addressDataOf(response: DAVResponse): string | null {
  const raw = response.props?.addressData;
  const data =
    raw !== null && typeof raw === "object"
      ? (raw as { _cdata?: unknown })._cdata
      : raw;
  return typeof data === "string" && data.length > 0 ? data : null;
}

/**
 * Every object URL a depth-one property find over one address book reports.
 *
 * The collection's own href is filtered out — a real server includes it — and
 * every remaining href is resolved against the collection so a server that
 * answers with a path is handled on exactly the shape iCloud actually sends.
 */
function objectUrlsFrom(responses: DAVResponse[], bookUrl: string): string[] {
  const urls: string[] = [];

  for (const response of responses) {
    const href = response.href;
    if (typeof href !== "string" || href.length === 0) continue;

    let url: string;
    try {
      url = new URL(href, bookUrl).href;
    } catch {
      // Nothing is read from the caught value.
      continue;
    }
    if (url === bookUrl) continue;
    urls.push(url);
  }

  return urls;
}

/**
 * The server route: ONE request, filtered by iCloud (D-62).
 *
 * Taken only where the collection advertises the query report, which turns the
 * route choice from an error-recovery branch into a pre-flight check — a book
 * that does not advertise it costs no failed request at all.
 */
async function serverRoute(
  book: AddressBook,
  term: string,
  davFetch: DavFetch,
): Promise<Array<{ url: string; body: string }>> {
  const responses = await addressBookQuery({
    url: book.url,
    props: { "d:getetag": {}, "card:address-data": {} },
    filters: contactFilter(term),
    depth: "1",
    // Never a credential from here. `./transport.ts` attaches it per call and
    // is the only place that may.
    headers: {},
    fetch: davFetch,
  });

  return cardsFrom(responses, book.url);
}

/**
 * The local route: enumerate the collection, fetch the cards, filter here.
 *
 * ## Two requests, and why not the library's one-call helper
 *
 * The library ships a "fetch every card in this address book" helper, and it
 * is NOT used — because it issues an `addressbook-query` internally to
 * enumerate the hrefs before it multi-gets their data. On this account that is
 * the very report whose absence sent the search down this route in the first
 * place, so the fallback would depend on the thing it exists to survive
 * without. This does the enumeration with a depth-one property find, which
 * every DAV server must answer, and then reads the bodies with the multi-get
 * report — which this account does advertise.
 *
 * ## What it costs, stated rather than discovered
 *
 * Two serial round trips per address book, and the second one carries EVERY
 * card in the book. On the measured account that is one address book, which is
 * what keeps this tractable; the card count inside it is unknown and
 * deliberately unmeasured. This is the honest cost of a search on a server
 * that will not filter, and the pre-check is what stops it being paid on a
 * server that would.
 */
async function localRoute(
  book: AddressBook,
  davFetch: DavFetch,
): Promise<Array<{ url: string; body: string }>> {
  const listed = await propfind({
    url: book.url,
    props: { "d:getetag": {}, "d:resourcetype": {} },
    depth: "1",
    headers: {},
    fetch: davFetch,
  });

  const objectUrls = objectUrlsFrom(listed, book.url);
  // No cards at all. Answered without a second request rather than with an
  // empty multi-get, which some servers refuse outright.
  if (objectUrls.length === 0) return [];

  const responses = await addressBookMultiGet({
    url: book.url,
    props: { "d:getetag": {}, "card:address-data": {} },
    // The path only, matching the form the library's own object fetch sends.
    objectUrls: objectUrls.map((one) => new URL(one).pathname),
    depth: "1",
    headers: {},
    fetch: davFetch,
  });

  return cardsFrom(responses, book.url);
}

/** Fold one book's route into the run's reported path. */
function joinPath(
  running: MatchPath | null,
  used: "server" | "local",
): MatchPath {
  if (running === null) return used;
  return running === used ? running : "mixed";
}

/** One card, as the row a caller reads. */
function summaryFor(pending: PendingContact): ContactSummary {
  return {
    id: encodeContactId({
      addressBookUrl: pending.addressBookUrl,
      objectUrl: pending.objectUrl,
    }),
    addressBookId: encodeAddressBookId({
      collectionUrl: pending.addressBookUrl,
    }),
    displayName: displayNameFor(pending.contact),
    emails: pending.contact.emails,
  };
}

/**
 * One card, as the full detail a caller reads (CONT-02).
 *
 * Built ON TOP of the search row rather than beside it, so the two cannot
 * disagree about a field they share.
 */
function detailFor(
  pending: PendingContact,
  cacheHit: boolean,
): ContactDetail {
  const { contact } = pending;

  return {
    ...summaryFor(pending),
    cacheHit,
    uid: contact.uid,
    formattedName: contact.formattedName,
    name: contact.name,
    organisation: contact.organisation,
    address: contact.address,
    note: contact.note,
    tels: contact.tels,
  };
}

/**
 * Search the account's contacts by name or email address, paged (CONT-01).
 *
 * ## The route choice, in full (D-62)
 *
 * For each address book, serially:
 *
 *   1. If it advertises the query report, take the SERVER route. A book that
 *      does not advertise it costs no failed request at all — the pre-check is
 *      what makes that true, and it is the difference between a design and an
 *      error-recovery branch dressed up as one.
 *   2. The error-driven fallback is kept as well, because the specification
 *      lets a server advertise the report and still refuse the FILTER inside
 *      it. A `DavNotFoundError` from the query — which is where the transport
 *      maps a capability refusal, and also where it maps a stale host — takes
 *      the local route.
 *   3. An authentication or throttling failure does NOT fall back. Those
 *      surface immediately, for the reasons D-60 already fixed: a second
 *      authentication attempt per tool call is the cadence that locks an
 *      account out of the user's own devices, and a throttled server is the
 *      last thing to send another request to.
 *
 * The honest cost of (2) is worth stating: a genuinely missing address book
 * pays the query AND the enumeration before it fails, because the fallback
 * cannot tell "this report is unavailable" from "this collection is gone" — the
 * transport maps both onto the same class. The local route's own error is what
 * surfaces, so the failure the caller reads is the one that had the last word.
 *
 * ## The order, and why it is imported rather than written here
 *
 * Rows are sorted by `compareContactOrder` and resumed by
 * `isAfterContactsCursor`, both from `./ids.ts`. Neither is reimplemented, and
 * that is the whole defence: the resume predicate over there is expressed
 * THROUGH the comparator, so the order a page is cut on and the order a cursor
 * resumes at cannot disagree by even one component.
 *
 * ## What the cursor pins, and the one thing it cannot
 *
 * It pins the NORMALISED term and compares it on resume, so a position recorded
 * against one search cannot be resumed against another. It cannot pin WHICH
 * ROUTE served the page — that fact lives here rather than in the token, and
 * the two routes can in principle see different sets, so a cursor minted from a
 * server page and resumed against a local one is not detectable. On the
 * measured account there is only one route and the exposure is theoretical, but
 * a future account, or a change on Apple's side, could advertise the report.
 * The search tool's own cursor parameter says so, which is the honest home for
 * a limit this server cannot compute.
 */
export async function searchContacts(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: ContactSearchOptions,
): Promise<ContactPage> {
  // Everything below runs BEFORE `withRediscovery`, and therefore before the
  // KV read discovery performs and before any outbound request. A blank term,
  // an over-long term and a cursor minted for a different search are all
  // refused without spending one unit of the connection budget.
  const term = normaliseTerm(options.term);

  let cursor: ContactsCursor | null = null;
  if (options.cursor !== undefined) {
    cursor = decodeContactsCursor(options.cursor, term);
  }

  const pageSize = clampPageSize(options.pageSize);

  return withRediscovery(env, principal, davFetch, "carddav", async (resolved) => {
    const books = await fetchBooks(davFetch, resolved);

    const pending: PendingContact[] = [];
    // Null until a book has actually been searched. With no address book at
    // all nothing was filtered anywhere, and `local` is the conservative claim
    // — reporting a server filter that never ran would be the one thing this
    // field exists to prevent.
    let path: MatchPath | null = null;

    // SERIAL. One address book at a time, awaited before the next begins. See
    // the module header: a combinator here is banned structurally, detectively,
    // and for a reason that costs the user their own mail rather than costing
    // this server a retry.
    for (const book of books) {
      let cards: Array<{ url: string; body: string }>;
      let used: "server" | "local";

      if (book.reports.includes(ADDRESS_BOOK_QUERY_REPORT)) {
        try {
          cards = await serverRoute(book, term, davFetch);
          used = "server";
        } catch (err) {
          // ONLY this class falls back. An auth or throttle failure propagates
          // untouched, and neither is named here — so neither can join the
          // fallback by accident, only by an edit that shows up in a diff.
          if (!(err instanceof DavNotFoundError)) throw err;
          cards = await localRoute(book, davFetch);
          used = "local";
        }
      } else {
        cards = await localRoute(book, davFetch);
        used = "local";
      }

      path = joinPath(path, used);

      for (const card of cards) {
        const contact = parseVCard(card.body);
        // Applied on BOTH routes' output only where it is the route's own job.
        // The server route returns what the server matched; re-filtering it
        // here would silently narrow a set this server did not compute and
        // would make the agreement assertion compare a function with itself.
        if (used === "local" && !matchesContact(contact, term)) continue;

        pending.push({
          key: {
            displayNameKey: displayNameKeyOf(displayNameFor(contact)),
            objectUrl: card.url,
          },
          addressBookUrl: book.url,
          objectUrl: card.url,
          contact,
        });
      }
    }

    pending.sort((a, b) => compareContactOrder(a.key, b.key));

    const after =
      cursor === null
        ? pending
        : pending.filter((one) => isAfterContactsCursor(one.key, cursor));

    // One more row than the page holds. The PRESENCE of that extra row is
    // has-more — there is no count to be wrong about — and it is dropped
    // before the cursor is minted, so the next page begins at the row after the
    // last one actually returned rather than after the one that only proved
    // there was more.
    const window = after.slice(0, pageSize + 1);
    const hasMore = window.length > pageSize;
    const rows = hasMore ? window.slice(0, pageSize) : window;
    const last = rows[rows.length - 1];

    return {
      contacts: rows.map(summaryFor),
      hasMore,
      nextCursor:
        hasMore && last !== undefined
          ? encodeContactsCursor({
              term,
              lastDisplayNameKey: last.key.displayNameKey,
              lastObjectUrl: last.key.objectUrl,
            })
          : null,
      matchPath: path ?? "local",
      cacheHit: resolved.cacheHit,
    };
  });
}

/**
 * Fetch one contact in full, by the opaque id a search returned (CONT-02).
 *
 * ## Cost
 *
 * ONE request. The address book URL and the object URL both live inside the
 * token, so addressing the card costs no lookup and no collection enumeration —
 * the argument that chose this identifier shape in the first place. Compare
 * `searchContacts`, which pays the book enumeration plus two round trips per
 * book on the local route.
 *
 * ## Why the whole body is inside `withRediscovery`
 *
 * Every operation in this module resolves through that wrapper. D-60's
 * single-retry policy is a property of the CARDDAV SERVICE LAYER rather than of
 * whichever operation happened to be written first: an operation added outside
 * the wrapper is a path on which a moved shard host surfaces to the user as
 * not-found instead of being re-resolved.
 *
 * The same honest limitation `getEvent` records applies here. The reference
 * carries ABSOLUTE URLs minted when the search ran, so a re-discovery does not
 * repoint this attempt at a new host. What it buys is real and identical on
 * both paths: the stale entry is deleted, so the next call resolves live.
 */
export async function getContact(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
): Promise<ContactDetail> {
  return withRediscovery(env, principal, davFetch, "carddav", async (resolved) => {
    // BEFORE the multi-get, because everything after this line reaches the
    // network and `./transport.ts` attaches the credential to whatever URL it is
    // handed. Both URLs, because each independently names what the server is
    // asked for. `resolved.homeUrl` is the CARDDAV home set — a different value
    // from the CalDAV one — because `withRediscovery` was already called with
    // `"carddav"` here (03-REVIEW.md CR-01).
    assertUnderHome(ref.addressBookUrl, resolved.homeUrl);
    assertUnderHome(ref.objectUrl, resolved.homeUrl);

    const responses = await addressBookMultiGet({
      url: ref.addressBookUrl,
      props: { "d:getetag": {}, "card:address-data": {} },
      // The path only, matching the form the library's own object fetch sends.
      objectUrls: [new URL(ref.objectUrl).pathname],
      depth: "1",
      // Never a credential from here.
      headers: {},
      fetch: davFetch,
    });

    const card = cardsFrom(responses, ref.addressBookUrl).find(
      (one) => one.url === ref.objectUrl,
    );

    // A card the server did not return, or returned empty. Not rediscoverable:
    // the host answered, and it answered about this resource.
    if (card === undefined) throw new DavNotFoundError(false);

    return detailFor(
      {
        key: { displayNameKey: "", objectUrl: ref.objectUrl },
        addressBookUrl: ref.addressBookUrl,
        objectUrl: ref.objectUrl,
        contact: parseVCard(card.body),
      },
      resolved.cacheHit,
    );
  });
}
