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

import {
  addressBookMultiGet,
  addressBookQuery,
  createVCard,
  fetchAddressBooks,
  propfind,
  updateVCard,
} from "tsdav";
import type { DAVResponse } from "tsdav";
import type { Env } from "../env";
// ONE definition of the entity-tag refusal, imported rather than written a
// second time. Its own docstring one module over carries the argument this
// module's conditional write inherits verbatim -- the library's header builder
// drops any entry whose value is falsy, so a falsy entity tag produces an
// UNCONDITIONAL write with a 200 and no warning. A second copy here is a second
// place that argument could be weakened without the first one changing.
import { assertEtag } from "./calendar";
import { assertUnderHome, davAccountFor, withRediscovery } from "./discovery";
import type { ResolvedDavAccount } from "./discovery";
import { DavNotFoundError } from "./errors";
import {
  clampPageSize,
  compareContactOrder,
  decodeAddressBookId,
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
 * The two properties a duplicate scan may probe, as the PROTOCOL spells them.
 *
 * Not the library's camel-cased reading — these go INTO a filter document rather
 * than being read out of a response, so they are RFC 6350 property names and the
 * spelling is the specification's. Named here rather than at the call site
 * because a typo in either would produce a filter a server answers with an empty
 * set, which is indistinguishable from "no duplicate exists".
 */
const EMAIL_PROPERTY = "EMAIL";
const TEL_PROPERTY = "TEL";

/**
 * How many candidates a preview may name.
 *
 * Three, decided in the phase context: a longer list is one the user skims
 * rather than reads. That is a statement about whether the safeguard WORKS and
 * not about response size — a safeguard nobody reads is not a safeguard.
 */
const DUPLICATE_CANDIDATE_MAX = 3;

/**
 * The ranking order of the signals, strongest first.
 *
 * Exact address, then exact number, then name similarity — the phase context's
 * locked order, expressed as a table so the sort reads it rather than
 * re-deriving it from a chain of comparisons. A signal added to
 * `DuplicateSignal` without a rank here fails to compile, which is the point of
 * the `Record` rather than a lookup with a default.
 */
const DUPLICATE_SIGNAL_RANK: Record<DuplicateSignal, number> = {
  email: 0,
  phone: 1,
  name: 2,
};

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

/**
 * WHICH signal made a card a duplicate candidate, as a CLOSED vocabulary.
 *
 * Three values this server chooses from after matching a fixed rule, on
 * `MatchPath`'s own footing exactly: it admits no free text, nothing a stranger
 * wrote can widen it, and a value outside it can only arrive by editing this
 * line. That is what lets the label ride in the TRUSTED half of a preview while
 * every display name and address beside it rides inside the fence.
 *
 * The order of the union is also the RANKING order, strongest first, and
 * `DUPLICATE_SIGNAL_RANK` is the machine-readable statement of the same thing.
 * `"name"` is last because CONW-05 calls name similarity a weak signal.
 */
export type DuplicateSignal = "email" | "phone" | "name";

/**
 * One card that already carries something a write is about to supply (CONW-05).
 *
 * **An EXTENSION of the search row rather than a parallel shape**, for
 * `ContactDetail`'s own recorded reason: two independently declared row shapes
 * agree today and drift the first time either grows a field, silently, because
 * both still serialise into a plausible response. Extending also means the
 * fence placement of every inherited field is already audited — a candidate's
 * `displayName` and `emails` are stranger-authored here for exactly the reason
 * they are stranger-authored on a search row.
 *
 * `signal` is the one field a candidate adds, and it is the one field on this
 * type this server wrote.
 */
export interface DuplicateCandidate extends ContactSummary {
  /** Which rule matched this card. The STRONGEST one it matched. */
  signal: DuplicateSignal;
}

/**
 * What one duplicate scan probes with, and the cost it is allowed to spend.
 *
 * **`email` and `tel` are the only two fields that can cause a request, and a
 * probe with both null causes none at all.** That is the phase's locked
 * decision — "a create carrying neither spends nothing" — and it is enforced by
 * `findDuplicateCandidates` refusing before it enters discovery, so the KV read
 * is not spent either.
 *
 * `displayName` is different in kind and the difference is the whole of CONW-05's
 * weak-signal rule: it RANKS and labels candidates the two probes already
 * returned, and it never becomes a query. A query on a name would be the
 * account-wide sweep this project has twice declined, so the value is carried
 * here for comparison only and no code path reads it before a probe has run.
 */
export interface DuplicateProbe {
  /** One address to look for, or null to look for none. */
  email: string | null;
  /** One telephone number to look for, or null to look for none. */
  tel: string | null;
  /**
   * The name of the card being written, for RANKING only. Never queried.
   *
   * The empty string is a legitimate value: a card with neither a formatted nor
   * a structured name is a real record, and `displayNameFor` returns `""` for
   * one. It shares no tokens with anything, so it ranks nothing.
   */
  displayName: string;
  /**
   * The object URL a candidate must NOT be, or null when there is none.
   *
   * Null on a create: there is no card yet. An update passes the card it is
   * updating, because offering a card as its own duplicate is not an answer.
   */
  excludeObjectUrl: string | null;
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
 * The server-side filter document for ONE named property (CONW-05).
 *
 * `contactFilter`'s sibling, and deliberately a narrower one: that function
 * builds a three-way disjunction because a search asks one question of three
 * properties, while a duplicate scan asks a different question per property and
 * must be able to count what each one cost. One property per call is what makes
 * "at most two queries, and only for the fields the caller supplied" a property
 * of the call sites rather than of a comment.
 *
 * **`searchContacts` cannot serve this, and that is why the sibling exists
 * rather than a second call to the search.** `contactFilter` names `FN`, `N` and
 * `EMAIL` and no telephone property; `matchesContact` tests the display name and
 * the addresses only; and `ContactSummary` carries no numbers at all. A scan
 * built on the search with a number as the term would return an empty page every
 * time and look like a working feature. Widening those two is NOT the repair:
 * they are held in documented agreement with each other by tests that every
 * existing read caller relies on, and a fourth property on one side changes
 * shipped search behaviour for a write-path reason.
 *
 * **The collation and the match type are set EXPLICITLY even though both are the
 * protocol's defaults**, for `contactFilter`'s own recorded reason: a default
 * that is correct today is a default that changes silently.
 *
 * **`contains` and not `equals`, and the server filter is therefore deliberately
 * a SUPERSET of the answer.** The equality rule this scan actually applies lives
 * in `emailMatchesCard` and `telMatchesCard` and is applied to the cards BOTH
 * routes return, so the two routes run one rule rather than two that agree until
 * somebody edits either. Asking the server for equality instead would make the
 * filter the rule on one route and the local comparison the rule on the other,
 * and a telephone number is exactly where those two answers part company: the
 * wire carries whatever spacing and punctuation somebody typed.
 *
 * **The term is carried as element TEXT, never concatenated into markup** — the
 * library escapes on serialisation, so a term containing angle brackets or
 * quotes becomes text rather than structure (T-16-18). This is `contactFilter`'s
 * recorded mitigation reused rather than re-derived.
 *
 * It issues no request, so it carries a WRITTEN disposition in the DAV write
 * manifest rather than the `"guarded"` string.
 */
export function duplicateFilter(
  propertyName: string,
  term: string,
): Record<string, unknown> {
  return {
    _attributes: { test: "anyof" },
    "prop-filter": [
      {
        _attributes: { name: propertyName },
        "text-match": {
          _attributes: {
            collation: "i;unicode-casemap",
            "match-type": "contains",
          },
          _text: term,
        },
      },
    ],
  };
}

/**
 * Whether a supplied address is ALREADY on a card.
 *
 * Whole-address equality after folding both sides, and NOT the substring rule
 * `matchesContact` uses. A substring rule is right for a person searching and
 * wrong for a duplicate check, where it would report every colleague at a shared
 * domain as a duplicate of every other.
 *
 * `fold` and not the locale-aware form: that function's own docstring carries
 * the argument, and it applies here unchanged.
 *
 * **No Unicode normalisation is applied to either side, and that is a decision
 * rather than an omission.** Normalising somebody's own address is a repair, and
 * this project refuses repairs on user-authored text as firmly as it refuses
 * them on stranger-authored text — `canonicalChange` in `../confirm.ts` states
 * the same rule for the same reason. The consequence is worth stating: two
 * addresses that differ only in how a composed character was encoded do not
 * match, so the candidate is missed rather than wrongly claimed. That is the
 * right direction for a signal that only ever surfaces and never acts.
 */
function emailMatchesCard(supplied: string, contact: ParsedContact): boolean {
  const needle = fold(supplied);
  if (needle.length === 0) return false;

  for (const email of contact.emails) {
    if (email.value !== null && fold(email.value) === needle) return true;
  }
  return false;
}

/** Every DIGIT of a value, in order, and nothing else. */
function digitsOf(value: string): string {
  let digits = "";
  for (const character of value) {
    if (character >= "0" && character <= "9") digits += character;
  }
  return digits;
}

/**
 * Whether a supplied telephone number is ALREADY on a card.
 *
 * Equality after removing every character that is not a digit, so the spacing,
 * the brackets and the dashes somebody typed do not decide the answer.
 *
 * **No country-code inference and no suffix matching, and the consequence is
 * stated here rather than left to be discovered: a number stored WITH a country
 * code will not match one supplied without it.** That is deliberate. Suffix
 * matching would make a seven-digit number match a different person's number in
 * another country, and inferring a country code means guessing which country the
 * user is in from a value they did not supply. The cost of this rule is a MISSED
 * candidate rather than a WRONG one, which is the only direction a weak signal
 * that surfaces on a preview may fail in.
 *
 * A probe or a card whose value carries no digit at all matches nothing. Without
 * that floor, a card holding `TEL:-` and a probe of `()` would both reduce to the
 * empty string and every card in the book would match every probe.
 */
function telMatchesCard(supplied: string, contact: ParsedContact): boolean {
  const needle = digitsOf(supplied);
  if (needle.length === 0) return false;

  for (const tel of contact.tels) {
    if (tel.value !== null && digitsOf(tel.value) === needle) return true;
  }
  return false;
}

/**
 * The whitespace-separated tokens of a name, folded, two characters and longer.
 *
 * The length floor is what stops an initial doing the work of a name: `J` shared
 * between "J Smith" and "J Okonkwo" is not evidence of anything, and a rule
 * without the floor would rank every card sharing an initial.
 */
function nameTokensOf(value: string): Set<string> {
  const tokens = new Set<string>();
  for (const token of fold(value).split(/\s+/)) {
    if (token.length >= 2) tokens.add(token);
  }
  return tokens;
}

/**
 * How many name tokens two display names share.
 *
 * **This RANKS and it never queries**, which is CONW-05's weak-signal rule and
 * the reason the whole function is a pure comparison over values the caller
 * already holds. It runs over candidates the two probes returned; a query on a
 * name would be the account-wide sweep this project has twice declined.
 *
 * Zero shared tokens is not a name match. The count is the ranking key WITHIN
 * the name group, descending, so the closest name reads first out of a list a
 * user skims.
 *
 * Which function computes this is named as Claude's discretion in the phase
 * context, so it can be changed later without moving a stored value or a signed
 * token. Shared-token counting is the cheapest rule that is symmetric, needs no
 * tuning constant, and cannot claim a similarity between two names with nothing
 * in common.
 */
function sharedNameTokens(left: string, right: string): number {
  const first = nameTokensOf(left);
  let shared = 0;
  for (const token of nameTokensOf(right)) {
    if (first.has(token)) shared += 1;
  }
  return shared;
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
 *
 * **The row carries the entity tag as well, and keeping it costs no request.**
 * Every multi-status this function is handed already ASKED for it — every call
 * site's `props` names `d:getetag` beside `card:address-data` — so the value was
 * always arriving and was always being dropped on the floor. The widening is
 * additive: `searchContacts`, `getContact` and the duplicate scan each read the
 * two fields they already read and ignore the third, which is why the shipped
 * contacts suite staying green is the proof rather than a reading of this diff.
 *
 * It is `null` for a response that carried no entity tag. A card this server
 * cannot name a version of is still a card it can READ, so the refusal belongs
 * at the one caller that is about to write (`getContactWithEtag`) rather than
 * here, where it would turn a readable card into an unreadable one.
 */
function cardsFrom(
  responses: DAVResponse[],
  bookUrl: string,
): Array<{ url: string; body: string; etag: string | null }> {
  const cards: Array<{ url: string; body: string; etag: string | null }> = [];

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
    cards.push({ url, body, etag: etagOf(response) });
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
 * One response's entity tag, however the XML layer read the element.
 *
 * `addressDataOf`'s double read exactly, and for the same reason: the library
 * types the prop loosely and hands back either the CDATA wrapper or the bare
 * value depending on how the body was written. `etagFor` in `./calendar.ts` is
 * the same read on the other tree; it is not shared because that one additionally
 * resolves an href and compares it, which is work `cardsFrom` has already done by
 * the time this is called.
 *
 * **Returned BYTE-EXACT, quotes and weak prefix included.** An entity tag is an
 * opaque quoted string. Stripping the quotes to re-add them later is a
 * normalisation that eventually meets a `W/"..."` and gets it wrong — and the
 * value's whole job is to travel back out unaltered on a conditional write, so a
 * normalisation here is a conditional write asking about a version the server
 * never named.
 */
function etagOf(response: DAVResponse): string | null {
  const raw = response.props?.getetag;
  const value =
    raw !== null && typeof raw === "object"
      ? (raw as { _cdata?: unknown })._cdata
      : raw;
  return typeof value === "string" && value.length > 0 ? value : null;
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

/** One card as it arrived: the parsed view, the raw bytes, and the version. */
interface ReadContact {
  detail: ContactDetail;
  /** The card's own text, byte-for-byte as the server sent it. */
  body: string;
  /** Byte-exact, quotes included. `null` when the server named no version. */
  etag: string | null;
}

/**
 * Fetch one contact in full, by the opaque id a search returned (CONT-02).
 *
 * ## Two callers, one body
 *
 * `readEvent` one module over, for the same reason and reached the same way: the
 * write path needs the entity tag from the SAME multi-status as the card, so the
 * plain read and the read-with-version share one body rather than issuing one
 * request each. `test/dav-home-containment.test.ts` keys its containment audit on
 * the ENCLOSING function's name, so this function being the enclosing one — and
 * not `getContact` any more — is a diff a reader has to approve rather than a
 * silent rename. The request did not move and did not lose its guard; it acquired
 * a second caller.
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
 * Re-discovery is left at its DEFAULT here, unlike the write path's containment
 * helper which pins it off: a retried read returns an answer, while a retried
 * write is a second write.
 *
 * The same honest limitation `getEvent` records applies here. The reference
 * carries ABSOLUTE URLs minted when the search ran, so a re-discovery does not
 * repoint this attempt at a new host. What it buys is real and identical on
 * both paths: the stale entry is deleted, so the next call resolves live.
 */
async function readContact(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
): Promise<ReadContact> {
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

    return {
      detail: detailFor(
        {
          key: { displayNameKey: "", objectUrl: ref.objectUrl },
          addressBookUrl: ref.addressBookUrl,
          objectUrl: ref.objectUrl,
          contact: parseVCard(card.body),
        },
        resolved.cacheHit,
      ),
      body: card.body,
      etag: card.etag,
    };
  });
}

/**
 * Fetch one contact in full (CONT-02). `readContact`'s parsed half, and nothing
 * else: the raw bytes and the version stamp are the write path's business, and a
 * read tool returning either would put them in front of eight call sites that
 * have no use for them.
 */
export async function getContact(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
): Promise<ContactDetail> {
  const read = await readContact(env, principal, davFetch, ref);
  return read.detail;
}

/** One card, the bytes it arrived as, and the version a write must bind to. */
export interface ContactWithEtag {
  /** The parsed view, exactly what `getContact` answers with. */
  detail: ContactDetail;
  /**
   * The card's own text, byte-for-byte as the server sent it.
   *
   * Carried rather than rebuilt from `detail`, and that is CONTEXT's decision
   * rather than a convenience: a patch needs BYTES to clone, and `ParsedContact`
   * is deliberately not growing to hold them — widening it would make eight
   * existing read call sites able to reshape the write path's fidelity guarantee.
   */
  body: string;
  /** Byte-exact, quotes included. Never absent: see `getContactWithEtag`. */
  etag: string;
}

/**
 * Read one card AND the version stamp a conditional write must bind to (CONW-02).
 *
 * ONE outbound request, and the count is the property rather than a side note.
 * It is `getContact`'s own multi-get — which already ASKED for the entity tag and
 * threw it away — reading both values out of the one multi-status.
 *
 * A card that came back with a body and no entity tag is REFUSED, through the
 * same `DavNotFoundError(false)` the absent-card path uses. That is not
 * fastidiousness: the caller of this function is about to sign that value into a
 * capability to write, and a missing one would travel as `undefined` into a
 * header builder that DROPS falsy entries — producing an unconditional write the
 * server answers 200 to. Refusing at the read is cheaper than discovering it at
 * the write, where the discovery is somebody's overwritten card.
 *
 * A plain `export function` declaration, for `planContactCreateTarget`'s stated
 * reason about the write manifest.
 */
export async function getContactWithEtag(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
): Promise<ContactWithEtag> {
  const read = await readContact(env, principal, davFetch, ref);
  assertEtag(read.etag);

  return { detail: read.detail, body: read.body, etag: read.etag };
}

// --------------------------------------------------- the write path's safeguard
//
// CONW-05. It writes nothing and it is read-shaped, but it exists only for the
// write path: it is the one moment at which a user can decide whether the card
// they are about to create should exist. It surfaces what it found and it acts on
// nothing — no merge, no redirect, no copied field, and no refusal. Refusing
// would make a legitimate second card for the same person impossible to create,
// and merging is the thing CONW-05 forbids by name.

/**
 * One filtered query over one address book, for one property (CONW-05).
 *
 * Extracted so the request count is countable by eye: this function issues
 * EXACTLY one request, so the number of requests the server route spends is the
 * number of times a call site reaches it.
 */
async function duplicateQuery(
  book: AddressBook,
  propertyName: string,
  term: string,
  davFetch: DavFetch,
): Promise<Array<{ url: string; body: string }>> {
  const responses = await addressBookQuery({
    url: book.url,
    props: { "d:getetag": {}, "card:address-data": {} },
    filters: duplicateFilter(propertyName, term),
    depth: "1",
    // Never a credential from here. `./transport.ts` attaches it per call and is
    // the only place that may.
    headers: {},
    fetch: davFetch,
  });

  return cardsFrom(responses, book.url);
}

/**
 * The probe route: at most TWO filtered queries, issued SERIALLY (CONW-05).
 *
 * One per supplied field and none for a field the caller did not supply, which is
 * the phase's locked cost decision expressed as control flow rather than as a
 * comment. The two awaits are sequential and MUST stay that way: a combinator
 * here is the exact shape `.claude/CLAUDE.md` §3 bans, and the reason is not this
 * server's latency — it is iCloud's own per-account connection ceiling, which is
 * lower than the platform's, undocumented, deliberately unmeasured, and which
 * does not fail politely when it is exhausted. It locks the user out of their own
 * mail in Mail.app on their own devices. `findDuplicateCandidates` is named in the
 * `dav-concurrent-request` alternation so a combinator around it fails the commit
 * rather than the review.
 *
 * A refusal propagates rather than falling back to the local route, unlike
 * `searchContacts`. The two are different situations: a search that cannot filter
 * still owes the caller their answer, while this scan is one leg of a preview, and
 * paying a failed query AND then a whole enumeration plus bulk read for an
 * advisory safeguard is spending the budget twice over. A failure here surfaces as
 * a failed preview, which is honest; swallowing it would report "no duplicates"
 * about a scan that never ran, which is the one answer this function must never
 * give.
 */
async function duplicateProbeRoute(
  book: AddressBook,
  probe: DuplicateProbe,
  davFetch: DavFetch,
): Promise<Array<{ url: string; body: string }>> {
  const cards: Array<{ url: string; body: string }> = [];

  if (probe.email !== null) {
    cards.push(
      ...(await duplicateQuery(book, EMAIL_PROPERTY, probe.email, davFetch)),
    );
  }
  // SERIAL: awaited after the one above, never beside it.
  if (probe.tel !== null) {
    cards.push(
      ...(await duplicateQuery(book, TEL_PROPERTY, probe.tel, davFetch)),
    );
  }

  return cards;
}

/** One candidate before the cap and the ordering are applied. */
interface ScoredCandidate {
  pending: PendingContact;
  signal: DuplicateSignal;
  /** Shared name tokens. Zero for an address or number match; it sorts last. */
  nameScore: number;
}

/**
 * The STRONGEST signal one card matched, or null for a card that matched none.
 *
 * Strongest wins in `DUPLICATE_SIGNAL_RANK`'s order, so a card carrying both the
 * address and the number is reported once, as an address match. Reporting it
 * twice would spend two of the three slots on one person.
 *
 * The same rule runs over the cards BOTH routes returned, which is what keeps the
 * routes answering one question. The server route's filter is a deliberate
 * superset — see `duplicateFilter` — so a card it returned may match no rule
 * here, and a card that matches nothing is not a candidate.
 */
function duplicateSignalFor(
  contact: ParsedContact,
  probe: DuplicateProbe,
): { signal: DuplicateSignal; nameScore: number } | null {
  if (probe.email !== null && emailMatchesCard(probe.email, contact)) {
    return { signal: "email", nameScore: 0 };
  }
  if (probe.tel !== null && telMatchesCard(probe.tel, contact)) {
    return { signal: "phone", nameScore: 0 };
  }

  const shared = sharedNameTokens(probe.displayName, displayNameFor(contact));
  if (shared > 0) return { signal: "name", nameScore: shared };

  return null;
}

/**
 * Which existing cards already carry something a write is about to supply
 * (CONW-05).
 *
 * ## What it costs, and the one case where it costs nothing at all
 *
 * A probe with NEITHER an address nor a number returns the empty list WITHOUT
 * entering `withRediscovery`, so it spends no KV read and no outbound request.
 * The phase's locked decision — "a create carrying neither spends nothing" — is
 * about the discovery read as well as about the queries, which is why the refusal
 * is lexically ahead of the wrapper rather than inside it.
 *
 * With something to probe with, per address book:
 *
 *   - **The book advertises the query report:** at most two filtered queries,
 *     one per supplied field, issued serially. See `duplicateProbeRoute`.
 *   - **It does not:** the local route ONCE — one enumeration and one bulk read —
 *     and BOTH probes matched against that single set of cards. One read serving
 *     two probes is strictly cheaper than two reads serving one each, and the
 *     local route already carries every card in the book, so asking twice buys
 *     nothing. **The obvious edit is to loop the whole route per probe. Do not:
 *     that doubles the most expensive route this module has for no new
 *     information.**
 *
 * Address books are walked SERIALLY, one awaited before the next begins, exactly
 * as `searchContacts` does and for the reason its own comment gives.
 *
 * ## It acts on nothing
 *
 * It returns rows. It merges nothing, copies nothing, redirects nothing and
 * refuses nothing, and the tool layer above it does the same — the candidate list
 * is deliberately outside the signed change, so it cannot alter the write or
 * cause a refusal (T-16-19). A create that found three candidates writes exactly
 * the card the user approved.
 *
 * ## Where the two routes agree, and where they do not
 *
 * They agree on the RULE: the same matchers classify the cards either route
 * returned. The residual divergence is the `"name"` signal, and it is asserted in
 * the tests rather than hidden behind a claim of equality — `contactFilter`'s
 * docstring makes the same statement about the search. The local route holds
 * every card in the book already, so a name-similar card with no matching address
 * or number is visible to it; the server route only sees what its two filters
 * returned. That divergence costs no extra request on either route, which is why
 * it is not the sweep CONW-05 forbids: no code path here queries a name.
 */
export async function findDuplicateCandidates(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  probe: DuplicateProbe,
): Promise<DuplicateCandidate[]> {
  // BEFORE `withRediscovery`, and therefore before the KV read discovery
  // performs and before any outbound request. See the docstring: this is the
  // locked "spends nothing" decision, and it is only true here.
  if (probe.email === null && probe.tel === null) return [];

  return withRediscovery(env, principal, davFetch, "carddav", async (resolved) => {
    const books = await fetchBooks(davFetch, resolved);

    const scored: ScoredCandidate[] = [];
    // The two queries can return the SAME card — a person whose card carries
    // both the address and the number is matched by each filter — and the local
    // route returns each card once. Keyed on the object URL so the answer does
    // not depend on which route ran.
    const seen = new Set<string>();

    // SERIAL. One address book at a time, awaited before the next begins.
    for (const book of books) {
      const cards = book.reports.includes(ADDRESS_BOOK_QUERY_REPORT)
        ? await duplicateProbeRoute(book, probe, davFetch)
        : await localRoute(book, davFetch);

      for (const card of cards) {
        // An update must not offer the card it is updating as its own duplicate.
        if (card.url === probe.excludeObjectUrl) continue;
        if (seen.has(card.url)) continue;
        seen.add(card.url);

        const contact = parseVCard(card.body);
        const matched = duplicateSignalFor(contact, probe);
        if (matched === null) continue;

        scored.push({
          pending: {
            key: {
              displayNameKey: displayNameKeyOf(displayNameFor(contact)),
              objectUrl: card.url,
            },
            addressBookUrl: book.url,
            objectUrl: card.url,
            contact,
          },
          signal: matched.signal,
          nameScore: matched.nameScore,
        });
      }
    }

    // Signal first, then the closest name inside the name group, then the object
    // URL. The last key is not decoration: without a total order two identical
    // calls could name different three of four equally-ranked candidates, and the
    // user would see a different answer each time they asked.
    scored.sort((a, b) => {
      const bySignal =
        DUPLICATE_SIGNAL_RANK[a.signal] - DUPLICATE_SIGNAL_RANK[b.signal];
      if (bySignal !== 0) return bySignal;
      if (a.nameScore !== b.nameScore) return b.nameScore - a.nameScore;
      if (a.pending.objectUrl === b.pending.objectUrl) return 0;
      return a.pending.objectUrl < b.pending.objectUrl ? -1 : 1;
    });

    return scored
      .slice(0, DUPLICATE_CANDIDATE_MAX)
      .map((one) => ({ ...summaryFor(one.pending), signal: one.signal }));
  });
}

// ---------------------------------------------------------------- the write half
//
// One entry point, and it is a create (CONW-01). Everything above this line
// reads; everything below it writes exactly one card per request, and the
// `dav-concurrent-request` scan rule names both new exports so a combinator
// around either fails the commit rather than the review.

/** The resource name a UID takes inside an address book, percent-encoded. */
function contactObjectNameFor(uid: string): string {
  return `${encodeURIComponent(uid)}.vcf`;
}

/**
 * Where a create WOULD write, decided before anything is sent (CONW-01).
 *
 * `planCreateTarget`'s twin one module over, and it inherits that function's
 * whole argument: the confirmation binds the resource the preview described, so
 * `ConfirmPayload.o` has to be an OBJECT url rather than a collection url, which
 * means the uid has to exist before the preview answers. The commit derives it
 * back out of the signed url rather than minting a second one.
 *
 * That buys the same second, independent replay defence for free. A commit
 * replayed after the KV reservation has propagated away still carries the
 * ORIGINAL object url, so its `PUT` meets `If-None-Match: *` against a resource
 * that now exists and is refused by the server.
 *
 * **It takes an OPAQUE address book id and never a url**, which is
 * `planCreateTarget`'s own stated reason and is the one line here worth reading
 * twice: a collection url taken straight from a caller is a request target, and
 * `./transport.ts` attaches the Apple ID and the app-specific password to
 * whatever url it is handed. The kind letter inside the token is what stops a
 * calendar id resolving here into a plausible-looking address book reference.
 *
 * **It reaches no network and asserts no containment**, and both are correct:
 * nothing is requested, so there is nothing to contain. `createContact` runs the
 * containment on both urls at the moment the write actually happens, which is
 * the only moment at which `resolved.homeUrl` exists.
 *
 * A plain `export function` declaration rather than a `const` arrow, and that is
 * not a style choice: `exportedFunctionNames` in
 * `scripts/forbidden-tokens.mjs` sees only `function` declarations, so an arrow
 * export in this module would be INVISIBLE to the DAV write manifest — an
 * unguarded export that looks exactly like a guarded one.
 */
export function planContactCreateTarget(addressBookId: string): ContactRef {
  const book = decodeAddressBookId(addressBookId);
  const uid = `${crypto.randomUUID()}@icloud-mcp`;

  return {
    addressBookUrl: book.collectionUrl,
    objectUrl: new URL(contactObjectNameFor(uid), book.collectionUrl).href,
  };
}

/**
 * The UID a card's own url names, or null when the url does not name one.
 *
 * `uidFromObjectUrl`'s twin one module over, and it exists here rather than in
 * the tool layer for one reason: the convention it reverses is
 * `contactObjectNameFor`'s, five lines up. A copy in the tool layer would be the
 * naming rule living in two modules, which is the drift `src/tokens.ts` names as
 * the failure in its own header.
 *
 * **The commit leg has one outbound request and it is the write, so it never
 * sees the resource's bytes.** The UID it must write therefore has to come from
 * the only thing it holds: the object url inside the signed confirmation.
 * Reading it back out rather than minting a second one is what makes "the card
 * that was previewed is the card that is created" true rather than merely
 * likely.
 *
 * The decode is what makes it work on a real account rather than only on a tidy
 * fixture: every uid this server mints carries an `@`, so the href naming it is
 * percent-encoded.
 *
 * It issues no request and asserts no containment, so it carries a written
 * disposition in the DAV write manifest rather than the `"guarded"` string.
 */
export function contactUidFromObjectUrl(objectUrl: string): string | null {
  let path: string;
  try {
    path = new URL(objectUrl).pathname;
  } catch {
    // Nothing is read from the caught value — the url may be attacker-chosen.
    return null;
  }

  const last = path.slice(path.lastIndexOf("/") + 1);
  if (!last.toLowerCase().endsWith(".vcf")) return null;

  try {
    return decodeURIComponent(last.slice(0, -".vcf".length));
  } catch {
    // A stray `%` is not a uid. Nothing is read from the caught value.
    return null;
  }
}

/**
 * What one contact create supplies, once the confirmation has been verified.
 *
 * The card BODY arrives already serialised, from `./vcard.ts`. This module owns
 * shape and cost and does not own meaning, which is the separation its header
 * states — so it never touches a vCard byte, here or anywhere else.
 */
export interface CreateContactInput {
  /** The target this create's own preview planned and signed. */
  ref: ContactRef;
  /** The card, serialised by `buildContactCard`. */
  vcfBody: string;
}

/** What a create answers with: the opaque ids the card is now addressable by. */
export interface CreatedContact {
  /** The opaque contact id, minted through the existing encoder. */
  id: string;
  /** The opaque address book id the card now lives in. */
  addressBookId: string;
  /** True when the write was accepted. */
  created: boolean;
}

/**
 * Assert both urls are under the resolved CardDAV home set, then write.
 *
 * `withContainedTarget`'s twin one module over, and a LOCAL helper rather than a
 * reuse of that one: it is typed on `EventRef` and resolves `"caldav"`. The
 * substitution is what matters here — **`resolved.homeUrl` is a DIFFERENT value
 * for CardDAV**, and reusing the calendar helper would assert a contact's urls
 * against the calendar home set, which is 03-REVIEW.md CR-01's bug exactly.
 *
 * The assert-then-delegate shape is held in one function so the two assertions
 * cannot drift apart from the write they protect, and both `assertUnderHome`
 * calls are lexically ahead of the delegation for the same reason
 * `test/dav-home-containment.test.ts` reads the calendar helper by name.
 *
 * Inside the callback rather than above it, because `resolved.homeUrl` does not
 * exist until discovery has run.
 *
 * **The final `false` is "no retry", and it is not a parameter.** No caller can
 * re-open the question. `withRediscovery` re-runs its operation once on a
 * rediscoverable failure when the account came from cache, and for a write that
 * means the request goes out TWICE: the second `PUT` meets `If-None-Match: *`
 * against the resource the first one created and is refused, so a create that
 * SUCCEEDED would be reported as a failure. The preview leg immediately before
 * resolved the same account successfully, so a genuinely-moved host is not the
 * likely cause of a failure here.
 */
async function withContainedContactTarget<T>(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
  write: (resolved: ResolvedDavAccount) => Promise<T>,
): Promise<T> {
  return withRediscovery(
    env,
    principal,
    davFetch,
    "carddav",
    async (resolved) => {
      assertUnderHome(ref.addressBookUrl, resolved.homeUrl);
      assertUnderHome(ref.objectUrl, resolved.homeUrl);
      return write(resolved);
    },
    false,
  );
}

/**
 * Write one new card into one address book (CONW-01).
 *
 * `createEvent`'s twin, and deliberately a narrower one. That function decodes an
 * id, checks a zone, builds a resource and mints a uid; this one does none of
 * those, because the gated path already did all of it at preview time and signed
 * the result. What arrives here is a target the confirmation named and a body
 * somebody approved, so the only work left is containment and the request.
 *
 * ONE outbound request, and no read before it: a create has nothing to read.
 * That is also why this is the only write path in the project where the write
 * count and the request count agree.
 *
 * Never a credential from here. `./transport.ts` attaches it per call and is the
 * only place that may. The library supplies the content type and the
 * `If-None-Match: *` that makes this write conditional — which is the create's
 * whole optimistic-concurrency story, `If-Match`'s mirror image: it asserts the
 * resource does NOT exist rather than that it is unchanged.
 *
 * A plain `export function` declaration, for `planContactCreateTarget`'s stated
 * reason about the write manifest.
 */
export async function createContact(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  input: CreateContactInput,
): Promise<CreatedContact> {
  const ref = input.ref;
  // Computed here rather than taken as an argument, so the name the library
  // resolves against the collection is byte-identical to the one the object url
  // inside the signed confirmation already carries.
  const filename = new URL(ref.objectUrl).pathname.split("/").pop() ?? "";

  return withContainedContactTarget(env, principal, davFetch, ref, async () => {
    await createVCard({
      addressBook: { url: ref.addressBookUrl },
      filename,
      vCardString: input.vcfBody,
      // Never a credential from here. See the docstring.
      headers: {},
      fetch: davFetch,
    });

    return {
      id: encodeContactId({
        addressBookUrl: ref.addressBookUrl,
        objectUrl: ref.objectUrl,
      }),
      addressBookId: encodeAddressBookId({ collectionUrl: ref.addressBookUrl }),
      created: true,
    };
  });
}

/** What an update answers with: the ids it wrote, and that it reached the account. */
export interface UpdatedContact {
  /** The opaque contact id, unchanged by the write — an update moves nothing. */
  id: string;
  /** The opaque address book id the card lives in, for join-by-identity. */
  addressBookId: string;
  /** True when the write was accepted. */
  applied: boolean;
}

/**
 * Overwrite one existing card, conditionally on the version it was read at
 * (CONW-02, CONW-06).
 *
 * `updateEvent`'s twin, down to the order of the first two lines, because the
 * order IS the safety property here.
 *
 * ONE outbound request. The read that produced `etag` was its own request on its
 * own leg; this one does not repeat it.
 *
 * **What happens when the card moved underneath.** The server answers 412, and
 * `./transport.ts` already maps that to `DavStaleResourceError`, which
 * `./errors.ts` already reports as `stale_resource`. That whole mechanism ships
 * and is consumed here rather than rebuilt — including the recorded decision that
 * 412 is NOT re-discovery eligible, because re-resolving the account's home URLs
 * cannot make a superseded version current, and falling through to the
 * unclassified floor would offer the model a retry of the one thing that can
 * never work.
 *
 * Never a credential from here. `./transport.ts` attaches it per call and is the
 * only place that may. The library supplies the content type and the conditional
 * header that makes this write conditional — asserting the resource is UNCHANGED,
 * which is `If-None-Match: *`'s mirror image on the create.
 *
 * A plain `export function` declaration, for `planContactCreateTarget`'s stated
 * reason about the write manifest.
 */
export async function updateContact(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  ref: ContactRef,
  vcfBody: string,
  etag: string | null | undefined,
): Promise<UpdatedContact> {
  // FIRST. See `assertEtag`'s own docstring — everything below this line can
  // reach the wire, and a falsy value reaching the library turns this write
  // unconditional with no error, no warning and a 200 from the server.
  assertEtag(etag);

  return withContainedContactTarget(env, principal, davFetch, ref, async () => {
    await updateVCard({
      vCard: { url: ref.objectUrl, data: vcfBody, etag },
      // Never a credential from here. See the docstring.
      headers: {},
      fetch: davFetch,
    });

    return {
      id: encodeContactId({
        addressBookUrl: ref.addressBookUrl,
        objectUrl: ref.objectUrl,
      }),
      addressBookId: encodeAddressBookId({ collectionUrl: ref.addressBookUrl }),
      applied: true,
    };
  });
}
