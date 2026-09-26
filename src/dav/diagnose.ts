// The transport-free half of `dav_diagnose` (D-54, D-61).
//
// Mirrors `src/mail/diagnose.ts`'s report/outcome split: the report is a record
// of what this run OBSERVED, the outcome is that report plus whatever ended the
// run. The report is returned even when the run failed, because a diagnostic
// that discards its measurements at the first problem is useless for the one
// job it has.
//
// Every field below documents what was observed, never what was configured.
// That is the whole discipline of the mail diagnostic's report, and it is why
// the shard host is read off the RESOLVED home URL rather than reconstructed
// from a pattern: a reconstructed value would agree with reality right up until
// the moment the answer mattered.
//
// This module contains no logging calls of any kind and must never acquire any.

import ICAL from "ical.js";
// tsdav's collection-creation helper is deliberately NOT imported, and it is
// named by role here rather than spelled because it is itself a banned token in
// every scanned root. It issues the RFC 4791 calendar-creation method, which
// this runtime refuses to build a request from — see `CREATE_METHOD` below for
// the measurement. What this module DOES send is RFC 5689 extended `MKCOL`,
// which is not banned and is spelled throughout. The helper's name stays on the
// `dav-concurrent-request` alternation in `scripts/forbidden-tokens.mjs`, and on
// the containment gate's request vocabulary, so a future call site is guarded
// the moment it appears; nothing here calls it.
import {
  calendarQuery,
  davRequest,
  deleteObject,
  fetchAddressBooks,
  propfind,
} from "tsdav";
import type { DAVResponse } from "tsdav";
import type { Env } from "../env";
import { davToErrorCategory } from "./errors";
import type { DavService, ResolvedDavAccount } from "./discovery";
import {
  DAV_SERVICES,
  assertUnderHome,
  clearDavCache,
  davAccountFor,
  resolveDavAccount,
} from "./discovery";
import type { DavFetch } from "./transport";
import type { Principal } from "../principal";

/** Where the time went, stage by stage. `null` means "this stage did not run". */
export interface DavServiceTimings {
  /** Resolving the three URLs — zero outbound requests on a cache hit. */
  discoveryMs: number | null;
  /** The one collection-listing round trip that follows it. */
  collectionsMs: number | null;
}

/**
 * What one service's half of the report carries.
 *
 * `null` is the empty state — "this stage did not run" — as distinct from `0`
 * or `false`, which mean the stage ran and the answer was none or no. The two
 * count fields are per-service by construction: `calendarCount` is `null` on
 * the CardDAV half and `addressBookCount` is `null` on the CalDAV half, rather
 * than both being zero, so a reader can never mistake "not applicable" for
 * "found nothing".
 */
/**
 * One collection in a home set, exactly as the server described it.
 *
 * Every field is read rather than derived, and nothing is filtered out of the
 * list this appears in. That is the whole point of it: the listing tool applies
 * a component filter, and a diagnostic that applied the same filter could not
 * show that the filter is hiding something. A to-do list has to be visible here
 * BY NAME rather than inferred from a count that does not add up.
 */
export interface DavCollectionProbe {
  /** The collection's href, resolved against the home URL. */
  href: string;
  /** The display name, or `""` when the server sent none this run can read. */
  displayName: string;
  /** The `resourcetype` children, as names — `calendar`, `subscribed`, … */
  resourceTypes: string[];
  /**
   * The components this collection advertises — `VEVENT`, `VTODO`, …
   *
   * EMPTY means the collection advertised no component set, which is a real
   * answer and not a missing one: a collection that declares no restriction
   * accepts every component type.
   */
  components: string[];
  /**
   * The default-calendar href this row advertises, or `null` when it carries
   * none.
   *
   * **RFC 6638 § 9.2 puts this property on the scheduling INBOX collection, not
   * on the principal**, and the inbox is a child of the calendar home — measured
   * live on 2026-09-25 at `…/calendars/inbox/` with `resourceTypes:
   * ["collection", "scheduleInbox"]`. So the depth-1 home PROPFIND this probe
   * already sends traverses the row that carries it, and asking for the property
   * costs nothing: a server that does not know it omits it rather than refusing
   * the whole PROPFIND, exactly as `cs:source` rides the listing one module over.
   *
   * **`null` on every row is the expected shape and it is not a bug.** Only the
   * scheduling inbox can carry a value, so every calendar collection answers
   * `null` by construction. The field is here rather than filtered to the inbox
   * because this probe filters on nothing except addressability — a property
   * that appeared only on the row the reader was already looking for could not
   * show that it appears somewhere else instead.
   *
   * Whether iCloud POPULATES the property is a separate question from whether
   * this server reads it, and the second is all that is settled in code.
   */
  scheduleDefaultCalendarUrl: string | null;
}

export interface DavServiceReport {
  /** The principal URL this run resolved. */
  principalUrl: string | null;
  /** The home-set URL this run resolved. */
  homeUrl: string | null;
  /** The hostname observed on the home URL — the `pXX-` shard. */
  shardHost: string | null;
  /** True when the three URLs came from KV and no request was made. */
  cacheHit: boolean | null;
  /**
   * CalDAV only: the account's default calendar URL, as discovery resolved it.
   *
   * **It was added so CALM-07 could be MEASURED in one call rather than in a
   * second deploy, and the measurement came back NULL.** On this account, on
   * every deploy since `7c0afd3a`, this field reads `null`:
   * `resolveDefaultCalendarUrl` asks the principal for its scheduling inbox and
   * then asks that inbox for `CALDAV:schedule-default-calendar-URL`, which is
   * where RFC 6638 § 9.2 defines the property, and iCloud answers nothing. The
   * depth-1 home listing answered it empty on all thirteen rows as well.
   * `runPropertyNameProbe` then closed the remaining "is there some OTHER
   * property" by measuring that iCloud does not implement `DAV:propname` at all.
   * CALM-07 was withdrawn on that evidence on 2026-09-26.
   *
   * **It is KEPT, and reporting it is what keeps the withdrawal honest.** Nothing
   * acts on the value any more — the delete-time predicate it fed is deleted — so
   * this field is now a STANDING MEASUREMENT. If Apple ever begins populating the
   * property, one `dav_diagnose` call against a real account says so, with no
   * deploy and no new probe. That is the whole reason the resolver survived the
   * requirement; see `resolveDefaultCalendarUrl`, which holds the decision.
   *
   * It is a URL under the account's OWN resolved home set and it is not a
   * credential — the same class of value as `homeUrl` and `principalUrl` beside
   * it, which this report has carried since Phase 3 — and the only caller is the
   * account's own owner. `null` on the CardDAV half, per this interface's own
   * convention: `resolveDavAccount` resolves it for CalDAV alone, because a
   * scheduling inbox is a calendaring concept.
   */
  defaultCalendarUrl: string | null;
  /** CalDAV only: how many calendar collections the home set holds. */
  calendarCount: number | null;
  /** CardDAV only: how many address books the home set holds. */
  addressBookCount: number | null;
  /**
   * The report names the collections of THIS service advertise.
   *
   * Per-service, not CardDAV-only — it was CardDAV-only, and the asymmetry was
   * the finding rather than the design: a tool that answered the question for
   * one service and returned `null` for the other could not be used to answer
   * it for the other, which cost a spike on 2026-09-23. Both halves now union
   * the names across their own collections.
   */
  reports: string[] | null;
  /**
   * CalDAV only: every collection the home set holds, with its component set.
   *
   * `null` on the CardDAV half, per the convention this interface's own
   * docstring states — not an empty array, which would say the home set was
   * enumerated and held nothing.
   */
  collections: DavCollectionProbe[] | null;
  /**
   * CalDAV only: what the collection write probe did, when it was asked for.
   *
   * `null` when `probeCollectionWrite` was absent or false, which is the
   * ordinary case and the default — a reader of an ordinary `dav_diagnose`
   * response sees exactly what they saw before this field existed, and the run
   * issued no mutating request at all.
   */
  collectionWrite: CollectionWriteProbe | null;
  /**
   * CalDAV only: the to-do objects in this account's task collections.
   *
   * `null` when `probeTaskObjects` was absent or false. Same convention, same
   * reason, and the same default: the ordinary response is unchanged in cost
   * and in shape.
   */
  taskObjects: TaskCollectionProbe | null;
  /**
   * CalDAV only: which property NAMES this account's resources carry.
   *
   * `null` when `probePropertyNames` was absent or false. Same convention, same
   * reason, and the same default as the two probes above: the ordinary response
   * is unchanged in cost and in shape, and the run issues no extra request.
   */
  propertyNames: PropertyNameProbe | null;
  timings: DavServiceTimings;
}

/**
 * One step of the collection write probe, as this server observed it.
 *
 * `status` is the HTTP status the step's own response carried. **`null` means
 * no status was observed**, which happens for exactly two reasons and they are
 * distinguishable by `ok`: the step issued no request of its own against the
 * probe collection (the resolve, and the re-listing, which delegates), or the
 * transport refused before a status could be read.
 *
 * `category` is this project's own fixed failure vocabulary, read off the
 * TYPE of the error the transport raised and never off its `.message` or
 * `.stack` — the same dispatch `davToErrorCategory` performs at the tool
 * boundary, for the reason ./.claude/CLAUDE.md §4 gives. It is `null` on a step
 * that did not fail.
 *
 * **The category is here rather than omitted because SPIKE-04's whole question
 * is HOW a refusal arrived.** `./transport.ts` maps a status number to a typed
 * error and throws, so a refused mutation reaches this report with its number
 * already gone. Without the category every refusal would read identically, and
 * "iCloud refuses collection writes from a third-party client" would be
 * indistinguishable from "this server sent a request with no credential on it"
 * — which is exactly the measured-looking wrong verdict this probe exists to
 * avoid producing.
 */
export interface CollectionWriteStep {
  /** Which step: `resolve`, `create`, `rename-and-recolour`, `delete`, `verify`. */
  step: string;
  /**
   * The HTTP method this step issued, or `null` for a step that issues no
   * single request of its own.
   *
   * **Here because a verdict is going to be written from this report, and the
   * method is the half of the answer a reader would otherwise supply from
   * memory.** The create step does not send the RFC 4791 calendar-creation
   * method — this runtime refuses to build a request carrying it — so it sends
   * RFC 5689 extended `MKCOL` instead. A server may accept one and refuse the
   * other, so
   * "create: ok, 201" without the method names a fact about a request that was
   * never sent. See `CREATE_METHOD` for the measurement behind this.
   */
  method: string | null;
  /** The HTTP status observed, or `null` when none was. */
  status: number | null;
  /** Whether this step did what it set out to do. */
  ok: boolean;
  /** The failure's category, from the fixed vocabulary. `null` when it did not fail. */
  category: string | null;
  /**
   * The property-name keys tsdav parsed out of a multistatus, or `null` for a
   * step that reads no propstat.
   *
   * **Here because the ONE thing nobody had ever measured about iCloud's
   * property-update answer is what its propstat keys are spelled as, and that
   * gap shipped a defect.** Plan 17-04 built a reader in `src/dav/calendar.ts` to
   * decide which properties a rename-and-recolour landed, and it decided by
   * looking for keys in `DAVResponse.props`. Every test behind it drove a fixture
   * built from RFC 4918 section 9.2's example shape, because no test in this
   * repository had ever seen a real one -- 17-04's own summary says so in as many
   * words. Measured live on 2026-09-25 against version
   * `8c7f848f-d6e3-4e44-b1bb-088f1dcb2c72`: iCloud accepted the update and
   * `calendar_update_calendar` reported `connection_failed` anyway, because
   * `changed` came back empty and the empty case threw. The write had landed.
   *
   * **AND THE ANSWER IS THE EMPTY ARRAY.** Not differently-spelled keys: none at
   * all. A refused update answers the same way, so through this library's parse a
   * success and a refusal are the same bytes -- which is why plan 17-10 retires
   * that reader outright rather than fixing its spellings, and verifies the
   * rename by reading the collection BACK instead. `./calendar.ts` carries that
   * change and the retirement note under it; this field is the evidence beneath
   * both, and it is committed first because the measurement came first.
   *
   * So the keys are reported here rather than inferred anywhere: an answer a
   * reader has to guess at is how the guess became a defect the first time.
   * Reporting DAV property NAMES and nothing else -- no value is read, so no
   * calendar title, colour or URL can ride out through this field.
   */
  propKeys: string[] | null;
}

/**
 * What the collection write probe did, and whether it actually cleaned up.
 *
 * **`cleanupVerified` is computed from a FRESH listing of the home set, never
 * from the delete's own status.** A delete that answered `204` is a statement
 * by a server about a request; the only evidence a collection is gone is
 * looking again and not finding it. When the two disagree the report says so,
 * and `url` is what the owner needs to remove the collection by hand — a
 * throwaway calendar left on a real account is litter found months later.
 */
export interface CollectionWriteProbe {
  /** The collection this probe addressed. Under the account's own home set. */
  url: string;
  /** Every step, in the order it ran. */
  steps: CollectionWriteStep[];
  /** True only when the re-listing ran AND no longer showed the collection. */
  cleanupVerified: boolean;
  /** Whether the re-listing still showed it. `null` when it did not run. */
  stillPresent: boolean | null;
}

/** One to-do object's identity: enough to match a reminder by name, and no more. */
export interface TaskObjectProbe {
  /** The object's UID, verbatim. */
  uid: string;
  /** The object's SUMMARY — its title, verbatim. UNTRUSTED third-party text. */
  summary: string;
}

/** One task collection's contents, bounded. */
export interface TaskCollectionEntry {
  /** The collection's href, as the enumeration resolved it. */
  href: string;
  /** Its display name, or `""` when the server sent none this run can read. */
  displayName: string;
  /** How many object responses the query returned, BEFORE the per-collection cap. */
  objectCount: number;
  /** True when the cap bit and this list is shorter than what the server sent. */
  truncated: boolean;
  /** How many objects were dropped because no UID and title could be read. */
  unparsed: number;
  /** The objects kept, in the order the server returned them. */
  objects: TaskObjectProbe[];
  /**
   * The category of the refusal this collection's query met, or `null` when
   * the server answered it.
   *
   * **This field is the difference between a partial answer that says so and
   * a partial answer that does not, and it arrived because the alternative
   * was measured.** The query used to be left to throw: one refused
   * collection travelled to the tool boundary, which discarded the whole
   * report — every other collection's to-do objects, both services'
   * discovery, all of it — and answered with a bare category. Against the real
   * account that is exactly what happened, on two abandoned lists that
   * predate Apple's iOS 13 storage migration.
   *
   * Swallowing the refusal would have been worse than either: SPIKE-02's
   * documented pass-but-wrong mode is a probe that answers short without
   * saying so, and a collection silently missing from this list is that mode
   * precisely. So the refusal is REPORTED, per collection, and the run
   * continues. The entry is still present, still named, and carries no
   * objects — a reader can see that this collection was asked and refused,
   * which is a different fact from it holding nothing.
   */
  category: string | null;
}

/**
 * The to-do objects in this account's task collections.
 *
 * **This exists because the collection enumeration answers a narrower question
 * than SPIKE-02 asks.** That field proves a task list is SERVED over CalDAV. It
 * cannot carry a reminder's title, and the spike's pass condition is that a
 * reminder the owner named on his phone appears in the report this server
 * produced. So this reads enough per-object identity for that comparison to be
 * made, and nothing else.
 *
 * **Nothing here does the comparing.** The probe takes no title to match
 * against and returns no verdict — it reports what it found. The comparison
 * happens in plan 14-06, as an exact string match against the full list. A
 * fuzzy match decided in this file would be this file deciding SPIKE-02.
 *
 * `collectionsFound` and `collectionsVisited` differ exactly when the
 * collection cap bit, which is why both are reported: a cap that returned a
 * short answer without saying so would let a MISSING reminder look like an
 * ABSENT one.
 */
export interface TaskCollectionProbe {
  /** How many collections in the home set advertise the to-do component. */
  collectionsFound: number;
  /** How many of them this run actually queried, at most `MAX_TASK_COLLECTIONS`. */
  collectionsVisited: number;
  /** One entry per visited collection, in home-set order. */
  collections: TaskCollectionEntry[];
  /**
   * The category of a refusal that stopped the probe BEFORE any collection was
   * visited, or `null` when it got as far as the collections.
   *
   * Distinct from the per-collection field above, and the distinction is the
   * one that matters to a reader: that one says "this list was asked and
   * refused", this one says "no list was ever asked". Both are reported rather
   * than thrown, because the report is this run's record of what it observed
   * and a diagnostic that discards its measurements at the first problem is
   * useless for the one job it has — the argument this module's own header
   * already makes.
   */
  category: string | null;
}

/**
 * One propstat block, and the property names it NAMED — never a value.
 *
 * **A propstat whose status is NOT 2xx still names properties, and those names
 * are exactly the interesting ones for this probe's question.** A resource that
 * knows a property but will not disclose it to this caller says so in a `403`
 * block; a resource that has never heard of it says so in a `404` block. Both
 * are answers to "what properties exist here", and the DAV library's own parse
 * discards every non-2xx block outright — which is one of the two reasons the
 * reading below works off the raw body instead.
 *
 * `status` is a NUMBER and never the status line it was read out of. The line is
 * prose a server wrote and `./../../.claude/CLAUDE.md` § 4 forbids echoing one;
 * three digits carry none of it, and a status NUMBER is already what
 * `CollectionWriteStep.status` beside this reports.
 */
export interface PropertyNameBlock {
  /** The propstat's own status, as a number. `null` when none could be read. */
  status: number | null;
  /** The names that block carried, as written on the wire, sorted. */
  names: string[];
}

/**
 * One resource, and every property NAME it carries — never a value.
 *
 * **The names are the ones the SERVER WROTE, prefix and all.** `d:displayname`,
 * `CS:getctag`, `ca:calendar-color`. This used to report the DAV library's own
 * spelling — the prefix stripped and the remainder camel-cased — and the wire
 * form replaced it for one reason: the library's parse could not answer this
 * question at all (see the section above `propertyNamesInBody`), so the reading
 * moved to the raw body, and the raw body spells a property the way the server
 * spelled it. That is better, because it is what was actually sent. Three
 * consequences are worth writing down rather than discovering.
 *
 * A PREFIX IS THE SERVER'S OWN ABBREVIATION AND NOT THE NAMESPACE. Two servers
 * may write the same property as `d:displayname` and `D:displayname`, and a
 * property in the document's default namespace arrives BARE, with no prefix at
 * all. So a name here identifies a property within one response and is not a
 * stable cross-server identifier. Nothing in this project matches on one.
 *
 * NOTHING IS RESOLVED AGAINST THE NAMESPACE DECLARATIONS, deliberately. Doing so
 * would mean reading attribute VALUES off the body, and every safety claim this
 * probe makes rests on reading element NAMES and nothing else.
 *
 * TWO PROPERTIES SHARING A BARE LOCAL NAME IN DIFFERENT NAMESPACES still collapse
 * if both arrive unprefixed. That is narrower than the collapse the library's
 * camel-casing caused — which merged them whatever their prefixes — but it is not
 * zero, so a name appearing once does not prove one property.
 *
 * ## `reading` is the discriminator, and there are five states
 *
 * It is always set, and exactly one value holds, so the states are mutually
 * exclusive by construction rather than by a reader cross-checking three nullable
 * fields. The state that forced it into existence is the third one: on 2026-09-25
 * all four targets answered `names: []` with a null category against an account
 * that unquestionably carries `displayname` on all four, and the report had no way
 * to say "answered, but this run could not read the answer".
 *
 * | `reading`               | `names` | what it says                                     |
 * | ----------------------- | ------- | ------------------------------------------------ |
 * | `names_read`            | array   | asked, answered, and these are the names          |
 * | `names_read_truncated`  | array   | the same, but the body was capped, so names may be missing |
 * | `unreadable_response`   | `null`  | asked, answered, and no propstat could be found in the answer |
 * | `refused`               | `null`  | asked and refused; `category` says how             |
 * | `not_asked`             | `null`  | no such row in the account's own listing, so nothing was asked |
 *
 * `names` and `blocks` are non-null exactly for the first two. `category` is
 * non-null exactly for `refused`. An EMPTY `names` under `names_read` is a real
 * answer and a different fact from all four of the others: the resource was
 * asked, it answered with a propstat, and that propstat named nothing.
 */
export interface PropertyNameTarget {
  /** Which resource: `principal`, `home`, `schedule-inbox`, `calendar`. */
  target: string;
  /** The href actually asked, or `""` when none could be derived. */
  href: string;
  /** Which of the five states this target is in. See the table above. */
  reading: string;
  /** Every property name carried, sorted. `null` unless names were read. */
  names: string[] | null;
  /** The same names, split by the propstat status each was named under. */
  blocks: PropertyNameBlock[] | null;
  /**
   * The HTTP status number the response carried, or `null` when none arrived.
   *
   * A number, never a status line — the same claim `PropertyNameBlock.status`
   * makes and for the same § 4 reason.
   */
  status: number | null;
  /**
   * How many characters of the answer this run read, or `null` when none arrived.
   *
   * A LENGTH, which is the safest diagnostic there is: it carries no character of
   * the body. It is here to separate "the server sent nothing" from "the server
   * sent something this run could not read", which are different fixes.
   *
   * It is what was READ rather than what was sent: the DAV library caps a raw
   * body at `RAW_BODY_CAP`, and `reading` says `names_read_truncated` when it did.
   */
  bodyChars: number | null;
  /**
   * Every ELEMENT NAME the answer carried, deduped, sorted and capped — reported
   * only when `reading` is `unreadable_response`.
   *
   * **This is the capture mechanism, and it exists because the previous version
   * of this probe passed ten tests and was wrong in production.** Every fixture
   * behind it was this repository's own idea of a `propname` answer, so nothing in
   * the suite could show that the real one has a different shape. When no propstat
   * can be found, this says what the body's shape actually WAS, and the next live
   * run therefore distinguishes the two fixes: element names including `propstat`
   * and `prop` mean the reader is wrong, element names with neither mean the
   * request got a different kind of answer than `propname` is defined to give, and
   * no element names at all with a zero `bodyChars` mean the answer was empty.
   *
   * **WHY THIS RATHER THAN AN EXCERPT OF THE BODY, argued because § 4 is the rule
   * it is in tension with.** An excerpt was the obvious route and it is refused: if
   * the reason no propstat was found is that iCloud answered as though asked for
   * every property with its VALUE, then an excerpt of that body carries calendar
   * titles, colours and hrefs, and § 4 forbids a diagnostic field echoing a server
   * body. This reports the body's SHAPE instead. It reads element names and never
   * one character of text content or of an attribute value, which is the same
   * guarantee `names` beside it rests on — so it cannot carry a property value, a
   * calendar title, an address or a URL, because every one of those is text.
   * Bounded by construction as well: deduped, and capped at `MAX_BODY_ELEMENTS`.
   *
   * The residual is stated rather than waved away: an element NAME is chosen by
   * the server, so a server that named an element after a secret would put it
   * here. That is the identical residual `names` carries, and it is the one this
   * whole probe already accepts in order to exist at all.
   */
  bodyElements: string[] | null;
  /** The refusal's category, from the fixed vocabulary. `null` when none. */
  category: string | null;
}

/**
 * What property NAMES iCloud carries on four resources of this account.
 *
 * **It existed because two targeted probes came back null and a requirement was
 * about to be deleted on the strength of that, and it ANSWERED.** CALM-07 asked
 * for a local refusal of the account's default calendar; measured live on
 * 2026-09-25, `CALDAV:schedule-default-calendar-URL` is absent from all thirteen
 * home rows AND from the scheduling inbox, which is where RFC 6638 § 9.2 defines
 * it. The likely explanation — Apple's "Default Calendar" is a per-DEVICE setting
 * rather than account state, so no server property exists to find — was plausible
 * and still an INFERENCE, because both probes so far asked for ONE NAMED property,
 * which is a different question from asking what properties exist.
 *
 * `DAV:propname` is that second question. RFC 4918 § 9.1 defines a PROPFIND whose
 * body is `<D:propfind><D:propname/></D:propfind>` as returning the name of every
 * property the resource carries, WITH NO VALUES. So this was the exhaustive ask —
 * and **iCloud does not implement it.** Measured on deploy `1fce400b`: the server
 * answers 207 with an empty 200 block and a 404 block naming `propname` itself,
 * having read the request MODE as the name of a property being requested. The
 * measurement, and why `allprop` cannot substitute for it, are recorded in full on
 * `runPropertyNameProbe` below. CALM-07 was withdrawn on 2026-09-26.
 *
 * **What makes it safe to point at a real account is the READING and not the
 * RFC, and that distinction was earned rather than chosen.** The first version of
 * this docstring said it cannot leak a value because the server sends none. That
 * is a guarantee resting on a server behaving, which is not a guarantee at all —
 * and the very next live run proved the server does something this repository did
 * not predict. The reading below takes element NAMES out of the raw body and reads
 * no text content and no attribute value at all, so the safety holds against a
 * server that answers with values, with something else entirely, or with nothing.
 *
 * **IT DID NOT WORK THE FIRST TIME, and the reason is written down one section
 * below rather than only in a plan file.** Shipped on 2026-09-25, this probe
 * reported an EMPTY name list for all four targets against an account that
 * unquestionably carries `displayname` and `resourcetype` on every one of them —
 * twice, the second time with the discovery cache cleared. The cause was the DAV
 * library's parse, not iCloud, and it is the same cause that had made
 * `calendar_update_calendar` report a landed write as a connection fault the day
 * before. See the section above `propertyNamesInBody` for the rule that follows
 * from it, which is the part that generalises past this probe.
 *
 * **Nothing here decides anything, and that held right through the verdict.** The
 * probe reports names; what CALM-07 should therefore say was the owner's call on
 * this reading, and the owner made it on 2026-09-26. A verdict computed in this
 * file would have been this file deciding CALM-07. Note which reading counted: the
 * first one, before the parse defect was fixed, settled NOTHING, because a broken
 * instrument's silence is not evidence of absence. The reading that counted is the
 * one taken after the fix, on deploy `1fce400b`.
 */
export interface PropertyNameProbe {
  /** One entry per target, in the fixed order the probe asks them. */
  targets: PropertyNameTarget[];
  /**
   * The category of a refusal that stopped the probe BEFORE any target could be
   * derived, or `null` when it got as far as the targets.
   *
   * Distinct from the per-target field for the reason `TaskCollectionProbe`'s
   * own pair is: that one says "this resource was asked and refused", this one
   * says "no resource was ever asked".
   */
  category: string | null;
}

/**
 * The whole `dav_diagnose` contract.
 *
 * **The two services are reported separately and unconditionally, including
 * when their shard hosts share a partition number.** The partition is per
 * account AND per service; a run where the two numbers happen to match is a
 * coincidence, and a report shaped so that a coincidence could be read as a
 * rule would be worse than no report — it would invite exactly the derivation
 * ("CalDAV is on p42, so CardDAV is too") that this phase exists to prevent.
 */
export interface DavDiagnosticReport {
  /** Whether this run was asked to clear the cache first (D-61). */
  refresh: boolean;
  caldav: DavServiceReport;
  carddav: DavServiceReport;
}

/** A finished diagnostic run: the report always, plus whatever ended it. */
export interface DavDiagnosticOutcome {
  report: DavDiagnosticReport;
  /** True when `error` is meaningful. */
  failed: boolean;
  /** What ended the run. A `catch` receives any value, so: unknown. */
  error: unknown;
}

function emptyServiceReport(): DavServiceReport {
  return {
    principalUrl: null,
    homeUrl: null,
    shardHost: null,
    cacheHit: null,
    defaultCalendarUrl: null,
    calendarCount: null,
    addressBookCount: null,
    reports: null,
    collections: null,
    collectionWrite: null,
    taskObjects: null,
    propertyNames: null,
    timings: { discoveryMs: null, collectionsMs: null },
  };
}

function emptyReport(refresh: boolean): DavDiagnosticReport {
  return {
    refresh,
    caldav: emptyServiceReport(),
    carddav: emptyServiceReport(),
  };
}

/**
 * The hostname actually present on the resolved home URL.
 *
 * Read rather than derived. `null` when the URL cannot be parsed, which is a
 * fact worth reporting rather than a reason to throw — the URL is already in
 * the report beside it, so a reader can see for themselves.
 */
function shardHostOf(homeUrl: string): string | null {
  try {
    return new URL(homeUrl).hostname;
  } catch {
    return null;
  }
}

function fillResolved(
  report: DavServiceReport,
  resolved: ResolvedDavAccount,
): void {
  report.principalUrl = resolved.principalUrl;
  report.homeUrl = resolved.homeUrl;
  report.shardHost = shardHostOf(resolved.homeUrl);
  report.cacheHit = resolved.cacheHit;
  // Read off the RESOLVED account rather than re-derived, so what this reports is
  // the value discovery actually stored rather than a second reading of it. That
  // mattered when a delete-time predicate consumed the same value; since CALM-07's
  // withdrawal on 2026-09-26 this report is the ONLY reader, which makes reading
  // it off the resolved account the whole of the measurement rather than a check
  // on it. On the CardDAV half it is null because `resolveDavAccount` never asks.
  report.defaultCalendarUrl = resolved.defaultCalendarUrl;
}

/**
 * Read a supported-report-set property into report names.
 *
 * The shape is the one tsdav's own `supportedReportSet` helper reads:
 * `supportedReport` is one element or an array of them, and each element's
 * `report` member is an object whose FIRST KEY is the report name.
 *
 * Hand-narrowed for the reason `reportNamesOf` below already gives — the
 * library types this whole region `any`, so the compiler is not watching this
 * boundary, and an unexpected object shape reaching `JSON.stringify` renders as
 * the nine characters `[object Object]`, which reads like a real answer in a
 * tool response. A name is kept only when it is a non-empty string; everything
 * else is dropped rather than coerced.
 */
function supportedReportNamesOf(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  const supported = (value as { supportedReport?: unknown }).supportedReport;
  if (supported === null || supported === undefined) return [];
  const entries = Array.isArray(supported) ? supported : [supported];

  const names: string[] = [];
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    const report = (entry as { report?: unknown }).report;
    if (report === null || typeof report !== "object") continue;
    const name = Object.keys(report as Record<string, unknown>)[0];
    if (typeof name === "string" && name.length > 0) names.push(name);
  }
  return names;
}

/**
 * The `supported-calendar-component-set` children, as component names.
 *
 * **A LOCAL twin of the reader in `src/dav/calendar.ts`, deliberately not an
 * import of it, and the separation is the safety property rather than an
 * oversight.** That module's reader feeds a filter which admits only collections
 * carrying the event component, and that filter is why reminder lists do not
 * appear in `calendar_list_calendars` as calendars with no events — a known
 * confusing outcome for third-party CalDAV clients (Pitfall 57, second half).
 * This diagnostic must report a to-do list; the listing must keep not showing
 * one. Two readers, so an edit to either can never reach the other.
 *
 * Hand-narrowed for the same reason everything else here is: the library types
 * this region `any`, and `_attributes.name` is a value a server chose.
 */
function componentNamesOf(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  const comp = (value as { comp?: unknown }).comp;
  const entries = Array.isArray(comp) ? comp : [comp];

  const names: string[] = [];
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    const name = (entry as { _attributes?: { name?: unknown } })._attributes
      ?.name;
    if (typeof name === "string" && name.length > 0) names.push(name);
  }
  return names;
}

/**
 * The `schedule-default-calendar-URL` href a row carries, or null.
 *
 * The property's content is a single `DAV:href`, so the parsed value is an
 * object with an `href` member — the same shape `CS:source` has one module
 * over, and hand-narrowed for the same reason: the library types this whole
 * region `any`, and an EMPTY element yields `{}` rather than `{ href }`, whose
 * string conversion is the nine characters `[object Object]`. That would read
 * as a real URL in a tool response.
 *
 * Resolved against the home URL, because iCloud answers relative hrefs. A value
 * that will not resolve is dropped rather than carried: a URL this server
 * cannot address is one it must not claim to have, which is the same rule the
 * enumeration below applies to a collection's own href. Nothing is read from a
 * caught value.
 */
function scheduleDefaultHrefOf(value: unknown, base: string): string | null {
  if (value === null || typeof value !== "object") return null;
  const href = (value as { href?: unknown }).href;
  if (typeof href !== "string" || href.length === 0) return null;
  try {
    return new URL(href, base).href;
  } catch {
    // Nothing is read from the caught value — ./.claude/CLAUDE.md §4.
    return null;
  }
}

/**
 * Everything the CalDAV home set can say about itself in ONE request.
 *
 * `propfind` at depth 1 rather than tsdav's `fetchCalendars`, and the reason is
 * the connection budget rather than style: `fetchCalendars` wraps a `Promise.all`
 * that issues one ADDITIONAL PROPFIND per calendar to read its supported report
 * set. The gate in `./transport.ts` would serialise that fan-out, so it would
 * be correct — but it would still cost one round trip per calendar to produce a
 * number, and a personal account has nine calendars.
 *
 * **The report names ride that same request.** A depth-1 PROPFIND may ask for
 * the supported-report-set alongside the resource type, and a server that does
 * not know a property omits it from the response rather than refusing the whole
 * PROPFIND — which is why `src/dav/calendar.ts`'s listing already free-loads
 * `cs:source` the same way. So the CalDAV half answers the question the CardDAV
 * half answers, at no extra round trip and with no per-collection helper.
 *
 * `calendarCount` counts the collections carrying the calendar resource type.
 * **That is deliberately a different number from the length of
 * `calendar_list_calendars`**, and the difference is the point: this count
 * includes a to-do list, because a reminder list is a calendar collection whose
 * component set is `VTODO`, while the listing filters on the event component and
 * drops it. A diagnostic that agreed with the listing could not show that the
 * listing is hiding something.
 *
 * `collections` is filtered on NOTHING except addressability. Every response
 * the home set returns becomes a row, whatever its resource type and whatever
 * its component set, with two exceptions that are not filters: the home
 * collection itself, which is the container rather than a member of it, and a
 * collection whose href will not resolve, which this server cannot address and
 * so must not claim to have. Filtering on the component is exactly what the
 * listing does and exactly what this field exists to see past.
 */
async function probeCalendarHome(
  davFetch: DavFetch,
  homeUrl: string,
): Promise<{
  calendarCount: number;
  reports: string[];
  collections: DavCollectionProbe[];
}> {
  const responses = await propfind({
    url: homeUrl,
    props: {
      "d:resourcetype": {},
      "d:displayname": {},
      "d:supported-report-set": {},
      "c:supported-calendar-component-set": {},
      // Free, on `cs:source`'s own footing one module over: this is one request
      // either way, and a server that does not know the property omits it from
      // the response rather than refusing the whole PROPFIND. RFC 6638 § 9.2
      // puts it on the scheduling inbox, which this depth-1 listing already
      // traverses — see `DavCollectionProbe.scheduleDefaultCalendarUrl`.
      "c:schedule-default-calendar-URL": {},
    },
    depth: "1",
    headers: {},
    fetch: davFetch,
  });

  let calendarCount = 0;
  // A Set, so the union across collections de-duplicates while keeping the
  // order the collections were seen in — symmetric with `reportNamesOf`.
  const reports = new Set<string>();
  const collections: DavCollectionProbe[] = [];

  // One pass. The count, the report union and the enumeration all read the
  // same responses, so splitting them into three loops would be three chances
  // for the three answers to stop describing the same request.
  for (const response of responses) {
    const props = response.props ?? {};
    const resourceTypes = Object.keys(props.resourcetype ?? {});

    if (resourceTypes.includes("calendar")) {
      calendarCount += 1;
      for (const name of supportedReportNamesOf(props.supportedReportSet)) {
        reports.add(name);
      }
    }

    const rawHref = response.href;
    if (typeof rawHref !== "string" || rawHref.length === 0) continue;

    let href: string;
    try {
      href = new URL(rawHref, homeUrl).href;
    } catch {
      // Nothing is read from the caught value — ./.claude/CLAUDE.md §4.
      continue;
    }
    // The container, not a member of it.
    if (href === homeUrl) continue;

    collections.push({
      href,
      displayName:
        typeof props.displayname === "string" ? props.displayname : "",
      resourceTypes,
      components: componentNamesOf(props.supportedCalendarComponentSet),
      // `schedule-default-calendar-URL` camel-cases to this after the library
      // strips the namespace prefix — `-U` becomes `U`, so the trailing
      // capitals survive. Resolved against the HOME rather than the row's own
      // href, because that is the base iCloud's relative hrefs are relative to.
      scheduleDefaultCalendarUrl: scheduleDefaultHrefOf(
        props.scheduleDefaultCalendarURL,
        homeUrl,
      ),
    });
  }

  return { calendarCount, reports: [...reports], collections };
}

/**
 * The report names every address book on this account advertises.
 *
 * `fetchAddressBooks` is used here rather than a bare `propfind`, unlike the
 * calendar side, because its `reports` array is the value D-62 genuinely wants:
 * it settles — permanently, in one call — whether this account advertises the
 * address-book query report, which is what decides whether plan 03-08's
 * server-side filter path is live or whether the fetch-all fallback is the only
 * path. Its `1 + N` cost is acceptable where the calendar side's was not,
 * because N is one to three for address books.
 *
 * **`DAVCollection.reports` is typed `any` by tsdav, so the compiler is not
 * watching this boundary.** Narrowing to strings here is what stops an
 * unexpected object shape reaching `JSON.stringify` and rendering as
 * `[object Object]` in a tool response — Pitfall 3, one field over.
 */
function reportNamesOf(collections: { reports?: unknown }[]): string[] {
  const names = new Set<string>();
  for (const collection of collections) {
    if (!Array.isArray(collection.reports)) continue;
    for (const name of collection.reports as unknown[]) {
      if (typeof name === "string" && name.length > 0) names.add(name);
    }
  }
  return [...names];
}

/**
 * Run the whole diagnostic and fold whatever ended it into an outcome.
 *
 * **The two services run in SEQUENCE, never through a concurrent combinator.**
 * Every DAV request counts against the same six-connection per-invocation
 * budget as a KV read and as the one the OAuth provider already spent, and
 * iCloud's own per-account ceiling is lower, undocumented, and deliberately
 * unmeasured. `davFetch` would serialise a combinator anyway; writing one here
 * would be a statement of intent that the next reader would copy somewhere the
 * gate does not reach.
 *
 * A failure before any request — an absent secret, most obviously — folds into
 * an outcome carrying an empty report, following `runDiagnosticOutcome`'s own
 * shape. The caller decides what crosses the tool boundary; nothing is thrown.
 */
export async function runDavDiagnosticOutcome(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  options: { refresh: boolean },
): Promise<DavDiagnosticOutcome> {
  const report = emptyReport(options.refresh);

  try {
    if (options.refresh) await clearDavCache(env, principal);

    for (const service of DAV_SERVICES) {
      await runOneService(env, principal, davFetch, service, report[service]);
    }
  } catch (err) {
    return { report, failed: true, error: err };
  }

  return { report, failed: false, error: null };
}

async function runOneService(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
  service: DavService,
  into: DavServiceReport,
): Promise<void> {
  const discoveryStart = Date.now();
  const resolved = await resolveDavAccount(env, principal, davFetch, service);
  into.timings.discoveryMs = Date.now() - discoveryStart;
  fillResolved(into, resolved);

  const collectionsStart = Date.now();
  if (service === "caldav") {
    const probe = await probeCalendarHome(davFetch, resolved.homeUrl);
    into.calendarCount = probe.calendarCount;
    into.reports = probe.reports;
    into.collections = probe.collections;
  } else {
    const books = await fetchAddressBooks({
      account: davAccountFor(service, resolved),
      headers: {},
      fetch: davFetch,
    });
    into.addressBookCount = books.length;
    into.reports = reportNamesOf(books);
  }
  into.timings.collectionsMs = Date.now() - collectionsStart;
}

// ---------------------------------------------------------------------------
// The opt-in probes (Phase 14: SPIKE-04 and SPIKE-02's object-level half;
// phase 17: the property-name reading that CALM-07's verdict was taken on).
//
// Every one of them is OFF by default, every one is reached only through its own
// named boolean on `dav_diagnose`, and none takes a URL, an identifier or a name
// from any caller. Every one is strictly SERIAL — a `for ... of` with its own
// `await`, never a concurrent combinator. `dav-concurrent-request` names each of
// them and every library primitive they call, and those names went onto that
// alternation before the functions were written, because a name omitted from it
// is invisible to every assertion in the suite.
//
// The COUNT is deliberately not stated in the paragraph above. It said "the two"
// and "both" throughout while there were two, and the third probe made every one
// of those words false rather than merely dated — which is the same silent
// staleness this tree has recorded elsewhere: nothing fails when prose stops
// matching code. How many there are is a question for the file.
//
// **Every tsdav helper below passes `fetch: davFetch` EXPLICITLY.** That
// parameter is declared `fetch?: typeof fetch` and resolved as
// `fetchOverride ?? fetch`, so an omitted option silently selects the bare
// global: no credential header, no `redirect: "manual"`, no serialisation gate,
// no status-to-error mapping. The source scan cannot see the omission — a
// helper called without the option is not a bare network call at the call site,
// and the fetch itself happens inside `node_modules`, which the scanner does not
// walk. It is the same blind spot `dav-concurrent-request`'s own reason string
// records for `fetchCalendars`. Against iCloud the omission is a 401 on every
// mutation, and a 401 on every mutation is indistinguishable at the report
// level from iCloud refusing collection writes outright — a measured-looking
// WRONG verdict for SPIKE-04, on a bug in this repository. The property is
// therefore asserted in `test/dav-diagnose.test.ts` off the RECORDED request's
// `authorization` header rather than off these call sites.
// ---------------------------------------------------------------------------

/** What the throwaway collection is called when it is created. */
const PROBE_DISPLAY_NAME = "iCloud MCP write probe (throwaway)";
/** And after the property update, so a rename that silently no-ops is visible. */
const PROBE_RENAMED = "iCloud MCP write probe (renamed)";
const PROBE_COLOUR = "#7F7F7FFF";
const PROBE_RECOLOURED = "#1F7F3FFF";

/**
 * The method the create step issues, and the reason it is not the obvious one.
 *
 * RFC 4791 defines a calendar-creation method for exactly this, and tsdav ships
 * a helper that issues it. **Neither can be used here: workerd refuses to build
 * a request carrying that method string.** Neither is spelled anywhere in this
 * tree, by role only, because both are banned tokens in every scanned root —
 * see `./../../.claude/CLAUDE.md` § Enforcement. It is the one method in this
 * project's whole
 * DAV vocabulary that it refuses — `PROPFIND`, `PROPPATCH`, `REPORT`, `MKCOL`,
 * `DELETE` and `PUT` are all accepted — and the refusal is a `TypeError` raised
 * before any I/O. Phase 14 shipped the helper, and the live probe reported
 * `connection_failed` on a request iCloud never received.
 *
 * So the create step issues RFC 5689 extended `MKCOL` instead: the same
 * intent, expressed with a method this platform will send. The body sets the
 * calendar resource type alongside the collection one, which is what makes the
 * result a calendar collection rather than a plain one.
 *
 * **This changes what the create step's answer MEANS, and the report says so
 * rather than leaving it to be inferred.** A server may accept the RFC 4791
 * calendar-creation method
 * and refuse extended `MKCOL`, or the reverse, so a `201` here is evidence
 * about extended `MKCOL` and about nothing else. The step record therefore
 * carries the method it used, because a verdict written from a report that
 * said only "create: ok, 201" would name the wrong method — which is the
 * measured-looking wrong verdict this probe exists to avoid producing.
 */
const CREATE_METHOD = "MKCOL";

/**
 * Whether the create step's own status means the collection was created.
 *
 * **`207` is the trap, and it is a trap this change introduced.** The RFC 4791
 * calendar-creation method
 * either works or fails with a plain status; extended `MKCOL` has a third
 * answer. RFC 5689 §3 makes the request all-or-nothing — a server that cannot
 * satisfy every property in the body MUST fail the whole request and MUST NOT
 * create the collection — and the body of that refusal is a
 * `DAV:mkcol-response` naming the property that was rejected.
 *
 * **The status that body arrives under is where an earlier version of this
 * docstring was wrong, and the correction does not change the rule.** It said
 * RFC 5689 "reports that partial failure as a `207 Multi-Status`". It does not:
 * the RFC's own §3.5 example carries the `DAV:mkcol-response` body under `403
 * Forbidden`, and the specification names no `207` for this case at all. The
 * refusal below stays exactly as it was, because it is conservative in the only
 * direction that matters: a `207` is definitionally an envelope rather than an
 * answer, so treating one as a refusal can only ever under-report a success,
 * while treating one as a success would record a creation that did not happen.
 * A server answering `207` here — whether or not the RFC sanctions it — means
 * NOTHING WAS CREATED, while sitting inside the 2xx range that
 * `recordWriteStep`'s generic rule reads as success.
 *
 * Left generic, the report would have said `create: ok, 207` and a verdict
 * written from it would have recorded that iCloud accepts collection creation
 * from a third-party client — which is the same shape of measured-looking wrong
 * answer this whole probe was rewritten to stop producing, arriving by a
 * different door.
 *
 * The rule is narrow on purpose: every 2xx is accepted EXCEPT `207`. Demanding
 * `201` exactly would be the mirror-image error — a server answering `200` on a
 * genuine creation would be recorded as having refused. `207` is the only
 * status in the range that is definitionally an envelope rather than an answer.
 *
 * Because the RFC makes the failure all-or-nothing, stopping the sequence on a
 * `207` leaves no litter: there is no collection to delete.
 */
function createdBy(status: number | null): boolean {
  if (status === null) return false;
  if (status === 207) return false;
  return status >= 200 && status < 300;
}

/**
 * The ceiling on task collections one to-do probe may visit.
 *
 * Every collection is a round trip, every round trip counts against the same
 * budget ./.claude/CLAUDE.md §3 records, and a personal account has fewer than
 * this. On trip the probe REPORTS the trip rather than quietly answering short.
 */
const MAX_TASK_COLLECTIONS = 8;

/** The ceiling on objects reported per collection, for the same reason. */
const MAX_TASK_OBJECTS = 25;

/**
 * Run one write step, recording what happened without reading the error's text.
 *
 * `run` returns the status it observed, or `null` when the step issues no
 * request whose status this layer can see. A throw is recorded as a refusal
 * carrying its CATEGORY — dispatched on the error's type by
 * `davToErrorCategory`, never read off `.message` or `.stack` — and the caller
 * decides whether the sequence continues.
 */
async function recordWriteStep(
  steps: CollectionWriteStep[],
  step: string,
  method: string | null,
  run: () => Promise<number | null>,
  /**
   * What counts as success for THIS step, when the generic rule is wrong.
   *
   * Only the create passes one. See `createdBy` for why: extended `MKCOL`
   * answers a partial failure with a `207`, which is inside the 2xx range and
   * means the opposite of what the range implies.
   */
  succeeded: (status: number | null) => boolean = (status) =>
    status === null || (status >= 200 && status < 300),
): Promise<boolean> {
  try {
    const status = await run();
    const ok = succeeded(status);
    steps.push({ step, method, status, ok, category: null, propKeys: null });
    return ok;
  } catch (err) {
    // The TYPE is read; the value never is.
    steps.push({
      step,
      method,
      status: null,
      ok: false,
      category: davToErrorCategory(err).category,
      propKeys: null,
    });
    return false;
  }
}

/** The first response's status, narrowed. `null` when the library sent none. */
function firstStatusOf(responses: DAVResponse[]): number | null {
  const status = responses[0]?.status;
  return typeof status === "number" ? status : null;
}

/**
 * SPIKE-04's instrument: create a throwaway calendar, change it, remove it, and
 * then LOOK AGAIN.
 *
 * No public source confirms any of the three mutations against iCloud from a
 * third-party client, so the only way to answer is to ask the server. The
 * verdict reshapes Phase 17's collection half; getting it wrong means planning
 * create / rename / recolour / delete against a server that refuses one of them.
 *
 * **The URL is not caller-supplied and cannot be.** Host, path root and shard
 * all come from this principal's own resolved home set, and the only free
 * component is one segment from `crypto.randomUUID()`. That is what keeps
 * `registerDavDiagnoseTool`'s docstring true after this function existed: the
 * boolean that reaches here selects a fixed code path, never a host, a port, a
 * transport mode or a URL.
 *
 * **Five awaits, in this order and no other**, each its own statement:
 *
 *   1. resolve the CalDAV account,
 *   2. create the collection, with RFC 5689 extended `MKCOL`,
 *   3. rename and recolour it with one PROPPATCH,
 *   4. delete it,
 *   5. re-list the home set and check whether it is still there.
 *
 * **Step 2 sends RFC 5689 extended `MKCOL` and NOT the RFC 4791
 * calendar-creation method, and that is a platform fact rather than a
 * preference.** workerd refuses to build a request carrying that other method
 * string — see `CREATE_METHOD` — so what it answers about iCloud is
 * unmeasurable from this runtime. The step records the method it did use,
 * because a report that named only the status would be read as an answer about
 * the method it did not.
 *
 * A refused CREATE stops the sequence — there is nothing to rename and nothing
 * to remove. A refused rename does NOT stop it, and that asymmetry is
 * deliberate: once the collection exists, the delete and the verification are
 * how it stops being litter on a real account.
 *
 * **Every step is RECORDED rather than thrown, including the first.** The
 * resolve used to be awaited bare, so a refusal there threw past this whole
 * function and the tool's catch discarded the entire report — a diagnostic
 * losing its own measurements at the first problem, which is the one thing
 * this module's header says it must never do.
 *
 * Statuses are recorded; bodies are not. A body is bytes a server wrote, and
 * this report carries this server's own observations (T-03-04).
 *
 * Nothing here is logged. This module contains no logging calls of any kind.
 */
export async function runCollectionWriteProbe(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<CollectionWriteProbe> {
  const steps: CollectionWriteStep[] = [];

  // 1. The account's own home set. Everything below is built from it.
  //
  // RECORDED like every other step, rather than awaited bare. It used to be
  // awaited bare and followed by a hand-written `ok: true`, which meant the
  // step could report only success: a refusal here threw past the whole probe,
  // the tool's catch discarded the entire report, and the one field that was
  // supposed to say which step failed said nothing at all because it never ran.
  let resolved: ResolvedDavAccount | null = null;
  await recordWriteStep(steps, "resolve", null, async () => {
    resolved = await resolveDavAccount(env, principal, davFetch, "caldav");
    // Discovery may answer from cache and issue no request, so there is no
    // status of its own to report. `recordWriteStep` reads `null` as "this
    // step issued no request whose status this layer can see", not as failure.
    return null;
  });

  if (resolved === null) {
    // No home set, so no URL can be built and nothing was addressed. The empty
    // URL is honest: the probe named no collection, so there is none to clean
    // up and none to report for a hand cleanup.
    return { url: "", steps, cleanupVerified: false, stillPresent: null };
  }
  // TypeScript cannot see through the closure assignment above.
  const home = (resolved as ResolvedDavAccount).homeUrl;

  // The one free component, and it is generated here rather than accepted.
  const url = new URL(`${crypto.randomUUID()}/`, home).href;

  // 2. Create — RFC 5689 extended MKCOL, NOT the RFC 4791 calendar-creation
  //    method. See `CREATE_METHOD` for the measurement that forced this:
  //    workerd refuses to build a request carrying that other method at all,
  //    so the helper that issues it threw before any byte left the Worker and
  //    the failure was reported as a connection fault against a server that
  //    never saw it.
  //
  //    Assembled by hand through tsdav's raw request helper, exactly as the
  //    property update below is and for the same reason: the library ships no
  //    helper for this shape.
  const created = await recordWriteStep(
    steps,
    "create",
    CREATE_METHOD,
    async () =>
      firstStatusOf(
        await davRequest({
          url,
          init: {
            method: CREATE_METHOD,
            // Never a credential from here. `./transport.ts` attaches it per
            // call and is the only place that may.
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
                    // The pair that makes the result a CALENDAR collection
                    // rather than a plain one. Without the second element this
                    // creates an ordinary WebDAV collection, which would be a
                    // different question answered by accident.
                    "d:resourcetype": {
                      "d:collection": {},
                      "c:calendar": {},
                    },
                    "d:displayname": PROBE_DISPLAY_NAME,
                    "ca:calendar-color": PROBE_COLOUR,
                  },
                },
              },
            },
          },
          fetch: davFetch,
        }),
      ),
    // The step whose generic 2xx rule is wrong. See `createdBy`.
    createdBy,
  );

  if (!created) {
    // Nothing exists, so there is nothing to clean up and nothing to look for.
    // `stillPresent` stays null rather than false: the probe did not look, and
    // saying "it is gone" without looking is the exact claim this field refuses
    // to make anywhere else in this function.
    return { url, steps, cleanupVerified: false, stillPresent: null };
  }

  // 3. Rename and recolour, in one property update. tsdav ships no PROPPATCH
  //    helper, so the request is assembled by hand through its raw request
  //    helper — which is why `davRequest` is named on the fan-out alternation.
  // The propstat keys iCloud actually answers with, captured on the way past.
  // See `CollectionWriteStep.propKeys`: this is the measurement whose absence
  // shipped a defect, so it is recorded rather than re-guessed.
  let renamePropKeys: string[] | null = null;
  await recordWriteStep(steps, "rename-and-recolour", "PROPPATCH", async () => {
    const responses = await davRequest({
        url,
        init: {
          method: "PROPPATCH",
          headers: {},
          namespace: "d",
          body: {
            "d:propertyupdate": {
              _attributes: {
                "xmlns:d": "DAV:",
                "xmlns:ca": "http://apple.com/ns/ical/",
              },
              "d:set": {
                "d:prop": {
                  "d:displayname": PROBE_RENAMED,
                  "ca:calendar-color": PROBE_RECOLOURED,
                },
              },
            },
          },
        },
      fetch: davFetch,
    });
    const keys = new Set<string>();
    for (const response of responses) {
      const props: unknown = response.props;
      if (props === null || typeof props !== "object") continue;
      for (const key of Object.keys(props as Record<string, unknown>)) {
        keys.add(key);
      }
    }
    renamePropKeys = [...keys].sort();
    return firstStatusOf(responses);
  });
  const renameStep = steps[steps.length - 1];
  if (renameStep !== undefined) renameStep.propKeys = renamePropKeys;

  // 4. Delete. Reached whether or not step 3 was accepted, because a collection
  //    that exists has to be removed either way.
  await recordWriteStep(steps, "delete", "DELETE", async () => {
    const response = await deleteObject({ url, headers: {}, fetch: davFetch });
    return response.status;
  });

  // 5. LOOK AGAIN. The delete's own status is not evidence of a deletion.
  let stillPresent: boolean | null = null;
  await recordWriteStep(steps, "verify", null, async () => {
    const listing = await probeCalendarHome(davFetch, home);
    stillPresent = listing.collections.some((one) => one.href === url);
    // The re-listing's own HTTP status is not surfaced by the enumeration, and
    // this report does not invent one.
    return null;
  });

  return {
    url,
    steps,
    cleanupVerified: stillPresent === false,
    stillPresent,
  };
}

/**
 * Read a to-do object's identity out of a `calendar-data` property.
 *
 * `null` when no UID and no title can be read — a body that will not parse, a
 * response carrying no to-do component, or one whose UID or SUMMARY is absent.
 * Such an object is COUNTED by the caller and never repaired, and never
 * reported with an empty title: a to-do with no readable title cannot answer
 * the question this probe exists to answer, and listing it as though it could
 * would make an unmatchable reminder look like a matched one.
 *
 * Both values are hand-narrowed to non-empty strings for the reason
 * `supportedReportNamesOf` above already gives: the library types this whole
 * region `any`, so the compiler is not watching, and an unexpected object
 * reaching `JSON.stringify` renders as nine characters that read like a real
 * answer.
 *
 * The double read of the raw property is `bodyFor`'s in `./calendar.ts`: the
 * XML layer hands back either the CDATA wrapper or the bare value depending on
 * how the element was written.
 */
function taskIdentityOf(raw: unknown): TaskObjectProbe | null {
  const data =
    raw !== null && typeof raw === "object"
      ? (raw as { _cdata?: unknown })._cdata
      : raw;
  if (typeof data !== "string" || data.length === 0) return null;

  let todo: ReturnType<
    InstanceType<typeof ICAL.Component>["getFirstSubcomponent"]
  >;
  try {
    todo = new ICAL.Component(ICAL.parse(data)).getFirstSubcomponent("vtodo");
  } catch {
    // Nothing is read from the caught value — ./.claude/CLAUDE.md §4.
    return null;
  }
  if (todo === null) return null;

  const uid: unknown = todo.getFirstPropertyValue("uid");
  const summary: unknown = todo.getFirstPropertyValue("summary");
  if (typeof uid !== "string" || uid.length === 0) return null;
  if (typeof summary !== "string" || summary.length === 0) return null;
  return { uid, summary };
}

/**
 * SPIKE-02's object-level half: the to-do items in this account's task
 * collections, with their titles.
 *
 * READ-ONLY. A CalDAV `calendar-query` REPORT writes nothing, and nothing here
 * goes anywhere near `src/mail/`.
 *
 * **It exists because the collection enumeration answers a narrower question
 * than the spike asks.** That field proves a task list is served over CalDAV;
 * the spike's pass condition is that a reminder the owner named on his phone
 * appears in the report this server produced, and no collection-level field can
 * carry a reminder's title. "The named list is present with to-do components"
 * is precisely the narrower substitution the phase's success criterion forbids.
 *
 * **Bounded in both directions, and both bounds are REPORTED when they bite.**
 * At most `MAX_TASK_COLLECTIONS` collections, at most `MAX_TASK_OBJECTS`
 * objects apiece. A cap that answered short without saying so would let a
 * missing reminder look like an absent one.
 *
 * **Strictly serial**: one `calendar-query` per collection, each its own
 * `await` inside a `for ... of`. This is the exact shape
 * `dav-concurrent-request` was written for — a loop over collections is where a
 * combinator gets written, because a combinator is what makes N round trips
 * fast — and every session is a socket's worth of a budget whose exhaustion
 * locks the user out of their own mail on their own devices.
 *
 * The `calendar-data` request is LIMITED to the VTODO component's UID and
 * SUMMARY (RFC 4791 §9.6), which is the smallest thing that can answer the
 * question. A server that honours the limit sends back those two properties; a
 * server that ignores it sends the whole object and the parse above reads the
 * same two values out of it either way.
 *
 * **A collection whose query the server refuses is RECORDED, and the run
 * continues.** This used to let the failure travel to the tool boundary
 * instead, on the reasoning that suppressing it would report a partial answer
 * as a whole one. The reasoning was right about the danger and wrong about the
 * remedy, and the live account proved it: two abandoned lists predating
 * Apple's iOS 13 storage migration answer 404, so the boundary's catch
 * discarded the entire report — every other collection's to-do objects, both
 * services' discovery, all of it — and replaced it with a bare category. The
 * remedy for "a partial answer must not read as a whole one" is to SAY which
 * part is missing, which is neither swallowing nor aborting: the entry stays
 * in the list, named, carrying no objects and carrying its refusal's category.
 *
 * A refusal before any collection is reached — discovery, or the home
 * listing — is recorded on the probe itself for the same reason, so the
 * report survives that too.
 *
 * Nothing here is logged. This module contains no logging calls of any kind.
 */
export async function runTaskCollectionProbe(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<TaskCollectionProbe> {
  // Discovery and the home listing, recorded rather than thrown. A refusal
  // here means no collection was ever asked, which the probe's own `category`
  // says — and the surrounding report survives to be read.
  let home: Awaited<ReturnType<typeof probeCalendarHome>>;
  try {
    const resolved = await resolveDavAccount(env, principal, davFetch, "caldav");
    home = await probeCalendarHome(davFetch, resolved.homeUrl);
  } catch (err) {
    // The TYPE is read; the value never is — ./.claude/CLAUDE.md §4.
    return {
      collectionsFound: 0,
      collectionsVisited: 0,
      collections: [],
      category: davToErrorCategory(err).category,
    };
  }

  const found = home.collections.filter((one) =>
    one.components.includes("VTODO"),
  );
  const visiting = found.slice(0, MAX_TASK_COLLECTIONS);

  const collections: TaskCollectionEntry[] = [];
  // One collection at a time, one await each. No combinator, and nothing that
  // resembles one.
  for (const collection of visiting) {
    let responses: DAVResponse[];
    try {
      responses = await calendarQuery({
        url: collection.href,
        props: {
          "d:getetag": {},
          "c:calendar-data": {
            "c:comp": {
              _attributes: { name: "VCALENDAR" },
              "c:comp": {
                _attributes: { name: "VTODO" },
                "c:prop": [
                  { _attributes: { name: "UID" } },
                  { _attributes: { name: "SUMMARY" } },
                ],
              },
            },
          },
        },
        filters: {
          "c:comp-filter": {
            _attributes: { name: "VCALENDAR" },
            "c:comp-filter": { _attributes: { name: "VTODO" } },
          },
        },
        depth: "1",
        headers: {},
        fetch: davFetch,
      });
    } catch (err) {
      // This collection was asked and refused. Recorded and named, so the
      // reader can tell it apart from a collection that holds nothing — and
      // the loop goes on to the next one, because one dead list must not cost
      // the whole account's answer. The TYPE is read; the value never is.
      collections.push({
        href: collection.href,
        displayName: collection.displayName,
        objectCount: 0,
        truncated: false,
        unparsed: 0,
        objects: [],
        category: davToErrorCategory(err).category,
      });
      continue;
    }

    const objects: TaskObjectProbe[] = [];
    let unparsed = 0;
    for (const response of responses) {
      if (objects.length >= MAX_TASK_OBJECTS) break;
      const identity = taskIdentityOf(response.props?.calendarData);
      if (identity === null) {
        unparsed += 1;
        continue;
      }
      objects.push(identity);
    }

    collections.push({
      href: collection.href,
      displayName: collection.displayName,
      objectCount: responses.length,
      truncated: responses.length > objects.length + unparsed,
      unparsed,
      objects,
      // The server answered. An empty list here means the collection really
      // holds no to-do objects, which is why this must not be conflated with
      // the refusal branch above.
      category: null,
    });
  }

  return {
    collectionsFound: found.length,
    collectionsVisited: visiting.length,
    collections,
    category: null,
  };
}

// ---------------------------------------------------------------------------
// Reading property NAMES out of the RAW multistatus body
//
// THE RULE THIS SECTION EXISTS FOR. **The DAV library's parsed property region is
// the EMPTY OBJECT whenever the library could not parse a multistatus out of the
// answer at all.** An empty body, a content type that does not say xml, or a root
// element that is not `multistatus`: in every one of those cases `davRequest`
// returns an ordinary-looking SUCCESSFUL response object carrying a `raw` field
// and no `props` at all, so `Object.keys(response.props ?? {})` is `[]` — which is
// the identical reading to a server that answered properly and named nothing. The
// two cannot be told apart through the parse, in either direction. The parse also
// discards every propstat whose status is not 2xx, which is a second way for the
// region to come back empty while the server named plenty.
//
// TWO SYMPTOMS, ONE DAY APART, ONE CAUSE.
//
//  1. Plan 17-04's PROPPATCH reader in `./calendar.ts` decided which properties a
//     rename-and-recolour had landed by looking for their keys in that region.
//     Measured live on 2026-09-25: the region was empty on every SUCCESSFUL write,
//     so `calendar_update_calendar` reported `connection_failed` three times in a
//     row while the calendar was renamed and recoloured each time.
//     `CollectionWriteStep.propKeys` above is that measurement;
//     `./calendar.ts`'s house note above `observedOutcomes` carries the retirement.
//  2. This probe, measured live on 2026-09-25 and again with the discovery cache
//     cleared: all four `DAV:propname` targets answered `names: []` with a null
//     category, against an account that unquestionably carries `displayname` and
//     `resourcetype` on all four. Same empty region, same null-looking health.
//
// WHAT THE CAUSE IS NOT, recorded because the obvious guess is wrong and was
// believed on the way here. It is NOT that the parse drops a property carrying no
// value. That was CHECKED, by driving the library's own parse with a conformant
// valueless propstat: the keys survive it intact. So asking the parse more
// carefully cannot work, and neither can a table of key spellings — 17-04 already
// retired one of those.
//
// SO: ANY DAV QUESTION OF THE FORM "WHAT PROPERTIES EXIST HERE" MUST READ THE RAW
// BODY. A question of the form "what is this property's VALUE" may keep using the
// parse, because a value that arrives at all arrives parsed, and the whole rest of
// this module does exactly that.
// ---------------------------------------------------------------------------

/**
 * The length at which the DAV library truncates a raw body it hands back.
 *
 * A library constant restated here rather than imported, because it is not
 * exported. It is used for ONE thing: deciding whether `reading` should say the
 * names are short. Being wrong about it can only mislabel a boundary case, never
 * drop a name, and a body that long against a `propname` answer has never been
 * seen — but silent truncation is exactly the failure class this whole fix exists
 * to remove, so it is detected rather than assumed away.
 */
const RAW_BODY_CAP = 4096;

/** The ceiling on element names one unreadable body may report back. */
const MAX_BODY_ELEMENTS = 40;

/** `reading`: asked, answered, and `names` holds what the answer named. */
const READING_NAMES = "names_read";
/** `reading`: the same, but the body was capped, so `names` may be short. */
const READING_TRUNCATED = "names_read_truncated";
/** `reading`: asked and answered, and no propstat was found in the answer. */
const READING_UNREADABLE = "unreadable_response";
/** `reading`: asked and refused. `category` says how. */
const READING_REFUSED = "refused";
/** `reading`: no such row in the account's own listing, so nothing was asked. */
const READING_NOT_ASKED = "not_asked";

/**
 * The status NUMBER inside a DAV status line, and nothing else from it.
 *
 * Three digits out, everything else discarded on the spot. This is the one place
 * in this reading that looks at an element's text content, and it is confined to
 * the `DAV:status` element of a propstat — never to a property element, whose text
 * is where a VALUE would be. `./../../.claude/CLAUDE.md` § 4 forbids a diagnostic
 * field echoing a server's status line; a number is not one, and it is already what
 * `CollectionWriteStep.status` reports.
 *
 * `null` when the text does not carry a status line this run can read, which is a
 * fact worth reporting rather than a reason to guess at one.
 */
function statusNumberOf(text: string): number | null {
  const match = /HTTP\/\d(?:\.\d)?\s+(\d{3})\b/i.exec(text);
  if (match === null) return null;
  const status = Number.parseInt(match[1], 10);
  return Number.isNaN(status) ? null : status;
}

/** An element's local name — the namespace prefix, if any, removed. */
function localNameOf(name: string): string {
  const colon = name.indexOf(":");
  return colon === -1 ? name : name.slice(colon + 1);
}

/** What one walk over a raw multistatus body found. */
interface BodyReading {
  /** One entry per propstat that carried a `prop` element, in document order. */
  propstats: PropertyNameBlock[];
  /** Every element name the body carried, deduped, capped, in document order. */
  elements: string[];
}

/**
 * Every property NAME a raw multistatus body carried, by propstat block.
 *
 * **NAMES ONLY, and that is the safety property rather than a convenience.** The
 * walk records an element's NAME and steps over everything between one tag and the
 * next. The single exception is `statusNumberOf` above, which reads the text of a
 * propstat's own `DAV:status` element and keeps three digits from it. No other text
 * content and no attribute value is read anywhere, so no property value can ride
 * out of this function no matter what the server put in the body — which is what
 * makes the whole probe safe to point at a real account, and it now holds against
 * a server that answered with values rather than only against one that did not.
 *
 * **A property name is a DIRECT child of a `prop` element that is itself a direct
 * child of a `propstat`.** That is what excludes the contents of a property: an
 * href inside `schedule-default-calendar-URL` is a grandchild of `prop`, so it is
 * never mistaken for a property, and its text is never read either way.
 *
 * **Every propstat is reported, whatever its status**, which is the second reason
 * this reads the body rather than the parse — see the section above. The status is
 * carried on the block so a reader can tell "this resource has the property and
 * will not disclose it" from "this resource has never heard of it", and the union
 * across blocks is what the target's own `names` reports.
 *
 * Hand-rolled rather than handed to an XML parser, and the reason is not
 * preference: the only parser in this dependency tree is the one whose parse this
 * fix exists to stop trusting, and adding a second XML library to read four
 * diagnostic responses would be a larger decision than the defect warrants. The
 * walk handles the four things a real body contains that a naive scan gets wrong —
 * comments, CDATA, processing instructions and a `>` inside a quoted attribute
 * value — and stops cleanly at a tag with no end, which is what a capped body ends
 * in. A propstat left unterminated by that stop is still reported, because its
 * names were already read and dropping them would under-report a truncation
 * instead of labelling it.
 */
function propertyNamesInBody(body: string): BodyReading {
  const propstats: PropertyNameBlock[] = [];
  const elements = new Set<string>();
  /** The LOCAL names of the elements currently open, outermost first. */
  const open: string[] = [];
  /** The propstat being read, or `null` between them. */
  let current: { status: number | null; names: Set<string>; sawProp: boolean } | null =
    null;

  /** Close the propstat being read, keeping it only if it carried a `prop`. */
  const flush = (): void => {
    if (current !== null && current.sawProp) {
      propstats.push({
        status: current.status,
        names: [...current.names].sort(),
      });
    }
    current = null;
  };

  let at = 0;
  while (at < body.length) {
    const next = body.indexOf("<", at);
    if (next === -1) break;
    at = next;

    // The four non-element constructs, stepped over without reading anything out
    // of them. A comment or a CDATA section may contain any characters at all,
    // including whole tags, so skipping them is correctness rather than tidiness.
    if (body.startsWith("<!--", at)) {
      const close = body.indexOf("-->", at);
      if (close === -1) break;
      at = close + 3;
      continue;
    }
    if (body.startsWith("<![CDATA[", at)) {
      const close = body.indexOf("]]>", at);
      if (close === -1) break;
      at = close + 3;
      continue;
    }
    if (body.startsWith("<?", at)) {
      const close = body.indexOf("?>", at);
      if (close === -1) break;
      at = close + 2;
      continue;
    }
    if (body.startsWith("<!", at)) {
      const close = body.indexOf(">", at);
      if (close === -1) break;
      at = close + 1;
      continue;
    }

    const closing = body.startsWith("</", at);
    let cursor = at + (closing ? 2 : 1);
    const nameStart = cursor;
    while (cursor < body.length && !/[\s/>]/.test(body[cursor])) cursor += 1;
    const name = body.slice(nameStart, cursor);

    // The end of the tag, honouring quoted attribute values: `>` is legal inside
    // one, so scanning for the next `>` alone would end the tag early.
    let quote = "";
    let tagEnd = -1;
    while (cursor < body.length) {
      const char = body[cursor];
      if (quote !== "") {
        if (char === quote) quote = "";
      } else if (char === '"' || char === "'") {
        quote = char;
      } else if (char === ">") {
        tagEnd = cursor;
        break;
      }
      cursor += 1;
    }
    // A tag with no end. The body was cut mid-tag, so there is nothing further to
    // read and nothing half-read is recorded.
    if (tagEnd === -1) break;
    const selfClosing = body[tagEnd - 1] === "/";
    at = tagEnd + 1;
    if (name === "") continue;

    const local = localNameOf(name);

    if (closing) {
      // Pop to the matching open element rather than popping one, so a body with
      // an unclosed element cannot leave the stack permanently out of step.
      const found = open.lastIndexOf(local);
      if (found !== -1) open.length = found;
      if (local === "propstat") flush();
      continue;
    }

    if (elements.size < MAX_BODY_ELEMENTS) elements.add(name);

    const parent = open[open.length - 1];
    const grandparent = open[open.length - 2];

    if (local === "propstat") {
      // A malformed body could nest one; the outer one's names are kept.
      flush();
      current = { status: null, names: new Set<string>(), sawProp: false };
      // `<propstat/>` carries no prop and therefore no names.
      if (selfClosing) current = null;
    } else if (current !== null && local === "prop" && parent === "propstat") {
      // Recorded on entry rather than on a name, so `<prop/>` and `<prop></prop>`
      // both mean "answered, and named nothing" instead of "unreadable".
      current.sawProp = true;
    } else if (current !== null && parent === "prop" && grandparent === "propstat") {
      current.names.add(name);
    } else if (
      current !== null &&
      local === "status" &&
      parent === "propstat" &&
      !selfClosing
    ) {
      // The one text read in this walk, and only three digits survive it.
      const textEnd = body.indexOf("<", at);
      current.status = statusNumberOf(
        textEnd === -1 ? body.slice(at) : body.slice(at, textEnd),
      );
    }

    if (!selfClosing) open.push(local);
  }

  // A propstat the stop above left open. See the docstring: its names were read.
  flush();

  return { propstats, elements: [...elements].sort() };
}

/**
 * One target of the property-name probe, before it is asked.
 *
 * `contained` says whether the href arrived from the WIRE, which is what decides
 * whether `assertUnderHome` can be run against it at all — see the probe's own
 * docstring for why that is not the same question as "is it caller-supplied".
 */
interface PropertyNameAsk {
  target: string;
  href: string;
  contained: boolean;
}

/**
 * Ask four of this account's resources what property NAMES they carry.
 *
 * ## WHAT IT MEASURED: iCloud does not implement `DAV:propname`
 *
 * This probe was built to answer an open question and the question is CLOSED. Run
 * against the owner's real account on deploy `1fce400b`, it sends a
 * correctly-formed `<d:propfind xmlns:d="DAV:"><d:propname/></d:propfind>` at
 * `Depth: 0` — the element as a CHILD of `propfind` and not inside `prop`,
 * verified against the request the library actually assembles — and iCloud answers
 * **207 with an empty 200 block and a 404 block naming `propname` ITSELF**. The
 * server read `propname` as the NAME OF A PROPERTY BEING REQUESTED. RFC 4918 § 9.1
 * defines it as a request MODE; iCloud treats it as a property name.
 *
 * So the exhaustive-enumeration route does not exist on this server, and
 * `DAV:allprop` cannot substitute: § 9.1 returns dead properties plus the live
 * properties RFC 4918 ITSELF defines, so a CalDAV live property needs `<include>`,
 * and `include` requires NAMING the property — which is a targeted ask and not an
 * enumeration. **There is therefore no WebDAV mechanism to enumerate live
 * properties exhaustively against iCloud, and a targeted ask at the location the
 * relevant RFC defines is the strongest evidence this protocol permits.**
 *
 * That measurement is what withdrew CALM-07, on 2026-09-26: the requirement asked
 * for a local refusal of the account's default calendar, iCloud answers null for
 * `schedule-default-calendar-URL` both on the calendar home and on the scheduling
 * inbox where RFC 6638 § 9.2 defines it, and this probe closed the remaining "but
 * is there some OTHER property" by showing the question cannot be asked. The
 * domain fact behind every null: Apple's "Default Calendar" is a PER-DEVICE
 * setting, so there is no account-side value to serve.
 *
 * **It is KEPT rather than retired with the requirement it settled**, and that is
 * the point of this section. The finding above is a permanent, reusable fact about
 * THIS server — the next time anyone wonders what properties an iCloud resource
 * carries, the answer is "it will not tell you, and here is the instrument that
 * established that". Deleting the instrument would leave the fact as a claim in
 * prose with nothing behind it, and the first session to doubt it would rebuild
 * this probe from scratch. `resolveDefaultCalendarUrl` is kept on the same
 * footing.
 *
 * READ-ONLY. `DAV:propname` (RFC 4918 § 9.1) asks for names, this reading takes
 * names, and no text content or attribute value is read out of the answer at any
 * point — so there is no value in the response for this code to mishandle even if
 * the server sends one. It writes nothing, and it goes nowhere near `src/mail/`.
 *
 * **The ANSWER is read out of the raw body, never out of the library's parse.**
 * That is the whole of plan 17-05's fix and the section above
 * `propertyNamesInBody` carries the rule behind it. The REQUEST is untouched: the
 * library still assembles the `propname` body from the object below, so the bytes
 * that leave this Worker are the bytes the two live runs on 2026-09-25 sent.
 *
 * **Four targets, depth 0 each, and every one derived from the account's own
 * resolved discovery.** The principal, the calendar home, the scheduling inbox,
 * and one real calendar. The last two are READ OFF the home listing by their
 * advertised resource type rather than constructed from a string, because a URL
 * this server assembled from a pattern would agree with reality right up until
 * the moment the answer mattered — the argument this module's header already
 * makes about the shard host. The calendar is reported BY HREF, so the reading is
 * reproducible against the same collection later.
 *
 * **TOTAL, never throwing.** Every refusal folds into the returned value: per
 * target when a target was asked and refused, on the probe itself when nothing
 * could be derived at all. That is the contract the two probes above already
 * obey and it is not a convenience — this module's header says a diagnostic that
 * discards its measurements at the first problem is useless for the one job it
 * has, and the live account has already proved it, answering 404 on two abandoned
 * collections and costing an entire report.
 *
 * **Strictly serial**: one `for ... of`, one `await` per target, no combinator
 * and nothing resembling one. Four round trips plus discovery and the listing is
 * already most of a per-invocation connection budget, and iCloud's own per-account
 * ceiling is lower, undocumented and deliberately unmeasured.
 *
 * ## Containment, and the one target it cannot cover
 *
 * The two hrefs that came off the WIRE — the scheduling inbox and the calendar —
 * are passed through `assertUnderHome` against this account's own resolved home
 * before anything is requested, because `./transport.ts` attaches the Apple ID
 * and the app-specific password to whatever URL it is handed and "the server said
 * so" is not an authorisation. The enumeration resolves a relative href against
 * the home and drops one that will not resolve, but it does not check ORIGIN, so
 * an absolute href naming another host would otherwise survive it. A refusal
 * arrives as the same typed class every other not-found does and becomes that
 * target's category, which is why it is inside the per-target `try`.
 *
 * **The home URL is the base, so there is nothing above it to be contained by** —
 * the claim `fetchCollections`' own exemption makes one module over.
 *
 * **The principal is NOT under the home set and cannot be made to be, so no
 * containment claim is asserted on it and this is what stands in its place.** It
 * sits on the unsharded DISCOVERY ENTRY host while every collection on the account
 * sits on the account's own `pXX-` shard, which is the host the home URL carries —
 * the trap `resolveDefaultCalendarUrl` records at length, and the reason it
 * resolves a relative inbox href against the home rather than the principal.
 * Running `assertUnderHome(principalUrl, homeUrl)` would therefore refuse a URL
 * this account genuinely owns, on an origin mismatch, every single time. What
 * protects it instead is where it came from: `resolveDavAccount` produced it for
 * THIS principal, and it is the very same URL `resolveDefaultCalendarUrl` already
 * requests without a containment check. Writing a check that cannot hold would be
 * worse than writing none, because the next reader would believe it.
 *
 * ## What the caller cannot aim
 *
 * Nothing. The whole input is one boolean saying whether to run. No host, no
 * path, no identifier and no name crosses the tool boundary, which is why the
 * containment gate carries this site as exempt-with-a-reason rather than checked.
 *
 * Nothing here is logged. This module contains no logging calls of any kind, and
 * no server's status line, response body or URL reaches any error report — only a
 * category, dispatched on the error's TYPE.
 */
export async function runPropertyNameProbe(
  env: Env,
  principal: Principal,
  davFetch: DavFetch,
): Promise<PropertyNameProbe> {
  // Discovery and the home listing, recorded rather than thrown, exactly as the
  // to-do probe records them. A refusal here means no resource was ever asked.
  let resolved: ResolvedDavAccount;
  let home: Awaited<ReturnType<typeof probeCalendarHome>>;
  try {
    resolved = await resolveDavAccount(env, principal, davFetch, "caldav");
    home = await probeCalendarHome(davFetch, resolved.homeUrl);
  } catch (err) {
    // The TYPE is read; the value never is — ./.claude/CLAUDE.md §4.
    return { targets: [], category: davToErrorCategory(err).category };
  }

  // Both read OFF the listing by advertised resource type, never constructed.
  // `scheduleInbox` is how the library spells RFC 6638's inbox resource type
  // once it has stripped the namespace prefix — measured live on 2026-09-25,
  // and recorded on `DavCollectionProbe.scheduleDefaultCalendarUrl`.
  const inbox = home.collections.find((one) =>
    one.resourceTypes.includes("scheduleInbox"),
  );
  // The FIRST calendar collection, whichever the listing put first. Which one it
  // is does not matter to the question and the href says which it was.
  const calendar = home.collections.find((one) =>
    one.resourceTypes.includes("calendar"),
  );

  const asks: PropertyNameAsk[] = [
    // Not contained, and the docstring above says at length why a check here
    // cannot hold rather than merely why one is absent.
    { target: "principal", href: resolved.principalUrl, contained: false },
    // The base itself. Nothing above it to be contained by.
    { target: "home", href: resolved.homeUrl, contained: false },
    { target: "schedule-inbox", href: inbox?.href ?? "", contained: true },
    { target: "calendar", href: calendar?.href ?? "", contained: true },
  ];

  const targets: PropertyNameTarget[] = [];
  // One target at a time, one await each. No combinator, and nothing that
  // resembles one.
  for (const ask of asks) {
    if (ask.href === "") {
      // The listing held no such row, so nothing was asked. `not_asked` is that
      // state, and it is a different fact from a refusal, a different fact again
      // from an answer nobody could read, and a different fact again from an
      // empty list of names.
      targets.push({
        target: ask.target,
        href: "",
        reading: READING_NOT_ASKED,
        names: null,
        blocks: null,
        status: null,
        bodyChars: null,
        bodyElements: null,
        category: null,
      });
      continue;
    }

    try {
      if (ask.contained) assertUnderHome(ask.href, resolved.homeUrl);
      const responses = await davRequest({
        url: ask.href,
        // The library must NOT parse the answer. Its parse is what lost the
        // reading — see the section above `propertyNamesInBody` — and with this
        // false it hands back the response text instead, which is what the
        // property names are read out of. The REQUEST is unchanged: the body is
        // still assembled by the library from the object below, so the bytes that
        // go out are the same bytes the live runs on 2026-09-25 sent.
        parseOutgoing: false,
        init: {
          method: "PROPFIND",
          // The WebDAV depth header, and nothing else. Never a credential from
          // here: `./transport.ts` attaches it per call and is the only place
          // that may.
          headers: { depth: "0" },
          namespace: "d",
          // RFC 4918 § 9.1: `propname` is a CHILD of `propfind` rather than a
          // property inside `prop`, which is why the library's own `propfind`
          // helper cannot express it — that helper always wraps what it is
          // given in a `prop` element.
          body: {
            "d:propfind": {
              _attributes: { "xmlns:d": "DAV:" },
              "d:propname": {},
            },
          },
        },
        fetch: davFetch,
      });
      // The RAW body, and the answer is read out of it rather than out of the
      // library's parse. `parseOutgoing: false` is what makes the library hand it
      // over: the section above `propertyNamesInBody` records why the parse cannot
      // answer this question, and the two symptoms that proved it. Hand-narrowed,
      // because the library types `raw` as `any` and an absent one must read as an
      // empty answer rather than throw.
      const first = responses[0];
      const raw: unknown = first?.raw;
      const body = typeof raw === "string" ? raw : "";
      const status = typeof first?.status === "number" ? first.status : null;
      const reading = propertyNamesInBody(body);

      if (reading.propstats.length === 0) {
        // Answered, and this run could not find a propstat in the answer. The
        // state that had no name before 2026-09-25, when four targets reported an
        // empty list of names and nothing said the list was not a reading.
        targets.push({
          target: ask.target,
          href: ask.href,
          reading: READING_UNREADABLE,
          names: null,
          blocks: null,
          status,
          bodyChars: body.length,
          // Element names only. See `PropertyNameTarget.bodyElements` for the § 4
          // argument, and for why an excerpt of the body was refused.
          bodyElements: reading.elements,
          category: null,
        });
        continue;
      }

      // The union across every propstat, whatever its status, sorted.
      const names = new Set<string>();
      for (const block of reading.propstats) {
        for (const name of block.names) names.add(name);
      }
      targets.push({
        target: ask.target,
        href: ask.href,
        reading:
          body.length > RAW_BODY_CAP ? READING_TRUNCATED : READING_NAMES,
        names: [...names].sort(),
        blocks: reading.propstats,
        status,
        bodyChars: body.length,
        bodyElements: null,
        category: null,
      });
    } catch (err) {
      // This resource was asked and refused, or its href was refused by the
      // containment check before it could be asked. Either way the run goes on
      // to the next target: one dead resource must not cost the whole reading.
      // The TYPE is read; the value never is.
      targets.push({
        target: ask.target,
        href: ask.href,
        reading: READING_REFUSED,
        names: null,
        blocks: null,
        status: null,
        bodyChars: null,
        bodyElements: null,
        category: davToErrorCategory(err).category,
      });
    }
  }

  return { targets, category: null };
}
