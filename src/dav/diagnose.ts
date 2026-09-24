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
// `makeCalendar` is deliberately NOT imported. It is tsdav's collection-creation
// helper and it issues `MKCALENDAR`, which this runtime refuses to build a
// request from — see `CREATE_METHOD` below for the measurement. It stays on the
// `dav-concurrent-request` alternation in `scripts/forbidden-tokens.mjs` so a
// future call site is guarded the moment it appears; nothing here calls it.
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
   * memory.** The create step does not send `MKCALENDAR` — this runtime
   * refuses to build a request carrying that method — so it sends RFC 5689
   * extended `MKCOL` instead. A server may accept one and refuse the other, so
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
    calendarCount: null,
    addressBookCount: null,
    reports: null,
    collections: null,
    collectionWrite: null,
    taskObjects: null,
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
// The two opt-in probes (Phase 14: SPIKE-04 and SPIKE-02's object-level half).
//
// Both are OFF by default, both are reached only through their own named
// boolean on `dav_diagnose`, and neither takes a URL, an identifier or a name
// from any caller. Both are strictly SERIAL — a `for ... of` with its own
// `await`, never a concurrent combinator. `dav-concurrent-request` names both
// of them and all four library primitives they call, and those names went onto
// that alternation before either function was written, because a name omitted
// from it is invisible to every assertion in the suite.
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
 * RFC 4791 defines `MKCALENDAR` for exactly this, and tsdav ships a helper that
 * issues it. **Neither can be used here: workerd refuses to build a request
 * carrying that method string.** It is the one method in this project's whole
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
 * rather than leaving it to be inferred.** A server may accept `MKCALENDAR`
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
 * **`207` is the trap, and it is a trap this change introduced.** `MKCALENDAR`
 * either works or fails with a plain status; extended `MKCOL` has a third
 * answer. RFC 5689 §3 makes the request all-or-nothing — a server that cannot
 * satisfy every property in the body MUST fail the whole request and MUST NOT
 * create the collection — and it reports that partial failure as a `207
 * Multi-Status` whose body says which property was refused. So `207` here means
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
    steps.push({ step, method, status, ok, category: null });
    return ok;
  } catch (err) {
    // The TYPE is read; the value never is.
    steps.push({
      step,
      method,
      status: null,
      ok: false,
      category: davToErrorCategory(err).category,
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
 * **Step 2 is not `MKCALENDAR`, and that is a platform fact rather than a
 * preference.** workerd refuses to build a request carrying that method string
 * — see `CREATE_METHOD` — so what it answers about iCloud is unmeasurable from
 * this runtime. The step records the method it did use, because a report that
 * named only the status would be read as an answer about the method it did
 * not.
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

  // 2. Create — RFC 5689 extended MKCOL, NOT MKCALENDAR. See `CREATE_METHOD`
  //    for the measurement that forced this: workerd refuses to build a
  //    request carrying `MKCALENDAR` at all, so the helper that issues it
  //    threw before any byte left the Worker and the failure was reported as
  //    a connection fault against a server that never saw it.
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
  await recordWriteStep(steps, "rename-and-recolour", "PROPPATCH", async () =>
    firstStatusOf(
      await davRequest({
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
      }),
    ),
  );

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
