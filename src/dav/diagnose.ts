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

import { fetchAddressBooks, propfind } from "tsdav";
import type { Env } from "../env";
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
  timings: DavServiceTimings;
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
