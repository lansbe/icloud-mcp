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
  /** CardDAV only: the report names this account's address books advertise. */
  reports: string[] | null;
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
 * Count the calendar collections in a home set with ONE request.
 *
 * `propfind` at depth 1 rather than tsdav's `fetchCalendars`, and the reason is
 * the connection budget rather than style: `fetchCalendars` wraps a `Promise.all`
 * that issues one ADDITIONAL PROPFIND per calendar to read its supported report
 * set. The gate in `./transport.ts` would serialise that fan-out, so it would
 * be correct — but it would still cost one round trip per calendar to produce a
 * number, and a personal account has half a dozen calendars.
 */
async function countCalendars(
  davFetch: DavFetch,
  homeUrl: string,
): Promise<number> {
  const responses = await propfind({
    url: homeUrl,
    props: { "d:resourcetype": {}, "d:displayname": {} },
    depth: "1",
    headers: {},
    fetch: davFetch,
  });

  return responses.filter((response) =>
    Object.keys(response.props?.resourcetype ?? {}).includes("calendar"),
  ).length;
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
  davFetch: DavFetch,
  options: { refresh: boolean },
): Promise<DavDiagnosticOutcome> {
  const report = emptyReport(options.refresh);

  try {
    if (options.refresh) await clearDavCache(env);

    for (const service of DAV_SERVICES) {
      await runOneService(env, davFetch, service, report[service]);
    }
  } catch (err) {
    return { report, failed: true, error: err };
  }

  return { report, failed: false, error: null };
}

async function runOneService(
  env: Env,
  davFetch: DavFetch,
  service: DavService,
  into: DavServiceReport,
): Promise<void> {
  const discoveryStart = Date.now();
  const resolved = await resolveDavAccount(env, davFetch, service);
  into.timings.discoveryMs = Date.now() - discoveryStart;
  fillResolved(into, resolved);

  const collectionsStart = Date.now();
  if (service === "caldav") {
    into.calendarCount = await countCalendars(davFetch, resolved.homeUrl);
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
