// The tracer's proof: ONE `dav_diagnose` call, end to end, through every layer
// this phase will build on.
//
// This is deliberately not a per-layer unit test. It drives the registered tool
// callback through the response shaper, the discovery policy, the KV cache and
// the serialised transport, against a stub `fetch` returning canned PROPFIND
// `207` bodies. Task 3's two suites take the layers apart; this one asserts
// that assembled, they answer the question D-54 exists to answer.
//
// No network and no real credentials. D-09 forbids any automated job
// authenticating against the real Apple ID, so the seam the tests use is the
// same one production uses: tsdav resolves `fetchOverride ?? fetch`, and this
// project's `davFetch` is that override.

import type { McpServer } from "@modelcontextprotocol/server";
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
import { SAFE_MESSAGES } from "../src/errors";
import type { DavDiagnosticOutcome } from "../src/dav/diagnose";
import type { DavCollectionProbe } from "../src/dav/diagnose";
import {
  runCollectionWriteProbe,
  runDavDiagnosticOutcome,
} from "../src/dav/diagnose";
// The listing, driven against the SAME stub as the diagnostic. Pitfall 57's
// quieter half is that loosening the listing's component filter would make
// reminder lists show up as calendars with no events; asserting both answers
// off one fixture is what makes a drift between them visible here.
import { listCalendars } from "../src/dav/calendar";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { createDavFetch } from "../src/dav/transport";
import { createServerFactory } from "../src/mcp/server";
import {
  davDiagnosticResult,
  registerDavDiagnoseTool,
} from "../src/mcp/tools/dav-diagnose";
import {
  FAKE_APP_PASSWORD,
  FAKE_APPLE_ID,
  ownerPrincipal,
  refusedPrincipal,
} from "./fixtures/bound-secrets";
import { assertMethodIsBuildable } from "./fixtures/sendable-method";
import type { Principal } from "../src/principal";

/**
 * The RFC 4791 calendar-creation method this runtime refuses to build.
 *
 * **Assembled from fragments, and the assembly is the point rather than an
 * accident.** That method's name is a forbidden token in every scanned root —
 * `src/`, `scripts/` and `test/` alike, with no scope and no file exclusion —
 * so a source file that SPELLS it fails the commit hook. Joining two fragments
 * puts the identical string in this constant at runtime while leaving no
 * contiguous literal for the scan to find. ONE construction per file, here,
 * rather than six inline ones: that is the same discipline the socket and write
 * choke-points already use, and it means a later reader has one thing to
 * understand instead of six.
 *
 * **Do NOT "tidy" this into a plain string literal.** `scripts/forbidden-tokens.mjs`
 * warns in its own header that a concatenation written to dodge self-matching
 * reads as an accident and gets cleaned up by the next person through, so this
 * says it outright: collapsing the join does not tidy the file, it breaks the
 * pre-commit hook and stops every commit that touches this tree until it is put
 * back. The permitted answer for a legitimate mention is at the SOURCE — build
 * the string, or name the method by its role — and never by narrowing the
 * pattern or adding the file to the scan's exclusions. `.claude/CLAUDE.md`
 * § Enforcement is the authority, and it is explicit: never make the rule see
 * less.
 *
 * The cases below construct it ON PURPOSE. They are what keeps SPIKE-04's
 * platform verdict honest — they ask the runtime whether it will build a
 * request carrying this method and watch it refuse — so the construction is
 * load-bearing test code rather than a mention. `.planning/PROJECT.md`'s
 * SPIKE-04 row is the authority for the constraint itself.
 */
const REFUSED_CREATE_METHOD = ["MK", "CALENDAR"].join("");

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
//
// CalDAV lands on partition 42 and CardDAV on partition 61 — DIFFERENT numbers,
// on purpose. The partition is per-account AND per-service, so a fixture where
// they happened to match would let a "derive the second from the first" bug pass
// every case here. One case below pins the matching-partition shape separately.
// ---------------------------------------------------------------------------

const CALDAV_ROOT = "https://caldav.icloud.com/";
const CARDDAV_ROOT = "https://contacts.icloud.com/";
const PRINCIPAL_PATH = "/1234567890/principal/";
const CALDAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";
const CARDDAV_HOME = "https://p61-contacts.icloud.com/1234567890/carddavhome/";
const ADDRESS_BOOK_A = `${CARDDAV_HOME}card/`;
const ADDRESS_BOOK_B = `${CARDDAV_HOME}collection/`;

const XML_HEADERS = { "content-type": "text/xml; charset=utf-8" };

function multistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CARD="urn:ietf:params:xml:ns:carddav">${body}</multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

function principalBody(): string {
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`;
}

function calendarHomeBody(home: string): string {
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${home}</href></C:calendar-home-set></prop></propstat></response>`;
}

function addressBookHomeBody(home: string): string {
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><CARD:addressbook-home-set><href>${home}</href></CARD:addressbook-home-set></prop></propstat></response>`;
}

/**
 * A supported-report-set property carrying the named reports.
 *
 * Spelt the way iCloud spells it — one `supported-report` wrapper per report,
 * each holding a `report` element whose single child names it. tsdav strips the
 * namespace and camel-cases the name, so `<C:calendar-query/>` arrives as the
 * string `calendarQuery`.
 */
function reportSetProp(...reports: string[]): string {
  const entries = reports
    .map((report) => `<supported-report><report>${report}</report></supported-report>`)
    .join("");
  return `<supported-report-set>${entries}</supported-report-set>`;
}

/**
 * A supported-calendar-component-set property naming the given components.
 *
 * Same spelling `test/dav-calendar.test.ts` uses, because the two halves are
 * reading the same property off the same request and a fixture that spelt it
 * differently would prove nothing about the real one.
 */
function componentSetProp(...components: string[]): string {
  const comps = components
    .map((component) => `<C:comp name="${component}"/>`)
    .join("");
  return `<C:supported-calendar-component-set>${comps}</C:supported-calendar-component-set>`;
}

/** One `response` element for a collection carrying the calendar resourcetype. */
function calendarCollection(href: string, name: string, extra: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/><C:calendar/></resourcetype><displayname>${name}</displayname>${extra}</prop></propstat></response>`;
}

/** The home collection itself, which is not a member of the home set. */
function homeSelfResponse(): string {
  return `<response><href>${CALDAV_HOME}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/></resourcetype></prop></propstat></response>`;
}

/**
 * Three calendars, a reminder list, and the home collection itself.
 *
 * The three calendars advertise OVERLAPPING but not identical report sets, so
 * the union the diagnostic reports has to de-duplicate to be right — an
 * implementation that concatenated would pass against a fixture where every
 * collection said the same thing.
 *
 * **The three calendars declare no component set and the reminder list declares
 * `VTODO`**, which is the shape that makes the three numbers in play here
 * visibly different from one another: four collections carry the calendar
 * resourcetype, `calendar_list_calendars` shows three of them, and the
 * enumeration shows all four. A fixture where those numbers agreed could not
 * tell a diagnostic that sees the reminder list from one that does not.
 */
function calendarListBody(): string {
  return (
    homeSelfResponse() +
    calendarCollection(
      `${CALDAV_HOME}home/`,
      "Home",
      reportSetProp("<C:calendar-query/>", "<C:calendar-multiget/>", "<sync-collection/>"),
    ) +
    calendarCollection(
      `${CALDAV_HOME}work/`,
      "Work",
      reportSetProp("<C:calendar-query/>", "<sync-collection/>"),
    ) +
    calendarCollection(
      `${CALDAV_HOME}birthdays/`,
      "Birthdays",
      reportSetProp("<C:calendar-query/>", "<C:free-busy-query/>"),
    ) +
    calendarCollection(
      `${CALDAV_HOME}tasks/`,
      "Groceries",
      reportSetProp("<C:calendar-query/>") + componentSetProp("VTODO"),
    )
  );
}

function addressBookListBody(): string {
  const book = (href: string, name: string) =>
    `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/><CARD:addressbook/></resourcetype><displayname>${name}</displayname></prop></propstat></response>`;
  return (
    `<response><href>${CARDDAV_HOME}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/></resourcetype></prop></propstat></response>` +
    book(ADDRESS_BOOK_A, "Contacts") +
    book(ADDRESS_BOOK_B, "Collected")
  );
}

function supportedReportSetBody(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><supported-report-set><supported-report><report><CARD:addressbook-query/></report></supported-report><supported-report><report><CARD:addressbook-multiget/></report></supported-report><supported-report><report><sync-collection/></report></supported-report></supported-report-set></prop></propstat></response>`;
}

// ---------------------------------------------------------------------------
// The stub, and what it records
// ---------------------------------------------------------------------------

interface ObservedRequest {
  url: string;
  method: string;
  init: RequestInit;
  /** Monotonic tick when the stub was entered. */
  start: number;
  /** Monotonic tick when the stub resolved. */
  end: number;
}

interface Stub {
  requests: ObservedRequest[];
  /** True if any two calls were ever inside the stub at the same time. */
  overlapped: boolean;
  fetch: typeof globalThis.fetch;
}

/**
 * A stub that answers a realistic iCloud discovery conversation.
 *
 * It yields to the event loop between entry and exit, which is what makes the
 * serialisation assertion meaningful: without an await, every call would appear
 * atomic and a fan-out would look serial.
 */
function davStub(
  options: {
    caldavHome?: string;
    carddavHome?: string;
    onRequest?: (url: string, method: string, seq: number) => Response | null;
    /**
     * The calendar-home listing body, read FRESH on every listing request.
     *
     * A function rather than a string, because the write probe lists the home
     * set twice — once while the two services run, and once after its own
     * delete — and the whole point of the second listing is that it can answer
     * DIFFERENTLY from the first. A fixed string could not express "the
     * collection was there and is now gone", which is the only shape that
     * distinguishes a verified cleanup from an assumed one.
     */
    caldavHomeBody?: () => string;
  } = {},
): Stub {
  const caldavHome = options.caldavHome ?? CALDAV_HOME;
  const carddavHome = options.carddavHome ?? CARDDAV_HOME;
  const state: Stub = {
    requests: [],
    overlapped: false,
    fetch: async () => new Response(null, { status: 500 }),
  };

  let tick = 0;
  let open = 0;
  let seq = 0;

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET");

    // Before the record push, and the whole argument for why is in
    // `test/fixtures/sendable-method.ts`.
    assertMethodIsBuildable(url, method);

    const record: ObservedRequest = {
      url,
      method,
      init: init ?? {},
      start: (tick += 1),
      end: -1,
    };
    state.requests.push(record);

    open += 1;
    if (open > 1) state.overlapped = true;
    // Yield. See the docstring: an atomic stub cannot observe a fan-out.
    await new Promise((resolve) => setTimeout(resolve, 0));

    let response: Response;
    const override = options.onRequest?.(url, method, (seq += 1));
    if (override) {
      response = override;
    } else if (url.includes("/.well-known/")) {
      // iCloud does not serve a useful redirect here for this account shape.
      response = new Response(null, { status: 404 });
    } else if (url === CALDAV_ROOT || url === CALDAV_ROOT.slice(0, -1)) {
      response = multistatus(principalBody());
    } else if (url === CARDDAV_ROOT || url === CARDDAV_ROOT.slice(0, -1)) {
      response = multistatus(principalBody());
    } else if (url.endsWith(PRINCIPAL_PATH) && url.includes("caldav")) {
      response = multistatus(calendarHomeBody(caldavHome));
    } else if (url.endsWith(PRINCIPAL_PATH)) {
      response = multistatus(addressBookHomeBody(carddavHome));
    } else if (url === caldavHome) {
      response = multistatus(
        (options.caldavHomeBody ?? calendarListBody)(),
      );
    } else if (url === carddavHome) {
      response = multistatus(addressBookListBody());
    } else {
      response = multistatus(supportedReportSetBody(url));
    }

    open -= 1;
    record.end = tick += 1;
    return response;
  }) as typeof globalThis.fetch;

  return state;
}

/**
 * What the registered `dav_diagnose` callback accepts.
 *
 * Three booleans and nothing else. Named once so the two probes phase 14 added
 * are visible in one place beside `refresh`, and so a fourth input added later
 * has to be written down here before any case can reach it.
 */
interface DiagnoseArgs {
  refresh?: boolean;
  probeCollectionWrite?: boolean;
  probeTaskObjects?: boolean;
}

/** Pull the one registered `dav_diagnose` callback out, without a real server. */
function diagnoseHandler(
  davFetch: ReturnType<typeof createDavFetch>,
  // Who the callback acts for. The owner, unless a case hands in a promise of
  // its own, such as one that rejects.
  who: Promise<Principal> = owner,
): (args: DiagnoseArgs) => Promise<{
  isError?: boolean;
  content: { type: "text"; text: string }[];
}> {
  let captured:
    | ((args: DiagnoseArgs) => Promise<{
        isError?: boolean;
        content: { type: "text"; text: string }[];
      }>)
    | null = null;
  const server = {
    registerTool(
      _name: string,
      _options: Record<string, unknown>,
      callback: (args: DiagnoseArgs) => Promise<{
        isError?: boolean;
        content: { type: "text"; text: string }[];
      }>,
    ) {
      captured = callback;
    },
  };
  registerDavDiagnoseTool(server as unknown as McpServer, davFetch, who);
  expect(captured, "dav_diagnose registered no callback").not.toBeNull();
  return captured!;
}

function reportOf(result: {
  content: { type: "text"; text: string }[];
}): Record<string, never> & Record<string, unknown> {
  return JSON.parse(result.content[0].text) as Record<string, never> &
    Record<string, unknown>;
}

function serviceOf(
  result: { content: { type: "text"; text: string }[] },
  service: "caldav" | "carddav",
): Record<string, unknown> {
  return reportOf(result)[service] as Record<string, unknown>;
}

/**
 * The requests this run made against the CalDAV side of the account.
 *
 * The two services' hosts share no substring — `caldav.icloud.com` and
 * `p42-caldav.icloud.com` on one side, `contacts.icloud.com` and
 * `p61-contacts.icloud.com` on the other, and the CardDAV well-known path
 * spells `carddav`, which does not contain `caldav`. So this partition is exact
 * rather than approximate.
 */
function caldavRequests(stub: Stub): ObservedRequest[] {
  return stub.requests.filter((request) => request.url.includes("caldav"));
}

/**
 * How many round trips a cold CalDAV half costs: the well-known probe, which
 * tsdav tries twice (PROPFIND, then GET) against an account that answers it
 * with a 404; the root PROPFIND that names the principal; the principal
 * PROPFIND that names the home set; and the one depth-1 listing of that home
 * set.
 *
 * Pinned as a literal on purpose. Everything this phase adds to the CalDAV
 * report — the supported-report-set, the collection enumeration — rides the
 * LAST of those five, and the whole claim that it does is this number not
 * moving.
 */
const COLD_CALDAV_REQUESTS = 5;

describe("dav_diagnose, end to end", () => {
  beforeEach(async () => {
    await clearDavCache(env, principal);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves BOTH services' sharded hosts in one call", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(result.isError).toBeUndefined();
    const caldav = serviceOf(result, "caldav");
    const carddav = serviceOf(result, "carddav");

    expect(caldav.homeUrl).toBe(CALDAV_HOME);
    expect(caldav.principalUrl).toBe(`https://caldav.icloud.com${PRINCIPAL_PATH}`);
    expect(caldav.shardHost).toBe("p42-caldav.icloud.com");
    expect(caldav.cacheHit).toBe(false);
    // FOUR, not three: the reminder list is a calendar collection too. This
    // count and the length of `calendar_list_calendars` are deliberately
    // different numbers — see the case below that drives both.
    expect(caldav.calendarCount).toBe(4);

    expect(carddav.homeUrl).toBe(CARDDAV_HOME);
    expect(carddav.shardHost).toBe("p61-contacts.icloud.com");
    expect(carddav.cacheHit).toBe(false);
    expect(carddav.addressBookCount).toBe(2);
    expect(carddav.reports).toContain("addressbookQuery");
  });

  it("answers the CalDAV supported-report-set, the way it already answers CardDAV's", async () => {
    // SPIKE-03. Before this, `reports` was `null` for CalDAV and a real list for
    // CardDAV, and the asymmetry was the finding: the tool never asked.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    const caldav = serviceOf(result, "caldav");
    expect(caldav.reports).not.toBeNull();
    // The UNION across the three collections, de-duplicated, in the order the
    // collections were seen. `syncCollection` appears on two of them and
    // `calendarQuery` on all three; each appears once.
    expect(caldav.reports).toEqual([
      "calendarQuery",
      "calendarMultiget",
      "syncCollection",
      "freeBusyQuery",
    ]);
  });

  it("costs the CalDAV half no extra round trip to say so", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(caldavRequests(stub).length).toBe(COLD_CALDAV_REQUESTS);
    // Exactly one of those five is the home-set listing, and it is the one
    // carrying the answer. No per-collection helper ran.
    expect(
      caldavRequests(stub).filter((request) => request.url === CALDAV_HOME).length,
    ).toBe(1);
    expect(serviceOf(result, "caldav").reports).not.toBeNull();
    expect(stub.overlapped).toBe(false);
  });

  it("drops a malformed report element rather than stringifying it", async () => {
    // `DAVCollection`'s report region is typed `any` by the library, so nothing
    // upstream of the narrowing is watching this. An object reaching
    // `JSON.stringify` renders as nine characters that read like a real answer.
    const malformed =
      `<response><href>${CALDAV_HOME}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/></resourcetype></prop></propstat></response>` +
      `<response><href>${CALDAV_HOME}odd/</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/><C:calendar/></resourcetype><displayname>Odd</displayname>` +
      `<supported-report-set>` +
      `<supported-report><report/></supported-report>` +
      `<supported-report/>` +
      `<supported-report><report><C:calendar-query/></report></supported-report>` +
      `</supported-report-set>` +
      `</prop></propstat></response>`;

    const stub = davStub({
      onRequest: (url) =>
        url === CALDAV_HOME ? multistatus(malformed) : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const caldav = serviceOf(result, "caldav");

    expect(caldav.reports).toEqual(["calendarQuery"]);
    expect(JSON.stringify(caldav)).not.toContain("[object Object]");
  });

  it("enumerates every collection in the calendar home, with its component set", async () => {
    // HALF of SPIKE-02's instrument, and only half. A collection being SERVED
    // over CalDAV is not evidence that its CONTENTS are, which is the question
    // SPIKE-02 actually asks; the object-level query that makes a named
    // reminder matchable is plan 14-02's. Neither half settles it alone.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];

    expect(collections.map((one) => one.displayName)).toEqual([
      "Home",
      "Work",
      "Birthdays",
      "Groceries",
    ]);

    const tasks = collections.find((one) => one.displayName === "Groceries");
    expect(tasks).toBeDefined();
    expect(tasks!.href).toBe(`${CALDAV_HOME}tasks/`);
    expect(tasks!.components).toEqual(["VTODO"]);
    expect(tasks!.resourceTypes).toContain("calendar");
  });

  it("gives a collection with no component set an EMPTY list, not a dropped row", async () => {
    // A server that simply did not answer the property is not a server with no
    // collections. Dropping the row would make the diagnostic quieter than the
    // account, which is the one thing it must never be.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];

    const home = collections.find((one) => one.displayName === "Home");
    expect(home).toBeDefined();
    expect(home!.components).toEqual([]);
  });

  it("yields one row per collection: a VEVENT calendar and a VTODO list make TWO", async () => {
    const body =
      homeSelfResponse() +
      calendarCollection(
        `${CALDAV_HOME}personal/`,
        "Personal",
        componentSetProp("VEVENT"),
      ) +
      calendarCollection(
        `${CALDAV_HOME}reminders/`,
        "Reminders",
        componentSetProp("VTODO"),
      );

    const stub = davStub({
      onRequest: (url) => (url === CALDAV_HOME ? multistatus(body) : null),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];

    expect(collections.length).toBe(2);
    expect(collections[0].components).toEqual(["VEVENT"]);
    expect(collections[1].components).toEqual(["VTODO"]);
  });

  it("omits a collection whose href will not parse, rather than failing the run", async () => {
    const body =
      homeSelfResponse() +
      calendarCollection(`${CALDAV_HOME}good/`, "Good", componentSetProp("VEVENT")) +
      // A scheme this URL parser refuses, so it cannot be resolved against the
      // home URL. A collection this server cannot address is one it must not
      // pretend to have — but it is also not a reason to lose the rest.
      calendarCollection("http://[", "Broken", componentSetProp("VEVENT"));

    const stub = davStub({
      onRequest: (url) => (url === CALDAV_HOME ? multistatus(body) : null),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(result.isError).toBeUndefined();
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];
    expect(collections.map((one) => one.displayName)).toEqual(["Good"]);
  });

  it("leaves the collection enumeration NULL on the CardDAV half", async () => {
    // The per-service `null` convention this module's header states: a reader
    // must never be able to mistake "not applicable" for "found nothing".
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(serviceOf(result, "carddav").collections).toBeNull();
    expect(serviceOf(result, "caldav").collections).not.toBeNull();
  });

  it("does not change what calendar_list_calendars shows for the same account", async () => {
    // Pitfall 57's quieter half. The listing's VEVENT filter at
    // src/dav/calendar.ts:506 stays exactly as it is: loosening it would make
    // reminder lists appear as calendars with no events, degrading a shipped
    // tool. The diagnostic sees the reminder list; the listing still does not.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const listing = await listCalendars(env, principal, createDavFetch(owner));

    expect(listing.calendars.map((one) => one.displayName)).toEqual([
      "Birthdays",
      "Home",
      "Work",
    ]);
    expect(listing.calendars.map((one) => one.displayName)).not.toContain(
      "Groceries",
    );
  });

  it("reports the two shard hosts as INDEPENDENT fields, never derived", async () => {
    // The partitions differ here, so a "derive the second from the first"
    // implementation cannot pass. The matching-partition case below is the
    // other half: a coincidence must not become a rule.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const report = reportOf(result);

    expect((report.caldav as Record<string, unknown>).shardHost).toBe(
      "p42-caldav.icloud.com",
    );
    expect((report.carddav as Record<string, unknown>).shardHost).toBe(
      "p61-contacts.icloud.com",
    );
  });

  it("still reports two separate results when the partitions MATCH", async () => {
    const matchedCarddav = "https://p42-contacts.icloud.com/1234567890/carddavhome/";
    const stub = davStub({ carddavHome: matchedCarddav });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const caldav = serviceOf(result, "caldav");
    const carddav = serviceOf(result, "carddav");

    expect(caldav.shardHost).toBe("p42-caldav.icloud.com");
    expect(carddav.shardHost).toBe("p42-contacts.icloud.com");
    // Two fields, two values, one per service — even though the number matched.
    expect(caldav.homeUrl).not.toBe(carddav.homeUrl);
  });

  it("issues ZERO outbound requests on a cache hit", async () => {
    const warm = davStub();
    vi.stubGlobal("fetch", warm.fetch);
    await diagnoseHandler(createDavFetch(owner))({});
    expect(warm.requests.length).toBeGreaterThan(0);

    const cold = davStub();
    vi.stubGlobal("fetch", cold.fetch);
    const cached = await resolveDavAccount(env, principal, createDavFetch(owner), "caldav");

    expect(cached.cacheHit).toBe(true);
    expect(cached.homeUrl).toBe(CALDAV_HOME);
    expect(cold.requests.length).toBe(0);
  });

  it("deletes both entries and re-resolves live on refresh: true (D-61)", async () => {
    const warm = davStub();
    vi.stubGlobal("fetch", warm.fetch);
    const first = await diagnoseHandler(createDavFetch(owner))({});
    expect(serviceOf(first, "caldav").cacheHit).toBe(false);

    const second = davStub();
    vi.stubGlobal("fetch", second.fetch);
    const cachedRun = await diagnoseHandler(createDavFetch(owner))({});
    expect(serviceOf(cachedRun, "caldav").cacheHit).toBe(true);
    expect(serviceOf(cachedRun, "carddav").cacheHit).toBe(true);

    const refreshed = davStub();
    vi.stubGlobal("fetch", refreshed.fetch);
    const third = await diagnoseHandler(createDavFetch(owner))({ refresh: true });

    expect(reportOf(third).refresh).toBe(true);
    expect(serviceOf(third, "caldav").cacheHit).toBe(false);
    expect(serviceOf(third, "carddav").cacheHit).toBe(false);
    expect(serviceOf(third, "caldav").homeUrl).toBe(CALDAV_HOME);
    expect(refreshed.requests.length).toBeGreaterThan(0);
  });

  it("carries redirect: manual and a Basic header on EVERY request", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    await diagnoseHandler(createDavFetch(owner))({});

    expect(stub.requests.length).toBeGreaterThan(0);
    for (const request of stub.requests) {
      expect(request.init.redirect).toBe("manual");
      const authorization = new Headers(request.init.headers).get(
        "authorization",
      );
      expect(authorization).toBeTruthy();
      expect(authorization!.startsWith("Basic ")).toBe(true);
    }
  });

  it("never has two requests in flight at once", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    await diagnoseHandler(createDavFetch(owner))({});

    expect(stub.overlapped).toBe(false);
    // And strictly: each request finished before the next one started.
    for (let index = 1; index < stub.requests.length; index += 1) {
      expect(stub.requests[index - 1].end).toBeLessThan(
        stub.requests[index].start,
      );
    }
  });

  it("never lets a credential reach the response", async () => {
    expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
    expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);

    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);
    const result = await diagnoseHandler(createDavFetch(owner))({});
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain(FAKE_APPLE_ID);
    expect(serialized).not.toContain(FAKE_APP_PASSWORD);
  });

  it("fails with auth_failed BEFORE any request when the principal was refused", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    // A bad credential cannot be expressed below the door: the diagnostic takes
    // a principal, and none is built from a credential the constructor turns
    // away. So the REGISTERED callback is driven with the promise the door hands
    // over instead. It rejects, the callback's first await throws, and the
    // callback's own catch shapes the refusal. Same two assertions as before, on
    // the same two fields.
    const refused = refusedPrincipal("appleId");
    refused.catch(() => {});

    const shaped = await diagnoseHandler(createDavFetch(refused), refused)({});

    expect(stub.requests.length).toBe(0);
    expect(shaped.isError).toBe(true);
    const body = JSON.parse(shaped.content[0].text) as {
      category: string;
      message: string;
    };
    expect(body.category).toBe("auth_failed");
    expect(body.message).toBe(SAFE_MESSAGES.auth_failed);
  });

  it("is constructible from the real per-request server factory", async () => {
    // The wiring half: `createServerFactory` builds a DAV fetch and registers
    // this tool per request, beside the session gate. If that edit regressed,
    // this throws rather than silently shipping a server with no DAV surface.
    const factory = createServerFactory(ownerPrincipal());
    expect(() => factory({ era: "modern" })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Phase 14's two probes: the collection write (SPIKE-04) and the bounded to-do
// listing (SPIKE-02's object-level half).
//
// Both are OFF unless asked for by name, and the two "it did nothing" cases
// below carry more weight than the rest — they are asserted by filtering the
// RECORDED request methods, so they read what was actually sent rather than the
// shape of the code that sends it.
// ---------------------------------------------------------------------------

/** The methods that change something. A run not asked to write sends none. */
const MUTATING_METHODS = [
  REFUSED_CREATE_METHOD,
  "PROPPATCH",
  "DELETE",
  "PUT",
  "MKCOL",
];

function methodsOf(stub: Stub, ...methods: string[]): ObservedRequest[] {
  return stub.requests.filter((request) => methods.includes(request.method));
}

/** One write-probe step, as the report carries it. */
interface WriteStep {
  step: string;
  /** The method the step issued, or null for a step that issues no request. */
  method: string | null;
  status: number | null;
  ok: boolean;
  category: string | null;
}

interface WriteProbe {
  url: string;
  steps: WriteStep[];
  cleanupVerified: boolean;
  stillPresent: boolean | null;
}

interface TaskObject {
  uid: string;
  summary: string;
}

interface TaskEntry {
  href: string;
  displayName: string;
  objectCount: number;
  truncated: boolean;
  unparsed: number;
  objects: TaskObject[];
  category: string | null;
}

interface TaskProbe {
  collectionsFound: number;
  collectionsVisited: number;
  collections: TaskEntry[];
  category: string | null;
}

function writeProbeOf(result: {
  content: { type: "text"; text: string }[];
}): WriteProbe | null {
  return serviceOf(result, "caldav").collectionWrite as WriteProbe | null;
}

function taskProbeOf(result: {
  content: { type: "text"; text: string }[];
}): TaskProbe | null {
  return serviceOf(result, "caldav").taskObjects as TaskProbe | null;
}

function stepNamed(probe: WriteProbe, step: string): WriteStep | undefined {
  return probe.steps.find((one) => one.step === step);
}

/** A PROPPATCH answer: one `response`, every property accepted. */
function propertyUpdateBody(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><displayname/><ca:calendar-color xmlns:ca="http://apple.com/ns/ical/"/></prop></propstat></response>`;
}

/**
 * A stub that answers the write probe's three mutations and can be told to
 * keep showing the probe collection after the delete.
 *
 * `lingers` is the case the `cleanupVerified` field exists for: a delete that
 * answered `204` is not evidence of a deletion, and the only thing that is, is
 * looking again.
 */
function writeProbeStub(
  options: {
    createStatus?: number;
    patchStatus?: number;
    deleteStatus?: number;
    lingers?: boolean;
    /** Extra rows on the calendar-home listing — the to-do collections. */
    extraHomeRows?: string;
    onOther?: (url: string, method: string) => Response | null;
  } = {},
): { stub: Stub; probeUrl: () => string | null } {
  let probeUrl: string | null = null;

  const stub = davStub({
    caldavHomeBody: () =>
      calendarListBody() +
      (options.extraHomeRows ?? "") +
      (options.lingers === true && probeUrl !== null
        ? calendarCollection(probeUrl, "iCloud MCP write probe", "")
        : ""),
    onRequest: (url, method) => {
      // MKCOL, not the RFC 4791 calendar-creation method. workerd refuses to
      // build a request carrying that one at all, so the probe issues RFC 5689
      // extended MKCOL -- and this stub now proves that by construction rather
      // than by agreement: the `new Request` at the top of `davStub` throws on
      // the old method, so a regression here cannot be papered over by teaching
      // the stub to answer it.
      if (method === "MKCOL") {
        probeUrl = url;
        return new Response(null, { status: options.createStatus ?? 201 });
      }
      if (method === "PROPPATCH") {
        const status = options.patchStatus ?? 207;
        return status === 207
          ? multistatus(propertyUpdateBody(url))
          : new Response(null, { status });
      }
      if (method === "DELETE") {
        return new Response(null, { status: options.deleteStatus ?? 204 });
      }
      return options.onOther?.(url, method) ?? null;
    },
  });

  return { stub, probeUrl: () => probeUrl };
}

const TASKS_A = `${CALDAV_HOME}tasks/`;
const TASKS_B = `${CALDAV_HOME}worklist/`;

/** A collection row advertising the to-do component and nothing else. */
function todoCollection(href: string, name: string): string {
  return calendarCollection(href, name, componentSetProp("VTODO"));
}

/** One to-do resource, as iCloud serves it inside a `calendar-query` answer. */
function todoObject(href: string, uid: string, summary: string): string {
  const ics = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//iCloud MCP test//EN",
    "BEGIN:VTODO",
    `UID:${uid}`,
    `SUMMARY:${summary}`,
    "END:VTODO",
    "END:VCALENDAR",
  ].join("\r\n");
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><getetag>"${uid}"</getetag><C:calendar-data><![CDATA[${ics}]]></C:calendar-data></prop></propstat></response>`;
}

/** A resource whose body is not iCalendar at all. */
function unreadableObject(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><getetag>"x"</getetag><C:calendar-data><![CDATA[this is not iCalendar]]></C:calendar-data></prop></propstat></response>`;
}

describe("dav_diagnose, the collection write probe (SPIKE-04)", () => {
  beforeEach(async () => {
    await clearDavCache(env, principal);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("issues NO mutating request at all when the probe was not asked for", async () => {
    // Read off the recorded METHODS, not off the code that sends them. A
    // permanently-registered tool that can write to the account has to be
    // provably inert on the ordinary path, and "we only call it behind the
    // boolean" is a claim about the source rather than about the wire.
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(methodsOf(stub, ...MUTATING_METHODS)).toEqual([]);
    expect(writeProbeOf(result)).toBeNull();
    expect(stub.overlapped).toBe(false);
  });

  it("creates, renames, deletes, and confirms the collection is GONE", async () => {
    const { stub, probeUrl } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result);
    expect(probe).not.toBeNull();
    expect(probe!.steps.map((one) => one.step)).toEqual([
      "resolve",
      "create",
      "rename-and-recolour",
      "delete",
      "verify",
    ]);
    expect(probe!.steps.every((one) => one.ok)).toBe(true);
    expect(stepNamed(probe!, "create")!.status).toBe(201);
    expect(stepNamed(probe!, "delete")!.status).toBe(204);
    expect(probe!.stillPresent).toBe(false);
    expect(probe!.cleanupVerified).toBe(true);
    expect(probe!.url).toBe(probeUrl());
    expect(stub.overlapped).toBe(false);
  });

  it("reports cleanup NOT verified and names the URL when the delete is refused", async () => {
    const { stub } = writeProbeStub({ deleteStatus: 403, lingers: true });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    expect(stepNamed(probe, "delete")!.ok).toBe(false);
    expect(stepNamed(probe, "delete")!.category).toBe("auth_failed");
    expect(probe.cleanupVerified).toBe(false);
    expect(probe.stillPresent).toBe(true);
    // The URL the owner has to remove by hand. A throwaway calendar left on the
    // account is litter found months later.
    expect(probe.url.startsWith(CALDAV_HOME)).toBe(true);
    expect(stub.overlapped).toBe(false);
  });

  it("reports cleanup NOT verified when the delete was ACCEPTED but it is still listed", async () => {
    // An accepted delete is not evidence of a deletion. This is the case that
    // makes `cleanupVerified` mean something rather than restate the status.
    const { stub } = writeProbeStub({ deleteStatus: 204, lingers: true });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    expect(stepNamed(probe, "delete")!.ok).toBe(true);
    expect(stepNamed(probe, "delete")!.status).toBe(204);
    expect(probe.stillPresent).toBe(true);
    expect(probe.cleanupVerified).toBe(false);
    expect(stub.overlapped).toBe(false);
  });

  it("stops at the CREATE when the create is refused, and says so", async () => {
    const { stub } = writeProbeStub({ createStatus: 403 });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    expect(probe.steps.map((one) => one.step)).toEqual(["resolve", "create"]);
    expect(stepNamed(probe, "create")!.ok).toBe(false);
    expect(stepNamed(probe, "create")!.category).toBe("auth_failed");
    // Nothing was created, so there is nothing to have cleaned up — and the
    // probe says it did not look, rather than claiming the collection is gone.
    expect(probe.stillPresent).toBeNull();
    expect(probe.cleanupVerified).toBe(false);
    expect(methodsOf(stub, "PROPPATCH", "DELETE")).toEqual([]);
    expect(stub.overlapped).toBe(false);
  });

  it("aims the write at the account's OWN home set, with a server-generated segment", async () => {
    // T-14-08. Read off the recorded request URL rather than off the code that
    // built it: the tool takes no URL, no id and no name, so the only free
    // component is the identifier this server minted.
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const created = methodsOf(stub, "MKCOL");
    expect(created.length).toBe(1);
    expect(created[0].url.startsWith(CALDAV_HOME)).toBe(true);
    expect(writeProbeOf(result)!.url.startsWith(CALDAV_HOME)).toBe(true);
    // One path segment plus a trailing slash, and nothing else.
    const segment = created[0].url.slice(CALDAV_HOME.length);
    expect(segment.endsWith("/")).toBe(true);
    expect(segment.slice(0, -1)).not.toContain("/");
    expect(stub.overlapped).toBe(false);
  });

  // ---------------------------------------------------------------------
  // THE CREDENTIAL CASE. Do not delete this as redundant with the
  // default-run version further up — it is the only assertion in this
  // repository that can see the failure it is written against.
  //
  // Every tsdav helper declares `fetch?: typeof fetch` as OPTIONAL and
  // resolves it as `fetchOverride ?? fetch`. Omit the option at any one of
  // the four call sites the two probes add and that helper silently uses
  // the bare global instead: no `authorization` header, no
  // `redirect: "manual"`, no per-request serialisation gate, no
  // status-to-error mapping.
  //
  // `scripts/forbidden-tokens.mjs` CANNOT catch this. `dav-fetch-outside-
  // transport` fires on a bare network call inside `src/dav/`, and a helper
  // invoked without the option is not a bare call at that site — the fetch
  // happens inside `node_modules`, which the scanner does not walk. It is
  // the same blind spot `dav-concurrent-request`'s own reason string already
  // records for `fetchCalendars`.
  //
  // What it would cost: against iCloud, a 401 on every mutation. At the
  // report level that is indistinguishable from iCloud refusing collection
  // writes from a third-party client — a measured-looking WRONG verdict for
  // SPIKE-04, produced by a bug in this repository, reshaping Phase 17.
  //
  // A call-site grep would be the weaker check. This reads what was actually
  // SENT: `vi.stubGlobal("fetch", stub.fetch)` makes the stub the global, so
  // a helper that fell back to the global still lands in `stub.requests` —
  // just without the two properties only `createDavFetch` sets.
  // ---------------------------------------------------------------------
  it("sends EVERY request of BOTH probes through this project's own transport", async () => {
    const { stub } = writeProbeStub({
      onOther: (url, method) =>
        method === "REPORT"
          ? multistatus(todoObject(`${url}1.ics`, "uid-milk", "Buy milk"))
          : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
      probeTaskObjects: true,
    });

    // Non-vacuity first, and per probe: a walk over a list that never grew
    // the probes' own requests would pass while proving nothing about them.
    expect(methodsOf(stub, "MKCOL").length).toBe(1);
    expect(methodsOf(stub, "PROPPATCH").length).toBe(1);
    expect(methodsOf(stub, "DELETE").length).toBe(1);
    expect(methodsOf(stub, "REPORT").length).toBeGreaterThan(0);
    expect(writeProbeOf(result)).not.toBeNull();
    expect(taskProbeOf(result)).not.toBeNull();

    for (const request of stub.requests) {
      const authorization = new Headers(request.init.headers).get(
        "authorization",
      );
      expect(
        authorization,
        `${request.method} ${request.url} carried no credential — a tsdav helper was called without fetch: davFetch`,
      ).toBeTruthy();
      expect(authorization!.startsWith("Basic ")).toBe(true);
      // The other property only `createDavFetch` sets, applied last so no
      // caller-supplied init can override it. One line, and it fails on the
      // same omission.
      expect(
        request.init.redirect,
        `${request.method} ${request.url} did not carry redirect: manual`,
      ).toBe("manual");
    }

    expect(stub.overlapped).toBe(false);
  });

  it("never has two requests in flight while the write probe runs", async () => {
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    await diagnoseHandler(createDavFetch(owner))({ probeCollectionWrite: true });

    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.requests.length; index += 1) {
      expect(stub.requests[index - 1].end).toBeLessThan(
        stub.requests[index].start,
      );
    }
  });
});

describe("dav_diagnose, the bounded to-do listing (SPIKE-02, object level)", () => {
  beforeEach(async () => {
    await clearDavCache(env, principal);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends NO report request when the to-do probe was not asked for", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(methodsOf(stub, "REPORT")).toEqual([]);
    expect(taskProbeOf(result)).toBeNull();
    expect(stub.overlapped).toBe(false);
  });

  it("lists each to-do collection's OBJECTS, with their titles and UIDs", async () => {
    // This is the half plan 14-01 could not reach. A collection advertising the
    // to-do component says a task list is SERVED over CalDAV; success criterion
    // 2 passes only when a reminder the owner named on his phone appears in the
    // report this server produced, and no collection-level field can carry a
    // reminder's title.
    const stub = davStub({
      caldavHomeBody: () =>
        homeSelfResponse() +
        calendarCollection(`${CALDAV_HOME}home/`, "Home", componentSetProp("VEVENT")) +
        todoCollection(TASKS_A, "Groceries") +
        todoCollection(TASKS_B, "Work"),
      onRequest: (url, method) => {
        if (method !== "REPORT") return null;
        if (url === TASKS_A) {
          return multistatus(
            todoObject(`${TASKS_A}1.ics`, "uid-milk", "Buy milk") +
              todoObject(`${TASKS_A}2.ics`, "uid-bread", "Buy bread"),
          );
        }
        return multistatus(todoObject(`${TASKS_B}1.ics`, "uid-slides", "Finish slides"));
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    const probe = taskProbeOf(result)!;
    expect(probe.collectionsFound).toBe(2);
    expect(probe.collectionsVisited).toBe(2);
    expect(probe.collections.map((one) => one.displayName)).toEqual([
      "Groceries",
      "Work",
    ]);
    expect(probe.collections[0].objects).toEqual([
      { uid: "uid-milk", summary: "Buy milk" },
      { uid: "uid-bread", summary: "Buy bread" },
    ]);
    expect(probe.collections[1].objects).toEqual([
      { uid: "uid-slides", summary: "Finish slides" },
    ]);
    expect(probe.collections[0].truncated).toBe(false);
    expect(stub.overlapped).toBe(false);
  });

  it("reports TRUNCATED rather than silently returning a short list", async () => {
    // A cap that returned a short list without saying so would let a MISSING
    // reminder look like an ABSENT one, which is the pass-but-wrong mode in a
    // different costume.
    const many = Array.from({ length: 30 }, (_unused, index) =>
      todoObject(`${TASKS_A}${index}.ics`, `uid-${index}`, `Task ${index}`),
    ).join("");

    const stub = davStub({
      caldavHomeBody: () => homeSelfResponse() + todoCollection(TASKS_A, "Groceries"),
      onRequest: (url, method) =>
        method === "REPORT" ? multistatus(many) : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    const entry = taskProbeOf(result)!.collections[0];
    expect(entry.objects.length).toBe(25);
    expect(entry.objectCount).toBe(30);
    expect(entry.truncated).toBe(true);
  });

  it("visits at most EIGHT to-do collections and reports how many it found", async () => {
    const lists = Array.from({ length: 11 }, (_unused, index) =>
      todoCollection(`${CALDAV_HOME}list${index}/`, `List ${index}`),
    ).join("");

    const stub = davStub({
      caldavHomeBody: () => homeSelfResponse() + lists,
      onRequest: (url, method) =>
        method === "REPORT"
          ? multistatus(todoObject(`${url}1.ics`, "uid-1", "One"))
          : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    const probe = taskProbeOf(result)!;
    expect(probe.collectionsFound).toBe(11);
    expect(probe.collectionsVisited).toBe(8);
    expect(probe.collections.length).toBe(8);
    // Eight REPORTs, not eleven. The cap bit and it is visible rather than
    // silent.
    expect(methodsOf(stub, "REPORT").length).toBe(8);
    expect(stub.overlapped).toBe(false);
  });

  it("omits an object it cannot read a UID and a title from, and COUNTS it", async () => {
    const stub = davStub({
      caldavHomeBody: () => homeSelfResponse() + todoCollection(TASKS_A, "Groceries"),
      onRequest: (url, method) =>
        method === "REPORT"
          ? multistatus(
              todoObject(`${TASKS_A}1.ics`, "uid-milk", "Buy milk") +
                unreadableObject(`${TASKS_A}2.ics`),
            )
          : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    const entry = taskProbeOf(result)!.collections[0];
    expect(entry.objects).toEqual([{ uid: "uid-milk", summary: "Buy milk" }]);
    expect(entry.unparsed).toBe(1);
    // Never an empty title dressed as a real one.
    expect(JSON.stringify(entry)).not.toContain("[object Object]");
    expect(entry.objects.every((one) => one.summary.length > 0)).toBe(true);
  });

  it("queries every collection in its OWN await, never two at once", async () => {
    const lists = Array.from({ length: 5 }, (_unused, index) =>
      todoCollection(`${CALDAV_HOME}list${index}/`, `List ${index}`),
    ).join("");

    const stub = davStub({
      caldavHomeBody: () => homeSelfResponse() + lists,
      onRequest: (url, method) =>
        method === "REPORT"
          ? multistatus(todoObject(`${url}1.ics`, "uid-1", "One"))
          : null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    await diagnoseHandler(createDavFetch(owner))({ probeTaskObjects: true });

    expect(methodsOf(stub, "REPORT").length).toBe(5);
    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.requests.length; index += 1) {
      expect(stub.requests[index - 1].end).toBeLessThan(
        stub.requests[index].start,
      );
    }
  });

  it("accepts no title, id or name to match against, and returns no verdict", async () => {
    // The tool REPORTS what it found; plan 14-06 compares that against what the
    // owner names, as an exact string match over the full list. A fuzzy match
    // decided here would be this code deciding SPIKE-02, which is the thing the
    // phase exists to stop.
    const registered: Record<string, unknown>[] = [];
    const server = {
      registerTool(
        _name: string,
        options: Record<string, unknown>,
        _callback: unknown,
      ) {
        registered.push(options);
      },
    };
    registerDavDiagnoseTool(
      server as unknown as McpServer,
      createDavFetch(owner),
      owner,
    );

    expect(registered.length).toBe(1);
    const shape = registered[0].inputSchema as { shape: Record<string, unknown> };
    expect(Object.keys(shape.shape).sort()).toEqual([
      "probeCollectionWrite",
      "probeTaskObjects",
      "refresh",
    ]);
  });
});

// ---------------------------------------------------------------------------
// The Phase 14 write-probe defect, and the three layers that close it.
//
// MEASURED LIVE on 2026-09-24 against deployed version
// b35d0d58-14b3-4c65-88ab-53052a40d1bc. The probe reported
// `{ step: "create", status: null, ok: false, category: "connection_failed" }`
// and no calendar appeared on the account. That reads as "iCloud refused the
// collection write", and it was on its way into SPIKE-04's verdict.
//
// It was not iCloud. It was workerd refusing to BUILD the request: tsdav's
// collection-creation helper issues the RFC 4791 calendar-creation method, the
// `Request` constructor rejects that method string, the `TypeError` landed in
// the DAV transport's `catch`, and `davToErrorCategory`'s DEFAULT arm answered
// `connection_failed`. No byte left the Worker.
//
// The 14-02 suite could not see any of it, and the reason is worth stating
// because it is the reason a whole CLASS of failure was invisible:
// `vi.stubGlobal("fetch", stub.fetch)` replaces the runtime's fetch with a
// plain function, so no `Request` was ever constructed and workerd's method
// validation never ran. `davStub` now builds one per call, which is the guard
// that makes every case below able to fail.
// ---------------------------------------------------------------------------

describe("the methods this runtime will and will not send", () => {
  it("refuses the calendar-creation method and accepts every other method this project sends", () => {
    // THE FINDING ITSELF, pinned against the real runtime rather than against
    // a note in a summary. Nothing in this repository can assert what
    // Cloudflare will accept; it can only ask, which is what this does.
    //
    // If a future workerd accepts the RFC 4791 calendar-creation method, this
    // case goes red and the create step's whole reason for using extended
    // MKCOL is up for review. That is the intended behaviour: a workaround for
    // a platform limit must fail loudly when the limit lifts, not outlive it
    // silently.
    const observed: Record<string, boolean> = {};
    for (const method of [
      "GET",
      "PUT",
      "DELETE",
      "PROPFIND",
      "PROPPATCH",
      "REPORT",
      "MKCOL",
      REFUSED_CREATE_METHOD,
    ]) {
      try {
        new Request("https://method-check.invalid/", { method });
        observed[method] = true;
      } catch {
        observed[method] = false;
      }
    }

    expect(observed).toEqual({
      GET: true,
      PUT: true,
      DELETE: true,
      PROPFIND: true,
      PROPPATCH: true,
      REPORT: true,
      MKCOL: true,
      // The one that cost a live probe run and nearly cost a verdict. A
      // COMPUTED key, so the assertion is keyed on the same built string the
      // loop above drove -- spelling it here would fail the commit hook, and
      // the computed form is what keeps the expectation and the drive reading
      // off one constant rather than two spellings that could drift.
      [REFUSED_CREATE_METHOD]: false,
    });
  });

  it("makes the stub refuse what the runtime refuses, so a bad method cannot pass offline", async () => {
    // The GUARD, asserted directly rather than only through its effect on the
    // cases above. Without this the harness is blind to every runtime-level
    // rejection, which is exactly how the defect shipped green.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    await expect(
      stub.fetch("https://p1-caldav.icloud.invalid/x/", {
        method: REFUSED_CREATE_METHOD,
      }),
    ).rejects.toThrow();
    // Nothing recorded: in production nothing goes on the wire either.
    expect(stub.requests).toEqual([]);
  });
});

describe("the collection write probe, after the unsendable-method finding", () => {
  beforeEach(async () => {
    await clearDavCache(env, principal);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("creates with extended MKCOL and NEVER sends the calendar-creation method", async () => {
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    // Read off the wire, not off the call site.
    expect(methodsOf(stub, REFUSED_CREATE_METHOD)).toEqual([]);
    expect(methodsOf(stub, "MKCOL").length).toBe(1);
    expect(stepNamed(writeProbeOf(result)!, "create")!.ok).toBe(true);
  });

  it("names the method on every step, so a verdict cannot be written about the wrong request", async () => {
    // The report is evidence. A create step reporting only "ok, 201" would be
    // read as iCloud accepting the RFC 4791 calendar-creation method, which is
    // a fact about a request this server cannot even build. The method is
    // therefore IN the report.
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    expect(
      probe.steps.map((one) => [one.step, one.method]),
    ).toEqual([
      ["resolve", null],
      ["create", "MKCOL"],
      ["rename-and-recolour", "PROPPATCH"],
      ["delete", "DELETE"],
      ["verify", null],
    ]);
    // Nowhere in the response does the method it could not send appear.
    expect(JSON.stringify(probe)).not.toContain(REFUSED_CREATE_METHOD);
  });

  it("sends the calendar resourcetype in the MKCOL body, so the result is a CALENDAR collection", async () => {
    // Extended MKCOL without this pair creates an ordinary WebDAV collection,
    // which would answer a different question by accident and look identical
    // in the report.
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    await diagnoseHandler(createDavFetch(owner))({ probeCollectionWrite: true });

    const body = String(methodsOf(stub, "MKCOL")[0].init.body);
    expect(body).toContain("<d:mkcol");
    expect(body).toContain("<d:collection/>");
    expect(body).toContain("<c:calendar/>");
    expect(body).toContain('xmlns:c="urn:ietf:params:xml:ns:caldav"');
    expect(body).toContain("iCloud MCP write probe (throwaway)");
  });

  it("treats a 207 on the create as a REFUSAL, not as a 2xx success", async () => {
    // THE TRAP THIS CHANGE INTRODUCED, closed deliberately. The RFC 4791
    // calendar-creation method either works or fails with a plain status.
    // Extended MKCOL has a third answer: RFC 5689 makes the request
    // all-or-nothing, and a server that cannot set every property in the body
    // fails the WHOLE request, creates nothing, and says so with a 207
    // Multi-Status naming the property it refused.
    //
    // 207 sits inside the 2xx range. Read by the generic rule it would have
    // produced `create: ok, 207` -- and a SPIKE-04 verdict written from that
    // would record iCloud as accepting collection creation on a run where
    // nothing was created. That is the same measured-looking wrong answer the
    // unsendable-method defect produced, arriving through a different door: a
    // report that reads as a measurement of iCloud and is a measurement of
    // something else entirely.
    const { stub } = writeProbeStub({ createStatus: 207 });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    const create = stepNamed(probe, "create")!;
    expect(create.status).toBe(207);
    expect(create.ok).toBe(false);
    // The sequence stopped. RFC 5689's all-or-nothing rule means there is
    // nothing to rename and nothing to delete -- and no litter left behind.
    expect(probe.steps.map((one) => one.step)).toEqual(["resolve", "create"]);
    expect(methodsOf(stub, "PROPPATCH")).toEqual([]);
    expect(methodsOf(stub, "DELETE")).toEqual([]);
    expect(probe.stillPresent).toBeNull();
  });

  it("still accepts a plain 2xx that is not 207, so the rule is narrow", async () => {
    // The mirror-image error, guarded against. Demanding 201 exactly would
    // record a server answering 200 on a genuine creation as having refused.
    // 207 is the only status in the range that is an envelope rather than an
    // answer, and it is the only one excluded.
    const { stub } = writeProbeStub({ createStatus: 200 });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeCollectionWrite: true,
    });

    const probe = writeProbeOf(result)!;
    expect(stepNamed(probe, "create")!.ok).toBe(true);
    expect(probe.steps.map((one) => one.step)).toEqual([
      "resolve",
      "create",
      "rename-and-recolour",
      "delete",
      "verify",
    ]);
  });

  it("records a REFUSED resolve as a failed step instead of throwing past the probe", async () => {
    // The resolve used to be awaited bare and followed by a hand-written
    // `ok: true`, so the step could only ever report SUCCESS -- and a refusal
    // threw past the whole probe, where the tool boundary discarded the entire
    // report. The one field that was supposed to say which step failed said
    // nothing, because it never ran.
    //
    // Driven against the probe directly rather than through the tool, because
    // the tool only reaches the probe once discovery has already succeeded and
    // been cached. That is exactly why this case has to exist separately: the
    // path is unreachable from the handler, so nothing else in this file can
    // fail on it.
    const stub = davStub({
      onRequest: (_url, _method) => new Response(null, { status: 503 }),
    });
    vi.stubGlobal("fetch", stub.fetch);
    await clearDavCache(env, principal);

    const probe = await runCollectionWriteProbe(
      env,
      principal,
      createDavFetch(owner),
    );

    // It RETURNED. Before the fix this call threw.
    expect(probe.steps.length).toBe(1);
    expect(probe.steps[0].step).toBe("resolve");
    expect(probe.steps[0].ok).toBe(false);
    expect(probe.steps[0].category).toBe("rate_limited");
    // No URL was ever built, so the probe names none -- rather than naming one
    // the owner would go looking for on an account that never had it.
    expect(probe.url).toBe("");
    expect(probe.cleanupVerified).toBe(false);
    expect(probe.stillPresent).toBeNull();
    // And nothing was attempted on the account.
    expect(methodsOf(stub, ...MUTATING_METHODS)).toEqual([]);
  });
});

describe("the to-do probe when one collection is refused", () => {
  beforeEach(async () => {
    await clearDavCache(env, principal);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("records the refusal per collection and KEEPS GOING", async () => {
    // MEASURED LIVE: the owner's account carries two abandoned to-do lists
    // that predate Apple's iOS 13 storage migration, and iCloud answers 404 on
    // a calendar-query against them. While the query was left to throw, asking
    // for the to-do listing discarded the ENTIRE diagnostic -- both services'
    // discovery, the collection enumeration, the timings, and the other
    // collection's reminders -- and answered with a bare `not_found`.
    //
    // Swallowing it would have been worse than either: a collection silently
    // missing from this list is SPIKE-02's documented pass-but-wrong mode
    // exactly. So it is REPORTED, per collection, and the run continues.
    const stub = davStub({
      caldavHomeBody: () =>
        homeSelfResponse() +
        todoCollection(TASKS_A, "Reminders (abandoned)") +
        todoCollection(TASKS_B, "Groceries"),
      onRequest: (url, method) => {
        if (method !== "REPORT") return null;
        if (url === TASKS_A) return new Response(null, { status: 404 });
        return multistatus(todoObject(`${TASKS_B}1.ics`, "uid-milk", "Buy milk"));
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    // Not an error payload. The report came back.
    expect(result.isError).toBeUndefined();
    const probe = taskProbeOf(result)!;
    expect(probe.category).toBeNull();
    expect(probe.collectionsFound).toBe(2);
    expect(probe.collectionsVisited).toBe(2);

    // The refused one is PRESENT and NAMED, carrying its category and no
    // objects -- which is a different fact from a list that holds nothing.
    const refused = probe.collections[0];
    expect(refused.displayName).toBe("Reminders (abandoned)");
    expect(refused.category).toBe("not_found");
    expect(refused.objects).toEqual([]);

    // And the collection after it was still asked, which is the "keeps going"
    // half. A probe that stopped would have left this entry out entirely.
    const answered = probe.collections[1];
    expect(answered.category).toBeNull();
    expect(answered.objects).toEqual([
      { uid: "uid-milk", summary: "Buy milk" },
    ]);
    expect(methodsOf(stub, "REPORT").length).toBe(2);
    expect(stub.overlapped).toBe(false);
  });

  it("tells a refused collection apart from an EMPTY one", async () => {
    // The distinction the `category` field exists for. Without it both read as
    // `objects: []`, and "your reminder is not there" would be indistinguish-
    // able from "this server could not look".
    const stub = davStub({
      caldavHomeBody: () =>
        homeSelfResponse() +
        todoCollection(TASKS_A, "Refused") +
        todoCollection(TASKS_B, "Genuinely empty"),
      onRequest: (url, method) => {
        if (method !== "REPORT") return null;
        return url === TASKS_A
          ? new Response(null, { status: 404 })
          : multistatus("");
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    const probe = taskProbeOf(result)!;
    expect(probe.collections[0].objects).toEqual([]);
    expect(probe.collections[1].objects).toEqual([]);
    // Identical object lists, different answers.
    expect(probe.collections[0].category).toBe("not_found");
    expect(probe.collections[1].category).toBeNull();
  });

  it("keeps the report when the probe is refused BEFORE any collection is reached", async () => {
    // A refusal on the home listing means no list was ever asked, which is a
    // different statement from a list being asked and refused -- so it is
    // carried on the probe rather than on an entry. Either way the surrounding
    // report survives: a diagnostic that discards its own measurements at the
    // first problem is useless for the one job it has.
    let seenHome = 0;
    const stub = davStub({
      onRequest: (url, _method) => {
        if (url !== CALDAV_HOME) return null;
        // The first listing belongs to the two services and must succeed, so
        // there is a real report for the probe's failure to survive inside.
        seenHome += 1;
        return seenHome === 1 ? null : new Response(null, { status: 404 });
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probeTaskObjects: true,
    });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text) as Record<string, unknown>;
    // The services' own measurements are still there.
    expect(
      (parsed.caldav as { homeUrl: string | null }).homeUrl,
    ).not.toBeNull();

    const probe = taskProbeOf(result)!;
    expect(probe.category).toBe("not_found");
    expect(probe.collections).toEqual([]);
    expect(probe.collectionsFound).toBe(0);
  });
});
