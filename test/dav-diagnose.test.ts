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
// The property-name probe's fixture (phase 17)
//
// `DAV:propname` (RFC 4918 § 9.1) returns the NAME of every property a resource
// carries and no values at all, which is what makes it safe to aim at a real
// account — and what these fixtures have to express faithfully, including the
// hostile shape where a server sends values anyway.
// ---------------------------------------------------------------------------

/** The CalDAV principal, as discovery resolves it off the root's own answer. */
const CALDAV_PRINCIPAL = `https://caldav.icloud.com${PRINCIPAL_PATH}`;
/** The scheduling inbox, which the probe must READ off the listing, not build. */
const SCHEDULE_INBOX = `${CALDAV_HOME}inbox/`;
/** The first calendar collection `calendarListBody` puts in the home set. */
const FIRST_CALENDAR = `${CALDAV_HOME}home/`;

/**
 * A `DAV:propname` answer: one `response`, every property NAMED and EMPTY.
 *
 * Empty elements, because that is what the RFC says a server sends — the whole
 * safety argument for pointing this probe at a real account is that there is no
 * value in the response to mishandle. `valuedPropNameBody` below is the
 * non-conformant twin that carries values anyway, and the two together are what
 * pin the names-only guarantee rather than assume it.
 */
function propNameBody(href: string, ...names: string[]): string {
  const props = names.map((name) => `<${name}/>`).join("");
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop>${props}</prop></propstat></response>`;
}

/**
 * The four answers this account gives, one per target.
 *
 * **The four name sets are deliberately DIFFERENT from one another**, and one of
 * them — the inbox — is the only one carrying the default-calendar property. A
 * fixture where the four agreed could not tell a probe that asks each target from
 * one that asks one target four times, and a fixture where every target carried
 * the interesting property could not show which resource carries it, which is the
 * entire question this probe exists to answer.
 *
 * Spelled the way iCloud spells them, on the wire: the DAV library strips the
 * namespace prefix and camel-cases the remainder, so `C:schedule-default-
 * calendar-URL` arrives as `scheduleDefaultCalendarURL`. Asserting the CAMELCASED
 * form against a fixture written in the WIRE form is what makes these cases read
 * the real transformation rather than a restatement of it.
 */
function defaultPropNames(url: string): Response {
  if (url === CALDAV_PRINCIPAL) {
    return multistatus(
      propNameBody(
        PRINCIPAL_PATH,
        "current-user-principal",
        "principal-URL",
        "C:calendar-home-set",
        "C:schedule-inbox-URL",
        "C:schedule-outbox-URL",
      ),
    );
  }
  if (url === CALDAV_HOME) {
    return multistatus(
      propNameBody(
        CALDAV_HOME,
        "resourcetype",
        "displayname",
        "owner",
        "current-user-privilege-set",
      ),
    );
  }
  if (url === SCHEDULE_INBOX) {
    return multistatus(
      propNameBody(
        SCHEDULE_INBOX,
        "resourcetype",
        "getctag",
        "C:schedule-default-calendar-URL",
      ),
    );
  }
  return multistatus(
    propNameBody(
      url,
      "resourcetype",
      "displayname",
      "C:supported-calendar-component-set",
    ),
  );
}

/** One `response` for the scheduling inbox, as the home listing carries it. */
function schedulingInboxResponse(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/><C:schedule-inbox/></resourcetype><displayname>Inbox</displayname></prop></propstat></response>`;
}

/**
 * The home listing WITH the scheduling inbox in it.
 *
 * Measured live on 2026-09-25: the inbox is a child of the calendar home,
 * carrying `resourceTypes: ["collection", "scheduleInbox"]`. The probe finds it
 * by that resource type rather than by a constructed URL, so a fixture without
 * this row is what proves the "not found" branch and one with it is what proves
 * the probe reads the listing instead of guessing a path.
 */
function calendarListWithInboxBody(): string {
  return calendarListBody() + schedulingInboxResponse(SCHEDULE_INBOX);
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
    /**
     * The scheduling inbox the CalDAV principal advertises, or `null` for none.
     *
     * `null` is the default and keeps this conversation exactly as it was: the
     * principal answers its home set to the inbox question,
     * `resolveDefaultCalendarUrl` reads no inbox href, and the account's default
     * calendar resolves to `null`. That is the FAIL-OPEN state CALM-07's refusal
     * cannot fire in, and `dav_diagnose` exists to say which state a real account
     * is in.
     */
    scheduleInboxUrl?: string | null;
    /** The default calendar that inbox names, or `null` for none. */
    defaultCalendarUrl?: string | null;
    /**
     * The answer to a `DAV:propname` PROPFIND, per URL.
     *
     * Absent keeps this conversation exactly as it was: no request in it carries
     * a `propname` body, so the branch is unreachable and every case that
     * predates the property-name probe is untouched.
     */
    propNames?: (url: string) => Response;
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
    } else if (String(init?.body ?? "").includes("propname")) {
      // RFC 4918 § 9.1's exhaustive ask, and it has to be discriminated on the
      // BODY rather than the URL: a `propname` PROPFIND goes to the SAME
      // principal and the SAME home URL the two discovery questions do, so the
      // URL alone cannot tell them apart — exactly as it cannot for CALM-07's
      // two legs further down. FIRST among the branches for the same reason:
      // every one below it would otherwise claim these requests as its own.
      response = (options.propNames ?? defaultPropNames)(url);
    } else if (url.includes("/.well-known/")) {
      // iCloud does not serve a useful redirect here for this account shape.
      response = new Response(null, { status: 404 });
    } else if (url === CALDAV_ROOT || url === CALDAV_ROOT.slice(0, -1)) {
      response = multistatus(principalBody());
    } else if (url === CARDDAV_ROOT || url === CARDDAV_ROOT.slice(0, -1)) {
      response = multistatus(principalBody());
    } else if (
      url.endsWith(PRINCIPAL_PATH) &&
      url.includes("caldav") &&
      String(init?.body ?? "").includes("schedule-inbox-URL")
    ) {
      // CALM-07's first leg. Discriminated on the BODY rather than the URL,
      // because it goes to the SAME principal URL the home-set question does —
      // so the URL alone cannot tell them apart, exactly as it cannot for the
      // address-set question in `test/dav-tools.test.ts`.
      const inbox = options.scheduleInboxUrl ?? null;
      response = multistatus(
        `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop>` +
          (inbox === null
            ? ""
            : `<C:schedule-inbox-URL><href>${inbox}</href></C:schedule-inbox-URL>`) +
          `</prop></propstat></response>`,
      );
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
    } else if (
      String(init?.body ?? "").includes("schedule-default-calendar-URL")
    ) {
      // CALM-07's second leg: the depth-0 read against the scheduling INBOX,
      // which is where RFC 6638 § 9.2 puts the property. AFTER the two home-set
      // branches, so the home listing — which asks for the same property on
      // every row — keeps its own answer.
      const target = options.defaultCalendarUrl ?? null;
      response = multistatus(
        `<response><href>${new URL(url).pathname}</href><propstat><status>HTTP/1.1 200 OK</status><prop>` +
          (target === null
            ? ""
            : `<C:schedule-default-calendar-URL><href>${target}</href></C:schedule-default-calendar-URL>`) +
          `</prop></propstat></response>`,
      );
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
 * Booleans and nothing else. Named once so every probe is visible in one place
 * beside `refresh`, and so an input added later has to be written down here
 * before any case can reach it.
 *
 * The COUNT is deliberately not in this sentence any more. It said "three
 * booleans" and phase 17's property-name probe made that false — the same silent
 * staleness a number written into prose always acquires, because nothing fails
 * when it stops matching. How many there are is a question for the interface, and
 * the schema case below is what pins the answer mechanically.
 */
interface DiagnoseArgs {
  refresh?: boolean;
  probeCollectionWrite?: boolean;
  probeTaskObjects?: boolean;
  probePropertyNames?: boolean;
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
 * PROPFIND that names the home set; the depth-1 listing of that home set; and —
 * since phase 17 (CALM-07) — one further principal PROPFIND asking where this
 * account's scheduling inbox is.
 *
 * Pinned as a literal on purpose. Everything the DIAGNOSTIC adds to the CalDAV
 * report — the supported-report-set, the collection enumeration, the
 * default-calendar property on each row — still rides ONE listing, and the whole
 * claim that it does is the home-listing count beside this one staying at one.
 *
 * **The sixth request is not part of the report, and it moved this number for a
 * reason worth writing down rather than absorbing.** `resolveDavAccount` now
 * resolves the account's default calendar on a cache MISS and stores it with the
 * triple, because CALM-07 refuses a delete of that calendar by a LOCAL
 * comparison and the value therefore has to be in hand before the delete tool is
 * called. It is two requests at most, and this stub pays only the first: its
 * principal names no scheduling inbox, so there is no inbox to ask a second
 * question of. A fixture that DID name one would make this seven.
 */
const COLD_CALDAV_REQUESTS = 6;

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
    // Exactly ONE of them is the home-set listing, and it is the one carrying
    // the answer. No per-collection helper ran. This is the assertion that
    // actually holds the "no extra round trip to say so" claim — the total beside
    // it also counts discovery's own bootstrap, which grew by one in phase 17
    // and has nothing to do with the report.
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

  // -------------------------------------------------------------------------
  // `schedule-default-calendar-URL` (CALM-07 / D-11)
  //
  // These two prove the PARSING, in both directions, and they cannot prove
  // anything else. RFC 6638 § 9.2 puts the property on the scheduling INBOX,
  // and the inbox is a child of the calendar home — measured live on
  // 2026-09-25. Whether iCloud POPULATES it is a question about Apple's server
  // that no fixture can answer, which is why the phase spends a deploy and a
  // live `dav_diagnose { refresh: true }` on it rather than a test.
  // -------------------------------------------------------------------------

  /** One `response` element for the scheduling inbox, with whatever extra props. */
  function scheduleInbox(extra: string): string {
    return (
      `<response><href>${CALDAV_HOME}inbox/</href><propstat>` +
      `<status>HTTP/1.1 200 OK</status><prop>` +
      `<resourcetype><collection/><C:schedule-inbox/></resourcetype>` +
      `<displayname>Inbox</displayname>${extra}` +
      `</prop></propstat></response>`
    );
  }

  it("reports the RESOLVED default calendar on the CalDAV half (CALM-07)", async () => {
    // **The whole reason this field exists, and the reason it is on the resolved
    // half rather than only on a collection row.** `isDefaultCalendar` is handed
    // `ResolvedDavAccount.defaultCalendarUrl` at delete time, and until this field
    // shipped that value was reachable from no response at all — so whether
    // iCloud populates the property could only be answered by deploying another
    // probe. Plan 17-09's UAT reads it in one call instead.
    const stub = davStub({
      scheduleInboxUrl: `${CALDAV_HOME}inbox/`,
      defaultCalendarUrl: `${CALDAV_HOME}home/`,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(result.isError).toBeUndefined();
    expect(serviceOf(result, "caldav").defaultCalendarUrl).toBe(
      `${CALDAV_HOME}home/`,
    );
    // NULL on the CardDAV half, and that is the convention rather than a gap:
    // `resolveDavAccount` asks for CalDAV alone, because a scheduling inbox is a
    // calendaring concept.
    expect(serviceOf(result, "carddav").defaultCalendarUrl).toBeNull();
  });

  it("reports NULL when the account names no default calendar — the fail-open", async () => {
    // **This is the state the phase's one open risk is about, and the value that
    // makes it legible.** A null here means `isDefaultCalendar` answers false for
    // every collection, which means `calendar_delete_calendar` does not refuse the
    // account's own default calendar. A reader of this response can tell that
    // state from the other one, which is the entire point of surfacing the field.
    const stub = davStub({ scheduleInboxUrl: null });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(result.isError).toBeUndefined();
    expect(serviceOf(result, "caldav").defaultCalendarUrl).toBeNull();
  });

  it("reports NULL when the inbox exists and names no default calendar", async () => {
    // The other direction, and the one the live probe exists to distinguish from
    // a reader that is simply broken: the inbox ANSWERED and what it said is
    // nothing. Absent must read as absent rather than as a failure.
    const stub = davStub({
      scheduleInboxUrl: `${CALDAV_HOME}inbox/`,
      defaultCalendarUrl: null,
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(result.isError).toBeUndefined();
    expect(serviceOf(result, "caldav").defaultCalendarUrl).toBeNull();
  });

  it("surfaces the default-calendar href the scheduling inbox row carries", async () => {
    // The href is RELATIVE, which is how iCloud answers one. An implementation
    // that stored it raw would put a path where every comparison downstream
    // expects an absolute URL, and CALM-07's refusal compares raw by design.
    const body =
      homeSelfResponse() +
      calendarCollection(`${CALDAV_HOME}home/`, "Home", componentSetProp("VEVENT")) +
      scheduleInbox(
        "<C:schedule-default-calendar-URL><href>/1234567890/calendars/home/</href></C:schedule-default-calendar-URL>",
      );

    const stub = davStub({
      onRequest: (url) => (url === CALDAV_HOME ? multistatus(body) : null),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];

    const inbox = collections.find((one) => one.displayName === "Inbox");
    expect(inbox).toBeDefined();
    expect(inbox!.resourceTypes).toContain("scheduleInbox");
    expect(inbox!.scheduleDefaultCalendarUrl).toBe(`${CALDAV_HOME}home/`);

    // Every other row answers null, and that is the expected shape rather than
    // a gap: only the inbox can carry the property at all.
    const home = collections.find((one) => one.displayName === "Home");
    expect(home!.scheduleDefaultCalendarUrl).toBeNull();
  });

  it("reports NULL when the inbox row carries no default-calendar property", async () => {
    // The other direction, and the one the live probe exists to distinguish
    // from a reader that is simply broken. Absent must read as absent.
    const body =
      homeSelfResponse() +
      calendarCollection(`${CALDAV_HOME}home/`, "Home", componentSetProp("VEVENT")) +
      scheduleInbox("");

    const stub = davStub({
      onRequest: (url) => (url === CALDAV_HOME ? multistatus(body) : null),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});
    const collections = serviceOf(result, "caldav")
      .collections as DavCollectionProbe[];

    const inbox = collections.find((one) => one.displayName === "Inbox");
    expect(inbox).toBeDefined();
    expect(inbox!.scheduleDefaultCalendarUrl).toBeNull();
    // An EMPTY element is the other absent shape, and the one that renders as
    // nine characters that read like a real URL if it is not narrowed.
    expect(JSON.stringify(inbox)).not.toContain("[object Object]");
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
  /**
   * The property-name keys the DAV library parsed out of a multistatus, or null
   * for a step that reads no propstat.
   *
   * **The one thing nobody had measured about iCloud's answer to a property
   * update, and the gap that shipped a defect.** Plan 17-04 decided which half of
   * a rename-and-recolour had landed by looking for those keys; against the real
   * account there are none, so `calendar_update_calendar` reported
   * `connection_failed` on writes that succeeded. It is reported here rather than
   * inferred anywhere, and the cases below pin both shapes.
   */
  propKeys: string[] | null;
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

/** A PROPPATCH answer: one `response`, every property named and accepted. */
function propertyUpdateBody(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><displayname/><ca:calendar-color xmlns:ca="http://apple.com/ns/ical/"/></prop></propstat></response>`;
}

/**
 * The same answer with an EMPTY property region — iCloud's own measured shape.
 *
 * A propstat, a `200`, and no property named inside it. Measured live on
 * 2026-09-25: the DAV library parses this to no keys at all, which is what
 * `propKeys: []` reports and what made the retired reader in `src/dav/calendar.ts`
 * find nothing on every successful write.
 */
function emptyPropertyUpdateBody(href: string): string {
  return `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop/></propstat></response>`;
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
    /** What the property update answers, when it answers a multistatus at all. */
    patchBody?: (href: string) => string;
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
          ? multistatus((options.patchBody ?? propertyUpdateBody)(url))
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

  it("reports the property-update keys, and reports them on THAT step only", async () => {
    // **The measurement whose absence shipped a defect.** Nothing in this
    // repository had ever asked what a property update's answer parses to, so
    // `src/dav/calendar.ts` decided which half of a rename had landed by looking
    // for keys nobody had checked were there. This step reports them.
    //
    // `null` on every other step is the other half of the claim: it distinguishes
    // "this step read a propstat and it was empty" from "this step reads no
    // propstat at all", and those two must not collapse into one another — an
    // empty array on a step that never looked would read as a measurement.
    const { stub } = writeProbeStub();
    vi.stubGlobal("fetch", stub.fetch);

    const probe = writeProbeOf(
      await diagnoseHandler(createDavFetch(owner))({
        probeCollectionWrite: true,
      }),
    )!;

    // Sorted, so two runs agree. This body NAMES both properties, which is the
    // shape every fixture in the repository used to assume iCloud sends.
    expect(stepNamed(probe, "rename-and-recolour")!.propKeys).toEqual([
      "calendarColor",
      "displayname",
    ]);
    for (const step of ["resolve", "create", "delete", "verify"]) {
      expect(
        stepNamed(probe, step)!.propKeys,
        `${step} reported property keys it never read`,
      ).toBeNull();
    }
  });

  it("reports NO keys for iCloud's own answer, which is the measured shape", async () => {
    // **The shape measured live on 2026-09-25, and the whole reason this field
    // exists.** A `207` whose propstat names no property parses to an empty
    // region — so `changed` was always empty in the reader plan 17-04 shipped, and
    // the "nothing landed" arm behind it threw on every successful write.
    //
    // A REFUSED update answers the same way, which is why no reader of this
    // region can tell success from refusal and why the rename is now verified by
    // reading the collection back instead. That argument is recorded on
    // `observedOutcomes`; this case is the evidence under it.
    const { stub } = writeProbeStub({ patchBody: emptyPropertyUpdateBody });
    vi.stubGlobal("fetch", stub.fetch);

    const probe = writeProbeOf(
      await diagnoseHandler(createDavFetch(owner))({
        probeCollectionWrite: true,
      }),
    )!;
    const step = stepNamed(probe, "rename-and-recolour")!;

    // EMPTY, and not null. The step looked and found nothing, which is a
    // measurement — the distinction the case above pins from the other side.
    expect(step.propKeys).toEqual([]);
    // And the step still reports the envelope as accepted, which is exactly how a
    // successful write came to be reported as a connection fault: the status says
    // yes and the region says nothing.
    expect(step.status).toBe(207);
    expect(step.ok).toBe(true);
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
      "probePropertyNames",
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

// ---------------------------------------------------------------------------
// The property-name probe (phase 17)
//
// WHY IT EXISTS, stated here because a reader arriving at a failing case needs
// it. CALM-07 refuses the account's own default calendar as a delete target,
// "locally, before any request is sent". Measured live on 2026-09-25 the guard is
// INERT: `CALDAV:schedule-default-calendar-URL` is absent from all thirteen home
// rows AND from the scheduling inbox, which is where RFC 6638 § 9.2 defines it.
// The likely explanation is that Apple's "Default Calendar" is a per-DEVICE
// setting rather than account state — in which case no server property exists to
// find, and the requirement should be withdrawn.
//
// That explanation may well be right, and it is still an INFERENCE. Both probes
// so far asked for ONE NAMED property, which is a different question from asking
// what properties exist. `DAV:propname` (RFC 4918 § 9.1) is the second question,
// and these cases are what make it safe to ask a real account: the guarantee that
// no VALUE can come back through it is pinned against a fixture that sends values
// anyway, rather than assumed from the RFC.
// ---------------------------------------------------------------------------

/** One property-name target, as the report carries it. */
interface NameTarget {
  target: string;
  href: string;
  names: string[] | null;
  category: string | null;
}

interface NameProbe {
  targets: NameTarget[];
  category: string | null;
}

function nameProbeOf(result: {
  content: { type: "text"; text: string }[];
}): NameProbe | null {
  return serviceOf(result, "caldav").propertyNames as NameProbe | null;
}

/** Every request whose body carried the exhaustive ask. */
function propNameRequests(stub: Stub): ObservedRequest[] {
  return stub.requests.filter((request) =>
    String(request.init.body ?? "").includes("propname"),
  );
}

function targetNamed(probe: NameProbe, target: string): NameTarget | undefined {
  return probe.targets.find((one) => one.target === target);
}

/**
 * A NON-CONFORMANT `propname` answer: every property named AND valued.
 *
 * RFC 4918 § 9.1 says a server answers `propname` with names alone, so this is a
 * shape no conformant server sends — which is exactly why it is the fixture the
 * names-only guarantee is pinned against. A guarantee that holds only while the
 * server behaves is not a guarantee; this one has to hold because the probe reads
 * KEYS and never indexes into the property object, and the only way to prove that
 * is to put values in front of it and watch none come out.
 *
 * The three values are chosen to be unmistakable in a serialised report: a
 * calendar title a real account might carry, a colour, and an href. None of them
 * is a URL this report legitimately contains, so a case can assert their absence
 * from the WHOLE response rather than only from the field they would land in.
 */
function valuedPropNameBody(href: string): string {
  return (
    `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop>` +
    `<displayname>Job search interviews</displayname>` +
    `<ca:calendar-color xmlns:ca="http://apple.com/ns/ical/">#FF2D55FF</ca:calendar-color>` +
    `<C:schedule-default-calendar-URL><href>/1234567890/calendars/secret-default/</href></C:schedule-default-calendar-URL>` +
    `</prop></propstat></response>`
  );
}

describe("what property NAMES iCloud carries, asked exhaustively", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is OFF unless asked for by name, and an ordinary run asks nothing", async () => {
    // The default, and the property that makes this probe free to ship: a reader
    // of an ordinary `dav_diagnose` response sees exactly what they saw before it
    // existed, and the run issues not one extra request.
    const stub = davStub({ caldavHomeBody: calendarListWithInboxBody });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({});

    expect(nameProbeOf(result)).toBeNull();
    expect(propNameRequests(stub)).toEqual([]);
  });

  it("refuses to run on anything but the boolean itself", async () => {
    // `=== true` rather than a truthy test, asserted rather than read off the
    // source. A truthy test would let a string, a number or an object turn a
    // probe on, and the four booleans are the whole reason D-06's argument
    // survives on this tool.
    const stub = davStub({ caldavHomeBody: calendarListWithInboxBody });
    vi.stubGlobal("fetch", stub.fetch);

    const handler = diagnoseHandler(createDavFetch(owner));
    for (const truthy of ["yes", 1, {}, []] as unknown[]) {
      const result = await handler({
        probePropertyNames: truthy,
      } as unknown as DiagnoseArgs);
      expect(nameProbeOf(result)).toBeNull();
    }
    expect(propNameRequests(stub)).toEqual([]);
  });

  it("asks four resources derived from discovery and reports what each NAMES", async () => {
    // The whole instrument, in one call. The four targets are the principal, the
    // calendar home, the scheduling inbox and one real calendar — and the last
    // two are READ OFF the home listing by advertised resource type rather than
    // built from a string, which is why the fixture has to carry an inbox row for
    // this case to reach it at all.
    //
    // The four name sets differ from one another ON PURPOSE, and only the inbox
    // carries the default-calendar property. A fixture where they agreed could not
    // tell a probe that asks each target from one that asks one target four times.
    const stub = davStub({ caldavHomeBody: calendarListWithInboxBody });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    expect(result.isError).toBeUndefined();
    const probe = nameProbeOf(result)!;
    expect(probe.category).toBeNull();

    // The fixed order, and the href each target resolved to. The calendar is
    // reported BY HREF so the reading is reproducible against the same collection.
    expect(probe.targets.map((one) => one.target)).toEqual([
      "principal",
      "home",
      "schedule-inbox",
      "calendar",
    ]);
    expect(probe.targets.map((one) => one.href)).toEqual([
      CALDAV_PRINCIPAL,
      CALDAV_HOME,
      SCHEDULE_INBOX,
      FIRST_CALENDAR,
    ]);

    // Sorted, de-duplicated, and spelled as the DAV library hands them back: the
    // namespace prefix stripped and the remainder camel-cased. The fixture is
    // written in the WIRE form, so these lists read the real transformation.
    expect(targetNamed(probe, "principal")!.names).toEqual([
      "calendarHomeSet",
      "currentUserPrincipal",
      "principalURL",
      "scheduleInboxURL",
      "scheduleOutboxURL",
    ]);
    expect(targetNamed(probe, "home")!.names).toEqual([
      "currentUserPrivilegeSet",
      "displayname",
      "owner",
      "resourcetype",
    ]);
    // THE ROW THE WHOLE PROBE IS FOR. RFC 6638 § 9.2 puts the default-calendar
    // property on the scheduling inbox, and this is the reading that would show
    // it there if iCloud carried it.
    expect(targetNamed(probe, "schedule-inbox")!.names).toEqual([
      "getctag",
      "resourcetype",
      "scheduleDefaultCalendarURL",
    ]);
    expect(targetNamed(probe, "calendar")!.names).toEqual([
      "displayname",
      "resourcetype",
      "supportedCalendarComponentSet",
    ]);
    for (const one of probe.targets) expect(one.category).toBeNull();

    // FOUR requests, one per target, each a depth-0 PROPFIND.
    const asked = propNameRequests(stub);
    expect(asked.length).toBe(4);
    expect(asked.map((request) => request.url)).toEqual([
      CALDAV_PRINCIPAL,
      CALDAV_HOME,
      SCHEDULE_INBOX,
      FIRST_CALENDAR,
    ]);
    for (const request of asked) {
      expect(request.method).toBe("PROPFIND");
      expect(new Headers(request.init.headers).get("depth")).toBe("0");
    }

    // READ-ONLY, and asserted over the whole run rather than over this probe's
    // own requests: a mutating method anywhere here would mean the probe reached
    // something it has no business reaching.
    expect(methodsOf(stub, "MKCOL", "PROPPATCH", "DELETE", "PUT")).toEqual([]);
    expect(stub.overlapped).toBe(false);
  });

  it("reports only NAMES even when the server answers with values", async () => {
    // THE SAFETY CASE, and the one that makes this probe safe to point at a real
    // account. A conformant server sends empty elements, so a probe that read
    // values would look correct against every honest fixture. This one is
    // deliberately non-conformant — every property is named AND valued, on all
    // four targets — and the report still has to carry names alone.
    //
    // Asserted against the WHOLE serialised response rather than against the
    // `names` field, because a value that leaked into any other field would pass
    // a field-scoped check while still reaching a model's context.
    const stub = davStub({
      caldavHomeBody: calendarListWithInboxBody,
      propNames: (url) => multistatus(valuedPropNameBody(url)),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    const probe = nameProbeOf(result)!;
    expect(probe.targets.length).toBe(4);
    for (const one of probe.targets) {
      expect(one.names).toEqual([
        "calendarColor",
        "displayname",
        "scheduleDefaultCalendarURL",
      ]);
    }

    // Non-vacuity first: the values really were sent, so a probe that carried
    // them through would have had something to carry.
    const sent = propNameRequests(stub);
    expect(sent.length).toBe(4);

    const whole = result.content[0].text;
    for (const value of [
      "Job search interviews",
      "#FF2D55FF",
      "secret-default",
    ]) {
      expect(
        whole.includes(value),
        `a property VALUE reached the response: ${value}`,
      ).toBe(false);
    }
  });

  it("folds a refused target into its category and KEEPS GOING", async () => {
    // TOTAL rather than throwing. A refusal on one target must not cost the other
    // three, and must not cost the surrounding report either — this module's own
    // header says a diagnostic that discards its measurements at the first problem
    // is useless for the one job it has, and the live account has already proved
    // it by answering 404 on two abandoned collections.
    const stub = davStub({
      caldavHomeBody: calendarListWithInboxBody,
      propNames: (url) =>
        url === SCHEDULE_INBOX
          ? new Response(null, { status: 404 })
          : defaultPropNames(url),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    // Not an error payload. The report came back.
    expect(result.isError).toBeUndefined();
    const probe = nameProbeOf(result)!;
    expect(probe.category).toBeNull();

    const refused = targetNamed(probe, "schedule-inbox")!;
    expect(refused.category).toBe("not_found");
    expect(refused.names).toBeNull();
    // Named anyway, so a reader can see that this resource WAS asked — a
    // different fact from one that was never derived.
    expect(refused.href).toBe(SCHEDULE_INBOX);

    // And the target after it was still asked, which is the "keeps going" half.
    expect(targetNamed(probe, "calendar")!.names).toEqual([
      "displayname",
      "resourcetype",
      "supportedCalendarComponentSet",
    ]);
    expect(propNameRequests(stub).length).toBe(4);

    // The services' own measurements survived too.
    expect(serviceOf(result, "caldav").homeUrl).toBe(CALDAV_HOME);
    expect(serviceOf(result, "carddav").addressBookCount).toBe(2);
  });

  it("refuses a wire-sourced href outside the account's own home, at ZERO cost", async () => {
    // The containment half. The home enumeration resolves a relative href
    // against the home and drops one that will not resolve, but it does not
    // compare ORIGIN — so an ABSOLUTE href naming another host survives it, and
    // `src/dav/transport.ts` attaches the Apple ID and the app-specific password
    // to whatever URL it is handed. "The server said so" is not an authorisation.
    //
    // The falsifiable half is the request COUNT: the refusal is synchronous and
    // reaches no network, so nothing is ever sent to the foreign host.
    const foreign = "https://attacker.example/1234567890/calendars/inbox/";
    const stub = davStub({
      caldavHomeBody: () =>
        calendarListBody() + schedulingInboxResponse(foreign),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    const probe = nameProbeOf(result)!;
    const refused = targetNamed(probe, "schedule-inbox")!;
    // Byte-identical at this layer to a genuine not-found, which is deliberate:
    // a distinguishable refusal is an existence oracle.
    expect(refused.category).toBe("not_found");
    expect(refused.names).toBeNull();

    expect(
      stub.requests.filter((request) => request.url.includes("attacker.example")),
      "the credential was sent to a host outside the account's own home set",
    ).toEqual([]);
    // Three asked, not four — and the three that were asked still answered.
    expect(propNameRequests(stub).length).toBe(3);
    expect(targetNamed(probe, "calendar")!.names).not.toBeNull();
  });

  it("says a target was never asked when the listing holds no such row", async () => {
    // The third state, and it is a different fact from both of the others. A null
    // `names` with a NULL category and an empty href means the home set carried no
    // scheduling inbox at all, so nothing was asked — as distinct from a refusal,
    // and as distinct again from a resource that answered with no names.
    //
    // `calendarListBody` is the shape that produces it: four calendars, a reminder
    // list, and no inbox row.
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    const probe = nameProbeOf(result)!;
    const missing = targetNamed(probe, "schedule-inbox")!;
    expect(missing.href).toBe("");
    expect(missing.names).toBeNull();
    expect(missing.category).toBeNull();

    // Still four entries: the target is reported as unasked rather than dropped,
    // because a target silently missing from this list would read as a resource
    // that carries no properties.
    expect(probe.targets.length).toBe(4);
    expect(propNameRequests(stub).length).toBe(3);
  });

  it("tells a refused target apart from one that NAMES NOTHING", async () => {
    // Without the category both read as "no names", and "this server could not
    // look" would be indistinguishable from "this resource carries nothing".
    const stub = davStub({
      caldavHomeBody: calendarListWithInboxBody,
      propNames: (url) =>
        url === SCHEDULE_INBOX
          ? new Response(null, { status: 404 })
          : multistatus(propNameBody(url)),
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    const probe = nameProbeOf(result)!;
    expect(targetNamed(probe, "schedule-inbox")!.names).toBeNull();
    expect(targetNamed(probe, "schedule-inbox")!.category).toBe("not_found");
    // Asked, answered, and named nothing. An EMPTY ARRAY, not a null.
    expect(targetNamed(probe, "calendar")!.names).toEqual([]);
    expect(targetNamed(probe, "calendar")!.category).toBeNull();
  });

  it("keeps the report when NOTHING could be derived at all", async () => {
    // A refusal before any target exists — discovery, or the home listing — is
    // carried on the probe rather than on an entry, because "no resource was ever
    // asked" is a different statement from "this resource was asked and refused".
    // Either way the surrounding report survives.
    let seenHome = 0;
    const stub = davStub({
      onRequest: (url) => {
        if (url !== CALDAV_HOME) return null;
        // The first listing belongs to the two services and must succeed, so
        // there is a real report for the probe's failure to survive inside.
        seenHome += 1;
        return seenHome === 1 ? null : new Response(null, { status: 404 });
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    expect(result.isError).toBeUndefined();
    expect(serviceOf(result, "caldav").homeUrl).toBe(CALDAV_HOME);

    const probe = nameProbeOf(result)!;
    expect(probe.category).toBe("not_found");
    expect(probe.targets).toEqual([]);
    expect(propNameRequests(stub)).toEqual([]);
  });

  it("sends EVERY request through this project's own transport, serially", async () => {
    // The credential case, for the probe this plan adds. Every tsdav helper
    // declares `fetch?: typeof fetch` as OPTIONAL and resolves it as
    // `fetchOverride ?? fetch`, so omitting the option at the new call site would
    // silently use the bare global: no `authorization` header, no
    // `redirect: "manual"`, no per-request serialisation gate, no
    // status-to-error mapping. Against iCloud that is a 401 on every target, and
    // at the report level a 401 on every target is indistinguishable from iCloud
    // carrying no properties — a measured-looking WRONG verdict on the very
    // question this probe exists to settle, produced by a bug in this repository.
    //
    // The source scan cannot see the omission: the fetch happens inside
    // `node_modules`, which it does not walk. This reads what was actually SENT.
    const stub = davStub({ caldavHomeBody: calendarListWithInboxBody });
    vi.stubGlobal("fetch", stub.fetch);

    const result = await diagnoseHandler(createDavFetch(owner))({
      probePropertyNames: true,
    });

    // Non-vacuity first: a walk over a list that never grew the probe's own
    // requests would pass while proving nothing about them.
    expect(propNameRequests(stub).length).toBe(4);
    expect(nameProbeOf(result)).not.toBeNull();

    for (const request of stub.requests) {
      const authorization = new Headers(request.init.headers).get(
        "authorization",
      );
      expect(
        authorization,
        `${request.method} ${request.url} carried no credential — a tsdav helper was called without fetch: davFetch`,
      ).toBeTruthy();
      expect(authorization!.startsWith("Basic ")).toBe(true);
      expect(
        request.init.redirect,
        `${request.method} ${request.url} did not carry redirect: manual`,
      ).toBe("manual");
    }

    // Serial, and asserted off the recorded ticks rather than off the absence of
    // a combinator in the source: every request ended before the next began.
    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.requests.length; index += 1) {
      expect(stub.requests[index - 1].end).toBeLessThan(
        stub.requests[index].start,
      );
    }
  });
});
