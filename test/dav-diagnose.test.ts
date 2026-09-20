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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SAFE_MESSAGES } from "../src/errors";
import type { DavDiagnosticOutcome } from "../src/dav/diagnose";
import { runDavDiagnosticOutcome } from "../src/dav/diagnose";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { createDavFetch } from "../src/dav/transport";
import { createServerFactory } from "../src/mcp/server";
import {
  davDiagnosticResult,
  registerDavDiagnoseTool,
} from "../src/mcp/tools/dav-diagnose";
import { principalFromEnv } from "../src/principal";
import {
  type BoundMailSecrets,
  assertMailSecretsBound,
  ownerPrincipal,
} from "./fixtures/bound-secrets";

// The owner's principal, as the PROMISE the real env constructor returns over
// the pool's ambient environment. The DAV fetch builder and the registrars take
// the promise. The no-op handler means a file that builds it and awaits it
// nowhere leaves no rejection unheard. Everyone who does await it still sees
// the refusal.
const owner = ownerPrincipal();
owner.catch(() => {});

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

/** Three calendars and the home collection itself, which is not one. */
function calendarListBody(): string {
  const calendar = (href: string, name: string) =>
    `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/><C:calendar/></resourcetype><displayname>${name}</displayname></prop></propstat></response>`;
  return (
    `<response><href>${CALDAV_HOME}</href><propstat><status>HTTP/1.1 200 OK</status><prop><resourcetype><collection/></resourcetype></prop></propstat></response>` +
    calendar(`${CALDAV_HOME}home/`, "Home") +
    calendar(`${CALDAV_HOME}work/`, "Work") +
    calendar(`${CALDAV_HOME}birthdays/`, "Birthdays")
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
      response = multistatus(calendarListBody());
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

/** Pull the one registered `dav_diagnose` callback out, without a real server. */
function diagnoseHandler(
  davFetch: ReturnType<typeof createDavFetch>,
): (args: { refresh?: boolean }) => Promise<{
  isError?: boolean;
  content: { type: "text"; text: string }[];
}> {
  let captured:
    | ((args: { refresh?: boolean }) => Promise<{
        isError?: boolean;
        content: { type: "text"; text: string }[];
      }>)
    | null = null;
  const server = {
    registerTool(
      _name: string,
      _options: Record<string, unknown>,
      callback: (args: { refresh?: boolean }) => Promise<{
        isError?: boolean;
        content: { type: "text"; text: string }[];
      }>,
    ) {
      captured = callback;
    },
  };
  registerDavDiagnoseTool(server as unknown as McpServer, davFetch);
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

describe("dav_diagnose, end to end", () => {
  beforeEach(async () => {
    await clearDavCache(env);
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
    expect(caldav.calendarCount).toBe(3);

    expect(carddav.homeUrl).toBe(CARDDAV_HOME);
    expect(carddav.shardHost).toBe("p61-contacts.icloud.com");
    expect(carddav.cacheHit).toBe(false);
    expect(carddav.addressBookCount).toBe(2);
    expect(carddav.reports).toContain("addressbookQuery");
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
    const cached = await resolveDavAccount(env, createDavFetch(owner), "caldav");

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
    assertMailSecretsBound(env);
    const bound: BoundMailSecrets = env;
    expect(bound.APPLE_ID.length).toBeGreaterThan(0);
    expect(bound.APPLE_APP_PASSWORD.length).toBeGreaterThan(0);

    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);
    const result = await diagnoseHandler(createDavFetch(owner))({});
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain(bound.APPLE_ID);
    expect(serialized).not.toContain(bound.APPLE_APP_PASSWORD);
  });

  it("fails with auth_failed BEFORE any request when a secret is absent", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);

    const refused = principalFromEnv({ ...env, APPLE_ID: undefined });
    refused.catch(() => {});

    const outcome: DavDiagnosticOutcome = await runDavDiagnosticOutcome(
      { ...env, APPLE_ID: undefined },
      createDavFetch(refused),
      { refresh: false },
    );

    expect(outcome.failed).toBe(true);
    expect(stub.requests.length).toBe(0);

    const shaped = davDiagnosticResult(outcome);
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
