// The calendar half of the change check, at the request level (CHNG-01,
// CHNG-04, CHNG-05, CHNG-06).
//
// Every case drives the real `calendarChangesSince` through the real
// `createDavFetch`, with the global fetch stubbed by a small router on method
// and URL. Every multistatus body is a literal. The stub keeps a request log
// (method, URL, body) and counts how many requests are inside it at once, so a
// fan-out shows up as a maximum above one rather than as a faster test.
//
// No network and no real credentials (D-36: live testing is owner-only).

import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CalendarBlock } from "../src/change-marker";
import { calendarKeyOf } from "../src/change-marker";
import { calendarChangesSince, readSyncAnswer } from "../src/dav/calendar";
import type { CalendarChanges } from "../src/dav/calendar";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { DavAuthError, DavThrottleError } from "../src/dav/errors";
import { encodeCalendarId } from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

const owner = ownerPrincipal();
owner.catch(() => {});
let principal: Principal;

const CALDAV_SERVER = "https://caldav.icloud.com";
const PRINCIPAL_PATH = "/1234567890/principal/";
const HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";
const HOME_PATH = "/1234567890/calendars/";

const WORK = `${HOME}work/`;
const FAMILY = `${HOME}family/`;
const HOLIDAYS = `${HOME}holidays/`;

const XML_HEADERS = { "content-type": "text/xml; charset=utf-8" };

function multistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/" xmlns:CA="http://apple.com/ns/ical/">${body}</multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

interface Cal {
  url: string;
  name: string;
  /** `null` means the property is absent from the answer. */
  token: string | null;
  subscribed?: boolean;
}

function collectionEntry(cal: Cal): string {
  const type = cal.subscribed
    ? "<collection/><CS:subscribed/>"
    : "<collection/><C:calendar/>";
  const token = cal.token === null ? "" : `<sync-token>${cal.token}</sync-token>`;
  return (
    `<response><href>${new URL(cal.url).pathname}</href><propstat>` +
    `<prop><displayname>${cal.name}</displayname><resourcetype>${type}</resourcetype>` +
    `<C:supported-calendar-component-set><C:comp name="VEVENT"/></C:supported-calendar-component-set>` +
    `${token}</prop><status>HTTP/1.1 200 OK</status></propstat></response>`
  );
}

function homeListing(cals: readonly Cal[]): Response {
  return multistatus(
    `<response><href>${HOME_PATH}</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>` +
      cals.map(collectionEntry).join(""),
  );
}

/** A member or the collection itself, answered 200 with an etag. */
function ok(href: string, etag = '"e1"'): string {
  return `<response><href>${href}</href><propstat><prop><getetag>${etag}</getetag></prop><status>HTTP/1.1 200 OK</status></propstat></response>`;
}

/** A removed member: the status line iCloud sends, with no reason phrase. */
function removed(href: string): string {
  return `<response><href>${href}</href><status>HTTP/1.1 404</status></response>`;
}

function syncAnswer(entries: string, token: string | null): Response {
  return multistatus(
    entries + (token === null ? "" : `<sync-token>${token}</sync-token>`),
  );
}

function syncTokenRefusal(status: number): Response {
  return new Response(
    `<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:valid-sync-token/></D:error>`,
    { status, headers: XML_HEADERS },
  );
}

interface Logged {
  method: string;
  url: string;
  body: string;
}

interface Stub {
  log: Logged[];
  maxInFlight: number;
  fetch: typeof globalThis.fetch;
}

/**
 * The router. Discovery is answered like test/dav-calendar.test.ts answers it.
 * The home PROPFIND answers the listing; a REPORT answers from `report`.
 */
function davStub(
  cals: readonly Cal[],
  report: (url: string, body: string) => Response = () =>
    new Response(null, { status: 500 }),
  home: () => Response = () => homeListing(cals),
): Stub {
  const state: Stub = {
    log: [],
    maxInFlight: 0,
    fetch: async () => new Response(null, { status: 500 }),
  };
  let open = 0;

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET").toUpperCase();
    const body =
      init?.body === undefined || init?.body === null ? "" : String(init.body);
    state.log.push({ method, url, body });

    open += 1;
    state.maxInFlight = Math.max(state.maxInFlight, open);
    await new Promise((resolve) => setTimeout(resolve, 0));
    open -= 1;

    if (url.includes("/.well-known/")) return new Response(null, { status: 404 });
    if (url.startsWith(CALDAV_SERVER)) {
      if (url.endsWith(PRINCIPAL_PATH)) {
        return multistatus(
          `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:calendar-home-set><href>${HOME}</href></C:calendar-home-set></prop></propstat></response>`,
        );
      }
      return multistatus(
        `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`,
      );
    }
    if (method === "PROPFIND" && url === HOME) return home();
    if (method === "REPORT") return report(url, body);
    return new Response(null, { status: 500 });
  }) as typeof globalThis.fetch;

  return state;
}

/** Resolve discovery first, so every log below holds the change check only. */
async function warm(stub: Stub): Promise<void> {
  vi.stubGlobal("fetch", stub.fetch);
  await clearDavCache(env, principal, "caldav");
  await resolveDavAccount(env, principal, createDavFetch(owner), "caldav");
  stub.log.length = 0;
  stub.maxInFlight = 0;
}

async function run(
  stub: Stub,
  prior: CalendarBlock | null,
  restartAll = false,
): Promise<CalendarChanges> {
  await warm(stub);
  return calendarChangesSince(env, principal, createDavFetch(owner), prior, restartAll);
}

async function block(
  entries: readonly [string, string][],
  takenAt = 1790000000,
): Promise<CalendarBlock> {
  return {
    takenAt,
    calendars: await Promise.all(
      entries.map(async ([url, syncToken]) => ({
        key: await calendarKeyOf(url),
        syncToken,
      })),
    ),
  };
}

const idOf = (url: string) => encodeCalendarId({ collectionUrl: url });

beforeEach(async () => {
  principal = await owner;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const TWO: Cal[] = [
  { url: WORK, name: "Work", token: "work-2" },
  { url: FAMILY, name: "Family", token: "family-1" },
];

describe("calendarChangesSince: the cheap path (D-23)", () => {
  it("no prior block: one PROPFIND asking for sync-token, no REPORT, every calendar started", async () => {
    const stub = davStub(TWO);
    const result = await run(stub, null);

    expect(stub.log.map((one) => `${one.method} ${one.url}`)).toEqual([
      `PROPFIND ${HOME}`,
    ]);
    expect(stub.log[0]!.body).toContain("sync-token");
    expect(stub.log[0]!.body).toContain("displayname");
    expect(stub.log[0]!.body).toContain("resourcetype");

    // URL order: family before work.
    expect(result.calendars.map((one) => [one.calendarId, one.state])).toEqual([
      [idOf(FAMILY), "started"],
      [idOf(WORK), "started"],
    ]);
    expect(result.calendars.every((one) => one.mechanism === "propfind-token")).toBe(true);
    expect(result.calendars.every((one) => one.addedOrChanged === null)).toBe(true);
    expect(result.fresh.calendars).toEqual([
      { key: await calendarKeyOf(FAMILY), syncToken: "family-1" },
      { key: await calendarKeyOf(WORK), syncToken: "work-2" },
    ]);
    expect(result.notCovered).toEqual([]);
    expect(result.gone).toBe(0);
  });

  it("restartAll: every calendar restarted from its property token, no REPORT", async () => {
    const stub = davStub(TWO);
    const result = await run(stub, null, true);
    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    expect(result.calendars.map((one) => one.state)).toEqual([
      "restarted",
      "restarted",
    ]);
  });

  it("all tokens equal: one PROPFIND, no REPORT, every calendar no_changes", async () => {
    const stub = davStub(TWO);
    const prior = await block([
      [WORK, "work-2"],
      [FAMILY, "family-1"],
    ]);
    const result = await run(stub, prior);

    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    for (const one of result.calendars) {
      expect(one.state).toBe("no_changes");
      expect(one.mechanism).toBe("propfind-token");
      expect(one.addedOrChanged).toBe(0);
      expect(one.removed).toBe(0);
      expect(one.more).toBe(false);
    }
  });

  it("a calendar new since the marker is started", async () => {
    const stub = davStub(TWO);
    const result = await run(stub, await block([[WORK, "work-2"]]));
    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    expect(result.calendars.map((one) => [one.calendarId, one.state])).toEqual([
      [idOf(FAMILY), "started"],
      [idOf(WORK), "no_changes"],
    ]);
  });
});

describe("calendarChangesSince: a moved token (D-23, D-24, D-25)", () => {
  const WORK_PATH = new URL(WORK).pathname;

  it("costs exactly one REPORT carrying the old token; the collection's own href is not counted", async () => {
    const stub = davStub(TWO, () =>
      syncAnswer(
        ok(WORK_PATH, '"coll"') +
          ok(`${WORK_PATH}a.ics`) +
          ok(`${WORK_PATH}b.ics`) +
          removed(`${WORK_PATH}c.ics`),
        "work-3",
      ),
    );
    const prior = await block([
      [WORK, "work-1"],
      [FAMILY, "family-1"],
    ]);
    const result = await run(stub, prior);

    expect(stub.log.map((one) => `${one.method} ${one.url}`)).toEqual([
      `PROPFIND ${HOME}`,
      `REPORT ${WORK}`,
    ]);
    const report = stub.log[1]!.body;
    expect(report).toContain("sync-collection");
    expect(report).toContain("work-1");
    expect(report).toMatch(/<d:sync-level>1<\/d:sync-level>/);
    expect(report).toContain("getetag");
    expect(report).not.toContain("calendar-data");

    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "changes",
      addedOrChanged: 2,
      removed: 1,
      more: false,
      mechanism: "sync-report",
    });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-3",
    });
    expect(stub.maxInFlight).toBe(1);
  });

  it("an empty multistatus with a new token is no_changes, and keeps the new token", async () => {
    const stub = davStub(TWO, () => syncAnswer("", "work-3"));
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "no_changes",
      addedOrChanged: 0,
      removed: 0,
      mechanism: "sync-report",
    });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-3",
    });
  });

  it("an answer carrying no sync token is not_checked, never no_changes, and keeps the old token", async () => {
    const stub = davStub(TWO, () => syncAnswer("", null));
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("not_checked");
    expect(work.reason).toBe("no_usable_answer");
    expect(work.addedOrChanged).toBeNull();
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-1",
      takenAt: 1790000000,
    });
  });

  it("a REPORT refused with the valid-sync-token element restarts that calendar", async () => {
    const stub = davStub(TWO, () => syncTokenRefusal(403));
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("restarted");
    expect(work.why).toBe("token_refused");
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-2",
    });
  });

  it("a REPORT 403 without the element, after the PROPFIND succeeded, restarts with its own why", async () => {
    const stub = davStub(TWO, () =>
      new Response("<error/>", { status: 403, headers: XML_HEADERS }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("restarted");
    expect(work.why).toBe("listing_refused");
    expect(work.why).not.toBe("token_refused");
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-2",
    });
  });

  it("a truncated answer (507 on the collection) is changes with more, keeping the returned token", async () => {
    const stub = davStub(TWO, () =>
      syncAnswer(
        `<response><href>${WORK_PATH}</href><status>HTTP/1.1 507 Insufficient Storage</status></response>` +
          ok(`${WORK_PATH}a.ics`),
        "work-3",
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ state: "changes", more: true, addedOrChanged: 1 });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-3",
    });
  });

  it("a member element that failed makes the whole answer not_checked", async () => {
    const stub = davStub(TWO, () =>
      syncAnswer(
        ok(`${WORK_PATH}a.ics`) +
          `<response><href>${WORK_PATH}b.ics</href><status>HTTP/1.1 500</status></response>`,
        "work-3",
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("not_checked");
    expect(work.reason).toBe("no_usable_answer");
  });
});

describe("calendarChangesSince: a throttle stops the calendar side (D-29)", () => {
  it("the first REPORT answered 503: it and the second are not_checked, old tokens kept, and nothing is sent after", async () => {
    const cals: Cal[] = [
      { url: FAMILY, name: "Family", token: "family-2" },
      { url: WORK, name: "Work", token: "work-2" },
    ];
    const stub = davStub(cals, () => new Response(null, { status: 503 }));
    const prior = await block([
      [FAMILY, "family-1"],
      [WORK, "work-1"],
    ]);
    const result = await run(stub, prior);

    expect(stub.log.map((one) => `${one.method} ${one.url}`)).toEqual([
      `PROPFIND ${HOME}`,
      `REPORT ${FAMILY}`,
    ]);
    expect(result.calendars.map((one) => [one.state, one.reason])).toEqual([
      ["not_checked", "throttled"],
      ["not_checked", "throttled"],
    ]);
    expect(result.fresh.calendars).toEqual([
      { key: await calendarKeyOf(FAMILY), syncToken: "family-1", takenAt: 1790000000 },
      { key: await calendarKeyOf(WORK), syncToken: "work-1", takenAt: 1790000000 },
    ]);
  });

  it("a carried calendar keeps the takenAt it already had", async () => {
    const stub = davStub(TWO, () => new Response(null, { status: 503 }));
    const prior: CalendarBlock = {
      takenAt: 1790000500,
      calendars: [
        { key: await calendarKeyOf(FAMILY), syncToken: "family-1" },
        { key: await calendarKeyOf(WORK), syncToken: "work-1", takenAt: 1790000000 },
      ],
    };
    const result = await run(stub, prior);
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-1",
      takenAt: 1790000000,
    });
  });

  it("a throttle at the home PROPFIND is thrown to the caller", async () => {
    const stub = davStub(TWO, undefined, () => new Response(null, { status: 429 }));
    await warm(stub);
    await expect(
      calendarChangesSince(env, principal, createDavFetch(owner), null, false),
    ).rejects.toBeInstanceOf(DavThrottleError);
  });

  it("a sign-in refusal at the home PROPFIND is thrown to the caller", async () => {
    const stub = davStub(TWO, undefined, () => new Response(null, { status: 401 }));
    await warm(stub);
    await expect(
      calendarChangesSince(env, principal, createDavFetch(owner), null, false),
    ).rejects.toBeInstanceOf(DavAuthError);
  });
});

describe("calendarChangesSince: which calendars (D-22)", () => {
  it("a subscription gets no REPORT and is listed once as not covered", async () => {
    const cals: Cal[] = [
      ...TWO,
      { url: HOLIDAYS, name: "Holidays", token: "h-9", subscribed: true },
    ];
    const stub = davStub(cals);
    const result = await run(stub, await block([[WORK, "work-2"], [FAMILY, "family-1"]]));
    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    expect(result.notCovered).toEqual([{ calendarId: idOf(HOLIDAYS), displayName: "Holidays" }]);
    expect(result.calendars.map((one) => one.calendarId)).not.toContain(idOf(HOLIDAYS));
    expect(result.fresh.calendars).toHaveLength(2);
  });

  it("a calendar in the prior block and absent now is counted as gone and dropped", async () => {
    const stub = davStub(TWO);
    const result = await run(
      stub,
      await block([
        [WORK, "work-2"],
        [FAMILY, "family-1"],
        [`${HOME}old/`, "old-1"],
      ]),
    );
    expect(result.gone).toBe(1);
    expect(result.fresh.calendars).toHaveLength(2);
  });

  it("a REPORT answered 404 makes that calendar gone", async () => {
    const stub = davStub(TWO, () => new Response(null, { status: 404 }));
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("gone");
    expect(result.fresh.calendars.map((one) => one.syncToken)).toEqual(["family-1"]);
  });

  it("a calendar with no token property is not_checked for now, and keeps its old token", async () => {
    const cals: Cal[] = [
      { url: WORK, name: "Work", token: null },
      { url: FAMILY, name: "Family", token: "family-1" },
    ];
    const stub = davStub(cals);
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("not_checked");
    expect(work.reason).toBe("no_usable_answer");
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-1",
      takenAt: 1790000000,
    });
  });

  it("holds at most one request in flight across several moved calendars", async () => {
    const cals: Cal[] = [
      { url: FAMILY, name: "Family", token: "family-2" },
      { url: HOLIDAYS, name: "Holidays", token: "h-2" },
      { url: WORK, name: "Work", token: "work-2" },
    ];
    const stub = davStub(cals, (url) => syncAnswer(ok(`${new URL(url).pathname}x.ics`), "n"));
    const result = await run(
      stub,
      await block([
        [FAMILY, "family-1"],
        [HOLIDAYS, "h-1"],
        [WORK, "work-1"],
      ]),
    );
    expect(stub.log.map((one) => one.method)).toEqual([
      "PROPFIND",
      "REPORT",
      "REPORT",
      "REPORT",
    ]);
    expect(result.calendars.every((one) => one.state === "changes")).toBe(true);
    expect(stub.maxInFlight).toBe(1);
  });
});

describe("readSyncAnswer (pure)", () => {
  const COLLECTION = WORK;
  const path = new URL(WORK).pathname;

  function responses(body: string): any[] {
    // The shape tsdav hands back: one element per response, each carrying the
    // whole parsed document as `raw`.
    const raw = { multistatus: { syncToken: "t2" } };
    const out: any[] = [];
    const re = /<href>([^<]+)<\/href><status>HTTP\/1\.1 (\d+)/g;
    for (const match of body.matchAll(re)) {
      const status = Number(match[2]);
      out.push({ raw, href: match[1], status, ok: status >= 200 && status < 300 });
    }
    return out;
  }

  it("de-duplicates hrefs and ignores the collection's own", () => {
    const answer = readSyncAnswer(
      responses(
        `<href>${path}</href><status>HTTP/1.1 200` +
          `<href>${path}a.ics</href><status>HTTP/1.1 200` +
          `<href>${path}a.ics</href><status>HTTP/1.1 200` +
          `<href>${path}c.ics</href><status>HTTP/1.1 404`,
      ),
      COLLECTION,
      HOME,
    );
    expect(answer).toEqual({
      usable: true,
      token: "t2",
      addedOrChanged: [`${COLLECTION}a.ics`],
      removed: [`${COLLECTION}c.ics`],
      truncated: false,
    });
  });

  it("does not count a member outside the home", () => {
    const answer = readSyncAnswer(
      responses(
        `<href>https://elsewhere.example/x.ics</href><status>HTTP/1.1 200` +
          `<href>${path}a.ics</href><status>HTTP/1.1 200`,
      ),
      COLLECTION,
      HOME,
    );
    expect(answer.usable).toBe(true);
    expect(answer.addedOrChanged).toEqual([`${COLLECTION}a.ics`]);
  });

  it("is unusable with no token, with a blank token, or with a failed element", () => {
    expect(readSyncAnswer([{ raw: {}, status: 207, ok: true }] as any, COLLECTION, HOME).usable).toBe(false);
    expect(
      readSyncAnswer(
        [{ raw: { multistatus: { syncToken: "" } }, status: 207, ok: true }] as any,
        COLLECTION,
        HOME,
      ).usable,
    ).toBe(false);
    expect(
      readSyncAnswer(
        responses(`<href>${path}a.ics</href><status>HTTP/1.1 403`),
        COLLECTION,
        HOME,
      ).usable,
    ).toBe(false);
    expect(
      readSyncAnswer(
        [{ raw: "<not xml>", status: 207, ok: true }] as any,
        COLLECTION,
        HOME,
      ).usable,
    ).toBe(false);
  });

  it("an empty answer with a token is usable and empty", () => {
    expect(
      readSyncAnswer(
        [{ raw: { multistatus: { syncToken: "t9" } }, status: 207, ok: true }] as any,
        COLLECTION,
        HOME,
      ),
    ).toEqual({ usable: true, token: "t9", addedOrChanged: [], removed: [], truncated: false });
  });
});
