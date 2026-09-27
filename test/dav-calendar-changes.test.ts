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
import { decodeEventId, encodeCalendarId } from "../src/dav/ids";
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

  it("costs one sync REPORT carrying the old token, then one multiget; the collection's own href is not counted", async () => {
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
      `REPORT ${WORK}`,
    ]);
    // The second REPORT is the detail read: the two changed members, never the
    // removed one and never the collection itself.
    expect(stub.log[2]!.body).toContain("calendar-multiget");
    expect(stub.log[2]!.body).toContain(`${WORK_PATH}a.ics`);
    expect(stub.log[2]!.body).toContain(`${WORK_PATH}b.ics`);
    expect(stub.log[2]!.body).not.toContain(`${WORK_PATH}c.ics`);
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
    // One sync REPORT and one multiget per calendar, never overlapping.
    expect(stub.log.map((one) => one.method)).toEqual([
      "PROPFIND",
      "REPORT",
      "REPORT",
      "REPORT",
      "REPORT",
      "REPORT",
      "REPORT",
    ]);
    expect(
      stub.log.slice(1).map((one) => one.body.includes("calendar-multiget")),
    ).toEqual([false, true, false, true, false, true]);
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

  it("does not count a member outside the home, and a dropped member makes the answer unusable (WR-01)", () => {
    const answer = readSyncAnswer(
      responses(
        `<href>https://elsewhere.example/x.ics</href><status>HTTP/1.1 200` +
          `<href>${path}a.ics</href><status>HTTP/1.1 200`,
      ),
      COLLECTION,
      HOME,
    );
    expect(answer.addedOrChanged).toEqual([`${COLLECTION}a.ics`]);
    // A member it could not use is a change it cannot report: never "nothing".
    expect(answer.usable).toBe(false);
  });

  it("an answer whose only members were dropped is unusable, never an empty change (WR-01)", () => {
    for (const body of [
      `<href>https://elsewhere.example/x.ics</href><status>HTTP/1.1 200`,
      `<href>/999/calendars/work/y.ics</href><status>HTTP/1.1 404`,
      `<href>http://[bad</href><status>HTTP/1.1 200`,
    ]) {
      const answer = readSyncAnswer(responses(body), COLLECTION, HOME);
      expect(answer.addedOrChanged).toEqual([]);
      expect(answer.removed).toEqual([]);
      expect(answer.usable).toBe(false);
    }
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

// ---------------------------------------------------------------------------
// 23-05: which events changed (D-26), the no-token fallback (D-23), and the
// remaining arms (D-25, D-27)
// ---------------------------------------------------------------------------

/** The prior block's time is 2026-09-21. One CREATED after it, one before. */
const AFTER = "20260925T000000Z";
const BEFORE = "20260101T000000Z";

const ROW_KEYS = ["allDay", "calendar", "cancelled", "end", "id", "start", "title"];

function xmlText(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** An event carrying fields no change row may copy. */
function eventIcs(
  uid: string,
  options: { created?: string; summary?: string; status?: string } = {},
): string {
  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Example//Change fixture//EN",
    "BEGIN:VEVENT",
    `UID:${uid}`,
    "DTSTAMP:20260926T000000Z",
    ...(options.created === undefined ? [] : [`CREATED:${options.created}`]),
    `SUMMARY:${options.summary ?? uid}`,
    "DESCRIPTION:Private notes that must not travel",
    "LOCATION:Room four",
    "ATTENDEE;CN=Sam Lee:mailto:sam.lee@example.invalid",
    "ORGANIZER;CN=Priya:mailto:priya@example.invalid",
    ...(options.status === undefined ? [] : [`STATUS:${options.status}`]),
    "DTSTART:20261001T160000Z",
    "DTEND:20261001T170000Z",
    "BEGIN:VALARM",
    "ACTION:DISPLAY",
    "DESCRIPTION:Alarm text",
    "TRIGGER:-PT15M",
    "END:VALARM",
    "END:VEVENT",
    "END:VCALENDAR",
    "",
  ].join("\r\n");
}

function memberWithData(href: string, ics: string): string {
  return (
    `<response><href>${href}</href><propstat><prop><getetag>"e"</getetag>` +
    `<C:calendar-data>${xmlText(ics)}</C:calendar-data></prop>` +
    `<status>HTTP/1.1 200 OK</status></propstat></response>`
  );
}

/** The paths a multiget body names, in the order it names them. */
function multigetPaths(body: string): string[] {
  return [...body.matchAll(/<(?:d:)?href>([^<]+)<\/(?:d:)?href>/g)].map((m) => m[1]!);
}

/**
 * A REPORT router: sync REPORTs go to `sync`; a multiget is answered from
 * `events`, keyed by path, for the paths it names that `events` holds.
 */
function router(
  sync: (url: string, body: string) => Response,
  events: Record<string, string> = {},
  multiget?: (url: string, body: string) => Response,
): (url: string, body: string) => Response {
  return (url, body) => {
    if (!body.includes("calendar-multiget")) return sync(url, body);
    if (multiget !== undefined) return multiget(url, body);
    return multistatus(
      multigetPaths(body)
        .filter((path) => path in events)
        .map((path) => memberWithData(path, events[path]!))
        .join(""),
    );
  };
}

const multigets = (stub: Stub) =>
  stub.log.filter((one) => one.method === "REPORT" && one.body.includes("calendar-multiget"));

describe("calendarChangesSince: which events were added or changed (D-26)", () => {
  const WORK_PATH = new URL(WORK).pathname;
  const FAMILY_PATH = new URL(FAMILY).pathname;

  it("splits by CREATED against the token time: one multiget naming both, one added and one changed", async () => {
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}new.ics`) + ok(`${WORK_PATH}old.ics`), "work-3"), {
        [`${WORK_PATH}new.ics`]: eventIcs("new", { created: AFTER, summary: "Interview loop" }),
        [`${WORK_PATH}old.ics`]: eventIcs("old", { created: BEFORE, summary: "Team lunch" }),
      }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));

    expect(multigets(stub).map((one) => one.url)).toEqual([WORK]);
    expect(multigetPaths(multigets(stub)[0]!.body)).toEqual([
      `${WORK_PATH}new.ics`,
      `${WORK_PATH}old.ics`,
    ]);
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "changes",
      added: 1,
      changed: 1,
      addedOrChanged: 0,
      removed: 0,
    });
    expect(work.events).toHaveLength(2);
    const byTitle = Object.fromEntries(work.events.map((row) => [row.title, row]));
    expect(byTitle["Interview loop"]!.kind).toBe("added");
    expect(byTitle["Team lunch"]!.kind).toBe("changed");
    expect(stub.maxInFlight).toBe(1);
  });

  it("a row carries exactly the seven fields plus kind, and its id names the event", async () => {
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}new.ics`), "work-3"), {
        [`${WORK_PATH}new.ics`]: eventIcs("new", { created: AFTER, summary: "Interview loop" }),
      }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const row = result.calendars.find((one) => one.calendarId === idOf(WORK))!.events[0]!;

    expect(Object.keys(row).sort()).toEqual([...ROW_KEYS, "kind"].sort());
    expect(row).toEqual({
      id: row.id,
      calendar: idOf(WORK),
      title: "Interview loop",
      start: "2026-10-01T16:00:00Z",
      end: "2026-10-01T17:00:00Z",
      allDay: false,
      cancelled: false,
      kind: "added",
    });
    expect(decodeEventId(row.id)).toEqual({
      calendarUrl: WORK,
      objectUrl: `${WORK}new.ics`,
      recurrenceId: null,
    });
    const text = JSON.stringify(result);
    for (const leaked of ["Private notes", "Room four", "sam.lee", "Priya", "Alarm text"]) {
      expect(text).not.toContain(leaked);
    }
  });

  it("an event without CREATED is counted as added-or-changed, and its row carries no label", async () => {
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}plain.ics`), "work-3"), {
        [`${WORK_PATH}plain.ics`]: eventIcs("plain", { status: "CANCELLED" }),
      }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ added: 0, changed: 0, addedOrChanged: 1, removed: 0 });
    expect(work.events).toHaveLength(1);
    expect(Object.keys(work.events[0]!).sort()).toEqual(ROW_KEYS);
    expect(work.events[0]!.cancelled).toBe(true);
  });

  it("thirty changes across two calendars: 25 rows, the first calendar first, the rest counted", async () => {
    const pad = (n: number) => String(n).padStart(2, "0");
    const events: Record<string, string> = {};
    let familyEntries = "";
    for (let n = 0; n < 20; n += 1) {
      familyEntries += ok(`${FAMILY_PATH}e${pad(n)}.ics`);
      events[`${FAMILY_PATH}e${pad(n)}.ics`] = eventIcs(`f${n}`, { created: AFTER });
    }
    let workEntries = "";
    for (let n = 0; n < 10; n += 1) {
      workEntries += ok(`${WORK_PATH}e${pad(n)}.ics`);
      events[`${WORK_PATH}e${pad(n)}.ics`] = eventIcs(`w${n}`, { created: AFTER });
    }
    const cals: Cal[] = [
      { url: FAMILY, name: "Family", token: "family-2" },
      { url: WORK, name: "Work", token: "work-2" },
    ];
    const stub = davStub(
      cals,
      router(
        (url) =>
          url === FAMILY ? syncAnswer(familyEntries, "family-3") : syncAnswer(workEntries, "work-3"),
        events,
      ),
    );
    const result = await run(stub, await block([[FAMILY, "family-1"], [WORK, "work-1"]]));

    const [family, work] = result.calendars;
    expect(family!.calendarId).toBe(idOf(FAMILY));
    expect(family!.events).toHaveLength(20);
    expect(family).toMatchObject({ added: 20, changed: 0, addedOrChanged: 0 });
    expect(work!.events).toHaveLength(5);
    expect(work).toMatchObject({ added: 5, changed: 0, addedOrChanged: 5 });

    expect(multigets(stub).map((one) => one.url)).toEqual([FAMILY, WORK]);
    expect(multigetPaths(multigets(stub)[1]!.body)).toEqual(
      [0, 1, 2, 3, 4].map((n) => `${WORK_PATH}e${pad(n)}.ics`),
    );
    expect(stub.maxInFlight).toBe(1);
  });

  it("a member the multiget does not return gets no row and is counted as added-or-changed", async () => {
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}a.ics`) + ok(`${WORK_PATH}b.ics`), "work-3"), {
        [`${WORK_PATH}a.ics`]: eventIcs("a", { created: AFTER }),
      }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ state: "changes", added: 1, changed: 0, addedOrChanged: 1 });
    expect(work.events.map((row) => row.title)).toEqual(["a"]);
  });

  it("a member the multiget answers 404 gets no row, is counted as added-or-changed, and is no error", async () => {
    const stub = davStub(
      TWO,
      router(
        () => syncAnswer(ok(`${WORK_PATH}a.ics`) + ok(`${WORK_PATH}b.ics`), "work-3"),
        {},
        () =>
          multistatus(
            memberWithData(`${WORK_PATH}a.ics`, eventIcs("a", { created: AFTER })) +
              removed(`${WORK_PATH}b.ics`),
          ),
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work.state).toBe("changes");
    expect(work.events.map((row) => row.title)).not.toContain("b");
    expect((work.added ?? 0) + (work.changed ?? 0) + (work.addedOrChanged ?? 0)).toBe(2);
    expect(work.addedOrChanged).toBeGreaterThanOrEqual(1);
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-3",
    });
  });

  it("an event that does not parse gets no row and is counted as added-or-changed", async () => {
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}bad.ics`), "work-3"), {
        [`${WORK_PATH}bad.ics`]: "this is not a calendar",
      }),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ added: 0, changed: 0, addedOrChanged: 1 });
    expect(work.events).toEqual([]);
  });

  it("a carried calendar is classified against its own takenAt, not the block's", async () => {
    // Created 2026-07-25: after the calendar's own time, before the block's.
    const stub = davStub(
      TWO,
      router(() => syncAnswer(ok(`${WORK_PATH}mid.ics`), "work-3"), {
        [`${WORK_PATH}mid.ics`]: eventIcs("mid", { created: "20260725T000000Z" }),
      }),
    );
    const prior: CalendarBlock = {
      takenAt: 1790000000,
      calendars: [
        { key: await calendarKeyOf(WORK), syncToken: "work-1", takenAt: 1780000000 },
        { key: await calendarKeyOf(FAMILY), syncToken: "family-1" },
      ],
    };
    const result = await run(stub, prior);
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ added: 1, changed: 0 });
    expect(work.events[0]!.kind).toBe("added");
  });

  it("a member on another host, or outside the home, is neither counted nor fetched, and the calendar is not_checked (WR-01)", async () => {
    const stub = davStub(
      TWO,
      router(
        () =>
          syncAnswer(
            ok("https://elsewhere.example/1234567890/calendars/work/x.ics") +
              ok("/999/calendars/work/y.ics") +
              ok(`${WORK_PATH}a.ics`),
            "work-3",
          ),
        { [`${WORK_PATH}a.ics`]: eventIcs("a", { created: AFTER }) },
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    // Two changes it could not use: not "one change", and never "nothing".
    expect(work).toMatchObject({
      state: "not_checked",
      reason: "no_usable_answer",
      addedOrChanged: null,
    });
    expect(multigets(stub)).toEqual([]);
    // The token does not move, so the next check asks about the same span.
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-1",
      takenAt: 1790000000,
    });
    expect(stub.log.some((one) => one.url.includes("elsewhere"))).toBe(false);
    expect(stub.log.some((one) => one.body.includes("/999/"))).toBe(false);
  });

  it("a truncated answer is changes with more, the rows it named, and the answer's token kept", async () => {
    const stub = davStub(
      TWO,
      router(
        () =>
          syncAnswer(
            `<response><href>${WORK_PATH}</href><status>HTTP/1.1 507 Insufficient Storage</status></response>` +
              ok(`${WORK_PATH}a.ics`),
            "work-3",
          ),
        { [`${WORK_PATH}a.ics`]: eventIcs("a", { created: AFTER }) },
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({ state: "changes", more: true, added: 1 });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-3",
    });
  });
});

describe("calendarChangesSince: a calendar with no token property (D-23 fallback)", () => {
  const WORK_PATH = new URL(WORK).pathname;
  const NO_PROPERTY: Cal[] = [
    { url: WORK, name: "Work", token: null },
    { url: FAMILY, name: "Family", token: "family-1" },
  ];

  it("no prior token: one REPORT with an empty token, members discarded, started from the answer's token", async () => {
    const stub = davStub(
      NO_PROPERTY,
      router(() => syncAnswer(ok(`${WORK_PATH}a.ics`) + ok(`${WORK_PATH}b.ics`), "work-9")),
    );
    const result = await run(stub, null);

    expect(stub.log.map((one) => `${one.method} ${one.url}`)).toEqual([
      `PROPFIND ${HOME}`,
      `REPORT ${WORK}`,
    ]);
    expect(stub.log[1]!.body).toContain("sync-collection");
    expect(stub.log[1]!.body).toMatch(/<d:sync-token\s*\/>|<d:sync-token><\/d:sync-token>/);
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "started",
      mechanism: "report-token",
      added: null,
      addedOrChanged: null,
    });
    expect(work.events).toEqual([]);
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-9",
    });
  });

  it("a prior token: one REPORT with it, handled like a moved token, recorded as report-token", async () => {
    const stub = davStub(
      NO_PROPERTY,
      router(
        (_url, body) =>
          body.includes("work-1")
            ? syncAnswer(ok(`${WORK_PATH}a.ics`), "work-2")
            : new Response(null, { status: 500 }),
        { [`${WORK_PATH}a.ics`]: eventIcs("a", { created: BEFORE }) },
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));

    const syncs = stub.log.filter(
      (one) => one.method === "REPORT" && one.body.includes("sync-collection"),
    );
    expect(syncs).toHaveLength(1);
    expect(syncs[0]!.body).toContain("work-1");
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "changes",
      mechanism: "report-token",
      added: 0,
      changed: 1,
      addedOrChanged: 0,
    });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-2",
    });
  });

  it("an unusable starting answer is not_checked, never started", async () => {
    const stub = davStub(NO_PROPERTY, router(() => syncAnswer("", null)));
    const result = await run(stub, null);
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "not_checked",
      reason: "no_usable_answer",
      mechanism: "report-token",
    });
    expect(result.fresh.calendars.map((one) => one.syncToken)).toEqual(["family-1"]);
  });

  it("a refused prior token starts again from a fresh empty-token REPORT", async () => {
    const stub = davStub(
      NO_PROPERTY,
      router((_url, body) =>
        body.includes("work-1") ? syncTokenRefusal(403) : syncAnswer(ok(`${WORK_PATH}a.ics`), "work-9"),
      ),
    );
    const result = await run(stub, await block([[WORK, "work-1"], [FAMILY, "family-1"]]));
    const work = result.calendars.find((one) => one.calendarId === idOf(WORK))!;
    expect(work).toMatchObject({
      state: "restarted",
      why: "token_refused",
      mechanism: "report-token",
    });
    expect(result.fresh.calendars).toContainEqual({
      key: await calendarKeyOf(WORK),
      syncToken: "work-9",
    });
    expect(multigets(stub)).toEqual([]);
  });
});

describe("calendarChangesSince: calendars past what one marker holds (WR-06)", () => {
  const url = (n: number) => `${HOME}c${String(n).padStart(2, "0")}/`;

  it("a calendar pushed past the cap is not_checked with marker_full, never gone, and costs no request", async () => {
    // Sixty-five calendars now; the marker held the last sixty-four. The new
    // first one pushes the last one past the cap.
    const cals: Cal[] = Array.from({ length: 65 }, (_, n) => ({
      url: url(n),
      name: `Cal ${n}`,
      token: `t-${n}`,
    }));
    const stub = davStub(cals);
    const prior = await block(
      Array.from({ length: 64 }, (_, n): [string, string] => [url(n + 1), `t-${n + 1}`]),
    );
    const result = await run(stub, prior);

    expect(stub.log.map((one) => one.method)).toEqual(["PROPFIND"]);
    expect(result.gone).toBe(0);
    expect(result.notCovered).toEqual([]);
    const last = result.calendars.find((one) => one.calendarId === idOf(url(64)))!;
    expect(last).toMatchObject({
      state: "not_checked",
      reason: "marker_full",
      addedOrChanged: null,
    });
    expect(result.calendars[0]).toMatchObject({ calendarId: idOf(url(0)), state: "started" });
    expect(result.fresh.calendars).toHaveLength(64);
    expect(result.fresh.calendars.map((one) => one.syncToken)).not.toContain("t-64");
  });
});

describe("calendarChangesSince: every kept state fits the marker (CR-01)", () => {
  it("a moved calendar whose new state does not fit is marker_full: no detail read, nothing kept, not gone", async () => {
    const cals: Cal[] = [
      { url: FAMILY, name: "Family", token: "family-2" },
      { url: WORK, name: "Work", token: "work-2" },
    ];
    const stub = davStub(cals, (url) => syncAnswer(ok(`${new URL(url).pathname}x.ics`), "n"));
    await warm(stub);
    const result = await calendarChangesSince(
      env,
      principal,
      createDavFetch(owner),
      await block([
        [FAMILY, "family-1"],
        [WORK, "work-1"],
      ]),
      false,
      (states) => states.length <= 1,
    );

    // Family: its sync REPORT and its multiget. Work: its sync REPORT only.
    expect(stub.log.map((one) => `${one.method} ${one.url}`)).toEqual([
      `PROPFIND ${HOME}`,
      `REPORT ${FAMILY}`,
      `REPORT ${FAMILY}`,
      `REPORT ${WORK}`,
    ]);
    expect(result.calendars.map((one) => [one.state, one.reason])).toEqual([
      ["changes", undefined],
      ["not_checked", "marker_full"],
    ]);
    expect(result.fresh.calendars).toEqual([
      { key: await calendarKeyOf(FAMILY), syncToken: "n" },
    ]);
    expect(result.gone).toBe(0);
  });
});

describe("calendarChangesSince: a sign-in refusal on the sync REPORT (WR-02)", () => {
  it("a REPORT answered 401 is thrown as the sign-in failure it is, never a restart", async () => {
    const stub = davStub(TWO, () => new Response(null, { status: 401 }));
    await warm(stub);
    await expect(
      calendarChangesSince(
        env,
        principal,
        createDavFetch(owner),
        await block([
          [WORK, "work-1"],
          [FAMILY, "family-1"],
        ]),
        false,
      ),
    ).rejects.toBeInstanceOf(DavAuthError);
  });
});
