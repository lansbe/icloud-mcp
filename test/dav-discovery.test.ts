// DAV-02 and DAV-03, taken apart: the discovery chain, the KV cache, and the
// whole of D-60's failure matrix.
//
// Three properties here are the kind that fail silently rather than loudly, and
// each has cases written to make the silence audible:
//
//   1. The cache WRITE. A discovery result that is resolved correctly and never
//      stored is indistinguishable from a working cache at every call site —
//      every call simply pays full discovery cost forever. The live deploy
//      confirmed the write works; these cases are what stop it regressing.
//   2. The single retry. A recursion guard that is a counter rather than a
//      parameter passes its own test while the loop is still reachable, so the
//      no-loop case below counts ATTEMPTS and pins the ceiling at two.
//   3. The never-retried statuses. 401/403/429/503 taking a second attempt
//      costs the user their own mail in Mail.app, not this server anything, so
//      each is pinned to exactly one outbound request.
//
// No network and no real credentials (D-09). The seam is the one production
// uses: tsdav resolves `fetchOverride ?? fetch`, and `davFetch` is that
// override.

import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import {
  DavAuthError,
  DavConfirmationError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavThrottleError,
  davToErrorCategory,
} from "../src/dav/errors";
import {
  DISCOVERY_TTL_SECONDS,
  assertUnderHome,
  clearDavCache,
  resolveDavAccount,
  withRediscovery,
} from "../src/dav/discovery";
import { createDavFetch } from "../src/dav/transport";
import { principalFromEnv } from "../src/principal";
import {
  assertMailSecretsBound,
  type BoundMailSecrets,
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
// Partition 42 for CalDAV, 61 for CardDAV — different on purpose, so a
// "derive the second from the first" implementation cannot pass anything here.
// ---------------------------------------------------------------------------

const CALDAV_SERVER = "https://caldav.icloud.com";
const CARDDAV_SERVER = "https://contacts.icloud.com";
const PRINCIPAL_PATH = "/1234567890/principal/";
const CALDAV_HOME = "https://p42-caldav.icloud.com/1234567890/calendars/";
const CARDDAV_HOME = "https://p61-contacts.icloud.com/1234567890/carddavhome/";

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

/** A well-formed 207 that simply carries no principal href. */
function principalBodyWithoutHref(): string {
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal/></prop></propstat></response>`;
}

function homeBody(service: "caldav" | "carddav", home: string): string {
  const element =
    service === "caldav" ? "C:calendar-home-set" : "CARD:addressbook-home-set";
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><${element}><href>${home}</href></${element}></prop></propstat></response>`;
}

/** A well-formed 207 that carries no home-set href. */
function homeBodyWithoutHref(service: "caldav" | "carddav"): string {
  const element =
    service === "caldav" ? "C:calendar-home-set" : "CARD:addressbook-home-set";
  return `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><${element}/></prop></propstat></response>`;
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

interface Observed {
  url: string;
  method: string;
  start: number;
  end: number;
}

interface Stub {
  observed: Observed[];
  overlapped: boolean;
  fetch: typeof globalThis.fetch;
}

interface StubOptions {
  /** Answer this request instead of the canned conversation. `null` defers. */
  onRequest?: (url: string, method: string) => Response | null;
  /** Serve no principal href, so the chain cannot produce a principal URL. */
  principalHref?: boolean;
  /** Serve no home-set href, so the chain cannot produce a home URL. */
  homeHref?: boolean;
}

/**
 * A stub answering a realistic iCloud discovery conversation.
 *
 * It yields between entry and exit so the sequential-walk assertions mean
 * something: without the yield every call looks atomic and a fan-out is
 * indistinguishable from a queue.
 */
function davStub(options: StubOptions = {}): Stub {
  const wantPrincipal = options.principalHref ?? true;
  const wantHome = options.homeHref ?? true;

  const state: Stub = {
    observed: [],
    overlapped: false,
    fetch: async () => new Response(null, { status: 500 }),
  };

  let tick = 0;
  let open = 0;

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET");
    const record: Observed = { url, method, start: (tick += 1), end: -1 };
    state.observed.push(record);

    open += 1;
    if (open > 1) state.overlapped = true;
    await new Promise((resolve) => setTimeout(resolve, 0));
    open -= 1;
    record.end = tick += 1;

    const override = options.onRequest?.(url, method);
    if (override) return override;

    if (url.includes("/.well-known/")) {
      // iCloud serves no useful redirect here for this account shape.
      return new Response(null, { status: 404 });
    }
    if (url.startsWith(CALDAV_SERVER) && url.endsWith(PRINCIPAL_PATH)) {
      return multistatus(
        wantHome ? homeBody("caldav", CALDAV_HOME) : homeBodyWithoutHref("caldav"),
      );
    }
    if (url.startsWith(CARDDAV_SERVER) && url.endsWith(PRINCIPAL_PATH)) {
      return multistatus(
        wantHome
          ? homeBody("carddav", CARDDAV_HOME)
          : homeBodyWithoutHref("carddav"),
      );
    }
    return multistatus(
      wantPrincipal ? principalBody() : principalBodyWithoutHref(),
    );
  }) as typeof globalThis.fetch;

  return state;
}

/** Answers every request with one status, whatever is asked. */
function statusStub(status: number): Stub {
  return davStub({
    onRequest: () => new Response("<multistatus/>", { status }),
  });
}

/** Run something and hand back whatever it threw. */
async function capture(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw, got a resolution");
}

/** Resolve one service into the real KV binding and return the live stub. */
async function warmCache(service: "caldav" | "carddav"): Promise<Stub> {
  const stub = davStub();
  vi.stubGlobal("fetch", stub.fetch);
  const resolved = await resolveDavAccount(env, createDavFetch(owner), service);
  expect(resolved.cacheHit).toBe(false);
  return stub;
}

// ---------------------------------------------------------------------------
// A recording KV, for the assertions the real binding cannot make
// ---------------------------------------------------------------------------

interface RecordedPut {
  key: string;
  value: string;
  options?: KVNamespacePutOptions;
}

interface FakeKv {
  binding: KVNamespace;
  puts: RecordedPut[];
  deletes: string[];
  gets: string[];
}

/**
 * A KV binding this suite can see inside.
 *
 * Miniflare's real namespace is the right thing to round-trip against, and the
 * round-trip case below uses it. But the TTL is not readable back through the
 * binding API, and a rejecting `put` is not producible through it either — and
 * those are exactly the two properties whose failure is silent. Hence a
 * recording fake for those, and the real binding for the behaviour.
 */
function fakeKv(options: { putRejects?: boolean } = {}): FakeKv {
  const store = new Map<string, string>();
  const state: Partial<FakeKv> = { puts: [], deletes: [], gets: [] };

  const binding = {
    async get(key: string, type?: unknown): Promise<unknown> {
      state.gets!.push(key);
      const raw = store.get(key);
      if (raw === undefined) return null;
      return type === "json" ? JSON.parse(raw) : raw;
    },
    async put(
      key: string,
      value: string,
      putOptions?: KVNamespacePutOptions,
    ): Promise<void> {
      state.puts!.push({ key, value, options: putOptions });
      if (options.putRejects) throw new Error("kv write refused");
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
      state.deletes!.push(key);
      store.delete(key);
    },
    async list(): Promise<unknown> {
      return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true };
    },
    async getWithMetadata(): Promise<unknown> {
      return { value: null, metadata: null };
    },
  };

  state.binding = binding as unknown as KVNamespace;
  return state as FakeKv;
}

function envWith(kv: FakeKv): Env {
  return { ...env, DAV_CACHE: kv.binding };
}

// ---------------------------------------------------------------------------

describe("the discovery chain (DAV-02)", () => {
  beforeEach(async () => {
    await clearDavCache(env);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    ["caldav", CALDAV_SERVER, CALDAV_HOME, "p42-caldav.icloud.com"],
    ["carddav", CARDDAV_SERVER, CARDDAV_HOME, "p61-contacts.icloud.com"],
  ] as const)(
    "resolves %s to a sharded pXX- home URL",
    async (service, server, home, shard) => {
      const stub = davStub();
      vi.stubGlobal("fetch", stub.fetch);

      const resolved = await resolveDavAccount(env, createDavFetch(owner), service);

      expect(resolved.rootUrl.startsWith(server)).toBe(true);
      expect(resolved.principalUrl).toBe(`${server}${PRINCIPAL_PATH}`);
      expect(resolved.homeUrl).toBe(home);
      expect(new URL(resolved.homeUrl).hostname).toBe(shard);
      expect(resolved.cacheHit).toBe(false);
    },
  );

  it("walks the candidate roots strictly in sequence, first success wins", async () => {
    // tsdav builds more than one candidate root and recurses through them. The
    // first is refused here, so the walk has to reach the second — and nothing
    // may be in flight twice while it does, because every candidate is a
    // request against the same six-connection budget.
    const refused = new Set<string>();
    const stub = davStub({
      onRequest: (url) => {
        if (url === `${CALDAV_SERVER}/`) {
          refused.add(url);
          return new Response(null, { status: 404 });
        }
        return null;
      },
    });
    vi.stubGlobal("fetch", stub.fetch);

    const resolved = await resolveDavAccount(env, createDavFetch(owner), "caldav");

    expect(refused.size).toBeGreaterThan(0);
    expect(resolved.homeUrl).toBe(CALDAV_HOME);
    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.observed.length; index += 1) {
      expect(stub.observed[index - 1].end).toBeLessThan(
        stub.observed[index].start,
      );
    }
  });

  it("throws a TYPED DavNotFoundError when no principal href comes back", async () => {
    // The failure this refuses is an empty string used as a later request
    // target: it resolves against nothing and produces a failure whose cause is
    // invisible. tsdav's own refusal here is a bare `Error`, which would fall
    // through to `connection_failed` and tell the user to check their network
    // about a server that answered perfectly well.
    vi.stubGlobal("fetch", davStub({ principalHref: false }).fetch);

    const raised = await capture(() =>
      resolveDavAccount(env, createDavFetch(owner), "caldav"),
    );

    expect(raised).toBeInstanceOf(DavNotFoundError);
    expect(davToErrorCategory(raised).category).toBe("not_found");
  });

  it("throws a TYPED DavNotFoundError when no home-set href comes back", async () => {
    vi.stubGlobal("fetch", davStub({ homeHref: false }).fetch);

    const raised = await capture(() =>
      resolveDavAccount(env, createDavFetch(owner), "carddav"),
    );

    expect(raised).toBeInstanceOf(DavNotFoundError);
    expect(davToErrorCategory(raised).category).toBe("not_found");
  });

  it("refuses before any request when a secret is absent", async () => {
    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);
    const scoped = { ...env, APPLE_APP_PASSWORD: undefined };
    // The promise the door would hand over with that secret unset.
    const refused = principalFromEnv(scoped);
    refused.catch(() => {});

    const raised = await capture(() =>
      resolveDavAccount(scoped, createDavFetch(refused), "caldav"),
    );

    expect(raised).toBeInstanceOf(DavAuthError);
    expect(stub.observed.length).toBe(0);
  });
});

describe("the discovery cache (DAV-03)", () => {
  beforeEach(async () => {
    await clearDavCache(env);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("WRITES the resolved triple back, so the next call is a hit with zero requests", async () => {
    // The regression this exists to catch is invisible from every call site: a
    // result resolved correctly and never stored behaves exactly like a working
    // cache, except that every DAV call in this project pays full discovery
    // cost forever. The live deploy observed the drop; this is what keeps it.
    const cold = await warmCache("caldav");
    expect(cold.observed.length).toBeGreaterThan(0);

    const warm = davStub();
    vi.stubGlobal("fetch", warm.fetch);
    const second = await resolveDavAccount(env, createDavFetch(owner), "caldav");

    expect(second.cacheHit).toBe(true);
    expect(warm.observed.length).toBe(0);
    // Byte-identical to what live discovery produced, which is the other half:
    // a cache that answers quickly with a different answer is worse than none.
    expect(second.homeUrl).toBe(CALDAV_HOME);
    expect(second.principalUrl).toBe(`${CALDAV_SERVER}${PRINCIPAL_PATH}`);
  });

  it("writes with an 86400-second TTL (D-59)", async () => {
    const kv = fakeKv();
    const scoped = envWith(kv);
    vi.stubGlobal("fetch", davStub().fetch);

    await resolveDavAccount(scoped, createDavFetch(owner), "caldav");

    expect(kv.puts.length).toBe(1);
    expect(kv.puts[0].options?.expirationTtl).toBe(DISCOVERY_TTL_SECONDS);
    expect(DISCOVERY_TTL_SECONDS).toBe(86400);
    // KV's floor is 60 seconds; a value under it is rejected at write time.
    expect(DISCOVERY_TTL_SECONDS).toBeGreaterThanOrEqual(60);
    expect(JSON.parse(kv.puts[0].value)).toEqual({
      rootUrl: expect.stringContaining(CALDAV_SERVER),
      principalUrl: `${CALDAV_SERVER}${PRINCIPAL_PATH}`,
      homeUrl: CALDAV_HOME,
    });
  });

  it("reads and writes the SAME key, one per service", async () => {
    const kv = fakeKv();
    const scoped = envWith(kv);
    vi.stubGlobal("fetch", davStub().fetch);

    await resolveDavAccount(scoped, createDavFetch(owner), "caldav");
    await resolveDavAccount(scoped, createDavFetch(owner), "carddav");

    // A key mismatch between the read and the write is the other way the cache
    // silently never hits: the write succeeds, and the read never finds it.
    expect(kv.puts.map((put) => put.key)).toEqual([kv.gets[0], kv.gets[1]]);
    expect(kv.puts[0].key).not.toBe(kv.puts[1].key);
    expect(kv.puts[0].key.endsWith(":caldav")).toBe(true);
    expect(kv.puts[1].key.endsWith(":carddav")).toBe(true);
  });

  it("never puts the Apple ID in the key in cleartext (T-03-07)", async () => {
    assertMailSecretsBound(env);
    const bound: BoundMailSecrets = env;
    expect(bound.APPLE_ID.length).toBeGreaterThan(0);

    const kv = fakeKv();
    const scoped = envWith(kv);
    vi.stubGlobal("fetch", davStub().fetch);
    await resolveDavAccount(scoped, createDavFetch(owner), "caldav");

    const key = kv.puts[0].key;
    expect(key).not.toContain(bound.APPLE_ID);
    expect(key).toMatch(/^dav:v1:[0-9a-f]{64}:caldav$/);
  });

  it("degrades to uncached, silently, when the write is refused", async () => {
    // Swallowed without a log because ./.claude/CLAUDE.md §4 forbids one. The
    // three URLs in hand are correct either way, and failing the operation over
    // a cache miss would trade a slow answer for no answer.
    const kv = fakeKv({ putRejects: true });
    const scoped = envWith(kv);
    vi.stubGlobal("fetch", davStub().fetch);

    const resolved = await resolveDavAccount(
      scoped,
      createDavFetch(owner),
      "caldav",
    );

    expect(resolved.homeUrl).toBe(CALDAV_HOME);
    expect(resolved.cacheHit).toBe(false);
    expect(kv.puts.length).toBe(1);
  });

  it("clears one service without disturbing the other", async () => {
    await warmCache("caldav");
    await warmCache("carddav");
    await clearDavCache(env, "carddav");

    const stub = davStub();
    vi.stubGlobal("fetch", stub.fetch);
    const caldav = await resolveDavAccount(env, createDavFetch(owner), "caldav");

    expect(caldav.cacheHit).toBe(true);
    expect(stub.observed.length).toBe(0);
  });
});

describe("D-60: the failure matrix", () => {
  beforeEach(async () => {
    await clearDavCache(env);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * Run one operation against a warm cache, counting attempts.
   *
   * Warm on purpose: every case in this block is about what happens to an
   * operation running against a CACHED host, which is the only situation in
   * which re-discovery is even a question.
   */
  async function runAgainstWarmCache(
    stub: Stub,
    target = (home: string) => `${home}query/`,
  ): Promise<{ attempts: number; raised: unknown; ok: boolean }> {
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(owner);
    let attempts = 0;

    try {
      await withRediscovery(env, davFetch, "caldav", async (resolved) => {
        attempts += 1;
        return davFetch(target(resolved.homeUrl), { method: "REPORT" });
      });
      return { attempts, raised: null, ok: true };
    } catch (err) {
      return { attempts, raised: err, ok: false };
    }
  }

  it.each([
    [401, "auth_failed", DavAuthError],
    [403, "auth_failed", DavAuthError],
    [429, "rate_limited", DavThrottleError],
    [503, "rate_limited", DavThrottleError],
  ] as const)(
    "%i surfaces %s immediately, with exactly ONE outbound request",
    async (status, category, klass) => {
      // A second attempt here is not a correctness question. Two services times
      // two attempts on every tool call is the cadence that gets an account
      // locked out of Mail.app on the user's own devices, and a server that has
      // just said it is throttling is the last thing to send a request to.
      await warmCache("caldav");
      const stub = davStub({
        onRequest: (url) =>
          url.endsWith("query/") ? new Response(null, { status }) : null,
      });

      const outcome = await runAgainstWarmCache(stub);

      expect(outcome.ok).toBe(false);
      expect(outcome.raised).toBeInstanceOf(klass);
      expect(davToErrorCategory(outcome.raised).category).toBe(category);
      expect(outcome.attempts).toBe(1);
      expect(stub.observed.length).toBe(1);
    },
  );

  it.each([401, 403, 429, 503])(
    "leaves the cache entry intact after %i",
    async (status) => {
      await warmCache("caldav");
      await runAgainstWarmCache(
        davStub({
          onRequest: (url) =>
            url.endsWith("query/") ? new Response(null, { status }) : null,
        }),
      );

      const after = davStub();
      vi.stubGlobal("fetch", after.fetch);
      const resolved = await resolveDavAccount(env, createDavFetch(owner), "caldav");

      expect(resolved.cacheHit).toBe(true);
      expect(after.observed.length).toBe(0);
    },
  );

  it.each([404, 410, 400, 302])(
    "%i against a cached host re-discovers and retries exactly once, and the retry wins",
    async (status) => {
      await warmCache("caldav");
      let operationCalls = 0;
      const stub = davStub({
        onRequest: (url) => {
          if (!url.endsWith("query/")) return null;
          operationCalls += 1;
          return operationCalls === 1
            ? new Response(null, { status })
            : multistatus("");
        },
      });

      const outcome = await runAgainstWarmCache(stub);

      expect(outcome.ok).toBe(true);
      expect(outcome.attempts).toBe(2);
      // Between the two attempts, discovery ran live again: more than the two
      // operation requests were observed.
      expect(stub.observed.length).toBeGreaterThan(2);
      const discovery = stub.observed.filter(
        (request) => !request.url.endsWith("query/"),
      );
      expect(discovery.length).toBeGreaterThan(0);
    },
  );

  it("a transport-level failure against a cached host takes the same path as 404", async () => {
    await warmCache("caldav");
    let operationCalls = 0;
    const stub = davStub({
      onRequest: (url) => {
        if (!url.endsWith("query/")) return null;
        operationCalls += 1;
        // `null` defers to the canned conversation, so a throw has to be raised
        // by the transport instead: an unroutable status the transport maps to
        // DavConnectError is the closest producible analog of a dead shard.
        return operationCalls === 1
          ? new Response(null, { status: 502 })
          : multistatus("");
      },
    });

    const outcome = await runAgainstWarmCache(stub);

    expect(outcome.ok).toBe(true);
    expect(outcome.attempts).toBe(2);
  });

  it("does NOT loop: the same failure on the retry surfaces, with no third attempt", async () => {
    // The property under test is structural, not statistical. `allowRediscovery`
    // is `false` on the second call and is read BEFORE the error is classified,
    // so there is no branch from the retry to a third attempt regardless of how
    // the failure arrives. A counter would pass a weaker version of this case
    // while the recursion was still reachable.
    await warmCache("caldav");
    const stub = davStub({
      onRequest: (url) =>
        url.endsWith("query/") ? new Response(null, { status: 404 }) : null,
    });

    const outcome = await runAgainstWarmCache(stub);

    expect(outcome.ok).toBe(false);
    expect(outcome.attempts).toBe(2);
    expect(outcome.raised).toBeInstanceOf(DavNotFoundError);
    expect(davToErrorCategory(outcome.raised).category).toBe("not_found");

    const operationRequests = stub.observed.filter((request) =>
      request.url.endsWith("query/"),
    );
    expect(operationRequests.length).toBe(2);
  });

  it("honours allowRediscovery: false directly, against a warm cache", async () => {
    // The case above pins the CEILING; this one pins the PARAMETER, and the
    // difference was measured rather than assumed. Deleting the
    // `allowRediscovery` guard leaves the no-loop case green, because after a
    // live re-resolution `cacheHit` is false and that second guard stops the
    // recursion on its own — two independent barriers, which is the right
    // engineering answer and the wrong test coverage. Driving the parameter
    // from outside is what makes it load-bearing here: the cache is warm, so
    // the cacheHit guard would NOT fire, and only the flag can refuse.
    await warmCache("caldav");
    const stub = davStub({
      onRequest: (url) =>
        url.endsWith("query/") ? new Response(null, { status: 404 }) : null,
    });
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(owner);
    let attempts = 0;

    const raised = await capture(() =>
      withRediscovery(
        env,
        davFetch,
        "caldav",
        async (resolved) => {
          attempts += 1;
          return davFetch(`${resolved.homeUrl}query/`, { method: "REPORT" });
        },
        false,
      ),
    );

    expect(attempts).toBe(1);
    expect(stub.observed.length).toBe(1);
    expect(raised).toBeInstanceOf(DavNotFoundError);
    expect((raised as DavNotFoundError).rediscoverable).toBe(true);

    // And the entry survives, because nothing deleted it.
    const after = davStub();
    vi.stubGlobal("fetch", after.fetch);
    expect((await resolveDavAccount(env, createDavFetch(owner), "caldav")).cacheHit).toBe(
      true,
    );
  });

  it("does not re-discover after a cache MISS — there is no stale entry to blame", async () => {
    // Nothing warmed here on purpose. Re-running discovery after a live
    // resolution asks Apple the same question and gets the same answer, for one
    // more request against the tightest budget this project has.
    const stub = davStub({
      onRequest: (url) =>
        url.endsWith("query/") ? new Response(null, { status: 404 }) : null,
    });
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(owner);
    let attempts = 0;

    const raised = await capture(() =>
      withRediscovery(env, davFetch, "caldav", async (resolved) => {
        attempts += 1;
        return davFetch(`${resolved.homeUrl}query/`, { method: "REPORT" });
      }),
    );

    expect(attempts).toBe(1);
    expect(raised).toBeInstanceOf(DavNotFoundError);
  });

  it.each([415, 501])(
    "%i is a CAPABILITY refusal, so it is never re-discovered",
    async (status) => {
      // "This server does not offer this report" is what plan 03-08's contacts
      // fallback reads to tell a refused server-side filter apart from a failed
      // network. Re-discovering here would burn a request and change nothing.
      await warmCache("caldav");
      const stub = davStub({
        onRequest: (url) =>
          url.endsWith("query/") ? new Response(null, { status }) : null,
      });

      const outcome = await runAgainstWarmCache(stub);

      expect(outcome.ok).toBe(false);
      expect(outcome.attempts).toBe(1);
      expect((outcome.raised as DavNotFoundError).rediscoverable).toBe(false);
    },
  );

  it("412 is a PRECONDITION failure, so it is never re-discovered (CALW-05)", async () => {
    // `isRediscoverable` does not name `DavStaleResourceError`, so it returns
    // false for free — and this is the case that proves it, because the
    // function is module-private and cannot be imported.
    //
    // The COUNT is the assertion that matters, not the class. Pitfall 1's two
    // failures are separable: a test checking only the category would pass
    // while the wasted PROPFIND and the second write were still being spent on
    // every failed commit. A 412 says the RESOURCE has moved, not that the
    // account has; re-resolving the host asks a different question and gets
    // the identical answer.
    await warmCache("caldav");
    const stub = davStub({
      onRequest: (url) =>
        url.endsWith("query/") ? new Response(null, { status: 412 }) : null,
    });

    const outcome = await runAgainstWarmCache(stub);

    expect(outcome.ok).toBe(false);
    expect(outcome.raised).toBeInstanceOf(DavStaleResourceError);
    expect(davToErrorCategory(outcome.raised).category).toBe("stale_resource");
    expect(outcome.attempts).toBe(1);
    // The cache was warm, so discovery spent nothing: one request in total, and
    // it is the operation's own.
    expect(stub.observed.length).toBe(1);
  });

  it("the same harness DOES re-issue a rediscoverable failure — the control for the case above", async () => {
    // Without this the 412 case agrees with itself rather than with the code: a
    // harness that never retried anything would satisfy `attempts === 1` no
    // matter what `isRediscoverable` returned, and deleting the whole retry
    // path would leave it green.
    //
    // Everything here is identical to the case above except the status, which
    // is what makes the pair a control rather than two unrelated cases. 404
    // produces a `DavNotFoundError` with `rediscoverable === true`, so the
    // entry is deleted, discovery runs live, and the operation is re-issued.
    await warmCache("caldav");
    const stub = davStub({
      onRequest: (url) =>
        url.endsWith("query/") ? new Response(null, { status: 404 }) : null,
    });

    const outcome = await runAgainstWarmCache(stub);

    expect(outcome.raised).toBeInstanceOf(DavNotFoundError);
    expect((outcome.raised as DavNotFoundError).rediscoverable).toBe(true);
    expect(outcome.attempts).toBe(2);

    const operationRequests = stub.observed.filter((request) =>
      request.url.endsWith("query/"),
    );
    expect(operationRequests.length).toBe(2);
    // And the live re-resolution between the two attempts cost real requests,
    // which is precisely the spend a 412 must not incur.
    expect(stub.observed.length).toBeGreaterThan(2);
  });

  it("passes the operation's own result through untouched on success", async () => {
    await warmCache("caldav");
    vi.stubGlobal("fetch", davStub().fetch);

    const value = await withRediscovery(
      env,
      createDavFetch(owner),
      "caldav",
      async (resolved) => resolved.homeUrl,
    );

    expect(value).toBe(CALDAV_HOME);
  });
});

describe("davToErrorCategory never reads a message", () => {
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a string", "PROPFIND https://p42-caldav.icloud.com/ returned 401"],
    ["a plain object", { status: 401, url: "https://p42-caldav.icloud.com/" }],
    [
      "a tsdav bare Error naming a server URL",
      new Error(
        "Invalid credentials: PROPFIND https://p42-caldav.icloud.com/ returned 401 Unauthorized",
      ),
    ],
  ])("falls through to connection_failed for %s", (_label, value) => {
    // The fall-through is a FLOOR, not the plan: real classification happens in
    // the transport, by status number, before tsdav sees the response. What
    // matters here is that nothing reads the text — a tsdav message embeds the
    // resolved shard host, and the discovery layer exists precisely so the
    // model never learns where the account physically lives.
    const { category, message } = davToErrorCategory(value);

    expect(category).toBe("connection_failed");
    expect(message).not.toContain("icloud");
    expect(message).not.toContain("PROPFIND");
    expect(message).not.toContain("401");
  });

  it.each([
    [new DavAuthError(), "auth_failed"],
    [new DavThrottleError(), "rate_limited"],
    [new DavNotFoundError(true), "not_found"],
    [new DavNotFoundError(false), "not_found"],
    [new DavStaleResourceError(), "stale_resource"],
    [new DavConfirmationError(), "confirmation_invalid"],
    [new DavConnectError(), "connection_failed"],
  ] as const)("maps %o to %s by TYPE", (err, category) => {
    expect(davToErrorCategory(err).category).toBe(category);
  });
});

// ---------------------------------------------------------------------------
// CR-01 — the home-set containment assertion
//
// The helper is pure and reaches no network, so these cases need no stub and no
// cache. The BROAD corpus — the userinfo form, percent-encoded traversal, the
// same-origin sibling collection, backslashes, ports and host case — belongs to
// 03-13's standing audit, which pins each case with its disposition. What is
// asserted here is the one path the tracer proved end to end, plus the field
// that keeps a forged id off the re-discovery budget.
// ---------------------------------------------------------------------------

describe("assertUnderHome (03-REVIEW.md CR-01)", () => {
  it("returns without throwing for a collection under the home set", () => {
    expect(() =>
      assertUnderHome(`${CALDAV_HOME}work/`, CALDAV_HOME),
    ).not.toThrow();
  });

  it("refuses a URL on a different origin", () => {
    let thrown: unknown;
    try {
      assertUnderHome("https://attacker.example/1234567890/calendars/work/", CALDAV_HOME);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(DavNotFoundError);
    // FALSE deliberately. Re-discovery re-resolves the account's OWN home URLs,
    // and no amount of re-resolving makes an attacker's host belong to the
    // account — marking it true would spend a real PROPFIND against iCloud on
    // every forged id ever submitted.
    expect((thrown as DavNotFoundError).rediscoverable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The adversarial URL corpus (03-13 Task 1)
//
// `assertUnderHome` is one origin comparison and one prefix test. That is
// exactly the size of check that is right for the cases someone thought of and
// wrong for the case they did not — so the cases are enumerated here, as a
// table, with each row carrying the reason its disposition is correct.
//
// **Every disposition below was established by RUNNING the URL parser, not by
// reasoning about the WHATWG algorithm.** Four of them are counter-intuitive
// enough that a reader who re-derives them from the specification, or from how
// the string looks, will get them wrong:
//
//   - `https://real@attacker.example/…` is REFUSED and `https://attacker.example@real/…`
//     is ALLOWED. The userinfo is before the host in both; which side the real
//     host lands on is what decides, and only `origin` sees it.
//   - `…/calendars/%2e%2e/%2e%2e/other/` is REFUSED — percent-encoded dot
//     segments ARE decoded and normalised away by the parser.
//   - `…/calendars/..%2f..%2fother/` is ALLOWED — a percent-encoded SEPARATOR
//     is not, so the path stays under the home set as far as the parser is
//     concerned. This is a recorded ACCEPTED residual (03-12 T-03-73), not a
//     defect: the request still goes to iCloud's own origin, so it is
//     same-origin path confusion and not an exfiltration path.
//   - `/1234567890/calendarsEVIL/` is REFUSED only because the home pathname is
//     normalised to a trailing `/` first. It is same-origin, so the origin
//     check passes it, and an unnormalised prefix test passes it too.
//
// ## The ALLOW rows matter as much as the REFUSE rows
//
// A corpus that only proves refusals cannot tell a correct check from an
// over-broad one that has quietly broken legitimate access. The legitimate
// shapes are asserted to PASS here, not merely omitted.
//
// ## The rule for changing this table
//
// A row whose disposition changes means `assertUnderHome`'s BOUNDARY moved. If
// that was deliberate, the reason string is what has to be rewritten. Never
// delete a row to make a run go green — a deleted row is a boundary nobody is
// watching any more, which is indistinguishable from one that was never tested.
// ---------------------------------------------------------------------------

/** What the corpus expects the shipped helper to do with one URL. */
type Containment = "allow" | "refuse";

interface ContainmentCase {
  /** The case, named as the shape rather than as the string. */
  readonly name: string;
  /** The target URL handed to `assertUnderHome`. */
  readonly url: string;
  /** The disposition, established by execution. */
  readonly disposition: Containment;
  /** Why that disposition is correct. Travels with the case, by design. */
  readonly why: string;
}

/**
 * Every URL shape known to defeat a naive containment check, plus the
 * legitimate shapes that must keep working.
 *
 * Exported so a reader who arrives from a failing run — or from
 * `test/dav-home-containment.test.ts`, which guards the call sites this
 * protects — can find it by name rather than by line number.
 */
export const CONTAINMENT_CORPUS: readonly ContainmentCase[] = Object.freeze([
  // -- the legitimate shapes, asserted rather than assumed -------------------
  {
    name: "a collection directly under the home set",
    url: `${CALDAV_HOME}work/`,
    disposition: "allow",
    why: "The shape every listed calendar has. If this ever refuses, the check has broken real access rather than tightened anything.",
  },
  {
    name: "an object under a collection under the home set",
    url: `${CALDAV_HOME}work/weekly.ics`,
    disposition: "allow",
    why: "The shape every event id decodes to. Same reason as above, one level deeper.",
  },
  {
    name: "the home set URL itself",
    url: CALDAV_HOME,
    disposition: "allow",
    why: "Trivially under itself once the home pathname is normalised to a trailing slash. Refusing it would be an off-by-one exactly at the boundary.",
  },
  {
    name: "a host differing only in case",
    url: "https://P42-CalDAV.iCloud.com/1234567890/calendars/work/weekly.ics",
    disposition: "allow",
    why: "The parser lower-cases the host, so `origin` matches. DNS is case-insensitive and this is the same machine.",
  },
  {
    name: "a fragment appended after a legitimate path",
    url: `${CALDAV_HOME}work/weekly.ics#/../../other`,
    disposition: "allow",
    why: "The fragment is not part of `pathname` and is never sent on the wire, so traversal spelled inside one reaches nothing.",
  },
  {
    name: "a query string appended after a legitimate path",
    url: `${CALDAV_HOME}work/weekly.ics?scope=../../other`,
    disposition: "allow",
    why: "Same reason as the fragment: the query is not part of `pathname`, and the request target is still the collection under the home set.",
  },

  // -- the two surprising ALLOWs, recorded so nobody 'fixes' them ------------
  {
    name: "the REAL host as userinfo in front of the real host",
    url: "https://attacker.example@p42-caldav.icloud.com/1234567890/calendars/work/weekly.ics",
    disposition: "allow",
    why: "SURPRISING BUT CORRECT. `origin` is the real host, so the connection goes to iCloud; the userinfo is discarded because `createDavFetch` overwrites the `authorization` header unconditionally, so no credential is misdirected. Do not 'fix' this into a refusal on the strength of how the string looks.",
  },
  {
    name: "a percent-encoded path separator inside a segment",
    url: `${CALDAV_HOME}..%2f..%2fother/weekly.ics`,
    disposition: "allow",
    why: "SURPRISING BUT DELIBERATE — 03-12's T-03-73, dispositioned ACCEPTED. The encoded slash survives normalisation, so the pathname stays literally under the home path. The request still goes to iCloud's own origin, so this is same-origin path confusion and not an exfiltration path. A test asserting a refusal here would contradict a recorded disposition rather than strengthen it.",
  },

  // -- foreign origin: the CR-01 case itself ---------------------------------
  {
    name: "a wholly foreign origin",
    url: "https://attacker.example/1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "The CR-01 exfiltration path verbatim: a forged opaque id naming an attacker's host, which `createDavFetch` would have attached the Apple ID and app-specific password to.",
  },
  {
    name: "the real host as USERINFO in front of an attacker host",
    url: "https://p42-caldav.icloud.com@attacker.example/1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "The userinfo bypass, and the reason the comparison must be on `origin` — this URL's origin is `attacker.example`. Any check written against the URL STRING or against a `hostname` SUBSTRING reads the real host here and passes it. This row is why 03-12's T-03-68 is dispositioned `mitigate`.",
  },
  {
    name: "the real host on a non-default port",
    url: "https://p42-caldav.icloud.com:8443/1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "`origin` folds the port in, and a different port is a different service on the same machine.",
  },
  {
    name: "the real host over a downgraded scheme",
    url: "http://p42-caldav.icloud.com/1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "`origin` folds the scheme in too, so a cleartext downgrade of an otherwise legitimate URL is refused before it can carry a credential unencrypted.",
  },
  {
    name: "a trailing-dot (fully-qualified) form of the real host",
    url: "https://p42-caldav.icloud.com./1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "The parser keeps the trailing dot in the host, so the origin differs textually. Refusing is the conservative reading and costs nothing: no legitimate id is ever minted in this form, because every URL here is re-anchored to the discovered home set.",
  },
  {
    name: "a non-HTTP scheme",
    url: "javascript:alert(1)",
    disposition: "refuse",
    why: "An opaque-origin URL parses, so it does not take the parse-failure path — its `origin` is the string `null`, which cannot equal the home origin. Pinned because 'it parsed' and 'it is a request target' are different claims.",
  },

  // -- same origin, wrong path ----------------------------------------------
  {
    name: "a same-origin sibling whose path merely STARTS WITH the home path",
    url: "https://p42-caldav.icloud.com/1234567890/calendarsEVIL/weekly.ics",
    disposition: "refuse",
    why: "The row that proves the trailing-slash normalisation is doing work. It is same-origin, so the origin check passes it, and an UNNORMALISED prefix test passes it too. 03-12's T-03-69.",
  },
  {
    name: "dot-segment traversal escaping the home path",
    url: `${CALDAV_HOME}../../other/weekly.ics`,
    disposition: "refuse",
    why: "The parser normalises the segments away BEFORE the prefix test runs, so `/other/weekly.ics` is what gets compared — the escaped path, not the written one.",
  },
  {
    name: "percent-encoded dot segments escaping the home path",
    url: `${CALDAV_HOME}%2e%2e/%2e%2e/other/weekly.ics`,
    disposition: "refuse",
    why: "The non-obvious half: encoded dot SEGMENTS are decoded and normalised by the parser, exactly as the literal form is, so this collapses to `/other/weekly.ics` too. Contrast the encoded-SEPARATOR row above, which does not.",
  },
  {
    name: "a backslash before an attacker host",
    url: "https://p42-caldav.icloud.com\\@attacker.example/1234567890/calendars/weekly.ics",
    disposition: "refuse",
    why: "The parser treats the backslash as a path separator for a special scheme, so the attacker host lands in the PATH (`/@attacker.example/…`) rather than in the authority. Same origin, wrong path, refused by the prefix test.",
  },
  {
    name: "the home path WITHOUT its trailing slash",
    url: "https://p42-caldav.icloud.com/1234567890/calendars",
    disposition: "refuse",
    why: "The strict edge of the normalisation: the home path is normalised to end in `/`, and `/1234567890/calendars` does not start with `/1234567890/calendars/`. Deliberate — this is a collection reference this server never mints, and admitting it would mean loosening the very prefix that stops the sibling case above.",
  },

  // -- unparseable: the failure must not escape as a TypeError ---------------
  {
    name: "a relative URL",
    url: "/1234567890/calendars/work/weekly.ics",
    disposition: "refuse",
    why: "No base is passed to `new URL`, so this throws at parse. The refusal must be a `DavNotFoundError`, not a `TypeError` — a `TypeError` would escape the DAV error vocabulary and reach the tool layer as an unclassified failure.",
  },
  {
    name: "a protocol-relative URL",
    url: "//attacker.example/1234567890/calendars/weekly.ics",
    disposition: "refuse",
    why: "Also a parse failure without a base, and worth pinning separately because it LOOKS absolute — a check that reached for a string test rather than the parser would read the attacker host here.",
  },
  {
    name: "the empty string",
    url: "",
    disposition: "refuse",
    why: "Parse failure. Pinned so an absent field decoded out of a malformed token refuses rather than throwing something the caller does not expect.",
  },
  {
    name: "a non-URL string",
    url: "not a url at all",
    disposition: "refuse",
    why: "Parse failure. The caught value is deliberately never read by the helper, because a `URL` parse failure's message quotes its input and one of the two inputs is attacker-chosen.",
  },
]);

describe("assertUnderHome, against the adversarial URL corpus (03-13)", () => {
  // Non-vacuity FIRST, on both dispositions. A table that lost its refuse rows
  // would pass every assertion below while proving nothing about containment,
  // and a table that lost its allow rows could not detect an over-broad check.
  it("carries enough cases, in both dispositions, to be worth running", () => {
    expect(CONTAINMENT_CORPUS.length).toBeGreaterThanOrEqual(15);
    expect(
      CONTAINMENT_CORPUS.filter((one) => one.disposition === "allow").length,
      "the corpus has no ALLOW rows, so it cannot detect an over-broad check",
    ).toBeGreaterThan(0);
    expect(
      CONTAINMENT_CORPUS.filter((one) => one.disposition === "refuse").length,
      "the corpus has no REFUSE rows, so it is not testing containment at all",
    ).toBeGreaterThan(0);
    // Every row must carry its reason, or the table decays into a list of
    // strings whose dispositions nobody can check without re-deriving them.
    for (const one of CONTAINMENT_CORPUS) {
      expect(one.why.length, `${one.name} carries no reason`).toBeGreaterThan(20);
    }
  });

  it.each(CONTAINMENT_CORPUS)(
    "$disposition: $name",
    ({ url, disposition, why }) => {
      if (disposition === "allow") {
        expect(() => assertUnderHome(url, CALDAV_HOME), why).not.toThrow();
        return;
      }

      let thrown: unknown;
      try {
        assertUnderHome(url, CALDAV_HOME);
      } catch (err) {
        thrown = err;
      }

      // BOTH halves, every time. "Something threw" is not the property: a
      // `TypeError` out of the parser would satisfy it while meaning the
      // failure escaped the DAV error vocabulary entirely.
      expect(thrown, why).toBeInstanceOf(DavNotFoundError);
      // FALSE keeps T-03-71 closed. Re-discovery re-resolves the account's OWN
      // home URLs, so no amount of re-resolving makes a foreign host belong to
      // the account — `true` would spend one of D-60's two permitted PROPFINDs
      // on every forged id ever submitted, turning a refusal into an amplifier.
      // This is the assertion that would silently stop holding if someone later
      // reached for the one-argument constructor form.
      expect(
        (thrown as DavNotFoundError).rediscoverable,
        `${why} -- and the refusal must not be rediscoverable`,
      ).toBe(false);
    },
  );
});
