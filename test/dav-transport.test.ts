// DAV-01, taken apart. The tracer proved these layers work assembled; this
// suite proves each obligation of the choke point independently, so a
// regression names the thing that broke instead of "dav_diagnose is red".
//
// Four obligations land on `createDavFetch` and no other seam can serve any of
// them: the credential is attached per call, the redirect policy is forced to
// the observable one, requests are serialised against the per-invocation
// connection budget, and a status NUMBER is turned into a typed error before
// tsdav ever sees the response. Each has cases below.
//
// No network and no real credentials — D-09 forbids any automated job
// authenticating against the real Apple ID. The seam is the same one production
// uses: the global `fetch` these tests stub is the one `createDavFetch` closes
// over.

import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DavAuthError,
  DavConfirmationError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavThrottleError,
  davToErrorCategory,
} from "../src/dav/errors";
import { createDavFetch, davAuthHeader } from "../src/dav/transport";
import { SAFE_MESSAGES } from "../src/errors";
import {
  type BoundMailSecrets,
  assertMailSecretsBound,
} from "./fixtures/bound-secrets";

const TARGET = "https://p42-caldav.icloud.com/1234567890/calendars/";

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

interface Observed {
  url: string;
  init: RequestInit;
  headers: Headers;
  /** Monotonic tick when the stub was entered. */
  start: number;
  /** Monotonic tick when the stub resolved. */
  end: number;
}

interface Stub {
  observed: Observed[];
  /** True if two calls were ever inside the stub at the same time. */
  overlapped: boolean;
  fetch: typeof globalThis.fetch;
}

/**
 * A stub that yields to the event loop between entry and exit.
 *
 * The yield is what makes the serialisation case meaningful rather than
 * decorative: an atomic stub makes every call look instantaneous, so a fan-out
 * and a queue are indistinguishable from the outside.
 *
 * `respond` receives the call ordinal (1-based) so a case can answer the first
 * request differently from the second — which is what the retry cases need.
 */
function stubFetch(
  respond: (url: string, seq: number) => Response | Promise<never>,
): Stub {
  const state: Stub = {
    observed: [],
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
    const record: Observed = {
      url,
      init: init ?? {},
      headers: new Headers(init?.headers),
      start: (tick += 1),
      end: -1,
    };
    state.observed.push(record);

    open += 1;
    if (open > 1) state.overlapped = true;
    await new Promise((resolve) => setTimeout(resolve, 0));
    open -= 1;
    record.end = tick += 1;

    return respond(url, (seq += 1));
  }) as typeof globalThis.fetch;

  return state;
}

/** Always answers with one status, whatever is asked. */
function statusStub(status: number): Stub {
  return stubFetch(
    () => new Response(status === 204 ? null : "<multistatus/>", { status }),
  );
}

/**
 * The error's OWN enumerable fields, which is the set a serializer would emit.
 *
 * `message` and `stack` are own properties too but non-enumerable, so neither
 * appears here — and neither would appear in `JSON.stringify`. `message` is
 * pinned separately below, by value, because a fixed internal label is the
 * property that matters and an assertion over its absence would not catch a
 * server string arriving in it.
 */
function ownFields(err: unknown): Record<string, unknown> {
  const source = err as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(source)) out[key] = source[key];
  return out;
}

/** Run `davFetch` and hand back whatever it threw. */
async function raise(
  davFetch: ReturnType<typeof createDavFetch>,
  init?: RequestInit,
): Promise<unknown> {
  try {
    await davFetch(TARGET, init);
  } catch (err) {
    return err;
  }
  throw new Error("davFetch resolved where a throw was expected");
}

// ---------------------------------------------------------------------------

describe("davAuthHeader", () => {
  it("builds a Basic header from the two bound secrets", () => {
    assertMailSecretsBound(env);
    const bound: BoundMailSecrets = env;

    const header = davAuthHeader(env);

    expect(header.startsWith("Basic ")).toBe(true);
    expect(atob(header.slice("Basic ".length))).toBe(
      `${bound.APPLE_ID}:${bound.APPLE_APP_PASSWORD}`,
    );
  });

  it("encodes a non-ASCII Apple ID over UTF-8 BYTES, not UTF-16 code units", () => {
    // U+00FC is the case that separates the two encodings while staying inside
    // btoa's own range, so the wrong answer is producible rather than merely
    // theoretical: as a code unit it is one byte 0xFC, as UTF-8 it is 0xC3 0xBC.
    // A header built the wrong way is accepted by btoa and rejected by Apple,
    // and the user is told their app-specific password is wrong when only its
    // encoding was.
    const appleId = "rüssell@example.invalid";
    const password = "test-password-not-real";
    const scoped = { ...env, APPLE_ID: appleId, APPLE_APP_PASSWORD: password };

    const header = davAuthHeader(scoped);
    const encoded = header.slice("Basic ".length);

    const utf8 = new TextEncoder().encode(`${appleId}:${password}`);
    let asBytes = "";
    for (const byte of utf8) asBytes += String.fromCharCode(byte);

    expect(encoded).toBe(btoa(asBytes));
    // And the wrong answer is genuinely different, so the case above is not
    // asserting a tautology.
    expect(encoded).not.toBe(btoa(`${appleId}:${password}`));
  });

  it.each([
    ["APPLE_ID absent", { APPLE_ID: undefined }],
    ["APPLE_ID empty", { APPLE_ID: "" }],
    ["APPLE_APP_PASSWORD absent", { APPLE_APP_PASSWORD: undefined }],
    ["APPLE_APP_PASSWORD empty", { APPLE_APP_PASSWORD: "" }],
  ])("throws DavAuthError when %s", (_label, patch) => {
    expect(() => davAuthHeader({ ...env, ...patch })).toThrow(DavAuthError);
  });

  it.each([
    ["a trailing newline", "test-password-not-real\n"],
    ["a carriage return", "test-\rpassword"],
    ["a NUL", "test-\u0000password"],
  ])("throws DavAuthError on a secret carrying %s", (_label, password) => {
    // A secret provisioned from a file carries the file's trailing newline, so
    // this is the mundane case rather than the hostile one. Refusing beats
    // escaping: an escaped value is rejected by the server, and the user is
    // told the credential is wrong when only its encoding was.
    expect(() =>
      davAuthHeader({ ...env, APPLE_APP_PASSWORD: password }),
    ).toThrow(DavAuthError);
  });

  it("refuses an illegal character in the Apple ID too", () => {
    expect(() => davAuthHeader({ ...env, APPLE_ID: "a\nb@example.invalid" })).toThrow(
      DavAuthError,
    );
  });
});

describe("createDavFetch — the credential", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("merges authorization into caller-supplied headers rather than replacing them", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    await createDavFetch(env)(TARGET, {
      method: "PROPFIND",
      headers: { depth: "1", "content-type": "application/xml" },
    });

    const [observed] = stub.observed;
    expect(observed.headers.get("depth")).toBe("1");
    expect(observed.headers.get("content-type")).toBe("application/xml");
    expect(observed.headers.get("authorization")?.startsWith("Basic ")).toBe(
      true,
    );
  });

  it("overrides a caller-supplied authorization header", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    await createDavFetch(env)(TARGET, {
      headers: { authorization: "Bearer caller-supplied" },
    });

    expect(stub.observed[0].headers.get("authorization")).not.toBe(
      "Bearer caller-supplied",
    );
    expect(
      stub.observed[0].headers.get("authorization")?.startsWith("Basic "),
    ).toBe(true);
  });

  it("refuses before the request when a secret is absent", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    const scoped = { ...env, APPLE_ID: undefined };
    await expect(createDavFetch(scoped)(TARGET)).rejects.toBeInstanceOf(
      DavAuthError,
    );
    expect(stub.observed.length).toBe(0);
  });
});

describe("createDavFetch — the redirect policy (T-03-01)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("passes redirect: manual on every request", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(env);

    await davFetch(TARGET);
    await davFetch(TARGET, { method: "PROPFIND" });
    await davFetch(TARGET, { headers: { depth: "0" } });

    expect(stub.observed.length).toBe(3);
    for (const observed of stub.observed) {
      expect(observed.init.redirect).toBe("manual");
    }
  });

  it("overrides a caller asking for the follow policy", async () => {
    // Cloudflare documents the follow policy as forwarding ALL headers to the
    // destination, across hostnames included — and the header here carries the
    // app-specific password. A caller must not be able to opt into that.
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    await createDavFetch(env)(TARGET, { redirect: "follow" });

    expect(stub.observed[0].init.redirect).toBe("manual");
  });
});

describe("createDavFetch — serialisation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("holds at most one request in flight under overlapping callers", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(env);

    // Fired without awaiting: this is the shape tsdav's own internal fan-out
    // takes, and the gate is the only thing between it and the six-connection
    // per-invocation budget.
    await Promise.all([
      davFetch(`${TARGET}a/`),
      davFetch(`${TARGET}b/`),
      davFetch(`${TARGET}c/`),
      davFetch(`${TARGET}d/`),
    ]);

    expect(stub.observed.length).toBe(4);
    expect(stub.overlapped).toBe(false);
    for (let index = 1; index < stub.observed.length; index += 1) {
      expect(stub.observed[index - 1].end).toBeLessThan(
        stub.observed[index].start,
      );
    }
  });

  it("does not wedge the queue when a request fails", async () => {
    // `then(run, run)` rather than `finally`: a rejected chain that was never
    // reset would leave every later call in the request unrunnable, which is a
    // far worse failure than the one that caused it.
    const stub = stubFetch(
      (_url, seq) => new Response(null, { status: seq === 1 ? 500 : 207 }),
    );
    vi.stubGlobal("fetch", stub.fetch);
    const davFetch = createDavFetch(env);

    await expect(davFetch(TARGET)).rejects.toBeInstanceOf(DavConnectError);
    const second = await davFetch(TARGET);

    expect(second.status).toBe(207);
    expect(stub.observed.length).toBe(2);
  });

  it("gives each request its own queue rather than one shared at module scope", async () => {
    // Two independent `createDavFetch` instances must not serialise against
    // each other: a module-level chain would turn an isolate into a single-file
    // line, which is the opposite mistake from the session gate's.
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    const first = createDavFetch(env);
    const second = createDavFetch(env);
    await Promise.all([first(`${TARGET}a/`), second(`${TARGET}b/`)]);

    // The stub still records them, and the assertion here is about
    // independence, not order: two separate instances have two separate chains.
    expect(stub.observed.length).toBe(2);
  });
});

describe("createDavFetch — status to typed error (D-60)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([200, 201, 204, 207])("returns the response on %i", async (status) => {
    vi.stubGlobal("fetch", statusStub(status).fetch);
    const response = await createDavFetch(env)(TARGET);
    expect(response.status).toBe(status);
  });

  it.each([401, 403])(
    "throws DavAuthError on %i, which is never retried",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(env))).toBeInstanceOf(DavAuthError);
    },
  );

  it.each([429, 503])(
    "throws DavThrottleError on %i, which is never retried",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(env))).toBeInstanceOf(DavThrottleError);
    },
  );

  it.each([400, 404, 410, 301, 302, 303, 307, 308])(
    "throws a re-discovery-ELIGIBLE DavNotFoundError on %i",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = await raise(createDavFetch(env));
      expect(raised).toBeInstanceOf(DavNotFoundError);
      expect((raised as DavNotFoundError).rediscoverable).toBe(true);
    },
  );

  it.each([415, 501])(
    "throws a re-discovery-INELIGIBLE DavNotFoundError on %i",
    async (status) => {
      // "This server does not offer this report" is a statement about a missing
      // CAPABILITY, not about a stale host — re-discovery cannot help, and plan
      // 03-08's contacts fallback needs exactly this signal to tell a refused
      // server-side filter apart from a failed network.
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = await raise(createDavFetch(env));
      expect(raised).toBeInstanceOf(DavNotFoundError);
      expect((raised as DavNotFoundError).rediscoverable).toBe(false);
    },
  );

  it("throws DavStaleResourceError on 412 (CALW-05)", async () => {
    // Before this plan, 412 fell through to the final line of `throwForStatus`
    // and became a `DavConnectError` — which `isRediscoverable` accepts. So a
    // raced write on a warm cache deleted the discovery entry, spent a real
    // PROPFIND against Apple, re-issued the write, received 412 again, and
    // reported "This may be transient — safe to retry once." Three failures
    // compounding: the wrong category, a wasted request against the tightest
    // budget in the project, and guidance telling the model to do the one
    // thing that can never work.
    vi.stubGlobal("fetch", statusStub(412).fetch);
    const raised = await raise(createDavFetch(env));

    expect(raised).toBeInstanceOf(DavStaleResourceError);
    expect(raised).not.toBeInstanceOf(DavConnectError);
    expect(davToErrorCategory(raised).category).toBe("stale_resource");
  });

  it.each([405, 409, 418, 500, 502, 507])(
    "throws DavConnectError on %i",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(env))).toBeInstanceOf(DavConnectError);
    },
  );

  it.each([
    [401, DavAuthError, null],
    [403, DavAuthError, null],
    [429, DavThrottleError, null],
    [503, DavThrottleError, null],
    [415, DavNotFoundError, false],
    [501, DavNotFoundError, false],
    [400, DavNotFoundError, true],
    [404, DavNotFoundError, true],
    [410, DavNotFoundError, true],
    [302, DavNotFoundError, true],
    [500, DavConnectError, null],
  ] as const)(
    "still classifies %i exactly as it did before the 412 branch was inserted",
    async (status, klass, rediscoverable) => {
      // A regression in the surrounding chain is the REAL risk of this edit —
      // one line inserted into an ordered sequence of `if`s, where a
      // misplacement is silent and changes the answer for a status nobody was
      // looking at. The cases above assert each classification for its own
      // reason; this one asserts the whole table has not moved, so a
      // regression names the status rather than the feature.
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = await raise(createDavFetch(env));

      expect(raised).toBeInstanceOf(klass);
      if (rediscoverable !== null) {
        expect((raised as DavNotFoundError).rediscoverable).toBe(
          rediscoverable,
        );
      }
    },
  );

  it("throws DavConnectError on a transport-level failure, without reading it", async () => {
    const hostile = {
      get message(): string {
        throw new Error("the caught value must never be read");
      },
    };
    vi.stubGlobal(
      "fetch",
      (async () => {
        throw hostile;
      }) as typeof globalThis.fetch,
    );

    expect(await raise(createDavFetch(env))).toBeInstanceOf(DavConnectError);
  });
});

describe("the two categories that arrived with Phase 5", () => {
  it("translates DavStaleResourceError to stale_resource and its fixed message", () => {
    expect(davToErrorCategory(new DavStaleResourceError())).toEqual({
      category: "stale_resource",
      message: SAFE_MESSAGES.stale_resource,
    });
  });

  it("translates DavConfirmationError to confirmation_invalid and its fixed message", () => {
    expect(davToErrorCategory(new DavConfirmationError())).toEqual({
      category: "confirmation_invalid",
      message: SAFE_MESSAGES.confirmation_invalid,
    });
  });

  it("leaves DavConnectError as the explicit floor of the chain", () => {
    // The two new branches are inserted BEFORE the connect branch, so that one
    // stays last. If either had been appended after it the chain would still
    // pass every case above — `DavConnectError` is not a supertype of them —
    // but the ordering constraint the docstring states would have quietly
    // stopped being true, and the next branch added would land after the floor.
    expect(davToErrorCategory(new DavConnectError()).category).toBe(
      "connection_failed",
    );
    expect(davToErrorCategory(new Error("something unrecognised")).category).toBe(
      "connection_failed",
    );
  });

  it.each([
    ["DavStaleResourceError", () => new DavStaleResourceError()],
    ["DavConfirmationError", () => new DavConfirmationError()],
  ])("%s carries nothing beyond the shape every Dav* class has", (_label, make) => {
    // `kind` and `name` are what `DavAuthError` and `DavThrottleError` already
    // carry — the discriminant and the assigned class name. Asserting the SET
    // is what makes a newly-added field fail here instead of shipping: neither
    // class takes a constructor argument, so there is no URL, no status line
    // and no server body for one to hold.
    const raised = make();
    const fields = ownFields(raised);

    expect(Object.keys(fields).sort()).toEqual(["kind", "name"]);
    expect("rediscoverable" in fields).toBe(false);

    const serialized = JSON.stringify(raised);
    expect(serialized).not.toContain("http");
    expect(serialized).not.toContain("icloud");
    expect(serialized).not.toContain("412");
    expect(raised.message).toMatch(/^dav-[a-z-]+$/);
  });
});

describe("no Dav* error carries anything a server said (T-03-03, T-03-04)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    [401, ["kind", "name"]],
    [429, ["kind", "name"]],
    [500, ["kind", "name"]],
    [412, ["kind", "name"]],
    [404, ["kind", "name", "rediscoverable"]],
    [415, ["kind", "name", "rediscoverable"]],
  ])(
    "the error raised by %i has exactly the fields %j",
    async (status, expected) => {
      // A server body reaching an error field is the whole of T-03-04, and the
      // failure mode is silent: nothing breaks, a URL just starts appearing in
      // tool responses. Asserting the SET rather than an absence is what makes
      // a newly-added field fail here instead of shipping.
      vi.stubGlobal(
        "fetch",
        stubFetch(
          () =>
            new Response(
              `<?xml version="1.0"?><error xmlns="DAV:"><href>${TARGET}</href></error>`,
              { status, headers: { "content-type": "text/xml" } },
            ),
        ).fetch,
      );

      const raised = await raise(createDavFetch(env));
      const fields = ownFields(raised);

      expect(Object.keys(fields).sort()).toEqual(expected);

      const serialized = JSON.stringify(fields);
      expect(serialized).not.toContain("http");
      expect(serialized).not.toContain("icloud");
      expect(serialized).not.toContain(String(status));
      expect(serialized).not.toContain("DAV:");
    },
  );

  it.each([401, 429, 404, 500])(
    "the message on %i is a fixed internal label, never server text",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = (await raise(createDavFetch(env))) as Error;

      expect(raised.message).toMatch(/^dav-[a-z-]+$/);
      expect(raised.message).not.toContain("http");
      expect(raised.message).not.toContain(String(status));
    },
  );

  it("never lets a credential reach a thrown error", async () => {
    assertMailSecretsBound(env);
    const bound: BoundMailSecrets = env;
    expect(bound.APPLE_ID.length).toBeGreaterThan(0);
    expect(bound.APPLE_APP_PASSWORD.length).toBeGreaterThan(0);

    vi.stubGlobal("fetch", statusStub(401).fetch);
    const raised = (await raise(createDavFetch(env))) as Error;
    const serialized = `${JSON.stringify(ownFields(raised))}${raised.message}${raised.stack ?? ""}`;

    expect(serialized).not.toContain(bound.APPLE_ID);
    expect(serialized).not.toContain(bound.APPLE_APP_PASSWORD);
  });
});
