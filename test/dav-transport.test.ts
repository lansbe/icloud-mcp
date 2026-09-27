// DAV-01, taken apart. The tracer proved these layers work assembled; this
// suite proves each obligation of the choke point independently, so a
// regression names the thing that broke instead of "dav_diagnose is red".
//
// Five obligations land on `createDavFetch` and no other seam can serve any of
// them: the credential is attached per call, the redirect policy is forced to
// the observable one, requests are serialised against the per-invocation
// connection budget, a status NUMBER is turned into a typed error before tsdav
// ever sees the response, and a method this runtime cannot build a request from
// is refused BEFORE the attempt. Each has cases below. The fifth arrived in
// Phase 14, after the absence of it produced a wrong answer that was read as a
// measurement of iCloud's behaviour.
//
// No network and no real credentials — D-09 forbids any automated job
// authenticating against the real Apple ID. The seam is the same one production
// uses: the global `fetch` these tests stub is the one `createDavFetch` closes
// over.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DavAuthError,
  DavForbiddenError,
  DavConfirmationError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavSyncTokenError,
  DavThrottleError,
  DavUnsendableError,
  davToErrorCategory,
} from "../src/dav/errors";
import { createDavFetch, davAuthHeader } from "../src/dav/transport";
import { SAFE_MESSAGES } from "../src/errors";
import { guardAgainstPause } from "../src/password-pause";
import type { Principal } from "../src/principal";
import { principalFromProps } from "../src/principal";
import {
  FAKE_APP_PASSWORD,
  FAKE_APPLE_ID,
  ownerPrincipal,
  refusedPrincipal,
} from "./fixtures/bound-secrets";

// The owner's principal, as the PROMISE the real constructor returns over the
// fixture's own two fake credentials. The DAV fetch builder and the registrars
// take the promise. The no-op handler means a file that builds it and awaits it
// nowhere leaves no rejection unheard. Everyone who does await it still sees
// the refusal.
const owner = ownerPrincipal();
owner.catch(() => {});

const TARGET = "https://p42-caldav.icloud.com/1234567890/calendars/";

/**
 * The RFC 4791 calendar-creation method this runtime refuses to build.
 *
 * **Assembled from fragments, and the assembly is the point rather than an
 * accident.** That method's name is a forbidden token in every scanned root —
 * `src/`, `scripts/` and `test/` alike, with no scope and no file exclusion —
 * so a source file that SPELLS it fails the commit hook. Joining two fragments
 * puts the identical string in this constant at runtime while leaving no
 * contiguous literal for the scan to find. ONE construction per file, here,
 * rather than one per case: the same discipline the socket and write
 * choke-points already use.
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
 * The cases below construct it ON PURPOSE, to drive the sendability check with
 * a method the runtime genuinely refuses and watch `DavUnsendableError` come
 * back instead of a connection fault. `.planning/PROJECT.md`'s SPIKE-04 row is
 * the authority for the constraint itself.
 */
const REFUSED_CREATE_METHOD = ["MK", "CALENDAR"].join("");

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
  // The refusal cases below stub the global fetch, to count what left.
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("builds a Basic header from the owner's two credentials", async () => {
    // The owner's principal, from the real props constructor. The assertion
    // below compares against the very two constants that principal was built
    // from, untouched: it is the proof that threading the principal did not
    // move one byte of the header.
    const header = davAuthHeader(await owner);

    expect(header.startsWith("Basic ")).toBe(true);
    expect(atob(header.slice("Basic ".length))).toBe(
      `${FAKE_APPLE_ID}:${FAKE_APP_PASSWORD}`,
    );
  });

  it("encodes a non-ASCII password over UTF-8 BYTES, not UTF-16 code units", async () => {
    // U+00FC is the case that separates the two encodings while staying inside
    // btoa's own range, so the wrong answer is producible rather than merely
    // theoretical: as a code unit it is one byte 0xFC, as UTF-8 it is 0xC3 0xBC.
    // A header built the wrong way is accepted by btoa and rejected by Apple,
    // and the user is told their app-specific password is wrong when only its
    // encoding was.
    //
    // The non-ASCII character used to sit in the Apple ID. It moved to the
    // password in Phase 9: a principal cannot be built from an Apple ID outside
    // printable ASCII (Apple IDs follow email conventions, D-21), and only a
    // real principal reaches the header now. A password may still carry one,
    // and it goes through the very same encoder call.
    const appleId = "russell@example.invalid";
    const password = "test-pässword-not-real";
    const scoped = await principalFromProps({
      v: 1,
      appleId,
      appPassword: password,
    });

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
    ["the Apple ID half is unusable", "appleId"],
    ["the password half is unusable", "appPassword"],
  ] as const)(
    "refuses with DavAuthError and sends nothing when %s",
    async (_label, which) => {
      // This case's subject is the SHORT CIRCUIT and not how the principal came
      // to be refused: a refused principal promise makes the DAV fetch raise its
      // own auth error, and no request leaves.
      //
      // It ran four rows until Phase 13 — one per account binding, absent and
      // empty — by handing a patched environment to the constructor that phase
      // deletes. There is no environment to patch now, so what survives is the
      // two rows the fixture's helper can express: one bad half each. Whether an
      // unset credential and an empty one are BOTH refused is the constructor's
      // own claim, and it is held where the constructor is tested.
      const stub = statusStub(207);
      vi.stubGlobal("fetch", stub.fetch);

      const refused = refusedPrincipal(which);
      refused.catch(() => {});

      expect(await raise(createDavFetch(refused))).toBeInstanceOf(DavAuthError);
      expect(stub.observed.length).toBe(0);
    },
  );

  it.each([
    ["a trailing newline", `${FAKE_APP_PASSWORD}\n`],
    ["a carriage return", "test-\rpassword"],
    ["a NUL", "test-\u0000password"],
  ])(
    "refuses with DavAuthError and sends nothing on a password carrying %s",
    async (_label, password) => {
      // A password pasted out of another window carries whatever line ending
      // came with it, so this is the mundane case rather than the hostile one.
      // Refusing beats escaping: an escaped value is turned down by the server,
      // and the person is told the credential is wrong when only its encoding
      // was.
      //
      // Built through the REAL constructor rather than the fixture's helper,
      // because the helper picks which half is bad and this case needs a
      // SPECIFIC bad value in that half. The principal module refuses these
      // first; the header function's own check is the second layer behind it.
      const stub = statusStub(207);
      vi.stubGlobal("fetch", stub.fetch);

      const refused = principalFromProps({
        v: 1,
        appleId: FAKE_APPLE_ID,
        appPassword: password,
      });
      refused.catch(() => {});

      expect(await raise(createDavFetch(refused))).toBeInstanceOf(DavAuthError);
      expect(stub.observed.length).toBe(0);
    },
  );

  it("refuses an illegal character in the Apple ID too", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    // The line ending sits in the MIDDLE, so the trim check (D-18) passes it
    // through and the id function's ASCII rule is what turns it away — the same
    // refusal this case has always been about.
    const refused = principalFromProps({
      v: 1,
      appleId: "a\nb@example.invalid",
      appPassword: FAKE_APP_PASSWORD,
    });
    refused.catch(() => {});

    expect(await raise(createDavFetch(refused))).toBeInstanceOf(DavAuthError);
    expect(stub.observed.length).toBe(0);
  });

  it("reads a refused principal as auth_failed, never as a connection fault", async () => {
    // The await of the promise sits OUTSIDE the try around the fetch. Inside it,
    // this would read `connection_failed`, and that invites a retry that can
    // never work (D-27).
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    const refused = refusedPrincipal("appleId");
    refused.catch(() => {});

    const raised = await raise(createDavFetch(refused));
    expect(davToErrorCategory(raised).category).toBe("auth_failed");
    expect(stub.observed.length).toBe(0);
  });

  describe("a principal no constructor built (D-16)", () => {
    it("refuses a hand-made look-alike, and sends nothing", async () => {
      const stub = statusStub(207);
      vi.stubGlobal("fetch", stub.fetch);

      // The right two fields and the right types. It is still not an object a
      // constructor returned, so the password reader has nothing for it.
      const lookalike: Principal = {
        userId: "0".repeat(64),
        appleId: "lookalike@example.invalid",
      };

      expect(() => davAuthHeader(lookalike)).toThrow(DavAuthError);
      expect(
        await raise(createDavFetch(Promise.resolve(lookalike))),
      ).toBeInstanceOf(DavAuthError);
      expect(stub.observed.length).toBe(0);
    });

    it("refuses a spread copy of a real principal, and sends nothing", async () => {
      const stub = statusStub(207);
      vi.stubGlobal("fetch", stub.fetch);

      // Done here ONLY to prove it is refused. Nothing under `src/` may do this.
      const copy: Principal = { ...(await owner) };

      expect(() => davAuthHeader(copy)).toThrow(DavAuthError);
      expect(await raise(createDavFetch(Promise.resolve(copy)))).toBeInstanceOf(
        DavAuthError,
      );
      expect(stub.observed.length).toBe(0);
    });

    it("serves the real object the copy was made from (the control)", async () => {
      const stub = statusStub(207);
      vi.stubGlobal("fetch", stub.fetch);

      await createDavFetch(owner)(TARGET);

      expect(stub.observed.length).toBe(1);
    });
  });
});

describe("createDavFetch — the credential", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("merges authorization into caller-supplied headers rather than replacing them", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    await createDavFetch(owner)(TARGET, {
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

    await createDavFetch(owner)(TARGET, {
      headers: { authorization: "Bearer caller-supplied" },
    });

    expect(stub.observed[0].headers.get("authorization")).not.toBe(
      "Bearer caller-supplied",
    );
    expect(
      stub.observed[0].headers.get("authorization")?.startsWith("Basic "),
    ).toBe(true);
  });

  it("refuses before the request when the principal was refused", async () => {
    const stub = statusStub(207);
    vi.stubGlobal("fetch", stub.fetch);

    // The promise the door hands over when the grant's credentials do not check
    // out. It rejects, and the DAV fetch turns the rejection into its own auth
    // error.
    const refused = refusedPrincipal("appleId");
    refused.catch(() => {});
    await expect(createDavFetch(refused)(TARGET)).rejects.toBeInstanceOf(
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
    const davFetch = createDavFetch(owner);

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

    await createDavFetch(owner)(TARGET, { redirect: "follow" });

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
    const davFetch = createDavFetch(owner);

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
    const davFetch = createDavFetch(owner);

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

    const first = createDavFetch(owner);
    const second = createDavFetch(owner);
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
    const response = await createDavFetch(owner)(TARGET);
    expect(response.status).toBe(status);
  });

  it.each([401, 403])(
    "throws DavAuthError on %i, which is never retried",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(owner))).toBeInstanceOf(DavAuthError);
    },
  );

  it("tells a 403 apart from a 401 by type only: same name, message and fields (WR-02)", async () => {
    vi.stubGlobal("fetch", statusStub(403).fetch);
    const forbidden = await raise(createDavFetch(owner));
    vi.stubGlobal("fetch", statusStub(401).fetch);
    const unauthorised = await raise(createDavFetch(owner));

    expect(forbidden).toBeInstanceOf(DavForbiddenError);
    expect(unauthorised).toBeInstanceOf(DavAuthError);
    expect(unauthorised).not.toBeInstanceOf(DavForbiddenError);
    expect((forbidden as Error).name).toBe((unauthorised as Error).name);
    expect((forbidden as Error).message).toBe((unauthorised as Error).message);
    expect(Object.keys(forbidden as object).sort()).toEqual(
      Object.keys(unauthorised as object).sort(),
    );
    expect(davToErrorCategory(forbidden)).toEqual(davToErrorCategory(unauthorised));
  });

  it.each([429, 503])(
    "throws DavThrottleError on %i, which is never retried",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(owner))).toBeInstanceOf(DavThrottleError);
    },
  );

  it.each([400, 404, 410, 301, 302, 303, 307, 308])(
    "throws a re-discovery-ELIGIBLE DavNotFoundError on %i",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = await raise(createDavFetch(owner));
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
      const raised = await raise(createDavFetch(owner));
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
    const raised = await raise(createDavFetch(owner));

    expect(raised).toBeInstanceOf(DavStaleResourceError);
    expect(raised).not.toBeInstanceOf(DavConnectError);
    expect(davToErrorCategory(raised).category).toBe("stale_resource");
  });

  it.each([405, 409, 418, 500, 502, 507])(
    "throws DavConnectError on %i",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      expect(await raise(createDavFetch(owner))).toBeInstanceOf(DavConnectError);
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
      const raised = await raise(createDavFetch(owner));

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

    expect(await raise(createDavFetch(owner))).toBeInstanceOf(DavConnectError);
  });
});

describe("the wait outcome, from the status number to the sentence a caller reads (CONF-06)", () => {
  // The leg that had never been measured. `test/errors.test.ts` constructs
  // `DavThrottleError` by hand and asserts the category it maps to; the cases
  // above construct a 429 and assert the CLASS it raises. Neither joins the
  // two, so nothing in the suite said that a server asking this client to wait
  // arrives at the caller as a sentence telling it to wait.
  //
  // That join is what CONF-06 is for. Phase 14's collection write probe
  // produced "This may be transient — safe to retry once" for a failure that
  // was neither, and the report read as a measurement of iCloud's behaviour.
  // The answer for a throttling server has been correct all along on both
  // sides; it had simply never been proven from one end to the other, and an
  // unproven correct answer is indistinguishable from a lucky one.

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([429, 503])(
    "carries %i to the fixed wait sentence, and to no other category",
    async (status) => {
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const raised = await raise(createDavFetch(owner));

      expect(raised).toBeInstanceOf(DavThrottleError);

      const answer = davToErrorCategory(raised);
      expect(answer.category).toBe("rate_limited");

      // Compared against the shipped table rather than a restated literal, so
      // a reword moves both sides together. A literal here would let the table
      // and the proof drift apart, which is the failure this whole case exists
      // to close one layer down.
      expect(answer.message).toBe(SAFE_MESSAGES.rate_limited);

      // The two answers it must never be. `connection_failed` is the floor
      // every unclassified value lands on and it offers a retry;
      // `request_unsendable` says the remote end was never involved, which
      // would be false — the server answered, and its answer was "wait".
      expect(answer.category).not.toBe("connection_failed");
      expect(answer.category).not.toBe("request_unsendable");
      expect(raised).not.toBeInstanceOf(DavConnectError);
      expect(raised).not.toBeInstanceOf(DavUnsendableError);
    },
  );

  it.each([429, 503])(
    "sends exactly one request while producing the wait outcome on %i",
    async (status) => {
      // The transport's own docstring says a server that has just declared it
      // is throttling is the last thing to send a second request to. Nothing
      // measured that. A retry inserted anywhere between the status number and
      // the caller's string would walk straight into iCloud's undocumented
      // per-account ceiling, whose cost falls on the user's own Mail.app
      // rather than on this server.
      const stub = statusStub(status);
      vi.stubGlobal("fetch", stub.fetch);
      const raised = await raise(createDavFetch(owner));

      expect(stub.observed.length).toBe(1);
      expect(davToErrorCategory(raised).message).toBe(SAFE_MESSAGES.rate_limited);
    },
  );
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

      const raised = await raise(createDavFetch(owner));
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
      const raised = (await raise(createDavFetch(owner))) as Error;

      expect(raised.message).toMatch(/^dav-[a-z-]+$/);
      expect(raised.message).not.toContain("http");
      expect(raised.message).not.toContain(String(status));
    },
  );

  it("never lets a credential reach a thrown error", async () => {
    expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
    expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);

    vi.stubGlobal("fetch", statusStub(401).fetch);
    const raised = (await raise(createDavFetch(owner))) as Error;
    const serialized = `${JSON.stringify(ownFields(raised))}${raised.message}${raised.stack ?? ""}`;

    expect(serialized).not.toContain(FAKE_APPLE_ID);
    expect(serialized).not.toContain(FAKE_APP_PASSWORD);
  });
});

// ---------------------------------------------------------------------------
// The fifth obligation: refuse a method this runtime cannot send.
//
// MEASURED on 2026-09-24. workerd's `Request` constructor rejects the RFC 4791
// calendar-creation method -- and accepts `PROPFIND`, `PROPPATCH`, `REPORT`,
// `MKCOL`, `DELETE` and `PUT`. tsdav's collection-creation helper hardcodes the
// one it rejects, so the `TypeError` landed in the `catch` around the fetch below,
// became a `DavConnectError`, and reached the caller as `connection_failed`:
// "Could not establish a secure connection to iCloud Mail. This may be
// transient -- safe to retry once." Every clause of that was false. No
// connection was attempted, nothing was transient, and no retry could ever
// work.
//
// The check is BEHAVIOURAL rather than a written-down allow-list, and that is
// the design: a list here would be a second copy of workerd's, agreeing today
// and drifting silently. The runtime is asked instead.
// ---------------------------------------------------------------------------

describe("a method this runtime cannot send", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("raises request_unsendable, NOT connection_failed", async () => {
    // The whole point. `connection_failed` told the reader a connection to
    // iCloud had failed and that a retry was safe, about a server that was
    // never contacted -- and that report was on its way into SPIKE-04's
    // written verdict.
    const stub = stubFetch(() => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", stub.fetch);

    const davFetch = createDavFetch(owner);
    await expect(
      davFetch("https://p42-caldav.icloud.com/x/", {
        method: REFUSED_CREATE_METHOD,
      }),
    ).rejects.toBeInstanceOf(DavUnsendableError);

    const { category, message } = davToErrorCategory(new DavUnsendableError());
    expect(category).toBe("request_unsendable");
    expect(message).toBe(SAFE_MESSAGES.request_unsendable);
    expect(category).not.toBe("connection_failed");
  });

  it("says nothing was sent and that retrying cannot help", async () => {
    // The message is the only prose a caller ever sees, and it is what stops a
    // platform limit being written down as Apple's answer.
    const { message } = davToErrorCategory(new DavUnsendableError());
    expect(message).toContain("iCloud never saw it");
    expect(message).toContain("Retrying will not help");
  });

  it("issues NO request at all, so nothing reaches the network", async () => {
    const stub = stubFetch(() => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", stub.fetch);

    await expect(
      createDavFetch(owner)("https://p42-caldav.icloud.com/x/", {
        method: REFUSED_CREATE_METHOD,
      }),
    ).rejects.toThrow();

    expect(stub.observed).toEqual([]);
  });

  it("lets through every method this project actually sends", async () => {
    // Non-vacuity, and a guard against the check being tightened into a
    // hand-written allow-list that quietly drops one. Each of these is a
    // method some shipped path depends on.
    const stub = stubFetch(() => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", stub.fetch);

    const davFetch = createDavFetch(owner);
    for (const method of [
      "GET",
      "PUT",
      "DELETE",
      "PROPFIND",
      "PROPPATCH",
      "REPORT",
      "MKCOL",
    ]) {
      await expect(
        davFetch("https://p42-caldav.icloud.com/x/", { method }),
      ).resolves.toBeInstanceOf(Response);
    }
    expect(stub.observed.length).toBe(7);
  });

  it("carries no method, no URL and no credential on the error it raises", async () => {
    // Same discipline as every other class in this tree. A method string
    // cannot hold a secret, but a field that exists is one step from being
    // reported, and the report already names its own method because it chose
    // it -- not because an error handed it over.
    const raised = new DavUnsendableError();
    const serialized = `${JSON.stringify(ownFields(raised))}${raised.message}${raised.stack ?? ""}`;

    expect(raised.message).toMatch(/^dav-[a-z-]+$/);
    expect(serialized).not.toContain(REFUSED_CREATE_METHOD);
    expect(serialized).not.toContain("icloud");
    expect(serialized).not.toContain(FAKE_APPLE_ID);
    expect(serialized).not.toContain(FAKE_APP_PASSWORD);
  });
});

// ---------------------------------------------------------------------------
// Phase 23 (D-28): an expired sync token is told apart from a wrong password.
//
// RFC 6578 names the precondition a stale token fails, `DAV:valid-sync-token`,
// and does NOT fix the status. Servers answer 403 (CalendarServer, SabreDAV),
// 410 (Google) or 409. Before this branch each of those read as something false:
// a rejected password, a moved shard, a transient fault. The transport now reads
// a bounded prefix of the body for a REPORT answered one of those three, and
// nothing else changes. Every case below drives the real `createDavFetch`.
// ---------------------------------------------------------------------------

describe("createDavFetch — an expired sync token (D-28)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const REPORT: RequestInit = { method: "REPORT" };

  /** An RFC 6578 precondition body, with the element under a chosen prefix. */
  function syncTokenBody(prefix: string): string {
    const open = prefix === "" ? "" : `${prefix}:`;
    const ns = prefix === "" ? 'xmlns="DAV:"' : `xmlns:${prefix}="DAV:"`;
    return `<?xml version="1.0" encoding="utf-8"?><${open}error ${ns}><${open}valid-sync-token/></${open}error>`;
  }

  /** Answer every request with this status and this body. */
  function bodyStub(status: number, body: string): Stub {
    return stubFetch(
      () =>
        new Response(body, {
          status,
          headers: { "content-type": "application/xml" },
        }),
    );
  }

  it.each([403, 409, 410])(
    "a REPORT answered %i naming the element raises DavSyncTokenError",
    async (status) => {
      vi.stubGlobal("fetch", bodyStub(status, syncTokenBody("D")).fetch);
      const raised = await raise(createDavFetch(owner), REPORT);
      expect(raised).toBeInstanceOf(DavSyncTokenError);
    },
  );

  it.each([
    ["no prefix", ""],
    ["a different prefix", "x"],
    ["a long prefix", "webdav"],
  ])("finds the element with %s", async (_label, prefix) => {
    vi.stubGlobal("fetch", bodyStub(403, syncTokenBody(prefix)).fetch);
    const raised = await raise(createDavFetch(owner), REPORT);
    expect(raised).toBeInstanceOf(DavSyncTokenError);
  });

  it("matches the method case-insensitively", async () => {
    vi.stubGlobal("fetch", bodyStub(403, syncTokenBody("D")).fetch);
    const raised = await raise(createDavFetch(owner), { method: "report" });
    expect(raised).toBeInstanceOf(DavSyncTokenError);
  });

  it("finds it with an opening tag carrying whitespace and attributes", async () => {
    const body = `<D:error xmlns:D="DAV:"><D:valid-sync-token\n  a="b"></D:valid-sync-token></D:error>`;
    vi.stubGlobal("fetch", bodyStub(410, body).fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavSyncTokenError,
    );
  });

  it("a REPORT 403 whose body names no such element is still DavAuthError", async () => {
    const body = `<D:error xmlns:D="DAV:"><D:need-privileges/></D:error>`;
    vi.stubGlobal("fetch", bodyStub(403, body).fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavAuthError,
    );
  });

  it("the name as text, not as an element, does not count", async () => {
    const body = `<D:error xmlns:D="DAV:"><D:description>valid-sync-token</D:description><D:valid-sync-tokens/></D:error>`;
    vi.stubGlobal("fetch", bodyStub(403, body).fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavAuthError,
    );
  });

  it("a REPORT 410 without the element is still a re-discovery-eligible DavNotFoundError", async () => {
    vi.stubGlobal("fetch", bodyStub(410, "<multistatus/>").fetch);
    const raised = await raise(createDavFetch(owner), REPORT);
    expect(raised).toBeInstanceOf(DavNotFoundError);
    expect((raised as DavNotFoundError).rediscoverable).toBe(true);
  });

  it("a REPORT 409 without the element is still DavConnectError", async () => {
    vi.stubGlobal("fetch", bodyStub(409, "<multistatus/>").fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavConnectError,
    );
  });

  it("a PROPFIND 403 WITH the element is still DavAuthError: the branch is REPORT-only", async () => {
    vi.stubGlobal("fetch", bodyStub(403, syncTokenBody("D")).fetch);
    expect(
      await raise(createDavFetch(owner), { method: "PROPFIND" }),
    ).toBeInstanceOf(DavAuthError);
  });

  it.each(["PUT", "DELETE"])(
    "a %s 403 with the element is still DavAuthError",
    async (method) => {
      vi.stubGlobal("fetch", bodyStub(403, syncTokenBody("D")).fetch);
      expect(await raise(createDavFetch(owner), { method })).toBeInstanceOf(
        DavAuthError,
      );
    },
  );

  it.each([
    [410, DavNotFoundError],
    [409, DavConnectError],
  ] as const)(
    "a request with no method answered %i with the element is unchanged",
    async (status, klass) => {
      vi.stubGlobal("fetch", bodyStub(status, syncTokenBody("D")).fetch);
      const raised = await raise(createDavFetch(owner));
      expect(raised).toBeInstanceOf(klass);
      expect(raised).not.toBeInstanceOf(DavSyncTokenError);
    },
  );

  it.each([400, 404, 412, 500, 503])(
    "a REPORT answered %i with the element is classified exactly as before",
    async (status) => {
      vi.stubGlobal("fetch", bodyStub(status, syncTokenBody("D")).fetch);
      const raised = await raise(createDavFetch(owner), REPORT);
      expect(raised).not.toBeInstanceOf(DavSyncTokenError);
      vi.stubGlobal("fetch", statusStub(status).fetch);
      const plain = await raise(createDavFetch(owner), REPORT);
      expect((raised as Error).constructor).toBe((plain as Error).constructor);
    },
  );

  it("reads a bounded prefix only: the element past 8 KB is not seen", async () => {
    // The padding sits INSIDE the error element as whitespace, so the body is
    // still well-formed XML naming the precondition. Only the bound hides it.
    const padding = " ".repeat(9000);
    const body = `<D:error xmlns:D="DAV:">${padding}<D:valid-sync-token/></D:error>`;
    vi.stubGlobal("fetch", bodyStub(403, body).fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavAuthError,
    );
  });

  it("finds the element just inside the bound", async () => {
    const padding = " ".repeat(7000);
    const body = `<D:error xmlns:D="DAV:">${padding}<D:valid-sync-token/></D:error>`;
    vi.stubGlobal("fetch", bodyStub(403, body).fetch);
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavSyncTokenError,
    );
  });

  it("stops reading at the bound, and cancels the rest of a long body", async () => {
    // A body that would never end. Reading it to the end would hang the case;
    // a bounded read returns and cancels the stream.
    let cancelled = false;
    let pulled = 0;
    const chunk = new TextEncoder().encode(" ".repeat(1024));
    vi.stubGlobal(
      "fetch",
      stubFetch(
        () =>
          new Response(
            new ReadableStream<Uint8Array>({
              pull(controller) {
                pulled += 1;
                controller.enqueue(chunk);
              },
              cancel() {
                cancelled = true;
              },
            }),
            { status: 403 },
          ),
      ).fetch,
    );
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavAuthError,
    );
    expect(cancelled).toBe(true);
    expect(pulled).toBeLessThan(20);
  });

  it("a body that fails to read counts as no element", async () => {
    vi.stubGlobal(
      "fetch",
      stubFetch(
        () =>
          new Response(
            new ReadableStream<Uint8Array>({
              pull(controller) {
                controller.error(new Error("the read failed"));
              },
            }),
            { status: 403 },
          ),
      ).fetch,
    );
    expect(await raise(createDavFetch(owner), REPORT)).toBeInstanceOf(
      DavAuthError,
    );
  });

  it("a REPORT 207 is returned untouched, with its body still readable", async () => {
    const body = `<d:multistatus xmlns:d="DAV:"><d:sync-token>t2</d:sync-token></d:multistatus>`;
    vi.stubGlobal("fetch", bodyStub(207, body).fetch);
    const response = await createDavFetch(owner)(TARGET, REPORT);
    expect(response.status).toBe(207);
    expect(await response.text()).toBe(body);
  });

  it("a 401 on a REPORT still reports the refusal before throwing DavAuthError", async () => {
    const puts: string[] = [];
    const kv = {
      get: async () => null,
      put: async (key: string) => {
        puts.push(key);
      },
    } as unknown as KVNamespace;
    vi.stubGlobal("fetch", bodyStub(401, syncTokenBody("D")).fetch);
    const davFetch = createDavFetch(guardAgainstPause(ownerPrincipal(), kv));

    expect(await raise(davFetch, REPORT)).toBeInstanceOf(DavAuthError);
    expect(puts).toHaveLength(1);
  });

  it("the error carries no byte of the body", async () => {
    const MARK = "BODY-TEXT-MUST-NOT-TRAVEL";
    const body = `<D:error xmlns:D="DAV:"><D:valid-sync-token/><D:href>${TARGET}${MARK}</D:href></D:error>`;
    vi.stubGlobal("fetch", bodyStub(403, body).fetch);
    const raised = (await raise(createDavFetch(owner), REPORT)) as Error;

    expect(raised).toBeInstanceOf(DavSyncTokenError);
    expect(Object.keys(ownFields(raised)).sort()).toEqual(["kind", "name"]);
    expect(raised.message).toMatch(/^dav-[a-z-]+$/);
    const serialized = `${JSON.stringify(raised)}${JSON.stringify(ownFields(raised))}${raised.message}`;
    expect(serialized).not.toContain(MARK);
    expect(serialized).not.toContain("http");
    expect(serialized).not.toContain("valid-sync-token");
    expect(serialized).not.toContain("DAV:");
  });

  it("maps to stale_resource and that category's fixed message", async () => {
    vi.stubGlobal("fetch", bodyStub(409, syncTokenBody("D")).fetch);
    const raised = await raise(createDavFetch(owner), REPORT);
    expect(davToErrorCategory(raised)).toEqual({
      category: "stale_resource",
      message: SAFE_MESSAGES.stale_resource,
    });
  });

  it("sends exactly one request: nothing is retried", async () => {
    const stub = bodyStub(410, syncTokenBody("D"));
    vi.stubGlobal("fetch", stub.fetch);
    await raise(createDavFetch(owner), REPORT);
    expect(stub.observed).toHaveLength(1);
  });
});
