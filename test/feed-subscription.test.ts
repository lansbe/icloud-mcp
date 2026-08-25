// The uncredentialed feed-fetch choke point, taken apart (T-quick-01,
// T-quick-02).
//
// `fetchSubscriptionFeed` is the one function in this repository permitted to
// GET a `CS:source` href — a value the account's own PROPFIND response
// supplies, but one that names an arbitrary third-party host, per the debug
// session's live measurement (`sm-cal.apple.com`, anonymously readable,
// `content-type: application/octet-stream`). Every case here proves one
// obligation this module carries and no DAV code does: no credential is ever
// attached, https is enforced before and after any redirect, and the body is
// size-capped by BOTH a declared Content-Length and a streamed running total,
// because the real feed shipped no reliable Content-Length at all.
//
// No network and no real credentials. The global `fetch` these tests stub is
// the one `fetchSubscriptionFeed` closes over, the same seam
// `test/dav-transport.test.ts` uses for `createDavFetch`.

import { afterEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import { DavConnectError } from "../src/dav/errors";
import {
  MAX_SUBSCRIPTION_FEED_BYTES,
  fetchSubscriptionFeed,
} from "../src/feed/subscription-feed";

const FEED_URL = "https://sm-cal.apple.com/cal/5fdfa7c8d27442fd8ee139d66429fc4d";

interface RecordedCall {
  url: string;
  init: RequestInit | undefined;
}

/** A stub `fetch` that records every call it received. */
function fetchSpy(
  respond: (url: string) => Response | Promise<never>,
): { fetch: typeof globalThis.fetch; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    calls.push({ url, init });
    return respond(url);
  }) as typeof globalThis.fetch;
  return { fetch, calls };
}

/**
 * A duck-typed `Response`, built directly rather than through the `Response`
 * constructor. A directly-constructed `Response` reports an empty `.url` —
 * correct for that constructor's own contract, but this module reads `.url`
 * to check the scheme survived any redirect, so the fixture has to be able to
 * say what a real fetch would have reported.
 */
function fakeResponse(options: {
  status?: number;
  url?: string;
  headers?: HeadersInit;
  body?: ReadableStream<Uint8Array> | null;
}): Response {
  const status = options.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    url: options.url ?? FEED_URL,
    headers: new Headers(options.headers),
    body: options.body ?? null,
  } as unknown as Response;
}

/** A `ReadableStream` that yields the given chunks one `pull` at a time. */
function streamOf(
  chunks: Uint8Array[],
  onCancel?: () => void,
): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index]);
        index += 1;
      } else {
        controller.close();
      }
    },
    cancel() {
      onCancel?.();
    },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchSubscriptionFeed — no credential, ever", () => {
  it("issues a plain GET with no Authorization header, and no init object at all", async () => {
    const bodyText = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    const encoded = new TextEncoder().encode(bodyText);
    const { fetch, calls } = fetchSpy(() =>
      fakeResponse({ status: 200, body: streamOf([encoded]) }),
    );
    vi.stubGlobal("fetch", fetch);

    const text = await fetchSubscriptionFeed(FEED_URL);

    expect(text).toBe(bodyText);
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toBe(FEED_URL);
    // No init object at all -- not an empty one -- is the strongest form of
    // "no header was set": there is no object here for a header to ride in.
    expect(calls[0]!.init).toBeUndefined();
  });
});

describe("fetchSubscriptionFeed — scheme enforcement", () => {
  it("refuses a non-https url before any network call", async () => {
    const { fetch, calls } = fetchSpy(() => fakeResponse({ status: 200 }));
    vi.stubGlobal("fetch", fetch);

    await expect(
      fetchSubscriptionFeed("http://sm-cal.apple.com/cal/x"),
    ).rejects.toBeInstanceOf(DavConnectError);
    expect(calls.length).toBe(0);
  });

  it("refuses a url that does not parse at all, before any network call", async () => {
    const { fetch, calls } = fetchSpy(() => fakeResponse({ status: 200 }));
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed("not a url")).rejects.toBeInstanceOf(
      DavConnectError,
    );
    expect(calls.length).toBe(0);
  });

  it("refuses when the final url, after any redirect, is not https", async () => {
    // The requested url is https; the response's own `.url` -- what a real
    // fetch reports the request actually landed on -- is not. Redirects are
    // followed normally here (unlike davFetch's forced manual policy), so
    // only the FINAL scheme is checked.
    const { fetch } = fetchSpy(() =>
      fakeResponse({ status: 200, url: "http://sm-cal.apple.com/cal/x" }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
  });
});

describe("fetchSubscriptionFeed — transport failures", () => {
  it("refuses a non-2xx response", async () => {
    const { fetch } = fetchSpy(() => fakeResponse({ status: 404 }));
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
  });

  it("refuses a network throw from fetch, and never reads the caught value", async () => {
    // The message below is deliberately shaped like something worth hiding --
    // a resolved host and a fragment that reads like a credential -- so a
    // regression that DID read the caught value would show up here rather
    // than in a bland fixture that could not tell the difference.
    const fetch = (async () => {
      throw new Error(
        "GET https://sm-cal.apple.com/cal/x failed: password=hunter2",
      );
    }) as typeof globalThis.fetch;
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toMatchObject({
      name: "DavConnectError",
      message: "dav-transport-failed",
    });
  });

  it("refuses when the response carries no body at all", async () => {
    const { fetch } = fetchSpy(() => fakeResponse({ status: 200, body: null }));
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
  });
});

describe("fetchSubscriptionFeed — the size cap, both halves", () => {
  it("refuses before the body is read when Content-Length already exceeds the cap", async () => {
    const explodingBody = {
      getReader() {
        throw new Error(
          "must not be called: Content-Length already refused this response",
        );
      },
    } as unknown as ReadableStream<Uint8Array>;
    const { fetch } = fetchSpy(() =>
      fakeResponse({
        status: 200,
        headers: { "content-length": String(MAX_SUBSCRIPTION_FEED_BYTES + 1) },
        body: explodingBody,
      }),
    );
    vi.stubGlobal("fetch", fetch);

    // If the implementation regressed to consuming the body before checking
    // Content-Length, the exploding reader above would throw a plain Error
    // rather than a DavConnectError, and this assertion would fail with a
    // different error than the one it expects.
    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
  });

  it("refuses mid-read when the streamed total exceeds the cap, with no Content-Length at all", async () => {
    // The real feed observed live carried content-type
    // application/octet-stream with no reliable size guarantee -- this is
    // the shape a Content-Length check alone cannot catch.
    const chunkSize = 1024 * 1024; // 1 MiB
    const chunks = [
      new Uint8Array(chunkSize),
      new Uint8Array(chunkSize),
      new Uint8Array(chunkSize), // 3 MiB total, over the 2 MiB cap
    ];
    let cancelled = false;
    const body = streamOf(chunks, () => {
      cancelled = true;
    });
    const { fetch } = fetchSpy(() => fakeResponse({ status: 200, body }));
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
    expect(cancelled).toBe(true);
  });

  it("refuses mid-read when a present Content-Length UNDERSTATES the real size", async () => {
    const chunkSize = 1024 * 1024;
    const chunks = [
      new Uint8Array(chunkSize),
      new Uint8Array(chunkSize),
      new Uint8Array(chunkSize),
    ];
    const body = streamOf(chunks);
    const { fetch } = fetchSpy(() =>
      fakeResponse({
        status: 200,
        // Understates the real 3 MiB stream, so only the streamed check below
        // can catch it.
        headers: { "content-length": "100" },
        body,
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(fetchSubscriptionFeed(FEED_URL)).rejects.toBeInstanceOf(
      DavConnectError,
    );
  });
});

describe("fetchSubscriptionFeed — the success path", () => {
  it("returns a well-formed https response under the cap as a string", async () => {
    const bodyText =
      "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    const encoded = new TextEncoder().encode(bodyText);
    const { fetch } = fetchSpy(() =>
      fakeResponse({
        status: 200,
        headers: { "content-length": String(encoded.byteLength) },
        body: streamOf([encoded]),
      }),
    );
    vi.stubGlobal("fetch", fetch);

    const text = await fetchSubscriptionFeed(FEED_URL);
    expect(text).toBe(bodyText);
  });
});
