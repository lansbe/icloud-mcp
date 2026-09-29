// The download route, attacked (Phase 29.1, plan 06).
//
// The tracer in test/save-tracer.test.ts proves the happy path end to end. This
// file proves the route holds when it is poked at: every bad link gets one
// answer, nothing but a GET spends a link, a copy never outlives an expired or
// abandoned download, and a stranger's bytes are never shown as a page.
//
// Most cases drive `handleSaveDownload` directly, with an execution context of
// their own, so the test can wait for the delete that runs after the answer.
// A few go through `SELF`, where the real Worker entry matters.
//
// Copies are made with the real bucket helpers and links with the real seal.
// Each case uses its own random user segment, so no case sees another's copies.
// This file stores nothing outside the pool, prints nothing and reports nothing.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { SAVE_ROUTE_PATH, mintSaveLink, spentMarkKey } from "../src/save/link";
import { handleSaveDownload } from "../src/save/route";
import { putSaved } from "../src/staging/r2";
import { entryEnv } from "./fixtures/bound-secrets";

const ENCODER = new TextEncoder();

/** A fresh 64-hex user segment, so each case has a prefix of its own. */
function freshUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A base64url string of `count` random bytes, with no padding. */
function randomBase64Url(count: number): string {
  let binary = "";
  for (const byte of crypto.getRandomValues(new Uint8Array(count))) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A saved copy and its link. */
interface Saved {
  url: string;
  token: string;
  userId: string;
  key: string;
}

/** Store `bytes` as a saved copy and mint its link, as the tool does. */
async function saveCopy(
  bytes: Uint8Array,
  options: { nowMs?: number; env?: Env } = {},
): Promise<Saved> {
  const env = options.env ?? entryEnv();
  const nowMs = options.nowMs ?? Date.now();
  const userId = freshUserId();
  const key = await putSaved(env, userId, bytes, nowMs);
  expect(key).not.toBeNull();
  const link = await mintSaveLink(env, userId, key!, bytes.byteLength, nowMs);
  expect(link).not.toBeNull();
  const token = link!.url.slice(link!.url.indexOf(SAVE_ROUTE_PATH) + SAVE_ROUTE_PATH.length);
  return { url: link!.url, token, userId, key: key! };
}

/** A URL on this host for a raw path. */
function urlFor(path: string): string {
  return `https://example.test${path}`;
}

/**
 * One request to the route, with its execution context.
 *
 * Each request comes from a fresh address unless the case names its headers,
 * so the brake's shared no-address budget is never spent by accident across
 * this suite. A case that wants no address header passes `headers: {}`.
 */
async function call(
  url: string,
  options: { method?: string; env?: Env; headers?: Record<string, string> } = {},
): Promise<{ response: Response; ctx: ExecutionContext }> {
  const ctx = createExecutionContext();
  const headers = options.headers ?? { "cf-connecting-ip": freshAddress() };
  const request = new Request(url, { method: options.method ?? "GET", headers });
  const response = await handleSaveDownload(request, options.env ?? entryEnv(), ctx);
  return { response, ctx };
}

/** One request, read to the end, and the context settled. */
async function settle(
  url: string,
  options: { method?: string; env?: Env; headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: [string, string][]; body: Uint8Array }> {
  const { response, ctx } = await call(url, options);
  const body = new Uint8Array(await response.arrayBuffer());
  await waitOnExecutionContext(ctx);
  return { status: response.status, headers: [...response.headers].sort(), body };
}

/** Whether a copy is still in the bucket. */
async function stored(key: string): Promise<boolean> {
  return (await entryEnv().ATTACHMENT_STAGING.head(key)) !== null;
}

/** Whether the spent mark for a token is written. */
async function spent(token: string): Promise<boolean> {
  return (await entryEnv().SAVE_LINK_KV.get(await spentMarkKey(token))) !== null;
}

/** The one refusal a bad link gets: status, headers and body, exactly. */
const GONE = { status: 410, headers: [["cache-control", "no-store"]], body: new Uint8Array(0) };

/** The six fixed download headers. */
const DOWNLOAD_HEADERS: [string, string][] = [
  ["cache-control", "no-store"],
  ["content-disposition", 'attachment; filename="download"'],
  ["content-security-policy", "sandbox; default-src 'none'"],
  ["content-type", "application/octet-stream"],
  ["referrer-policy", "no-referrer"],
  ["x-content-type-options", "nosniff"],
];

/** The small file most cases save. */
const SMALL = ENCODER.encode("a small attachment, 41 bytes long, exact.");

describe("every bad link gets one answer: an empty 410", () => {
  it("refuses malformed tokens, and a real link still downloads afterwards", async () => {
    const live = await saveCopy(SMALL);
    const real = live.token;

    const malformed = [
      ["too short", "A".repeat(63)],
      ["too long", "A".repeat(513)],
      ["a plus", `${real.slice(0, 100)}+${real.slice(101)}`],
      ["a slash", `${real.slice(0, 100)}/${real.slice(101)}`],
      ["an encoded slash", `${real.slice(0, 100)}%2F${real.slice(103)}`],
      ["a dot", `${real.slice(0, 100)}.${real.slice(101)}`],
      ["empty", ""],
      ["a trailing slash", `${real}/`],
      ["an extra segment", `${real}/more`],
      ["ten thousand characters", "A".repeat(10_000)],
    ] as const;

    for (const [, token] of malformed) {
      const answer = await settle(urlFor(`${SAVE_ROUTE_PATH}${token}`));
      expect(answer).toEqual(GONE);
    }

    // None of them spent the real link.
    expect(await spent(real)).toBe(false);
    const download = await settle(live.url);
    expect(download.status).toBe(200);
    expect(download.body).toEqual(SMALL);
  });

  it("refuses a malformed token without touching the mark store", async () => {
    // A store that throws on any use: a 410 rather than a 503 proves the shape
    // check ran first.
    const env = { ...entryEnv(), SAVE_LINK_KV: throwingStore("read") };
    const answer = await settle(urlFor(`${SAVE_ROUTE_PATH}${"A".repeat(10)}`), { env });
    expect(answer).toEqual(GONE);
  });

  it("refuses a well-formed token that does not unseal", async () => {
    const live = await saveCopy(SMALL);
    const middle = 120;
    const swapped = live.token[middle] === "A" ? "B" : "A";
    const oneCharChanged = `${live.token.slice(0, middle)}${swapped}${live.token.slice(middle + 1)}`;

    const otherKey = { ...entryEnv(), SAVE_LINK_SEAL_KEY: randomBase64Url(32) };
    const foreign = await saveCopy(SMALL, { env: otherKey });

    for (const token of [randomBase64Url(180), oneCharChanged, foreign.token]) {
      const answer = await settle(urlFor(`${SAVE_ROUTE_PATH}${token}`));
      expect(answer).toEqual(GONE);
    }
    // The real link is untouched by the edited copy of it.
    expect(await spent(live.token)).toBe(false);
  });

  it("refuses a second spelling of a real link, and spends nothing", async () => {
    // A token's last character can carry bits no byte uses. Setting one names
    // the same bytes, so it unseals, but it hashes to a different spent mark.
    // Find a size whose token has such a tail: its length is not a multiple of 4.
    let live: Saved | null = null;
    for (const size of [41, 141, 1041]) {
      const candidate = await saveCopy(new Uint8Array(size));
      if (candidate.token.length % 4 !== 0) {
        live = candidate;
        break;
      }
    }
    expect(live).not.toBeNull();
    const real = live!.token;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(real[real.length - 1]!);
    const other = `${real.slice(0, -1)}${alphabet[last ^ 1]}`;
    expect(other).not.toBe(real);

    expect(await settle(urlFor(`${SAVE_ROUTE_PATH}${other}`))).toEqual(GONE);
    expect(await spent(other)).toBe(false);
    expect(await spent(real)).toBe(false);

    // The one real spelling still downloads.
    expect((await settle(live!.url)).status).toBe(200);
  });

  it("refuses an expired link and deletes its copy", async () => {
    const old = await saveCopy(SMALL, { nowMs: Date.now() - 6 * 60 * 1000 });
    expect(await stored(old.key)).toBe(true);

    const answer = await settle(old.url);

    expect(answer).toEqual(GONE);
    expect(await stored(old.key)).toBe(false);
  });

  it("refuses a spent link", async () => {
    const live = await saveCopy(SMALL);
    expect((await settle(live.url)).status).toBe(200);
    expect(await settle(live.url)).toEqual(GONE);
  });

  it("refuses a second GET that starts while the first is still streaming", async () => {
    const live = await saveCopy(SMALL);
    const first = await call(live.url);
    expect(first.response.status).toBe(200);

    // The first body is not read yet, so its copy is still in the bucket.
    expect(await stored(live.key)).toBe(true);
    expect(await settle(live.url)).toEqual(GONE);

    expect(new Uint8Array(await first.response.arrayBuffer())).toEqual(SMALL);
    await waitOnExecutionContext(first.ctx);
    expect(await stored(live.key)).toBe(false);
  });

  it("refuses a live link whose copy is gone", async () => {
    const live = await saveCopy(SMALL);
    await entryEnv().ATTACHMENT_STAGING.delete(live.key);
    expect(await settle(live.url)).toEqual(GONE);
  });

  it("refuses every token when the seal key is not set", async () => {
    const live = await saveCopy(SMALL);
    const env = { ...entryEnv(), SAVE_LINK_SEAL_KEY: undefined };
    expect(await settle(live.url, { env })).toEqual(GONE);
    expect(await spent(live.token)).toBe(false);
  });

  it("gives the five causes byte-for-byte the same answer", async () => {
    const live = await saveCopy(SMALL);
    await settle(live.url);
    const spentUrl = live.url;
    const expired = await saveCopy(SMALL, { nowMs: Date.now() - 6 * 60 * 1000 });
    const missing = await saveCopy(SMALL);
    await entryEnv().ATTACHMENT_STAGING.delete(missing.key);

    const answers = [
      await settle(urlFor(`${SAVE_ROUTE_PATH}not-a-token`)),
      await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`)),
      await settle(expired.url),
      await settle(spentUrl),
      await settle(missing.url),
    ];
    for (const answer of answers) expect(answer).toEqual(GONE);
  });
});

describe("nothing but a GET spends a link", () => {
  it("answers 405 to six other methods, spends nothing, then a GET downloads", async () => {
    const live = await saveCopy(SMALL);

    for (const method of ["HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]) {
      const answer = await settle(live.url, { method });
      expect(answer).toEqual({
        status: 405,
        headers: [
          ["allow", "GET"],
          ["cache-control", "no-store"],
        ],
        body: new Uint8Array(0),
      });
      expect(await spent(live.token)).toBe(false);
    }

    const download = await settle(live.url);
    expect(download.status).toBe(200);
    expect(download.body).toEqual(SMALL);
  });

  it("answers a HEAD through the real Worker entry with 405, and spends nothing", async () => {
    const live = await saveCopy(SMALL);
    const response = await entryEnv().SELF.fetch(live.url, { method: "HEAD" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(await spent(live.token)).toBe(false);
  });
});

/** A mark store that throws on a read, or reads nothing and throws on a write. */
function throwingStore(which: "read" | "write"): KVNamespace {
  return {
    get: () => (which === "read" ? Promise.reject(new Error()) : Promise.resolve(null)),
    put: () => Promise.reject(new Error()),
  } as unknown as KVNamespace;
}

describe("a store failure serves nothing", () => {
  for (const which of ["read", "write"] as const) {
    it(`answers an empty 503 when the mark store's ${which} throws`, async () => {
      const live = await saveCopy(SMALL);
      const env = { ...entryEnv(), SAVE_LINK_KV: throwingStore(which) };
      const answer = await settle(live.url, { env });
      expect(answer).toEqual({
        status: 503,
        headers: [["cache-control", "no-store"]],
        body: new Uint8Array(0),
      });
    });
  }

  it("answers an empty 503 when the bucket's read throws", async () => {
    const live = await saveCopy(SMALL);
    const bucket = {
      get: () => Promise.reject(new Error()),
      delete: () => Promise.resolve(),
    } as unknown as R2Bucket;
    const env = { ...entryEnv(), ATTACHMENT_STAGING: bucket };
    const answer = await settle(live.url, { env });
    expect(answer).toEqual({
      status: 503,
      headers: [["cache-control", "no-store"]],
      body: new Uint8Array(0),
    });
  });
});

describe("a stranger's file is never shown as a page", () => {
  const hostile = {
    "an HTML page with a script": "<!doctype html><html><body><script>alert(1)</script></body></html>",
    "an SVG with a script":
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><circle r="4"/></svg>',
  };

  for (const [name, text] of Object.entries(hostile)) {
    it(`serves ${name} as a file to save, with every fixed header`, async () => {
      const bytes = ENCODER.encode(text);
      const live = await saveCopy(bytes);

      const answer = await settle(live.url);

      expect(answer.status).toBe(200);
      expect(answer.headers).toEqual(
        [...DOWNLOAD_HEADERS, ["content-length", String(bytes.byteLength)] as [string, string]].sort(),
      );
      expect(answer.body).toEqual(bytes);
    });
  }
});

describe("a copy never outlives its download", () => {
  it("deletes the copy when the download is cancelled after the first chunk", async () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const big = new Uint8Array(16 * bytes.byteLength);
    for (let i = 0; i < 16; i += 1) big.set(bytes, i * bytes.byteLength);
    const live = await saveCopy(big);

    const { response, ctx } = await call(live.url);
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const firstChunk = await reader.read();
    expect(firstChunk.done).toBe(false);
    await reader.cancel();

    await waitOnExecutionContext(ctx);
    expect(await stored(live.key)).toBe(false);
  });
});

/** A fresh documentation-range address, so each case has a budget of its own. */
function freshAddress(): string {
  const [a, b] = crypto.getRandomValues(new Uint16Array(2));
  return `2001:db8:${a!.toString(16)}:${b!.toString(16)}::1`;
}

/** The approved brake: this many requests a minute from one address. */
const BRAKE_LIMIT = 30;

/** The pool's real brake, wrapped so a case can see every key it was given. */
function recordingBrake(): { brake: RateLimit; keys: string[] } {
  const keys: string[] = [];
  const real = entryEnv().SAVE_IP_LIMITER;
  return {
    keys,
    brake: {
      limit: (options: RateLimitOptions) => {
        keys.push(options.key);
        return real.limit(options);
      },
    } as RateLimit,
  };
}

describe("the per-address brake", () => {
  it("answers the approved number of bad links a minute, then an empty 429", async () => {
    const headers = { "cf-connecting-ip": freshAddress() };
    for (let i = 0; i < BRAKE_LIMIT; i += 1) {
      const answer = await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { headers });
      expect(answer).toEqual(GONE);
    }
    const braked = await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { headers });
    expect(braked).toEqual({
      status: 429,
      headers: [["cache-control", "no-store"]],
      body: new Uint8Array(0),
    });
  });

  it("does not spend a live link it refuses, and another address then downloads it", async () => {
    const braked = { "cf-connecting-ip": freshAddress() };
    for (let i = 0; i < BRAKE_LIMIT; i += 1) {
      await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { headers: braked });
    }
    const live = await saveCopy(SMALL);

    expect((await settle(live.url, { headers: braked })).status).toBe(429);
    expect(await spent(live.token)).toBe(false);
    expect(await stored(live.key)).toBe(true);

    const download = await settle(live.url, { headers: { "cf-connecting-ip": freshAddress() } });
    expect(download.status).toBe(200);
    expect(download.body).toEqual(SMALL);
  });

  it("refuses malformed tokens before the brake, so they do not count", async () => {
    const { brake, keys } = recordingBrake();
    const env = { ...entryEnv(), SAVE_IP_LIMITER: brake };
    const headers = { "cf-connecting-ip": freshAddress() };
    for (let i = 0; i < BRAKE_LIMIT + 10; i += 1) {
      expect(await settle(urlFor(`${SAVE_ROUTE_PATH}bad.${i}`), { env, headers })).toEqual(GONE);
    }
    expect(keys).toEqual([]);

    // The address's budget is untouched: a well-formed request is still let through.
    expect(await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { env, headers })).toEqual(
      GONE,
    );
    expect(keys).toEqual([headers["cf-connecting-ip"]]);
  });

  it("brakes a request with no address header under one shared key", async () => {
    const { brake, keys } = recordingBrake();
    const env = { ...entryEnv(), SAVE_IP_LIMITER: brake };
    await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { env, headers: {} });
    await settle(urlFor(`${SAVE_ROUTE_PATH}${randomBase64Url(180)}`), { env, headers: {} });
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
    expect(keys[0]!.length).toBeGreaterThan(0);

    // And that key is braked, not waved through.
    const refusing = { limit: () => Promise.resolve({ success: false }) } as unknown as RateLimit;
    const live = await saveCopy(SMALL);
    const answer = await settle(live.url, {
      env: { ...entryEnv(), SAVE_IP_LIMITER: refusing },
      headers: {},
    });
    expect(answer.status).toBe(429);
    expect(await spent(live.token)).toBe(false);
  });
});
