// Which client a request's grant belongs to (Phase 26, D-35).
//
// The key and the field are proved against the REAL library: a client and a
// grant are created through the installed provider's own helpers, in the
// pool's own OAuth store, and the grant id is found through the library's own
// listing. A reader that guessed the key or the field would answer null here
// and fail, rather than pass against a record this file wrote by hand.
//
// The store the reader is handed is wrapped in a recorder, so each case can
// count the reads it made. Several cases assert that NO read was made: a reader
// that reads the store for a header it should have refused is a reader that
// builds keys from anything a caller sends.

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { grantClientOf } from "../src/mcp/grant-client";

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// test/lease-coverage.test.ts carries the same comment.
const DOOR_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/api-handler.ts",
  { query: "?raw", import: "default", eager: true },
);
const DOOR_SOURCE: string = Object.values(DOOR_SOURCE_GLOB)[0] ?? "";

// @ts-expect-error — as above.
const READER_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/grant-client.ts",
  { query: "?raw", import: "default", eager: true },
);
const READER_SOURCE: string = Object.values(READER_SOURCE_GLOB)[0] ?? "";

/** The smallest options object the library's helpers accept. */
function minimalOptions() {
  const handler = {
    fetch() {
      return new Response(null, { status: 404 });
    },
  };
  return {
    apiRoute: "/mcp",
    apiHandler: handler,
    defaultHandler: handler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
  };
}

/** The library's helpers over the pool's own OAuth store. */
function helpers() {
  return getOAuthApi(minimalOptions() as never, { OAUTH_KV: env.OAUTH_KV });
}

const REDIRECT = "https://client.example.invalid/callback";

/** A PKCE challenge the library accepts in shape; no code is ever redeemed here. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

/**
 * A client and a grant made through the library itself, for a fresh user id.
 * Answers the user id, the grant id (from the library's own listing), and the
 * client id.
 */
async function libraryGrant(): Promise<{ userId: string; grantId: string; clientId: string }> {
  const api = helpers();
  const client = await api.createClient({
    redirectUris: [REDIRECT],
    clientName: "Ordinary client",
    tokenEndpointAuthMethod: "none",
  });
  // A 64-hex user id, the shape this server's user ids have.
  const userId = [...crypto.getRandomValues(new Uint8Array(32))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  await api.completeAuthorization({
    request: {
      responseType: "code",
      clientId: client.clientId,
      redirectUri: REDIRECT,
      scope: ["mcp"],
      state: "state",
      codeChallenge: CODE_CHALLENGE,
      codeChallengeMethod: "S256",
    },
    userId,
    metadata: { clientName: "Ordinary client" },
    scope: ["mcp"],
    props: { marker: "not read by this reader" },
  });
  const listed = await api.listUserGrants(userId);
  expect(listed.items).toHaveLength(1);
  const grantId = listed.items[0]!.id;
  return { userId, grantId, clientId: client.clientId };
}

/** The pool's OAuth store, with every read counted. */
function recordingStore(overrides: { get?: () => Promise<unknown> } = {}) {
  const reads: string[] = [];
  const store = {
    async get(key: string, options?: unknown): Promise<unknown> {
      reads.push(key);
      if (overrides.get) return overrides.get();
      return env.OAUTH_KV.get(key, options as never);
    },
  };
  return { store: store as unknown as KVNamespace, reads };
}

/** A request carrying exactly this Authorization header, or none. */
function requestWith(authorization?: string): Request {
  const headers = new Headers();
  if (authorization !== undefined) headers.set("Authorization", authorization);
  return new Request("https://example.invalid/mcp", { method: "POST", headers });
}

/** A secret segment that must never reach the store. */
const SECRET = "the-secret-segment-never-read";

describe("the grant's client, read against the real library (D-35)", () => {
  it("a grant the library created answers that grant's client id", async () => {
    const { userId, grantId, clientId } = await libraryGrant();
    const { store, reads } = recordingStore();

    const client = await grantClientOf(requestWith(`Bearer ${userId}:${grantId}:${SECRET}`), store)();

    expect(client).toBe(clientId);
    expect(reads).toHaveLength(1);
    // The secret segment is not part of anything the store was asked for.
    expect(reads.join("")).not.toContain(SECRET);
  });

  it("a header naming a grant that does not exist answers null", async () => {
    const { userId } = await libraryGrant();
    const { store, reads } = recordingStore();

    const client = await grantClientOf(
      requestWith(`Bearer ${userId}:NoSuchGrant0000:${SECRET}`),
      store,
    )();

    expect(client).toBeNull();
    expect(reads).toHaveLength(1);
  });

  it("a record without a string client id answers null", async () => {
    const { store } = recordingStore({ get: async () => ({ clientId: 42 }) });

    expect(await grantClientOf(requestWith(`Bearer abc:def:${SECRET}`), store)()).toBeNull();
  });

  it("a record with an empty client id answers null", async () => {
    const { store } = recordingStore({ get: async () => ({ clientId: "" }) });

    expect(await grantClientOf(requestWith(`Bearer abc:def:${SECRET}`), store)()).toBeNull();
  });

  it("a store read that rejects answers null, and nothing is thrown", async () => {
    const { store, reads } = recordingStore({
      get: async () => Promise.reject(new Error("store down")),
    });

    await expect(
      grantClientOf(requestWith(`Bearer abc:def:${SECRET}`), store)(),
    ).resolves.toBeNull();
    expect(reads).toHaveLength(1);
  });
});

describe("a header the reader refuses reads nothing", () => {
  const refused: ReadonlyArray<{ name: string; header?: string }> = [
    { name: "no Authorization header" },
    { name: "a Basic scheme", header: "Basic dXNlcjpwYXNz" },
    { name: "a lower-case scheme", header: `bearer abc:def:${SECRET}` },
    { name: "an empty bearer token", header: "Bearer " },
    { name: "two segments", header: "Bearer abc:def" },
    { name: "four segments", header: `Bearer abc:def:${SECRET}:extra` },
    { name: "an empty user segment", header: `Bearer :def:${SECRET}` },
    { name: "an empty grant segment", header: `Bearer abc::${SECRET}` },
    { name: "an empty secret segment", header: "Bearer abc:def:" },
    { name: "a slash in the user segment", header: `Bearer ab/c:def:${SECRET}` },
    { name: "a space in the grant segment", header: `Bearer abc:d ef:${SECRET}` },
    { name: "a key-shaped grant segment", header: `Bearer abc:def*:${SECRET}` },
    { name: "an over-long user segment", header: `Bearer ${"a".repeat(129)}:def:${SECRET}` },
  ];

  for (const { name, header } of refused) {
    it(`${name}: null, and no store read`, async () => {
      const { store, reads } = recordingStore();

      expect(await grantClientOf(requestWith(header), store)()).toBeNull();
      expect(reads).toEqual([]);
    });
  }
});

describe("the reader is lazy and memoized", () => {
  it("building it reads nothing", async () => {
    const { store, reads } = recordingStore();

    grantClientOf(requestWith(`Bearer abc:def:${SECRET}`), store);

    // Give any stray promise a chance to run.
    await new Promise((settle) => setTimeout(settle, 5));
    expect(reads).toEqual([]);
  });

  it("called twice in one request, it reads the store once and answers the same", async () => {
    const { userId, grantId, clientId } = await libraryGrant();
    const { store, reads } = recordingStore();
    const reader = grantClientOf(requestWith(`Bearer ${userId}:${grantId}:${SECRET}`), store);

    const first = await reader();
    const second = await reader();

    expect(first).toBe(clientId);
    expect(second).toBe(clientId);
    expect(reads).toHaveLength(1);
  });
});

describe("the door passes the reader and still does not await (text probes)", () => {
  const strip = (source: string): string =>
    source
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
      .join("\n");

  it("reads the real sources", () => {
    expect(DOOR_SOURCE).toContain("export function createMcpApiHandler(");
    expect(READER_SOURCE).toContain("export function grantClientOf(");
  });

  it("createMcpApiHandler's fetch passes grantClientOf(request, env.OAUTH_KV) to buildRequestHandler", () => {
    const code = strip(DOOR_SOURCE);
    const body = code.slice(code.indexOf("export function createMcpApiHandler("));

    expect(body).toMatch(
      /buildRequestHandler\([^;]*grantClientOf\(\s*request\s*,\s*env\.OAUTH_KV\s*\)/,
    );
    // The reader is built once, at the door, and nowhere else in the file.
    expect((code.match(/grantClientOf\(/g) ?? []).length).toBe(1);
  });

  it("the door's fetch contains no await", () => {
    const code = strip(DOOR_SOURCE);
    const start = code.indexOf("export function createMcpApiHandler(");
    const end = code.indexOf("export const mcpApiHandler");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    expect(code.slice(start, end)).not.toMatch(/\bawait\b/);
  });

  it("the reader logs nothing and reads no caught value", () => {
    const code = strip(READER_SOURCE);

    expect(code).not.toMatch(/console\./);
    expect(code).not.toMatch(/\.message\b|\.stack\b/);
    // `catch {` with no binding: nothing is caught into a name.
    expect(code).not.toMatch(/catch\s*\(/);
  });
});
