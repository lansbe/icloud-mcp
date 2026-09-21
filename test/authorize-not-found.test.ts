// The unknown-path 404 says where the client should have gone.
//
// This exists because of a real failure, not a hypothetical one. The user
// pointed Claude Desktop at the bare origin with no path. OAuth discovery and
// the entire authorization ceremony SUCCEEDED there — the metadata documents
// and /authorize, /oauth/token and /oauth/register are all root-level — and
// then the MCP POST hit `/`, fell through to this handler, and got a bare 404
// whose body said "Not found". From the client's side that is indistinguishable
// from a server that is down, a server that never existed, and a server that
// refuses this account. The one thing it does not resemble is the truth: the
// right server, reached at the wrong path, one segment away.
//
// Every case here fails against the pre-fix body. Pre-fix there was no exported
// helper at all, so the derivation cases could not be written; and the body was
// a fixed two-word string, so every assertion about naming an endpoint, about
// content-type, and about the origin varying with the request failed outright.
//
// The origin cases are the ones worth guarding. It would be simpler to write
// the production hostname in as a constant, and it would pass every other case
// in this file. The different-origin case is what stops that: the served URL is
// derived from the request's own origin, which is why the auth module needs no
// dependency on the MCP module for a display string, and why this body stays
// correct if the hostname ever changes.

import { describe, expect, it } from "vitest";
import {
  UNCONFIGURED_BODY,
  loginHandler,
  notFoundBody,
} from "../src/auth/login-handler";
import type { Env, LoginGateSecret } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/**
 * An env carrying nothing at all.
 *
 * The 404 returns before any binding is touched, so an empty env is not a
 * shortcut — it is a second, structural assertion that the unknown-path refusal
 * reads no configuration, consults no store, and cannot depend on one.
 */
function emptyEnv(): Env & LoginGateSecret {
  return {} as unknown as Env & LoginGateSecret;
}

function get(url: string): Promise<Response> {
  return loginHandler.fetch(new Request(url), emptyEnv());
}

describe("an unknown path names the MCP endpoint", () => {
  it("answers the bare origin — the path the client was actually pointed at", async () => {
    const response = await get(`${ORIGIN}/`);

    expect(response.status).toBe(404);
    // Asserted against the value the handler serves, exactly as the
    // UNCONFIGURED_BODY cases do, so a reworded sentence cannot pass silently
    // while the test keeps checking a stale copy of it.
    expect(await response.text()).toBe(notFoundBody(ORIGIN));
  });

  it("answers a wrong guess and a near miss with the same body", async () => {
    // The failure mode is "the client was pointed somewhere wrong", and `/sse`
    // is the specific wrong guess an MCP client makes. `/mcp/` is the near miss
    // — one trailing slash from correct, and the case most likely to leave
    // someone convinced the endpoint does not exist. A fix scoped to `/` alone
    // would answer neither.
    for (const path of ["/sse", "/mcp/"]) {
      const response = await get(`${ORIGIN}${path}`);

      expect(response.status).toBe(404);
      expect(await response.text()).toBe(notFoundBody(ORIGIN));
    }
  });

  it("puts the absolute endpoint URL in the body", async () => {
    // Pins the load-bearing part — the URL the reader has to act on — while
    // leaving every other word free to change without breaking this file.
    const body = await (await get(`${ORIGIN}/`)).text();

    expect(body).toContain(`${ORIGIN}/mcp`);
  });

  it("serves it as plain text", async () => {
    // text/plain is not incidental: it is what makes the reflected origin below
    // inert. Nothing here is interpreted as markup by anything that reads it.
    const response = await get(`${ORIGIN}/`);

    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  });
});

describe("the endpoint URL is derived from the request", () => {
  it("names the requesting origin, not a hardcoded hostname", async () => {
    // THE case that fails if someone simplifies the helper back to a fixed
    // string. Every other assertion in this file would still pass against a
    // hardcoded production URL; this one would not.
    const response = await get("https://example.test/some/wrong/path");

    const body = await response.text();
    expect(body).toContain("https://example.test/mcp");
    expect(body).not.toContain(DEPLOYED_HOSTNAME);
  });

  it("builds the URL from the origin it is given", async () => {
    // The helper in isolation, so a future reader can see the contract without
    // reconstructing it from a Response.
    expect(notFoundBody("https://example.test")).toContain(
      "https://example.test/mcp",
    );
    expect(notFoundBody(ORIGIN)).toContain(`${ORIGIN}/mcp`);
  });
});

describe("/authorize is unaffected", () => {
  it("does not receive the unknown-path body", async () => {
    // The 404 belongs strictly outside the /authorize branch. If the new body
    // had been placed above the pathname check, /authorize would answer it too
    // and the login surface would disappear behind a signpost pointing at the
    // MCP endpoint.
    //
    // Since Phase 11 the 503 this drives comes from an absent ALLOW LIST rather
    // than an absent shared secret — the gate in that position changed subject,
    // not position. What this case is about did not change at all: it is here
    // to show /authorize answers something OTHER than the unknown-path body.
    const response = await loginHandler.fetch(
      new Request(`${ORIGIN}/authorize?response_type=code&client_id=abc`),
      { ALLOWED_APPLE_IDS: undefined } as unknown as Env & LoginGateSecret,
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
  });
});
