// The ordering proof (FND-02, D-03, criterion 1).
//
// "Unauthenticated requests are rejected before any tool handler runs" is
// currently a property of @cloudflare/workers-oauth-provider rather than of
// project code: the provider owns routing and validates the bearer token before
// it ever calls the API handler. That is a good place for the property to live,
// and exactly why it needs a repo-owned regression guard — nothing in this
// repository would notice if a future refactor moved the handler wiring, and a
// 401 alone never establishes ordering. A handler could dispatch, run, and have
// its result discarded in favour of a 401, and the status code would look
// identical from outside.
//
// So every rejection case asserts two things: the status, and that a tool
// registered into the same server factory recorded no invocation.
//
// The first test in this file is the positive control, and the rest are worth
// nothing without it: a canary that can never fire reports "never invoked"
// whatever the gate does. Every case below sends the SAME fully well-formed
// request that the positive control proves does reach the tool. The only
// difference is the Authorization header. That is what makes "still false" mean
// "the gate stopped it" rather than "the request was malformed anyway".

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { entryEnv } from "./fixtures/bound-secrets";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import worker, { CANARY_TOOL_NAME } from "./fixtures/worker-with-canary";

const HOSTNAME = DEPLOYED_HOSTNAME;
const ORIGIN = `https://${HOSTNAME}`;

/** Drive the test-only Worker through its real fetch handler. */
async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/**
 * A fully well-formed 2026-07-28 `tools/call` for the recording tool.
 *
 * Every header and envelope field the revision requires is present, so nothing
 * downstream of the gate has an excuse to reject it. `extraHeaders` is the only
 * thing that varies between cases.
 */
function toolCall(path: string, extraHeaders: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
      "Mcp-Method": "tools/call",
      "Mcp-Name": CANARY_TOOL_NAME,
      ...extraHeaders,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: CANARY_TOOL_NAME,
        arguments: {},
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/**
 * The shape Claude Desktop was observed sending: a claim-less `tools/call`.
 *
 * No `_meta` protocol-version envelope, no `MCP-Protocol-Version` header, and
 * none of the `Mcp-*` routing headers the 2026-07-28 revision adds — a bare
 * 2025-era JSON-RPC POST and nothing more. Captured live against production
 * with `wrangler tail`, user-agent `Claude-User`.
 *
 * This is deliberately a second helper rather than an option on `toolCall`.
 * What distinguishes the two is the ABSENCE of fields, and an absence expressed
 * as a flag on a builder is one `...spread` away from silently reappearing.
 */
function claimlessToolCall(
  path: string,
  extraHeaders: Record<string, string> = {},
): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
      ...extraHeaders,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: CANARY_TOOL_NAME, arguments: {} },
    }),
  });
}

async function canaryWasInvoked(): Promise<boolean> {
  const response = await call(new Request(`${ORIGIN}/__canary`));
  const body = (await response.json()) as { invoked: boolean };
  return body.invoked;
}

beforeEach(async () => {
  // Reset between cases, so a passing first case cannot mask a failing second.
  await call(new Request(`${ORIGIN}/__canary/reset`, { method: "POST" }));
  expect(await canaryWasInvoked()).toBe(false);
});

describe("the canary can actually fire", () => {
  it("records its own invocation when the tool layer is genuinely reached", async () => {
    // Straight to the MCP handler, gate deliberately stepped around. Without
    // this passing, every assertion below is vacuous.
    const response = await call(toolCall("/__canary/dispatch"));

    expect(response.status).toBe(200);
    expect(await canaryWasInvoked()).toBe(true);
  });
});

describe("the auth gate runs before dispatch", () => {
  it("rejects a tools/call with no Authorization header, and the tool never runs", async () => {
    const response = await call(toolCall("/mcp"));

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toMatch(/^Bearer/);

    // The assertion this whole file exists for.
    expect(
      await canaryWasInvoked(),
      "the tool layer was reached on an unauthenticated request",
    ).toBe(false);
  });

  it("rejects a syntactically valid but bogus bearer token, and the tool never runs", async () => {
    // A header-absent-only test would still pass if the malformed-token path
    // dispatched first and validated afterwards. This is that path.
    const response = await call(
      toolCall("/mcp", { authorization: "Bearer not-a-real-token-but-well-formed" }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toMatch(/^Bearer/);
    expect(
      await canaryWasInvoked(),
      "the tool layer was reached with an invalid bearer token",
    ).toBe(false);
  });

  it("rejects a token shaped like a real one, and the tool never runs", async () => {
    // The provider's tokens are colon-delimited. A token that parses but does
    // not resolve exercises the lookup path rather than the parse path, and both
    // must reject before dispatch.
    const response = await call(
      toolCall("/mcp", {
        authorization: "Bearer user0000000000:grant0000000000:secret0000000000",
      }),
    );

    expect(response.status).toBe(401);
    expect(await canaryWasInvoked()).toBe(false);
  });
});

describe("the compatibility lane can actually fire", () => {
  it("dispatches a claim-less tools/call to the tool layer", async () => {
    // The positive control for every claim-less case below, and the one case in
    // this file that fails against the pre-fix handler options: with the lane
    // disabled, this exact request was classified legacy, found no legacy
    // handler, and was answered 400 with an unsupported-protocol-version error
    // by the strict path — never reaching a tool. A 200 here is only meaningful
    // together with the flag, because the strict path's 400 and a served
    // request are both "a response".
    const response = await call(claimlessToolCall("/__canary/dispatch"));

    expect(response.status).toBe(200);

    // The lane answers over SSE and the tool runs as the stream is pulled.
    // Reading the flag without draining first reads it before the tool has run,
    // which reports a false negative on a working lane.
    await response.text();

    expect(
      await canaryWasInvoked(),
      "a claim-less tools/call did not reach the tool layer",
    ).toBe(true);
  });
});

describe("the compatibility lane sits behind the same gate", () => {
  it("rejects a claim-less tools/call with no Authorization header, and the tool never runs", async () => {
    // T-Q-01. Enabling a second serving lane must not open a second way in.
    // This sends the SAME request the control above proves does reach the tool,
    // so "still false" means the gate stopped it rather than the lane refusing
    // a request it never would have served. Pre-fix this case was unwritable in
    // any meaningful form: the request could not reach a tool even with the
    // gate stepped around, so the canary assertion was vacuous by construction.
    const response = await call(claimlessToolCall("/mcp"));

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toMatch(/^Bearer/);
    expect(
      await canaryWasInvoked(),
      "the compatibility lane reached the tool layer unauthenticated",
    ).toBe(false);
  });

  it("rejects a claim-less tools/call with a bogus bearer token, and the tool never runs", async () => {
    // The lookup path rather than the header-absent path, on the new lane. A
    // header-absent-only test would still pass if a malformed-token request
    // dispatched first and validated afterwards.
    const response = await call(
      claimlessToolCall("/mcp", {
        authorization: "Bearer not-a-real-token-but-well-formed",
      }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toMatch(/^Bearer/);
    expect(
      await canaryWasInvoked(),
      "the compatibility lane reached the tool layer with an invalid bearer token",
    ).toBe(false);
  });
});

describe("the challenge points somewhere real", () => {
  it("serves the protected-resource metadata the 401 refers clients to", async () => {
    // The WWW-Authenticate challenge names this document. A challenge that
    // referenced a 404 would be a broken flow that still looked like a correct
    // rejection from the status code alone.
    const response = await call(
      new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`),
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { resource?: string };
    expect(body.resource).toBe(`${ORIGIN}/mcp`);
  });

  it("names that document in the challenge it sends", async () => {
    const response = await call(toolCall("/mcp"));
    expect(response.headers.get("WWW-Authenticate")).toContain(
      "/.well-known/oauth-protected-resource/mcp",
    );
  });
});
