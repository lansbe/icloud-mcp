// SPIKE-08, the half of it that is about THIS code rather than about the
// platform.
//
// **What a service binding actually is, because everything below follows from
// it.** A service binding does not go through the edge. There is no DNS lookup,
// no TLS handshake, no Cloudflare Access hop and no automatic Host rewriting by
// anything in front of the Worker. The caller constructs a `Request` object and
// the platform hands that exact object to the target Worker's fetch handler in
// the same process. So every property of such a call that could differ from an
// edge request is a property of what the CALLER built — which is precisely why
// each of them is testable here, with no deploy, by handing a caller-built
// `Request` straight to the real provider.
//
// That is what these cases do. `test/grant-lifetime.test.ts` already drives the
// real ceremony; this file reuses that machinery and then makes ONE call that
// looks like the one a Phase 27 alarm job would make: no Origin header, a host
// the caller had to construct itself, a bearer token the caller had to hold,
// and a fresh execution context carrying nothing.
//
// The two cases that carry most of the weight:
//
//   THE HOST CASE. `createMcpHandler` is given an explicit accepted-host list
//   (see `src/mcp/api-handler.ts`), so host validation is live on this custom
//   domain rather than skipped. A self-binding caller has to build the deployed
//   hostname itself, and nothing in a service binding does that for it. Proved
//   in both directions, so the finding is "the caller must use this exact
//   hostname" rather than "it worked once".
//
//   THE NO-IDENTITY CASE. A service binding supplies no props of its own. The
//   execution context arrives empty and the principal the handler acts for is
//   decrypted out of the grant behind the bearer token. So the binding is a
//   transport convenience and nothing else: the alarm job still has to present a
//   real access token for the user it is acting for, and the binding does not
//   shrink the credential-custody problem by one byte.
//
// Nothing here deploys anything, adds a route, adds a binding, or changes what
// is reachable. The Worker's reachable surface is unchanged and the question
// still gets answered.
//
// **No real Apple ID is ever authenticated (D-09).** Every sign-in below goes
// through `test/fixtures/worker-with-login-proof.ts`, whose proof is a counter.
// The address is under the reserved `.invalid` domain and the password is
// plainly fake.
//
// ---------------------------------------------------------------------------
// **The four hygiene rules from `test/grant-lifetime.test.ts` hold here too,
// and for the same reasons. Do not undo them.**
//
// 1. EVERY sign-in runs against a SPREAD COPY of `entryEnv()` whose two login
//    limiters are allow-all stubs. The pool's real per-target binding refuses a
//    fourth sign-in per address per minute, its windows are aligned to the wall
//    clock, and nothing clears them between files or between runs.
// 2. NEVER write onto the shared environment object. The `env-assignment` scan
//    rule refuses it, and the object is shared by every test in a file and every
//    request in an isolate.
// 3. Check keys by the grant id THIS case minted, never by a total. Sibling
//    files read and write the same namespaces at the same time.
// 4. CLEAN UP. Grants and client records no longer expire, so each case deletes
//    the `grant:` key, every `token:` key under it, and the client record it
//    registered, in a `finally`.
//
// The helpers below are COPIED from `test/grant-lifetime.test.ts` rather than
// imported. That is this repository's stated habit for test helpers, and that
// file's own header says so.
// ---------------------------------------------------------------------------

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { userIdOf } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/**
 * A hostname this deployment is not served on, and can never be.
 *
 * Under the reserved `.invalid` domain, following the habit the fake addresses
 * set: it can never resolve, so a case that reached the network by mistake
 * fails rather than talking to somebody.
 */
const WRONG_HOSTNAME = "not-this-worker.example.invalid";

/** The PKCE verifier this file redeems codes with. Copied, pair intact. */
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gFWFOEjXk";

/** `BASE64URL(SHA256(ASCII(CODE_VERIFIER)))`. Copied together with the above. */
const CODE_CHALLENGE = "90EpwHQr_xi9uDtjYyz5mq9Z4RekugHRqg5ijpXC3FQ";

const CLAUDE_WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

/** A rate-limit binding stub that always lets the request through (rule 1). */
function limiter(success: boolean) {
  return {
    async limit(_options: { key: string }): Promise<{ success: boolean }> {
      return { success };
    },
  };
}

/** The pool's environment with both limiters replaced, as a COPY (rule 2). */
function allowAllEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    ...entryEnv(),
    LOGIN_IP_LIMITER: limiter(true),
    LOGIN_ID_LIMITER: limiter(true),
    ...overrides,
  } as unknown as Env;
}

/**
 * What one delivery to the Worker's fetch handler produced.
 *
 * The props are read off the SAME context object either side of the call,
 * because the whole no-identity finding is the difference between the two: a
 * caller hands in a context carrying nothing, and whatever is on it afterwards
 * was put there by the provider out of the grant behind the token.
 */
type Delivery = {
  response: Response;
  propsBefore: unknown;
  propsAfter: unknown;
};

/**
 * Hand a caller-built Request straight to the Worker's fetch handler.
 *
 * This is the whole simulation, and it is a faithful one: a service binding
 * invokes `fetch(request, env, ctx)` on the target Worker in the same process,
 * with the Request the caller built and an execution context of its own. There
 * is no edge in between to add, rewrite or strip anything.
 */
async function deliver(request: Request, env: Env): Promise<Delivery> {
  const ctx = createExecutionContext();
  const propsBefore = ctx.props;
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return { response, propsBefore, propsAfter: ctx.props };
}

/** Drive the Worker's real fetch, keeping only the response. */
async function callWorker(request: Request, env: Env): Promise<Response> {
  return (await deliver(request, env)).response;
}

/** A registration request carrying exactly the metadata it is handed. */
function registerRequest(metadata: Record<string, unknown>): Request {
  return new Request(`${ORIGIN}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(metadata),
  });
}

/** The metadata a public client registers with, which is how Claude registers. */
function publicClientMetadata(
  clientName: string,
  redirectUri: string,
): Record<string, unknown> {
  return {
    client_name: clientName,
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}

/** Register a real public client through the real registration endpoint. */
async function register(
  env: Env,
  clientName: string,
  redirectUri: string,
): Promise<string> {
  const response = await callWorker(
    registerRequest(publicClientMetadata(clientName, redirectUri)),
    env,
  );

  expect(response.status).toBeLessThan(300);
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

/** An authorization query the real provider parses and re-validates. */
function authorizeQuery(
  clientId: string,
  redirectUri: string,
  state: string,
): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    state,
  }).toString();
}

/** A source key this invocation owns and nothing else in the repository uses. */
function freshSource(): string {
  return `test-source-${crypto.randomUUID()}`;
}

/** A sign-in POST at the real Worker, from a named source connection. */
function postFrom(source: string, appleId: string, query: string): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": source,
    },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
    }).toString(),
  });
}

/** Sign the listed address in, and hand back the authorization code. */
async function signIn(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string,
): Promise<string> {
  const response = await callWorker(
    postFrom(
      freshSource(),
      LISTED_APPLE_ID,
      authorizeQuery(clientId, redirectUri, state),
    ),
    env,
  );

  expect(response.status).toBe(302);
  const location = response.headers.get("location");
  expect(location).not.toBeNull();
  const code = new URL(location as string).searchParams.get("code");
  expect(code).not.toBeNull();
  return code as string;
}

/** Redeem an authorization code at the real token endpoint. */
async function exchangeCode(
  env: Env,
  clientId: string,
  redirectUri: string,
  code: string,
): Promise<string> {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    }),
    env,
  );

  // The body is read FIRST and named in the assertion, because a 400 here is
  // otherwise a bare status with no clue which of the exchange's inputs the
  // provider disliked.
  const text = await response.text();
  expect(`${response.status} ${text}`).toBe(`200 ${text}`);
  const body = JSON.parse(text) as { access_token: string };
  expect(typeof body.access_token).toBe("string");
  return body.access_token;
}

/** The grant id inside a token this library issued (rule 3). */
function grantIdOf(token: string): string {
  const segments = token.split(":");
  expect(segments).toHaveLength(3);
  return segments[1] as string;
}

/** Every key listed under a prefix. */
async function keysUnder(prefix: string): Promise<Array<{ name: string }>> {
  const listed = await entryEnv().OAUTH_KV.list({ prefix });
  return listed.keys;
}

/** Delete a grant and every access token under it (rule 4). Serial, always. */
async function forgetGrant(userId: string, grantId: string): Promise<void> {
  const kv = entryEnv().OAUTH_KV;
  for (const key of await keysUnder(`token:${userId}:${grantId}:`)) {
    await kv.delete(key.name);
  }
  await kv.delete(`grant:${userId}:${grantId}`);
}

/** Delete a client record this file registered (rule 4). */
async function forgetClient(clientId: string): Promise<void> {
  await entryEnv().OAUTH_KV.delete(`client:${clientId}`);
}

/** The listed address's user id, derived by the real function. Never hashed here. */
async function listedUserId(): Promise<string> {
  const userId = await userIdOf(LISTED_APPLE_ID);
  expect(userId).not.toBeNull();
  return userId as string;
}

/**
 * Mint one real grant, run a case against it, and clean up after it (rule 4).
 *
 * The whole ceremony: register a public client, sign the listed address in,
 * redeem the code. The access token handed to the body is one the real provider
 * issued and will validate — not a fabricated string, which would prove nothing
 * about the door.
 */
async function withGrant(
  name: string,
  body: (env: Env, accessToken: string) => Promise<void>,
): Promise<void> {
  const env = allowAllEnv();
  const userId = await listedUserId();
  const clientId = await register(env, name, CLAUDE_WEB_REDIRECT);
  let grantId: string | null = null;

  try {
    const code = await signIn(env, clientId, CLAUDE_WEB_REDIRECT, name);
    const accessToken = await exchangeCode(
      env,
      clientId,
      CLAUDE_WEB_REDIRECT,
      code,
    );
    grantId = grantIdOf(accessToken);
    await body(env, accessToken);
  } finally {
    if (grantId !== null) await forgetGrant(userId, grantId);
    await forgetClient(clientId);
  }
}

/**
 * The call a self service binding would make: a `tools/list` the CALLER built.
 *
 * Every varying part is a parameter, because every one of them is a thing the
 * caller has to get right and nothing upstream will fix for it. The Origin
 * header is absent on purpose and there is no way to add one — a binding call
 * originates in a Worker, not in a browsing context, so no Origin exists to
 * send. Case 1 asserts that absence rather than assuming it.
 */
function boundCall(options: {
  url?: string;
  host?: string | null;
  accessToken?: string | null;
}): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "Mcp-Method": "tools/list",
  };
  if (options.host !== null) {
    headers.host = options.host ?? DEPLOYED_HOSTNAME;
  }
  if (options.accessToken != null) {
    headers.authorization = `Bearer ${options.accessToken}`;
  }

  return new Request(options.url ?? `${ORIGIN}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/**
 * The JSON-RPC message in a response body, on either lane.
 *
 * Copied from `test/door.test.ts` by way of `test/grant-lifetime.test.ts`. The
 * modern lane answers with a JSON body; an event stream carries the message
 * after `data:`. Null when it holds neither.
 */
function rpcMessageIn(bodyText: string): Record<string, unknown> | null {
  const trimmed = bodyText.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  return null;
}

/** The tool names in a response body, or null when it carries no tool list. */
async function toolNamesIn(response: Response): Promise<string[] | null> {
  const message = rpcMessageIn(await response.text());
  if (message === null) return null;
  const tools = (message as { result?: { tools?: unknown } }).result?.tools;
  if (!Array.isArray(tools)) return null;
  return tools.map((tool) => (tool as { name?: unknown }).name as string);
}

describe("SPIKE-08: the request a self service binding would deliver", () => {
  // Titled so `-t "SPIKE-08"` matches. A name filter that matches nothing passes
  // SILENTLY, which would leave the spike looking covered while measuring
  // nothing.

  it("is served a tool list at the deployed hostname, with no Origin header", async () => {
    await withGrant("SPIKE-08 served", async (env, accessToken) => {
      const request = boundCall({ accessToken });

      // ASSERTED, not assumed. The whole case is about a request built outside
      // a browsing context; if some later change started adding an Origin here,
      // this case would silently stop being about that request.
      expect(request.headers.get("origin")).toBeNull();

      const { response } = await deliver(request, env);
      expect(response.status).toBe(200);
      const names = await toolNamesIn(response);
      expect(names).not.toBeNull();
      expect((names as string[]).length).toBeGreaterThan(0);
    });
  });

  it("is refused at any host other than the deployed one", async () => {
    await withGrant("SPIKE-08 wrong host", async (env, accessToken) => {
      // (a) The caller built the whole URL wrong — the shape of a Phase 27 job
      //     that was handed the wrong hostname. Two independent checks stand in
      //     its way and the token audience is the first: the token is bound to
      //     the resource `https://<deployed>/mcp`, and this request's resource
      //     server is not that.
      const wrongUrl = await deliver(
        boundCall({
          url: `https://${WRONG_HOSTNAME}/mcp`,
          host: WRONG_HOSTNAME,
          accessToken,
        }),
        env,
      );
      expect(wrongUrl.response.status).not.toBe(200);
      expect(await toolNamesIn(wrongUrl.response)).toBeNull();

      // (b) The URL is right and only the Host header is wrong, which isolates
      //     the handler's own host validation from the audience check above.
      //     This is the check that would be SKIPPED on a custom domain if the
      //     accepted-host list in src/mcp/api-handler.ts were ever dropped — so
      //     this assertion is what notices that.
      const wrongHost = await deliver(
        boundCall({ host: WRONG_HOSTNAME, accessToken }),
        env,
      );
      expect(wrongHost.response.status).not.toBe(200);
      expect(await toolNamesIn(wrongHost.response)).toBeNull();

      // And the positive control, so neither refusal above is vacuous: the same
      // call with the right host is served.
      const right = await deliver(boundCall({ accessToken }), env);
      expect(right.response.status).toBe(200);
      expect(await toolNamesIn(right.response)).not.toBeNull();
    });
  });

  it("is refused 401 when the caller carries no bearer token", async () => {
    // No grant is needed, and that is the point: there is nothing for a binding
    // to present. The refusal happens in the provider, before the door and
    // before any project code.
    const env = allowAllEnv();
    const { response } = await deliver(
      boundCall({ accessToken: null }),
      env,
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).not.toBeNull();
    expect(await toolNamesIn(response)).toBeNull();
  });

  it("gets its identity from the token, because the binding supplies none", async () => {
    await withGrant("SPIKE-08 identity", async (env, accessToken) => {
      const served = await deliver(boundCall({ accessToken }), env);

      // GOING IN: nothing. A service binding hands the target a fresh execution
      // context; it carries no props of its own, and there is no API by which a
      // caller could put an identity on one.
      expect(served.propsBefore).toBeUndefined();

      // COMING OUT: the grant. The provider decrypted it out of the record
      // behind the bearer token and put it here, which is the only reason the
      // door had a principal to act for.
      expect(served.propsAfter).not.toBeUndefined();
      expect((served.propsAfter as { appleId?: unknown }).appleId).toBe(
        LISTED_APPLE_ID,
      );

      // The same context, from the same call that was actually served.
      expect(served.response.status).toBe(200);

      // And the control that gives the first assertion its meaning: without a
      // token nothing is ever put on the context, so it is empty on both sides.
      // If a binding did supply identity of its own, THIS is where it would
      // show up.
      const unauthenticated = await deliver(
        boundCall({ accessToken: null }),
        env,
      );
      expect(unauthenticated.propsBefore).toBeUndefined();
      expect(unauthenticated.propsAfter).toBeUndefined();
    });
  });

  it("reaches the tool layer only at exactly the API path", async () => {
    await withGrant("SPIKE-08 path", async (env, accessToken) => {
      // (a) A path that does not begin with the API route never reaches the MCP
      //     handler at all — the provider routes it to the sign-in handler,
      //     which answers 404 for anything that is not its own path.
      const elsewhere = await deliver(
        boundCall({ url: `${ORIGIN}/tools/list`, accessToken }),
        env,
      );
      expect(elsewhere.response.status).toBe(404);
      expect(await toolNamesIn(elsewhere.response)).toBeNull();

      // (b) A NEAR MISS is the one worth knowing about, and it behaves
      //     differently from (a). The provider matches its API route by PREFIX,
      //     so this request DOES cross the authenticated boundary — the bearer
      //     token is validated and the grant is decrypted onto the context —
      //     and only then does the MCP handler, which matches its route
      //     exactly, answer 404. A Phase 27 caller that appends anything to the
      //     path gets a 404 that says nothing about why.
      const nearMiss = await deliver(
        boundCall({ url: `${ORIGIN}/mcp/extra`, accessToken }),
        env,
      );
      expect(nearMiss.response.status).toBe(404);
      expect(await toolNamesIn(nearMiss.response)).toBeNull();
      expect(nearMiss.propsAfter).not.toBeUndefined();
    });
  });
});
