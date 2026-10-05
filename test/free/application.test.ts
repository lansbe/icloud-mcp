import { localToken, rpc } from "../fixtures/free-oauth";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { runInDurableObject } from "cloudflare:test";
import entrypoint from "../../src/index";
import type { Env } from "../../src/env";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";
import { budgetOf, FREE_BUDGETS } from "../../src/free/budget";
import { USER_A, USER_B } from "../fixtures/two-users";

const origin = `https://${DEPLOYED_HOSTNAME}`;
beforeEach(async () => {
  await runInDurableObject(budgetOf(env), (_instance, state) => state.storage.sql.exec("delete from budget"));
});

describe("actual edge -> application DO -> OAuth -> MCP", () => {
  it("returns a closed capacity response when the provider cannot deliver to the DO", async () => {
    const unavailable = {FREE_APPLICATION: {getByName: () => ({fetch: async () => {throw new Error("synthetic unavailable");}})}} as unknown as Env;
    const response = await entrypoint.fetch(new Request(`${origin}/mcp`), unavailable, {} as ExecutionContext);
    expect(response.status).toBe(503);
    expect(await response.text()).toContain("free_capacity_unavailable");
  });
  it("refuses unauthenticated tools and wrong hosts; discovery is served", async () => {
    expect((await env.SELF.fetch(new Request(`${origin}/mcp`, {method: "POST", body: "{}"}))).status).toBe(401);
    expect((await env.SELF.fetch(new Request("https://wrong.example.invalid/mcp"))).status).toBe(421);
    const discovery = await env.SELF.fetch(`${origin}/.well-known/oauth-authorization-server`);
    expect(discovery.status).toBe(200);
    expect((await discovery.json() as {issuer: string}).issuer).toBe(origin);
  });

  it("keeps identity isolated across interleaved users and snapshots all 47 schemas", async () => {
    const a = await localToken(USER_A);
    const b = await localToken(USER_B);
    const answers = await Promise.all([rpc(a, "tools/call", {name: "account_whoami", arguments: {}}),
      rpc(b, "tools/call", {name: "account_whoami", arguments: {}})]);
    for (const [i, user] of [USER_A, USER_B].entries()) {
      expect(answers[i]!.response.status, answers[i]!.text).toBe(200);
      expect(answers[i]!.text).toContain(user.appleId);
      expect(answers[i]!.text).not.toContain(i ? USER_A.appleId : USER_B.appleId);
      expect(answers[i]!.text).not.toContain(user.appPassword);
    }
    const list = await rpc(a, "tools/list");
    expect(list.response.status).toBe(200);
    expect(list.body.error).toBeUndefined();
    expect(list.body.result.tools).toHaveLength(47);
    expect(list.body.result.tools).toMatchSnapshot();
    const unknown = await rpc(a, "tools/call", {name: "nonexistent-tool", arguments: {}});
    expect(unknown.body.error).toBeDefined();
  });

  it("fails closed when its Free admission limit is reached", async () => {
    await budgetOf(env).take("requests", FREE_BUDGETS.requests.limit);
    const response = await env.SELF.fetch(`${origin}/.well-known/oauth-authorization-server`);
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("3600");
    expect(await response.text()).toContain("free_capacity_unavailable");
  });

  it("recovers all application slots after four incomplete anonymous bodies", async () => {
    const results = await Promise.all(Array.from({length: 4}, () =>
      env.SELF.fetch(new Request(`${origin}/oauth/register`, {method: "POST",
        headers: {"content-type": "application/json"},
        body: new ReadableStream<Uint8Array>({start(controller) { controller.enqueue(new TextEncoder().encode("{")); }}),
      })).then(response => response.status)));
    expect(results).toEqual([408, 408, 408, 408]);
    expect((await env.SELF.fetch(`${origin}/.well-known/oauth-authorization-server`)).status).toBe(200);
  });

  it("preserves token revocation after ordinary request and OAuth budgets exhaust", async () => {
    let clientId = "";
    const token = await localToken(USER_A, id => { clientId = id; });
    await runInDurableObject(budgetOf(env), (_instance, state) => {
      state.storage.sql.exec("delete from budget");
    });
    await budgetOf(env).take("requests", FREE_BUDGETS.requests.limit);
    await budgetOf(env).take("oauthWrites", FREE_BUDGETS.oauthWrites.limit);
    const response = await env.SELF.fetch(new Request(`${origin}/oauth/token`, {method: "POST",
      headers: {"content-type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({token, token_type_hint: "access_token", client_id: clientId}),
    }));
    // Public-client revocation is processed by the provider, not a Free 503.
    expect(response.status).toBe(200);
    expect(await budgetOf(env).take("oauthCleanup", FREE_BUDGETS.oauthCleanup.limit)).toBe(false);
  });

  it("does not mix identities across repeated concurrent requests", async () => {
    const tokens = [await localToken(USER_A), await localToken(USER_B)];
    for (let round = 0; round < 4; round++) {
      const results = await Promise.all(Array.from({length: 4}, (_, i) =>
        rpc(tokens[i % 2]!, "tools/call", {name: "account_whoami", arguments: {}})));
      for (let i = 0; i < results.length; i++) {
        expect(results[i]!.response.status).toBe(200);
        expect(results[i]!.text).toContain(i % 2 ? USER_B.appleId : USER_A.appleId);
        expect(results[i]!.text).not.toContain(i % 2 ? USER_A.appleId : USER_B.appleId);
      }
    }
  });
});
