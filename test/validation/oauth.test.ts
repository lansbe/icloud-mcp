import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { localToken, rpc } from "../fixtures/free-oauth";
import { USER_A, USER_B } from "../fixtures/two-users";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";

describe("read-only admission through actual OAuth and Free routing", () => {
  it("requires authentication and retains isolated identity reads", async () => {
    const request = new Request(`https://${DEPLOYED_HOSTNAME}/mcp`, {method: "POST", body: "{}"});
    expect((await env.SELF.fetch(request)).status).toBe(401);
    for (const user of [USER_A, USER_B]) {
      const token = await localToken(user);
      const response = await rpc(token, "tools/call", {name: "account_whoami", arguments: {}});
      expect(response.response.status).toBe(200);
      expect(response.text).toContain(user.appleId);
      expect(response.text).not.toContain(user === USER_A ? USER_B.appleId : USER_A.appleId);
      expect(response.text).not.toContain(user.appPassword);
    }
  });
  it("keeps the inventory and refuses valid write/indexing requests on the wire", async () => {
    const token = await localToken(USER_A);
    const list = await rpc(token, "tools/list");
    expect(list.body.result.tools).toHaveLength(47);
    for (const params of [
      {name: "calendar_create_calendar", arguments: {displayName: "Synthetic forbidden", color: "#123456"}},
      {name: "mail_recall_backfill", arguments: {}},
    ]) {
      const reply = await rpc(token, "tools/call", params);
      expect(reply.response.status).toBe(200);
      expect(reply.body.result?.isError, reply.text).toBe(true);
      expect(reply.text).toContain("read_only_validation");
    }
  });
});
