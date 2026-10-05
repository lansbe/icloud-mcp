import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { McpServer } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { autonomyConfigured, signInNotices } from "../../src/auth/login-handler";
import { createServerFactory } from "../../src/mcp/server";
import { withValidationAccess } from "../../src/mcp/validation-access";
import { readOnlyValidation, VALIDATION_MAIL_TOOLS } from "../../src/validation-access";
import { runRecallStep, runRecallBackfill } from "../../src/recall/drive";
import { embedder, RecallEmbedError } from "../../src/recall/embed";
import { agentFor } from "../../src/agent/lease";
import type { LeasedMail } from "../../src/agent/lease";
import { USER_A } from "../fixtures/two-users";
import { principalFromProps } from "../../src/principal";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";

const actor = () => principalFromProps({v: 1, appleId: USER_A.appleId, appPassword: USER_A.appPassword});
afterEach(() => vi.restoreAllMocks());

describe("read-only validation is enforced by the server", () => {
  it("fails closed for missing/misspelled Free modes and retains explicit full access", () => {
    expect(readOnlyValidation(env)).toBe(true);
    for (const ACCESS_MODE of [undefined, "", "readonly", "FULL"]) {
      expect(readOnlyValidation({FREE_APPLICATION: {}, ACCESS_MODE})).toBe(true);
    }
    expect(readOnlyValidation({FREE_APPLICATION: {}, ACCESS_MODE: "full"})).toBe(false);
    expect(readOnlyValidation({})).toBe(false);
  });

  it("retains all 47 registrations and blocks all 39 non-Mail-read callbacks", async () => {
    const callbacks = new Map<string, (...args: unknown[]) => unknown>();
    const real = McpServer.prototype.registerTool;
    vi.spyOn(McpServer.prototype, "registerTool").mockImplementation(function (this: McpServer, name, config, cb) {
      callbacks.set(name, cb as (...args: unknown[]) => unknown);
      return real.call(this, name, config as never, cb as never);
    });
    createServerFactory(Promise.resolve(await actor()))({era: "modern"} as never);
    expect(callbacks.size).toBe(47);
    expect(VALIDATION_MAIL_TOOLS.size).toBe(8);
    for (const name of VALIDATION_MAIL_TOOLS) expect(callbacks.has(name)).toBe(true);
    let blocked = 0;
    for (const [name, cb] of callbacks) {
      if (VALIDATION_MAIL_TOOLS.has(name)) continue;
      const answer = await cb({}) as {isError: boolean; content: {text: string}[]};
      expect(answer.isError, name).toBe(true);
      expect(answer.content[0]?.text, name).toContain("read_only_validation");
      blocked++;
    }
    expect(blocked).toBe(39);
  });

  it("refuses future unknown tools before invoking their callback; full mode retains it", async () => {
    let callback: (...args: unknown[]) => unknown = () => {};
    const fake = {registerTool: (_name: string, _config: unknown, cb: typeof callback) => { callback = cb; }} as unknown as McpServer;
    const work = vi.fn(async () => ({content: []}));
    withValidationAccess(fake, true).registerTool("future_mutation", {}, work);
    expect(await callback({})).toMatchObject({isError: true});
    expect(work).not.toHaveBeenCalled();
    expect(withValidationAccess(fake, false)).toBe(fake);
    withValidationAccess(fake, false).registerTool("future_mutation", {}, work);
    await callback({});
    expect(work).toHaveBeenCalledOnce();
  });

  it("does not trigger implicit indexing, explicit backfill or AI", async () => {
    const grant = vi.fn(async () => "interactive-client");
    const mail = {withConnectionLease: vi.fn()} as unknown as LeasedMail;
    const principal = await actor();
    await runRecallStep(Promise.resolve(principal), mail, grant);
    expect(await runRecallBackfill(principal, mail, grant)).toEqual({kind: "refused"});
    expect(grant).not.toHaveBeenCalled();
    expect(mail.withConnectionLease).not.toHaveBeenCalled();
    await expect(embedder().embed(["synthetic text"])).rejects.toBeInstanceOf(RecallEmbedError);
  });

  it("does not mint or arm autonomous access even when secrets are configured", async () => {
    expect(autonomyConfigured(env)).toBe(false);
    const notices = signInNotices(env);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.heading).toBe("Mail-only read validation");
    const stub = agentFor(await actor());
    await runInDurableObject(stub, async (instance) => {
      const outbound = vi.spyOn(instance, "autonomySelfFetch");
      expect(await instance.armAutonomy("synthetic-code:synthetic-grant")).toEqual({kind: "not_armed"});
      expect(outbound).not.toHaveBeenCalled();
    });
  });

  it("blocks signed upload routes before processing files", async () => {
    const response = await env.SELF.fetch(new Request(`https://${DEPLOYED_HOSTNAME}/upload/test`, {
      method: "PUT", body: "synthetic bytes",
    }));
    expect(response.status).toBe(403);
  });
});
