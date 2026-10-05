import { DurableObject } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { oauthProviderOptions } from "../auth/oauth";
import type { Env } from "../env";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import { takeBudget } from "./budget";
import { handleUpload } from "./upload";
import { boundedBody, BodyLimitError } from "./body";
import { readOnlyValidation } from "../validation-access";

export function freeUnavailable(status = 503): Response {
  return Response.json({ error: "free_capacity_unavailable", retry: "Retry later; no upgrade is performed." }, {
    status, headers: { "cache-control": "no-store", "retry-after": "3600" },
  });
}

// The edge forwards bytes only. OAuth, JSON/schema construction, MIME, PDF and
// all tools run in this SQLite Durable Object's documented CPU budget. It has
// no persistent identity: each invocation gets a fresh context and MCP server.
export class FreeApplication extends DurableObject<Env> {
  private provider = new OAuthProvider<Env>(oauthProviderOptions);
  private active = 0;

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.hostname !== DEPLOYED_HOSTNAME) return new Response(null, { status: 421 });
    if (this.active >= 4) return freeUnavailable(429);
    this.active++;
    try {
      if (url.pathname.startsWith("/upload/")) {
        if (readOnlyValidation(this.env)) return new Response(null, { status: 403 });
        await takeBudget(this.env, "requests");
        return await handleUpload(request, this.env);
      }
      let cleanup = false;
      if (request.body) {
        const maximum = url.pathname === "/mcp" ? 16 * 1024 * 1024 : 64 * 1024;
        if (Number(request.headers.get("content-length")) > maximum) return new Response(null, {status: 413});
        const body = await boundedBody(request.body, maximum);
        if (url.pathname === "/oauth/token" && request.method === "POST" &&
            request.headers.get("content-type")?.split(";")[0] === "application/x-www-form-urlencoded") {
          const fields = new URLSearchParams(new TextDecoder().decode(body));
          cleanup = fields.has("token") && !fields.has("grant_type");
        }
        request = new Request(request, { body });
      }
      // Revocation has its own bounded reserve so ordinary admission/refresh
      // exhaustion cannot strand the bearer minted for an autonomy session.
      if (cleanup) await takeBudget(this.env, "oauthCleanup");
      else {
        await takeBudget(this.env, "requests");
        if (request.method === "POST" &&
            ["/oauth/register", "/oauth/token", "/authorize"].includes(url.pathname)) {
          await takeBudget(this.env, "oauthWrites");
        }
      }
      // Never pass the DO's shared state object to an OAuth library which puts
      // authenticated props on its context. Only waitUntil is delegated.
      const ctx = {
        waitUntil: (promise: Promise<unknown>) => this.ctx.waitUntil(promise),
        passThroughOnException() {},
        props: {},
      } as ExecutionContext;
      return await this.provider.fetch(request, this.env, ctx);
    } catch (error) {
      if (error instanceof BodyLimitError) return new Response(null, {status: error.status});
      return freeUnavailable();
    } finally {
      this.active--;
    }
  }
}
