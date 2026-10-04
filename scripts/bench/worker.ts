// Local benchmark entry only. Never referenced by either deployment config.
import production, { FreeApplication } from "../../src/index";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { oauthProviderOptions } from "../../src/auth/oauth";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";
import { userIdOf } from "../../src/principal";
import { semanticIndex } from "../../src/free/semantic-store";
import { extractMessage } from "../../src/mail/mime";
import { extractText } from "unpdf";
import { textPdf } from "./pdf-fixture";
export { BlobVault, FreeBudget, SemanticStore, UserAgent } from "../../src/index";

const origin = `https://${DEPLOYED_HOSTNAME}`;
const line = "Synthetic benchmark text with no personal information. ".repeat(2);
const large = textPdf(Array.from({length: 360}, () => Array.from({length: 45}, () => line)));
const tiny = textPdf([["Synthetic document."]]);
const mime = new TextEncoder().encode("From: synthetic@example.invalid\r\nTo: fixture@example.invalid\r\nSubject: Synthetic\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + "<p>Synthetic &amp; safe</p>".repeat(16000));

export class BenchApplication extends FreeApplication {
  async fetch(request: Request) {
    const path = new URL(request.url).pathname;
    if (path === "/__local_bench/vector-seed") {
      const index = semanticIndex(this.env);
      const owner = "a".repeat(64);
      const values = [1, ...new Array(1023).fill(0)];
      for (let page = 0; page < 100; page++) await index.upsert(Array.from({length: 100}, (_, i) => ({
        id: (page * 100 + i + 1).toString(16).padStart(64, "0"), namespace: owner, values,
        metadata: {u: owner, r: "synthetic", s: "synthetic", a: 1},
      })));
      return Response.json({count: 10000});
    }
    if (path === "/__local_bench/vector-query") {
      const owner = "a".repeat(64);
      const result = await semanticIndex(this.env).query([1, ...new Array(1023).fill(0)], {
        namespace: owner, filter: {u: owner}, topK: 5,
      });
      return Response.json({count: result.count, score: result.matches[0]?.score});
    }
    if (path === "/__local_bench/pdf-small" || path === "/__local_bench/pdf-large") {
      const pdf = path.endsWith("large") ? large : tiny;
      const result = await extractText(pdf.slice(), {mergePages: true});
      return Response.json({bytes: pdf.byteLength, pages: result.totalPages, characters: result.text.length});
    }
    if (path === "/__local_bench/mime") {
      const parsed = await extractMessage(mime);
      return Response.json({bytes: mime.byteLength, subject: parsed.subject});
    }
    return super.fetch(request);
  }
}

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    if (new URL(request.url).pathname === "/__local_bench/setup") {
      const helpers = getOAuthApi(oauthProviderOptions, {...env});
      const redirect = "https://claude.ai/api/mcp/auth_callback";
      const client = await helpers.createClient({redirectUris: [redirect], tokenEndpointAuthMethod: "none"});
      const parsed = await helpers.parseAuthRequest(new Request(`${origin}/authorize?${new URLSearchParams({
        response_type: "code", client_id: client.clientId, redirect_uri: redirect, scope: "mcp", state: "synthetic",
        resource: `${origin}/mcp`, code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256",
      })}`));
      const granted = await helpers.completeAuthorization({request: parsed, userId: (await userIdOf("synthetic@example.invalid"))!, metadata: {}, scope: ["mcp"],
        props: {v: 1, appleId: "synthetic@example.invalid", appPassword: "ffff-ffff-ffff-ffff"}});
      const response = await env.SELF.fetch(new Request(`${origin}/oauth/token`, {method: "POST",
        headers: {"content-type": "application/x-www-form-urlencoded"}, body: new URLSearchParams({
          grant_type: "authorization_code", code: new URL(granted.redirectTo).searchParams.get("code")!,
          client_id: client.clientId, redirect_uri: redirect, resource: `${origin}/mcp`,
          code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        })}));
      return response;
    }
    // Miniflare transports over loopback and replaces Host; restore the
    // canonical synthetic host only in this non-deployable local harness.
    request = new Request(request);
    request.headers.set("host", DEPLOYED_HOSTNAME);
    return production.fetch(request, env, ctx);
  },
};
