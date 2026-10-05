import { env } from "cloudflare:workers";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { describe, expect, it } from "vitest";
import { isAllowedRedirectUri } from "../../src/auth/login-handler";
import { matchesOpenAiRedirect, validOpenAiRedirect } from "../../src/auth/openai-redirect";
import { oauthProviderOptions } from "../../src/auth/oauth";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";
import { USER_A } from "../fixtures/two-users";

const origin = `https://${DEPLOYED_HOSTNAME}`;
const callback = "https://chatgpt.com/connector/oauth/synthetic-callback";
const stable = "https://chatgpt.com/connector_platform_oauth_redirect";

describe("OpenAI exact callback admission", () => {
  it("accepts only the configured complete URL, with no default callback", () => {
    expect(validOpenAiRedirect(stable)).toBe(true);
    expect(validOpenAiRedirect(callback)).toBe(true);
    expect(validOpenAiRedirect(callback + "\n")).toBe(false);
    expect(isAllowedRedirectUri(callback, callback)).toBe(true);
    expect(isAllowedRedirectUri(stable, stable)).toBe(true);
    expect(isAllowedRedirectUri(callback)).toBe(false);
    expect(isAllowedRedirectUri(stable, callback)).toBe(false);
    expect(isAllowedRedirectUri("https://chatgpt.com", callback)).toBe(false);
  });
  it.each([
    callback + "/", callback + "?next=https://evil.invalid", callback + "#fragment",
    callback.replace("synthetic-callback", "different-callback"),
    callback.replace("https:", "http:"), callback.replace("chatgpt.com", "chatgpt.com.evil.invalid"),
    callback.replace("chatgpt.com", "evil.invalid@chatgpt.com"),
    callback.replace("chatgpt.com", "chatgpt.com:443"),
    callback.replace("chatgpt.com", "chatgpt.com:8443"),
    callback.replace("chatgpt.com", "chatgpt.com."),
    callback.replace("/connector/oauth/", "/redirect/../connector/oauth/"),
    callback.replace("synthetic-callback", "%73ynthetic-callback"),
    " https://chatgpt.com/connector/oauth/synthetic-callback",
    "https://chatgpt.com/connector/oauth/*", "https://chatgpt.com/redirect",
  ])("refuses modified or malformed callback %s", (uri) => {
    expect(isAllowedRedirectUri(uri, callback)).toBe(false);
    expect(matchesOpenAiRedirect(uri, callback)).toBe(false);
  });
  it("enforces the callback during real DCR and exposes PKCE/issuer metadata", async () => {
    const metadata = await env.SELF.fetch(`${origin}/.well-known/oauth-authorization-server`);
    const data = await metadata.json() as any;
    expect(data.issuer).toBe(origin);
    expect(data.authorization_response_iss_parameter_supported).toBe(true);
    expect(data.code_challenge_methods_supported).toContain("S256");
    expect(data.client_id_metadata_document_supported).toBe(false);
    for (const [uri, status] of [[callback, 201], [stable, 400], [callback + "?next=x", 400]] as const) {
      const response = await env.SELF.fetch(new Request(`${origin}/oauth/register`, {
        method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({client_name: "Synthetic OpenAI", redirect_uris: [uri],
          grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none"}),
      }));
      expect(response.status, await response.text()).toBe(status);
    }
  });
  it("returns the exact issuer and destination through a synthetic authorization", async () => {
    const api = getOAuthApi(oauthProviderOptions, {...env});
    const client = await api.createClient({redirectUris: [callback], tokenEndpointAuthMethod: "none"});
    const request = await api.parseAuthRequest(new Request(`${origin}/authorize?${new URLSearchParams({
      response_type: "code", client_id: client.clientId, redirect_uri: callback, scope: "mcp", state: "synthetic-state",
      resource: `${origin}/mcp`, code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256",
    })}`));
    const result = await api.completeAuthorization({request, userId: USER_A.userId, metadata: {}, scope: ["mcp"],
      props: {v: 1, appleId: USER_A.appleId, appPassword: USER_A.appPassword}});
    const target = new URL(result.redirectTo);
    expect(target.origin + target.pathname).toBe(callback);
    expect(target.searchParams.get("iss")).toBe(origin);
    expect(target.searchParams.get("state")).toBe("synthetic-state");
    expect(target.searchParams.has("code")).toBe(true);
    const form = await env.SELF.fetch(new Request(`${origin}/authorize?${new URLSearchParams({
      response_type: "code", client_id: client.clientId, redirect_uri: callback, scope: "mcp", state: "synthetic-state",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256",
    })}`));
    const html = await form.text();
    expect(form.status, html).toBe(200);
    expect(html).toContain("Mail-only read validation");
    expect(html).not.toContain("It can put a draft in your Drafts folder");
  });
});
