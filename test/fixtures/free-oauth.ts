// Local synthetic OAuth only. Never authenticates to Apple or a cloud account.
import { env } from "cloudflare:workers";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { expect } from "vitest";
import { oauthProviderOptions } from "../../src/auth/oauth";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";
import type { TestUser } from "./two-users";
const origin = `https://${DEPLOYED_HOSTNAME}`;
const redirect = "https://claude.ai/api/mcp/auth_callback";
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
export async function localToken(user: TestUser, clientCreated?: (id: string) => void): Promise<string> {
  // Direct fixture authorization substitutes only the iCloud proof. Everything
  // after it uses the real local provider, encrypted grants, PKCE and entrypoint.
  const helpers = getOAuthApi(oauthProviderOptions, { ...env });
  const client = await helpers.createClient({ redirectUris: [redirect], tokenEndpointAuthMethod: "none" });
  clientCreated?.(client.clientId);
  const request = await helpers.parseAuthRequest(new Request(`${origin}/authorize?${new URLSearchParams({
    response_type: "code", client_id: client.clientId, redirect_uri: redirect, scope: "mcp", state: "fixture",
    resource: `${origin}/mcp`, code_challenge: challenge, code_challenge_method: "S256",
  })}`));
  const result = await helpers.completeAuthorization({ request, userId: user.userId,
    metadata: {}, scope: ["mcp"], props: { v: 1, appleId: user.appleId, appPassword: user.appPassword } });
  const code = new URL(result.redirectTo).searchParams.get("code")!;
  const response = await env.SELF.fetch(new Request(`${origin}/oauth/token`, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.clientId,
      redirect_uri: redirect, code_verifier: verifier, resource: `${origin}/mcp` }) }));
  expect(response.status).toBe(200);
  return (await response.json() as {access_token: string}).access_token;
}
export async function rpc(token: string, method: string, params: unknown = {}) {
  const response = await env.SELF.fetch(new Request(`${origin}/mcp`, { method: "POST", headers: {
    "authorization": `Bearer ${token}`, "content-type": "application/json", "accept": "application/json, text/event-stream",
    "host": DEPLOYED_HOSTNAME,
  }, body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}) }));
  const text = await response.text();
  const line = text.split("\n").find(x => x.startsWith("data: "))?.slice(6) ?? text;
  return { response, body: JSON.parse(line) as {result?: any; error?: unknown}, text };
}
