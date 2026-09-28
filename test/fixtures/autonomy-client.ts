// The autonomy client, installed into the pool's own OAuth store.
//
// The library's client creation always picks a random id, and dynamic
// registration can never produce the fixed autonomy id. So the client is made
// through the library's own helper, which gives it the library's record shape
// and the library's secret hash, and then that one record is re-keyed under the
// fixed id. The secret is then set to the pool's fake value through the
// library's own update helper, so the library hashes the known value and the
// person's object can authenticate with it.
//
// This re-key is the same procedure plan 27-03's setup command performs against
// the real store. Plan 27-03 makes this fixture call that shared code instead
// of carrying its own copy.
//
// The client is confidential (`client_secret_basic`) and carries one redirect
// URI, on this server's own origin, which is never served (D-29).

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import {
  AUTONOMY_CLIENT_ID,
  AUTONOMY_CLIENT_NAME,
  AUTONOMY_REDIRECT_PATH,
} from "../../src/agent/autonomy-client";
import { oauthProviderOptions } from "../../src/auth/oauth";
import type { Env } from "../../src/env";
import { DEPLOYED_HOSTNAME } from "../../src/mcp/api-handler";

/** The client's one redirect URI. */
export const AUTONOMY_REDIRECT_URI = `https://${DEPLOYED_HOSTNAME}${AUTONOMY_REDIRECT_PATH}`;

/**
 * Install the autonomy client under its fixed id. Returns a cleanup that
 * deletes the record.
 *
 * `env` must carry the pool's fake client secret; the case's spread copy of
 * the pool's environment does.
 */
export async function installAutonomyClient(env: Env): Promise<() => Promise<void>> {
  const helpers = getOAuthApi(oauthProviderOptions, env);
  const created = await helpers.createClient({
    clientName: AUTONOMY_CLIENT_NAME,
    redirectUris: [AUTONOMY_REDIRECT_URI],
    tokenEndpointAuthMethod: "client_secret_basic",
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
  });

  const randomKey = `client:${created.clientId}`;
  const record = await env.OAUTH_KV.get<Record<string, unknown>>(randomKey, "json");
  if (record === null) throw new Error("the created client record was not found");
  await env.OAUTH_KV.put(
    `client:${AUTONOMY_CLIENT_ID}`,
    JSON.stringify({ ...record, clientId: AUTONOMY_CLIENT_ID }),
  );
  await env.OAUTH_KV.delete(randomKey);

  const secret = env.AUTONOMY_CLIENT_SECRET;
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("the case's environment carries no autonomy client secret");
  }
  const updated = await helpers.updateClient(AUTONOMY_CLIENT_ID, { clientSecret: secret });
  if (updated === null) throw new Error("the re-keyed client record was not found");

  return async () => {
    await env.OAUTH_KV.delete(`client:${AUTONOMY_CLIENT_ID}`);
  };
}
