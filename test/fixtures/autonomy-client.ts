// The autonomy client, installed into the pool's own OAuth store.
//
// The library's client creation always picks a random id, and dynamic
// registration can never produce the fixed autonomy id. So the client is made
// through the library's own helper and then re-keyed under the fixed id, with
// the secret set to the pool's fake value through the library's own update
// helper, so the library hashes the known value and the person's object can
// authenticate with it.
//
// That procedure is `installAutonomyClientRecord` in `scripts/grants-core.mjs`,
// the same function the owner's `autonomy-setup` command runs against the real
// store (plan 27-03). This fixture carries no copy of it, so the ceremony the
// tests pass is the one the owner's setup produces.
//
// It passes `replace: true`, which is what this fixture did before the move:
// several suites install the client into the one shared pool store, and each
// installs the same record with the same fake secret, so replacing one is
// harmless here. The owner's command refuses without `--replace` instead.
//
// The client is confidential (`client_secret_basic`) and carries one redirect
// URI, on this server's own origin, which is never served (D-29).

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { installAutonomyClientRecord } from "../../scripts/grants-core.mjs";
import type { GrantStore } from "../../scripts/grants-core.mjs";
import { AUTONOMY_CLIENT_ID, AUTONOMY_REDIRECT_PATH } from "../../src/agent/autonomy-client";
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
  const secret = env.AUTONOMY_CLIENT_SECRET;
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("the case's environment carries no autonomy client secret");
  }

  const installed = await installAutonomyClientRecord({
    helpers: getOAuthApi(oauthProviderOptions, env),
    kv: env.OAUTH_KV as unknown as GrantStore,
    redirectUris: [AUTONOMY_REDIRECT_URI],
    clientSecret: secret,
    replace: true,
  });
  if (installed.kind !== "installed") {
    throw new Error("the autonomy client was not installed");
  }

  return async () => {
    await env.OAUTH_KV.delete(`client:${AUTONOMY_CLIENT_ID}`);
  };
}
