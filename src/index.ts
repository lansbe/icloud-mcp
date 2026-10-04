// The Free edge forwards requests to the bounded application DO. OAuth still
// validates every bearer before entering MCP. The legacy path is retained for
// the original test profile; the Free deploy validator requires all bindings.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { oauthProviderOptions } from "./auth/oauth";
import type { Env } from "./env";
import { freeUnavailable } from "./free/application";

const legacyProvider = new OAuthProvider<Env>(oauthProviderOptions);
export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (env.FREE_APPLICATION) {
      return env.FREE_APPLICATION.getByName("application-v1").fetch(request).catch(() => freeUnavailable());
    }
    return legacyProvider.fetch(request, env, ctx);
  },
};
export { FreeApplication } from "./free/application";
export { BlobVault } from "./free/blob-vault";
export { FreeBudget } from "./free/budget";
export { SemanticStore } from "./free/semantic-store";

// The per-person Durable Object class (Phase 24). Deploy and the test pool both
// require a class bound in wrangler.jsonc to be exported from this entry module;
// without this line the deploy refuses the binding and the pool cannot run the
// object.
export { UserAgent } from "./agent/user-agent";
