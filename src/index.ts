// Worker entry point.
//
// The default export is the OAuth provider itself, which is what makes
// FND-02's ordering clause a property of the library rather than of project
// code: the provider owns routing, and its API path validates the bearer
// token and returns 401 before it ever reaches the API handler's fetch. No
// project code sits in front of that check, so no refactor of project code
// can move it.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { oauthProviderOptions } from "./auth/oauth";
import type { Env } from "./env";

export default new OAuthProvider<Env>(oauthProviderOptions);

// The per-person Durable Object class (Phase 24). Deploy and the test pool both
// require a class bound in wrangler.jsonc to be exported from this entry module;
// without this line the deploy refuses the binding and the pool cannot run the
// object.
export { UserAgent } from "./agent/user-agent";
