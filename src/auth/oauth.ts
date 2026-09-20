// The OAuth provider's configuration, as a named object rather than an
// inline literal.
//
// Exported so a later plan's ordering test can compose the REAL production
// configuration — the real gate, the real endpoints, the real handler
// composition — and substitute only the API handler. A test that had to
// rebuild this object would be testing its own copy.

import type { OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import type { EntryEnv } from "../env";
import { DEPLOYED_HOSTNAME, mcpApiHandler } from "../mcp/api-handler";
import { loginHandler } from "./login-handler";

export const oauthProviderOptions: OAuthProviderOptions<EntryEnv> = {
  apiRoute: "/mcp",

  // The adapter, never the raw handler. See src/mcp/api-handler.ts for what
  // assigning the handler directly would silently discard.
  apiHandler: mcpApiHandler,

  // Everything that is not an API request, which for this server means the
  // /authorize form and nothing else.
  defaultHandler: loginHandler,

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",

  // Dynamic Client Registration only. The Client-ID-Metadata-Document option
  // is deliberately left unset: it requires an egress-restricting
  // compatibility flag whose interaction with this Worker's outbound
  // transport is unverified, and this is the one Worker whose entire purpose
  // is proving that transport works. 01-02-SUMMARY.md records the full
  // reasoning and the escape hatch if a client cannot register dynamically.
  clientRegistrationEndpoint: "/oauth/register",

  // D-05. Both values are also the library defaults, stated explicitly so a
  // future change is a visible diff. Refresh-token rotation is automatic and
  // not configurable in this library; see 01-02-SUMMARY.md for the one way
  // D-05's stated properties turned out weaker than assumed.
  accessTokenTTL: 3600,
  refreshTokenTTL: 2592000,

  scopesSupported: ["mcp"],

  resourceMetadata: {
    // This becomes the RFC 8707 token audience. Changing it after
    // authorization invalidates every issued token and forces the OAuth
    // ceremony to be repeated.
    resource: `https://${DEPLOYED_HOSTNAME}/mcp`,
    scopes_supported: ["mcp"],
    resource_name: "iCloud MCP",
  },

  // Both are already the defaults. Restated so that turning either on is a
  // change someone has to write, and a reviewer can see.
  allowImplicitFlow: false,
  allowPlainPKCE: false,
};
