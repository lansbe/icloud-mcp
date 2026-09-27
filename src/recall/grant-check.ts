// Does this person still hold any grant? (Phase 25, RCLL-06, D-09, D-25)
//
// Grants are revoked only through the owner's script, which runs in Node
// through wrangler and cannot reach a person's object. So the object asks,
// from its alarm, about its own stored name. Only a definite "none" destroys
// that person's recall index. An error answers "unknown", and nothing is
// destroyed that time.
//
// What "revoked" means here is the person's LAST grant: someone replacing a
// lost laptop drops one grant and keeps another, and must not lose their index
// (CONTEXT D-09, owner-reviewable at 25-05).
//
// Recall is inherent (owner, 2026-09-27), so this is the only wholesale
// destroy, and every way a person's access ends arrives here as "no grant
// left": the owner's revoke, the person disconnecting, a grant expiring, and
// removal from the allow list through its revoke step (D-25). Phase 27-05 will
// make this ignore the autonomy grant (27-CONTEXT D-32).
//
// It asks through the OAuth library's own public listing, the same call the
// grants script uses, and never reads the library's storage format itself. No
// caught value is read, and nothing is logged (./.claude/CLAUDE.md §4).

import { getOAuthApi, type OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";

/** A user id: 64 lower-case hex characters. */
const USER_ID = /^[0-9a-f]{64}$/;

/**
 * The smallest options object the library accepts, the same five fields
 * `scripts/grants-core.mjs` uses.
 *
 * Defined here rather than imported from `src/auth/oauth.ts`: that module
 * reaches the Worker's handlers and, through them, the mail tree, and the
 * person's object must not. Nothing here serves a request; the listing only
 * needs the store.
 */
function minimalOptions(): OAuthProviderOptions<{ OAUTH_KV: KVNamespace }> {
  const handler = {
    fetch() {
      return new Response(null, { status: 404 });
    },
  };
  return {
    apiRoute: "/mcp",
    apiHandler: handler,
    defaultHandler: handler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
  };
}

/** Whether `userId` holds any grant: some, none, or unknown on any failure. */
export async function grantsRemainFor(
  kv: KVNamespace,
  userId: string,
): Promise<"some" | "none" | "unknown"> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return "unknown";
  try {
    const helpers = getOAuthApi(minimalOptions(), { OAUTH_KV: kv });
    const page = await helpers.listUserGrants(userId);
    const items = Array.isArray(page?.items) ? page.items : null;
    if (items === null) return "unknown";
    if (items.length > 0) return "some";
    // An empty page that still offers a cursor is not a definite answer.
    return page.cursor === undefined || page.cursor === "" ? "none" : "unknown";
  } catch {
    return "unknown";
  }
}
