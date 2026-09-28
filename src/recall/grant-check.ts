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
// removal from the allow list through its revoke step (D-25).
//
// IT IGNORES THE AUTONOMY GRANT (Phase 27, 27-CONTEXT D-32). Autonomy is
// inherent, so every signed-in person also holds one grant for the autonomy
// client. Counting it would mean a person whose access was revoked still reads
// as signed in, and their recall data would never be destroyed. So only grants
// from any other client count. When the first page holds only autonomy grants
// and more pages exist, the pages are followed, one after another, until an
// ordinary grant turns up or the pages end.
//
// It asks through the OAuth library's own public listing, the same call the
// grants script uses, and never reads the library's storage format itself. No
// caught value is read, and nothing is logged (./.claude/CLAUDE.md §4).

import { getOAuthApi, type OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import { AUTONOMY_CLIENT_ID } from "../agent/autonomy-client";

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

/** A page cap, so a store that keeps handing back a cursor cannot spin forever. */
const MAX_PAGES = 1000;

/**
 * Whether one listed grant summary counts: anything whose client id is not
 * exactly the autonomy client's. A summary with no readable client id counts,
 * because only a definite "none" destroys.
 */
function isOrdinary(item: unknown): boolean {
  return (item as { clientId?: unknown } | null)?.clientId !== AUTONOMY_CLIENT_ID;
}

/**
 * Whether `userId` holds any grant from a client other than the autonomy one:
 * some, none, or unknown on any failure. Every page is followed until an
 * ordinary grant is found or the pages end. Hitting the page cap is unknown.
 */
export async function grantsRemainFor(
  kv: KVNamespace,
  userId: string,
): Promise<"some" | "none" | "unknown"> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return "unknown";
  try {
    const helpers = getOAuthApi(minimalOptions(), { OAUTH_KV: kv });
    let cursor: string | undefined;
    for (let pages = 0; pages < MAX_PAGES; pages += 1) {
      const page = await helpers.listUserGrants(
        userId,
        cursor === undefined ? undefined : { cursor },
      );
      const items: unknown = page?.items;
      if (!Array.isArray(items)) return "unknown";
      if (items.some(isOrdinary)) return "some";
      if (typeof page.cursor !== "string" || page.cursor === "") return "none";
      cursor = page.cursor;
    }
    return "unknown";
  } catch {
    return "unknown";
  }
}
