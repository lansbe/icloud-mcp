// The one place autonomy asks the OAuth library about grants (Phase 27, D-28, D-33).
//
// Two questions, both about one person, both answered from the library's own
// public listing, which returns grant SUMMARIES: an id, a client id, a scope, a
// time. Never props. Nothing here reads a grant's props, and nothing here calls
// the library's token-unwrapping helper, which hands back decrypted props.
//
// 1. `sweepAutonomyGrants` revokes this person's autonomy grants, all of them
//    or all but one. The object runs it after every arm: a successful arm keeps
//    the grant its record names, and a failed arm keeps none (D-13, D-28). It
//    also runs when the standing check below says the key has ended.
// 2. `keyStandingFor` says whether the key the record names still stands: its
//    own grant is still listed, and the person still holds an ordinary grant
//    from some other client (D-33). The session asks it before every unseal,
//    and plan 27-05's alarm job asks the same question for a key nobody uses.
//
// WHY NOT `src/auth/oauth.ts`. That module holds the Worker's real provider
// options, and through them it reaches the Worker's handlers and the mail tree.
// The person's object must never import those. So this file builds its own
// minimal options object, the same five fields `scripts/grants-core.mjs` uses.
// Phase 25's `src/recall/grant-check.ts` keeps its own copy for the same reason.
// The listing and the revoke only need the store.
//
// A user id is checked before anything is asked: 64 lower-case hex, or the
// answer is the "could not tell" one. Every page of the listing is followed,
// one after another. Every `catch` reads nothing, and nothing is logged
// (./.claude/CLAUDE.md §4).

import { getOAuthApi, type OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import { AUTONOMY_CLIENT_ID } from "./autonomy-client";

/** A user id: 64 lower-case hex characters. */
const USER_ID = /^[0-9a-f]{64}$/;

/** A page cap, so a store that keeps handing back a cursor cannot spin forever. */
const MAX_PAGES = 1000;

/** What the sweep answers. `incomplete` when anything could not be listed or revoked. */
export type SweepOutcome = "done" | "incomplete";

/**
 * Whether the key the record names still stands (D-33).
 *
 * `standing`: its grant is listed and the person holds another grant.
 * `revoked`: its grant is not listed.
 * `connection_ended`: no grant from any other client is listed.
 * `unknown`: the question could not be answered, so nothing may be ended on it.
 */
export type KeyStanding = "standing" | "revoked" | "connection_ended" | "unknown";

/** One listed grant, as much of its summary as autonomy reads. */
interface ListedGrant {
  readonly id: string;
  readonly clientId: string;
}

/**
 * The smallest options object the library accepts, the same five fields
 * `scripts/grants-core.mjs` uses. Nothing here serves a request.
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

/** The library's helpers over one store. */
function helpersOver(kv: KVNamespace) {
  return getOAuthApi(minimalOptions(), { OAUTH_KV: kv });
}

/**
 * Every grant the library lists for `userId`, following every page, or null
 * when any page could not be read or the page cap was reached.
 */
async function everyGrantOf(kv: KVNamespace, userId: string): Promise<ListedGrant[] | null> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return null;
  try {
    const helpers = helpersOver(kv);
    const grants: ListedGrant[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const result = await helpers.listUserGrants(
        userId,
        cursor === undefined ? undefined : { cursor },
      );
      const items: unknown = result?.items;
      if (!Array.isArray(items)) return null;
      for (const item of items) {
        const summary = item as { id?: unknown; clientId?: unknown } | null;
        grants.push({
          id: typeof summary?.id === "string" ? summary.id : "",
          clientId: typeof summary?.clientId === "string" ? summary.clientId : "",
        });
      }
      if (typeof result.cursor !== "string" || result.cursor.length === 0) return grants;
      cursor = result.cursor;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Revoke every autonomy grant `userId` holds, except `keepGrantId` and any id
 * in `alsoKeep` (D-13, D-28).
 *
 * `keepGrantId` is the grant a successful arm just stored, or null to keep
 * none. `alsoKeep` holds the grants whose own arm is waiting in the object's
 * queue: those are other sign-ins still in flight, and revoking one would make
 * that arm fail and end the person's key (D-27).
 *
 * Revokes one at a time, through the library's own revoke, which deletes the
 * grant and every token under it. Answers `done`, or `incomplete` when the
 * listing failed or any revoke rejected. An incomplete sweep is not a failure
 * of the arm: a stray grant opens nothing on its own, and the next arm sweeps
 * again.
 */
export async function sweepAutonomyGrants(
  kv: KVNamespace,
  userId: string,
  keepGrantId: string | null,
  alsoKeep: ReadonlySet<string> = new Set(),
): Promise<SweepOutcome> {
  const grants = await everyGrantOf(kv, userId);
  if (grants === null) return "incomplete";
  let outcome: SweepOutcome = "done";
  for (const grant of grants) {
    if (grant.clientId !== AUTONOMY_CLIENT_ID) continue;
    if (grant.id.length === 0) {
      outcome = "incomplete";
      continue;
    }
    if (grant.id === keepGrantId || alsoKeep.has(grant.id)) continue;
    try {
      await helpersOver(kv).revokeGrant(grant.id, userId);
    } catch {
      outcome = "incomplete";
    }
  }
  return outcome;
}

/**
 * Revoke one autonomy grant by its id, through the library's own revoke, which
 * deletes the grant and every token under it (review WR-02).
 *
 * A direct key operation, not a listing. The sweep above finds grants through
 * the store's listing, and a listing can lag a fresh write by about a minute.
 * So a re-arm that relied on the sweep alone could miss the grant it had just
 * replaced, when that grant was armed a moment earlier by a second submission
 * of the same sign-in form. That grant would then stay live, with its refresh
 * token thrown away and never revoked. The caller passes only an id it read
 * from its own record, which only ever names an autonomy grant.
 *
 * Answers `done`, or `incomplete` when the user id is malformed, the id is
 * empty, or the revoke rejected. Never throws.
 */
export async function revokeAutonomyGrant(
  kv: KVNamespace,
  userId: string,
  grantId: string,
): Promise<SweepOutcome> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return "incomplete";
  if (typeof grantId !== "string" || grantId.length === 0) return "incomplete";
  try {
    await helpersOver(kv).revokeGrant(grantId, userId);
    return "done";
  } catch {
    return "incomplete";
  }
}

/**
 * Whether the key whose grant is `grantId` still stands (D-33). One pass over
 * every page of the person's grants. See `KeyStanding`.
 */
export async function keyStandingFor(
  kv: KVNamespace,
  userId: string,
  grantId: string,
): Promise<KeyStanding> {
  const grants = await everyGrantOf(kv, userId);
  if (grants === null) return "unknown";
  if (!grants.some((grant) => grant.id === grantId)) return "revoked";
  if (!grants.some((grant) => grant.clientId !== AUTONOMY_CLIENT_ID)) return "connection_ended";
  return "standing";
}
