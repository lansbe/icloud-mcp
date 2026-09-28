// The one place autonomy asks the OAuth library about grants (Phase 27, D-28, D-33).
//
// Two questions, both about one person, both answered from the library's own
// public listing, which returns grant SUMMARIES: an id, a client id, a scope, a
// time. Never props. Nothing here reads a grant's props, and nothing here calls
// the library's token-unwrapping helper, which hands back decrypted props.
//
// One helper, `storedGrantOf`, also reads a single grant's stored record by its
// key (review R2-WR-02, R2-IN-01). The library's listing loads the same record
// to build its summary. The helper takes two facts from it, the client id and
// whether the one-time code is still unexchanged, and nothing else. The props
// in that record are encrypted under a key derived from a token this module
// never holds, and nothing here looks at them.
//
// 1. `sweepAutonomyGrants` revokes this person's autonomy grants, all of them
//    or all but one. The object runs it after every arm: a successful arm keeps
//    the grant its record names, and a failed arm keeps none (D-13, D-28). It
//    also runs when the standing check below says the key has ended, and on
//    the alarm while the key stands, keeping the record's grant (R2-WR-02).
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

/**
 * A grant id as the library makes them: base64url letters, and no colon, so it
 * can only ever name one grant key of the one person it is read under.
 */
const GRANT_ID = /^[A-Za-z0-9_-]{1,64}$/;

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

/**
 * How long, in seconds, the library keeps a grant whose code has not been
 * exchanged: its code record is written with a ten-minute expiry. A grant
 * younger than this may belong to a sign-in whose arm has not reached the
 * object yet (review WR-01).
 */
export const AUTONOMY_CODE_LIFETIME_SECONDS = 600;

/** One listed grant, as much of its summary as autonomy reads. */
interface ListedGrant {
  readonly id: string;
  readonly clientId: string;
  /** Seconds since the epoch, or null when the summary carried none. */
  readonly createdAt: number | null;
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
        const summary = item as { id?: unknown; clientId?: unknown; createdAt?: unknown } | null;
        const createdAt = summary?.createdAt;
        grants.push({
          id: typeof summary?.id === "string" ? summary.id : "",
          clientId: typeof summary?.clientId === "string" ? summary.clientId : "",
          createdAt: typeof createdAt === "number" && Number.isFinite(createdAt) ? createdAt : null,
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

/** What one grant's stored record says, as much of it as autonomy reads. */
type StoredGrant =
  | { readonly kind: "found"; readonly clientId: string; readonly codeUnexchanged: boolean }
  | { readonly kind: "absent" }
  | { readonly kind: "unreadable" };

/**
 * Read one grant's stored record straight from the store, by its key (review
 * R2-WR-02, R2-IN-01). A direct key read, not a listing, so it does not lag a
 * fresh write the way the listing can.
 *
 * Answers the grant's client id, and whether its one-time code is still
 * unexchanged. The library keeps the code's wrapped key on the grant until the
 * code is exchanged, and deletes it in the exchange, so its presence is the
 * library's own mark of a code nobody has redeemed yet. `absent` when no grant
 * has that key. `unreadable` when the ids are malformed or the read failed.
 */
async function storedGrantOf(kv: KVNamespace, userId: string, grantId: string): Promise<StoredGrant> {
  if (typeof userId !== "string" || !USER_ID.test(userId)) return { kind: "unreadable" };
  if (typeof grantId !== "string" || !GRANT_ID.test(grantId)) return { kind: "unreadable" };
  try {
    const raw: unknown = await kv.get(`grant:${userId}:${grantId}`, { type: "json" });
    if (raw === null) return { kind: "absent" };
    if (typeof raw !== "object" || Array.isArray(raw)) return { kind: "unreadable" };
    const grant = raw as { clientId?: unknown; authCodeWrappedKey?: unknown };
    return {
      kind: "found",
      clientId: typeof grant.clientId === "string" ? grant.clientId : "",
      codeUnexchanged: typeof grant.authCodeWrappedKey === "string",
    };
  } catch {
    return { kind: "unreadable" };
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
 * A SWEEP THAT KEEPS A GRANT (a `keepGrantId` given: a successful arm, or the
 * alarm while the key stands) also leaves every autonomy grant that is BOTH
 * created less than `AUTONOMY_CODE_LIFETIME_SECONDS` before `nowSeconds` AND
 * still holding an unexchanged code (review WR-01, narrowed by R2-WR-02).
 * `alsoKeep` covers a sibling sign-in only once its arm has reached the
 * object. Its grant exists earlier than that: the sign-in mints it, builds its
 * answer, and only then sends the arm. The Claude client submits the form
 * twice, about 1.4 seconds apart, so a first arm's sweep regularly lands in
 * that window. Revoking the sibling's grant there makes the sibling's arm fail,
 * and its fail-toward-off then ends the first arm's key too, so the person is
 * left with none. Such a grant's code is unexchanged, because only its own arm
 * exchanges it, and arms run one at a time. So a young grant is spared only
 * when its stored record (`storedGrantOf`) still shows an unexchanged code:
 * that grant is either about to be armed, or ends by itself when the library's
 * ten-minute expiry on it runs out.
 *
 * A young grant that WAS exchanged is not spared (review R2-WR-02). Two kinds
 * exist, and both land on the double-submit path, where every grant is young:
 * the grant a re-arm replaced, when the revoke of it by id failed; and the
 * grant of an arm that died after its exchange. An exchanged grant has no
 * expiry of its own, so sparing it once left it live until the person's next
 * sign-in. The revoke by id (`revokeAutonomyGrant`) is best effort, and this
 * sweep is its backstop. When the listing lags and this sweep cannot see the
 * grant either, the alarm's sweep finds it later. A young grant whose record
 * cannot be read is spared and the answer is `incomplete`. A grant with no
 * readable `createdAt` is treated as old.
 *
 * A sweep that ENDS the key (`keepGrantId` null: a failed arm, the standing
 * check, the alarm job once the key has ended) leaves only `alsoKeep`. It does
 * not apply the age rule, because leaving young grants there could leave a
 * live grant with no record.
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
  nowSeconds: number = Math.floor(Date.now() / 1000),
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
    if (
      keepGrantId !== null &&
      grant.createdAt !== null &&
      nowSeconds - grant.createdAt < AUTONOMY_CODE_LIFETIME_SECONDS
    ) {
      // Young. Spared only while its code is unexchanged (review R2-WR-02).
      const stored = await storedGrantOf(kv, userId, grant.id);
      if (stored.kind === "absent") continue;
      if (stored.kind === "unreadable") {
        outcome = "incomplete";
        continue;
      }
      if (stored.codeUnexchanged) continue;
    }
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
 * Best effort (review R2-WR-02). The caller does not act on `incomplete`: the
 * arm's sweep that follows revokes the grant anyway, because an exchanged
 * grant is never spared for being young, and when the listing does not show
 * it yet, the alarm's sweep finds it later.
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
