// Which client a request's grant belongs to (Phase 26, D-35).
//
// WHY THIS EXISTS. A scheduled job will call this server's mail tools with the
// autonomy key, and the owner ruled out indexing mail with it. So a recall
// build step must know which client the request's grant was issued to. The
// OAuth library hands the API handler the grant's props and nothing else, and
// the props are the same for both grants, so the props cannot tell them apart.
// The bearer token can. Its first two segments are the library's user id and
// grant id, and the library keeps the grant's client id in plain text in that
// grant's record in the OAuth store.
//
// WHEN IT RUNS. The door builds the reader synchronously and reads nothing: it
// only captures the request and the store. The store is read the first time
// the reader is called, which is only when a recall step is about to run, and
// the answer is kept for the rest of the request. So the door still neither
// awaits nor throws, and a request that runs no step reads nothing at all.
//
// THE TOKEN. Only the two id segments are kept. The third segment is the
// token's secret; it is never assigned, returned or stored here. The library
// has already checked the whole token before this handler runs, so the two ids
// name a grant the request really holds.
//
// FAILS TOWARD NOT INDEXING. No header, a malformed one, a missing record, a
// record without a client id, or a store error: the answer is null, and null
// runs no step. A missed step only delays the build.
//
// This module logs nothing (./.claude/CLAUDE.md §4), and no caught value is
// read.

/**
 * What an id segment may contain. The library's own ids use letters, digits,
 * `-` and `_`, and this server's user ids are lowercase hex. Anything else is
 * not a key this reader will build.
 */
const ID_SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;

/** The authorization scheme the library accepts. */
const BEARER = "Bearer ";

/**
 * A lazy reader of the client id of the grant the request came in on.
 *
 * Building it reads nothing. The first call reads that grant's record once;
 * later calls answer the same promise. It never throws and never rejects.
 */
export function grantClientOf(
  request: Request,
  kv: KVNamespace,
): () => Promise<string | null> {
  let answer: Promise<string | null> | null = null;
  return () => {
    answer ??= readGrantClient(request, kv);
    return answer;
  };
}

/** The one read behind `grantClientOf`. Never rejects. */
async function readGrantClient(request: Request, kv: KVNamespace): Promise<string | null> {
  try {
    const header = request.headers.get("Authorization");
    if (header === null || !header.startsWith(BEARER)) return null;

    const segments = header.slice(BEARER.length).split(":");
    if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
      return null;
    }
    // The first two segments only. The third is the secret, and is not named.
    const [userSegment, grantSegment] = segments;
    if (userSegment === undefined || grantSegment === undefined) return null;
    if (!ID_SEGMENT.test(userSegment) || !ID_SEGMENT.test(grantSegment)) return null;

    // The key the installed library (0.10.3) keeps a grant under.
    const record: unknown = await kv.get(`grant:${userSegment}:${grantSegment}`, {
      type: "json",
    });
    if (typeof record !== "object" || record === null) return null;
    const clientId = (record as { clientId?: unknown }).clientId;
    return typeof clientId === "string" && clientId.length > 0 ? clientId : null;
  } catch {
    // A store that fails answers the same as a grant that is not there. The
    // caught value is not read.
    return null;
  }
}
