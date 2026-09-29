// The download route: GET /save/<link> (Phase 29.1).
//
// The one public path this server has besides the sign-in form. It needs no
// sign-in. It serves exactly one thing: a saved copy the save tool made, named
// by a sealed link the save tool minted. It opens no mail connection, takes no
// lease and reads no sign-in, and this module imports nothing that could: only
// the link helpers, the bucket helpers and the environment's type. Who a copy
// belongs to comes from the unsealed link and from nothing else in the request.
//
// What each answer is:
//   - anything but GET: 405, and nothing is read;
//   - every bad link, spent link, expired link and missing copy: one empty 410,
//     and an expired link's copy is deleted first;
//   - more than thirty well-formed requests a minute from one address: an
//     empty 429, before the link is opened;
//   - the brake, the spent-mark store or the bucket failing: an empty 503;
//   - otherwise: 200, the copy's exact bytes, always as a file to save and never
//     as a page to show, and the copy is deleted once the stream ends.
//
// This module contains no logging calls of any kind and must never acquire
// any. A caught value is never read.

import type { Env } from "../env";
import { type SavedStream, deleteStaged, openSaved } from "../staging/r2";
import { SAVE_ROUTE_PATH, type SaveClaim, claimSaveLink, hasSaveTokenShape } from "./link";

/**
 * Every answer that is not a download, built in one place so the bodies and
 * headers cannot drift apart. Always an empty body and no-store; a 405 also
 * says which method works. Nothing here names why a link was refused.
 */
function refuse(status: 405 | 410 | 429 | 503): Response {
  const headers: Record<string, string> = { "cache-control": "no-store" };
  if (status === 405) headers.allow = "GET";
  return new Response(null, { status, headers });
}

/**
 * The brake's key for a request with no connecting-address header. Such a
 * request is counted under this one shared key, never let through unbraked.
 */
const SHARED_ADDRESS_KEY = "unknown-address";

/** The brake's key: the connecting address, or the shared key. */
function addressKey(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? SHARED_ADDRESS_KEY;
}

/**
 * The download's headers, fixed. The filename is the fixed word "download",
 * never the attachment's own name: that name is a stranger's and does not go
 * into a header. The client picks the name on disk from the tool's answer.
 */
const DOWNLOAD_HEADERS = {
  "content-type": "application/octet-stream",
  "content-disposition": 'attachment; filename="download"',
  "x-content-type-options": "nosniff",
  "cache-control": "no-store",
  "content-security-policy": "sandbox; default-src 'none'",
  "referrer-policy": "no-referrer",
} as const;

/**
 * Serve one download.
 *
 * The checks run in a fixed order. The method first and the token's shape
 * second, both before anything is read, so a HEAD or any other prefetch never
 * reaches the spent mark. Then the per-address brake (29.1-WORDING.md decision
 * 3), so probing costs the prober a 429 before any store read and a refused
 * request never spends a link. A malformed token is refused before the brake
 * and does not count. Then the claim, which spends the link.
 *
 * `clock` is injectable so a test can pin the instant; production passes
 * nothing and gets the wall clock.
 */
export async function handleSaveDownload(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  clock: () => number = () => Date.now(),
): Promise<Response> {
  if (request.method !== "GET") return refuse(405);

  const pathname = new URL(request.url).pathname;
  const token = pathname.startsWith(SAVE_ROUTE_PATH)
    ? pathname.slice(SAVE_ROUTE_PATH.length)
    : "";
  if (!hasSaveTokenShape(token)) return refuse(410);

  let claim: SaveClaim | null;
  let saved: SavedStream | null;
  try {
    // A key and nothing else: the limit and the window live on the binding.
    const brake = await env.SAVE_IP_LIMITER.limit({ key: addressKey(request) });
    if (!brake.success) return refuse(429);
    claim = await claimSaveLink(env, token, clock());
    if (claim === null) return refuse(410);
    if (claim.state === "expired") {
      // The link is dead, so its copy is too: remove it now rather than leave
      // it for the bucket's sweep. A failed delete still answers 410.
      await deleteStaged(env, claim.userId, claim.key).catch(() => undefined);
      return refuse(410);
    }
    saved = await openSaved(env, claim.userId, claim.key);
  } catch {
    // The brake, the mark store or the bucket failed. Serve nothing.
    return refuse(503);
  }
  if (saved === null) return refuse(410);
  if (saved.sizeBytes !== claim.sizeBytes) {
    // Not the copy the link was sealed for. Serve nothing.
    await saved.body.cancel().catch(() => undefined);
    return refuse(410);
  }

  const { userId, key } = claim;
  const { readable, writable } = new FixedLengthStream(saved.sizeBytes);
  const piped = saved.body.pipeTo(writable).then(
    () => undefined,
    () => undefined,
  );
  // The copy is deleted once the stream ends, whichever way it ends. A broken
  // download has already spent the link, so the copy is of no further use.
  ctx.waitUntil(
    piped
      .then(() => deleteStaged(env, userId, key))
      .catch(() => undefined),
  );

  // The length is stated as a header as well as fixed by the stream. The
  // stream alone did not put it on the answer as the in-process service
  // binding delivers it (measured in test/save-tracer.test.ts), and the client
  // needs a real length to know the download is whole. The stream still holds
  // the body to exactly this many bytes.
  return new Response(readable, {
    status: 200,
    headers: { ...DOWNLOAD_HEADERS, "content-length": String(saved.sizeBytes) },
  });
}
