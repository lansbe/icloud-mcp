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
//   - every bad link, spent link, expired link and missing copy: one empty 410;
//   - the spent-mark store failing: an empty 503;
//   - otherwise: 200, the copy's exact bytes, always as a file to save and never
//     as a page to show, and the copy is deleted once the stream ends.
//
// This module contains no logging calls of any kind and must never acquire
// any. A caught value is never read.

import type { Env } from "../env";
import { deleteStaged, openSaved } from "../staging/r2";
import { SAVE_ROUTE_PATH, claimSaveLink } from "./link";

/** The headers every answer carries: nothing here may be cached. */
const NO_STORE = { "cache-control": "no-store" } as const;

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

/** The one answer for every link that does not lead to a file. */
function gone(): Response {
  return new Response(null, { status: 410, headers: NO_STORE });
}

/**
 * Serve one download.
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
  if (request.method !== "GET") {
    return new Response(null, { status: 405, headers: { allow: "GET", ...NO_STORE } });
  }

  const pathname = new URL(request.url).pathname;
  if (!pathname.startsWith(SAVE_ROUTE_PATH)) return gone();
  const token = pathname.slice(SAVE_ROUTE_PATH.length);

  let claim: Awaited<ReturnType<typeof claimSaveLink>>;
  try {
    claim = await claimSaveLink(env, token, clock());
  } catch {
    return new Response(null, { status: 503, headers: NO_STORE });
  }
  if (claim === null) return gone();
  if (claim.state === "expired") {
    // The link is dead, so its copy is too: remove it now rather than leave it
    // for the bucket's sweep. A failed delete still answers 410.
    try {
      await deleteStaged(env, claim.userId, claim.key);
    } catch {
      // The bucket's sweep is the backstop.
    }
    return gone();
  }

  const { userId, key } = claim;
  const saved = await openSaved(env, userId, key);
  if (saved === null) return gone();
  if (saved.sizeBytes !== claim.sizeBytes) {
    // Not the copy the link was sealed for. Serve nothing.
    await saved.body.cancel().catch(() => undefined);
    return gone();
  }

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
