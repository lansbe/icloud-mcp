// THE ONLY MODULE IN THIS REPOSITORY THAT MAY FETCH A CS:SOURCE SUBSCRIPTION
// FEED.
//
// This is the structural half of the choke point: `fetchSubscriptionFeed`
// takes a url and nothing else, attaches no credential, and is the sole
// permitted `fetch()` caller under `src/feed/`. The detective half is the
// `SUBSCRIPTION_FEED_FETCH_CALL` count constraint in
// `scripts/forbidden-tokens.mjs`, run from the test suite and the pre-commit
// hook — the same two-layer shape `src/dav/transport.ts` and
// `src/mail/socket.ts` already carry for their own choke points.
//
// This CANNOT live inside `src/dav/` and cannot reuse `davFetch`. A `CS:source`
// href is a value iCloud's PROPFIND response supplies, but it names an
// ARBITRARY THIRD-PARTY HOST the account does not control — the debug session
// that discovered this measured it live: `sm-cal.apple.com`, anonymously
// readable, `content-type: application/octet-stream`. `davFetch`
// (`./transport.ts`) attaches the Apple ID and app-specific password to
// whatever URL it is handed, on every call, unconditionally — that is exactly
// correct for a request to iCloud's own CalDAV shard and exactly wrong for a
// request to a stranger's server. Routing a subscription feed fetch through it
// would post the user's iCloud credential to a third party. So this is a
// second, deliberately separate seam: uncredentialed by construction, with no
// import of `davAuthHeader`, `env`, or any credential-bearing value anywhere in
// this file.
//
// This module contains no logging calls of any kind and must never acquire any.

import { DavConnectError } from "../dav/errors";

/**
 * The ceiling on one subscription feed's response body, in bytes.
 *
 * The debug session measured the real feed this project has actually seen:
 * 22,846 bytes for 34 `VEVENT`s, roughly 650 bytes per event. 2 MiB is wide
 * headroom above that — comfortably enough for a much larger personal
 * subscription (thousands of events) — while staying well inside a single
 * request's CPU and memory budget. It is enforced twice: once against a
 * present `Content-Length` header, before the body is read at all, and once
 * against the actual streamed byte count, because the real feed's
 * `content-type` was `application/octet-stream` with no guarantee any server
 * sends an honest — or any — `Content-Length`.
 */
export const MAX_SUBSCRIPTION_FEED_BYTES = 2 * 1024 * 1024;

/**
 * Fetch one `CS:source` subscription feed and return its body as text.
 *
 * Every failure — a non-https url, a network throw, a non-2xx response, a
 * non-https final url after a redirect, or a body over the size cap — maps to
 * `DavConnectError`. No new error category is invented, following the "no
 * fifth error category" discipline `src/dav/calendar.ts`'s `assertRange` and
 * `src/dav/icalendar.ts`'s unsupported-charset handling already sit on: the
 * caller cannot act differently on any of these distinctions, and the fixed
 * safe message already says what to do.
 *
 * **No `Authorization` header is ever set — not conditionally, not for a
 * same-host request, never.** That is the whole point of this module existing
 * apart from `./transport.ts`.
 *
 * **Redirects are followed normally, unlike `davFetch`'s forced manual
 * policy.** There is no credential attached here for a redirect to leak, so
 * `davFetch`'s reason for the manual policy does not apply; only the FINAL
 * url's scheme is checked, after any redirect completes.
 *
 * A caught value from `fetch` or from the stream reader is never read — not
 * its message, not its stack — on the same discipline every transport-layer
 * catch in this project already follows: a transport failure carries no
 * status, and the value itself can carry anything at all.
 */
export async function fetchSubscriptionFeed(url: string): Promise<string> {
  let requested: URL;
  try {
    requested = new URL(url);
  } catch {
    // Nothing is read from the caught value.
    throw new DavConnectError();
  }
  // Checked BEFORE any network call, so a non-https url costs nothing.
  if (requested.protocol !== "https:") throw new DavConnectError();

  let response: Response;
  try {
    response = await fetch(url);
  } catch {
    // Nothing is read from the caught value.
    throw new DavConnectError();
  }

  if (!response.ok) throw new DavConnectError();

  let finalUrl: URL;
  try {
    finalUrl = new URL(response.url);
  } catch {
    throw new DavConnectError();
  }
  if (finalUrl.protocol !== "https:") throw new DavConnectError();

  // Checked before the body is touched at all. A present, honest
  // Content-Length that already exceeds the cap means the streamed read below
  // never has to run.
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (
      Number.isFinite(parsedLength) &&
      parsedLength > MAX_SUBSCRIPTION_FEED_BYTES
    ) {
      throw new DavConnectError();
    }
  }

  const body = response.body;
  if (body === null) throw new DavConnectError();

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let total = 0;

  for (;;) {
    let result: ReadableStreamReadResult<Uint8Array>;
    try {
      result = await reader.read();
    } catch {
      // Nothing is read from the caught value.
      throw new DavConnectError();
    }
    if (result.done) break;

    total += result.value.byteLength;
    // Refused MID-READ, the moment the running total crosses the cap, rather
    // than after the whole body is materialised — this is the guard that
    // matters for a response with no Content-Length, or one that understates
    // its real size, since the header check above cannot see either shape.
    if (total > MAX_SUBSCRIPTION_FEED_BYTES) {
      await reader.cancel();
      throw new DavConnectError();
    }

    text += decoder.decode(result.value, { stream: true });
  }
  text += decoder.decode();

  return text;
}
