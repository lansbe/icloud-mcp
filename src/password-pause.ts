// The dead-password pause: stop asking Apple for fifteen minutes (LIFE-04).
//
// A revoked or rotated app-specific password turns every tool call into a
// doomed login against a real account. Apple's lockout threshold is
// unpublished, and running into it locks the user out of their own mail in
// Mail.app on their own devices. So when Apple itself refuses the password
// saved in a grant, a marker goes into the OAuth store keyed by that person's
// own derived id, and while it is there the door refuses every call for them
// before anything reaches Apple. The user-facing half of LIFE-04 already
// shipped: the auth error says to reconnect and that retrying will not help.
//
// It lives at the ROOT, for the same reason `./principal.ts` does: the mail
// tree and the DAV tree both call it and those two trees must not import each
// other. A root module is the one place both can reach without either reaching
// into the other. For the same reason this module imports no protocol tree
// itself — it imports the auth error and the principal type, and nothing else.
//
// **ARMING IS THE WHOLE DESIGN, and it is structural rather than a flag.** Two
// traps shape it.
//
// First, many things raise the auth error without Apple refusing anything: a
// grant this server will not read, a password it refuses before any socket, a
// missing staging secret. So the report is called at the three sites where
// Apple itself said no, and nowhere else.
//
// Second, the IMAP login code is SHARED with the sign-in page. If the report
// fired there, a stranger who knows a listed address could pause that person's
// working apps from the login page — breaking the bound the owner accepted in
// Phase 11 (D8: the login limiter "blocks new sign-ins only; a connected client
// keeps working"). So only a principal the DOOR built is armed to report. The
// login page's principal is never armed. Arming is membership of a WeakMap
// private to this module, keyed by the very object, so there is no value a
// caller can pass and no field a caller can set that would arm one.
//
// **The read fails OPEN, and that is the opposite of the allow-list read.** See
// `guardAgainstPause` for the argument. In short: the pause limits attempts at
// Apple. It is not access control.
//
// This module contains no logging calls of any kind and must never acquire any.

import { ImapAuthError } from "./errors";
import type { Principal } from "./principal";

/**
 * The marker's key prefix.
 *
 * **The user id must be interpolated with NOTHING between it and this
 * constant**, not even a space. The `store-key-without-a-user` rule in
 * `scripts/forbidden-tokens.mjs` anchors on a prefix constant spelled like this
 * one and requires the id on the very next character, because a key with no
 * user segment is a key any signed-in caller could name.
 *
 * The version segment is the same hedge the login counter's `authorize-failures:v3:`
 * carries, and `confirm:v2:` and `dav:v1:` before it: a later change to the
 * shape becomes detectable rather than being silently misread as the current
 * one. No older shape is read, so a leftover key is ignored and expires on its
 * own TTL.
 *
 * Exported so a test asserts against the real value rather than against a
 * second copy of it. The owner's runbook lists by this prefix too.
 */
export const PASSWORD_PAUSE_KEY_PREFIX = "password-pause:v1:";

/**
 * How long the pause lasts, in seconds.
 *
 * Fifteen minutes: the TOP of the roadmap's ten-to-fifteen range, chosen in
 * `12-CONTEXT.md` because Apple's own lockout threshold is unpublished and the
 * cost of waiting is smaller than the cost of a locked account. Err long.
 *
 * It is also the marker's TTL, which is what makes the pause self-clearing —
 * there is no sweep to run and nothing to expire by hand. The store's minimum
 * TTL is sixty seconds, so this is comfortably valid.
 */
export const PASSWORD_PAUSE_SECONDS = 900;

/**
 * The marker's key for one person.
 *
 * Private. One key per person, with nothing after the id: the owner's escape in
 * the phase runbook is a prefix listing, and a suffix would break it.
 */
function pauseKey(userId: string): string {
  return `${PASSWORD_PAUSE_KEY_PREFIX}${userId}`;
}

/**
 * The principals that may report a refusal, and the store each would write to.
 *
 * Never exported, and the only state at module scope. It has the same shape as
 * the password holder in `./principal.ts` and for the same reasons: keyed by the
 * very object a constructor returned, so a spread copy, a clone or a look-alike
 * made by hand is a different object and is not armed; and the entry dies with
 * its principal, so nothing here outlives the request.
 *
 * A table keyed by an address or a user id would arm anybody who could name one.
 */
const ARMED = new WeakMap<Principal, KVNamespace>();

/**
 * Check the pause, then arm the principal. The door's one call.
 *
 * It takes the PROMISE the props constructor returned and hands back a promise,
 * so `src/mcp/api-handler.ts`'s `fetch` still neither awaits nor throws: the
 * read happens inside the promise, and every tool already awaits that promise
 * as the first line of its own `try`. A marker present means the promise
 * rejects with the plain auth error, so every tool answers `auth_failed` with
 * the text that already tells the user to reconnect.
 *
 * **THE READ FAILS OPEN, WHICH IS THE OPPOSITE OF `readStoredAllowList`.** That
 * one treats an unreadable store as "nobody", because a store outage must not
 * admit someone who was removed. This one treats an unreadable store as "not
 * paused", because the pause is a brake on attempts at Apple rather than access
 * control — and failing closed would turn a store blip into every tool telling
 * every user that their password had been rejected, which is both false and
 * un-actionable. The caught value is never read.
 *
 * **Whatever the promise resolved to is handed back AS IT IS.** Never spread
 * and never cloned: the password reader answers only that one object (D-16), so
 * a copy would reach no credential and the arming would name an object nothing
 * else holds.
 */
export function guardAgainstPause(
  principal: Promise<Principal>,
  kv: KVNamespace,
): Promise<Principal> {
  return principal.then(async (actor) => {
    let paused = false;
    try {
      paused = (await kv.get(pauseKey(actor.userId))) !== null;
    } catch {
      // Never read the caught value. See the paragraph above: this is the
      // fail-OPEN edge, and it is deliberate.
    }
    if (paused) throw new ImapAuthError();

    ARMED.set(actor, kv);
    return actor;
  });
}

/**
 * Apple refused this principal's saved password. Start the pause.
 *
 * **Who is armed: the door. Who is not: the login page.** That asymmetry is the
 * whole defence against a stranger who knows a listed address pausing that
 * person's working apps from the sign-in page, and it is why this function
 * silently does nothing for an un-armed principal rather than taking a flag.
 * The three call sites are the places Apple itself said no — the mail session,
 * the mail diagnostic, and a DAV 401 — and a fourth would be a change to the
 * safety boundary rather than a refactor.
 *
 * The write swallows its own failure, like `countFailedGuess` one tree over and
 * for the same reason: the store throttles writes to a single key, and a
 * rejection here must not change the answer the caller is about to give. The
 * caught value is never read. Convention 4 forbids logging anywhere under
 * `src/`, so there is nothing to report it to and nothing that should.
 */
export async function reportRefusal(principal: Principal): Promise<void> {
  const kv = ARMED.get(principal);
  if (kv === undefined) return;

  try {
    await kv.put(pauseKey(principal.userId), "1", {
      expirationTtl: PASSWORD_PAUSE_SECONDS,
    });
  } catch {
    // Never read the caught value. See the paragraph above.
  }
}

/**
 * A sign-in Apple accepted. End the pause for that person.
 *
 * Without this, someone who has just made a fresh app-specific password still
 * waits out the pause and reasonably concludes the fix did not work. It takes
 * the user id rather than a principal because the login page has the id already
 * and never arms a principal at all.
 *
 * It swallows its own failure for the same reason the write does. A clear that
 * did not land costs the user the rest of the pause, which is the same position
 * they were in before signing in.
 */
export async function clearPause(
  kv: KVNamespace,
  userId: string,
): Promise<void> {
  try {
    await kv.delete(pauseKey(userId));
  } catch {
    // Never read the caught value.
  }
}
