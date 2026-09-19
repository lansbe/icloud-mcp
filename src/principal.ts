// The principal: who a request is acting for.
//
// Today this module holds one thing, the function that turns an Apple ID into a
// user id. The user id is what every per-user store will be keyed by, so it has
// to come out the same for the same person every time, and differently for a
// different person every time.
//
// It lives at the root rather than inside one of the protocol trees because
// both the mail tree and the DAV tree will need it, and those two trees must
// not import each other. A root module is the one place both can reach without
// either reaching into the other. For the same reason this module imports no
// protocol tree itself.
//
// **One function, not one per tree.** `userIdOf` is meant to be the only place
// in the repository that turns an address into a user id. Two functions that do
// that job are two rules, and two rules drift: the day they disagree about one
// input, one person becomes two users, or two people become one. Tests hold no
// second copy either. They compare a result with a literal from
// `test/fixtures/user-id-vectors.ts`, which is the spec this function is built
// from.
//
// That "only place" is not yet true, and the gap is known and dated. The cache
// key hash in the DAV tree's discovery module is a second site: it hashes the
// Apple ID as given, with no trim and no lowercasing. It is left alone on
// purpose in this phase. Phase 10 replaces it with the user id from here.
//
// Nothing that ships today calls this module. It is groundwork.
//
// This module contains no logging calls of any kind and must never acquire any.

const ENCODER = new TextEncoder();

/**
 * The longest input accepted, in UTF-16 code units, measured as typed.
 *
 * 254 is the longest address a mail system will carry. The count is taken
 * before the trim, so padding counts against it.
 */
const MAX_TYPED_LENGTH = 254;

function hex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Turn an Apple ID, exactly as typed, into a user id. Or refuse it.
 *
 * The user id is the full SHA-256 of the trimmed, lowercased address, as 64
 * lowercase hex characters. It is never shortened. A refusal is `null`.
 *
 * **It returns a Promise.** The platform's digest has no synchronous form, so
 * every caller awaits. A call that is not awaited holds a Promise, not an id.
 *
 * **It never throws, and it builds no message.** Every refusal is a plain
 * `null`, a value that is not a string included. No error is constructed
 * anywhere in this function, so there is nothing the typed address could ride
 * out on. The caller turns the `null` into its own fixed refusal.
 *
 * **It keeps nothing.** There is no cache, no memo and no table at module
 * scope. A memo here would hold every address ever typed, failed sign-ins
 * included, in memory shared by every user of the isolate.
 *
 * **The order of the steps is part of the rule.** Two orderings are costly to
 * get wrong, and each has a spec row that tells the two orders apart:
 *
 * - The cap is measured BEFORE the trim. A 254-character address with one
 *   trailing space is 255 as typed, and is refused.
 * - The ASCII check runs BEFORE lowercasing. The Kelvin sign is not ASCII, but
 *   it lowercases to a plain `k`. Checked after lowercasing, that address
 *   would be accepted and would share a user id with the plain spelling, so two
 *   different typed strings would become one user.
 *
 * Nothing is folded. A `+tag` address is its own user, and the same name at
 * each of Apple's three mail domains is three users. Folding would make two
 * people one user. No Unicode normalisation is applied either, because no
 * input outside ASCII is accepted in the first place.
 *
 * Changing any of this for an input that is already accepted re-keys that
 * user's stores. Refusing more later is safe. Accepting more, or accepting
 * differently, is not.
 */
export async function userIdOf(appleId: string): Promise<string | null> {
  // A caller may hand over anything at runtime, whatever the type says.
  if (typeof appleId !== "string") return null;

  // 1. The cap, on the input as typed, in UTF-16 code units. Before the trim.
  if (appleId.length > MAX_TYPED_LENGTH) return null;

  // 2. Trim the ends only. Nothing is ever removed from the middle.
  const trimmed = appleId.trim();

  // 3. Printable ASCII only, 0x21 to 0x7E. BEFORE lowercasing.
  for (let index = 0; index < trimmed.length; index += 1) {
    const code = trimmed.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) return null;
  }

  // 4. Lowercase. Never the locale-aware form: in a Turkish locale that one
  //    turns a plain capital I into a dotless i, and the same person would get
  //    a different user id on a different machine.
  const folded = trimmed.toLowerCase();

  // 5. Empty input, and input that was only white space, both end up here.
  if (folded.length === 0) return null;

  // 6. Exactly one at sign, with at least one character on each side.
  const at = folded.indexOf("@");
  if (at <= 0) return null;
  if (at !== folded.lastIndexOf("@")) return null;
  if (at === folded.length - 1) return null;

  // 7. The full SHA-256 of the UTF-8 bytes, as 64 lowercase hex characters.
  const digest = await crypto.subtle.digest("SHA-256", ENCODER.encode(folded));
  return hex(digest);
}
