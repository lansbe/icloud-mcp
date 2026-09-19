// The principal: who a request is acting for.
//
// This module holds three things. The function that turns an Apple ID into a
// user id. The principal, which is the small object that says who a request is
// for. And the holder that keeps that person's app password away from it.
//
// The user id is what every per-user store will be keyed by, so it has to come
// out the same for the same person every time, and differently for a different
// person every time.
//
// **The principal travels. The password does not.** A principal is a frozen
// object with two fields, the user id and the Apple ID, and neither is a
// secret. It gets passed through mail code and DAV code, and anything that is
// passed around ends up copied, turned into JSON, or put beside an error
// sooner or later. So the password is not on it. The password sits in a
// WeakMap that is private to this module and is keyed by the very object that
// was built. A spread copy, a clone or a look-alike made by hand is a different
// object, so it reaches nothing. The entry also dies with its principal: when
// the request is over and the object is gone, so is the password. Nothing here
// holds a password under a string key, and nothing here may start to.
//
// `passwordOf` is the one reader. Phase 9 adds a scan rule that counts the
// files allowed to import it.
//
// **Every refusal is the same error with nothing in it.** A bad grant, a
// missing secret, an address the id function turns away and a copied principal
// all raise the existing auth error, built with no argument. No message is put
// together from the input anywhere in this module, so there is nothing the
// address or the password could ride out on.
//
// `principalFromEnv` is temporary. It reads the two Worker secrets, which is
// how the one owner is identified today. Phase 13 removes the secrets and this
// function with them. There is no form constructor yet: that one waits for the
// login page in Phase 11.
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

import { isConfiguredSecret } from "./configured-secret";
import type { Env } from "./env";
import { ImapAuthError } from "./errors";

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

/**
 * Who a request is acting for.
 *
 * Two fields, and neither is a secret. `userId` is what stores are keyed by.
 * `appleId` is the address exactly as it was given to the constructor, with no
 * trim and no lowercasing, because it is what gets sent to Apple and changing
 * it would change bytes on the wire. `userIdOf` trims and lowercases its own
 * copy, so the id comes out the same either way.
 *
 * The object is frozen, so `readonly` holds at run time too. The password is
 * not here. See `passwordOf`.
 */
export interface Principal {
  readonly userId: string;
  readonly appleId: string;
}

/**
 * The passwords, keyed by the very principal object each one belongs to.
 *
 * Never exported. Apart from the encoder and the length cap it is the only
 * state at module scope, and it must stay that way: a table keyed by an
 * address or a user id would outlive the request and would answer for a
 * look-alike. A WeakMap keyed by the object does neither.
 */
const PASSWORDS = new WeakMap<Principal, string>();

/**
 * Build one principal and put its password in the holder.
 *
 * The one place a principal is made, so both constructors refuse the same
 * addresses for the same reason. A new object every call, never a shared one.
 */
async function build(appleId: string, appPassword: string): Promise<Principal> {
  const userId = await userIdOf(appleId);
  if (userId === null) throw new ImapAuthError();

  const principal: Principal = Object.freeze({ userId, appleId });
  PASSWORDS.set(principal, appPassword);
  return principal;
}

/**
 * The app password for a principal this module built.
 *
 * It answers only the very object a constructor returned. A spread copy, a
 * clone and an object made by hand all have the right two fields and are all
 * refused with the auth error, because none of them is that object. It never
 * returns `undefined` and never returns an empty string: a caller that got
 * either would send an empty password to Apple.
 *
 * It is sync. The constructors are async only because the id function is.
 */
export function passwordOf(principal: Principal): string {
  const password = PASSWORDS.get(principal);
  if (password === undefined) throw new ImapAuthError();
  return password;
}

/**
 * The principal for the one owner, read from the two Worker secrets.
 *
 * **Temporary.** Phase 13 removes the secrets and this function. Until then it
 * is how code that still runs as the owner gets a principal.
 *
 * A secret that is unset or empty is refused with the auth error, and so is an
 * Apple ID the id function turns away. The check is also what narrows each
 * binding from "string or undefined" to a string.
 */
export async function principalFromEnv(env: Env): Promise<Principal> {
  const appleId = env.APPLE_ID;
  const appPassword = env.APPLE_APP_PASSWORD;
  if (!isConfiguredSecret(appleId)) throw new ImapAuthError();
  if (!isConfiguredSecret(appPassword)) throw new ImapAuthError();

  return build(appleId, appPassword);
}

/**
 * The principal for a stored grant, built from the grant's props.
 *
 * Exactly one shape is accepted: `{ v: 1, appleId, appPassword }`. `v` is the
 * number 1, both others are non-empty strings, and there is no other key.
 * Anything else is refused with the auth error. That includes a grant stored
 * before this milestone, which holds a fixed owner id and none of these
 * fields. Such a grant must never become a session.
 *
 * **One argument, and no environment.** There is no fallback to the Worker
 * secrets for a grant that does not check out. A fallback would turn a broken
 * grant from anyone into the owner's session.
 *
 * **The user id is never read from the props.** It is derived from the Apple
 * ID every time, so the two cannot disagree. A props object that carries a
 * user id of its own has an extra key and is refused for that.
 *
 * Each field is read once, into a local, and only the locals are used after
 * the checks. What was checked is then what gets used, whatever the object
 * does on a second read.
 */
export async function principalFromProps(props: unknown): Promise<Principal> {
  if (typeof props !== "object" || props === null || Array.isArray(props)) {
    throw new ImapAuthError();
  }
  if (!("v" in props) || !("appleId" in props) || !("appPassword" in props)) {
    throw new ImapAuthError();
  }

  // Exactly the three keys, as the object's own. A fourth key of any kind, a
  // hidden one or a symbol included, is refused.
  const keys = Object.keys(props).sort();
  if (
    keys.length !== 3 ||
    keys[0] !== "appPassword" ||
    keys[1] !== "appleId" ||
    keys[2] !== "v" ||
    Reflect.ownKeys(props).length !== 3
  ) {
    throw new ImapAuthError();
  }

  const version = props.v;
  const appleId = props.appleId;
  const appPassword = props.appPassword;
  if (version !== 1) throw new ImapAuthError();
  if (!isConfiguredSecret(appleId)) throw new ImapAuthError();
  if (!isConfiguredSecret(appPassword)) throw new ImapAuthError();

  return build(appleId, appPassword);
}
