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
// object, so it reaches no password. It reaches the rest: the Apple ID is a
// plain field on the object, so a copy still answers the draft sender address,
// the DAV cache key and the organiser match. Only `passwordOf` refuses, and
// this sentence used to say "reaches nothing", which is a bigger claim than the
// WeakMap can back (code review IN-05). The entry also dies with its principal:
// when the request is over and the object is gone, so is the password. Nothing
// here holds a password under a string key, and nothing here may start to.
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
// function with them. The form constructor exists now: `principalFromProps`,
// added with the login page in Phase 11, is how a signed-in person's grant
// becomes a principal (code review IN-01).
//
// It lives at the root rather than inside one of the protocol trees because
// both the mail tree and the DAV tree will need it, and those two trees must
// not import each other. A root module is the one place both can reach without
// either reaching into the other. For the same reason this module imports no
// protocol tree itself.
//
// **One rule, not one per tree.** `userIdOf` is meant to be the only place in
// the repository that turns an address into a user id. Two functions that do
// that job are two rules, and two rules drift: the day they disagree about one
// input, one person becomes two users, or two people become one. Tests hold no
// second copy either. They compare a result with a literal from
// `test/fixtures/user-id-vectors.ts`, which is the spec this function is built
// from.
//
// The same goes for MASKING. `maskAppleId` is the only place in the repository
// that builds the masked form of an address, and it calls `normaliseAppleId`
// rather than folding again. The tool that answers "which account is this
// connection on" and the owner's grants script both call it. A mask written
// inline at a call site is how two forms drift until one of them stops masking.
//
// Since Phase 11 that one rule is spread over TWO exported functions, and the
// split is what keeps it one rule rather than making it two.
// `normaliseAppleId` folds an address; `userIdOf` folds it and then digests the
// folded string. `userIdOf` does not repeat a single step — it calls the other
// one — so there is still exactly one place the folding is written down.
//
// The second function exists because the door needs the comparison to be
// SYNCHRONOUS. It decides on every served request whether the address in the
// grant is still on the allow list, and `src/mcp/api-handler.ts` neither throws
// nor awaits inside `fetch`: an await there would put a gap in front of the
// 401. Web Crypto has no synchronous digest, so a comparison that went through
// `userIdOf` would have to await one. Comparing folded addresses instead needs
// no digest at all.
//
// The alternative — a second, sync folding function for the door — is the
// drift this paragraph exists to prevent. The day it disagreed with this one
// about a single input, an address on the list would stop matching the grant
// built from it, or worse, one that was removed would keep matching.
//
// That "only place" is not yet true, and the gap is known and dated. The cache
// key hash in the DAV tree's discovery module is a second site: it hashes the
// Apple ID as given, with no trim and no lowercasing. It is left alone on
// purpose in this phase. Phase 10 replaces it with the user id from here.
//
// This module ships. The door in `src/mcp/api-handler.ts` builds a principal
// from the grant's props on every served request, and the login page builds one
// when someone signs in. It stopped being groundwork in Phase 11, and this line
// went on saying otherwise until code review IN-01 named it.
//
// This module contains no logging calls of any kind and must never acquire any.

import { isConfiguredSecret } from "./configured-secret";
import type { OwnerMailSecrets } from "./env";
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
 * Fold an Apple ID into the one spelling this server compares and hashes. Or
 * refuse it.
 *
 * The folded form is the trimmed, lowercased address. A refusal is `null`.
 *
 * **It is synchronous, and that is the reason it exists apart from `userIdOf`**
 * rather than a convenience. The door compares the address in a grant against
 * the allow list on every served request, inside a `fetch` that must neither
 * throw nor await. There is no synchronous digest on the platform, so a
 * comparison routed through `userIdOf` would have to await one. Comparing
 * folded addresses needs no digest at all.
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
 * Nothing else is folded. A `+tag` address is its own user, and the same name
 * at each of Apple's three mail domains is three users. Folding those would
 * make two people one user. No Unicode normalisation is applied either, because
 * no input outside ASCII is accepted in the first place.
 *
 * Changing any of this for an input that is already accepted re-keys that
 * user's stores, because the digest below is taken over what this returns.
 * Refusing more later is safe. Accepting more, or accepting differently, is
 * not. `test/fixtures/user-id-vectors.ts` is the spec both halves are held to.
 */
export function normaliseAppleId(value: unknown): string | null {
  // A caller may hand over anything at runtime, whatever the type says.
  if (typeof value !== "string") return null;

  // 1. The cap, on the input as typed, in UTF-16 code units. Before the trim.
  if (value.length > MAX_TYPED_LENGTH) return null;

  // 2. Trim the ends only. Nothing is ever removed from the middle.
  const trimmed = value.trim();

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

  return folded;
}

/**
 * The mask body: three U+2022 BULLET characters, written as escapes.
 *
 * The escape rather than the character, so nothing in a diff or an editor can
 * turn it into three middle dots or three full stops without the change being
 * visible. One of those is not a mask.
 */
const MASK_BODY = "\u2022\u2022\u2022";

/**
 * The masked form of an Apple ID: first character, three bullets, the domain.
 *
 * `u•••@example.invalid`. This is the ONE masking rule in the repository. The
 * `account_whoami` tool calls it, and so does the owner's grants script. A
 * second mask written inline at either call site is how two forms drift until
 * one of them stops masking.
 *
 * **It calls `normaliseAppleId` and folds nothing itself.** That is the same
 * habit `userIdOf` keeps, and for the same reason: two places that fold an
 * address are two rules, and two rules drift.
 *
 * **What it reveals, and why that is enough.** The first character of the local
 * part and the whole domain. D4 settled that: the question this answers is
 * "which account is this connection on", asked by someone on a shared laptop,
 * and the first character plus the domain answers it. The full address would
 * also answer it, and would put a whole address into a tool response — text the
 * model reads and may quote back into a draft, an event or a later message.
 * That exception is recorded in `.claude/CLAUDE.md` § 4 (LIFE-06, D4).
 *
 * **A refusal is three bullets and nothing else.** Every input
 * `normaliseAppleId` turns away — a value that is not a string included — comes
 * back as the fixed body with no domain and no first character. What was refused
 * is never echoed, so there is nothing a typed address could ride out on.
 *
 * **It keeps nothing and never throws.** No cache, no memo, no message built
 * from the input. A memo here would hold every address ever typed.
 *
 * **The full address is deliberately not available from this module in any form
 * meant for a response.** `Principal.appleId` carries it because the wire needs
 * it — it is the login and the draft sender address — not because a response
 * may hold it. Widening this function, or adding a second one that returns
 * more, is a decision on the safety boundary rather than a refactor.
 */
export function maskAppleId(value: unknown): string {
  const folded = normaliseAppleId(value);
  if (folded === null) return MASK_BODY;

  // `normaliseAppleId` already guarantees exactly one at sign with at least one
  // character on each side, so both of these are in range.
  const at = folded.indexOf("@");
  return `${folded[0]}${MASK_BODY}${folded.slice(at)}`;
}

/**
 * Turn an Apple ID, exactly as typed, into a user id. Or refuse it.
 *
 * The user id is the full SHA-256 of the folded address, as 64 lowercase hex
 * characters. It is never shortened. A refusal is `null`.
 *
 * **It returns a Promise.** The platform's digest has no synchronous form, so
 * every caller awaits. A call that is not awaited holds a Promise, not an id.
 *
 * **Every rule about which addresses are accepted lives one function up**, in
 * `normaliseAppleId`, and this one adds none of its own. It refuses exactly
 * what that refuses, for exactly the reasons written there, and then digests
 * what it returns. Step 7 is the only step that lives here.
 *
 * It never throws and builds no message, for the same reason the folding does
 * not: there is nothing the typed address could ride out on.
 */
export async function userIdOf(appleId: string): Promise<string | null> {
  const folded = normaliseAppleId(appleId);
  if (folded === null) return null;

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
 * The two constructors differ on padding, on purpose (D-18). The env
 * constructor carries the binding untouched, padding included, so today's wire
 * bytes do not change. The props constructor REFUSES an address the trim would
 * change, so a principal built from props never carries padding. Neither one
 * ever changes the address it was given.
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
 * Whether a password may be stored at all (D-19).
 *
 * Two refusals. A password that is only white space is no password: another
 * module already treats such a secret as unset, and this one now gives the same
 * answer. And a password holding any control character, which is any code unit
 * below 0x20, or 0x7F. That covers CR, LF and NUL.
 *
 * CR and LF are the ones that matter. A login is one command line, and a line
 * ending inside the password would end that line early and start a second
 * command. The mail tree's quoting helper already refuses them before a
 * password reaches a command line, and it stays as the second layer. Refusing
 * here means no later call site has to remember to go through it.
 *
 * The test is on code units and uses no pattern, so this file needs no escape
 * sequence for a control character. It answers yes or no and builds nothing
 * from the password. A real app password holds no control character, so for
 * valid credentials nothing changes.
 *
 * **No shape check is here, and the one that exists is deliberately not the
 * four-groups-of-four rule.** `couldBeAppPassword` in
 * `src/auth/login-handler.ts` is where a submitted value's plausibility is
 * judged, and it refuses only what cannot be an app-specific password under any
 * grammar — Apple publishes no format, so affirming the remembered one would
 * lock out a legitimate person behind a message that will not say why. Read its
 * docstring before adding anything here.
 *
 * The two are ordered and the order matters. That one runs FIRST and only on
 * the login path, where a form was submitted and a refusal can be answered with
 * a page. This one runs SECOND and guards EVERY construction site, including
 * the props read at the door on a later request where there is no form and no
 * reader to tell.
 */
function isUsablePassword(appPassword: string): boolean {
  if (appPassword.trim().length === 0) return false;
  for (let index = 0; index < appPassword.length; index += 1) {
    const code = appPassword.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/**
 * Build one principal and put its password in the holder.
 *
 * The one place a principal is made, so both constructors refuse every address
 * the id function refuses, for the same reason. The props constructor refuses
 * an untrimmed address on top of that, before it gets here (D-18). Both refuse
 * the same passwords too, because that check is here (D-19). A new object
 * every call, never a shared one.
 */
async function build(appleId: string, appPassword: string): Promise<Principal> {
  if (!isUsablePassword(appPassword)) throw new ImapAuthError();

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
 * Apple ID the id function turns away. So is a password that is only white
 * space or holds a control character (D-19). The check is also what narrows
 * each binding from "string or undefined" to a string.
 */
export async function principalFromEnv(
  env: OwnerMailSecrets,
): Promise<Principal> {
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
 * **The Apple ID must already be trimmed (D-18).** An address with a space, a
 * line ending or any other white space at either end is refused, even though
 * the id function would accept it. The login page stores the trimmed address,
 * so nothing this server wrote looks like that. The env constructor does not
 * share this check: see `Principal`.
 *
 * **The password must be usable (D-19).** One that is only white space, or that
 * holds a control character, is refused. Both constructors share that check.
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

  // D-18. Props are written only by this server's own login page, and it
  // stores the trimmed address. So an address the trim would change means a bug
  // or tampering, and it is refused. Without this the id function would trim
  // its own copy and say yes, and the principal would then carry padding or a
  // line ending that the wire layer, or Apple, turns down on every call.
  if (appleId !== appleId.trim()) throw new ImapAuthError();

  return build(appleId, appPassword);
}
