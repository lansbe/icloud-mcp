// The one definition of who this server will sign in, and keep serving.
//
// **Two sources and two readers, and the two readers ask DIFFERENT questions.**
// An earlier version of this header said the opposite — that both readers asked
// the same question about the same list, so there was one rule here rather than
// one rule each. That premise stopped being true on 2026-09-20, when the owner
// split the storage, and it is replaced rather than left standing.
//
//   - **The seed**, `env.ALLOWED_APPLE_IDS_SEED`, a `vars` entry holding the
//     owner's own address. Read SYNCHRONOUSLY, through `parseAllowList`.
//   - **The store**, `env.ALLOW_LIST_KV`, holding everybody else. Read through
//     `readStoredAllowList`, at LOGIN ONLY, which is already an async path.
//
// **The questions differ because the LIFETIMES differ.** The login page asks
// who may START a session — a once-per-sign-in question, and it may spend a
// store round trip to answer it. The door asks, on every single served request,
// whether this deployment serves anybody at all — and it must answer with no
// I/O, because `createMcpApiHandler`'s `fetch` has a tested contract that it
// never awaits. That contract is what makes an unusable stored credential
// surface as a tool error instead of a 401, and a 401 there would tell the
// client to sign in again when signing in again cannot fix a password Apple has
// revoked. There is no way to read a namespace synchronously, so the door reads
// the seed and only the seed.
//
// **What the door gives up, said plainly rather than left to be discovered.**
// It no longer re-checks membership for a store-listed address. A well-shaped
// grant carrying an address the seed does not name is SERVED — the grant is
// itself the evidence that a login passed the store check when it was minted.
// So removing someone is TWO steps: take them out of the store so they cannot
// sign in again, and revoke their grants to end a live session. Phase 12's
// LIFE-05 revoke script is that second half; until it ships the stopgap is
// deleting the grant record from `OAUTH_KV` by hand with wrangler.
//
// **The drift risk is real and is MANAGED, not denied.** The old header warned
// that two definitions of "on the list" are two rules, and that two rules drift
// — the day one of them starts reading a malformed value as an open list, one
// path admits everybody and the other does not, and the one that admits
// everybody is whichever nobody was reading at the time. That warning is still
// correct. What answers it is not pretending the questions are the same: it is
// that there is exactly ONE parse rule, `parseAllowList`, which both sources go
// through, and exactly ONE membership predicate, `isAllowed`, which both
// callers use. Two sources, one rule, one predicate. A second predicate here
// would be the failure the old header named, arriving by the door it named.
//
// **This module imports two things, and still imports no more than two.** Say
// so rather than let it read as a weakening. Both imports are leaves
// themselves: `src/configured-secret.ts` imports nothing at all, and
// `src/principal.ts` imports only that module and the error module. So no cycle
// is possible, and nothing rides into a tree behind this one. It imports no
// protocol tree, no handler and no environment type. `KVNamespace` is an
// ambient global type and needs no import, which is why the store reader added
// nothing to this count — keep it that way.
//
// **The list holds ADDRESSES, never props.** Both readers extract the address
// and hand a string in. `src/mcp/api-handler.ts` is the one props reader in this
// codebase and this module must never become a second one.
//
// This module contains no logging calls of any kind and must never acquire any.

import { isConfiguredSecret } from "../configured-secret";
import { normaliseAppleId } from "../principal";

/**
 * Who may sign in: nobody, everybody, or a named set.
 *
 * Three members and no fourth. "Nobody" is a real answer rather than an error
 * value — an unconfigured deployment genuinely admits nobody, and saying so as
 * a value is what lets both callers treat it the same way without either of
 * them carrying a null check of its own.
 *
 * The named set holds FOLDED addresses, never the strings as they were typed
 * into the secret. Both the parse and the comparison go through
 * `normaliseAppleId`, so an entry written `Someone@ICloud.com` matches a person
 * who signs in as ` someone@icloud.com `. A set of raw strings would silently
 * refuse that person, and the owner's only clue would be a failed login.
 */
export type AllowList =
  | { readonly kind: "nobody" }
  | { readonly kind: "everybody" }
  | { readonly kind: "some"; readonly addresses: ReadonlySet<string> };

/** The one entry that means "anybody who can authenticate at Apple". */
const EVERYBODY_ENTRY = "*";

const NOBODY: AllowList = Object.freeze({ kind: "nobody" });
const EVERYBODY: AllowList = Object.freeze({ kind: "everybody" });

/**
 * Read the configured allow list. Anything this cannot read means NOBODY.
 *
 * **One rule over two sources.** It is handed the raw bytes of either the seed
 * or the store's one value, which hold the same grammar deliberately — keeping
 * one grammar is what lets one rule serve both, and a second rule would be the
 * drift the module header warns about.
 *
 * **The values here were REASONED, not observed.** Unlike the redirect-origin
 * allowlist one module over, there is no live store to enumerate: both sources
 * are written by hand by the owner, and between them they hold exactly one
 * address — the owner's — for the whole of Phase 11. So the rule is designed
 * against the ways a hand-written JSON value goes wrong, and every one of those
 * ways answers the same: nobody.
 *
 * The rule, in order. Each step exists because the looser version of it admits
 * somebody:
 *
 *   1. Unset or empty. A `vars` entry a live config never carried, and a store
 *      key nobody has written, both arrive as `undefined` or `null`; an entry
 *      emptied by hand arrives as `""`. The alternative — treating an absent
 *      list as open — is the failure mode this whole type exists to make
 *      unspeakable.
 *   2. Not JSON. `JSON.parse` throws and the throw is caught here, because an
 *      uncaught one in the door's `fetch` would be a 500 with no challenge.
 *   3. Not an array. A bare string, an object, a number, `null`. A rule that
 *      accepted a bare string would make `"*"` — five characters, no brackets,
 *      the single easiest typo — mean everybody.
 *   4. An empty array. Explicitly nobody, and it reads as the owner having
 *      deliberately emptied the list.
 *   5. Any entry that is not a string. One number in the array poisons the
 *      whole list rather than being skipped. Skipping would mean a list the
 *      owner mistyped silently admits the entries either side of the mistake.
 *   6. Entries are trimmed and empty ones dropped. `["", "  "]` is therefore
 *      nobody by way of step 4, which is why an all-empty list needs no case of
 *      its own.
 *   7. Exactly one star and nothing else means everybody.
 *   8. A star ALONGSIDE a name means nobody. This is the one that looks
 *      arbitrary and is not: the two readings ("everybody" and "these people
 *      plus a typo") are both plausible, and one of them opens the server to
 *      strangers. When a value has two readings and one is dangerous, the safe
 *      one is not a guess — it is the only choice that cannot be wrong in the
 *      direction that matters.
 *   9. Every remaining entry is folded, and a single entry the folding refuses
 *      poisons the whole list. Same argument as step 5.
 *
 * **Matching is equality on the folded address, never a substring or a suffix
 * test.** That single choice kills three looser rules without any of them being
 * enumerated as a case: a domain-wide entry cannot be written by accident, an
 * address that merely ENDS with a listed one is a different string, and a
 * `+tag` variant is a different string too. There is no check on the address's
 * domain anywhere in this codebase — any address may be listed, and this list
 * is the whole rule.
 *
 * **The recovery, because the only party a fail-closed list can lock out is the
 * owner.** A SEED this function cannot read takes the login page down for
 * everybody, the owner included, and it answers 503 rather than 401 so the
 * owner goes looking for a broken binding rather than for a typo in their own
 * password. The fix is to put a JSON array of addresses — brackets and quotes
 * included — in the `vars` seed in `wrangler.jsonc`, and deploy.
 *
 * A STORE value this function cannot read is the smaller failure, and it needs
 * no deploy at all: write the key again with wrangler and the next sign-in
 * reads it. That asymmetry is the whole reason the store exists — a Cloudflare
 * Secret could not be read back, so the administrator could not even see what
 * he was fixing.
 *
 * Neither repair revokes an existing grant, and neither can. Removing somebody
 * is the seed edit or the store write in reverse PLUS a revoke of their grants;
 * the module header says why, and names where the revoke lands.
 */
export function parseAllowList(raw: unknown): AllowList {
  if (!isConfiguredSecret(raw)) return NOBODY;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Never read the caught value. A list this server cannot read admits
    // nobody, which is the same answer every other unreadable list gets.
    return NOBODY;
  }

  if (!Array.isArray(parsed)) return NOBODY;

  const entries: string[] = [];
  for (const entry of parsed) {
    if (typeof entry !== "string") return NOBODY;
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;
    entries.push(trimmed);
  }

  if (entries.length === 0) return NOBODY;

  const stars = entries.filter((entry) => entry === EVERYBODY_ENTRY).length;
  if (stars > 0) {
    // Exactly one star and nothing beside it. A star next to a name is the
    // ambiguous case, and ambiguity resolves closed.
    return stars === 1 && entries.length === 1 ? EVERYBODY : NOBODY;
  }

  const addresses = new Set<string>();
  for (const entry of entries) {
    const folded = normaliseAppleId(entry);
    if (folded === null) return NOBODY;
    addresses.add(folded);
  }

  return { kind: "some", addresses };
}

/**
 * The WHOLE key the stored list lives under. Not a prefix.
 *
 * **Two things about this constant are deliberate, and both are argued here
 * rather than left to read as an evasion of a scan rule.**
 *
 * It is named for what it is — a complete key — and it is handed to `get`
 * directly instead of being interpolated into a template. The
 * `store-key-without-a-user` rule in `scripts/forbidden-tokens.mjs` refuses a
 * key built under `src/` from a prefix constant with no user id straight after
 * it, and this key carries no user id. It sits OUTSIDE the shape that rule
 * catches rather than inside it and hidden, and the reason it is outside is the
 * same reason it is safe:
 *
 *   - It names a CONFIGURATION DOCUMENT, not one person's data. The stores that
 *     rule protects hold a person's attachments, their pending writes, their
 *     account's home URLs. This holds the administrator's own list of who may
 *     sign in.
 *   - NO CALLER CAN NAME IT. It is a fixed literal reached only from the login
 *     path, so there is no argument any request can carry that changes which
 *     key is read. The failure that rule exists to stop — one person naming
 *     another person's key — has nothing here to reach.
 *
 * Do NOT rename a prefix constant to slip past that rule, and do NOT add a path
 * exclusion for this file: the scanner's skip list is per FILE and not per
 * rule, so excluding this one would silently drop the logging and fan-out rules
 * on it as well.
 *
 * The `v1` segment buys the hedge every other key in this project buys with
 * one: a future change to the stored shape becomes detectable rather than
 * silently misread as the current one.
 */
export const ALLOW_LIST_KEY = "allow-list:v1";

/**
 * Read the stored half of the allow list. Anything that goes wrong means NOBODY.
 *
 * Called at LOGIN ONLY. The door cannot call this — it has no way to await —
 * and the module header carries what that costs and what covers it.
 *
 * **It creates no second rule.** It fetches bytes and hands them to
 * `parseAllowList`, so a stored value and a seed value are read by the same
 * rule and can never disagree about what `["*"]` or a missing bracket means.
 *
 * **A read that fails means nobody, and never a pass.** The `try` wraps the
 * await rather than only the call, so a rejected promise and a synchronous
 * throw are both caught — a `try` around the call alone would catch only the
 * second, and a store that rejects is the likelier of the two. The caught value
 * is never read: a store this server cannot reach admits nobody, which is the
 * same answer every other unreadable list gets.
 *
 * That edge is the whole design and it is worth naming what the other direction
 * would cost. A reader that turned an outage into an open verdict would open a
 * server reaching real personal mail to anyone who can authenticate at Apple,
 * and it would do it in silence, because Convention 4 forbids logging anywhere
 * under `src/`. It fails closed in only one direction: a store outage refuses
 * the people the store would have admitted and leaves the seed's answer alone,
 * so it cannot lock the owner out of his own server.
 *
 * **It answers a verdict and returns nothing carrying the bytes it read.** The
 * stored value is a list of real people's addresses; the tempting shape for a
 * reader like this is to hand the raw value back "for diagnostics", and the
 * closed three-member return type is what makes that unspeakable.
 *
 * It contains no logging call and must never acquire one.
 */
export async function readStoredAllowList(
  store: KVNamespace,
): Promise<AllowList> {
  try {
    return parseAllowList(await store.get(ALLOW_LIST_KEY));
  } catch {
    // Never read the caught value. See the paragraph above: this is the
    // fail-closed edge, not a diagnostic opportunity.
    return NOBODY;
  }
}

/**
 * Whether a folded address is one this server will act for.
 *
 * Takes the address ALREADY FOLDED, and null for one the folding refused. Null
 * is false, which is the fail-closed edge: an address this server could not
 * read is refused rather than admitted. The caller folds because the caller
 * also needs the folded value for what comes next — the login page builds a
 * principal from it, the door compares the grant's own — and folding twice
 * would be two reads of the same rule with nothing forcing them to agree.
 *
 * Exported so a test can drive a table of shapes straight at the predicate.
 * That is both cheaper and far more exhaustive than routing every shape through
 * a handler; the handler-level and door-level cases still exist, and are what
 * prove the predicate is actually wired to anything.
 *
 * **It is synchronous and it never throws**, and both still matter after the
 * storage split even though the reason moved. The door no longer calls this —
 * it tests the seed's verdict for usability instead — so the constraint no
 * longer comes from a `fetch` that may do neither. It comes from the login
 * path, which calls this TWICE for one address, once per source, and a
 * predicate that could throw would put a 500 with no challenge on a path whose
 * every other refusal is one body at one status under one floor.
 *
 * **It still answers as a type predicate, and what that is worth has changed
 * rather than gone.** It was worth carrying the non-null through to the
 * caller's next step. The login path now folds the address once, refuses a null
 * explicitly before asking anything, and only then asks this predicate over the
 * two sources in turn — so that caller has already narrowed before it gets
 * here, and the narrowing buys it nothing.
 *
 * What the null arm is worth is unchanged, and it is the part that was always
 * load-bearing: an address this server could not fold is refused under EVERY
 * verdict, `everybody` included. That is the fail-closed edge, it is asserted
 * against all three members in `test/allow-list.test.ts`, and it is the one
 * thing here no caller may be trusted to remember for itself.
 */
export function isAllowed(
  list: AllowList,
  normalised: string | null,
): normalised is string {
  if (normalised === null) return false;
  if (list.kind === "nobody") return false;
  if (list.kind === "everybody") return true;
  return list.addresses.has(normalised);
}
