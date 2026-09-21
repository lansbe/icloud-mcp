// The one definition of who this server will sign in, and keep serving.
//
// Two readers by design. The login page asks "may this person sign in at all",
// before any socket is opened to Apple. The door asks "is the person in this
// grant still permitted", on every served request. Those are the same question
// about the same list, so they are one rule here rather than one rule each.
//
// **One predicate, not one per tree.** Two definitions of "on the list" are two
// rules, and two rules drift. The day one of them starts accepting a malformed
// secret as an open list, one of the two paths admits everybody and the other
// does not — and the one that admits everybody is whichever one nobody was
// reading at the time. `src/configured-secret.ts` makes the same argument about
// the same kind of value, and this module is its sibling.
//
// **This module imports two things, where that one imports none.** Say so
// rather than let it read as a weakening. Both imports are leaves themselves:
// `src/configured-secret.ts` imports nothing at all, and `src/principal.ts`
// imports only that module and the error module. So no cycle is possible, and
// nothing rides into a tree behind this one. It imports no protocol tree, no
// handler and no environment type.
//
// **The list holds ADDRESSES, never props.** The door extracts the address out
// of the grant and hands a string in. `src/mcp/api-handler.ts` is the one props
// reader in this codebase and this module must never become a second one.
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
 * **The values here were REASONED, not observed.** Unlike the redirect-origin
 * allowlist one module over, there is no live store to enumerate: the list is a
 * Workers Secret the owner writes by hand, and it holds exactly one address —
 * the owner's — for the whole of Phase 11. So the rule is designed against the
 * ways a hand-written JSON secret goes wrong, and every one of those ways
 * answers the same: nobody.
 *
 * The rule, in order. Each step exists because the looser version of it admits
 * somebody:
 *
 *   1. Unset or empty. A Workers Secret that was never provisioned, was
 *      deleted, or failed to provision all arrive as `undefined` or `""`. The
 *      alternative — treating an absent list as open — is the failure mode this
 *      whole type exists to make unspeakable.
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
 * owner.** A list this function cannot read takes the login page down for
 * everybody, the owner included, and it answers 503 rather than 401 so the
 * owner goes looking for a broken binding rather than for a typo in their own
 * password. The fix is to set `ALLOWED_APPLE_IDS` to a JSON array of addresses
 * — `["you@icloud.com"]`, brackets and quotes included — and deploy. It is a
 * Workers Secret rather than stored state, so nothing saved has to be edited or
 * deleted, and no existing grant is revoked by fixing it. Removing an address
 * is the same operation in reverse: set the secret without it and deploy, and
 * that person's access ends on their very next request.
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
 * It is synchronous and it never throws, because the door calls it inside a
 * `fetch` that may do neither.
 *
 * **It answers as a type predicate, and that is load-bearing rather than
 * decorative.** A `true` here means the address is a string this server folded
 * successfully AND one it will act for, so the compiler carries the non-null
 * through to the caller's next step — building the principal, deriving the user
 * id. Without it each caller would need its own null check after this one, and
 * a second check is a second rule that can drift from this one.
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
