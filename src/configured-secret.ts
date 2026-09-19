// The one definition of a usable configured secret.
//
// One predicate: is this value a string with something in it. Every module
// that reads a secret binding asks that question before it uses the value, and
// all of them must get the same answer.
//
// It lives at the root rather than inside one of the trees because five modules
// across four trees share it: the confirmation module at the root, the staging
// tree, the mail tree, and two modules under the DAV tree. It used to be
// defined in the login handler. A root leaf keeps those trees from importing
// the login handler, or each other, to get it. The login handler re-exports it
// from its old place, so every import written before the move still resolves.
//
// **One predicate, not one per tree.** Two definitions of "configured" are two
// rules, and two rules drift. The day one of them starts accepting an empty
// string, one tree treats an unset secret as set. The paragraph on the function
// below says what that costs, and it travels with the function for that
// reason: a copy without it is a copy someone relaxes.
//
// This module imports nothing, on purpose. A leaf can never be part of an
// import cycle, and nothing rides into a tree behind it.
//
// This module contains no logging calls of any kind and must never acquire any.

/**
 * True only for a non-empty string — the shape a usable configured secret has.
 *
 * This exists because the absent case is silently indistinguishable from the
 * empty one at the comparison. `TextEncoder.prototype.encode` is declared
 * `encode(optional USVString input = "")`, so `encode(undefined)` resolves to
 * the WebIDL default `""` — it does not throw and does not stringify to
 * `"undefined"`. An unset Workers Secret binding is `undefined` at runtime, so
 * both sides of the comparison become the SHA-256 digest of the empty string,
 * `timingSafeEqual` returns true, and an empty submitted value authorizes.
 * `src/env.ts` types the three secret bindings `string | undefined`, so this
 * predicate is also what narrows them. The compiler alone still cannot tell a
 * set secret from an empty one.
 *
 * Closes CR-01.
 */
export function isConfiguredSecret(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
