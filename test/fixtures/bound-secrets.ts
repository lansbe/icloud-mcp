// The two fake credentials the containment tests assert against, and the owner
// principal built from them.
//
// **The file used to read both values off the platform's secret bindings.**
// Phase 13 stops the platform binding them at all, so the values live here
// instead — as two plain constants this fixture owns. Nothing below reaches an
// environment object for a credential any more.
//
// **Both values are fakes and neither is a real credential.** The address sits
// under `example.invalid`, a name reserved so that it can never resolve, and the
// password is plainly not one. That is the habit `two-users.ts` already sets.
//
// **They equal what `vitest.config.ts` binds today, and the equality is
// deliberate.** With identical values the rebuilt `ownerPrincipal()` derives the
// identical user id the binding-backed one did, so every containment assertion
// in the nine guard files keeps its exact meaning through the change — and a red
// test during the conversion is a real breakage rather than an expected one.
// That coupling runs in one direction only: these constants are the single
// source, and the principal is built from them.
//
// **A containment case narrows by assertion and never by a coalesce.** Several
// tests assert a credential has non-zero length before asserting it is absent
// from a serialized response, and that length assertion is not decoration — it
// is the guard that stops the containment case being vacuous. `not.toContain("")`
// is true of every string. Coalescing a credential onto an empty string would
// typecheck, keep every case green, and silently turn the proof into a
// tautology. That is the precise failure the non-zero-length guards exist to
// prevent, and it is why they are re-expressed against these constants rather
// than dropped.
//
// The operator is described here rather than spelled, because a plan gate greps
// the touched files for it and a comment quoting it would fail the very check it
// was trying to explain — the same habit `.claude/CLAUDE.md` § 1 keeps for the
// banned transport paths.
//
// The same three rules as before: this file stores nothing, prints nothing and
// reports nothing.

import { env as ambientEnv } from "cloudflare:workers";
import type { EntryEnv } from "../../src/env";
import type { Principal } from "../../src/principal";
import { principalFromProps } from "../../src/principal";

/**
 * The fake Apple ID every containment case asserts against.
 *
 * Under the reserved `.invalid` domain, so it can never resolve. Its value is
 * the one `vitest.config.ts` binds, on purpose — see the file header.
 */
export const FAKE_APPLE_ID = "test@example.invalid";

/**
 * The fake app-specific password every containment case asserts against.
 *
 * Plainly not a real one, and the value `vitest.config.ts` binds. See the file
 * header for why the equality is deliberate.
 */
export const FAKE_APP_PASSWORD = "test-password-not-real";

/**
 * The pool's environment, typed the way the runtime really hands it to the
 * entry point (Phase 9 D-15).
 *
 * **This is the ONE cast in `test/`.** The three secret names left the shared
 * type in Phase 9, so the ambient environment no longer admits them, but the
 * test runner does bind all three — `vitest.config.ts` still carries them. The
 * cast states that fact in one place instead of in nineteen files.
 *
 * Plan 13-03 deletes the secrets and this function with them. It survives 13-02
 * because callers of its own remain; the constants above are what a test that
 * wants a CREDENTIAL uses, and no caller of this one reads a secret off it any
 * more.
 *
 * It reads no value and reports none. It hands back the binding surface, not a
 * credential.
 */
export function entryEnv(): EntryEnv {
  return ambientEnv as EntryEnv;
}

/**
 * The owner's principal, for a test that acts as the pool's ambient identity.
 *
 * It returns exactly what the REAL props constructor returns, given the one
 * shape that constructor accepts: three keys, `v` set to 1, and the two
 * constants above. There is no hand-built principal, no test-only export from
 * the principal module and no test-only way into the password store (D-17). So
 * the password reader answers for this object for the same reason it answers in
 * production: the real constructor built it.
 *
 * **Never spread or clone what this resolves to (D-16).** The password reader
 * answers only the very object the constructor returned. A copy has the same
 * two fields and gets the auth error. Pass the promise on as it is, or await it
 * and pass that one object on.
 *
 * **The signature is exactly `(): Promise<Principal>` and stays that way.** That
 * is why fifteen of its sixteen caller files needed no edit when the body moved
 * off the environment constructor.
 *
 * The same three rules as the rest of this file: it stores nothing, prints
 * nothing and reports nothing.
 */
export function ownerPrincipal(): Promise<Principal> {
  return principalFromProps({
    v: 1,
    appleId: FAKE_APPLE_ID,
    appPassword: FAKE_APP_PASSWORD,
  });
}

/** Which half of the credential pair a refused principal is bad in. */
export type RefusedHalf = "appleId" | "appPassword";

/**
 * A principal promise the REAL constructor refuses, for a test that needs one.
 *
 * Several tests reach a refused principal today by handing the environment
 * constructor a patched environment with one binding removed. That route
 * disappears with the constructor in plan 13-03, and this is the replacement. It
 * belongs in this fixture because this is where the credential constants live.
 *
 * It goes through `principalFromProps` like `ownerPrincipal` does, so the
 * refusal is the real one — not a rejected promise made here. `which` picks the
 * bad half: an address the id function turns away, or a password that is only
 * white space, which `isUsablePassword` refuses (D-19). The other half is the
 * ordinary constant, so exactly one thing is wrong at a time.
 *
 * **It hands back the promise unawaited**, because that is how every caller
 * consumes it: the promise is passed into the code under test, which awaits it
 * and sees the refusal where a real one would arrive. A caller that holds it
 * without consuming it must attach its own no-op catch.
 */
export function refusedPrincipal(which: RefusedHalf): Promise<Principal> {
  return principalFromProps({
    v: 1,
    appleId: which === "appleId" ? "not-an-address" : FAKE_APPLE_ID,
    appPassword: which === "appPassword" ? " " : FAKE_APP_PASSWORD,
  });
}

// Two exports used to sit here: a presence assertion over the two mail secret
// bindings, and the type naming the shape it narrowed them to. Their whole
// subject was the bindings — one turned absent-or-string into string, the other
// named the result. With the credentials being the two constants above there is
// nothing left to narrow, because a literal is already a string, and nine files'
// worth of callers went with them.
//
// Neither is named here, and that is not squeamishness: a plan gate greps every
// scanned tree for both names and requires no match, so a comment spelling them
// would fail the very check it was explaining. Same habit as the coalesce above,
// and as `.claude/CLAUDE.md` § 1 keeps for the banned transport paths.
