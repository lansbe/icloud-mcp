// The one presence assertion the credential-containment tests narrow with.
//
// `src/env.ts` types the three secret bindings as absent-or-string, which is
// what a Workers Secret binding is at runtime. Several tests then assert a
// bound value has non-zero length before asserting that value is absent from a
// serialized response — and that length assertion is not decoration, it is the
// guard that stops the containment case being vacuous. `not.toContain("")` is
// true of every string, so a containment case that ran against an empty binding
// would pass while proving nothing.
//
// That is why narrowing here is an ASSERTION and never a coalesce. Writing
// `env.APPLE_ID ?? ""` would typecheck, keep every case green, and silently
// convert the proof into a tautology — the precise failure the non-zero-length
// guards exist to prevent.
//
// This file holds no value of its own. It reads bindings the test runner
// supplies from `.dev.vars`, which are fakes, and it neither stores, returns,
// nor reports any of them: the thrown message names the BINDING, never its
// contents.

import { env as ambientEnv } from "cloudflare:workers";
import type { EntryEnv } from "../../src/env";
import type { Principal } from "../../src/principal";
import { principalFromEnv } from "../../src/principal";

/**
 * The pool's environment, typed the way the runtime really hands it to the
 * entry point (Phase 9 D-15).
 *
 * **This is the ONE cast in `test/`.** The three secret names left the shared
 * type in Phase 9, so the ambient environment no longer admits them, but the
 * test runner does bind all three — `vitest.config.ts` still carries them. The
 * cast states that fact in one place instead of in nineteen files, and a test
 * that wants a secret comes through here.
 *
 * Phase 13 deletes the secrets, this function and the rest of this file.
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
 * It returns the promise from the REAL env constructor, given the pool's
 * ambient environment, and nothing else. There is no test-only way into the
 * password store and no hand-built principal (D-17). Pass the promise on as it
 * is, or await it. Never spread or clone what it resolves to: the password
 * reader answers only the very object the constructor built (D-16).
 *
 * The same three rules as the rest of this file: it stores nothing, prints
 * nothing and reports nothing. No test may read, print or assert on a value it
 * carries, because a local override file may hold a live one there.
 */
export function ownerPrincipal(): Promise<Principal> {
  return principalFromEnv(entryEnv());
}

/** An entry environment whose two mail secrets are known present. */
export type BoundMailSecrets = EntryEnv & {
  APPLE_ID: string;
  APPLE_APP_PASSWORD: string;
};

/**
 * Assert both mail secrets are bound, narrowing them for the whole flow below.
 *
 * An assertion signature rather than a returned pair, so a caller keeps reading
 * the field off the value it was handed and every later access in the same
 * scope is `string` — the narrowing costs one line at the top of a block
 * instead of rewriting each use.
 *
 * It takes the ENTRY type, so a caller passes `entryEnv()` rather than the
 * ambient environment: the shared type cannot spell these two names any more.
 *
 * Throws rather than skipping. A missing binding means the test environment is
 * misconfigured, and a containment suite that quietly downgraded itself to a
 * no-op is worth strictly less than one that fails loudly.
 */
export function assertMailSecretsBound(
  env: EntryEnv,
): asserts env is BoundMailSecrets {
  if (env.APPLE_ID === undefined || env.APPLE_ID.length === 0) {
    throw new Error("test environment has no APPLE_ID bound");
  }
  if (
    env.APPLE_APP_PASSWORD === undefined ||
    env.APPLE_APP_PASSWORD.length === 0
  ) {
    throw new Error("test environment has no APPLE_APP_PASSWORD bound");
  }
}
