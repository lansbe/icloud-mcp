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

import type { Env } from "../../src/env";

/** An `Env` whose two mail secrets are known present. */
export type BoundMailSecrets = Env & {
  APPLE_ID: string;
  APPLE_APP_PASSWORD: string;
};

/**
 * Assert both mail secrets are bound, narrowing them for the whole flow below.
 *
 * An assertion signature rather than a returned pair, so a caller keeps reading
 * `env.APPLE_ID` and every later access in the same scope is `string` — the
 * narrowing costs one line at the top of a block instead of rewriting each use.
 *
 * Throws rather than skipping. A missing binding means the test environment is
 * misconfigured, and a containment suite that quietly downgraded itself to a
 * no-op is worth strictly less than one that fails loudly.
 */
export function assertMailSecretsBound(
  env: Env,
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
