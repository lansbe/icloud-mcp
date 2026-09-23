// The standing proof that a stray reader of a secret name does not compile.
//
// Phase 9 took the three secret names off the shared binding type and put them
// in two narrow interfaces (D-14). Phase 13 goes further: the platform stops
// binding two of them at all, and the narrow types go with the environment-backed
// constructor. What survives both phases is the guarantee this file is about —
// the shared type cannot spell a secret name, so the compiler, rather than a
// reviewer, is the first thing to find code that reads one.
//
// **The argument for the file is the same one it has always had, and it is the
// reason the file was rewritten rather than deleted: a type change is invisible
// once it has landed.** Put one name back on the shared type and everything
// still builds, still passes, and the guarantee is simply gone. Nothing else in
// the repository would go red.
//
// **The proof is the typecheck, not the run.** Each expect-error directive below
// is an assertion that the line under it IS an error. Put a name back on the
// shared type and the line stops being an error, the directive becomes unused,
// and `npm run typecheck` fails with TS2578. That failure is the whole point of
// this file; the one run-time case exists so the file is not empty at run time.
//
// **There are exactly three directives and a plan gate counts them**, which is
// why this header describes them by role rather than spelling the token. Fewer
// than three means a refusal was dropped. More means a directive was added where
// the proof does not need one, which is how a case that ought to compile gets a
// suppression instead of a fix.
//
// One small function per directive, so each error sits on its own line and each
// directive covers exactly one expression. A directive above a multi-line
// expression would be satisfied by any error anywhere in it.
//
// This file holds no value of its own. It reads no binding, opens nothing, and
// asserts on no credential.

import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";

/** The login gate's secret is not on the shared type. */
function readsGateSecret(shared: Env): unknown {
  // @ts-expect-error the gate's secret left the shared type (D-14)
  return shared.AUTH_SECRET;
}

/** Neither is the Apple ID, which CUT-01 stopped the platform binding. */
function readsAppleId(shared: Env): unknown {
  // @ts-expect-error the Apple ID secret left the shared type (D-14, CUT-01)
  return shared.APPLE_ID;
}

/** Nor the app-specific password, which CUT-01 stopped the platform binding. */
function readsAppPassword(shared: Env): unknown {
  // @ts-expect-error the app password secret left the shared type (D-14, CUT-01)
  return shared.APPLE_APP_PASSWORD;
}

/**
 * A type that CAN spell all three names, declared here and nowhere else.
 *
 * **It names nothing in `src/`.** No module exports a shape like this any more,
 * and none may: CUT-01's whole point is that the three names are unspellable
 * outside a test that is proving they are unspellable.
 *
 * It exists ONLY as the positive control for the three refusals above. Before
 * CUT-01 that control was the entry type, which really did carry all three
 * because the runtime really did hand them to the entry point. With that type
 * gone there is no in-kind replacement, so the control is declared locally
 * instead of dropped.
 *
 * **Dropping it would make the refusals vacuous in a way no directive can
 * catch.** An expect-error directive is satisfied by ANY error on the line below
 * it, a misspelled property name included. Without a case that compiles, a
 * rewrite that misspelled all three names would satisfy all three directives and
 * prove nothing at all.
 */
interface SpellsAllThree {
  readonly AUTH_SECRET: string | undefined;
  readonly APPLE_ID: string | undefined;
  readonly APPLE_APP_PASSWORD: string | undefined;
}

/**
 * The positive compile case, with no directive above it.
 *
 * The same read expression as the three refusals, against a type that admits
 * the names. If it stopped compiling, the refusals above would be errors for a
 * reason that has nothing to do with the narrowing.
 *
 * **Its parameter is deliberately not called `env`.** The read would then spell
 * the form the environment-read scan ban matches. That ban is scoped to `src/`
 * and this file is not in it, but a proof that reads as a violation is a proof
 * somebody deletes.
 */
function readsAllThreeOffTheControl(control: SpellsAllThree): unknown[] {
  return [
    control.AUTH_SECRET,
    control.APPLE_ID,
    control.APPLE_APP_PASSWORD,
  ];
}

describe("a stray reader of a secret name does not compile (D-14, CUT-01)", () => {
  it("keeps the four cases referenced, so nothing above is dead code", () => {
    // The typecheck is the assertion. This only stops a linter or a future
    // reader treating the functions as unused and deleting the proof.
    for (const fn of [
      readsGateSecret,
      readsAppleId,
      readsAppPassword,
      readsAllThreeOffTheControl,
    ]) {
      expect(fn).toBeTypeOf("function");
    }
  });
});
