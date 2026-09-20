// The standing proof that a stray reader of a secret name does not compile.
//
// Phase 9 took the three secret names off the shared binding type and put them
// in two narrow interfaces (D-14). That is what makes the compiler, rather than
// a reviewer, the first thing to find code that reads a secret it should not.
// But a type change is invisible once it has landed: put one name back on the
// shared type and everything still builds, still passes, and the guarantee is
// simply gone.
//
// **The proof is the typecheck, not the run.** Each `@ts-expect-error` below is
// an assertion that the line under it IS an error. Put a name back on the shared
// type and the line stops being an error, the directive becomes unused, and
// `npm run typecheck` fails with TS2578. That failure is the whole point of this
// file; the one run-time case exists so the file is not empty at run time.
//
// One small function per directive, so each error sits on its own line and each
// directive covers exactly one expression. A directive above a multi-line
// expression would be satisfied by any error anywhere in it.
//
// This file holds no value of its own. The run-time case goes through the same
// bridge every other test uses, asserts only that a principal came back, and
// reads nothing off it: a local override file may hold a live value there.

import { describe, expect, it } from "vitest";
import type { EntryEnv, Env } from "../src/env";
import { principalFromEnv } from "../src/principal";
import { entryEnv } from "./fixtures/bound-secrets";

/** The login gate's secret is not on the shared type. */
function readsGateSecret(shared: Env): unknown {
  // @ts-expect-error the gate's secret left the shared type (D-14)
  return shared.AUTH_SECRET;
}

/** Neither is the Apple ID. */
function readsAppleId(shared: Env): unknown {
  // @ts-expect-error the Apple ID secret left the shared type (D-14)
  return shared.APPLE_ID;
}

/** Nor the app-specific password. */
function readsAppPassword(shared: Env): unknown {
  // @ts-expect-error the app password secret left the shared type (D-14)
  return shared.APPLE_APP_PASSWORD;
}

/**
 * And the shared type cannot be handed to the owner's constructor.
 *
 * This is the one that matters most: it is the shape a future caller would
 * reach for, and the required fields are what make the error the clear
 * "missing the following properties" rather than the unhelpful weak-type one.
 */
function handsSharedToConstructor(shared: Env): unknown {
  // @ts-expect-error the shared type is missing both mail secrets (D-14)
  return principalFromEnv(shared);
}

/**
 * The positive compile case, with no directive above it.
 *
 * It is what stops the four refusals being vacuous in the other direction: if
 * NO type could spell these names, every line above would be an error for a
 * reason that has nothing to do with the narrowing. The entry type can spell
 * all three, because that is what the runtime really hands the entry point.
 */
function readsAllThreeOffTheEntryType(entry: EntryEnv): unknown[] {
  return [entry.AUTH_SECRET, entry.APPLE_ID, entry.APPLE_APP_PASSWORD];
}

describe("a stray reader of a secret name does not compile (Phase 9 D-14)", () => {
  it("keeps the five cases referenced, so nothing above is dead code", () => {
    // The typecheck is the assertion. This only stops a linter or a future
    // reader treating the functions as unused and deleting the proof.
    for (const fn of [
      readsGateSecret,
      readsAppleId,
      readsAppPassword,
      handsSharedToConstructor,
      readsAllThreeOffTheEntryType,
    ]) {
      expect(fn).toBeTypeOf("function");
    }
  });

  it("accepts the entry value the runtime really hands the door", async () => {
    // The run-time case: the hand-off the refusals above forbid for the shared
    // type is the ordinary thing to do with the entry type. It compiles with no
    // cast at the call site, and resolves.
    const principal = await principalFromEnv(entryEnv());

    expect(principal).toBeTypeOf("object");
  });
});
