// The standing proof of the mail session types' shapes.
//
// Written in the same register as `./env-narrowing.test.ts`, for the same
// reason: a type change is invisible once it has landed. Add a key to the
// session options and everything still builds and still passes, and the one
// place a mode flag could hide is open. Nothing else in the repository would go
// red.
//
// **The proof is `npm run typecheck`, not the run.** The typed constant below
// lists every key of the session options, and its type demands exactly that
// set. Add a key to the options type and the literal is missing a property.
// Remove one and the literal has an excess property. Either way `tsc` fails.
// The one run-time case exists so the file is not empty at run time.
//
// Plan 20-04 adds expect-error directives to this file, one per refusal, for
// D-04: a read session and a mutating session are not assignable to each other.
//
// This file holds no value of its own. It opens nothing and reads no binding.

import { describe, expect, it } from "vitest";
import type { MailSessionOptions } from "../src/mail/service";

/**
 * Every key of the session options, and no other.
 *
 * This is where a mode flag hidden in the options would be caught. The options
 * object reaches both read orchestrators, so a key such as a read-write switch
 * added here would widen every read call site without touching a signature the
 * signature pins in `./service.test.ts` can see. A new key is a decision on the
 * safety boundary (PITFALLS #32), not a refactor.
 */
const OPTION_KEYS: Record<keyof MailSessionOptions, true> = {
  readTimeoutMs: true,
  maxLiteralOctets: true,
  drainTimeoutMs: true,
  closeTimeoutMs: true,
  oneAttemptPerGuess: true,
  callDeadlineMs: true,
};

describe("the session options keep their key set (MUTA-01)", () => {
  it("lists six keys, which typecheck holds to the type's own set", () => {
    expect(Object.keys(OPTION_KEYS)).toHaveLength(6);
  });
});
