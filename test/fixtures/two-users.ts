// Two test users, A and B, and the cheapest honest way to be one of them today.
//
// **This file holds no real value.** Both addresses sit under `example.invalid`,
// a name reserved so that it can never resolve, and both passwords are plainly
// fake. They are shaped like app-specific passwords only so the fixture keeps
// working once a later phase starts checking that shape at the login page.
//
// **Today the environment object is the only carrier of "which user".** There is
// no principal yet. Every exported function at the tool layer takes that object
// as its first argument and reads the account from it, so handing a function a
// copy with B's two values in it IS being user B, as far as today's code can
// tell. That is what `envFor` does, and it is all it does.
//
// It returns a NEW object and never assigns to the ambient one. Assigning would
// leak B into every later test in the file, and Phase 8 adds a scan rule that
// rejects it outright.
//
// **Phase 9 swaps `envFor` for a principal.** When the tool layer starts taking
// a signed-in user, this file is the one place that changes: `envFor(user)`
// becomes whatever hands that user over. What the cross-user tests ASSERT does
// not change, which is the point of writing them against today's signatures
// (D-05).
//
// A and B both differ from the pool's own ambient identity, on purpose. A test
// user that happened to match it could pass by accident. No test may read,
// report or assert on the ambient identity: a local override file may hold a
// live value there.
//
// The user ids are COPIED from the vectors file and never computed. No
// fingerprinting code may exist in a test helper (D-12).

import { env } from "cloudflare:workers";
import type { Env } from "../../src/env";
import { USER_A_VECTOR, USER_B_VECTOR } from "./user-id-vectors";

/** One test user: who they are, and the user id the spec gives them. */
export interface TestUser {
  readonly label: "A" | "B";
  readonly appleId: string;
  readonly appPassword: string;
  readonly userId: string;
}

/** The user who owns the thing under test. */
export const USER_A: TestUser = {
  label: "A",
  appleId: USER_A_VECTOR.input,
  appPassword: "aaaa-aaaa-aaaa-aaaa",
  userId: USER_A_VECTOR.expected,
};

/** A second, legitimate, signed-in user who has got hold of one of A's values. */
export const USER_B: TestUser = {
  label: "B",
  appleId: USER_B_VECTOR.input,
  appPassword: "bbbb-bbbb-bbbb-bbbb",
  userId: USER_B_VECTOR.expected,
};

/**
 * The environment as `user` would have it: every real binding, and that user's
 * two account values in place of the ambient ones.
 *
 * Both values are overridden, never one. A copy carrying B's address and the
 * ambient password would be a third identity nobody meant to test.
 */
export function envFor(user: TestUser): Env {
  return {
    ...(env as Env),
    APPLE_ID: user.appleId,
    APPLE_APP_PASSWORD: user.appPassword,
  };
}

/** What one attempt came to: a value, or a refusal. Never a throw. */
export type Attempt<T> =
  | { readonly refused: false; readonly value: T }
  | { readonly refused: true };

/**
 * Run B's action and hand back what happened AS A VALUE.
 *
 * This never throws and never rethrows, and that is the whole reason it exists.
 * The runner turns ANY failure inside an expected-fail body into a pass and
 * discards the error. So once a fix makes B's call throw, a body that let the
 * throw escape would keep "failing as expected" for ever, and the fix would
 * never be noticed. Turning the throw into `refused: true` leaves the leak
 * assertion as the only thing in the body that can fail.
 *
 * The caught value is deliberately never bound and never read: a refusal is a
 * refusal, and nothing about an error object belongs in a test report.
 */
export async function attempt<T>(run: () => Promise<T>): Promise<Attempt<T>> {
  try {
    return { refused: false, value: await run() };
  } catch {
    return { refused: true };
  }
}
