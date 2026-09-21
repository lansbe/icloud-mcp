// A test-only Worker entry whose login proof is a counter rather than Apple.
//
// The production entry composes the real OAuth provider over the real login
// handler, whose proof opens one IMAP session against iCloud. This entry keeps
// every one of those parts — the real provider options, the real endpoints, the
// real gate, the real allow-list check, the real `completeAuthorization` — and
// changes exactly one thing: the proof.
//
// **That substitution is not a convenience, it is D-09.** No test, CI job,
// pre-commit hook or post-deploy check may ever authenticate against a real
// Apple ID. A case that drives the whole ceremony to its 302 has to get past the
// proof somehow, and the only honest way is to inject one.
//
// It is also what turns "the response was a 401" into "zero sockets were opened
// to Apple". A status code cannot tell those apart: a refusal that happened
// after a failed login looks exactly like one that happened before the socket
// existed. Only a counter the proof itself increments can say which.
//
// This file lives under test/ so it never enters the deployed bundle. The seam
// it uses — `createLoginHandler(proof)` — exists in src/ for precisely this
// purpose and is described there without naming this file.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createLoginHandler } from "../../src/auth/login-handler";
import { oauthProviderOptions } from "../../src/auth/oauth";
import type { EntryEnv } from "../../src/env";
import type { Principal } from "../../src/principal";

/**
 * An address the injected proof ACCEPTS, and which the pool's allow list holds.
 *
 * Named here and imported by the suites, rather than retyped in each of them,
 * so a change to `vitest.config.ts` breaks one line instead of silently
 * un-listing an address three files still believe is listed. The bound value
 * lives in `vitest.config.ts` under `ALLOWED_APPLE_IDS`.
 */
export const LISTED_APPLE_ID = "listed-user@example.invalid";

/**
 * An address the pool's allow list deliberately does NOT hold.
 *
 * Every refusal case posts this. Under the switch that is what makes a refusal
 * cheap and certain: the allow-list check sits above every use of the
 * credentials, so a POST carrying this address is answered without a principal
 * being built and without the proof being called at all.
 */
export const UNLISTED_APPLE_ID = "not-on-the-list@example.invalid";

/**
 * A password shaped like an app-specific one, and plainly fake.
 *
 * `.invalid` has no equivalent for passwords, so the name carries the claim
 * instead. Nothing here is a real credential, and the proof below never reads
 * it — it counts calls and answers, exactly as an injected proof should.
 */
export const FAKE_APP_PASSWORD = "cccc-cccc-cccc-cccc";

let calls = 0;
let refusedAddresses: readonly string[] = [];

/** How many times the proof has been called since the last reset. */
export function loginProofCalls(): number {
  return calls;
}

/**
 * Zero the counter, and optionally name addresses the proof should refuse.
 *
 * Refusing by ADDRESS rather than by password is deliberate. The proof is
 * handed a principal, and reading the password back off one would mean a second
 * password reader in this repository — the very thing the count constraint in
 * `scripts/forbidden-tokens.mjs` exists to prevent. The address is a plain
 * field on the principal and reading it costs nothing.
 *
 * Call this in a `beforeEach`, so a passing first case cannot mask a failing
 * second one.
 */
export function resetLoginProof(refuse: readonly string[] = []): void {
  calls = 0;
  refusedAddresses = refuse;
}

/**
 * The injected proof: count the call, then accept or refuse.
 *
 * A refusal throws, because that is what the production proof does — a login
 * iCloud turns down rejects out of `withMailSession`, and the handler branches
 * on the error's type and never on a returned flag. A stub that answered
 * `false` instead would be exercising a control flow production does not have.
 *
 * The error is built with no argument, so nothing about the credential can ride
 * out on it.
 */
async function countingProof(principal: Principal): Promise<void> {
  calls += 1;
  if (refusedAddresses.includes(principal.appleId)) {
    throw new Error("the injected proof refused this address");
  }
}

const provider = new OAuthProvider<EntryEnv>({
  ...oauthProviderOptions,
  defaultHandler: createLoginHandler(countingProof),
});

export default {
  fetch(
    request: Request,
    env: EntryEnv,
    ctx: ExecutionContext,
  ): Promise<Response> {
    return provider.fetch(request, env, ctx);
  },
};
