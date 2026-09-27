// The connection lease, seen from the Worker request (Phase 24, D-02, D-05,
// D-08, D-09).
//
// A mail tool call takes its person's lease before it opens its iCloud mail
// connection, and gives it back after the connection is closed. A second call
// for the same person, arriving while the first still holds the lease, is
// refused at once with `ConnectionBusyError`. So two overlapping requests from
// one Apple ID no longer open two iCloud connections.
//
// WHERE the lease is taken matters. It is taken BEFORE the session
// orchestrator is called, and never inside `withMailSession`'s check-and-acquire
// span in `src/mail/service.ts`. That span has no `await` in it, a test reads it
// as text and fails on one, and `src/mcp/api-handler.ts` rests its argument
// about legacy batches on that. Taking the lease outside keeps both true and
// means the service module is not edited at all.
//
// The per-request gate is untouched. It is still the structural guard against a
// second session inside ONE request. The lease is a third layer, across
// requests, added beside the gate and never replacing it (DOBJ-04). A bug here
// must not remove the only runtime check that exists without it.
//
// Refuse, never queue (D-09). No wait, no retry loop, no polling. A queue would
// make the second caller wait inside its own deadline, so its failure would
// arrive as a timeout instead of advice.
//
// Strict mode: the acquire is awaited, a held lease refuses, and an object that
// cannot be reached refuses too. The lease is the only guard across requests,
// so failing open would lose it silently. Strict is the mode until SPIKE-11's
// real-network measurement gives its verdict (plan 24-04); the advisory
// alternative differs only in this file.
//
// This module logs nothing (./.claude/CLAUDE.md §4). A caught value from the
// object is never read; a fixed error class is thrown in its place.

import { env } from "cloudflare:workers";
import { ConnectionBusyError, ImapConnectError } from "../errors";
import type { SessionGate } from "../mail/service";
import type { Principal } from "../principal";
import type { LeaseAnswer } from "./user-agent";

/**
 * The stub for this person's object. The only read of the binding under
 * `src/`, and the only stub construction.
 *
 * Named from `principal.userId` and from nothing else. The parameter is a
 * `Principal`, the object the door built from the signed-in grant, so no
 * request field, tool argument or typed address can choose whose object is
 * reached.
 */
export function agentFor(principal: Principal) {
  return env.USER_AGENT.getByName(principal.userId);
}

/** The lease-taking runner a mail tool reaches its session gate through. */
export interface LeasedMail {
  /**
   * Take `principal`'s lease, run `fn` with the request's gate, then give the
   * lease back.
   *
   * Throws `ConnectionBusyError` when another request holds the lease, and
   * `ImapConnectError` when the object cannot be reached. In both cases `fn`
   * never runs.
   */
  withConnectionLease<T>(
    principal: Principal,
    fn: (gate: SessionGate) => Promise<T>,
  ): Promise<T>;
}

/**
 * Build the lease runner for ONE request, over that request's gate.
 *
 * Built where the gate is built, once per request, so it cannot be shared
 * across requests any more than the gate can.
 */
export function createLeasedMail(gate: SessionGate): LeasedMail {
  return {
    async withConnectionLease<T>(
      principal: Principal,
      fn: (gate: SessionGate) => Promise<T>,
    ): Promise<T> {
      const stub = agentFor(principal);

      let answer: LeaseAnswer;
      try {
        answer = await stub.acquire();
      } catch {
        // Strict: an object that cannot be reached refuses the call. The
        // caught value is not read — its text is the platform's, not ours.
        throw new ImapConnectError();
      }
      if (!answer.held) throw new ConnectionBusyError();

      const { token } = answer;
      try {
        return await fn(gate);
      } finally {
        try {
          await stub.release(token);
        } catch {
          // A release that fails is covered by the expiry: the record frees
          // itself within `LEASE_TTL_MS`. Swallowed so it cannot replace the
          // call's own answer or error.
        }
      }
    },
  };
}
