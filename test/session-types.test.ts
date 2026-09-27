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
//
// The second half is D-04: a read session and a mutating session are not
// assignable to each other, in either direction, and neither orchestrator
// accepts a callback typed on the other kind. Each refusal is an expect-error
// directive over a line that must be an error. If the two types ever become
// assignable, the line stops being an error, the directive goes unused, and
// `npm run typecheck` fails with TS2578.
//
// **There are exactly four directives and a plan gate counts them**, which is
// why this header describes them by role rather than spelling the token. Fewer
// than four means a refusal was dropped. More means a directive was added where
// the proof does not need one, which is how a case that ought to compile gets a
// suppression instead of a fix.
//
// One small function per directive, so each error sits on its own line and each
// directive covers exactly one expression. A directive above a multi-line
// expression would be satisfied by any error anywhere in it. Two positive
// controls sit beside them with no directive, so a refusal cannot be satisfied
// by an unrelated error such as a wrong argument count.
//
// The run-time cases exist so the file is not empty at run time, and so nothing
// above reads as dead code. None of the functions is ever called: they would
// open a session.
//
// This file holds no value of its own. It opens nothing and reads no binding.

import { describe, expect, it } from "vitest";
import type { DuplexLike } from "../src/mail/imap-session";
import {
  type MailSession,
  type MailSessionOptions,
  type MutatingMailSession,
  type SessionGate,
  withMailSessionOver,
  withMutatingMailboxOver,
} from "../src/mail/service";
import type { Principal } from "../src/principal";

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

/** A mutating session cannot be handed back where a read session is expected. */
function mutatingAsRead(session: MutatingMailSession): MailSession {
  // @ts-expect-error a mutating session is not a read session (D-04)
  return session;
}

/** A read session cannot be handed back where a mutating session is expected. */
function readAsMutating(session: MailSession): MutatingMailSession {
  // @ts-expect-error a read session is not a mutating session (D-04)
  return session;
}

/** The read orchestrator refuses work written for a mutating session. */
function readOrchestratorGivenMutatingWork(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  work: (session: MutatingMailSession) => Promise<number>,
): Promise<number> {
  // @ts-expect-error the read orchestrator only hands out read sessions (D-04)
  return withMailSessionOver(duplex, principal, gate, "INBOX", 1, work);
}

/** The mutating orchestrator refuses work written for a read session. */
function mutatingOrchestratorGivenReadWork(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  work: (session: MailSession) => Promise<number>,
): Promise<unknown> {
  // @ts-expect-error the mutating orchestrator only hands out mutating sessions (D-04)
  return withMutatingMailboxOver(duplex, principal, gate, "INBOX", 1, work);
}

/**
 * The positive control for the read orchestrator: the same call, with work of
 * the right kind, and no directive. If this stopped compiling, the refusal
 * above could be an error for a reason that has nothing to do with D-04.
 */
function readOrchestratorGivenReadWork(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  work: (session: MailSession) => Promise<number>,
): Promise<number> {
  return withMailSessionOver(duplex, principal, gate, "INBOX", 1, work);
}

/** The positive control for the mutating orchestrator, in the same way. */
function mutatingOrchestratorGivenMutatingWork(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  work: (session: MutatingMailSession) => Promise<number>,
): Promise<unknown> {
  return withMutatingMailboxOver(duplex, principal, gate, "INBOX", 1, work);
}

describe("the session options keep their key set (MUTA-01)", () => {
  it("lists six keys, which typecheck holds to the type's own set", () => {
    expect(Object.keys(OPTION_KEYS)).toHaveLength(6);
  });
});

describe("the two session kinds are not interchangeable (MUTA-03, D-04)", () => {
  it("keeps the four refusals and their two controls referenced, so nothing above is dead code", () => {
    // The typecheck is the assertion. This only stops a linter or a future
    // reader treating the functions as unused and deleting the proof.
    for (const fn of [
      mutatingAsRead,
      readAsMutating,
      readOrchestratorGivenMutatingWork,
      mutatingOrchestratorGivenReadWork,
      readOrchestratorGivenReadWork,
      mutatingOrchestratorGivenMutatingWork,
    ]) {
      expect(fn).toBeTypeOf("function");
    }
  });
});
