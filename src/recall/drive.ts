// What drives the recall build: one step after a mail tool answers (Phase 26,
// RCLL-08; 26-CONTEXT D-26 to D-29, D-35).
//
// Recall is inherent, so there is no switch and no background job. The index is
// built and kept current by the person's own mail calls. After a mail tool has
// answered without an error, this module runs ONE build step for that person,
// and only then does the tool's answer go back. The answer itself is never
// touched: the wrapper hands back the very same object the tool built.
//
// WHY THE STEP RUNS AFTER THE TOOL'S SESSION, AND TAKES ITS OWN LEASE (D-26).
// A mail tool runs its own session under the person's connection lease and
// gives the lease back when its session closes. The step runs after that, and
// takes the lease itself for its one session, through the same lease runner
// every tool uses.
//   - Not inside the tool's lease. The step takes the lease for its own read,
//     and a second acquire for the same person while the first is held is
//     refused as busy. Inside the tool's lease the step could never run.
//   - Not after the answer is sent. The model's next call usually arrives right
//     after an answer. It would find the step holding the lease and be refused
//     as busy, and that would fail a call the person actually made.
//   - Awaited, then. A call made after another one finished can never meet a
//     step. The cost is an answer that can come back a few seconds later.
//
// WHY ONLY AFTER A SUCCESS. An error answer runs no step: connection busy, a
// refused or paused person, a failed call. A step must never add a sign-in
// attempt after one that failed or was paused, because repeated refused
// sign-ins are how an account gets locked.
//
// WHY NEVER ON THE AUTONOMY GRANT, OR AN UNKNOWN ONE (D-35). A scheduled job
// will call mail tools with the autonomy key, and the owner ruled out indexing
// with it. So a step runs only when the request's grant is positively known to
// belong to some other client. An unknown client (no header, a missing record,
// a store error) runs no step either. Failing that way only delays the build.
//
// ONE LEASE PER STEP, AND ALMOST ALWAYS ONE SESSION (D-27). A step takes the
// person's lease at most once, and holds it only for the reads under it. What
// the step does there is `recallStep`'s business, in ./sync.ts. Almost every
// step opens at most one iCloud session. A build page can open up to three,
// one after another under that one lease, in two rare cases in the page source
// (./mail-source.ts):
//   - the build cursor's mailbox changed its validity, so the page is read
//     again from the top: a second session;
//   - a page came back with no rows and no cursor to take the validity from,
//     for example an empty archive folder's first page, so the validity is
//     read on its own: one more session.
// The sessions never overlap: the request's session gate refuses a second one
// while the first is open. So no two connections to iCloud are ever open at
// once for a step. Getting to strictly one session in those two cases would
// change the listing's answer shape, which is the owner's decision
// (26-VERIFICATION, the one gap).
//
// NOTHING THE STEP DOES REACHES THE ANSWER. A step that is refused, finds the
// lease busy, or fails, is silent. The caught value is never read, nothing here
// logs (./.claude/CLAUDE.md §4), and nothing is thrown.
//
// WHAT THE BACKFILL COSTS PER PERSON (D-31). Recall is inherent, so this runs
// for everyone who signs in, and this is what each of them costs. One step per
// successful mail call. A step takes the lease at most once, and almost always
// opens at most one iCloud session; the two rare cases above open up to three,
// one after another. Pages (build,
// new mail, deletion sync) run at most one a minute and
// `RECALL_MAX_PAGES_PER_DAY` (200) a day, and a person holds at most
// `RECALL_MAX_VECTORS` (10,000) vectors. Both ceilings are Phase 25's, and this
// phase lowers neither. A typical 90-day window of 1,500 messages is 60 pages:
// about $0.02 once to embed, and about $0.02 a month to hold and query, filled
// over about 60 of the person's mail calls. A person at the ceiling costs about
// $0.12 once and $0.11 a month. The daily cap bounds a runaway at about $0.06
// of embedding per person per day. Status checks run at most once per folder
// per five minutes. The folder listing runs at most once a day, plus once
// after a folder is dropped as gone (26-REVIEW-2 WR-02). The numbers and their
// assumptions are in 26-CONTEXT D-31 and 25-CONTEXT D-24.
//
// THE BACKFILL THE PERSON ASKS FOR (Phase 29.1.1). `runRecallBackfill` runs one
// call of `recallBackfill` in ./sync.ts. It runs only from the backfill tool the
// person calls, while they watch, never from the seam above that drives steps
// and never from the object's alarm. It makes the same grant check a step makes:
// nothing runs, and nothing is called, unless the grant belongs to a client
// other than the autonomy client. One call indexes at most
// RECALL_BACKFILL_MAX_PAGES pages, one leased session at a time. Its pages skip
// the one-minute pause and the ordinary day count, and count on their own:
// at most RECALL_BACKFILL_MAX_PAGES_PER_DAY (400) pages a day, which is at most
// RECALL_MAX_VECTORS (10,000) messages. That is about $0.12 once to embed, the
// same as filling the ceiling (26-CONTEXT D-31, 25-CONTEXT D-24), and it is also
// the most a runaway backfill can cost a person in a day. The 10,000-vector
// ceiling, the 90-day window, read-only opens and peeking fetches are the same
// as for a step.

import type { McpServer } from "@modelcontextprotocol/server";
import { AUTONOMY_CLIENT_ID } from "../agent/autonomy-client";
import type { LeasedMail } from "../agent/lease";
import type { Principal } from "../principal";
import {
  type BackfillOutcome,
  productionStepDeps,
  recallBackfill,
  recallStep,
  type StepDeps,
} from "./sync";

/**
 * The mark every driven callback carries, as a non-enumerable property.
 *
 * It exists so a test can tell, from the real factory, which registered tools
 * run a step and which do not.
 */
export const RECALL_DRIVEN: unique symbol = Symbol("recall-driven");

/**
 * Which client the request's grant belongs to, read only when asked.
 *
 * Answers null when that cannot be known. The door builds the real one
 * (`grantClientOf` in src/mcp/grant-client.ts).
 */
export type GrantClient = () => Promise<string | null>;

/**
 * Run one recall build step for the person behind `principal`.
 *
 * Never throws. Runs nothing unless the grant client is a non-empty string other
 * than the autonomy client. This is the one call of the step under `src/`.
 */
export async function runRecallStep(
  principal: Promise<Principal>,
  mail: LeasedMail,
  grantClient: GrantClient,
): Promise<void> {
  try {
    const client = await grantClient();
    if (typeof client !== "string" || client.length === 0) return;
    if (client === AUTONOMY_CLIENT_ID) return;
    const actor = await principal;
    await recallStep(actor, productionStepDeps(mail));
  } catch {
    // Silent on purpose. A step that fails only delays the build, and the next
    // mail call tries again. The caught value is not read.
  }
}

/** What a backfill run came to: refused by the grant check, or ran. */
export type BackfillRun = { kind: "refused" } | { kind: "ran"; outcome: BackfillOutcome };

/**
 * Run one recall backfill call for the person behind `principal` (Phase
 * 29.1.1, LD-2, LD-8).
 *
 * The principal is already resolved: the tool has awaited it. Runs nothing, and
 * calls nothing, unless the grant client is a non-empty string other than the
 * autonomy client: the same test `runRecallStep` makes (D-35). This is the one
 * call of the backfill under `src/`.
 *
 * It does not swallow a thrown value. A throw here means the object could not
 * be reached, and the tool turns that into its fixed answer. Nothing here logs.
 */
export async function runRecallBackfill(
  principal: Principal,
  mail: LeasedMail,
  grantClient: GrantClient,
  depsFor: (mail: LeasedMail) => StepDeps = productionStepDeps,
): Promise<BackfillRun> {
  const client = await grantClient();
  if (typeof client !== "string" || client.length === 0) return { kind: "refused" };
  if (client === AUTONOMY_CLIENT_ID) return { kind: "refused" };
  return { kind: "ran", outcome: await recallBackfill(principal, depsFor(mail)) };
}

/** True when a tool's answer says it is an error. */
function isErrorAnswer(answer: unknown): boolean {
  return (
    typeof answer === "object" &&
    answer !== null &&
    (answer as { isError?: unknown }).isError === true
  );
}

/**
 * The same server, except that every tool registered through it runs one
 * recall step after a successful answer.
 *
 * Every property other than `registerTool` is the real server's own, bound to
 * it. `registerTool` registers the same name and config on the real server,
 * with the callback wrapped:
 *
 * - the original callback runs first, with the same arguments;
 * - if it throws, the same value is rethrown, unread, and no step runs;
 * - if its answer is not an error, one step runs and is awaited;
 * - the original answer object is returned, whatever the step did.
 */
export function withRecallStep(
  server: McpServer,
  principal: Promise<Principal>,
  mail: LeasedMail,
  grantClient: GrantClient,
): McpServer {
  const registerTool = (
    name: string,
    config: unknown,
    callback: (...args: unknown[]) => unknown,
  ): unknown => {
    const driven = async (...args: unknown[]): Promise<unknown> => {
      const answer = await callback(...args);
      if (!isErrorAnswer(answer)) await runRecallStep(principal, mail, grantClient);
      return answer;
    };
    Object.defineProperty(driven, RECALL_DRIVEN, { value: true, enumerable: false });
    return server.registerTool(name, config as never, driven as never);
  };

  return new Proxy(server, {
    get(target, property) {
      if (property === "registerTool") return registerTool;
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
