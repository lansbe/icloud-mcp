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
// ONE SESSION PER STEP (D-27). A step opens at most one iCloud session, and
// holds the lease for that session only. What the step does in that session is
// `recallStep`'s business, in ./sync.ts.
//
// NOTHING THE STEP DOES REACHES THE ANSWER. A step that is refused, finds the
// lease busy, or fails, is silent. The caught value is never read, nothing here
// logs (./.claude/CLAUDE.md §4), and nothing is thrown.

import type { McpServer } from "@modelcontextprotocol/server";
import { AUTONOMY_CLIENT_ID } from "../agent/autonomy-client";
import type { LeasedMail } from "../agent/lease";
import type { Principal } from "../principal";
import { productionStepDeps, recallStep } from "./sync";

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
