// Which Apple ID this connection is signed in as (LIFE-06, D4).
//
// The answer is the WHOLE address. `user-a@example.invalid`. Not a mask, not a
// first character and a domain — the address, as the grant this connection was
// built from stored it.
//
// **The masked form shipped first and was reversed** (owner decision,
// 2026-09-23). D4 chose the mask on 2026-09-21; asked live against the deployed
// server, the masked answer made the model say it could not confirm WHICH
// account it was on, which is the only question this tool exists to answer. The
// mask defeated the tool. The full address was chosen instead, with the cost
// accepted rather than argued away.
//
// **The cost, stated plainly.** This address is the login half of the credential
// pair, and a tool response is text the model reads and may quote into a draft,
// an event or a later message. That is real and it is not denied here. What is
// returned is one address — the one belonging to the person holding this
// connection — back to that same person. The password is not here and cannot be:
// it is not on the principal at all.
//
// **This is a recorded reversal, not a breach.** The argument is written down on
// the safety boundary itself, in `.claude/CLAUDE.md` Conventions § 4 (D4,
// LIFE-06, reversed 2026-09-23), because a session reading § 4 alone would read
// this file as a leak and delete it — and deleting it breaks a requirement
// rather than fixing a violation. Read that subsection before changing anything
// here.
//
// **Where the answer comes from.** The principal the door built from the grant,
// and nowhere else. This module opens no socket, sends no request and reads no
// environment secret. It imports nothing from the mail tree, nothing from the
// DAV tree, nothing from the environment types, and never the password reader.
//
// **`maskAppleId` in `src/principal.ts` stays, and is still the one masking
// rule.** It is no longer called from here. It governs the owner's grants
// listing, which prints one line per connection and is read at a glance, and it
// keeps its own table of tests. The reversal is scoped to this one tool.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { toErrorCategory } from "../../errors";
import type { Principal } from "../../principal";

/**
 * The MCP content result this tool produces, success or failure.
 *
 * A type alias rather than an interface, deliberately: the SDK's callback
 * return type carries an index signature, and TypeScript will not treat an
 * interface as assignable to one — only an alias or an object literal.
 */
type ToolResult = {
  isError?: boolean;
  content: { type: "text"; text: string }[];
};

/**
 * Shape the answer for one principal. The pure half, with no transport in it.
 *
 * One field, `signedInAs`, holding the principal's Apple ID as the grant stored
 * it. Nothing else goes in: no user id, no grant count, no client name. CONTEXT
 * leaves extra fields to discretion, and none is needed to answer the question
 * this tool exists for — which account is this connection on, asked by someone
 * with more than one Apple ID.
 *
 * **It reads `principal.appleId` and nothing else, and it transforms nothing.**
 * No fold, no trim, no mask. The address the door built the principal from is
 * the address that comes back, so what the user reads is what this connection
 * actually signs in to Apple as. A folded copy could differ from the stored one
 * in case or padding, and then the answer would be about a string this server
 * made up rather than about the account.
 *
 * Exported so the answer's shape and its provenance can be asserted without a
 * door and without a request. It reads no password, because the password is not
 * on the principal at all.
 */
export function signedInAsResult(principal: Principal): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ signedInAs: principal.appleId }),
      },
    ],
  };
}

/**
 * Register `account_whoami` on a per-request server instance.
 *
 * No input schema and no arguments, exactly as the mail diagnostic does it.
 * There is no value a caller can supply, so there is no argument that could
 * change what the answer holds. Adding one — a mode, a flag, a second address —
 * is a new decision on the safety boundary rather than a refactor.
 *
 * `principal` is a promise of who the request acts for, and the callback awaits
 * it as the first line of its own `try`, like every other tool (D-27). A
 * rejection — a grant this server will not build a principal from, a password it
 * refuses — answers `auth_failed` with the same fixed message every other tool
 * gives, because the recovery is the same one: sign in again. The caught value
 * is never read; `toErrorCategory` dispatches on its type.
 *
 * **A dead-password pause is one of those rejections, and this tool is NOT
 * exempt from it** (owner decision, 2026-09-22). The two diagnostics are, because
 * their job is explaining a failure; this one's is naming an account. So a paused
 * user reads `auth_failed` here and runs `mail_imap_diagnose` or `dav_diagnose`
 * to find out why. See `answersDuringPause` in `src/password-pause.ts`.
 */
export function registerAccountTool(
  server: McpServer,
  principal: Promise<Principal>,
): void {
  server.registerTool(
    "account_whoami",
    {
      description:
        "Show which Apple ID this connection is signed in as. Returns the " +
        "full address.",
    },
    async () => {
      try {
        const actor = await principal;
        return signedInAsResult(actor);
      } catch (err) {
        const { category, message } = toErrorCategory(err);
        return {
          isError: true,
          content: [
            { type: "text" as const, text: JSON.stringify({ category, message }) },
          ],
        };
      }
    },
  );
}
