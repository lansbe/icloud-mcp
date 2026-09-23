// Which Apple ID this connection is signed in as (LIFE-06, D4).
//
// The answer is MASKED: the first character of the local part, three bullets,
// and the domain. `u•••@example.invalid`. The full address is never returned,
// behind any flag or any argument, and this tool takes no arguments at all.
//
// A local part of exactly one character keeps no character — `•••@x.invalid` —
// because keeping "the first character" of a one-character local part keeps all
// of it. That edge is the only thing standing between the sentence above and
// being false, so it is named here rather than only at the function.
//
// **This is a recorded exception, not a breach.** The project's standing rule is
// that the Apple ID never appears in a tool response. The exception is written
// down on the safety boundary itself, in `.claude/CLAUDE.md` Conventions § 4
// (D4, LIFE-06, decided 2026-09-21), because a session reading § 4 alone would
// read this file as a leak and delete it — and deleting it breaks a requirement
// rather than fixing a violation. Read that subsection before changing anything
// here.
//
// **Where the answer comes from.** The principal the door built from the grant,
// and nowhere else. This module opens no socket, sends no request and reads no
// environment secret. It imports nothing from the mail tree, nothing from the
// DAV tree, nothing from the environment types, and never the password reader.
//
// **The masked form is built by one function**, `maskAppleId` in
// `src/principal.ts`. A mask written inline here would be a second rule, and two
// rules drift until one of them stops masking. The owner's grants script calls
// the same one.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { toErrorCategory } from "../../errors";
import type { Principal } from "../../principal";
import { maskAppleId } from "../../principal";

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
 * One field, `signedInAs`, holding what `maskAppleId` builds. Nothing else goes
 * in: no user id, no grant count, no client name. CONTEXT leaves extra fields to
 * discretion provided nothing else crosses the standing rule, and none is needed
 * to answer the question this tool exists for — which account is this connection
 * on, asked by someone at a shared laptop.
 *
 * Exported so the answer's shape can be asserted without a door and without a
 * request. It reads exactly one field of the principal and builds the mask from
 * it; it reads no password, because the password is not on the principal at all.
 */
export function signedInAsResult(principal: Principal): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ signedInAs: maskAppleId(principal.appleId) }),
      },
    ],
  };
}

/**
 * Register `account_whoami` on a per-request server instance.
 *
 * No input schema and no arguments, exactly as the mail diagnostic does it.
 * There is no value a caller can supply, so there is nothing a caller could
 * supply that would widen the answer.
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
        "Show which Apple ID this connection is signed in as. The address is " +
        "masked on purpose.",
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
