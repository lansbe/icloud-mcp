// Registration of the one tool this phase ships.
//
// The tool takes no arguments at all (D-06). Its callback's only parameter is
// the request context, so there is no arguments object to validate and no
// value a caller can supply that could reach the connect call. The reasoning
// behind the exact registration shape used below — and why an empty object
// would NOT be equivalent — is recorded in 01-02-SUMMARY.md rather than here.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import {
  ImapAuthError,
  ImapThrottleError,
  toErrorCategory,
} from "../../errors";
import type { DiagnosticOutcome } from "../../mail/diagnose";
import { runDiagnosticOutcome } from "../../mail/diagnose";
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
 * Turn a finished diagnostic run into the tool's response.
 *
 * Exported so the failure shapes can be asserted without a socket. No
 * automated job in this repository may authenticate against the real Apple ID,
 * so a response shaper welded to the transport would be untestable rather than
 * merely awkward.
 *
 * On failure the caller gets the FND-05 category and its fixed safe message,
 * and — for the two refusal types where the server said something worth
 * keeping — its own rejection text alongside them, under a field named for
 * which refusal it was.
 *
 * That last part is the whole point. "iCloud rejected the stored credentials"
 * is true of a wrong password and of a username format iCloud will not accept,
 * and those need different fixes. Apple's own reply is what tells them apart,
 * and it originates on the server: the credential travels in the command we
 * sent, never in the reply, so echoing the reply cannot echo the credential.
 *
 * A connection-limit refusal gets the same treatment (WINDOWS.md ledger entry
 * 6). It is the weaker of the two cases — the fixed safe message already tells
 * the caller to wait rather than retry — but this server has never returned a
 * throttle response in any observed run, so the first one it ever does return
 * is the only evidence of that shape there will be, and discarding it would
 * throw away the entire sample.
 *
 * Every branch dispatches on the error's TYPE and reads a report field. Nothing
 * here inspects message text — neither here nor in `toErrorCategory`, which is
 * contractually forbidden from reading `.message` or `.stack` because a caught
 * value on the credential path can carry a raw IMAP command line with the
 * password inline.
 */
export function diagnosticResult(outcome: DiagnosticOutcome): ToolResult {
  if (!outcome.failed) {
    return {
      content: [
        { type: "text", text: JSON.stringify(outcome.report, null, 2) },
      ],
    };
  }

  // The single FND-05 boundary. Only the category and its fixed safe message
  // cross it — never the caught value's own text.
  const { category, message } = toErrorCategory(outcome.error);

  // Two branches, not one. A connection-limit refusal now carries the server's
  // own words the same way an authentication refusal already does, and it
  // arrives under its OWN field name — the two failures are different facts and
  // a shared field would make the response ambiguous about which one it is
  // reporting.
  //
  // Both branches dispatch on the error's TYPE, and each one reads a
  // report field rather than anything belonging to the caught value. The
  // vocabulary is untouched: `toErrorCategory` above still returns one of the
  // same four categories with its same fixed message, and widening this gate
  // adds no fifth.
  let detailField: "authFailureDetail" | "throttleFailureDetail" | null = null;
  let detail: string | null = null;

  if (outcome.error instanceof ImapAuthError) {
    detailField = "authFailureDetail";
    detail = outcome.report.authFailureDetail;
  } else if (outcome.error instanceof ImapThrottleError) {
    detailField = "throttleFailureDetail";
    detail = outcome.report.throttleFailureDetail;
  }

  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          detailField === null || detail === null
            ? { category, message }
            : { category, message, [detailField]: detail },
        ),
      },
    ],
  };
}

/**
 * Register `mail_imap_diagnose` on a per-request server instance.
 *
 * The `mail_` prefix is deliberate: once calendar and contacts tools land,
 * an unprefixed `diagnose` would invite the model to reach for the wrong
 * protocol's health check.
 *
 * This is a permanent health check, not phase scaffolding (D-08). When a mail
 * tool fails in a later phase, "is it iCloud, my credentials, or our code?"
 * is answerable in one call with no deploy and no log dive.
 *
 * `principal` is a promise of who the request acts for. The callback awaits it
 * as the first line of its `try` (D-27). A refusal is already the auth error,
 * and the `catch` below already maps that to `auth_failed`, so an unset secret
 * reads the same as it always has.
 */
export function registerDiagnoseTool(
  server: McpServer,
  principal: Promise<Principal>,
): void {
  server.registerTool(
    "mail_imap_diagnose",
    {
      // Terse on purpose: a tool description is a token tax paid on every
      // call for the life of the server, and this tool is permanent surface.
      description: "Check iCloud IMAP connectivity, auth, and capabilities.",
    },
    async () => {
      try {
        await principal;
        return diagnosticResult(await runDiagnosticOutcome(env));
      } catch (err) {
        // A backstop for anything the diagnostic did not already fold into an
        // outcome. Same boundary, same fixed vocabulary.
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
