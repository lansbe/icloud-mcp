// THE ONLY MODULE IN THIS REPOSITORY THAT MAY OPEN A TCP SOCKET.
//
// This is the structural half of FND-06 (D-11). The detective half is a
// source scan run from the test suite and a git pre-commit hook, and the
// preventive half is the Conventions entry in ./.claude/CLAUDE.md, which
// carries the upstream issue reference and the full rationale.

import { connect } from "cloudflare:sockets";

const HOSTNAME = "imap.mail.me.com";
const PORT = 993;

/**
 * Opens an implicit-TLS IMAP socket to iCloud.
 *
 * Takes no parameters, by design. There is no host argument, no port
 * argument, and no transport-mode argument a caller can supply, so the two
 * unusable paths in this runtime — the opportunistic TLS upgrade, and the
 * cleartext IMAP port that would require it — are not merely rejected but
 * unspeakable. Every option value below is a literal at the call site rather
 * than a variable, a binding, or a config lookup, because a value read from
 * anywhere else is a caller-supplied value by another name.
 *
 * See the Conventions section of ./.claude/CLAUDE.md for the upstream issue
 * reference, its status, and why implicit TLS on the submission-free IMAPS
 * port covers every need this project has.
 */
export function connectImap(): Socket {
  return connect(
    { hostname: HOSTNAME, port: PORT },
    // `allowHalfOpen` stays at its default. The report that produced this
    // project's teardown requirement was filed by someone who had set it
    // true, so leaving it false is a deliberate choice rather than an
    // untouched default.
    { secureTransport: "on", allowHalfOpen: false },
  );
}

/**
 * The endpoint facts the diagnostic reports back to the caller.
 *
 * These are the values actually passed to the connect call above, exported so
 * `mail_imap_diagnose` can report observed configuration rather than a
 * second, independently-written copy of it that could drift.
 */
export const IMAP_ENDPOINT = {
  hostname: HOSTNAME,
  port: PORT,
  secureTransport: "on",
} as const;

/**
 * The conservative ceiling this project designs to (D-10).
 *
 * Production enforces a cap of six simultaneous connections per Worker
 * invocation, and that cap counts far more than sockets: outbound `fetch`
 * calls, Cache API calls, R2 and Queues operations, and KV reads all consume
 * one. The OAuth provider performs a KV lookup on every authenticated
 * request, so a single tool call has already spent one of the six before any
 * mail code runs.
 *
 * There is no wrangler configuration key for this. The option was requested
 * upstream and did not ship, and the `limits` block accepts only `cpu_ms` and
 * `subrequests`. The limit is therefore architectural: one live socket per
 * request, and never a concurrent fan-out around the connect call above.
 *
 * iCloud's own ceiling is undocumented and deliberately not measured — a
 * self-inflicted lockout would take Mail.app down across the user's own
 * devices. Three is the conservative constant chosen instead.
 */
export const MAX_CONCURRENT_CONNECTIONS = 3;
