// The reachable-deployment half of D-03: a post-deploy gate on the live 401.
//
// The in-process counterpart (test/auth-ordering.test.ts) proves ORDERING —
// that a tool handler is never reached on an unauthenticated request, using a
// canary that records its own invocation. It runs the real Worker composition
// inside workerd, which is exactly why it can say nothing about deployment: it
// never touches the network, so it cannot tell whether the thing actually
// serving traffic at the custom domain is this Worker, an older version of it,
// or something else entirely.
//
// This script proves the complementary thing and nothing more: the deployed
// origin, reached over the public internet, refuses an unauthenticated call.
// Two checks that assert different properties, not the same property twice.
//
//   node scripts/smoke-unauthenticated.mjs                       # live default
//   node scripts/smoke-unauthenticated.mjs https://host/mcp      # explicit
//
// Exit 0 only when both probes hold. Anything else — a wrong status, a missing
// challenge, an unresolvable host, a TLS failure — exits non-zero. A check that
// turns an unreachable host into a passing result certifies nothing, and with
// workers_dev: false (D-02) an unreachable host is a genuine and likely failure
// mode rather than a hypothetical one. There is deliberately no fallback status
// code anywhere below.

import { getHostname } from "./hostname.mjs";

/** The one tool the deployed surface exposes. */
const TOOL_NAME = "mail_imap_diagnose";

/**
 * A token that is syntactically a bearer credential and semantically nothing.
 *
 * The second probe exists because a deploy that accepted any token-shaped
 * string would sail through a header-absent-only check: "no Authorization
 * header" and "an Authorization header that means nothing" are different code
 * paths in every OAuth implementation, and only one of them is exercised by
 * omitting the header.
 */
const BOGUS_BEARER = "Bearer not-a-real-token-but-well-formed";

/**
 * Resolve the target.
 *
 * The default comes from `getHostname()` — the single derivation of the
 * deployed hostname this phase established — rather than from a second copy of
 * the same wrangler.jsonc lookup. A hostname change stays a one-line edit to
 * the config instead of a hunt for every reader of it.
 *
 * @returns {string}
 */
function targetUrl() {
  const explicit = process.argv[2];
  if (explicit !== undefined && explicit !== "") return explicit;
  return `https://${getHostname()}/mcp`;
}

/**
 * A well-formed 2026-07-28 `tools/call`, so a rejection cannot be blamed on the
 * request.
 *
 * The revision requires `Mcp-Method` and `Mcp-Name` headers alongside the body,
 * plus the `params._meta` envelope. Sending a deliberately malformed request
 * would make a 401 ambiguous: it could mean the gate rejected it, or it could
 * mean anything downstream would have rejected it too. Everything here is
 * exactly what a real client sends, minus a valid credential.
 *
 * @returns {string}
 */
function requestBody() {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: TOOL_NAME,
      arguments: {},
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  });
}

/**
 * Fire one probe and report whether it held.
 *
 * No try/catch: a fetch that rejects propagates to the top-level handler, which
 * exits non-zero. Swallowing it here and substituting a status would convert an
 * unreachable deployment into a passing gate.
 *
 * @param {string} url
 * @param {string} label
 * @param {Record<string, string>} extraHeaders
 * @returns {Promise<boolean>}
 */
async function probe(url, label, extraHeaders) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "Mcp-Method": "tools/call",
      "Mcp-Name": TOOL_NAME,
      ...extraHeaders,
    },
    body: requestBody(),
  });

  const challenge = response.headers.get("www-authenticate") ?? "";
  const statusHeld = response.status === 401;
  const challengeHeld = challenge.startsWith("Bearer");
  const held = statusHeld && challengeHeld;

  process.stdout.write(`${held ? "PASS" : "FAIL"}  ${label}\n`);
  process.stdout.write(
    `        status ${response.status} (want 401)` +
      `${statusHeld ? "" : "  <-- WRONG"}\n`,
  );
  process.stdout.write(
    `        www-authenticate ${challenge === "" ? "(absent)" : challenge}` +
      `${challengeHeld ? "" : "  <-- must begin with Bearer"}\n`,
  );

  return held;
}

async function main() {
  const url = targetUrl();
  process.stdout.write(`Unauthenticated smoke check against ${url}\n\n`);

  // Sequential, not concurrent. Two in-flight requests is not a load test worth
  // running against production, and sequential output reads in order.
  const noHeader = await probe(url, "no Authorization header", {});
  const bogusToken = await probe(url, "bogus bearer token", {
    authorization: BOGUS_BEARER,
  });

  if (noHeader && bogusToken) {
    process.stdout.write("\nBoth probes held: the deployed endpoint is gated.\n");
    return;
  }

  process.stderr.write(
    "\nThe deployed endpoint did NOT refuse an unauthenticated tools/call.\n" +
      "This is a live auth gate on an endpoint that reaches real personal mail.\n" +
      "Do not treat this as a flaky check — roll back or fix before proceeding.\n",
  );
  process.exit(1);
}

main().catch((err) => {
  // Reaching here means the request never completed: DNS failure, TLS failure,
  // connection refused, or a malformed target. None of those is a pass.
  process.stderr.write(
    `\nThe smoke check could not complete, so the gate is UNPROVEN:\n  ${err}\n`,
  );
  process.exit(1);
});
