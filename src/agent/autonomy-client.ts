// The autonomy client, in one place.
//
// Autonomy is inherent (owner, 2026-09-27). Every interactive sign-in also
// mints one grant for this client, and the person's own Durable Object keeps
// that grant's refresh token, sealed. This file holds the fixed facts about the
// client and nothing else.
//
// Phase 26 created this file with the id alone, because Phase 26 needs the id
// first: it reads it to keep the recall build off the autonomy key. A tool call
// made with that key never runs a build step (26-CONTEXT D-35). Phase 27 (plan
// 27-01) adds the other exports here rather than in a second file, so the id is
// spelled exactly once under `src/`. A second copy is how two spellings drift
// apart until one of them stops matching, and a mismatch here fails open: the
// build would index with the autonomy key.
//
// WHY A CONSTANT ID. The library's own client creation always picks a random
// sixteen-character id, so dynamic registration can never produce this one. The
// owner's setup command creates the client through the library and then
// re-keys that one record under this id. A constant id also lets the owner's
// grant listing label autonomy grants by id, and never by a name any
// registrant can choose.
//
// WHY THE REDIRECT PATH IS NEVER SERVED (D-29). The library requires a redirect
// URI at the second authorization and again at the code exchange. The code is
// read out of the library's redirect URL in memory by the sign-in, and handed
// to the object; no browser is ever sent there, and this server answers 404 on
// every path but the sign-in page. The redirect allow list is NOT widened for
// it. It already refuses this server's own origin, so a browser cannot drive
// this client through the sign-in page at all.
//
// NO LIFETIME OF ITS OWN (D-33, owner's answers of 2026-09-27). The key lives
// exactly as long as the person's ordinary connection and ends with it. So
// nothing here sets a lifetime, and nothing anywhere sets one for this client.
//
// `AUTONOMY_TOOLS` IS THE WHOLE LIST of tools the key may call, and it is
// closed. Phase 27 put one name on it: the check that the key works. Phase 28
// widened it to four under its D-09 (28-CONTEXT.md), for the rules job that runs
// on the person's own object with nobody present:
//   - the sign-in check, which also tells the job the account's own address, so
//     it never drafts a reply to it;
//   - the change check, which lists new inbox mail by sender and subject;
//   - the flag, which the job only ever sets and never clears;
//   - the reply tool, which places a threaded draft reply and never sends it.
// Nothing else. The tool that writes a brand-new message to anyone is NOT on
// it: a rule's draft is always a reply to the sender (D-05 as revised). So the
// job cannot send, delete, move, write a new message, answer an invitation or
// write an event. Phase 27's `call` refuses any name outside this list before a
// request leaves the object.
//
// The change check's name is held here as a literal because the object may not
// import tool code. A test ties it to the tool module's own constant, so a
// rename fails a test instead of silently stopping the job.
//
// There is ONE list, here. No second list of tool names lives anywhere under
// `src/agent/`. Adding a fifth name is a decision on the autonomous layer's rule
// in CLAUDE.md, not a refactor.
//
// No imports, on purpose. The owner's Node scripts import this file too, so it
// must stay a leaf: a leaf that imports nothing can be imported from anywhere
// without dragging a module graph, or the Worker runtime, along with it.

/** The fixed client id of the autonomy grant. */
export const AUTONOMY_CLIENT_ID = "icloud-mcp-autonomy";

/** The client's name, as the owner's listing and the grant's metadata show it. */
export const AUTONOMY_CLIENT_NAME = "iCloud MCP autonomy";

/**
 * The one redirect path the client carries, on this server's own origin.
 * Never served, and never visited by a browser (D-29).
 */
export const AUTONOMY_REDIRECT_PATH = "/autonomy/internal";

/**
 * Every tool the autonomy key may call, and nothing else (Phase 28, D-09).
 *
 * Frozen, so no module can push a name onto it at run time. Its element type
 * is the job's tool-name type, so a call naming anything else does not compile
 * either. A fifth name is a decision, not a refactor.
 */
export const AUTONOMY_TOOLS = Object.freeze([
  "account_whoami",
  "changes_since",
  "mail_flag",
  "mail_compose_reply",
] as const);
