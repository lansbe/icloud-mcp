// The autonomy grant's client id, in one place.
//
// This is the fixed client id of the autonomy grant: the grant a scheduled job
// uses to call this server's tools without a person at the keyboard.
//
// Phase 26 created this file with this one export, because Phase 26 needs the
// id first: it reads it to keep the recall build off the autonomy key. A tool
// call made with that key never runs a build step (26-CONTEXT D-35).
//
// Phase 27 (plan 27-01) adds its other exports to THIS file rather than
// creating a second one, so the id is spelled exactly once under `src/`. A
// second copy is how two spellings drift apart until one of them stops
// matching, and a mismatch here fails open: the build would index with the
// autonomy key.
//
// No imports, on purpose. A leaf that imports nothing can be imported from
// anywhere without dragging a module graph along with it.

/** The fixed client id of the autonomy grant. */
export const AUTONOMY_CLIENT_ID = "icloud-mcp-autonomy";
