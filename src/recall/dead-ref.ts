// Remove a recall result that no longer opens (Phase 26, RCLL-08).
//
// This is the lazy half of SEED-006 D-3's dead-ref path (ARCHITECTURE §4.6(a);
// this phase's D-17 item a). When `mail_get_message` answers not-found for a
// message, that message is gone from iCloud, or its mailbox was recreated. If
// the person's index still holds it, a later recall would keep offering a result
// that cannot be opened. So it is removed at once, here, instead of waiting for
// the next sync of its folder.
//
// THE LEDGER IS ASKED FIRST. The person's object answers which ids it holds. A
// person whose index does not hold this message costs one object read and no
// store call at all. Only a held id goes on to Phase 25's `forgetRefs`, which
// deletes from the store first and then from the ledger, so the ledger stays a
// superset of the store.
//
// IT NEVER CHANGES WHAT THE CALLER IS TOLD. The whole body sits in one `try`,
// and the `catch` returns without reading the caught value. It never throws, so
// the tool that calls it answers exactly the not-found answer it would have
// given anyway. A failed removal leaves the vector for the next sync to find.
//
// It reads no mail, so it takes no lease and no page slot. The id is recomputed
// from the caller's own principal, so it can only ever name that person's
// vector. No logging (./.claude/CLAUDE.md §4).

import { agentFor } from "../agent/lease";
import { encodeMessageId, type MessageRef } from "../mail/ids";
import type { Principal } from "../principal";
import { forgetRefs } from "./build";
import { vectorIdOf } from "./ids";
import { type RecallDeps, recallDeps } from "./pipeline";

/**
 * Remove `ref` from `principal`'s index when the index holds it.
 *
 * Never throws. `deps` is a function so the production default reads no
 * binding until a removal is actually needed, and tests pass fakes.
 */
export async function forgetDeadRef(
  principal: Principal,
  ref: MessageRef,
  deps: () => RecallDeps = recallDeps,
): Promise<void> {
  try {
    const id = await vectorIdOf(principal, encodeMessageId(ref));
    const held = await agentFor(principal).recallHolds([id]);
    if (!held.includes(id)) return;
    await forgetRefs(principal, [ref], deps());
  } catch {
    return;
  }
}
