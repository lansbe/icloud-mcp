// Who a rule's draft reply goes to (Phase 28, D-05 as revised, D-30).
//
// THIS IS THE ONE PLACE an address from a stranger's message becomes a
// recipient. It takes only the address in the message's From line, exactly as
// the row holds it. It never takes the sender's display name, the header that
// asks for replies to go somewhere else, the sender line, anyone copied, or any
// address in the text. Nothing else under `src/agent/` turns an address into a
// recipient, and the job's only caller of this function is `placeDraft`.
//
// It can say no, with one reason:
//   - `mailing-list`: the message came from a mailing list. Nobody wants a rule
//     replying to a list.
//   - `no-address`: the From address is missing, or is not one bare address
//     (the same check a rule's own sender addresses pass, in `./rules`).
//   - `own-address`: the From address is this account's own. A rule must never
//     reply to the person it works for.
//
// FROM CAN BE FORGED. Anyone can put any address in the From line, so a reply
// may be addressed to someone who did not write the message. That is accepted,
// not hidden: it is only ever a draft, and the person sees the address before
// sending it, as CLAUDE.md's autonomous-layer rule says. This function is not
// what protects against it, and does not pretend to be.
//
// `self` is the account's own address, as the sign-in check answered it. It is
// compared, and never answered. This module logs nothing.

import { isBareAddress } from "./rules";
import type { EnvelopeRow } from "./tool-call";

/** Why a reply is not placed. A closed list. */
type ReplySkip = "no-address" | "own-address" | "mailing-list";

/** Where a reply goes, or why it does not. */
type ReplyRecipient =
  | { readonly kind: "reply"; readonly to: string }
  | { readonly kind: "skip"; readonly reason: ReplySkip };

/**
 * The three Apple mail domains. One iCloud mailbox answers at all three, so
 * the same local part at any of them is the same person.
 */
const APPLE_DOMAINS: readonly string[] = ["icloud.com", "me.com", "mac.com"];

/** An address split at its one `@`, lower-cased. The caller checked the shape. */
function partsOf(address: string): { local: string; domain: string } {
  const at = address.indexOf("@");
  return { local: address.slice(0, at).toLowerCase(), domain: address.slice(at + 1).toLowerCase() };
}

/**
 * Whether `from` is this account's own address: the same address without
 * regard to case, or, when the account is at an Apple domain, the same local
 * part at any of the three.
 */
function isOwnAddress(from: string, self: string): boolean {
  const a = partsOf(from);
  const b = partsOf(self);
  if (a.local !== b.local) return false;
  if (a.domain === b.domain) return true;
  return APPLE_DOMAINS.includes(a.domain) && APPLE_DOMAINS.includes(b.domain);
}

/**
 * The reply's one recipient: the row's From address exactly as the row holds
 * it, or a skip naming one reason. Never `self`, never a display name, never
 * any other string. Never throws.
 */
export function replyRecipient(row: EnvelopeRow, self: string): ReplyRecipient {
  try {
    if (row.mailingList) return { kind: "skip", reason: "mailing-list" };
    const from = row.senderAddress;
    if (!isBareAddress(from)) return { kind: "skip", reason: "no-address" };
    // An own address that cannot be read cannot be ruled out, so nothing is
    // answered as a reply. Decided by Claude, owner may revise.
    if (!isBareAddress(self)) return { kind: "skip", reason: "own-address" };
    if (isOwnAddress(from, self)) return { kind: "skip", reason: "own-address" };
    return { kind: "reply", to: from };
  } catch {
    return { kind: "skip", reason: "no-address" };
  }
}
