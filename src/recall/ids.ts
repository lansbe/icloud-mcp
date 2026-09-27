// The id of a recall vector (Phase 25, RCLL-03, D-04).
//
// A vector's id is the lower-case hex SHA-256 of the person's user id, a colon,
// and the message token `encodeMessageId` already mints. 64 characters. It is a
// digest of the existing token, not a new identifier scheme.
//
// Why a digest and not the token itself. The store refuses an id longer than
// 64 bytes, and the message token is longer than that for any real mailbox and
// UIDVALIDITY.
//
// Why the user id is in the digest input. The store's id space is treated as
// index-wide, not per partition (SPIKE-09 (3) is unstated, so this designs to
// the cautious reading). Two people can hold a message with the same folder,
// the same UIDVALIDITY and the same UID. Without the user id their ids would
// collide, and one person's write would replace the other's vector.
//
// `TOKEN_VERSION` in the message-token module stays the one version field. A
// change to the token format changes every id, which is what it should do.
//
// This module imports only a TYPE, and nothing from the mail tree. Callers
// encode the ref and pass the token in. That keeps the person's object, which
// reaches this module through the store, from reaching the mail tree even
// indirectly: a type-only import is erased at build time.

import type { Principal } from "../principal";

const HEX = "0123456789abcdef";

/** The vector id for one message of one person. */
export async function vectorIdOf(principal: Principal, refToken: string): Promise<string> {
  const input = new TextEncoder().encode(`${principal.userId}:${refToken}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  let out = "";
  for (const byte of digest) out += HEX[byte >> 4]! + HEX[byte & 15]!;
  return out;
}
