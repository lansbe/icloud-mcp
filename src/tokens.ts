// The byte-level token codec, and its protocol-neutral refusal.
//
// Base64url encoding, strict UTF-8 decoding, and plain base64 over raw bytes.
// None of it knows anything about a transport, and that is why it lives at the
// root rather than inside one of the protocol trees: every protocol in this
// project mints opaque identifiers and page cursors, and each one needs exactly
// these primitives with exactly this strictness.
//
// **One codec, not one per tree.** The alternative was a second copy, and the
// argument against it is the one the identifier layer already makes about a
// second decoder: a cross-use refusal is a single rule, and a rule living in
// two decoders is a rule that drifts. The `fatal` and `ignoreBOM` reasoning
// below is the concrete thing that would drift — it is a paragraph explaining
// why two settings that look like pedantry are load-bearing, and a copy without
// that paragraph is a copy someone relaxes.
//
// This module contains no logging calls of any kind and must never acquire any.

/**
 * The refusal, named without naming a protocol.
 *
 * This is the one part of the codec that could not simply move. The decoder
 * previously threw the mail tree's own not-found class; a neutral module cannot,
 * because importing a protocol-specific error class here would make this module
 * protocol-specific and would put a second tree's callers on a path through a
 * first tree's error vocabulary.
 *
 * **What each protocol tree owes this class: a translation at its own
 * boundary.** This error is an internal signal, not a caller-visible outcome.
 * Every tree that decodes a token must catch it and rethrow its own not-found
 * class, because the shared error-categorisation function dispatches on type
 * and falls through to a connection diagnosis for anything it does not
 * recognise — so a `TokenDecodeError` that escaped would tell a caller the
 * network failed when what actually happened is that a malformed identifier was
 * refused. The translation is asserted end to end in `test/tokens.test.ts`.
 *
 * Constructed with a fixed internal label and never with any part of the
 * offending input, following the shape every error class in this repository
 * keeps. The commonest way to reach it is a token a model supplied, and a
 * diagnosis quoting that token back — or explaining which check it failed —
 * would teach the model the internal structure the opaque identifier layer
 * exists to withhold.
 */
export class TokenDecodeError extends Error {
  readonly kind = "token-decode" as const;

  constructor() {
    super("token-decode-failed");
    this.name = "TokenDecodeError";
  }
}

/** Base64url's alphabet, with no padding and no whitespace tolerated. */
const BASE64URL_ONLY = /^[A-Za-z0-9_-]+$/;

/** UTF-8 encoding for every token payload. Bytes, never code units. */
export const TOKEN_ENCODER = new TextEncoder();

/**
 * Strict UTF-8 decoding. Both options are set deliberately.
 *
 * `fatal` makes malformed byte sequences throw. The lenient default substitutes
 * U+FFFD for bad input, which is repair rather than decoding — a damaged token
 * would silently become a token naming a *different* mailbox.
 *
 * `ignoreBOM: true` is the stricter of the two readings despite how it sounds:
 * it means a leading byte-order mark is NOT quietly stripped but kept as a code
 * point, where `JSON.parse` then refuses it. The permissive setting would let a
 * BOM-prefixed token through as though it were clean.
 */
export const TOKEN_DECODER = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});

/**
 * Base64url over raw bytes.
 *
 * Takes bytes, never a string, so the caller is forced to decide the encoding
 * before reaching here. Handing a JavaScript string straight to the runtime's
 * base64 primitive encodes UTF-16 code units, which is wrong for every
 * non-ASCII byte and is the same class of bug as measuring a wire length in
 * code units instead of bytes. `credentials.ts` records the same trap on the
 * credential path; this is the same rule applied to mailbox names, which are
 * the values most likely to carry non-ASCII bytes in this whole project.
 *
 * Padding is stripped on the way out and tolerated by its absence on the way
 * back in, so no `=` ever needs escaping wherever a token is carried.
 */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Base64url back to raw bytes, refusing anything that is not exactly that.
 *
 * The alphabet check runs before the runtime primitive rather than relying on
 * it: `atob` tolerates whitespace and accepts the standard `+/` alphabet, so a
 * standard-base64 or whitespace-padded token would otherwise decode where it
 * should be refused.
 */
export function fromBase64Url(token: string): Uint8Array {
  if (!BASE64URL_ONLY.test(token)) throw new TokenDecodeError();

  const padding = "=".repeat((4 - (token.length % 4)) % 4);
  const standard =
    token.replace(/-/g, "+").replace(/_/g, "/") + padding;

  let binary: string;
  try {
    binary = atob(standard);
  } catch {
    // A length that cannot be a base64 quantum, among others.
    throw new TokenDecodeError();
  }

  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/**
 * Plain base64 over raw bytes — standard alphabet, padding kept.
 *
 * Deliberately a second function rather than a flag on `toBase64Url`, because
 * the two answers are not interchangeable and the caller is not choosing a
 * style. A Basic credential header is defined over standard base64 WITH
 * padding, and a server is entitled to reject anything else; an identifier
 * carried through a tool response wants neither, so that no `=` ever needs
 * escaping.
 *
 * Takes bytes for the same reason `toBase64Url` does, and it is the more
 * dangerous of the two places to get it wrong. Handing a JavaScript string
 * straight to the runtime's base64 primitive encodes UTF-16 code units, which
 * is wrong for every non-ASCII byte — and on a credential header that produces
 * a value the server rejects with an authentication failure, which reads as a
 * wrong password rather than as an encoding bug.
 *
 * The runtime's built-in is used rather than a hand-rolled alphabet table.
 */
export function base64Bytes(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}
