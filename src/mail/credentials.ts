// The write-only credential helper.
//
// The two WRITE helpers consume the app-specific password and return nothing.
// No object holding it is ever constructed and handed back, so no such object
// can be logged, serialized, attached to an error, or spread into a response.
//
// **That guarantee is about the PASSWORD, and the third export does not touch
// it.** `draftFromAddress` returns the Apple ID, and the distinction is written
// down rather than left to be inferred, because a reader who takes the sentence
// above as "this module returns nothing, ever" will read the third export as a
// breach of it. Reading the Apple ID is not new: `writeLoginCommand` already
// reads it into a local. What IS new is that the value now travels into a
// persisted message and, echoed, into a tool response — so that helper is
// deliberately given the Apple ID and nothing else, and the password is not in
// scope anywhere on its path.
//
// There is deliberately NO "build the command line" function here. IMAP puts
// the credential inline in the command — unlike an HTTP header there is no
// structurally separate field a redactor could target by name — so a helper
// that returned the finished line would hand every caller the exact string
// this module exists to contain. One convenience of that shape would undo the
// whole pattern.
//
// This module contains no logging calls of any kind and must never acquire
// any.

import { isConfiguredSecret } from "../auth/login-handler";
import type { Env } from "../env";
import { ImapAuthError } from "../errors";

const ENCODER = new TextEncoder();

/**
 * The characters that cannot appear inside an IMAP quoted string at all.
 *
 * RFC 3501's QUOTED-CHAR production excludes CR and LF outright. They have no
 * escaped form — so unlike a double-quote or a backslash, there is nothing to
 * substitute and refusing is the only correct handling. NUL is excluded on the
 * same grounds, and additionally delimits the SASL PLAIN blob, where a value
 * carrying one would silently redraw the username/password boundary.
 */
const ILLEGAL_IN_QUOTED_STRING = /[\r\n\u0000]/;

/**
 * Refuse a value carrying a character that is illegal in a quoted string.
 *
 * Refusing beats escaping, and the reason is not pedantry about the grammar. A
 * value carrying CR or LF does not produce a bad argument — it terminates the
 * command line early and injects a SECOND command line into the stream, whose
 * tag is taken from the credential's own bytes. Servers routinely quote the
 * offending tag or command fragment back in a `BAD` response.
 *
 * That reply is the problem. `src/mcp/tools/diagnose.ts` and
 * `src/mail/diagnose.ts` both forward the server's prose in
 * `authFailureDetail`, and both argue it is safe because the credential travels
 * in the command sent and never in the reply. The argument holds only while the
 * credential cannot influence what the server says, and this check is what
 * makes that true.
 *
 * The ordinary way a value acquires one of these characters is mundane and is
 * the reason this is not theoretical: a secret provisioned from a file carries
 * the file's trailing newline.
 *
 * A refusal is also the honest diagnosis. Escaping around it would send a value
 * the server rejects, and the user would be told the app-specific password was
 * wrong when the value is correct and only its encoding is not.
 */
function assertNoIllegalCharacters(value: string): void {
  if (ILLEGAL_IN_QUOTED_STRING.test(value)) throw new ImapAuthError();
}

/**
 * Refuse a binding that was never provisioned.
 *
 * Declared as an assertion signature rather than a boolean predicate on
 * purpose: `src/env.ts` types the three secret bindings as absent-or-string,
 * which is what they are at runtime, so the write helpers below need the value
 * narrowed before it reaches `quoted`. A predicate returning plain `boolean`
 * would not narrow at the call site and would leave the choice between a
 * failing typecheck and a forbidden cast. This narrows and needs neither.
 *
 * Wraps `isConfiguredSecret` rather than restating it — one definition of what
 * a usable configured secret looks like, shared with the `/authorize` path that
 * first needed it (CR-01).
 *
 * `ImapAuthError` is the right category and no fifth one is invented for this:
 * its fixed safe message already says a human needs to check the app-specific
 * password and that retrying will not help, which is exactly true of a binding
 * that is not set. The category it replaces, `connection_failed`, says the
 * opposite — that a retry is worth trying.
 */
function assertProvisioned(
  value: string | undefined,
): asserts value is string {
  if (!isConfiguredSecret(value)) throw new ImapAuthError();
}

/**
 * Wrap one argument as an IMAP quoted string.
 *
 * Module-private and never exported. An unescaped double-quote or backslash
 * desynchronises the server's parser, and the resulting failure looks exactly
 * like a rejected credential — the most expensive possible confusion on this
 * path, because it points the investigation at the password.
 *
 * The illegal-character refusal runs first, because the two characters it
 * rejects are not in the same class as the two escaped below: these have an
 * escaped form, those have none.
 *
 * The backslash substitution runs first of the two; reversing them would
 * re-escape the backslashes introduced by the quote substitution.
 */
function quoted(value: string): string {
  assertNoIllegalCharacters(value);
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Base64 over raw bytes.
 *
 * Takes bytes, not a string, so the caller is forced to decide the encoding
 * before reaching here. Handing a JavaScript string straight to the runtime's
 * base64 primitive encodes UTF-16 code units, which is wrong for every
 * non-ASCII byte and is the same class of bug as measuring a wire length in
 * code units instead of bytes.
 *
 * The runtime's built-in is used rather than a hand-rolled alphabet table.
 */
function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}

/**
 * The address a draft is authored as.
 *
 * **Fixed, and never a parameter.** A caller-supplied `From` is a
 * caller-supplied identity, on a message that will go out under the user's own
 * name — so the identity is resolved here, from the binding, and the compose
 * tool exposes no way to name one.
 *
 * Three things this function does and one it must never do:
 *
 * - It returns the Apple ID and nothing else. No object, no pair, no record —
 *   there is nothing here to spread into a response or attach to an error.
 * - `assertProvisioned` runs first, so an unset binding REFUSES rather than
 *   stringifying. That check is behavioural rather than compiler-driven and
 *   must not be removed on the grounds that the typecheck passes without it:
 *   the value lands in a template literal one module over, and a template
 *   literal accepts an absent binding silently, stringifying it to the nine
 *   characters that spell the absent value. A draft authored by that
 *   placeholder is a message with a fabricated sender.
 * - `assertNoIllegalCharacters` runs next, because the value reaches a header
 *   line: a secret provisioned from a file carries the file's trailing newline,
 *   and a newline in a `From` header injects a second header.
 * - **It must never be handed the app-specific password.** Nothing here reads
 *   it, and nothing that calls this may pass it in.
 */
export function draftFromAddress(env: Env): string {
  const appleId = env.APPLE_ID;
  assertProvisioned(appleId);
  assertNoIllegalCharacters(appleId);
  return appleId;
}

/**
 * Write a tagged `LOGIN` command directly into the socket writer.
 *
 * Returns `undefined`. The credential enters this function through `env` and
 * leaves it only as bytes on the writer.
 */
export async function writeLoginCommand(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  tag: string,
  env: Env,
): Promise<void> {
  // Both checks run as statements before the write, not inside its argument.
  // That ordering is the fix: a refusal raised while building the argument
  // would already be too late if any byte had gone out, and a rejected value
  // must leave no partial line on the wire for the server to read as the start
  // of a command.
  const appleId = env.APPLE_ID;
  const password = env.APPLE_APP_PASSWORD;
  assertProvisioned(appleId);
  assertProvisioned(password);

  await writer.write(
    ENCODER.encode(`${tag} LOGIN ${quoted(appleId)} ${quoted(password)}\r\n`),
  );
}

/**
 * Write a tagged `AUTHENTICATE PLAIN` command with its initial response inline.
 *
 * The initial-response form avoids the continuation round trip, which the
 * server's advertised capability list supports. The blob is base64 of the byte
 * sequence NUL, username, NUL, password — encoded to UTF-8 bytes first, then
 * base64ed. Returns `undefined`.
 *
 * Both checks below are made explicitly here rather than inherited, because
 * this path never reaches `quoted` — the values go to `base64` instead.
 *
 * The presence check in particular is BEHAVIOURAL, not compiler-driven, and
 * must not be removed on the grounds that the typecheck passes without it. The
 * values land in a template literal, and a template literal accepts an absent
 * binding silently: it stringifies to the nine characters spelling "undefined".
 * So the compiler raises nothing here, and without this check an unprovisioned
 * binding is base64-encoded and sent to iCloud as a literal placeholder
 * username and password. A green typecheck is not evidence the check is
 * redundant.
 *
 * The legality check matters here for a second reason on top of the shared one:
 * NUL is this mechanism's own field delimiter, so a value carrying one moves
 * the boundary between username and password inside the blob.
 */
export async function writeAuthenticatePlainCommand(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  tag: string,
  env: Env,
): Promise<void> {
  const appleId = env.APPLE_ID;
  const password = env.APPLE_APP_PASSWORD;
  assertProvisioned(appleId);
  assertProvisioned(password);
  assertNoIllegalCharacters(appleId);
  assertNoIllegalCharacters(password);

  const initialResponse = base64(
    ENCODER.encode(`\0${appleId}\0${password}`),
  );
  await writer.write(
    ENCODER.encode(`${tag} AUTHENTICATE PLAIN ${initialResponse}\r\n`),
  );
}
