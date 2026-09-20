// The IMAP wire conversation. SOCKET-FREE by construction.
//
// Everything here takes a `DuplexLike`, never a concrete socket, so plan
// 01-03's injected-failure tests and every later unit test can drive a real
// conversation with an in-memory TransformStream and no network. That seam is
// also where Phase 2's byte-counted literal parser attaches.
//
// This module contains no logging calls of any kind, and must never acquire
// any. IMAP puts the app-specific password inline in the LOGIN command, so a
// single "log what I am about to write" line here would put the credential
// into retained observability storage.

import type { Principal } from "../principal";
import {
  ImapAuthError,
  ImapConnectError,
  ImapThrottleError,
} from "../errors";
import {
  writeAuthenticatePlainCommand,
  writeLoginCommand,
} from "./credentials";
import type { ResponseLine } from "./imap-parser";
import {
  LITERAL_SUFFIX,
  indicatesConnectionLimit,
  isUntagged,
  literalPlaceholder,
  parseTaggedResponse,
  stripNul,
} from "./imap-parser";

/**
 * The duck-typed stream pair this module operates on.
 *
 * Structurally satisfied by a real socket, and by any in-memory fake with the
 * same four members — which is the whole point.
 */
export interface DuplexLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed: Promise<void>;
  close(): Promise<void>;
}

/**
 * How long teardown waits for the `closed` promise before giving up on it.
 *
 * This is a backstop, not the primary mechanism — see `teardown`.
 */
export const CLOSE_TIMEOUT_MS = 3000;

/**
 * The deadline on a single inbound read.
 *
 * Calibrated against the live proof (`01-IMAP-PROOF.md` § 4), where the slowest
 * whole stage was `loginMs` 219 and the slowest single read was the greeting at
 * `tlsHandshakeMs` 154. Ten seconds is roughly two orders of magnitude of
 * headroom for one server turn while staying far inside the Worker wall budget.
 *
 * It bounds ONE read, not a whole conversation. A server that keeps answering,
 * however slowly, is never cut off by this; a server that stops answering
 * entirely is.
 */
export const READ_TIMEOUT_MS = 10000;

/**
 * The deadline on teardown's step 2, the drain.
 *
 * Bounds the drain as a whole, not each read within it, so the worst case for
 * the entire teardown is `DRAIN_TIMEOUT_MS + CLOSE_TIMEOUT_MS` — **5000 ms**.
 * That sum is the number a later reader needs, which is why it is stated here
 * rather than left to be recomputed.
 *
 * Two seconds is generous against the live proof's `closeMs` of 0: steps 2
 * through 4 completed in under a millisecond against the real server, so a
 * healthy iCloud teardown is three orders of magnitude clear of this deadline.
 */
export const DRAIN_TIMEOUT_MS = 2000;

/**
 * The most literal payload this client will retain from one `{n}` declaration.
 *
 * What it bounds: the bytes KEPT in memory from a single literal. What it
 * deliberately does not bound: how many octets are consumed from the stream.
 * Everything past this ceiling is read and DISCARDED rather than refused, and
 * that distinction is the whole point. Abandoning the read would leave the
 * undeclared remainder sitting in the stream to be misparsed as commands — the
 * exact desynchronisation the byte counter exists to prevent — so a hostile
 * `{4294967295}` must be walked past, not walked away from.
 *
 * Truncating rather than erroring is also what keeps the FND-05 vocabulary
 * closed at four values. A fifth category for "that message was too big" was
 * considered and rejected: the caller can do nothing differently, and the
 * response already carries a truncation flag.
 *
 * Calibrated at 2 MiB, matching `src/mail/mime.ts`'s extracted-text ceiling
 * because the two are the same failure seen from either side. Peak memory on
 * the common path is roughly raw + parsed + decoded attachments, about three
 * times the wire size, so 2 MiB costs ~6 MiB against a 128 MB isolate and
 * leaves room for MIME parsing and JSON serialisation inside a bounded CPU
 * budget. It is far above any real piece of correspondence and far below
 * anything that threatens the isolate.
 */
export const MAX_LITERAL_OCTETS = 2 * 1024 * 1024;

/**
 * The injectable read bound (D-51, WINDOWS.md ledger entry 9).
 *
 * The exported constants above remain the defaults, so production behaviour is
 * unchanged and the existing tests that import them as values keep working.
 * This adds a seam rather than replacing a constant.
 *
 * An injectable bound on a safety path is a bound a future caller can set
 * wrong. The mitigation is structural: `withMailSession` in `./service.ts` is
 * the only production construction site, so there is exactly one place to audit
 * an injected value.
 *
 * `maxLiteralOctets` is the second use of that seam and the first one that is
 * not about a timeout, so it is worth saying what changes and what does not.
 * The exported constant remains the default, so every path that does not ask
 * for a raise behaves exactly as Phase 2 shipped it — including the tests that
 * import the constant as a value. What the seam buys is that the attachment
 * fetch in `./service.ts` can raise the ceiling FOR ITS OWN CALL rather than
 * globally, which is the difference between widening one command's exposure and
 * widening the whole-message read path's.
 */
export interface ChannelOptions {
  /** Overrides `READ_TIMEOUT_MS` for this channel only. */
  readTimeoutMs?: number;
  /**
   * Overrides `MAX_LITERAL_OCTETS` for this channel only.
   *
   * Raising this does NOT turn a truncation into a refusal — it only moves
   * where the truncation happens. The refusal lives in `./service.ts`, as an
   * unconditional pre-check against the part's declared octet count, and it is
   * required whether or not this option is set.
   */
  maxLiteralOctets?: number;
}

/** The injectable teardown bounds. Same seam, same reasoning as `ChannelOptions`. */
export interface TeardownOptions {
  /** Overrides `DRAIN_TIMEOUT_MS` for this teardown only. */
  drainTimeoutMs?: number;
  /** Overrides `CLOSE_TIMEOUT_MS` for this teardown only. */
  closeTimeoutMs?: number;
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();
const LF = 0x0a;

/** What `withDeadline` resolves to when the timer wins. */
const TIMED_OUT = Symbol("deadline-expired");

/**
 * Race `promise` against a timer, resolving `onTimeout()` if the timer wins.
 *
 * A `try`/`catch` is NOT a substitute for this and never was. A `catch` handles
 * a promise that *rejects*; it does nothing whatsoever about a promise that
 * never settles at all. The latter is precisely the shape `reader.read()` takes
 * against a peer that has completed its handshake and then neither sends a byte
 * nor closes its side — the case this module's teardown docstring says it exists
 * to defend against, and the case an unbounded `await` cannot survive.
 *
 * The timer is cleared whichever side wins, so a Worker request is never held
 * open by a pending timeout that no longer has a reader.
 *
 * The no-op rejection handler on the losing promise is load-bearing rather than
 * decorative. When teardown abandons a read and then calls `releaseLock()`, the
 * streams implementation rejects that outstanding read; with nothing subscribed
 * it would surface as an unhandled rejection inside the isolate, on a path whose
 * whole purpose is to fail quietly and let the remaining teardown steps run.
 *
 * Exported for exactly one outside caller: the per-call deadline in
 * `./service.ts`. It is exported rather than copied because a copy would omit
 * the rejection handler above — the part that is easiest to leave out and the
 * part whose absence surfaces as an unhandled rejection inside the isolate,
 * arbitrarily far from the code that caused it.
 */
export function withDeadline<T>(
  promise: Promise<T>,
  ms: number,
  onTimeout: () => T,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  promise.catch(() => {
    // See above: the abandoned read's eventual rejection must land somewhere.
  });

  return Promise.race([
    promise,
    new Promise<T>((resolve) => {
      timer = setTimeout(() => resolve(onTimeout()), ms);
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * How much of the server's own reply text the report may carry.
 *
 * Long enough to keep a real rejection reason intact, short enough that a
 * chatty or hostile server cannot use the field as an unbounded channel into
 * a model-visible response.
 *
 * The bound is on the ASSEMBLED string, not on each part. Truncating per part
 * and then concatenating made the real ceiling roughly twice this number plus
 * the label text, so the field was bounded — just not by the number written
 * here. It also meant the ceiling grew with the number of mechanisms tried: a
 * later phase adding a third to the fallback chain would have widened it again
 * by following the existing pattern exactly. Under a single truncation of the
 * finished string, that phase inherits this bound for free.
 */
const MAX_FAILURE_DETAIL = 200;

/**
 * Bound one piece of server reply text for a connection-limit refusal.
 *
 * **Nothing here parses, normalises, or pattern-matches the text, and that is a
 * constraint rather than an omission.** This server has never returned a
 * throttle response in any observed run, so its shape is genuinely unknown. The
 * only evidence that will ever exist about that shape is the text itself, and a
 * transform applied to it on the way out would discard exactly the thing the
 * field was added to capture. Inventing a format also risks the same
 * misclassification a Phase 1 gap-closure plan removed — see
 * `indicatesConnectionLimit` in `./imap-parser.ts`, whose two classification
 * lists must not grow a guessed throttle pattern either.
 *
 * So: pass through verbatim, apart from the length bound. A later contributor
 * reading this should not "improve" it into a parser.
 *
 * The bound is `MAX_FAILURE_DETAIL`, applied ONCE — see that constant, which
 * says the ceiling is on the assembled string so a later phase inherits it for
 * free. This is that later phase, and it inherits it by calling this once on a
 * single finished string rather than per part.
 */
function boundedReplyDetail(text: string): string | null {
  return text.length === 0 ? null : text.slice(0, MAX_FAILURE_DETAIL);
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const joined = new Uint8Array(left.length + right.length);
  joined.set(left, 0);
  joined.set(right, left.length);
  return joined;
}

/**
 * A line-oriented view over one `DuplexLike`.
 *
 * Owns the single reader for the connection's lifetime — deliberately, so
 * that `teardown` can drain that same reader without re-acquiring a lock the
 * conversation still holds.
 *
 * Every outbound command is encoded with a `TextEncoder`. Where a byte count
 * is ever needed it must come from the encoded value's `byteLength`, never
 * from a JavaScript string's `.length`: the two diverge on any non-ASCII
 * input. Phase 1 sent no literals, so the warning was a note about a seam;
 * Phase 2's non-ASCII search term is the first caller to depend on it, and
 * Phase 4's APPEND inherits the same machinery. Getting the count wrong fails
 * silently on exactly the messages a user cares about — too small and the
 * server parses the tail of the value as a new command, too large and it waits
 * for octets that never come.
 */
export class ImapChannel {
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;

  readonly #writable: WritableStream<Uint8Array>;
  readonly #readTimeoutMs: number;
  readonly #maxLiteralOctets: number;
  #buffer: Uint8Array = new Uint8Array(0);
  #ended = false;
  #issuedTags = 0;

  constructor(duplex: DuplexLike, options: ChannelOptions = {}) {
    this.reader = duplex.readable.getReader();
    this.#writable = duplex.writable;
    this.#readTimeoutMs = options.readTimeoutMs ?? READ_TIMEOUT_MS;
    this.#maxLiteralOctets = options.maxLiteralOctets ?? MAX_LITERAL_OCTETS;
  }

  /**
   * Hand out the next command tag.
   *
   * The counter belongs to the channel rather than the module, so two requests
   * running at once cannot collide on a tag — module-level state here would be
   * shared across every invocation of the Worker in the same isolate.
   */
  nextTag(): string {
    this.#issuedTags += 1;
    return `a${this.#issuedTags}`;
  }

  /**
   * Read one CRLF-terminated line, without its terminator.
   *
   * Every read is bounded by `READ_TIMEOUT_MS`, and a read that expires raises
   * `ImapConnectError`. `readGreeting` and `readUntilTag` both reach the wire
   * only through this method, so they inherit the bound and no inbound wait
   * anywhere in this module is unbounded.
   *
   * That matters most on the greeting. A server at its connection ceiling may
   * complete the TLS handshake and then stall without saying anything — an
   * unbounded read there would hold a socket open against the very ceiling that
   * caused the stall, for the whole request budget, and the caller's teardown
   * would never run.
   */
  async readLine(): Promise<string> {
    for (;;) {
      const index = this.#buffer.indexOf(LF);
      if (index !== -1) {
        const raw = DECODER.decode(this.#buffer.subarray(0, index));
        this.#buffer = this.#buffer.slice(index + 1);
        return raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      }

      if (this.#ended) {
        if (this.#buffer.length > 0) {
          const raw = DECODER.decode(this.#buffer);
          this.#buffer = new Uint8Array(0);
          return raw;
        }
        // The peer closed before completing a line we were waiting for.
        throw new ImapConnectError();
      }

      let chunk: ReadableStreamReadResult<Uint8Array> | typeof TIMED_OUT;
      try {
        chunk = await withDeadline<
          ReadableStreamReadResult<Uint8Array> | typeof TIMED_OUT
        >(this.reader.read(), this.#readTimeoutMs, () => TIMED_OUT);
      } catch {
        // Deliberately swallows the underlying value rather than wrapping it:
        // a transport error raised mid-conversation can carry the bytes that
        // were in flight, and on the credential path those bytes are the
        // LOGIN command.
        throw new ImapConnectError();
      }

      // The deadline expired. Same context-free error, for the same reason and
      // with even less to say: there is no underlying value here to inspect,
      // wrap, or re-raise — the peer simply stopped answering.
      if (chunk === TIMED_OUT) throw new ImapConnectError();

      if (chunk.done) {
        this.#ended = true;
        continue;
      }
      if (chunk.value) this.#buffer = concat(this.#buffer, chunk.value);
    }
  }

  /**
   * Read exactly `n` octets, bounded, and never decoded.
   *
   * Returns raw bytes rather than a string, and that is a correctness
   * requirement rather than a preference: a literal carries base64, binary, or
   * any charset, and a `TextDecoder` pass here would replace every invalid byte
   * with U+FFFD — silently, irrecoverably, and in a way that also breaks the
   * relationship between the declared count and what came back.
   *
   * Every underlying read is bounded by the same deadline `readLine()` uses, so
   * a peer that announces `{4000000}` and then stalls cannot hold a socket for
   * the whole request budget against iCloud's low, undocumented ceiling.
   *
   * All `n` octets are consumed from the stream, but at most the channel's
   * literal ceiling — `MAX_LITERAL_OCTETS` unless one was injected — are kept.
   * Consuming past the cap is what keeps the stream synchronised: an abandoned
   * read leaves the remainder to be misparsed as commands, which is precisely
   * the desync this whole path exists to close.
   *
   * **The short array carries no truncation signal, and that is deliberate
   * here and dangerous one layer up.** Nothing in the returned value says
   * whether it is whole. A caller that must not receive a corrupt prefix —
   * the attachment fetch in `./service.ts` is the one that must not — has to
   * refuse BEFORE asking, against the octet count the structure already
   * declared. Raising this ceiling does not change that; it only moves where
   * the silence would happen.
   *
   * Chunks are collected and concatenated ONCE. The `concat()` helper this file
   * uses for lines copies the whole accumulated buffer per chunk, which is
   * negligible for a line and quadratic for a two-megabyte payload — roughly
   * 128 copies averaging a megabyte each, on a CPU budget shared with MIME
   * parsing and JSON serialisation.
   *
   * The `catch` is `readLine()`'s, verbatim in spirit: a context-free transport
   * error, never wrapping or inspecting the caught value, because an error
   * raised mid-conversation can carry the bytes that were in flight.
   */
  async readOctets(n: number): Promise<Uint8Array> {
    if (n <= 0) return new Uint8Array(0);

    const keepLimit = Math.min(n, this.#maxLiteralOctets);
    const kept: Uint8Array[] = [];
    let keptLength = 0;
    let remaining = n;

    while (remaining > 0) {
      if (this.#buffer.length > 0) {
        const take = Math.min(remaining, this.#buffer.length);
        if (keptLength < keepLimit) {
          // A view, not a copy. The chunk it points into is never mutated, and
          // the single concatenation below is the only copy this method makes.
          kept.push(
            this.#buffer.subarray(0, Math.min(take, keepLimit - keptLength)),
          );
          keptLength += Math.min(take, keepLimit - keptLength);
        }
        this.#buffer = this.#buffer.subarray(take);
        remaining -= take;
        continue;
      }

      if (this.#ended) {
        // The declared octets never arrived. A literal that is short is not a
        // recoverable condition: everything after it would be read at the wrong
        // offset.
        throw new ImapConnectError();
      }

      let chunk: ReadableStreamReadResult<Uint8Array> | typeof TIMED_OUT;
      try {
        chunk = await withDeadline<
          ReadableStreamReadResult<Uint8Array> | typeof TIMED_OUT
        >(this.reader.read(), this.#readTimeoutMs, () => TIMED_OUT);
      } catch {
        // See readLine(): the caught value is deliberately not inspected.
        throw new ImapConnectError();
      }
      if (chunk === TIMED_OUT) throw new ImapConnectError();

      if (chunk.done) {
        this.#ended = true;
        continue;
      }
      // Direct assignment rather than concat: the buffer is empty here by the
      // loop's own structure, so there is nothing to join and no copy to make.
      if (chunk.value) this.#buffer = chunk.value;
    }

    const payload = new Uint8Array(keptLength);
    let offset = 0;
    for (const piece of kept) {
      payload.set(piece, offset);
      offset += piece.length;
    }
    return payload;
  }

  /**
   * Read ONE logical response, following literals by octet count.
   *
   * This is the security fix, and the reason is worth stating plainly. A reader
   * that returns on the first line matching its own tag can be terminated by a
   * message body, because tags are issued as `a1`, `a2`, … and are therefore
   * predictable, and because anyone who can send mail to this account controls
   * the bytes of a body. A body containing the line `a7 OK done` ends the read
   * early, makes the reported status a lie, and feeds the remainder of that body
   * to the NEXT command's reader — desynchronising the session against
   * attacker-chosen text. Counting octets closes it; nothing else does.
   *
   * No line terminator is consumed after a literal, deliberately. The byte
   * immediately after the last literal octet continues the SAME logical line —
   * the closing `)` of a `FETCH` reply arrives that way — so the next
   * `readLine()` picks up the remainder of the line already in progress.
   *
   * For a literal-free response this returns the line with an empty literal
   * list, so every Phase 1 path behaves byte-for-byte as it did before.
   */
  async readResponse(): Promise<ResponseLine> {
    let text = "";
    const literals: Uint8Array[] = [];
    for (;;) {
      const line = stripNul(await this.readLine());
      const match = LITERAL_SUFFIX.exec(line);
      if (match === null) return { text: text + line, literals };

      text += line.slice(0, match.index) + literalPlaceholder(literals.length);
      literals.push(await this.readOctets(Number(match[1])));
    }
  }

  /**
   * Run `emit` with an exclusive writer, releasing the lock afterwards.
   *
   * This is how the credential helper reaches the socket: it is handed the
   * writer and writes its own bytes, so the finished command line is never a
   * value in this module's scope and never crosses a function boundary as a
   * string. The lock is released on every path so nothing holds the writable
   * side when `close()` is eventually called.
   *
   * Any failure is replaced with a context-free transport error. That is
   * deliberate rather than lazy: a failure raised here happens while the
   * credential bytes are in flight, and the caught value can carry them.
   *
   * The guarantee covers ACQUIRING the writer as well as emitting through it.
   * `getWriter()` throws on an already-locked stream — reachable here, because
   * a `releaseLock()` failure below is swallowed — and acquiring outside the
   * conversion boundary would let that raw value escape on the credential path.
   * It was previously safe only because `toErrorCategory` happens to dispatch
   * on type; that is luck, not the guarantee this docstring makes.
   */
  async withWriter(
    emit: (writer: WritableStreamDefaultWriter<Uint8Array>) => Promise<void>,
  ): Promise<void> {
    let writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
    try {
      writer = this.#writable.getWriter();
      await emit(writer);
    } catch (err) {
      // The one deliberate exemption. An `ImapAuthError` raised inside `emit`
      // means the credential itself is unusable — absent or malformed — which
      // is permanent. Converting it would report it as `connection_failed`,
      // whose safe message tells the caller a retry is worth trying, and a
      // caller retrying a missing secret in a loop is the exact mis-signal this
      // module's error vocabulary exists to prevent.
      //
      // Safe to re-raise because `ImapAuthError` takes no constructor argument
      // and carries a fixed internal label, so it cannot have picked up any
      // credential-adjacent text on the way here. This is a check on the value's
      // TYPE; nothing reads its `.message` or `.stack`, here or downstream.
      if (err instanceof ImapAuthError) throw err;
      throw new ImapConnectError();
    } finally {
      try {
        writer?.releaseLock();
      } catch {
        // Already released or the stream is gone; neither is actionable.
      }
    }
  }

  /** Write one line, appending the CRLF terminator. */
  async write(line: string): Promise<void> {
    await this.withWriter(async (writer) => {
      await writer.write(ENCODER.encode(`${line}\r\n`));
    });
  }

  /**
   * Write raw bytes with no terminator appended.
   *
   * Goes through `withWriter` so that method's error-conversion guarantee holds
   * on this path too — a failure while raw bytes are in flight is converted to
   * a context-free transport error rather than escaping with whatever the
   * stream layer chose to say about the buffer it was holding.
   *
   * The count for any literal these bytes belong to must come from
   * `byteLength`, never from a string's `.length`; see this class's docstring.
   */
  async writeBytes(bytes: Uint8Array): Promise<void> {
    await this.withWriter(async (writer) => {
      await writer.write(bytes);
    });
  }
}

/**
 * Read the connection greeting.
 *
 * Reads until the first untagged line completes, which is the greeting by
 * definition — nothing else can precede it. A greeting that itself announces
 * a refusal is classified here, at the point of knowledge, rather than being
 * passed up as an opaque failure.
 */
export async function readGreeting(channel: ImapChannel): Promise<string> {
  for (;;) {
    const line = await channel.readLine();
    if (!isUntagged(line)) continue;

    if (line.startsWith("* BYE") && indicatesConnectionLimit(line)) {
      // The asymmetry a later reader will otherwise take for a bug: the other
      // two raise sites read their text from a PARSED TAGGED REPLY, and this
      // one reads it from the line itself. That is correct here — a greeting
      // refusal arrives as an untagged farewell, before any command has been
      // sent, so there is no tagged completion in existence to parse. The line
      // IS the server's reply, and it is still the server's own text rather
      // than a caught value's.
      throw new ImapThrottleError(boundedReplyDetail(line));
    }
    return line;
  }
}

/**
 * The outcome of one tagged command exchange.
 *
 * Both members carry `ResponseLine` rather than `string` since Phase 2: a
 * single logical response may span many physical lines and carry literal
 * payloads, and collapsing that back to a string would either lose the payload
 * or decode it at the wrong layer. For a literal-free response the shape is
 * `{ text: <the line>, literals: [] }`, so every Phase 1 path reads `.text` and
 * sees exactly what it saw before.
 */
export interface CommandResult {
  /** The tagged completion, verbatim. */
  tagged: ResponseLine;
  /** Every untagged response the server emitted before it, in order. */
  untagged: ResponseLine[];
  /** The parsed completion status. */
  status: "OK" | "NO" | "BAD";
}

/**
 * Send one tagged command and read through to its tagged completion.
 *
 * Tolerates any number of interleaved untagged `*` lines first, and any
 * number of tagged lines belonging to other tags — both are legal, and a
 * reader that stopped at the first tagged line it saw would desynchronise.
 */
export async function sendCommand(
  channel: ImapChannel,
  tag: string,
  line: string,
): Promise<CommandResult> {
  await channel.write(`${tag} ${line}`);
  return readUntilTag(channel, tag);
}

/**
 * Read through to the tagged completion of a command already on the wire.
 *
 * Split out from `sendCommand` because the authentication commands are not
 * written from a line: their bytes are produced inside the credential helper,
 * which never yields a string for anyone to pass along.
 *
 * **Reads through `readResponse()`, not `readLine()`, and that is the security
 * control this phase turns on.** See `ImapChannel.readResponse` for why a
 * line-splitting reader here is terminable by a message body. Any future code
 * path that reads a `FETCH`, `LIST` or `SEARCH` reply without coming through
 * here reopens it.
 */
export async function readUntilTag(
  channel: ImapChannel,
  tag: string,
): Promise<CommandResult> {
  const untagged: ResponseLine[] = [];
  for (;;) {
    const received = await channel.readResponse();
    const parsed = parseTaggedResponse(received.text);

    if (parsed && parsed.tag === tag) {
      return { tagged: received, untagged, status: parsed.status };
    }
    untagged.push(received);
  }
}

/**
 * Whether a response line is a command continuation request.
 *
 * `continue-req = "+" SP (resp-text / base64)` — the text after the sign is
 * free-form, so the match is on the sign itself or on its space-suffixed
 * prefix, NEVER on a whole line. A whole-line match would fail against every
 * real server (they all say something after the sign) and would also fail
 * against the bare form some send.
 */
function isContinuation(text: string): boolean {
  return text === "+" || text.startsWith("+ ");
}

/**
 * How a wait for a command continuation ended.
 *
 * Two outcomes rather than one-plus-an-exception, and that shape is a decision
 * rather than a convenience. A tagged rejection arriving instead of a
 * continuation is not always a failure: an unsupported search charset arrives
 * as a tagged `NO` carrying a `BADCHARSET` response code, and RFC 3501 §6.4.4 is
 * explicit that it is a `NO` and not a `BAD`. That is a well-specified answer —
 * the search ran and the server declined the encoding — which `./service.ts`
 * reports as an empty result rather than as an error, because none of the four
 * categories in the closed vocabulary describes it honestly.
 *
 * An exception here would destroy that distinction at the only place it exists.
 * Raising would also add a class `toErrorCategory` does not recognise, which
 * falls through to `connection_failed` — telling the caller to retry a command
 * that will be refused identically every time.
 */
export type ContinuationOutcome =
  | {
      kind: "continuation";
      /** Everything the server volunteered while the continuation was pending. */
      untagged: ResponseLine[];
    }
  | {
      kind: "rejected";
      /** The completion the server sent INSTEAD of a continuation. */
      result: CommandResult;
    };

/**
 * Wait for the server's continuation after a synchronizing literal's length.
 *
 * **The rejection branch is the entire point of this function**, and it is worth
 * stating at length because the naive implementation does not have it and looks
 * correct without it.
 *
 * RFC 3501 §2.2.1 gives the client three obligations, and only the first is
 * obvious. The server "sends a command continuation request response if it is
 * ready for the octets". But: "If instead, the server detected an error in the
 * command, it sends a BAD completion response with a tag matching the command
 * … to reject the command and prevent the client from sending any more of the
 * command." And: "It is also possible for the server to send a completion
 * response for some other command …, or untagged data. In either case, the
 * command continuation request is still pending; the client takes the
 * appropriate action for the response, and reads another response."
 *
 * Omit the second and the client blocks forever on a continuation that is never
 * coming. `READ_TIMEOUT_MS` converts that permanent hang into a ten-second
 * stall raised as `ImapConnectError` — half of the twenty-second call deadline
 * in `./service.ts` spent on a question the server has already answered, and
 * then reported to the caller as a transient transport fault whose safe message
 * says it is worth retrying. The retry sends the identical malformed command and
 * stalls identically. One branch turns all of that into an immediate, honest
 * answer (T-02-36, PITFALLS #7).
 *
 * Untagged lines and other tags' completions are COLLECTED and reading
 * continues, per the third obligation. They are handed back rather than dropped
 * because the caller merges them into the finished command's untagged list —
 * an `* EXPUNGE` that arrived during the handshake is as real as one that
 * arrives after it.
 *
 * Every read is bounded by the channel's own read deadline, so even a server
 * that sends neither a continuation nor a completion cannot hold the socket
 * past that bound.
 */
export async function awaitContinuation(
  channel: ImapChannel,
  tag: string,
): Promise<ContinuationOutcome> {
  const untagged: ResponseLine[] = [];
  for (;;) {
    // Through `readResponse`, never `readLine`, for the reason that method's
    // docstring gives: a literal payload may itself contain a line beginning
    // with a plus sign, and anyone who can send mail to this account chooses
    // those bytes. Only a byte-counted reader can tell that payload from the
    // server's own go-ahead.
    const received = await channel.readResponse();
    if (isContinuation(received.text)) return { kind: "continuation", untagged };

    const parsed = parseTaggedResponse(received.text);
    if (parsed !== null && parsed.tag === tag) {
      return {
        kind: "rejected",
        result: { tagged: received, untagged, status: parsed.status },
      };
    }
    untagged.push(received);
  }
}

/** The mechanisms this client will attempt, in the order it attempts them. */
export type AuthMechanism = "LOGIN" | "AUTHENTICATE PLAIN";

/** What the authentication exchange established. */
export interface AuthOutcome {
  authenticated: boolean;
  /** Which mechanism the server accepted, or `null` if none did. */
  mechanism: AuthMechanism | null;
  /**
   * The server's own reply text from each rejection, labelled and truncated.
   *
   * `null` on success. This text is Apple's, not ours — the credential is in
   * the command we sent, never in the reply — and it is what distinguishes a
   * wrong password from a wrong username format for a legacy account. Those
   * two failures are otherwise indistinguishable, and the alternative way to
   * tell them apart is a log dive that the credential policy on this path
   * forbids anyway.
   */
  failureDetail: string | null;
}

function replyText(result: CommandResult): string {
  return parseTaggedResponse(result.tagged.text)?.text ?? "";
}

/**
 * Authenticate, with exactly one fallback.
 *
 * `LOGIN` is attempted first: the greeting does not advertise that the command
 * is disabled, so it should be permitted, and it is the simpler path. If the
 * server refuses, the SASL mechanism is attempted **once** and then the
 * attempt stops. There is no third try and no loop — a client that keeps
 * retrying against a server that has already refused is the behaviour most
 * likely to escalate a temporary problem into a lockout of the user's own mail
 * across their own devices.
 *
 * The choice of mechanism is deliberately NOT an option, a parameter, or a
 * binding. Exposing it would reintroduce a caller-supplied value into a tool
 * defined as taking none, and the point of this function is to *discover*
 * which mechanism the server accepts, not to be told.
 *
 * Classification happens here, at the point of knowledge. A refusal that names
 * a connection ceiling is a throttle rather than a credential problem, and
 * retrying the other mechanism against it would make things worse — so that
 * case raises immediately instead of falling through to the retry.
 *
 * Returns the verdict rather than raising on a double rejection: the server's
 * reply text has to reach the diagnostic report as a dedicated field, and an
 * exception raised from here would strand it. The caller raises on the next
 * line, once it has recorded what the server said.
 */
export async function authenticate(
  channel: ImapChannel,
  principal: Principal,
): Promise<AuthOutcome> {
  const loginTag = channel.nextTag();
  await channel.withWriter((writer) =>
    writeLoginCommand(writer, loginTag, principal),
  );
  const login = await readUntilTag(channel, loginTag);

  if (login.status === "OK") {
    return { authenticated: true, mechanism: "LOGIN", failureDetail: null };
  }
  // Read from the parsed tagged reply, never from a caught value. See
  // `ImapThrottleError` for why that distinction is the whole safety argument.
  if (indicatesConnectionLimit(login.tagged.text)) {
    throw new ImapThrottleError(boundedReplyDetail(replyText(login)));
  }

  const saslTag = channel.nextTag();
  await channel.withWriter((writer) =>
    writeAuthenticatePlainCommand(writer, saslTag, principal),
  );
  const sasl = await readUntilTag(channel, saslTag);

  if (sasl.status === "OK") {
    return {
      authenticated: true,
      mechanism: "AUTHENTICATE PLAIN",
      failureDetail: null,
    };
  }
  if (indicatesConnectionLimit(sasl.tagged.text)) {
    throw new ImapThrottleError(boundedReplyDetail(replyText(sasl)));
  }

  // Both rejections are carried, not just the last. The first one is the more
  // diagnostic of the two when the username format is the real problem.
  //
  // Exactly one truncation, applied to the finished string — see
  // MAX_FAILURE_DETAIL. Slicing the parts instead would bound each of them and
  // none of the whole.
  const detail = (
    `LOGIN: ${replyText(login)} | ` +
    `AUTHENTICATE PLAIN: ${replyText(sasl)}`
  ).slice(0, MAX_FAILURE_DETAIL);

  return { authenticated: false, mechanism: null, failureDetail: detail };
}

/**
 * What the `closed` promise did, as three distinguishable facts.
 *
 * - `"closed"` — `sock.closed` fulfilled. The ordinary clean exit.
 * - `"rejected"` — `sock.closed` rejected. **This is the one that was actually
 *   observed against the real server** (01-IMAP-PROOF.md § 5): `closeMs` 0,
 *   `logoutOk` true, no leaked connection. Unremarkable for a socket whose peer
 *   has already sent `* BYE` and closed its side, and benign.
 * - `"timed-out"` — the backstop timer fired before `closed` settled either way.
 *   **This is the dangerous one.** It is the runtime hang step 4's race exists
 *   for: a promise that never settles, holding a connection open against
 *   iCloud's low, undocumented ceiling for the whole request budget.
 *
 * A boolean carried all three until now, and its `false` value meant both the
 * benign observed case and the dangerous one — a signal that erases itself.
 * `closeMs` disambiguated them, but only by inference and only for a reader who
 * knew to look. WINDOWS.md ledger entry 5 is that defect; this type closes it.
 *
 * `closeMs` is deliberately KEPT alongside this. It is what made the live proof
 * interpretable and it remains the independent cross-check: a `"timed-out"`
 * cannot show a sub-millisecond `closeMs`, and a `"rejected"` from a healthy
 * peer cannot show one at the deadline. Two fields, two jobs — which is exactly
 * what the defect was the absence of.
 */
export type CloseOutcome = "closed" | "rejected" | "timed-out";

/** What teardown observed on the way out. */
export interface TeardownResult {
  logoutOk: boolean;
  /** Which of the three ways step 4's race can end actually happened. */
  closeOutcome: CloseOutcome;
  /** Duration of step 1 alone (LOGOUT sent, tagged completion read). */
  logoutMs: number;
  /** Duration of steps 2 through 4 (drain, close, and the `closed` race). */
  closeMs: number;
}

/**
 * Close the connection in four steps, in order.
 *
 * 1. Send LOGOUT and read through to its tagged completion.
 * 2. **Drain the readable, bounded by `DRAIN_TIMEOUT_MS`.** Draining is not
 *    optional and not defensive programming. The runtime's `closed` promise
 *    resolves only after the readable has been read to completion; that
 *    behaviour is specified and intentional rather than a bug awaiting a fix.
 *    A session that reads exactly as far as the LOGOUT completion and then
 *    awaits `closed` hangs on every single call, not intermittently.
 *
 *    But the drain being *required* for `closed` does not make the drain itself
 *    bounded, and those are separate facts. Against a peer that never sends EOF
 *    the read never settles, so an unbounded drain never returns and steps 3
 *    and 4 are never reached — the backstop below would be unreachable in the
 *    exact failure it is written for. Abandoning the drain therefore falls
 *    through to `close()` and the race rather than returning: giving up on the
 *    drain costs at most a `closed` that will not resolve, which is precisely
 *    what step 4 already handles.
 * 3. Call `close()` explicitly. Stream completion alone is not a close.
 * 4. Race `closed` against `CLOSE_TIMEOUT_MS`. This is the backstop for a
 *    server that accepts the socket but never sends EOF, so a stuck promise
 *    cannot consume the whole request budget while holding a connection open
 *    against iCloud's low, undocumented ceiling.
 *
 * Every step is individually wrapped, so a failure in one does not skip the
 * rest. Teardown itself does not throw: a connection that cannot be closed
 * tidily is a fact to report, not a reason to abandon the remaining steps.
 */
export async function teardown(
  sock: DuplexLike,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  sendCommand: (line: string) => Promise<string>,
  options: TeardownOptions = {},
): Promise<TeardownResult> {
  const drainTimeoutMs = options.drainTimeoutMs ?? DRAIN_TIMEOUT_MS;
  const closeTimeoutMs = options.closeTimeoutMs ?? CLOSE_TIMEOUT_MS;

  // Step 1 — LOGOUT.
  const logoutStart = Date.now();
  let logoutOk = false;
  try {
    const tagged = await sendCommand("LOGOUT");
    logoutOk = parseTaggedResponse(tagged)?.status === "OK";
  } catch {
    // Fall through: the remaining steps still have to run.
  }
  const logoutMs = Date.now() - logoutStart;

  const closeStart = Date.now();

  // Step 2 — drain the readable, bounded as a whole and per read.
  //
  // Both bounds are needed and neither implies the other. The overall deadline
  // stops a peer that dribbles a byte at a time from extending the drain
  // indefinitely; the per-read deadline stops a single never-settling read from
  // consuming the loop before the overall deadline is ever re-examined. Each
  // read is given only the time remaining, so the whole loop is capped at
  // DRAIN_TIMEOUT_MS rather than at that value per iteration.
  const drainDeadline = Date.now() + drainTimeoutMs;
  try {
    for (;;) {
      const remaining = drainDeadline - Date.now();
      if (remaining <= 0) break;

      const result = await withDeadline<
        ReadableStreamReadResult<Uint8Array> | typeof TIMED_OUT
      >(reader.read(), remaining, () => TIMED_OUT);

      if (result === TIMED_OUT) break;
      if (result.done) break;
    }
  } catch {
    // A drain that fails still leaves close() and the race worth attempting.
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Already released; nothing to do.
    }
  }

  // Step 3 — explicit close.
  try {
    await sock.close();
  } catch {
    // The socket may already be gone; the race below reports the truth.
  }

  // Step 4 — bounded wait on `closed`.
  //
  // The race has exactly three arms and each one now reports itself. The
  // fulfil arm and the reject arm are two different facts about the peer, and
  // the timer arm is a fact about US — that we gave up waiting. Collapsing the
  // last two into one value is WINDOWS.md ledger entry 5; see `CloseOutcome`.
  //
  // The race is NOT widened to call a rejection clean. That was the tempting
  // one-line "fix" and it would have erased the distinction rather than
  // recording it: the live proof's benign rejection would then be
  // indistinguishable from a genuinely clean close, and the dangerous timeout
  // would be the only thing left with its own value.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const closeOutcome = await Promise.race([
    sock.closed.then(
      (): CloseOutcome => "closed",
      (): CloseOutcome => "rejected",
    ),
    new Promise<CloseOutcome>((resolve) => {
      timer = setTimeout(() => resolve("timed-out"), closeTimeoutMs);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);

  return { logoutOk, closeOutcome, logoutMs, closeMs: Date.now() - closeStart };
}
