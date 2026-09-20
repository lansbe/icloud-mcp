// The seam that makes every IMAP test socket-free.
//
// `src/mail/imap-session.ts` operates on a duck-typed `DuplexLike` rather than
// a concrete socket, so a pair of in-memory streams satisfies it structurally.
// Nothing in this file opens a network connection, and nothing in this file
// reads a real credential — D-09 forbids any automated job from authenticating
// against the real Apple ID, and the test environment offers no interception
// facility that would make a "quick integration test" anything other than a
// real login.
//
// The instrumentation here exists to prove ORDERING, not merely occurrence.
// Teardown's contract is that the readable reaches `done` BEFORE `close()` is
// called; a fake that only recorded "both happened" would pass against an
// implementation that got the order backwards, which is precisely the
// implementation that hangs on every call in the real runtime.

import type { DuplexLike } from "../../src/mail/imap-session";

const DECODER = new TextDecoder();

/** One observable thing the session did to the duplex, in order. */
export type DuplexEvent =
  | { kind: "write"; line: string }
  | { kind: "readable-done" }
  | { kind: "close" };

/** A `DuplexLike` that records what was done to it. */
export interface FakeDuplex extends DuplexLike {
  /** Every observed event, in the order it happened. */
  readonly events: DuplexEvent[];
  /** Raw outbound chunks, exactly as written. */
  readonly writes: Uint8Array[];
  /** Outbound lines, CRLF stripped. */
  writtenLines(): string[];
  /** Index of the first event of `kind`, or -1. */
  firstIndexOf(kind: DuplexEvent["kind"]): number;
}

/**
 * The outbound side: a `TransformStream` whose transform records rather than
 * forwards.
 *
 * The readable strategy's high-water mark is deliberately 1 rather than the
 * default 0. A transform stream signals backpressure to its writable side
 * whenever its readable side has no room, and this transform never enqueues,
 * so with the default the very first write would block forever waiting for a
 * reader that does not exist. With a positive mark the readable is pulled once
 * at start-up, backpressure clears, and every write completes synchronously
 * into the recorder — which is what lets a test assert on outbound bytes
 * immediately after awaiting the write.
 */
function recordingWritable(
  events: DuplexEvent[],
  writes: Uint8Array[],
): WritableStream<Uint8Array> {
  return new TransformStream<Uint8Array, Uint8Array>(
    {
      transform(chunk) {
        writes.push(chunk);
        for (const line of DECODER.decode(chunk).split("\r\n")) {
          if (line.length > 0) events.push({ kind: "write", line });
        }
      },
    },
    undefined,
    { highWaterMark: 1 },
  ).writable;
}

/**
 * The inbound side: a strictly demand-driven `ReadableStream`.
 *
 * The high-water mark of 0 is load-bearing. It means `pull` runs only when a
 * consumer actually has a read outstanding, so the `readable-done` event is
 * recorded at the exact moment the session asks for the byte past the end of
 * the script — not at some earlier moment when the stream chose to buffer
 * ahead. Any positive mark would let the stream close itself before the drain
 * ran, and the teardown-ordering assertion would then pass vacuously.
 */
function scriptedReadable(
  script: Uint8Array[],
  events: DuplexEvent[],
): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (index < script.length) {
          controller.enqueue(script[index]);
          index += 1;
          return;
        }
        events.push({ kind: "readable-done" });
        controller.close();
      },
    },
    { highWaterMark: 0 },
  );
}

function linesFrom(events: DuplexEvent[]): string[] {
  const lines: string[] = [];
  for (const event of events) {
    if (event.kind === "write") lines.push(event.line);
  }
  return lines;
}

function assemble(
  readable: ReadableStream<Uint8Array>,
  writable: WritableStream<Uint8Array>,
  closed: Promise<void>,
  onClose: () => void,
  events: DuplexEvent[],
  writes: Uint8Array[],
): FakeDuplex {
  return {
    readable,
    writable,
    closed,
    async close() {
      events.push({ kind: "close" });
      onClose();
    },
    events,
    writes,
    writtenLines: () => linesFrom(events),
    firstIndexOf: (kind) => events.findIndex((event) => event.kind === kind),
  };
}

/**
 * A duplex that replays `script` chunk by chunk and closes cleanly.
 *
 * `closed` settles when `close()` is called, which models a well-behaved peer.
 */
export function createFakeDuplex(script: Uint8Array[]): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];
  let resolveClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });

  return assemble(
    scriptedReadable(script, events),
    recordingWritable(events, writes),
    closed,
    () => resolveClosed(),
    events,
    writes,
  );
}

/**
 * A duplex whose `closed` promise REJECTS when `close()` is called.
 *
 * **This is the only fixture modelling what the real server actually did.**
 * 01-IMAP-PROOF.md § 5 records the one live teardown as `closeMs` 0, `logoutOk`
 * true, and `sock.closed` rejecting — no hang, no leak, entirely unremarkable
 * for a socket whose peer has already sent `* BYE` and closed its side.
 *
 * It did not exist before ledger entry 5 was closed, and its absence is part of
 * why the entry stayed open: while teardown reported a boolean that collapsed a
 * rejection and a timeout into one `false`, no fixture could have told the two
 * apart, so there was nothing for a fixture to assert. The fixture and the
 * three-valued outcome arrive together because neither is testable without the
 * other.
 *
 * The rejection is raised at `close()` rather than at construction so the
 * promise is not rejected while nothing is subscribed to it — an unhandled
 * rejection inside the isolate would surface as a test-runner failure with no
 * relationship to the case that caused it.
 */
export function createRejectingCloseDuplex(script: Uint8Array[]): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];
  let rejectClosed: (reason: unknown) => void = () => {};
  const closed = new Promise<void>((_resolve, reject) => {
    rejectClosed = reject;
  });
  // Teardown subscribes to `closed` only inside step 4's race, and step 3 calls
  // `close()` just before that. Attaching a no-op handler here keeps the window
  // between them from producing an unhandled rejection.
  closed.catch(() => {});

  return assemble(
    scriptedReadable(script, events),
    recordingWritable(events, writes),
    closed,
    () => rejectClosed(new Error("the peer had already closed its side")),
    events,
    writes,
  );
}

/**
 * A duplex whose `closed` promise NEVER settles.
 *
 * This is the shape the upstream runtime issue describes, and it is the reason
 * teardown races `closed` against a timeout instead of awaiting it. The
 * behaviour is specified and intentional rather than a bug awaiting a fix, so
 * it reproduces on every call — a session that simply awaited `closed` would
 * hang deterministically, holding a connection open against iCloud's low,
 * undocumented ceiling for the whole request budget.
 */
export function createNeverClosingDuplex(script: Uint8Array[]): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];

  return assemble(
    scriptedReadable(script, events),
    recordingWritable(events, writes),
    // Intentionally never resolved and never rejected.
    new Promise<void>(() => {}),
    () => {},
    events,
    writes,
  );
}

/**
 * A duplex modelling a peer that completed the handshake and then went silent.
 *
 * Its readable never enqueues a byte, never closes, and never errors: `pull`
 * returns a promise with no reachable `resolve`, so a consumer's `read()` stays
 * genuinely outstanding forever. Its `closed` never settles either.
 *
 * **This is the shape `createNeverClosingDuplex` does NOT model, and the
 * distinction is the entire substance of CR-02.** That fixture wraps
 * `scriptedReadable`, whose readable *ends* after the script — so a drain
 * against it always completes and the code after the drain is always reached.
 * A fixture whose readable ends can only ever exercise the `closed`-promise
 * hang; it cannot exercise a drain that does not finish, which is the hang that
 * made teardown's own backstop unreachable. Asserting `readable-done` against
 * *this* fixture would therefore be a contradiction: that event firing is proof
 * the case is testing something else.
 *
 * No script parameter, deliberately. A silent peer says nothing by definition,
 * and accepting bytes to replay would invite exactly the "but it does end
 * eventually" fixture this one exists to replace.
 */
export function createSilentPeerDuplex(): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];

  const readable = new ReadableStream<Uint8Array>(
    {
      pull() {
        // Never resolved, never rejected, and no handle to it escapes — the
        // stream will not pull again while this is pending, so the consumer's
        // read request simply stays queued forever.
        return new Promise<void>(() => {});
      },
    },
    { highWaterMark: 0 },
  );

  return assemble(
    readable,
    recordingWritable(events, writes),
    // Intentionally never resolved and never rejected.
    new Promise<void>(() => {}),
    () => {},
    events,
    writes,
  );
}

/**
 * A duplex that replays `script` and then goes silent, without ever ending.
 *
 * The third hang shape, and the one a literal read needs. The two existing
 * silent fixtures cannot express it: `createFakeDuplex` ENDS after its script,
 * which produces a short-literal failure on a different code path, and
 * `createSilentPeerDuplex` never says anything at all, so a reader would stall
 * before it ever saw the `{n}` head it is supposed to stall inside.
 *
 * What this models is a peer that announces a literal and then stops — the
 * shape that holds a socket open against iCloud's ceiling for the whole request
 * budget unless every read inside `readOctets` is bounded.
 */
export function createStallingDuplex(script: Uint8Array[]): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];
  let index = 0;

  const readable = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (index < script.length) {
          controller.enqueue(script[index]);
          index += 1;
          return;
        }
        // Never resolved, never rejected, and no handle to it escapes. The
        // stream will not pull again while this is pending, so the consumer's
        // read stays genuinely outstanding rather than completing as done.
        return new Promise<void>(() => {});
      },
    },
    { highWaterMark: 0 },
  );

  return assemble(
    readable,
    recordingWritable(events, writes),
    // Intentionally never resolved and never rejected.
    new Promise<void>(() => {}),
    () => {},
    events,
    writes,
  );
}

/** A held-first-read duplex, and the one way to let its first read go. */
export interface HeldFirstReadDuplex {
  readonly duplex: FakeDuplex;
  /** Let the first read complete. Safe to call more than once. */
  release(): void;
}

/**
 * A duplex whose FIRST read waits until the test says go, and which then
 * replays `script` and closes cleanly, exactly as `createFakeDuplex` does.
 *
 * What this models is a server that is slow to greet: the connection is open,
 * the session has asked for the greeting, and nothing has arrived yet. The
 * greeting read is the first thing a session awaits, and it sits BEFORE the
 * login write. So a session over this duplex is parked at a known point, having
 * written nothing, until `release()` is called. That is what lets a test run a
 * whole second session for another user in the gap and then look at what the
 * parked one sends when it wakes.
 *
 * No existing fixture can express it. `createFakeDuplex` answers every read at
 * once, so there is no gap to run anything in. `createSilentPeerDuplex` and
 * `createStallingDuplex` hold a read with a promise nobody can resolve, so the
 * parked session could never be woken.
 *
 * The high-water mark stays at 0, as it does for the scripted readable above
 * and for the same reason. With a positive mark the stream would call `pull`
 * ahead of any read, and "parked at the greeting read" would stop being a fact
 * about the session and become a fact about the stream's buffering.
 *
 * `closed` is the resolvable one, not a never-settling one, so teardown after
 * the release is the ordinary clean teardown and costs no timeout.
 */
export function createHeldFirstReadDuplex(
  script: Uint8Array[],
): HeldFirstReadDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];
  let resolveClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let index = 0;
  let first = true;

  const readable = new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        if (first) {
          first = false;
          // The stream will not pull again while this is pending, so the
          // session's read stays outstanding until the test releases it.
          await held;
        }
        if (index < script.length) {
          controller.enqueue(script[index]);
          index += 1;
          return;
        }
        events.push({ kind: "readable-done" });
        controller.close();
      },
    },
    { highWaterMark: 0 },
  );

  return {
    duplex: assemble(
      readable,
      recordingWritable(events, writes),
      closed,
      () => resolveClosed(),
      events,
      writes,
    ),
    release: () => release(),
  };
}

/**
 * A duplex that rejects on first use, modelling a connection that never
 * establishes.
 *
 * The error it raises carries deliberately generic text. Nothing that reads it
 * is permitted to surface it, and a transport error raised mid-conversation on
 * the credential path can carry the bytes that were in flight.
 */
export function createFailingDuplex(): FakeDuplex {
  const events: DuplexEvent[] = [];
  const writes: Uint8Array[] = [];
  let resolveClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(new Error("fake transport refused the connection"));
    },
  });

  const writable = new WritableStream<Uint8Array>({
    write() {
      throw new Error("fake transport refused the connection");
    },
  });

  return assemble(
    readable,
    writable,
    closed,
    () => resolveClosed(),
    events,
    writes,
  );
}
