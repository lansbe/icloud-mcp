// The connectivity proof: open one socket, find out what iCloud actually
// says, and close cleanly.
//
// Concurrency: exactly one socket is opened per invocation, and the connect
// call is never wrapped in any concurrent combinator. See
// MAX_CONCURRENT_CONNECTIONS in ./socket.ts for why; the rationale for not
// naming the specific combinators here is recorded in 01-02-SUMMARY.md.

import type { Principal } from "../principal";
import { reportRefusal } from "../password-pause";
import {
  ImapAuthError,
  ImapConnectError,
  ImapNotFoundError,
  ImapThrottleError,
} from "../errors";
import {
  hasLiteralPlus,
  parseCapabilityLine,
  parseExists,
  parseUidValidity,
  quoteMailbox,
} from "./imap-parser";
import type { ResponseLine } from "./imap-parser";
import type { CloseOutcome, DuplexLike } from "./imap-session";
import {
  authenticate,
  ImapChannel,
  readGreeting,
  sendCommand,
  teardown,
} from "./imap-session";
import { connectImap, IMAP_ENDPOINT } from "./socket";

/**
 * The mailbox the diagnostic opens.
 *
 * `INBOX` is reserved by RFC 3501 itself, so naming it is not a guess about
 * this account's folder layout — it is the one mailbox name the protocol
 * guarantees. Every other folder this project touches is discovered rather than
 * assumed.
 */
const DIAGNOSTIC_MAILBOX = "INBOX";

/**
 * Everything `mail_imap_diagnose` reports (D-07).
 *
 * The whole contract is defined here, in the plan that opens the socket,
 * rather than being grown field by field. Plan 01-03 adds the authenticated
 * stages by *filling* `postLoginCapability`, `literalPlus`, `authMechanism`,
 * `authenticated`, and `timings.loginMs` — it does not reshape the tool's
 * output, so a saved client configuration written against this shape stays
 * valid.
 *
 * `null` is the empty state: "this stage did not run", as distinct from
 * `false`, which means "this stage ran and the answer was no".
 */
export interface DiagnosticReport {
  /** The hostname actually passed to the connect call. */
  host: string;
  /** The port actually passed to the connect call. */
  port: number;
  /** The transport mode actually passed to the connect call. */
  secureTransport: string;
  /** True once an application byte has been read, which TLS must precede. */
  tlsEstablished: boolean;
  /** The pre-authentication CAPABILITY response, verbatim. */
  greetingCapability: string | null;
  /** The post-authentication CAPABILITY response, verbatim. Plan 01-03. */
  postLoginCapability: string | null;
  /** Derived from the POST-authentication capability list only. Plan 01-03. */
  literalPlus: boolean | null;
  /** Which authentication mechanism succeeded. Plan 01-03. */
  authMechanism: string | null;
  /** Whether authentication succeeded. Plan 01-03. */
  authenticated: boolean;
  /**
   * The server's own reply text when authentication was refused. Plan 01-03.
   *
   * `null` unless both mechanisms were rejected. The text originates with
   * Apple's server and structurally cannot contain the credential, which lives
   * in the command we sent rather than in the reply. It reaches the report as
   * a dedicated field read from the parsed reply — never by way of an error's
   * message, because the translation boundary is contractually forbidden from
   * reading those.
   */
  authFailureDetail: string | null;
  /**
   * The server's own reply text when it refused on connection count.
   *
   * `null` unless a connection-limit refusal ended the conversation. On the
   * same footing as `authFailureDetail` above and for the same reason: the text
   * originates with Apple's server, and the credential lives in the command we
   * sent rather than in the reply. It reaches the report from the parsed reply
   * by way of a dedicated field on the error class — never from a caught
   * value's message, which the translation boundary is contractually forbidden
   * from reading.
   *
   * **Whatever the server says arrives here verbatim, bounded only in length.**
   * No throttle format is assumed, because none has ever been observed from
   * this server; see `boundedReplyDetail` in `./imap-session.ts`.
   */
  throttleFailureDetail: string | null;
  /** Whether LOGOUT completed with an OK. */
  logoutOk: boolean;
  /**
   * Which of the three ways teardown's `closed` race can end happened.
   *
   * `null` is the empty state and means teardown did not run at all — the same
   * convention every other field here follows. It is reachable: the connect
   * wrapper below returns an untouched report when no socket was ever opened.
   *
   * Read `CloseOutcome`'s docstring for which value is dangerous. Read it
   * together with `timings.closeMs`, which is the independent cross-check and
   * is retained for exactly that reason.
   */
  closeOutcome: CloseOutcome | null;
  /**
   * The UIDVALIDITY the inbox reported when it was opened read-only.
   *
   * `null` means the stage did not run or the server did not send the code.
   * The RFC is explicit that an absent UIDVALIDITY means "the server does not
   * support unique identifiers", which is a fact worth seeing in a diagnostic
   * rather than defaulting to zero.
   *
   * Unsigned 32-bit, so it may legitimately exceed 2^31.
   */
  inboxUidValidity: number | null;
  /** How many messages the inbox reported. `null` if the stage did not run. */
  inboxMessageCount: number | null;
  /**
   * Per-stage durations in milliseconds, measured with `Date.now()` deltas.
   *
   * `performance.now()` is coarsened on this runtime and offers nothing here,
   * and a timing library for five subtractions would be absurd.
   *
   * The two connection stages are defined operationally, so the numbers stay
   * interpretable when a later phase diffs against them:
   *
   * - `connectMs` — how long the connect call itself takes to return.
   * - `tlsHandshakeMs` — how long until the first byte of the greeting
   *   becomes readable. The handshake must complete before any application
   *   byte can arrive, so this brackets it from above; it also includes the
   *   server's own time to compose the greeting.
   * - `examineMs` — one round trip to open the inbox read-only. **This is the
   *   measurement that closes 01-IMAP-PROOF.md § 4's stated caveat.** That
   *   document records its 424 ms connect-through-close total as a LOWER BOUND
   *   precisely because Phase 1 never opened a mailbox, and every real mail
   *   tool does. Named for the command actually sent — see the stage itself.
   */
  timings: {
    connectMs: number | null;
    tlsHandshakeMs: number | null;
    loginMs: number | null;
    examineMs: number | null;
    logoutMs: number | null;
    closeMs: number | null;
  };
}

/** A report with every stage unrun. Every field explicit, none inferred. */
function emptyReport(): DiagnosticReport {
  return {
    host: IMAP_ENDPOINT.hostname,
    port: IMAP_ENDPOINT.port,
    secureTransport: IMAP_ENDPOINT.secureTransport,
    tlsEstablished: false,
    greetingCapability: null,
    postLoginCapability: null,
    literalPlus: null,
    authMechanism: null,
    authenticated: false,
    authFailureDetail: null,
    throttleFailureDetail: null,
    logoutOk: false,
    closeOutcome: null,
    inboxUidValidity: null,
    inboxMessageCount: null,
    timings: {
      connectMs: null,
      tlsHandshakeMs: null,
      loginMs: null,
      examineMs: null,
      logoutMs: null,
      closeMs: null,
    },
  };
}

/**
 * The first capability list among a command's untagged responses.
 *
 * Takes `ResponseLine[]` since Phase 2's reader switched to logical responses.
 * A capability response never carries a literal, so `.text` here is the same
 * string this function read before the widening.
 */
function firstCapability(untagged: ResponseLine[]): string | null {
  for (const line of untagged) {
    const advertised = parseCapabilityLine(line.text);
    if (advertised !== null) return advertised;
  }
  return null;
}

/**
 * A finished diagnostic run: the report always, plus whatever ended it.
 *
 * The report is returned even when the conversation failed, because a
 * diagnostic that discards its measurements at the first problem is useless
 * for the one job it has. The error is handed back rather than thrown so the
 * caller decides what crosses the tool boundary; only the transport wrapper
 * below raises.
 */
export interface DiagnosticOutcome {
  report: DiagnosticReport;
  /** True when `error` is meaningful. */
  failed: boolean;
  /** What ended the conversation. A `catch` receives any value, so: unknown. */
  error: unknown;
}

/**
 * Hold the full IMAP conversation over an already-open stream pair.
 *
 * Separated from the socket so the whole conversation — including every
 * credential path and every failure category — can be driven against an
 * in-memory duplex. That is not a testing convenience: no automated job in
 * this repository may authenticate against the real Apple ID, and the test
 * environment offers no interception facility, so a version of this function
 * welded to a socket would be untestable rather than merely awkward.
 *
 * CAPABILITY is issued TWICE, once before authenticating and once after, and
 * both strings are reported verbatim. Capability lists changing after
 * authentication is normal, specified IMAP behaviour; iCloud is reported to
 * advertise the non-synchronizing-literal capability only in the second list.
 * Reading it once from the first yields a false negative that a later phase's
 * APPEND design would be built on — or, worse, the reverse. The extra round
 * trip costs one measurement in a tool whose whole job is measuring round
 * trips.
 *
 * Teardown runs in a `finally`, so a conversation that fails part-way still
 * closes. A leaked connection counts against a low, undocumented ceiling, and
 * enough of them lock the user out of their own mail on their own devices.
 */
export async function runDiagnosticOver(
  duplex: DuplexLike,
  principal: Principal,
  connectMs: number,
): Promise<DiagnosticOutcome> {
  const report = emptyReport();
  report.timings.connectMs = connectMs;

  const channel = new ImapChannel(duplex);
  let failed = false;
  let error: unknown = null;

  /**
   * Whether Apple named a credential condition — recorded, not acted on yet.
   *
   * Reported after teardown rather than at the refusal, so the store write is
   * never a second concurrent connection held alongside the open socket (WR-03).
   * `withMailSessionOver` in ./service.ts carries the same pattern and the full
   * argument.
   */
  let credentialRefused = false;

  try {
    const greetingStart = Date.now();
    await readGreeting(channel);
    report.timings.tlsHandshakeMs = Date.now() - greetingStart;
    report.tlsEstablished = true;

    const greetingCapability = await sendCommand(
      channel,
      channel.nextTag(),
      "CAPABILITY",
    );
    report.greetingCapability = firstCapability(greetingCapability.untagged);

    const loginStart = Date.now();
    const auth = await authenticate(channel, principal);
    report.timings.loginMs = Date.now() - loginStart;
    report.authenticated = auth.authenticated;
    report.authMechanism = auth.mechanism;
    report.authFailureDetail = auth.failureDetail;

    // Raised here rather than inside `authenticate` so the server's own reply
    // text lands in the report first. Both facts are needed and an exception
    // can carry only one of them, since our error classes are constructed
    // without context by design.
    if (!auth.authenticated) {
      // The second place on the mail tool path where APPLE ITSELF refused the
      // saved password (LIFE-04). The diagnostic is handed the door's principal,
      // so it is armed like any other tool; the sign-in page never reaches here.
      //
      // Branched on `credentialRefused` and NOT on `authenticated` — see the
      // matching site in `service.ts` for the argument. It matters more here
      // than anywhere: this is the tool somebody runs to find out WHY, and a
      // pause set from a server-side reply would make the next run of it answer
      // `auth_failed` instead of the report.
      //
      // Recorded here, written after teardown (WR-03). See the `finally` below.
      credentialRefused = auth.credentialRefused;
      throw new ImapAuthError();
    }

    const postLoginCapability = await sendCommand(
      channel,
      channel.nextTag(),
      "CAPABILITY",
    );
    report.postLoginCapability = firstCapability(postLoginCapability.untagged);
    report.literalPlus =
      report.postLoginCapability === null
        ? null
        : hasLiteralPlus(report.postLoginCapability);

    // The inbox stage (D-52). Two things it establishes that nothing else in
    // this tool can: the real cost of the mailbox round trip every mail tool
    // pays — 01-IMAP-PROOF.md § 4 calls its own total a lower bound for exactly
    // this omission — and that folder-path resolution works, before a list tool
    // gets blamed for a failure that was never its own.
    //
    // **NAMED FOR THE COMMAND ACTUALLY SENT, which is not the one D-52 asked
    // for.** That decision says "a SELECT INBOX stage"; SELECT opens a mailbox
    // read-WRITE, and a diagnostic that mutates state as a side effect of being
    // run is a worse thing to own than a stage with a different name. The
    // number D-52 wants — the missing round trip — is identical either way, so
    // the deviation costs nothing and the honest name is the one that survives
    // a later reader asking what the tool did to their mailbox.
    //
    // Same command and same parsers as `withMailSessionOver` in ./service.ts,
    // deliberately: a second implementation of this exchange could diverge from
    // the one that actually serves mail, and then the diagnostic would be
    // proving something about itself.
    const quoted = quoteMailbox(DIAGNOSTIC_MAILBOX);
    // **Provably redundant, and kept deliberately — verified, not assumed.**
    // Deleting this line leaves the whole suite green, because
    // `DIAGNOSTIC_MAILBOX` is a compile-time constant with no CR, LF or NUL in
    // it, so `quoteMailbox` cannot return null for it. No test can cover this
    // branch and none pretends to.
    //
    // It stays because the alternative is a shortened copy of the orchestrator's
    // path: `withMailSessionOver` refuses rather than repairs here, and a
    // diagnostic that skipped the refusal would stop being a faithful rehearsal
    // of what a real mail call does. It also fails closed on the day this
    // mailbox name stops being a constant.
    if (quoted === null) throw new ImapNotFoundError();

    const examineStart = Date.now();
    const examine = await sendCommand(
      channel,
      channel.nextTag(),
      `EXAMINE ${quoted}`,
    );
    // Recorded BEFORE the status check, so a refused open still reports what it
    // cost. A diagnostic that discards a measurement because the thing it
    // measured failed is useless for the one job it has.
    report.timings.examineMs = Date.now() - examineStart;

    for (const line of examine.untagged) {
      const validity = parseUidValidity(line.text);
      if (validity !== null) report.inboxUidValidity = validity;
      const count = parseExists(line.text);
      if (count !== null) report.inboxMessageCount = count;
    }

    if (examine.status !== "OK") throw new ImapNotFoundError();
  } catch (err) {
    failed = true;
    error = err;

    // A connection-limit refusal is raised from deep inside the conversation —
    // the greeting reader, or either of the authenticator's two rejections —
    // so unlike `authFailureDetail` there is no return value to carry its text
    // out. It rides on the error class instead, and is lifted back off here.
    //
    // This reads a field WE populated from a parsed reply, after checking the
    // value's TYPE. It is not the forbidden move: nothing here touches
    // `.message` or `.stack`, and the discipline those two are banned under is
    // about text of unknown provenance, not about a typed field whose one
    // producer is three lines in this repository.
    if (err instanceof ImapThrottleError) {
      report.throttleFailureDetail = err.detail;
    }
  } finally {
    try {
      const closed = await teardown(
        duplex,
        channel.reader,
        async (line) =>
          (await sendCommand(channel, channel.nextTag(), line)).tagged.text,
      );
      report.logoutOk = closed.logoutOk;
      report.closeOutcome = closed.closeOutcome;
      report.timings.logoutMs = closed.logoutMs;
      report.timings.closeMs = closed.closeMs;
    } catch {
      // teardown is written not to throw. If it somehow does, swallowing it
      // here preserves whichever error the conversation itself raised, which
      // is always the more informative of the two.
    }

    // LAST, with the socket gone, so the store write is never a second
    // concurrent connection (WR-03). `reportRefusal` is written not to throw,
    // and does nothing at all unless the door armed this principal.
    if (credentialRefused) await reportRefusal(principal);
  }

  return { report, failed, error };
}

/**
 * Run the connectivity diagnostic against iCloud, keeping the report.
 *
 * Opens exactly one socket, hands it to the conversation above, and returns
 * whatever came back — measurements included — rather than raising. The
 * connect call is never wrapped in a concurrent combinator; see
 * MAX_CONCURRENT_CONNECTIONS in ./socket.ts.
 *
 * This is the form the tool boundary uses, because the single most likely
 * failure in this phase is iCloud refusing the credentials, and the field that
 * distinguishes a wrong password from a wrong username format lives in the
 * report rather than in the error. Raising and discarding the report loses
 * exactly the information the diagnostic exists to produce, on exactly the run
 * where it matters most.
 *
 * It is now the module's only entry point. A raising sibling existed here and
 * was removed rather than kept for convenience: two exported entry points with
 * different failure semantics is a choice a later author makes without knowing
 * they are making it, and the simpler signature is the one they pick. A caller
 * that genuinely only wants the happy path can write the three-line raising form
 * at its own call site, where the decision to discard the report is visible to
 * the person taking it instead of inherited from a function name.
 */
export async function runDiagnosticOutcome(
  principal: Principal,
): Promise<DiagnosticOutcome> {
  const connectStart = Date.now();
  let sock: DuplexLike;
  try {
    sock = connectImap();
  } catch {
    // No socket was opened, so there is no conversation and no measurement
    // beyond the failure itself.
    return { report: emptyReport(), failed: true, error: new ImapConnectError() };
  }
  const connectMs = Date.now() - connectStart;

  return runDiagnosticOver(sock, principal, connectMs);
}
