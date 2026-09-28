// The mail session orchestrators, over one private core (D-43).
//
// Every mail tool reaches iCloud through an orchestrator in this module and
// through nothing else. Each orchestrator is a thin wrapper over one
// module-private core, `withMailSessionCore`, which owns the whole lifecycle:
// the gate, the channel, the sign-in, the call deadline and the teardown. The
// core exists so there is one teardown for every mail path. That is what makes
// "exactly one socket per Worker invocation" a property of the code rather than
// a convention each call site has to remember.
//
// Every read opens its mailbox read-only. The read orchestrator must never gain
// a mode argument. A mode parameter is how the read-only guarantee dies without
// a single test failing: every read call site becomes one argument away from a
// mailbox opened for changing (PITFALLS #32). A second orchestrator, if one
// exists, is a separate named function with its own open step.
//
// One does exist. `withMutatingMailbox` and `withMutatingMailboxOver` sit beside
// the read pair, over the same private core and the same request-scoped gate,
// and open their mailbox in the mutating form. Only `./triage.ts` may import
// them, and a scan count holds that in both directions. They take no mode, and
// neither does the read pair: which kind of session a caller gets is decided by
// which function it names, never by an argument it passes.
//
// Concurrency: exactly one socket is opened per invocation, and the connect
// call is never wrapped in any concurrent combinator. See
// MAX_CONCURRENT_CONNECTIONS in ./socket.ts for why.
//
// This module contains no logging calls of any kind and must never acquire any.

import PostalMime from "postal-mime";
import type { Address } from "postal-mime";
import { MAX_CHANGE_FOLDERS } from "../change-marker";
import type { Principal } from "../principal";
import { reportRefusal } from "../password-pause";
import {
  ImapAuthError,
  ImapConnectError,
  ImapGoneError,
  ImapNotFoundError,
  ImapValidityChangedError,
  ImapThrottleError,
} from "../errors";
import { MAX_APPEND_LITERAL_BYTES } from "./compose";
import type { AttachmentRef, MessageRef, PageCursor } from "./ids";
import {
  decodeCursor,
  encodeAttachmentId,
  encodeCursor,
  encodeFolderId,
  encodeMessageId,
  isWireNumber,
} from "./ids";
import type {
  Fingerprint,
  FolderRole,
  MailboxListLine,
  MailboxStatus,
  ResponseLine,
  RoleSource,
  SExpr,
  StatusSnapshot,
} from "./imap-parser";
import {
  FINGERPRINT_ITEMS,
  correlateStatus,
  decodeModifiedUtf7,
  parseAccessCode,
  parseCapabilityLine,
  parseCompletionCode,
  parseExists,
  parseFingerprint,
  parseListLine,
  parsePermanentFlags,
  parseSExpr,
  parseSearchLine,
  parseStatusLine,
  parseStatusSnapshot,
  parseUidValidity,
  quoteMailbox,
  resolveFolderRole,
} from "./imap-parser";
import type {
  AuthOptions,
  ChannelOptions,
  DuplexLike,
  TeardownOptions,
} from "./imap-session";
import type { CommandResult } from "./imap-session";
import {
  ImapChannel,
  authenticate,
  awaitContinuation,
  readGreeting,
  readUntilTag,
  sendCommand,
  teardown,
  withDeadline,
} from "./imap-session";
import type { AttachmentMeta, BodyPart, ParsedMessage } from "./mime";
import {
  attachmentsFrom,
  extractMessage,
  hasReadableText,
  htmlAlternativeOf,
  selectTextPart,
  snippetFromPart,
  walkBodystructure,
  windowOctetsFor,
} from "./mime";
import { connectImap } from "./socket";

/**
 * The single-slot concurrency gate (D-46).
 *
 * `acquire()` throws when the slot is already held; `release()` is idempotent
 * so a double release on an error path cannot open a second slot.
 */
export interface SessionGate {
  /** Take the slot, or refuse loudly. */
  acquire(): void;
  /** Give the slot back. Safe to call more than once. */
  release(): void;
  /** Whether the slot is currently taken. */
  readonly held: boolean;
}

/**
 * Build a gate for ONE request.
 *
 * **The obvious module-level counter is wrong here, and this file's neighbour
 * already says why in a different context.** `ImapChannel.nextTag()`'s counter
 * "belongs to the channel rather than the module, so two requests running at
 * once cannot collide on a tag — module-level state here would be shared across
 * every invocation of the Worker in the same isolate." A module-level session
 * counter has exactly that isolate-wide scope, but the six-connection cap it
 * defends is per Worker INVOCATION. So an isolate-wide counter would refuse a
 * perfectly legitimate second *request* that happened to land in the same
 * isolate — a false failure on a correct call, which is a worse outcome than
 * the fan-out it was trying to prevent.
 *
 * Request scope comes from the construction site rather than from bookkeeping:
 * `createServerFactory()` returns a function `createMcpHandler` calls once per
 * request, and the gate is built inside that function. Two requests get two
 * gates because they get two server instances, with nothing to reason about.
 *
 * The refusal is `ImapThrottleError`. Of the four categories in the closed
 * vocabulary it is the one whose guidance matches — wait, and do not retry in a
 * loop — where `connection_failed` is the floor, which still offers a retry,
 * inviting the immediate second attempt that fails again while the first session
 * is still open. The prose names iCloud rather than us, which is
 * a small inaccuracy accepted deliberately: the operational guidance is the
 * part a model acts on, and it is correct.
 */
export function createSessionGate(): SessionGate {
  let taken = false;
  return {
    acquire() {
      if (taken) throw new ImapThrottleError();
      taken = true;
    },
    release() {
      taken = false;
    },
    get held() {
      return taken;
    },
  };
}

/**
 * The deadline on one whole tool call (D-45).
 *
 * The existing read bound bounds ONE read and the drain bound bounds teardown,
 * but until now nothing bounded a *conversation* — because Phase 1 never had
 * one. Phase 2 issues six or more round trips per call, so a server that keeps
 * answering slowly, without ever stalling long enough to trip a single read,
 * could hold a request open indefinitely while its socket counts against
 * iCloud's low, undocumented ceiling.
 *
 * Twenty seconds, and the three-step worst case is what a later reader actually
 * needs: `CALL_DEADLINE_MS + DRAIN_TIMEOUT_MS + CLOSE_TIMEOUT_MS` =
 * 20 000 + 2 000 + 3 000 = **25 000 ms**. Stated here rather than left to be
 * recomputed, the way `DRAIN_TIMEOUT_MS` states its own two-step sum, because a
 * number nobody writes down is a number that goes stale.
 *
 * `READ_TIMEOUT_MS` stays at its calibrated 10 s. Lowering it on speculation
 * would trade a number measured against the live proof for a guess.
 */
export const CALL_DEADLINE_MS = 20000;

/**
 * Every bound this session can have injected (D-51, ledger entry 9).
 *
 * The defaults are the exported constants, so production behaviour is
 * unchanged. Tests inject a few milliseconds instead of genuinely waiting out
 * real timeout bounds — the suite was spending roughly 20 s of wall time doing
 * exactly that, and the call deadline above would have made it a third such
 * wait. The assertions stay discriminating: Phase 1 verified them by reverting
 * the bounds and watching all three hang to the runner timeout, and the
 * injected versions must still fail that way at roughly 1% of the cost.
 */
export interface MailSessionOptions
  extends ChannelOptions,
    TeardownOptions,
    AuthOptions {
  /** Overrides `CALL_DEADLINE_MS` for this call only. */
  callDeadlineMs?: number;
}

/**
 * An authenticated session, with one mailbox selected read-only or with none.
 *
 * The three mailbox fields are `null` together, and only together, when the
 * caller asked for authenticated-state-only work — see `withMailSessionOver`'s
 * optional mailbox. `null` there is a fact rather than a missing value: no
 * mailbox was opened, so the server never reported a validity or a count for
 * one, and a zero would be a claim this server cannot make.
 *
 * `access` is the discriminant that keeps this type apart from
 * `MutatingMailSession`. TypeScript compares shapes, not names, so without two
 * different literal values here a mutating session would be accepted wherever a
 * read session is asked for, and the other way round.
 */
export interface MailSession {
  /** Always `"read-only"`. Never widened: see `MutatingMailSession`. */
  readonly access: "read-only";
  channel: ImapChannel;
  /** The raw wire mailbox name that was opened, or `null` if none was. */
  mailbox: string | null;
  /** The UIDVALIDITY the server reported for it, already gate-checked. */
  uidValidity: number | null;
  /** How many messages the mailbox holds. */
  exists: number | null;
  /** The post-authentication capability list, verbatim, or `null`. */
  capability: string | null;
}

/**
 * Which content command actually ran, and how the server answered it.
 *
 * **This field exists to settle assumption A5 on the first real run**, the same
 * move `CountsSource` below makes for the extended-listing clause. A5 asks
 * whether this server accepts a part-scoped MIME-headers section specifier for
 * a part inside a multipart message. RFC 3501's grammar permits it; nothing
 * else does, and a scripted fixture cannot settle it because a fake duplex
 * answers whatever the fixture author expected.
 *
 * - `whole-message` — the message was under the wire ceiling and was fetched
 *   entire. The overwhelmingly common case, and the one that says nothing about
 *   A5 either way.
 * - `part-scoped` — the message was over the ceiling and the server ACCEPTED
 *   the part-scoped items. A5 answered yes.
 * - `part-scoped-refused` — the message was over the ceiling, the server
 *   rejected the item list as malformed, and the whole-message fetch ran
 *   instead. A5 answered no, and the ceiling did not save the isolate on that
 *   call — `MAX_LITERAL_OCTETS` did, by consuming and discarding past its cap.
 *   Seeing this value in the wild is the signal that this branch needs a
 *   different strategy rather than a tweak.
 */
export type FetchPath = "whole-message" | "part-scoped" | "part-scoped-refused";

/** One message, shaped for the tool boundary. */
export interface MessageDetail extends ParsedMessage {
  /** The opaque token that names this message. Generated here, so trusted. */
  id: string;
  /** The UID within its mailbox. Protocol-supplied, so trusted. */
  uid: number;
  /** Derived from the flag list: true when `\Seen` is absent. */
  unread: boolean;
  /**
   * The server's INTERNALDATE — when iCloud received it.
   *
   * Distinct from `date`, which is the sender's own `Date` header and is
   * therefore stranger-authored. The two are kept apart rather than merged
   * because only one of them is a fact this server can vouch for.
   */
  internalDate: string | null;
  /** RFC822.SIZE — the raw wire size, not the decoded size. */
  wireSizeBytes: number;
  /** Which content command ran. Derived here, so trusted. */
  fetchPath: FetchPath;
  /**
   * Whether the two independent derivations of the attachment list disagreed.
   *
   * `false` above the wire ceiling is NOT a claim that they agree — it is a
   * claim that only ONE of them exists there, because no attachment bytes were
   * fetched and so nothing parsed them. Reporting `true` in that case would
   * flag every oversized message as suspicious and the field would stop meaning
   * anything.
   */
  attachmentsDisagree: boolean;
}

/** What a caller may vary about one fetch. */
export interface GetMessageOptions extends MailSessionOptions {
  /**
   * Return the raw HTML part alongside the readable text (D-33).
   *
   * Off by default. The raw part is stranger-authored markup and nothing here
   * interprets it — rendering it is explicitly a later version's problem
   * (V2-MAIL-03), so this flag hands the markup over and stops there.
   */
  includeHtml?: boolean;
}

/** What `withDeadline` resolves to when the call deadline wins. */
const DEADLINE_EXPIRED = Symbol("call-deadline-expired");

/** The first capability list among a command's untagged responses. */
function firstCapability(untagged: ResponseLine[]): string | null {
  for (const line of untagged) {
    const advertised = parseCapabilityLine(line.text);
    if (advertised !== null) return advertised;
  }
  return null;
}

/**
 * The open step of one session, supplied by the orchestrator that owns it.
 *
 * It runs on the authenticated channel, opens a mailbox or deliberately does
 * not, and hands back the work to run. The core races that work against the
 * call deadline and never the open itself.
 *
 * A callback rather than a value, and that is the point. The open command stays
 * a literal inside the orchestrator that sends it, so the core has no open
 * command of its own and no argument that could choose one. The core also never
 * sees a session type: each orchestrator builds its own session inside this
 * step, so each can only ever hand its caller its own kind.
 */
type OpenStep<T> = (
  channel: ImapChannel,
  capability: string | null,
) => Promise<() => Promise<T>>;

/**
 * The session lifecycle every mail path shares. Module-private on purpose.
 *
 * Exporting it would be a raw escape hatch past the orchestrators: a caller
 * could supply any open step it liked, including one that opens a mailbox for
 * changing. The orchestrators are the only ways in, and each one names the open
 * it performs.
 *
 * The sequence is `greeting → CAPABILITY → authenticate → CAPABILITY →
 * open step → fn() → teardown`, strictly sequential throughout — one command in
 * flight at a time, as Phase 1 built it (D-44). Nothing here pipelines and
 * nothing later in this phase should: pipelining is the classic source of
 * parser desynchronisation, and the parser is the one component this phase
 * cannot afford to get subtly wrong.
 *
 * `gate.acquire()` is the first statement, before the `try`. A refused second
 * caller therefore never reaches the `finally` and cannot release the first
 * caller's slot. `src/mcp/api-handler.ts` depends on that placement for the
 * legacy-batch race it describes.
 *
 * **The deadline races the work, never the whole session.** Teardown has to run
 * AFTER the deadline fires; racing the outer call would abandon teardown along
 * with the work and leak exactly the connection the deadline exists to release.
 * It does not race the open step either, exactly as before the split.
 *
 * This is the only production construction site for `ImapChannel` and
 * `teardown` on the mail path, which is what makes D-51's injectable bounds
 * auditable in one place rather than at every call site.
 */
async function withMailSessionCore<T>(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  options: MailSessionOptions,
  open: OpenStep<T>,
): Promise<T> {
  gate.acquire();

  /**
   * Whether Apple named a credential condition — recorded, not acted on yet.
   *
   * The report is a store write, and a store write made while the socket is
   * still open is a second concurrent connection at the worst possible moment
   * (WR-03). CLAUDE.md § 3 is explicit that the six-simultaneous-connection
   * budget counts store reads alongside sockets, and that the OAuth provider has
   * already spent one before any mail code runs. It also extends the socket's
   * life by a store round trip on the one path that is already failing, and the
   * write throttles per key, so a burst makes it slow rather than instant.
   */
  let credentialRefused = false;

  const channel = new ImapChannel(duplex, {
    readTimeoutMs: options.readTimeoutMs,
    // The second bound on D-51's seam, threaded exactly as the first is. This
    // function remains the only production construction site of an
    // `ImapChannel`, so there is still exactly one place to audit an injected
    // value — which is the whole mitigation for making a safety bound
    // injectable at all.
    maxLiteralOctets: options.maxLiteralOctets,
  });

  try {
    await readGreeting(channel);
    await sendCommand(channel, channel.nextTag(), "CAPABILITY");

    // Threaded by name rather than by handing the whole options object over,
    // the way the channel's two bounds are threaded above. The authentication
    // step then receives exactly the one field that is its business, and a
    // reader can see at this line which fields reach it.
    const auth = await authenticate(channel, principal, {
      oneAttemptPerGuess: options.oneAttemptPerGuess,
    });
    if (!auth.authenticated) {
      // The one place on the mail tool path where APPLE ITSELF refused the
      // saved password (LIFE-04). Only a principal the door armed reports, so
      // the sign-in page — which runs this very function — pauses nobody.
      //
      // Branched on `credentialRefused` and NOT on `authenticated`, because
      // those are different questions. Every non-OK reply that is not a
      // connection ceiling arrives here, and two of them say nothing about the
      // password: a `NO [SERVERBUG]` or `NO [CONTACTADMIN]` from a server-side
      // fault, and a `BAD` from a protocol desync of our own making.
      // `indicatesCredentialRefusal` excludes exactly those; a refusal carrying
      // no bracketed code DOES pause, per the owner decision of 2026-09-22 that
      // reversed iteration 1's allow-list. The throw is unconditional either
      // way: the call still fails fast, exactly as the DAV site's 403 exclusion
      // leaves it.
      //
      // The need is RECORDED here and the store write happens after teardown
      // (WR-03). See the `finally` below for why.
      credentialRefused = auth.credentialRefused;
      throw new ImapAuthError();
    }

    const postLogin = await sendCommand(channel, channel.nextTag(), "CAPABILITY");
    const capability = firstCapability(postLogin.untagged);

    // The orchestrator's own open, and the session it builds. Outside the
    // deadline, as it was before the split.
    const work = await open(channel, capability);

    const outcome = await withDeadline<T | typeof DEADLINE_EXPIRED>(
      work(),
      options.callDeadlineMs ?? CALL_DEADLINE_MS,
      () => DEADLINE_EXPIRED,
    );
    if (outcome === DEADLINE_EXPIRED) throw new ImapConnectError();
    return outcome;
  } finally {
    try {
      await teardown(
        duplex,
        channel.reader,
        async (line) =>
          (await sendCommand(channel, channel.nextTag(), line)).tagged.text,
        {
          drainTimeoutMs: options.drainTimeoutMs,
          closeTimeoutMs: options.closeTimeoutMs,
        },
      );
    } catch {
      // teardown is written not to throw. If it somehow does, swallowing it
      // here preserves whichever error the conversation itself raised, which is
      // always the more informative of the two.
    }
    gate.release();

    // LAST, with the socket gone and the gate released, so the store write is
    // never a second concurrent connection (WR-03). `reportRefusal` is written
    // not to throw, so it cannot replace the error the conversation raised; and
    // it does nothing at all unless the door armed this principal, which is what
    // keeps the sign-in page — which runs this very function — from pausing
    // anybody.
    if (credentialRefused) await reportRefusal(principal);
  }
}

/**
 * The validity and message count an open reported, checked.
 *
 * Shared by every open, so each orchestrator refuses the same replies in the
 * same way. Both refusals are `ImapNotFoundError`.
 */
function checkedMailboxFacts(
  untagged: readonly ResponseLine[],
  expectedUidValidity: number | null,
): { uidValidity: number; exists: number } {
  let uidValidity: number | null = null;
  let exists = 0;
  for (const line of untagged) {
    const validity = parseUidValidity(line.text);
    if (validity !== null) uidValidity = validity;
    const count = parseExists(line.text);
    if (count !== null) exists = count;
  }

  // Absent fails closed, and this is the clause most easily skipped. The
  // RFC defines a missing UIDVALIDITY as "the server does not support
  // unique identifiers" — so every UID this call would return or accept is
  // meaningless. iCloud advertises UIDPLUS and will send it in practice,
  // but "will be present in practice" is not a check.
  if (uidValidity === null) throw new ImapNotFoundError();

  // D-23 / MAIL-06: refuse rather than silently restarting from page one. A
  // mismatch means the identifiers the caller is holding name different
  // messages now, and answering with whatever sits at that UID today would
  // be a wrong answer reported as the right one.
  // Its own subclass, so a caller can tell "the mailbox was recreated" from a
  // refused open (26-REVIEW WR-02). The category is still not_found.
  if (expectedUidValidity !== null && expectedUidValidity !== uidValidity) {
    throw new ImapValidityChangedError();
  }

  return { uidValidity, exists };
}

/**
 * Hold a read session over an already-open stream pair.
 *
 * Separated from the socket for the same reason `runDiagnosticOver` is: no
 * automated job in this repository may authenticate against the real Apple ID,
 * and the test environment offers no interception facility, so a version welded
 * to a socket would be untestable rather than merely awkward.
 *
 * The lifecycle — gate, channel, sign-in, deadline, teardown — is the private
 * core's. This function supplies only the open step, and the call into the core
 * is its first and only statement, so nothing awaits ahead of the gate.
 *
 * **The mailbox is OPTIONAL, and one entry point serves both shapes rather than
 * two.** A folder listing runs from the authenticated state and needs no
 * mailbox at all, so `null` here skips the open and the validity gate while
 * keeping everything that makes this the one read orchestrator: the
 * request-scoped gate, the call deadline, and the guaranteed teardown. The
 * alternative — a sibling entry point for authenticated-state-only work — is
 * precisely what `./diagnose.ts` argues against where it refuses a second
 * exported entry point: "two entry points is a choice a later author makes
 * without knowing they are making it, and the simpler signature is the one they
 * pick." A sibling here would have its own lifecycle semantics, and D-43's whole
 * claim is that one teardown covers every mail path.
 *
 * The three mailbox-shaped fields on `MailSession` go null together in that
 * case, so a caller cannot read one and infer another that was never
 * established.
 *
 * **The mailbox is opened with `EXAMINE`, and that is structural rather than
 * stylistic.** RFC 3501: "the selected mailbox is identified as read-only. No
 * changes to the permanent state of the mailbox, including per-user state, are
 * permitted". So a fetch that forgot the peeking form — the exact slip D-47
 * exists to prevent, and the one whose blast radius is a whole page of mail
 * marked read — is refused by Apple's server rather than silently succeeding.
 * It makes `\Seen` mutation unspeakable for the whole session in the same way
 * `connectImap()`'s empty parameter list makes the banned transport unspeakable
 * at the call site. Opening a mailbox in the mutating form on this path is a
 * decision, not a refactor.
 */
export async function withMailSessionOver<T>(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string | null,
  expectedUidValidity: number | null,
  fn: (session: MailSession) => Promise<T>,
  options: MailSessionOptions = {},
): Promise<T> {
  return withMailSessionCore(
    duplex,
    principal,
    gate,
    options,
    async (channel, capability) => {
      let uidValidity: number | null = null;
      let exists: number | null = null;

      // `null` means the caller does authenticated-state-only work. Everything
      // in this branch is the mailbox open and its gate, and skipping it is the
      // entire difference between the two shapes — the gate, the deadline and
      // the teardown are all in the core and run either way.
      if (mailbox !== null) {
        // Refuse rather than repair, exactly as `credentials.ts` does one layer
        // over: a mailbox name carrying CR or LF would terminate the command
        // line early and inject a second command built from the name's own
        // bytes.
        const quoted = quoteMailbox(mailbox);
        if (quoted === null) throw new ImapNotFoundError();

        const examine = await sendCommand(
          channel,
          channel.nextTag(),
          `EXAMINE ${quoted}`,
        );
        if (examine.status !== "OK") {
          // Only the server's NONEXISTENT code says the mailbox is gone
          // (26-REVIEW WR-03). Any other refusal may be transient.
          const gone =
            examine.status === "NO" &&
            parseCompletionCode(examine.tagged.text) === FOLDER_GONE_CODE;
          throw gone ? new ImapGoneError() : new ImapNotFoundError();
        }

        ({ uidValidity, exists } = checkedMailboxFacts(
          examine.untagged,
          expectedUidValidity,
        ));
      }

      const session: MailSession = {
        access: "read-only",
        channel,
        mailbox,
        uidValidity,
        exists,
        capability,
      };

      return () => fn(session);
    },
  );
}

/**
 * Open one socket and hold a mail session over it.
 *
 * The thin transport wrapper, copying `runDiagnosticOutcome`'s bare
 * try-connect-catch shape and its context-free error: a connect failure has no
 * conversation and no measurement beyond the failure itself, and the caught
 * value must not be inspected.
 *
 * **No raw escape hatch and no second exported entry point with different
 * failure semantics.** `diagnose.ts` records why, and it applies unchanged
 * here: two entry points is a choice a later author makes without knowing they
 * are making it, and the simpler signature is the one they pick.
 *
 * The gate is checked BEFORE the socket is opened, and the check is not
 * redundant with the `acquire()` inside the private core, `withMailSessionCore`,
 * which `withMailSessionOver` reaches with no await ahead of it. Acquiring only
 * after the connect would open a second socket and then refuse it, spending the
 * connection the gate exists to protect. Nothing awaits between the check here
 * and that acquire — `connectImap()` is synchronous and an async function's
 * body runs synchronously until its first `await` — so the pair is atomic with
 * respect to the event loop rather than merely likely to be.
 *
 * That is also why this takes a principal and never the promise of one. The
 * tool callback awaits the promise, as the first line of its try, and hands the
 * resolved object down. An await here, ahead of the socket open, would put a
 * gap between the check and the acquire, and two tool calls in one legacy batch
 * share one gate: both could pass the check and both could open a socket. A
 * test reads this function as text and fails if an await appears in that span.
 */
export async function withMailSession<T>(
  principal: Principal,
  gate: SessionGate,
  mailbox: string | null,
  expectedUidValidity: number | null,
  fn: (session: MailSession) => Promise<T>,
  options: MailSessionOptions = {},
): Promise<T> {
  if (gate.held) throw new ImapThrottleError();

  let sock: DuplexLike;
  try {
    sock = connectImap();
  } catch {
    throw new ImapConnectError();
  }

  return withMailSessionOver(
    sock,
    principal,
    gate,
    mailbox,
    expectedUidValidity,
    fn,
    options,
  );
}

/**
 * An authenticated session with one mailbox opened in the mutating form.
 *
 * Built only by `withMutatingMailboxOver`, and only after the server said the
 * mailbox is writable. A mutating session always has a mailbox open, so none of
 * the three mailbox fields can be `null` here, unlike on `MailSession`.
 *
 * `access` is `"read-write"` and `MailSession`'s is `"read-only"`. Those two
 * different literal values are what make the types unassignable to each other.
 * Without them TypeScript would compare the shapes, find them compatible, and
 * let a read helper take a mutating session or a verb take a read-only one.
 */
export interface MutatingMailSession {
  /** Always `"read-write"`. The discriminant that keeps the two kinds apart. */
  readonly access: "read-write";
  channel: ImapChannel;
  /** The raw wire mailbox name that was opened. */
  mailbox: string;
  /** The UIDVALIDITY the server reported, already checked against the id's. */
  uidValidity: number;
  /** How many messages the mailbox holds. */
  exists: number;
  /** The post-authentication capability list, verbatim, or `null`. */
  capability: string | null;
  /**
   * The last permanent-flags list the open reported, or `null` when it sent
   * none. RFC 3501 §6.3.1: no list means every flag is kept, so `null` is not
   * "unknown". Each verb checks the flag it needs against this itself (D-08),
   * which is why the orchestrator takes no mode argument.
   */
  readonly permanentFlags: readonly string[] | null;
}

/**
 * What the mutating orchestrator resolves to when the mailbox did not open for
 * writing.
 *
 * The server answered the open with OK but said the mailbox is read-only, or
 * gave no access code at all. Both are the same refusal (PITFALLS #33): absent
 * is not read-write.
 *
 * A third shape, a read-write open whose permanent-flags list leaves out the
 * flag a change needs, is no longer refused here. It belongs to each verb,
 * which checks the one flag it changes against the list the session records
 * (D-08). A change to a flag the list leaves out would last only until logout,
 * and the answer would report a change that is gone a moment later; the verb
 * refuses it before anything is sent.
 *
 * A value and not an exception, on purpose. The return type carries it, so
 * TypeScript makes every caller handle it. An exception could fall through to
 * `toErrorCategory`'s floor and come out as `connection_failed`, which tells the
 * model to retry something that will fail the same way every time.
 */
export const MAILBOX_NOT_WRITABLE: unique symbol = Symbol("mailbox-not-writable");

/**
 * The last permanent-flags list among an open's untagged replies, or `null`.
 *
 * Kept for the session so each verb can ask about the flag it needs. If a
 * server sends the list twice, the last one is its final word. RFC 3501
 * §6.3.1: no list at all means every flag is kept, so `null` is not "unknown".
 */
function permanentFlagsOf(untagged: readonly ResponseLine[]): string[] | null {
  let permanent: string[] | null = null;
  for (const line of untagged) {
    const flags = parsePermanentFlags(line.text);
    if (flags !== null) permanent = flags;
  }
  return permanent;
}

/**
 * Hold a session over an already-open stream pair, with one mailbox opened in
 * the mutating form.
 *
 * The lifecycle is the private core's, exactly as for the read orchestrator:
 * the same gate, the same sign-in, the same deadline, the same teardown. The
 * call into the core is the only statement, so nothing awaits ahead of the
 * gate. One session per request holds whichever kind of session it is.
 *
 * The mailbox and its validity are required, not nullable. A change is always
 * to a message the caller already holds an id for, and that id carries the
 * validity it was minted under.
 *
 * The open step, in order:
 *
 * 1. Quote the mailbox, refusing a name with CR, LF or NUL.
 * 2. Open it in the mutating form. This is the one place in the source tree
 *    that builds that command, and a scan count holds it there. Anything other
 *    than OK is `ImapNotFoundError`.
 * 3. Check the validity against the id's, before anything can change. Absent
 *    or different is `ImapNotFoundError`.
 * 4. Read the access code off the tagged completion. Only read-write goes on.
 *    Read-only and absent both resolve to `MAILBOX_NOT_WRITABLE`, and no
 *    command is sent after the open.
 * 5. Read the permanent-flags list off the untagged replies and record it on
 *    the session. This step refuses nothing. Each verb checks the one flag it
 *    changes against that list itself (D-08), which is why there is no mode
 *    argument here.
 * 6. Build the `MutatingMailSession` and hand it to `fn`.
 *
 * No mode argument, and none may be added. The read orchestrator takes none
 * either. Only `./triage.ts` imports this, and it exports verbs, never a session.
 */
export async function withMutatingMailboxOver<T>(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  expectedUidValidity: number,
  fn: (session: MutatingMailSession) => Promise<T>,
  options: MailSessionOptions = {},
): Promise<T | typeof MAILBOX_NOT_WRITABLE> {
  return withMailSessionCore<T | typeof MAILBOX_NOT_WRITABLE>(
    duplex,
    principal,
    gate,
    options,
    async (channel, capability) => {
      // Refuse rather than repair, as the read open does: a CR or LF in the
      // name would end the command line early and inject a second command.
      const quoted = quoteMailbox(mailbox);
      if (quoted === null) throw new ImapNotFoundError();

      const opened = await sendCommand(
        channel,
        channel.nextTag(),
        `SELECT ${quoted}`,
      );
      if (opened.status !== "OK") throw new ImapNotFoundError();

      // Before the access check, so a changed folder is not_found whether or
      // not it is writable. Nothing has been changed at this point either way.
      const { uidValidity, exists } = checkedMailboxFacts(
        opened.untagged,
        expectedUidValidity,
      );

      // OK alone does not mean writable. Only an explicit read-write code does.
      if (parseAccessCode(opened.tagged.text) !== "read-write") {
        return async () => MAILBOX_NOT_WRITABLE;
      }

      const session: MutatingMailSession = {
        access: "read-write",
        channel,
        mailbox,
        uidValidity,
        exists,
        capability,
        permanentFlags: permanentFlagsOf(opened.untagged),
      };

      return () => fn(session);
    },
  );
}

/**
 * Open one socket and hold a mutating session over it.
 *
 * The same shape as `withMailSession`, for the same reasons: the gate is
 * checked before the socket opens, nothing awaits between that check and the
 * core's acquire, and a connect failure is a context-free `ImapConnectError`.
 */
export async function withMutatingMailbox<T>(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  expectedUidValidity: number,
  fn: (session: MutatingMailSession) => Promise<T>,
  options: MailSessionOptions = {},
): Promise<T | typeof MAILBOX_NOT_WRITABLE> {
  if (gate.held) throw new ImapThrottleError();

  let sock: DuplexLike;
  try {
    sock = connectImap();
  } catch {
    throw new ImapConnectError();
  }

  return withMutatingMailboxOver(
    sock,
    principal,
    gate,
    mailbox,
    expectedUidValidity,
    fn,
    options,
  );
}

/**
 * The wire-size ceiling, above which a fetch stops pulling the whole message.
 *
 * **CALIBRATED, NOT MEASURED**, and that distinction is the reason this
 * sentence is first: a reader who believes this number was measured against
 * real messages will never revisit it, and it has not been. It is derived from
 * two things this project does know — Apple's own per-message limit, and the
 * isolate's heap — and from nothing else.
 *
 * Same order of magnitude as `MAX_EXTRACTED_TEXT_BYTES` in `./mime.ts`, and
 * identical to `MAX_LITERAL_OCTETS` in `./imap-session.ts`, because all three
 * bound the same failure seen from a different side: the transport's cap bounds
 * what is READ, this one bounds what is ASKED FOR, and the extraction cap bounds
 * what is HANDED ON. Peak memory on the common path is roughly the raw bytes
 * plus the parsed structure plus the decoded attachments — about three times the
 * wire size — so two mebibytes costs about six against a 128 MB isolate, with
 * room left for JSON serialisation.
 *
 * On trip it TRUNCATES and never raises (D-35). Adding a fifth error category
 * for "too big" was considered and rejected: Phase 1 closed the vocabulary at
 * four values deliberately and phases 3 through 6 all inherit it, and the
 * caller can do nothing differently with a fifth one anyway.
 *
 * This is explicitly NOT a context cap (D-34). The model asked for one specific
 * message by id and it gets that message; this bound protects the isolate, and
 * it is set high enough never to fire on real correspondence.
 */
export const MAX_WIRE_MESSAGE_BYTES = 2 * 1024 * 1024;

/**
 * The largest attachment PART this client will ask a server for.
 *
 * **CALIBRATED, NOT MEASURED**, and that sentence is first for the reason
 * `MAX_WIRE_MESSAGE_BYTES` gives above: a reader who believes this number was
 * measured against real attachments will never revisit it, and it has not been.
 *
 * The arithmetic. Plan 04-08 caps a staged file at 4 MiB of DECODED bytes.
 * Base64 inflates by a measured 1.3684 once the column wrapping RFC 2045
 * requires is counted, so 4 MiB of file arrives as roughly 5.6 MiB of encoded
 * octets. Eight mebibytes covers that with headroom for a part whose encoder
 * wraps shorter than 76 columns, and 8 MiB × the measured ~6.1 peak-to-source
 * ratio is about 50 MB against a 128 MB isolate — far above any real case this
 * project exists to serve and far below anything that threatens the isolate,
 * which is the same phrasing the other three ceilings calibrate themselves in.
 *
 * **This ceiling is raised on the attachment-fetch call ALONE.** It travels
 * through `MailSessionOptions` into one channel, per call. The whole-message
 * read path keeps `MAX_LITERAL_OCTETS` unchanged, so nothing here widens the
 * exposure of the path that pulls an entire stranger-composed message.
 *
 * On trip it REFUSES, and it is the one ceiling in this project that does. The
 * truncate-and-flag disposition `MAX_EXTRACTED_TEXT_BYTES` takes is correct for
 * a read path where a partial answer is still an answer; it is wrong here,
 * because a partial attachment is a corrupt file rather than a short one. See
 * `readAttachmentPart` for the failure in the concrete. No fifth error category
 * appears either (D-35): the refusal is a field on a SUCCESSFUL result, exactly
 * as `unsupportedCharset` is.
 */
export const MAX_ATTACHMENT_PART_OCTETS = 8 * 1024 * 1024;

/**
 * Round trip ONE: what the message IS, without a byte of what it says.
 *
 * `UID` is asked for explicitly rather than relying on the server to volunteer
 * it. RFC 3501 says a server must include it in a `UID FETCH` reply, but asking
 * costs nothing and removes the dependency on that guarantee — and the UID is
 * the only identifier permitted to reach the tool layer.
 *
 * `BODYSTRUCTURE` is the item that makes ATT-01 true as written. Attachment
 * filenames, media types and decoded sizes are all derivable from it, so the
 * metadata reaches the caller having downloaded no attachment at all. Reading
 * the same facts off a whole-message fetch would produce identical-looking
 * fields while having pulled every byte — which is the reason four earlier plans
 * declined to mark the requirement.
 *
 * Nothing in this reply is a literal, so this command's cost is a few hundred
 * bytes whatever the message weighs. That is what lets the size branch below
 * decide before it commits.
 */
const STRUCTURE_ITEMS = "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE)";

/**
 * Round trip TWO, common path: the whole message.
 *
 * The peeking form rather than the plain one: the peeking form does not set
 * `\Seen`. The mailbox is already open read-only so the server would refuse the
 * non-peeking form anyway, which is the point — two independent mechanisms, one
 * structural and one at the call site (D-47).
 */
const WHOLE_MESSAGE_ITEM = "BODY.PEEK[]";

/**
 * Round trip TWO, ceiling path: the headers, and one part.
 *
 * `section-text = section-msgtext / "MIME"` and "the MIME part specifier MUST
 * be prefixed by one or more numeric part specifiers" (RFC 3501 §9, §6.4.5), so
 * the part-scoped form is well-formed by the grammar. **Whether this server
 * accepts it is assumption A5 and is unverified** — see `FetchPath` for how the
 * answer is recorded rather than assumed.
 *
 * `null` means the structure offered no readable part at all, which happens for
 * a message that is nothing but attachments. There is then no part to name, so
 * only the headers are asked for; inventing a path would address nothing.
 */
function partScopedItems(path: string | null): string {
  if (path === null) return "(BODY.PEEK[HEADER])";
  return `(BODY.PEEK[HEADER] BODY.PEEK[${path}.MIME] BODY.PEEK[${path}])`;
}

/**
 * The origin marker a partial fetch's reply key carries.
 *
 * RFC 3501 §6.4.5: "A partial fetch that starts at octet 0 is returned as a
 * partial fetch, even if this truncation happened" — so a window request comes
 * back keyed `BODY[1]<0>` rather than `BODY[1]`, and it does so whether or not
 * anything was actually cut. The marker is therefore the NORMAL shape for a
 * windowed fetch and its absence is the special case, which is why it is
 * stripped at the parse site rather than guessed at by each reader: a lookup
 * that had to try both spellings is a lookup someone eventually writes one of.
 *
 * The origin itself is discarded rather than reported. Every window this client
 * asks for starts at octet zero, so the only value it can carry is one already
 * known at the call site.
 */
const ORIGIN_MARKER = /<\d+>$/;

/** Pair up a FETCH item list into a lookup, uppercasing the keys. */
function fetchItems(list: SExpr[]): Map<string, SExpr> {
  const items = new Map<string, SExpr>();
  for (let index = 0; index + 1 < list.length; index += 2) {
    const key = list[index];
    if (typeof key !== "string") continue;
    items.set(key.toUpperCase().replace(ORIGIN_MARKER, ""), list[index + 1]);
  }
  return items;
}

/**
 * The item list of the first untagged FETCH reply, or `null`.
 *
 * **The sequence-number prefix is discarded here and never travels further.**
 * Every untagged FETCH carries one — RFC 3501's `message-data` production puts
 * a sequence number in front of either the removal notice or a FETCH — even in
 * reply to a `UID FETCH`. It is the single
 * place in this phase where a sequence number is handed to the client unasked,
 * and MAIL-06 requires a UID-only surface, so it is dropped at the parse site
 * rather than filtered later by everyone who touches the result.
 */
function firstFetchItems(untagged: ResponseLine[]): Map<string, SExpr> | null {
  for (const line of untagged) {
    const parsed = parseSExpr(line);
    if (parsed[0] !== "*") continue;
    if (typeof parsed[2] !== "string" || parsed[2].toUpperCase() !== "FETCH") {
      continue;
    }
    const list = parsed[3];
    if (!Array.isArray(list)) continue;
    return fetchItems(list);
  }
  return null;
}

/**
 * Every untagged FETCH reply in a command's response, keyed by its OWN UID.
 *
 * **Keyed by the UID ITEM, never by the sequence-number prefix and never by
 * position.** The prefix is dropped at exactly the same place and for exactly
 * the same reason `firstFetchItems` drops it, and correlating by position
 * instead would be the hazard plan 02-06 reproduced one layer down, where
 * positional pairing put one folder's counts on another and the result still
 * looked entirely plausible. A batched page fetch is where that hazard has the
 * most room: twenty-five replies, any of which a server may legitimately omit,
 * reorder, or split.
 *
 * A reply carrying no UID item at all is skipped rather than guessed at. There
 * is nothing to correlate it to, and inventing a position for it is how one
 * message's snippet lands on another's row.
 */
function fetchReplies(untagged: ResponseLine[]): Map<number, Map<string, SExpr>> {
  const replies = new Map<number, Map<string, SExpr>>();

  for (const line of untagged) {
    const parsed = parseSExpr(line);
    if (parsed[0] !== "*") continue;
    if (typeof parsed[2] !== "string" || parsed[2].toUpperCase() !== "FETCH") {
      continue;
    }
    const list = parsed[3];
    if (!Array.isArray(list)) continue;

    const items = fetchItems(list);
    const uid = items.get("UID");
    if (typeof uid !== "string" || !/^[1-9]\d*$/.test(uid)) continue;
    replies.set(Number(uid), items);
  }

  return replies;
}

/** Whether a parsed FLAGS list carries `\Seen`. */
function isSeen(flags: SExpr): boolean {
  if (!Array.isArray(flags)) return false;
  return flags.some(
    (flag) => typeof flag === "string" && flag.toLowerCase() === "\\seen",
  );
}

/** Everything round trip one established about a message. */
interface MessageStructure {
  /** The reply's item map, kept for the fields only it carries. */
  items: Map<string, SExpr>;
  /** The part that IS this message's readable body, or `null`. */
  textPart: BodyPart | null;
  /** ATT-01's metadata, derived from the structure and nothing else. */
  attachments: AttachmentMeta[];
  /**
   * The walk's own output, carried rather than discarded (plan 04-07).
   *
   * `AttachmentMeta` deliberately reports a DECODED size and says nothing about
   * transfer encoding, because those are the right things to tell a user about
   * their own file. `readAttachmentContent` needs the other two — the encoded
   * octet count the part-size pre-check compares against, and the encoding the
   * caller must undo — and both live only here.
   */
  parts: BodyPart[];
  /** The UID the server itself reported. */
  uid: number;
  /** RFC822.SIZE — the raw wire size, which the ceiling branch decides on. */
  wireSizeBytes: number;
}

/** Ask what the message is. */
async function readStructure(
  session: MailSession,
  ref: MessageRef,
): Promise<MessageStructure> {
  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${STRUCTURE_ITEMS}`,
  );
  if (result.status !== "OK") throw new ImapNotFoundError();

  const items = firstFetchItems(result.untagged);
  // A UID that matches nothing produces a tagged OK with no untagged reply at
  // all, which is the commonest shape of "that message is gone". That one is
  // certain, so it is the certain class (26-REVIEW WR-03).
  if (items === null) throw new ImapGoneError();

  // A structure this walk cannot make sense of yields an EMPTY list rather than
  // a throw (T-02-21), and an empty list is survivable here: no text part means
  // the headers alone are fetched, and no attachments means none are reported.
  // Refusing the whole message because a stranger composed a malformed one
  // would let them deny the user their own mail.
  const declared = items.get("BODYSTRUCTURE");
  const parts = Array.isArray(declared) ? walkBodystructure(declared) : [];

  const uidField = items.get("UID");
  const size = items.get("RFC822.SIZE");

  return {
    items,
    textPart: selectTextPart(parts),
    attachments: attachmentsFrom(parts),
    parts,
    uid: typeof uidField === "string" ? Number(uidField) : ref.uid,
    wireSizeBytes: typeof size === "string" ? Number(size) : 0,
  };
}

/**
 * Put an addressable id on every attachment row (D-76).
 *
 * **This is where the pure module and the identifier layer meet, and it is the
 * only place they can.** `attachmentsFrom` in `./mime.ts` derives the part path
 * and nothing else, because it is socket-free and knows no mailbox;
 * `encodeAttachmentId` in `./ids.ts` is the one minting site in the project.
 * Only this module holds a `MessageRef`, so the join happens here rather than
 * by widening either of the other two.
 *
 * **The mint cannot fail on this input, and that is a property rather than a
 * hope.** `encodeAttachmentId` runs `assertPartPath`, whose pattern is anchored
 * digit-and-dot segments with no leading zero. The structure walk builds every
 * segment as `String(index + 1)`, and `attachmentsFrom` excludes multiparts —
 * the only parts that carry the empty path. So there is no fallback branch
 * here, deliberately: a branch nothing can reach is a branch nobody can
 * maintain, and swallowing a throw would turn a mint failure into an attachment
 * the model can see and cannot address.
 *
 * A row with a null path is left alone. That is the shape the MIME library
 * produces, and it never reaches a response — `fetchOne` reports the
 * structure-derived list on every branch.
 */
function withAttachmentIds(
  rows: AttachmentMeta[],
  ref: MessageRef,
  uid: number,
): AttachmentMeta[] {
  return rows.map((row) =>
    row.path === null
      ? row
      : {
          ...row,
          id: encodeAttachmentId({
            mailbox: ref.mailbox,
            uidValidity: ref.uidValidity,
            uid,
            path: row.path,
          }),
        },
  );
}

/** Ask for the whole message. */
async function readWholeMessage(
  session: MailSession,
  ref: MessageRef,
): Promise<Uint8Array> {
  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${WHOLE_MESSAGE_ITEM}`,
  );
  if (result.status !== "OK") throw new ImapNotFoundError();

  const items = firstFetchItems(result.untagged);
  if (items === null) throw new ImapNotFoundError();

  // The response key is spelled WITHOUT the peek. That is the server's spelling
  // for the reply to a peeking request, not evidence that a non-peeking item
  // was sent — see the fetch item constants above for the request side.
  const body = items.get("BODY[]");
  if (!(body instanceof Uint8Array)) throw new ImapNotFoundError();
  return body;
}

/** The two byte runs the ceiling path assembles a result from. */
interface ScopedContent {
  /** The message's own header block. */
  header: Uint8Array;
  /** The selected part as a standalone entity, or empty when there was none. */
  entity: Uint8Array;
}

const CRLF_CRLF = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

/** Drop trailing CR and LF bytes, so exactly one blank line can be inserted. */
function trimTrailingEol(bytes: Uint8Array): Uint8Array {
  let end = bytes.byteLength;
  while (end > 0 && (bytes[end - 1] === 0x0a || bytes[end - 1] === 0x0d)) {
    end -= 1;
  }
  return bytes.subarray(0, end);
}

/**
 * Ask for the headers and one part, or report that the server refused.
 *
 * `null` means a tagged **BAD** — and only BAD. `BAD` means the request was
 * malformed, which for this command means the section specifier was rejected;
 * `NO` would mean the server understood the request and refused it, which is a
 * fact about the message rather than about the syntax, so retrying the same
 * question in simpler words would spend a command on an answer already given.
 * The same distinction `listAllFolders` draws below, for the same reason.
 */
async function readSelectedPart(
  session: MailSession,
  ref: MessageRef,
  path: string | null,
): Promise<ScopedContent | null> {
  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${partScopedItems(path)}`,
  );
  if (result.status === "BAD") return null;
  if (result.status !== "OK") throw new ImapNotFoundError();

  const items = firstFetchItems(result.untagged);
  if (items === null) throw new ImapNotFoundError();

  const header = items.get("BODY[HEADER]");
  if (!(header instanceof Uint8Array)) throw new ImapNotFoundError();
  if (path === null) return { header, entity: new Uint8Array(0) };

  const mime = items.get(`BODY[${path}.MIME]`);
  const content = items.get(`BODY[${path}]`);
  if (!(content instanceof Uint8Array)) throw new ImapNotFoundError();

  // The part's own MIME headers, one blank line, then its body — a standalone
  // entity the MIME parser can handle. Without the part's headers the transfer
  // encoding and charset are unknown, and the body would be handed on still
  // base64 or quoted-printable, which reads as garbage rather than as a failure.
  const headers = mime instanceof Uint8Array ? trimTrailingEol(mime) : new Uint8Array(0);
  return {
    header,
    entity: concatBytes(headers, CRLF_CRLF, content),
  };
}

/**
 * Whether two independently derived sizes describe the same file.
 *
 * They cannot be compared for equality, and the reason is arithmetic rather
 * than sloppiness. The structure-derived figure comes from `body-fld-octets`,
 * which counts the CRLFs MIME wraps a base64 body in; `decodedSizeBytes`
 * converts those at three bytes per four characters, so the structure-derived
 * size sits slightly ABOVE the decoded length of every wrapped attachment. A
 * strict equality here would fire on every real attachment and turn the
 * disagreement flag into noise.
 *
 * The tolerance is derived, not guessed. Each wrapped line costs two octets and
 * therefore inflates the estimate by 1.5 bytes; a line of L base64 characters
 * carries 3L/4 source bytes, so the inflation rate is 2/L. RFC 2045 caps L at
 * 76, giving 2.6%; encoders that wrap shorter inflate more. One eighth covers
 * wrapping all the way down to sixteen characters a line, which is far looser
 * than any real encoder, plus three bytes for base64's padding rounding.
 *
 * **The discriminating half is the DIRECTION**, not the magnitude. A
 * structure-derived size BELOW the decoded length cannot be explained by
 * framing at all — it means one of the two derivations is wrong — so it is a
 * disagreement at any size.
 */
function sizesAgree(structureBytes: number, parsedBytes: number): boolean {
  if (structureBytes < parsedBytes) return false;
  return structureBytes - parsedBytes <= Math.ceil(parsedBytes / 8) + 3;
}

/** Whether the two derivations of the attachment list describe the same files. */
function attachmentsAgree(
  structure: AttachmentMeta[],
  parsed: AttachmentMeta[],
): boolean {
  if (structure.length !== parsed.length) return false;
  return structure.every((one, index) => {
    const other = parsed[index];
    if (other === undefined) return false;
    return (
      one.filename === other.filename &&
      one.mimeType === other.mimeType &&
      sizesAgree(one.sizeBytes, other.sizeBytes)
    );
  });
}

/**
 * Fetch one message inside an open session, in two round trips.
 *
 * The first asks what the message is; the second asks for as much of it as its
 * size warrants. Splitting them is what lets the client know a message's weight
 * before committing to pull it, and it is what makes ATT-01's "without
 * downloading the attachment" a property of the wire traffic rather than a
 * claim about the response shape.
 */
async function fetchOne(
  session: MailSession,
  ref: MessageRef,
  options: GetMessageOptions,
): Promise<MessageDetail> {
  const structure = await readStructure(session, ref);
  const path = structure.textPart?.path ?? null;

  let fetchPath: FetchPath = "whole-message";
  let attachmentsDisagree = false;
  let parsed: ParsedMessage;

  if (structure.wireSizeBytes > MAX_WIRE_MESSAGE_BYTES) {
    const scoped = await readSelectedPart(session, ref, path);

    if (scoped === null) {
      // A5 answered NO by the server itself. The whole-message fetch runs
      // instead and the caller is told which path ran, because the ceiling did
      // not protect the isolate on this call — `MAX_LITERAL_OCTETS` did, by
      // consuming and discarding past its cap.
      fetchPath = "part-scoped-refused";
      parsed = await extractMessage(await readWholeMessage(session, ref));
    } else {
      fetchPath = "part-scoped";
      const headers = await extractMessage(scoped.header);
      const body =
        scoped.entity.byteLength > 0
          ? await extractMessage(scoped.entity)
          : null;
      parsed = {
        ...headers,
        text: body?.text ?? "",
        html: body?.html ?? null,
        bodySource: body?.bodySource ?? null,
        truncated: headers.truncated,
      };
    }
    // Truncated on BOTH over-ceiling branches, and it is a statement about what
    // the caller HAS rather than about which command ran: neither branch
    // returned the whole message. A successful call throughout — no error is
    // raised and no fifth category appears (D-35).
    parsed = {
      ...parsed,
      truncated: true,
      attachments: withAttachmentIds(structure.attachments, ref, structure.uid),
    };
  } else {
    // **Quoted reply history is kept verbatim here (D-36).** Nothing between
    // the wire and this line strips it, and adding a stripping heuristic is a
    // DECISION rather than an improvement: quote detection is guesswork across
    // clients and languages, stripping wrong silently deletes the part of a
    // message that mattered, and the quoted history is frequently the part a
    // user actually wants summarised.
    const whole = await extractMessage(await readWholeMessage(session, ref));
    attachmentsDisagree = !attachmentsAgree(
      structure.attachments,
      whole.attachments,
    );
    // The STRUCTURE-derived list wins, because it is the one that exists on
    // both branches. The disagreement is surfaced rather than resolved — and
    // it is also the only one of the two that can carry an addressable id,
    // because the library-derived rows have no part path (D-76).
    parsed = {
      ...whole,
      attachments: withAttachmentIds(structure.attachments, ref, structure.uid),
    };
  }

  const internalDate = structure.items.get("INTERNALDATE");

  return {
    ...parsed,
    // Text by default, raw markup on request (D-33). The parser already
    // produced the markup either way — the flag governs what is REPORTED, not
    // what is fetched, so asking for it costs no extra round trip. Nothing here
    // interprets the markup: rendering it is explicitly V2-MAIL-03's problem.
    html: options.includeHtml === true ? parsed.html : null,
    id: encodeMessageId({ ...ref, uid: structure.uid }),
    uid: structure.uid,
    unread: !isSeen(structure.items.get("FLAGS") ?? null),
    internalDate: typeof internalDate === "string" ? internalDate : null,
    wireSizeBytes: structure.wireSizeBytes,
    fetchPath,
    attachmentsDisagree,
  };
}

/**
 * Round trip ZERO of a reply: the six headers the threading rules need.
 *
 * **The peeking form, and this is the site Convention 5 exists for on the write
 * path.** Reading the parent in order to reply to it must not mark it read:
 * Claude reading your mail is not you reading your mail, MAIL-02 returns the
 * read status, and a fetch that quietly set the flag would not merely have a
 * side effect — it would corrupt an answer the user asked for. Two independent
 * mechanisms hold it, as everywhere else on this path: the mailbox is opened
 * read-only for the whole session, and the item itself peeks.
 *
 * **Exactly six fields and no body part.** Every additional field is bytes on a
 * connection this project keeps strictly sequential, and nothing downstream
 * reads one — the same argument `LIST_WITH_STATUS` makes for its two attributes.
 *
 * The reply comes back keyed under the spelling WITHOUT the peek, which is the
 * server's spelling for the answer to a peeking request rather than evidence
 * that a mutating item was sent. `headerBlockOf` is what reads it, by prefix.
 */
const PARENT_HEADER_ITEM =
  "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID REFERENCES REPLY-TO FROM TO CC)])";

/**
 * The parent's threading and recipient headers, as the parent declared them.
 *
 * **Every value here is stranger-authored except the mailbox and UID that named
 * the message**, and unlike a fetched body these are values that go straight
 * back out into headers of a message the user will send. That is why the
 * builder shape-checks each one again rather than trusting this record.
 *
 * Display names are deliberately absent. The attribution line takes the
 * sender's name from the parsed message instead, so carrying them here would be
 * a second copy of a stranger-authored string with no reader.
 */
export interface ParentHeaders {
  /** The parent's own `Message-ID`, or `null` if it declared none. */
  messageId: string | null;
  /** The parent's `References` chain, in order. Empty when it had none. */
  references: string[];
  /** Bare addresses from `Reply-To`. Empty when the sender set none. */
  replyTo: string[];
  /** Bare addresses from `From`. Empty only for a message with no sender. */
  from: string[];
  /** Bare addresses from `To`. */
  to: string[];
  /** Bare addresses from `Cc`. */
  cc: string[];
}

/** Everything one parent read established, for one reply. */
export interface ReplyParent {
  /** The six threading and recipient headers. */
  headers: ParentHeaders;
  /** The parent itself, for the subject, the sender and the quoted original. */
  detail: MessageDetail;
}

/**
 * Every bare address in one parsed header field, groups flattened.
 *
 * A `group` — `Team: alice@x, bob@x;` — carries its members one level down, and
 * a reader that only looked at `.address` would silently drop every member of
 * one. On a reply-all that is a recipient the user expected to reach and did
 * not, reported as success.
 */
function addressesOf(list: Address[] | undefined): string[] {
  const found: string[] = [];
  for (const entry of list ?? []) {
    if (typeof entry.address === "string") {
      if (entry.address.length > 0) found.push(entry.address);
      continue;
    }
    for (const member of entry.group ?? []) {
      if (member.address.length > 0) found.push(member.address);
    }
  }
  return found;
}

/**
 * Read the six fields out of a header block.
 *
 * **Parsed by the shipped library rather than by hand, and the reason is the one
 * `./mime.ts` gives for decoding encoded-words the same way**: address-list
 * grammar has quoted local parts, comments, folding whitespace and groups in it,
 * and re-implementing that here is precisely the "~60 lines you shouldn't
 * reimplement" shape. Plan 02-01's recorded A7 answer confirmed the parser
 * accepts a bare header block, which is what makes a six-field reply parseable
 * at all.
 *
 * This is the one place in this module that reaches for the MIME library
 * directly rather than through `./mime.ts`, and that is a boundary worth naming.
 * `ParsedMessage` carries no recipients and no `References` today; plan 04-05
 * adds them there for D-70, and duplicating that work here to avoid one import
 * would have coupled two plans in the same wave to each other's edits of the
 * same file.
 *
 * Exported so the field mapping is testable against literal bytes with no
 * session, which is where every assertion about a stranger-authored value
 * belongs.
 */
export async function parseParentHeaders(
  block: Uint8Array,
): Promise<ParentHeaders> {
  const parsed = await PostalMime.parse(block);

  return {
    messageId: parsed.messageId ?? null,
    // The library hands back the field's raw value with folds already merged,
    // so splitting on whitespace recovers the tokens a folded chain arrived as.
    references: (parsed.references ?? "")
      .split(/\s+/)
      .filter((token) => token.length > 0),
    replyTo: addressesOf(parsed.replyTo),
    from: addressesOf(parsed.from === undefined ? undefined : [parsed.from]),
    to: addressesOf(parsed.to),
    cc: addressesOf(parsed.cc),
  };
}

/**
 * Ask the parent for its six headers.
 *
 * A tagged failure of either kind yields `not_found` rather than a partial
 * record: a reply built from half a parent threads wrong, and the append
 * succeeds anyway. Unlike `readSelectedPart` there is no BAD-versus-NO split to
 * make, because there is no simpler question to fall back to — this item list is
 * already the smallest one that answers DRAFT-03.
 */
async function fetchParentHeaders(
  session: MailSession,
  ref: MessageRef,
): Promise<ParentHeaders> {
  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${PARENT_HEADER_ITEM}`,
  );
  if (result.status !== "OK") throw new ImapNotFoundError();

  const items = firstFetchItems(result.untagged);
  if (items === null) throw new ImapNotFoundError();

  const block = headerBlockOf(items);
  if (block === null) throw new ImapNotFoundError();

  return parseParentHeaders(block);
}

/**
 * Everything a reply needs from its parent, on ONE session.
 *
 * Two reads, strictly sequential, with the parent's mailbox open and gated on
 * its UIDVALIDITY: the six threading headers first, then the message itself for
 * the subject, the sender and the quoted original. Headers first because that
 * command carries no literal, so a server that refuses the section specifier
 * says so before a byte of body has been pulled.
 *
 * D-69 is why this exists at all **and the reason is not optional**: the opaque
 * message id encodes the mailbox, the UIDVALIDITY and the UID, and NOT the
 * parent's `Message-ID`. DRAFT-03's `In-Reply-To` and `References` therefore
 * cannot be built from anything the caller holds, so the reply tool has to fetch
 * them itself, inside the compose call.
 *
 * **The write does not share this session, and that is a decision rather than an
 * oversight.** One connection for the whole reply was the preference, and it is
 * not reachable without giving something up: the write runs from the
 * authenticated state with no mailbox open, so merging the two means either
 * restructuring the shipped `appendDraft` entry points, or inverting control so
 * that the tool's assembly runs inside this session. The second is what costs
 * something real — `refuseOversize` checks the assembled size BEFORE the socket
 * is opened, which its own docstring calls the cheapest possible refusal and the
 * one that spends none of the connection budget, and an assembly that happened
 * mid-session would forfeit exactly that.
 *
 * So a reply spends two connections, SEQUENTIALLY. Never concurrently: D-46's
 * gate refuses a second acquisition at runtime and `npm run scan` refuses a
 * combinator around either at commit time, on the six-connection argument.
 */
async function readReplyParent(
  session: MailSession,
  ref: MessageRef,
): Promise<ReplyParent> {
  const headers = await fetchParentHeaders(session, ref);
  // The markup is asked for because D-73 quotes it byte-identically; the
  // conversion to text for the plain half runs on the same bytes.
  const detail = await fetchOne(session, ref, { includeHtml: true });
  return { headers, detail };
}

/** Read one reply's parent over an already-open stream pair. */
export async function getReplyParentOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReplyParent> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readReplyParent(session, ref),
    options,
  );
}

/**
 * Read one reply's parent from iCloud.
 *
 * The pair shape every entry point in this file follows. The token's own
 * UIDVALIDITY is what the session gate compares against, so a parent named by an
 * id minted before the mailbox was recreated is refused before the fetch command
 * is written rather than answered from whatever now occupies that UID.
 */
export async function getReplyParent(
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<ReplyParent> {
  return withMailSession(
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readReplyParent(session, ref),
    options,
  );
}

/**
 * The one-part fetch item, in the PEEKING form.
 *
 * Convention 5, on the path it was written for. Claude reading your mail is not
 * you reading your mail: MAIL-02 reports read status, so a fetch that quietly
 * set the seen flag would not merely have a side effect — it would corrupt an
 * answer the user asked for. Two independent mechanisms hold it here as
 * everywhere else on this path (D-47): the mailbox is opened read-only for the
 * whole session, and the item itself peeks.
 *
 * Exactly one part and nothing else. Unlike `partScopedItems` there is no
 * header section and no `.MIME` sibling, because the caller already holds the
 * part's declared type and encoding from the structure walk that minted its id.
 *
 * The reply comes back keyed under the spelling WITHOUT the peek, which is the
 * server's spelling for the answer to a peeking request rather than evidence
 * that a mutating item was sent.
 */
function attachmentPartItems(path: string): string {
  return `(BODY.PEEK[${path}])`;
}

/**
 * What one attachment part fetch produced — or why it was never asked for.
 *
 * The refusal is a field on a SUCCESSFUL result rather than a raised error,
 * following `searchPage`'s `unsupportedCharset` precedent exactly: the call ran,
 * this client declined to spend the round trip, and none of the four values in
 * the closed FND-05 vocabulary describes that honestly. Two numbers are more
 * use to a model than any sentence would be, because they are what it needs in
 * order to explain the problem to the user.
 */
export type AttachmentFetch =
  | {
      fetched: true;
      /**
       * The part's octets exactly as the server sent them — STILL
       * transfer-encoded. Decoding is the caller's, and deliberately so; see
       * `getAttachmentBytes`.
       */
      bytes: Uint8Array;
    }
  | {
      fetched: false;
      refusal: "part-too-large";
      /** What the structure declared this part weighs, encoded. */
      encodedOctets: number;
      /** `MAX_ATTACHMENT_PART_OCTETS`, reported so the two travel together. */
      limitBytes: number;
    };

/**
 * Fetch one part's bytes, or refuse before writing a single command.
 *
 * **The pre-check is the whole point and it is unconditional.** The literal
 * reader consumes every octet a server declares but keeps at most its ceiling,
 * and it returns the short array with NO truncation signal of any kind. On a
 * read path that is survivable — a cut body is still readable text and a flag
 * says so. Here it is not: a base64 part cut mid-stream decodes to a corrupt
 * PREFIX of a real file. A PDF cut that way opens, renders its first pages, and
 * is wrong, and the user then attaches it to a message they send. That failure
 * is undetectable from the outside, which is why this refuses rather than
 * truncating, and why it refuses BEFORE the request rather than after the reply.
 *
 * Do not reach for the truncation flag `MAX_EXTRACTED_TEXT_BYTES` sets. That
 * disposition is right for a path where a partial answer is still an answer,
 * and this is not one.
 *
 * The check costs one comparison and no round trip: `encodedOctets` is already
 * on `BodyPart` and arrives from the same `BODYSTRUCTURE` reply that minted the
 * part's id, so it is a number the caller is holding anyway.
 *
 * **On the part path's provenance, answering plan 04-02's explicit question.**
 * This function RELIES on `assertPartPath` and does not re-check. The path
 * arrives inside an `AttachmentRef`, which is the type `decodeAttachmentId`
 * returns and the only type this project mints one from; that codec runs the
 * assertion on mint and again on decode, and the assertion's pattern is anchored
 * digits-and-dots, so a path reaching here carries no section keyword, no
 * bracket, no byte range and no CR or LF. A second check here would be a second
 * rule with a second lifetime — the two would drift, and the day they disagreed
 * the one nobody had updated would be the one deciding what reaches the wire.
 */
async function readAttachmentPart(
  session: MailSession,
  ref: AttachmentRef,
  encodedOctets: number,
): Promise<AttachmentFetch> {
  if (encodedOctets > MAX_ATTACHMENT_PART_OCTETS) {
    return {
      fetched: false,
      refusal: "part-too-large",
      encodedOctets,
      limitBytes: MAX_ATTACHMENT_PART_OCTETS,
    };
  }

  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${attachmentPartItems(ref.path)}`,
  );
  // No BAD-versus-NO split, and for `fetchParentHeaders`'s reason rather than
  // `readSelectedPart`'s: there is no simpler question to fall back to. This is
  // already the smallest item list that names one part.
  if (result.status !== "OK") throw new ImapNotFoundError();

  const items = firstFetchItems(result.untagged);
  if (items === null) throw new ImapNotFoundError();

  const content = items.get(`BODY[${ref.path}]`);
  if (!(content instanceof Uint8Array)) throw new ImapNotFoundError();

  return { fetched: true, bytes: content };
}

/** Fetch one attachment part over an already-open stream pair. */
export async function getAttachmentBytesOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: AttachmentRef,
  encodedOctets: number,
  options: MailSessionOptions = {},
): Promise<AttachmentFetch> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readAttachmentPart(session, ref, encodedOctets),
    attachmentSessionOptions(options),
  );
}

/**
 * The session bounds an attachment fetch runs under.
 *
 * One override and one only: the literal ceiling, raised to
 * `MAX_ATTACHMENT_PART_OCTETS` for this call. Written as a `??` rather than a
 * hard set so a test can still drive a smaller ceiling, and stated as a default
 * rather than a global so no other command in this module inherits the raise.
 */
function attachmentSessionOptions(
  options: MailSessionOptions,
): MailSessionOptions {
  return {
    ...options,
    maxLiteralOctets: options.maxLiteralOctets ?? MAX_ATTACHMENT_PART_OCTETS,
  };
}

/**
 * Fetch one attachment part from iCloud.
 *
 * The pair shape every entry point in this file follows. The reference carries
 * its own UIDVALIDITY, so a part named by an id minted before the mailbox was
 * recreated is refused before the fetch command is written rather than answered
 * from whatever now occupies that UID.
 *
 * **The bytes come back still transfer-encoded, and decoding them is the
 * caller's job on purpose.** `CALL_DEADLINE_MS` races the session callback and
 * nothing else, so any work done inside it is work done holding a socket open.
 * Base64-decoding several megabytes is real CPU, and iCloud's per-account
 * connection ceiling is low and undocumented — exhausting it locks the user out
 * of their own mail on their own devices. There is no reason to spend a
 * connection on arithmetic, so the decode happens after this returns. A later
 * reader moving it back inside would reintroduce exactly that, silently.
 */
export async function getAttachmentBytes(
  principal: Principal,
  gate: SessionGate,
  ref: AttachmentRef,
  encodedOctets: number,
  options: MailSessionOptions = {},
): Promise<AttachmentFetch> {
  return withMailSession(
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readAttachmentPart(session, ref, encodedOctets),
    attachmentSessionOptions(options),
  );
}

/**
 * One attachment, described and then fetched.
 *
 * **The shape exists because of what `mail_get_attachment` is allowed to be
 * given: an opaque id and nothing else (D-76).** The id decodes to a mailbox, a
 * UIDVALIDITY, a UID and a part path — and to nothing about the part's SIZE,
 * ENCODING or declared TYPE, all three of which the caller needs and none of
 * which it holds. Plan 04-05 left that gap open by name, offering two answers:
 * the tool asks the structure walk, or the attachment row carries the numbers.
 *
 * **The structure walk is the answer, and the row was rejected for a reason
 * stronger than taste.** A row travels to the model inside a
 * `mail_get_message` response, so putting the encoded octet count and the
 * transfer encoding on it would publish two facts about MIME plumbing that the
 * model can neither act on nor verify — and `AttachmentMeta.sizeBytes`'s own
 * docstring is emphatic that the encoded count must never be reported as a size.
 * More decisively, the row does not come back: the tool is handed an id, not a
 * row, so a row carrying the numbers would still need the model to pass them
 * back, and a number the model can pass is a number the model can get wrong. The
 * walk asks the server, on the same session, one round trip before the fetch.
 *
 * The meta fields are present on BOTH arms of the nested `fetch`, so the tool's
 * trusted half reports the same fields whether the part was read or refused. A
 * refusal that could not say what it refused would be a worse answer than the
 * one `readAttachmentPart` already gives.
 */
export interface AttachmentContent {
  /** The declared media type, `type/subtype`, lowercased. Sender-authored. */
  mimeType: string;
  /** The sender's filename, or `null`. Sender-authored. */
  filename: string | null;
  /** The DECODED size — what the file weighs on disk. Never the wire count. */
  sizeBytes: number;
  /** The part's declared charset parameter, or `null`. Sender-authored. */
  charset: string | null;
  /** Lowercased `body-fld-enc`. The caller undoes this after the session. */
  encoding: string;
  /** `body-fld-octets` — the wire count the part-size pre-check decided on. */
  encodedOctets: number;
  /** The fetch outcome, unchanged from plan 04-05's tested type. */
  fetch: AttachmentFetch;
}

/**
 * Describe one attachment from the server's own structure, then fetch it.
 *
 * **An id can only address a part that appears as an ATTACHMENT ROW.** The
 * lookup runs against `structure.attachments` — the list `attachmentsFrom`
 * produces, which excludes multiparts, excludes anything inside a forwarded
 * message, and excludes the selected body part by path — rather than against
 * the raw walk. That is the property D-76 rejected a raw part path to obtain:
 * the value class that "addresses ANY part including the body" is exactly what
 * the opaque id exists to make unspeakable, and resolving against the raw walk
 * here would hand it back through the side door. The `parts` lookup that follows
 * is only for the two numbers, and it cannot widen what is reachable because the
 * row lookup has already run.
 *
 * A path matching no row is `ImapNotFoundError`. That is one of the four
 * categories and it describes the situation honestly — the message was recomposed
 * or is gone — so unlike the size refusal there is nothing here to structure.
 *
 * The bytes come back STILL TRANSFER-ENCODED, unchanged from
 * `getAttachmentBytes`'s contract and for its reason: the decode is megabytes of
 * arithmetic and `CALL_DEADLINE_MS` races the session callback, so spending it
 * inside would hold a socket against iCloud's low undocumented per-account
 * ceiling for no gain.
 */
async function readAttachmentContent(
  session: MailSession,
  ref: AttachmentRef,
): Promise<AttachmentContent> {
  const structure = await readStructure(session, ref);

  const row = structure.attachments.find((one) => one.path === ref.path);
  if (row === undefined) throw new ImapNotFoundError();

  const part = structure.parts.find((one) => one.path === ref.path);
  if (part === undefined) throw new ImapNotFoundError();

  return {
    mimeType: row.mimeType,
    filename: row.filename,
    sizeBytes: row.sizeBytes,
    charset: part.params.charset ?? null,
    encoding: part.encoding,
    encodedOctets: part.encodedOctets,
    fetch: await readAttachmentPart(session, ref, part.encodedOctets),
  };
}

/** Describe and fetch one attachment over an already-open stream pair. */
export async function getAttachmentContentOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: AttachmentRef,
  options: MailSessionOptions = {},
): Promise<AttachmentContent> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readAttachmentContent(session, ref),
    attachmentSessionOptions(options),
  );
}

/**
 * Describe and fetch one attachment from iCloud, on ONE session.
 *
 * The entry point `mail_get_attachment` calls, and the pair shape every entry
 * point in this file follows.
 *
 * **This does not replace `getAttachmentBytes`, and the two are not
 * duplicates.** That one is the narrow call for a caller that already holds the
 * part's encoded octet count; this one is the composition for a caller holding
 * only an id. Both route through the same private `readAttachmentPart`, so the
 * unconditional pre-check that refuses before a fetch line is written is
 * inherited rather than re-implemented — there is exactly one place in this
 * project that decides whether a part is too large to ask for.
 */
export async function getAttachmentContent(
  principal: Principal,
  gate: SessionGate,
  ref: AttachmentRef,
  options: MailSessionOptions = {},
): Promise<AttachmentContent> {
  return withMailSession(
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readAttachmentContent(session, ref),
    attachmentSessionOptions(options),
  );
}

/** Fetch one message over an already-open stream pair. */
export async function getMessageOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: GetMessageOptions = {},
): Promise<MessageDetail> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => fetchOne(session, ref, options),
    options,
  );
}

/**
 * Fetch one message from iCloud.
 *
 * The token's own UIDVALIDITY is what the session gate compares against, so a
 * message id minted before the mailbox was recreated is refused rather than
 * answered with whatever now occupies that UID.
 */
export async function getMessage(
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: GetMessageOptions = {},
): Promise<MessageDetail> {
  return withMailSession(
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => fetchOne(session, ref, options),
    options,
  );
}

/**
 * How the per-folder counts were obtained — or why they are absent.
 *
 * **This field exists to settle a protocol question empirically on the first
 * real run**, which is the same move `parseCapabilityLine` makes by returning
 * the capability string verbatim and `resolveFolderRole` makes by reporting its
 * own provenance. The question: this account's measured post-authentication
 * capability list advertises the status-return option (`LIST-STATUS`) but NOT
 * the extended-listing extension whose syntax that option is written in. A
 * server offering the one without the other has no other way to expose the
 * feature, so it almost certainly accepts the clause — and "almost certainly"
 * is exactly the standing this project refuses for a protocol fact.
 *
 * So both paths are built, and the one that ran is reported. A listing whose
 * counts are `null` because the syntax was rejected is a different fact from a
 * listing whose folders genuinely hold no messages, and without this field the
 * two are indistinguishable (T-02-35).
 */
export type CountsSource = "list-status" | "unavailable";

/** One folder, as a listing reports it. */
export interface FolderSummary {
  /**
   * The opaque token that names this folder in a later call. Minted here, so
   * trusted — the same place and for the same reason `MessageDetail.id` is.
   */
  id: string;
  /**
   * The name exactly as the server spelled it, still modified-UTF-7 encoded.
   *
   * This is the value that round-trips back into a mailbox selection, and it
   * never crosses the tool boundary: the model holds `id` instead. Keeping the
   * wire form rather than the decoded one is what makes that round trip
   * byte-exact by construction and is why this project has a decoder and no
   * encoder.
   */
  wireName: string;
  /** The decoded name, for display only. Never sent back to the server. */
  displayName: string;
  /** The attribute list VERBATIM — original order, original casing. */
  attributes: string[];
  /** The resolved role, or `null` for an ordinary user folder. */
  role: FolderRole;
  /** Which path resolved the role, or `null` when none did (D-30, T-02-24). */
  roleSource: RoleSource;
  /** The folder's message count, or `null` when the server reported none. */
  totalCount: number | null;
  /** The folder's unread count, or `null` when the server reported none. */
  unreadCount: number | null;
}

/** Everything one folder listing established. */
export interface FolderListing {
  /** Every folder, in the order the server listed them. Never re-sorted. */
  folders: FolderSummary[];
  /** The hierarchy separator READ FROM THE WIRE, or `null` for a flat namespace. */
  delimiter: string | null;
  /** Which of the two listing paths ran. */
  countsSource: CountsSource;
}

/**
 * The recursive listing command, with the counts asked for inline.
 *
 * `""` is the reference name — the namespace root — and `*` matches at every
 * depth, so nested folders are visible (D-32). The `RETURN (STATUS …)` clause is
 * what makes the counts cost no extra round trip; it is also the part this
 * server may reject, which is what `LIST_PLAIN` below exists for.
 *
 * Only `MESSAGES` and `UNSEEN` are requested. Every additional attribute is a
 * count the server has to compute for every folder on a connection this project
 * deliberately keeps sequential, and nothing downstream reads them.
 */
const LIST_WITH_STATUS = 'LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))';

/** The RFC 3501 form, with no return clause. The fallback, and nothing else. */
const LIST_PLAIN = 'LIST "" "*"';

/**
 * Split a listing's untagged replies into its two response types.
 *
 * Both parsers return `null` for a line that is not theirs, so an untagged line
 * the server volunteers mid-listing — an `* OK [...]` status code, say — is
 * simply skipped rather than mistaken for either.
 */
function splitListingReplies(untagged: ResponseLine[]): {
  lists: MailboxListLine[];
  statuses: MailboxStatus[];
} {
  const lists: MailboxListLine[] = [];
  const statuses: MailboxStatus[] = [];

  for (const line of untagged) {
    const list = parseListLine(line);
    if (list !== null) {
      lists.push(list);
      continue;
    }
    const status = parseStatusLine(line);
    if (status !== null) statuses.push(status);
  }

  return { lists, statuses };
}

/**
 * The hierarchy separator, taken from the reply's own field (D-32).
 *
 * The first non-null one wins. A `NIL` delimiter is legal — it means a flat
 * namespace — and it is why this returns `null` rather than defaulting to `/`:
 * nothing in this project assumes a separator character, in the same spirit as
 * the ban on assuming a DAV hostname.
 */
function firstDelimiter(lists: MailboxListLine[]): string | null {
  for (const line of lists) {
    if (line.delimiter !== null) return line.delimiter;
  }
  return null;
}

/**
 * List every folder inside an already-open session.
 *
 * Sends the extended form first. On a tagged **BAD** — and only BAD — retries
 * once with the plain form. `BAD` means the request was malformed, which for
 * this command means the syntax was rejected; `NO` would mean the server
 * understood the command and refused it, which is a fact about the mailbox and
 * not about the clause, so retrying the same question in simpler words would
 * spend a command on an answer already given.
 *
 * **The fallback issues exactly ONE additional command, and must never issue
 * one status command per folder.** That loop is the obvious "improvement" and it
 * is the wrong one: twenty folders on a single sequential connection is
 * precisely the cost D-19 declined, and it would spend most of the call deadline
 * (T-02-07) to recover counts the tool already reports as unavailable. A later
 * contributor reading this should not add the loop.
 */
async function listAllFolders(session: MailSession): Promise<FolderListing> {
  let result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    LIST_WITH_STATUS,
  );
  let countsSource: CountsSource = "list-status";

  if (result.status === "BAD") {
    result = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      LIST_PLAIN,
    );
    countsSource = "unavailable";
  }

  // Whichever form ran, a non-OK completion here is a listing that did not
  // happen. `not_found` is the category in the closed four-value vocabulary
  // whose guidance fits — the resource could not be reached — and no fifth
  // category is added for it, for the reason `src/errors.ts` already gives.
  if (result.status !== "OK") throw new ImapNotFoundError();

  const { lists, statuses } = splitListingReplies(result.untagged);
  const delimiter = firstDelimiter(lists);

  // Correlated by NAME. Positional pairing puts one folder's counts on another
  // whenever the server legitimately omits a status reply — for an unselectable
  // mailbox, or when its own lookup failed — and the result still looks
  // entirely plausible.
  const correlated = correlateStatus(lists, statuses);

  // In SERVER order, and deliberately not sorted. The order a server lists
  // folders in is itself information about how the account is organised, and a
  // re-sort discards it while adding nothing a caller cannot do for itself.
  const folders = correlated.map(({ line, counts }): FolderSummary => {
    const displayName = decodeModifiedUtf7(line.name);
    // The line's OWN delimiter, not the listing-wide one: it is the server's
    // answer about this mailbox, and the whole-name rule that stops a child
    // folder claiming its parent's role is stated against it.
    const { role, source } = resolveFolderRole(
      line.attributes,
      displayName,
      line.delimiter,
    );

    return {
      id: encodeFolderId({ mailbox: line.name }),
      wireName: line.name,
      displayName,
      attributes: line.attributes,
      role,
      roleSource: source,
      // Absent stays absent. A folder the server reported no counts for is a
      // different fact from a folder with none, and only one of the two is true.
      totalCount: counts?.MESSAGES ?? null,
      unreadCount: counts?.UNSEEN ?? null,
    };
  });

  return { folders, delimiter, countsSource };
}

/** Why a role folder could not be named: there was none, or there were two. */
export type RoleFolderRefusal = "none" | "ambiguous";

/**
 * Find the account's own archive or Trash folder in a listing it already has.
 *
 * Pure: it reads the listing and sends nothing. Only folders whose resolved
 * role is the one asked for are looked at, in two tiers.
 *
 * - **The attribute tier first.** Exactly one folder the server itself marked
 *   with the role's special-use attribute wins. An attribute is the server's own
 *   answer about its own mailbox.
 * - **The name tier only when no folder carries the attribute.** Exactly one
 *   folder whose top-level name matched the ladder wins. A name is a claim
 *   anyone can make (T-02-24): any user or mail client can make a folder called
 *   "Archive". So a name never outranks an attribute.
 *
 * **Two in the same tier is a refusal, never a pick** (D-03: never guess). The
 * listing order is the server's and says nothing about which one the user
 * means. None in either tier is a refusal too. There is no fallback to a
 * folder named anything, because a guess that happens to be right is still a
 * guess, and a wrong one files the user's mail where they will not look.
 *
 * Phase 22 reuses this for its Trash, and adds its own stricter check on top.
 */
export function resolveRoleFolder(
  listing: FolderListing,
  role: "archive" | "trash",
): { folder: FolderSummary } | { refusal: RoleFolderRefusal } {
  const candidates = listing.folders.filter((folder) => folder.role === role);
  for (const tier of ["special-use", "name-match"] as const) {
    const matched = candidates.filter((folder) => folder.roleSource === tier);
    if (matched.length === 1) return { folder: matched[0]! };
    if (matched.length > 1) return { refusal: "ambiguous" };
  }
  return { refusal: "none" };
}

/** List every folder over an already-open stream pair. */
export async function listFoldersOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  options: MailSessionOptions = {},
): Promise<FolderListing> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    // No mailbox: the listing command runs from the authenticated state, so no
    // mailbox is opened and no validity gate runs.
    null,
    null,
    listAllFolders,
    options,
  );
}

/**
 * List every folder in the account.
 *
 * Takes no folder, no pattern and no flag — the tool above it takes no
 * parameters at all, and this signature is what makes that shape honest rather
 * than merely enforced at the boundary.
 */
export async function listFolders(
  principal: Principal,
  gate: SessionGate,
  options: MailSessionOptions = {},
): Promise<FolderListing> {
  return withMailSession(principal, gate, null, null, listAllFolders, options);
}

// ---------------------------------------------------------------------------
// The move preview's read (Phase 21, D-09)
//
// A preview writes nothing, so it runs on the READ path: the source folder is
// opened read-only through the read orchestrator, exactly as a listing opens
// it. One folder listing to resolve the destination, and one fetch that reads
// each message's fingerprint and a peek at three header fields. No new open
// command, no mode argument, and nothing on the read path changes.
// ---------------------------------------------------------------------------

/**
 * The preview's fetch items: the fingerprint, plus a peek at three headers.
 *
 * The peeking form, as `PAGE_ITEMS` uses, so reading the subject for the
 * preview cannot mark the message read.
 */
const MOVE_PREVIEW_ITEMS =
  `${FINGERPRINT_ITEMS.slice(0, -1)} BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])`;

/** One message a move preview found, with the three fields it shows. */
export interface MoveCandidate {
  /** Size, internal date and MODSEQ, which the confirmation seals. */
  fingerprint: Fingerprint;
  /** The sender's subject line. Stranger-authored. */
  subject: string | null;
  /** The sender's declared address, or their name without one. Stranger-authored. */
  from: string | null;
  /** The sender's own Date header. Stranger-authored. */
  date: string | null;
}

/** Everything a move preview's one read session established. */
export interface MoveSetFacts {
  /** Every folder in the account, as the listing tool reports them. */
  listing: FolderListing;
  /** The messages found, in the order the UIDs were asked for. */
  found: MoveCandidate[];
  /** The UIDs the fetch had no reply for. */
  missing: number[];
  /**
   * Whether the folder reported mod-sequences. `"unavailable"` when the fetch
   * was answered BAD, or a message came back with no MODSEQ item: RFC 7162
   * §3.1.2 says a folder without persistent mod-sequences answers a MODSEQ
   * fetch that way. A move cannot be bound to "nothing changed" without them.
   */
  changeNumbers: "available" | "unavailable";
}

/** The folder a move leaves from: its wire name and the validity its ids carry. */
export interface MoveSource {
  mailbox: string;
  uidValidity: number;
}

/**
 * Read what a move preview needs, inside a session already open read-only.
 *
 * The validity gate has run by the time this is called: the read orchestrator
 * refuses a changed folder before any fetch is written.
 */
async function readMoveSetIn(
  session: MailSession,
  uids: readonly number[],
): Promise<MoveSetFacts> {
  if (uids.length === 0 || !uids.every((uid) => isWireNumber(uid) && uid > 0)) {
    throw new ImapNotFoundError();
  }

  const listing = await listAllFolders(session);

  const fetched = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${uids.join(",")} ${MOVE_PREVIEW_ITEMS}`,
  );
  if (fetched.status === "BAD") {
    return { listing, found: [], missing: [], changeNumbers: "unavailable" };
  }
  if (fetched.status !== "OK") throw new ImapNotFoundError();

  const replies = fetchReplies(fetched.untagged);
  const found: MoveCandidate[] = [];
  const missing: number[] = [];
  let changeNumbers: MoveSetFacts["changeNumbers"] = "available";

  for (const uid of uids) {
    const items = replies.get(uid);
    if (items === undefined) {
      missing.push(uid);
      continue;
    }
    const fingerprint = parseFingerprint(fetched.untagged, uid);
    if (fingerprint === null) {
      // No MODSEQ at all is the folder saying it has none. Anything else that
      // does not parse cannot be sealed, and is treated as not found.
      if (!items.has("MODSEQ")) changeNumbers = "unavailable";
      else missing.push(uid);
      continue;
    }

    const header = headerBlockOf(items);
    const parsed = header === null ? null : await extractMessage(header);
    found.push({
      fingerprint,
      subject: parsed?.subject ?? null,
      from: parsed?.fromAddress ?? parsed?.fromName ?? null,
      date: parsed?.date ?? null,
    });
  }

  return { listing, found, missing, changeNumbers };
}

/** Read a move preview's facts over an already-open stream pair. */
export async function readMoveSetOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  source: MoveSource,
  uids: readonly number[],
  options: MailSessionOptions = {},
): Promise<MoveSetFacts> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    source.mailbox,
    source.uidValidity,
    (session) => readMoveSetIn(session, uids),
    options,
  );
}

/** Read a move preview's facts: one socket, one read-only session. */
export async function readMoveSet(
  principal: Principal,
  gate: SessionGate,
  source: MoveSource,
  uids: readonly number[],
  options: MailSessionOptions = {},
): Promise<MoveSetFacts> {
  return withMailSession(
    principal,
    gate,
    source.mailbox,
    source.uidValidity,
    (session) => readMoveSetIn(session, uids),
    options,
  );
}

// ---------------------------------------------------------------------------
// The draft delete's preview read (Phase 22, D-05, D-07, D-08)
//
// The move preview's shape, for one draft. A preview writes nothing, so it runs
// on the READ path: the draft's folder is opened read-only through the read
// orchestrator, with its validity gate. One folder listing, which finds the
// drafts folder by the same ladder the compose tools use and the Trash folder
// by the server's own special-use attribute. Then one fetch of the draft's
// fingerprint and a peek at four header fields. No body is read.
// ---------------------------------------------------------------------------

/**
 * The draft preview's fetch items: the fingerprint, plus a peek at four headers.
 *
 * The peeking form, so reading the subject cannot mark the draft read.
 */
const DRAFT_PREVIEW_ITEMS =
  `${FINGERPRINT_ITEMS.slice(0, -1)} BODY.PEEK[HEADER.FIELDS (SUBJECT TO CC DATE)])`;

/**
 * Why a draft preview refused. Each wrote nothing and needs no retry advice.
 *
 * - `not-in-drafts`: the message is not in the folder the drafts ladder
 *   resolves (D-07).
 * - `no-trash-folder`: no folder carries the server's special-use Trash
 *   attribute. A folder merely NAMED Trash does not count (D-08).
 * - `ambiguous-role-folder`: two folders carry it, so none is picked.
 * - `no-change-numbers`: the folder reports no MODSEQ, so a delete could not
 *   be bound to "nothing changed" (D-05).
 * - `not-a-draft`: the message does not carry the draft flag (D-07).
 * - `already-marked-for-removal`: the draft already carries the removal mark,
 *   and its copy in Trash would carry it too (D-05).
 */
export type DraftPreviewRefusal =
  | "not-in-drafts"
  | "no-trash-folder"
  | "ambiguous-role-folder"
  | "no-change-numbers"
  | "not-a-draft"
  | "already-marked-for-removal";

/** What a draft preview found, for the confirmation and the answer. */
export interface DraftForChange {
  /** Size, internal date and MODSEQ, which the confirmation seals. */
  fingerprint: Fingerprint;
  /** The draft's subject line. Not vouched for: any app can write a draft. */
  subject: string | null;
  /** The To addresses, as the draft declares them. */
  to: string[];
  /** The Cc addresses, as the draft declares them. */
  cc: string[];
  /** The draft's own Date header. */
  date: string | null;
  /** The drafts folder's wire name, as the listing spelled it. */
  draftsMailbox: string;
  /** Which tier of the ladder found the drafts folder. */
  draftsRoleSource: RoleSource;
  /** The Trash folder's wire name, as the listing spelled it. */
  trashMailbox: string;
  /** The Trash folder's decoded name, for display only. */
  trashDisplayName: string;
}

/** A draft preview's answer: a refusal by name, or the facts. */
export type DraftReadOutcome =
  | { refusal: DraftPreviewRefusal }
  | { draft: DraftForChange };

/** Whether a flag list holds `flag`, compared without case. */
function hasFlag(flags: readonly string[], flag: string): boolean {
  const wanted = flag.toLowerCase();
  return flags.some((one) => one.toLowerCase() === wanted);
}

/** Every address a parsed header field carries, name-only entries by name. */
function addressList(
  list: readonly { name: string | null; address: string | null }[],
): string[] {
  const found: string[] = [];
  for (const entry of list) {
    const value = entry.address ?? entry.name;
    if (value !== null && value.length > 0) found.push(value);
  }
  return found;
}

/**
 * Read what a draft delete's preview needs, inside a session already open
 * read-only on the draft's folder.
 *
 * In order, and each step refuses before the next is sent:
 * 1. The folder listing. The drafts folder is the one the compose tools write
 *    to; with none, this is `not_found` and nothing is guessed. A message in
 *    any other folder is `not-in-drafts`, and no fetch is sent.
 * 2. Trash, from the same listing: exactly one folder the server marks as
 *    Trash. A name match does not count here (D-08).
 * 3. One fetch of the fingerprint and four headers.
 * 4. The draft flag must be there, and the removal mark must not.
 */
async function readDraftIn(
  session: MailSession,
  ref: MessageRef,
): Promise<DraftReadOutcome> {
  if (!isWireNumber(ref.uid) || ref.uid <= 0) throw new ImapNotFoundError();

  const listing = await listAllFolders(session);
  const drafts = resolveAppendTarget(listing, null);
  if (ref.mailbox !== drafts.mailbox) return { refusal: "not-in-drafts" };

  // A tie is `ambiguous-role-folder` only when it is a tie between folders the
  // server itself marks as Trash. Two folders that merely share a Trash-like
  // name mean no folder carries the attribute, and that is `no-trash-folder`.
  const trash = resolveRoleFolder(listing, "trash");
  if ("refusal" in trash) {
    const marked = listing.folders.some(
      (folder) => folder.role === "trash" && folder.roleSource === "special-use",
    );
    return {
      refusal: trash.refusal === "ambiguous" && marked ? "ambiguous-role-folder" : "no-trash-folder",
    };
  }
  if (trash.folder.roleSource !== "special-use") return { refusal: "no-trash-folder" };

  const fetched = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${ref.uid} ${DRAFT_PREVIEW_ITEMS}`,
  );
  if (fetched.status === "BAD") return { refusal: "no-change-numbers" };
  if (fetched.status !== "OK") throw new ImapNotFoundError();

  const items = fetchReplies(fetched.untagged).get(ref.uid);
  if (items === undefined) throw new ImapNotFoundError();
  const fingerprint = parseFingerprint(fetched.untagged, ref.uid);
  if (fingerprint === null) {
    // No MODSEQ at all is the folder saying it has none. Anything else that
    // does not parse cannot be sealed, and is treated as not found.
    if (!items.has("MODSEQ")) return { refusal: "no-change-numbers" };
    throw new ImapNotFoundError();
  }

  if (!hasFlag(fingerprint.flags, "\\Draft")) return { refusal: "not-a-draft" };
  if (hasFlag(fingerprint.flags, "\\Deleted")) {
    return { refusal: "already-marked-for-removal" };
  }

  const header = headerBlockOf(items);
  const parsed = header === null ? null : await extractMessage(header);
  return {
    draft: {
      fingerprint,
      subject: parsed?.subject ?? null,
      to: addressList(parsed?.to ?? []),
      cc: addressList(parsed?.cc ?? []),
      date: parsed?.date ?? null,
      draftsMailbox: drafts.mailbox,
      draftsRoleSource: drafts.roleSource,
      trashMailbox: trash.folder.wireName,
      trashDisplayName: trash.folder.displayName,
    },
  };
}

/** Read a draft delete's preview facts over an already-open stream pair. */
export async function readDraftForChangeOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<DraftReadOutcome> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readDraftIn(session, ref),
    options,
  );
}

/** Read a draft delete's preview facts: one socket, one read-only session. */
export async function readDraftForChange(
  principal: Principal,
  gate: SessionGate,
  ref: MessageRef,
  options: MailSessionOptions = {},
): Promise<DraftReadOutcome> {
  return withMailSession(
    principal,
    gate,
    ref.mailbox,
    ref.uidValidity,
    (session) => readDraftIn(session, ref),
    options,
  );
}

// ---------------------------------------------------------------------------
// The change check's mail reads (CHNG-01, CHNG-07)
//
// Two reads, in two sessions, one after the other. The first asks each folder
// for its numbers and opens no mailbox. The second runs only for a folder whose
// next UID moved, and it opens that folder read-only through the orchestrator.
// A folder where nothing arrived is never opened at all.
// ---------------------------------------------------------------------------

export { MAX_CHANGE_FOLDERS };

/** What the status command asks for, in this order. */
const SNAPSHOT_ITEMS = "(UIDVALIDITY UIDNEXT MESSAGES HIGHESTMODSEQ)";

/**
 * One folder's answer to the status command, or the fact that it gave none.
 *
 * `answered: false` covers a name that could not be sent, a refused command,
 * and a reply that left out the validity or the next UID. The tool reports
 * each of those as "not checked" and keeps the folder's old state, so a folder
 * that did not answer is never reported as unchanged.
 */
export type FolderSnapshotOutcome =
  | { mailbox: string; answered: true; snapshot: StatusSnapshot }
  | { mailbox: string; answered: false; gone?: false }
  /**
   * The server refused the status command with the NONEXISTENT response code
   * (RFC 5530): the folder does not exist. Only that code. Any other refusal
   * is plain `answered: false`, so a wrong reading of iCloud's refusals costs a
   * repeated "not checked", never a folder dropped from the marker.
   */
  | { mailbox: string; answered: false; gone: true };

/** The one response code that says a folder is gone. */
const FOLDER_GONE_CODE = "NONEXISTENT";

/**
 * Ask each folder for its numbers, one at a time, in one session.
 *
 * The status command runs from the authenticated state, so no mailbox is
 * opened. The reply is matched to the folder by exact name, the way
 * `correlateStatus` matches, never by position.
 */
async function snapshotsIn(
  session: MailSession,
  mailboxes: readonly string[],
): Promise<FolderSnapshotOutcome[]> {
  const outcomes: FolderSnapshotOutcome[] = [];
  for (const mailbox of mailboxes) {
    // A name carrying CR, LF or NUL cannot be sent without injecting a second
    // command, so no line is sent for it at all.
    const quoted = quoteMailbox(mailbox);
    if (quoted === null) {
      outcomes.push({ mailbox, answered: false });
      continue;
    }

    const result = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      `STATUS ${quoted} ${SNAPSHOT_ITEMS}`,
    );
    if (result.status !== "OK") {
      const gone =
        result.status === "NO" &&
        parseCompletionCode(result.tagged.text) === FOLDER_GONE_CODE;
      outcomes.push(
        gone ? { mailbox, answered: false, gone: true } : { mailbox, answered: false },
      );
      continue;
    }

    let snapshot: StatusSnapshot | null = null;
    for (const line of result.untagged) {
      const candidate = parseStatusSnapshot(line);
      if (candidate !== null && candidate.name === mailbox) {
        snapshot = candidate;
        break;
      }
    }
    if (
      snapshot === null ||
      snapshot.uidValidity === null ||
      snapshot.uidNext === null
    ) {
      outcomes.push({ mailbox, answered: false });
      continue;
    }
    outcomes.push({ mailbox, answered: true, snapshot });
  }
  return outcomes;
}

/** Refuse more folders than the change check allows, before any socket. */
function assertFolderCount(mailboxes: readonly string[]): void {
  if (mailboxes.length > MAX_CHANGE_FOLDERS) throw new ImapNotFoundError();
}

/** Each folder's numbers, over an already-open stream pair. */
export async function folderSnapshotsOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailboxes: readonly string[],
  options: MailSessionOptions = {},
): Promise<FolderSnapshotOutcome[]> {
  assertFolderCount(mailboxes);
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    // No mailbox: the status command needs none, so none is opened.
    null,
    null,
    (session) => snapshotsIn(session, mailboxes),
    options,
  );
}

/**
 * Each folder's numbers: validity, next UID, message count, mod-sequence.
 *
 * One session, no mailbox opened. At most `MAX_CHANGE_FOLDERS` folders; more is
 * refused before any socket is opened.
 */
export async function folderSnapshots(
  principal: Principal,
  gate: SessionGate,
  mailboxes: readonly string[],
  options: MailSessionOptions = {},
): Promise<FolderSnapshotOutcome[]> {
  assertFolderCount(mailboxes);
  return withMailSession(
    principal,
    gate,
    null,
    null,
    (session) => snapshotsIn(session, mailboxes),
    options,
  );
}

/**
 * The most new-mail rows one folder returns. The count is exact regardless.
 */
export const MAX_NEW_MAIL_ROWS = 25;

/**
 * The row fetch's items: UID, flags, receipt time, and a peek of four header
 * fields. Nothing else.
 *
 * **A narrower row than `MessageSummary`, on purpose (CHNG-09).** The change
 * check says who new mail is from and what it is about. It fetches no snippet
 * window, no structure and no size, so it can carry no preview and no
 * attachment flag. A snippet is the start of a body, and the change check does
 * not read bodies. The header item is the peeking form, so nothing is marked
 * read even on a server that ignored the read-only open.
 *
 * **The two list fields are asked for only to see whether they are there
 * (Phase 28 D-31).** Mail sent through a mailing list carries a list id or an
 * unsubscribe field. The row says whether either one came back, and that is
 * all. Their values are never read into the row. This is how the autonomous
 * job knows not to draft a reply to list mail.
 */
const NEW_MAIL_ROW_ITEMS =
  "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM LIST-ID LIST-UNSUBSCRIBE)])";

/**
 * A header line that starts one of the two list fields. Only the name and its
 * colon are matched. The value after the colon is never captured.
 *
 * Anchored at the start of a line, so a subject that mentions a list field
 * does not count. A folded continuation line starts with a space or a tab, so
 * it cannot match either. Space before the colon is allowed because the old
 * header syntax permits it, and reading such a field as a list only means
 * fewer automatic replies.
 */
const LIST_FIELD_LINE = /^(?:list-id|list-unsubscribe)[ \t]*:/i;

/**
 * Whether a fetched header block holds a list id or an unsubscribe field.
 *
 * Decoded only to find where lines start. Field names are plain ASCII, so a
 * value in some other encoding cannot change the answer.
 */
function hasListField(header: Uint8Array): boolean {
  const text = new TextDecoder().decode(header);
  return text.split(/\r?\n/).some((line) => LIST_FIELD_LINE.test(line));
}

/**
 * One new message: who it is from and what it is about, and nothing more.
 *
 * `id`, `uid`, `unread` and `receivedAt` are this server's or the protocol's.
 * `fromName`, `fromAddress` and `subject` are stranger-authored and belong in
 * the fenced block.
 */
export interface NewMailRow {
  id: string;
  uid: number;
  unread: boolean;
  /** The server's INTERNALDATE, verbatim: when iCloud received it. */
  receivedAt: string | null;
  fromName: string | null;
  fromAddress: string | null;
  subject: string | null;
  /**
   * True when the message had a list id or an unsubscribe field, or both.
   * Only whether one was there; the values are never kept.
   *
   * The sender decides whether these fields are present, so a sender can
   * leave both off. False means neither came back, not that the message is
   * surely personal mail.
   */
  mailingList: boolean;
}

/** The new mail in one folder's UID range. */
export interface NewMail {
  /** How many messages in the range are still present. Exact. */
  count: number;
  /** Up to `MAX_NEW_MAIL_ROWS`, newest first. */
  rows: NewMailRow[];
}

/**
 * Count the messages still present in `[fromUid, toUidExclusive)`.
 *
 * **The range is bounded on both ends, and that is the point.** The open-ended
 * form always includes the newest message in the folder, even when nothing new
 * arrived, and it would also count mail that arrived after the status reply,
 * which the fresh marker does not cover. The upper end is the status reply's
 * next UID minus one, so what is counted is exactly what the fresh marker moves
 * past. Mail that arrives in between is left for the next call.
 *
 * Counted from what the search found, never from the difference between the
 * two next UIDs: that difference counts mail that arrived and was then deleted.
 * Only UIDs inside the range are kept, because a server may answer a range with
 * a UID outside it.
 *
 * An OK with no untagged search line counts as none, and that is measured, not
 * assumed. iCloud sends no search line at all when a UID search matches nothing
 * (21-UAT.md, "Probe, 2026-09-27"), and for a range that is the ordinary answer
 * when mail arrived and left again before this check. A move's re-read cannot
 * read it that way, because there "none" is the claim being proven; this range
 * only reports a count, so it can.
 */
async function newMailIn(
  session: MailSession,
  fromUid: number,
  toUidExclusive: number,
): Promise<NewMail> {
  if (toUidExclusive <= fromUid) return { count: 0, rows: [] };
  const mailbox = session.mailbox;
  const uidValidity = session.uidValidity;
  // Unreachable under an opened mailbox, and asserted rather than assumed: a
  // row with no validity would mint an id no later call could gate.
  if (mailbox === null || uidValidity === null) throw new ImapNotFoundError();

  const found = await uidsInRange(session, fromUid, toUidExclusive);

  const page = [...found].sort((a, b) => b - a).slice(0, MAX_NEW_MAIL_ROWS);
  if (page.length === 0) return { count: 0, rows: [] };

  const fetched = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${page.join(",")} ${NEW_MAIL_ROW_ITEMS}`,
  );
  if (fetched.status !== "OK") throw new ImapNotFoundError();
  const replies = fetchReplies(fetched.untagged);

  const rows: NewMailRow[] = [];
  for (const uid of page) {
    const items = replies.get(uid);
    // Expunged between the search and the fetch: an ordinary race, and the row
    // is simply absent. The count still says what the search found.
    if (items === undefined) continue;

    const header = headerBlockOf(items);
    // The same header parser the listing uses, so decoding cannot drift.
    const parsed = header === null ? null : await extractMessage(header);
    const internalDate = items.get("INTERNALDATE");

    rows.push({
      id: encodeMessageId({ mailbox, uidValidity, uid }),
      uid,
      unread: !isSeen(items.get("FLAGS") ?? null),
      receivedAt: typeof internalDate === "string" ? internalDate : null,
      fromName: parsed?.fromName ?? null,
      fromAddress: parsed?.fromAddress ?? null,
      subject: parsed?.subject ?? null,
      mailingList: header === null ? false : hasListField(header),
    });
  }

  return { count: found.size, rows };
}

/**
 * The UIDs still present in `[fromUid, toUidExclusive)`, inside an open
 * session. The caller has checked the range is not empty.
 *
 * THE ONE BOUNDED RANGE SEARCH (Phase 23 D-18). The range is closed at both
 * ends: the upper end is `toUidExclusive - 1`, never the open-ended form, which
 * would always take in the newest message and anything that arrived after the
 * status reply. Only UIDs inside the range are kept, because a server may
 * answer a range with a UID outside it. An OK with no search line is none.
 */
async function uidsInRange(
  session: MailSession,
  fromUid: number,
  toUidExclusive: number,
): Promise<Set<number>> {
  const last = toUidExclusive - 1;
  const result = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID SEARCH UID ${fromUid}:${last}`,
  );
  if (result.status !== "OK") throw new ImapNotFoundError();

  const found = new Set<number>();
  for (const line of result.untagged) {
    const identifiers = parseSearchLine(line);
    if (identifiers === null) continue;
    for (const uid of identifiers) {
      if (uid >= fromUid && uid <= last) found.add(uid);
    }
  }
  return found;
}

/** New mail in one folder's range, over an already-open stream pair. */
export async function newMailOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  uidValidity: number,
  fromUid: number,
  toUidExclusive: number,
  options: MailSessionOptions = {},
): Promise<NewMail> {
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    mailbox,
    uidValidity,
    (session) => newMailIn(session, fromUid, toUidExclusive),
    options,
  );
}

/**
 * New mail in one folder, between two next-UID values.
 *
 * The folder is opened read-only through the orchestrator, with the validity
 * the status reply gave as the expected one, so a folder whose validity moved
 * in between is refused rather than searched.
 */
export async function newMail(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  uidValidity: number,
  fromUid: number,
  toUidExclusive: number,
  options: MailSessionOptions = {},
): Promise<NewMail> {
  return withMailSession(
    principal,
    gate,
    mailbox,
    uidValidity,
    (session) => newMailIn(session, fromUid, toUidExclusive),
    options,
  );
}

// ---------------------------------------------------------------------------
// The paginated message listing (MAIL-02, D-20 … D-25, criterion 2)
//
// This is the response the model reads most, so it is where cost discipline
// matters most — on the wire and in the model's context alike. A page of any
// size costs ONE identifier command, ONE batched metadata command, and one
// snippet command per DISTINCT resolved part path. Never one command per
// message: at D-22's hundred-row maximum that shape would be two hundred
// sequential round trips inside a twenty-second deadline (T-02-07).
// ---------------------------------------------------------------------------

/**
 * The default page size (D-22).
 *
 * Twenty-five rows carrying a capped snippet each is a readable screenful at a
 * modest context cost — enough to find a message without paging, few enough
 * that the response is a list rather than a wall of prose.
 */
export const PAGE_SIZE_DEFAULT = 25;

/**
 * The page-size ceiling (D-22).
 *
 * A hundred rows stays well inside the CPU budget with headroom for the snippet
 * round trips, which is the only part that scales with the page: the identifier
 * and metadata commands are one apiece whatever the size, so this is really a
 * bound on how much MIME parsing and how many bytes of preview one call does.
 *
 * A request above it is CLAMPED rather than refused — see `clampPageSize`.
 */
export const PAGE_SIZE_MAX = 100;

/**
 * One row of a listing: everything criterion 2 names, and nothing else.
 *
 * **There is no body field on this type, and that is the point.** MAIL-02 says
 * "metadata only — never full bodies by default", and the reliable way to keep
 * that true against a later change is for the shape to have nowhere to put one.
 * `snippet` is a capped preview built from a bounded window of the message's
 * text part, not a body: it is measured in characters, it comes from a partial
 * fetch, and no path here ever asks for a whole message.
 */
export interface MessageSummary {
  /** The opaque token that names this message. Minted here, so trusted. */
  id: string;
  /** The UID within its mailbox. Protocol-supplied, so trusted. */
  uid: number;
  /** Derived from the flag list: true when `\Seen` is absent. */
  unread: boolean;
  /**
   * The server's INTERNALDATE — when iCloud received it.
   *
   * The sender's own `Date` header is deliberately NOT a field here. It is
   * stranger-authored, it disagrees with the receipt time on plenty of real
   * mail, and a listing carrying both would invite a reader to pick whichever
   * looked better. One date, and it is the one this server can vouch for.
   */
  internalDate: string | null;
  /** RFC822.SIZE — the raw wire size, not the decoded size. */
  wireSizeBytes: number;
  /** The sender's subject line. Stranger-authored. */
  subject: string | null;
  /** The sender's display name, exactly as they chose it. Stranger-authored. */
  fromName: string | null;
  /** The sender's declared address — declared, not verified. Stranger-authored. */
  fromAddress: string | null;
  /**
   * A capped preview of the readable part. Stranger-authored.
   *
   * `""` for a message whose structure offered no selectable text part, or
   * whose window decoded to nothing. That is an outcome rather than an error:
   * a snippet is a convenience, and no failure of one should cost the caller a
   * row. Never `null`, so a reader never has to distinguish two empties.
   */
  snippet: string;
  /**
   * Whether the message carries attachments, from the structure alone.
   *
   * Derived here from the same `BODYSTRUCTURE` the snippet path resolves
   * against, so it is this server's own reading rather than a sender's claim —
   * and not one byte of any attachment is fetched to establish it.
   */
  hasAttachments: boolean;
}

/**
 * One page of a listing.
 *
 * **`hasMore` and `nextCursor` are two separately named fields, deliberately
 * (D-24).** Criterion 2 asks for an explicit cursor AND an explicit signal that
 * more results exist, and two fields answer that literally — a model reading a
 * false `hasMore` stops without having to reason about what a null cursor
 * means.
 *
 * A total match count was considered and left out (D-24). An exact total is not
 * cheap on every path, and a number that is sometimes an estimate is worse than
 * no number at all in a response a model will quote back to a user.
 */
export interface MessagePage {
  /** The rows, newest first by descending identifier. */
  messages: MessageSummary[];
  /** Whether identifiers remained below this page. */
  hasMore: boolean;
  /** The token that continues below this page, or `null` when nothing does. */
  nextCursor: string | null;
}

/**
 * One page of a search.
 *
 * Identical to a listing page but for one field, because a search result IS a
 * listing — same rows, same metadata-only discipline, same cursor contract. The
 * model reads one shape whichever tool it reached for.
 */
export interface SearchPage extends MessagePage {
  /**
   * The server declined the charset this search needed (T-02-37).
   *
   * `true` means the call SUCCEEDED and found nothing to show — the search ran,
   * the server refused the encoding, and no error was raised. It is a field
   * rather than an error category because the closed four-value vocabulary has
   * nothing that describes it honestly: reporting `not_found` would tell the
   * model the mailbox does not exist, and `connection_failed` would tell it to
   * retry a command that will be refused identically every time.
   *
   * Always `false` on any search whose terms were plain ASCII, because no
   * charset clause was sent at all.
   */
  unsupportedCharset: boolean;
}

/** What a caller may vary about one listing. */
export interface ListMessagesOptions extends MailSessionOptions {
  /** Rows per page. Clamped, never refused — see `clampPageSize`. */
  pageSize?: number;
  /**
   * The `nextCursor` from a previous page. Absent means page one.
   *
   * One opaque token rather than an exposed identifier plus a validity (D-21),
   * so the two cannot travel separately and a caller cannot omit the half that
   * makes the other meaningful.
   */
  cursor?: string;
}

/**
 * Round trip TWO of a page: everything about every message on it, at once.
 *
 * `sequence-set` accepts a comma-separated list, so the whole page is one
 * command whatever its size. Every field criterion 2 names comes from this one
 * reply: the identifier, the read status (`FLAGS`), the receipt time
 * (`INTERNALDATE`), the wire size, the structure that resolves the snippet path
 * and the attachment presence, and a header block for the subject and sender.
 *
 * `UID` is asked for explicitly for the reason `STRUCTURE_ITEMS` gives: the RFC
 * requires the server to include it in a `UID FETCH` reply, but asking costs
 * nothing and removes the dependency on that guarantee — and here the UID is
 * what every reply is correlated by.
 *
 * The header block is a HEADER.FIELDS section rather than the whole header, and
 * it is fed to the MIME parser so the same RFC 2047 decoding serves the listing
 * and the full fetch. Plan 02-01's recorded A7 answer confirmed the parser
 * accepts a bare header block, which is what makes that possible and is what
 * keeps the hand-rolled encoded-word decoder this project refuses to write out
 * of the picture.
 *
 * The peeking form, for the reason `WHOLE_MESSAGE_ITEM` gives and one more: a
 * page fetch touches every message on the page at once.
 */
const PAGE_ITEMS =
  "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE " +
  "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)])";

/**
 * Round trip THREE and onward: a bounded window of ONE resolved part path.
 *
 * A partial fetch, so the window is `octets` encoded octets and not a byte more
 * — the reply's size is bounded by the request rather than by the message. One
 * command covers every message on the page that resolved to this path AND this
 * window, which is what turns "a snippet per message" into "a command per
 * distinct shape": in practice a page of ordinary mail resolves to one or two.
 *
 * `octets` is supplied rather than fixed because how far in a part's prose
 * begins depends on its subtype — see `windowOctetsFor`, which owns that
 * mapping. It is a NUMBER, and that is load-bearing: the peeking spelling stays
 * a LITERAL inside this function, so nothing about the fetch item's SHAPE
 * becomes caller-supplied and CLAUDE.md §5 is still held structurally rather
 * than by convention. There is no value a caller can pass that reaches the wire
 * as anything but a window size.
 *
 * The peeking form, and this is the site D-47 exists for. A page's snippet
 * fetch touches every message on it, so the non-peeking form here would mark a
 * whole page read in a single call — a far worse failure than the same slip on
 * a single-message fetch, and the reason `scripts/forbidden-tokens.mjs` names
 * the page-listing path in its rule.
 */
function snippetItems(path: string, octets: number): string {
  return `(BODY.PEEK[${path}]<0.${octets}>)`;
}

/**
 * The header block from a metadata reply, whatever spacing the server echoed.
 *
 * Matched by PREFIX rather than by the exact key this client asked for. A
 * server is free to echo the section specifier with different internal spacing
 * or field order, and an exact-key lookup would then silently return no subject
 * and no sender for every row — a page that looks like a folder full of blank
 * mail rather than like a bug.
 */
function headerBlockOf(items: Map<string, SExpr>): Uint8Array | null {
  for (const [key, value] of items) {
    if (key.startsWith("BODY[HEADER") && value instanceof Uint8Array) {
      return value;
    }
  }
  return null;
}

/**
 * Bring a requested page size inside its bounds, rather than refusing it.
 *
 * A refusal here costs a round trip and teaches nothing: the caller learns a
 * number was wrong and has to ask again. A clamp gives it a usable answer on
 * the first call, and the ceiling exists to protect this server rather than as
 * a contract the caller agreed to.
 *
 * A size below one clamps to the DEFAULT rather than to one. Zero and negative
 * numbers are not requests for a tiny page — they are a caller that has not
 * decided, and a one-row page would be a strange thing to invent on its behalf.
 */
function clampPageSize(requested: number | undefined): number {
  if (requested === undefined || !Number.isFinite(requested)) {
    return PAGE_SIZE_DEFAULT;
  }
  const whole = Math.floor(requested);
  if (whole < 1) return PAGE_SIZE_DEFAULT;
  return Math.min(whole, PAGE_SIZE_MAX);
}

/**
 * What a caller may filter a search by (MAIL-04, MAIL-05).
 *
 * **The two date fields are BOTH inclusive from the caller's point of view**,
 * and their names say so rather than echoing the protocol's own asymmetric
 * pair. IMAP's `SINCE` is inclusive of the day it names and `BEFORE` is
 * exclusive of it, and nothing in those two words signposts the difference — so
 * naming these fields after them would push the single most likely correctness
 * bug in search out to every caller. `searchKeys` below converts.
 *
 * Every field is optional, including all of them at once: a search with no
 * criteria is a listing, and the grammar has a key for that.
 */
export interface SearchCriteria {
  /** Matched against headers AND body, which is what "search my mail" means. */
  keyword?: string;
  /** Matched against the envelope's from field. */
  sender?: string;
  /** `YYYY-MM-DD`. INCLUSIVE of the day it names. */
  startDate?: string;
  /** `YYYY-MM-DD`. INCLUSIVE of the day it names — see `searchKeys`. */
  endDate?: string;
  /** Restrict to messages carrying no `\Seen` flag (MAIL-05). */
  unreadOnly?: boolean;
}

/**
 * The month names the protocol uses: fixed, English, three letters.
 *
 * `date-month = "Jan" / "Feb" / … / "Dec"` (RFC 3501 §9). A table rather than a
 * formatter, and that is a correctness requirement rather than a preference: a
 * locale-aware formatter produces `févr.` on a French runtime, which the server
 * cannot parse, and it does so silently on a code path that looks correct
 * everywhere the developer ran it.
 */
const IMAP_MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
] as const;

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Read a caller's `YYYY-MM-DD` into the UTC instant that day begins.
 *
 * Refuses rather than repairs, the way every other caller-supplied value on
 * this path does. The round-trip check is what catches `2026-02-31`: `Date.UTC`
 * happily rolls it forward to 3 March, and a range silently shifted by two days
 * is exactly the plausible-looking wrong answer this whole section exists to
 * prevent.
 *
 * `not_found` rather than a fifth category, for the reason `src/errors.ts`
 * gives: the vocabulary is closed at four, and this is the same shape of
 * failure as a token that will not decode — a caller-supplied value naming
 * something unaddressable.
 */
function parseIsoDay(value: string): Date {
  const match = ISO_DAY.exec(value);
  if (match === null) throw new ImapNotFoundError();

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const parsed = new Date(Date.UTC(year, month - 1, day));

  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    throw new ImapNotFoundError();
  }
  return parsed;
}

/** Format one day as `date-day "-" date-month "-" date-year`, in UTC. */
function imapDate(day: Date): string {
  return `${day.getUTCDate()}-${IMAP_MONTHS[day.getUTCMonth()]}-${day.getUTCFullYear()}`;
}

/**
 * The day after `day`, by UTC arithmetic rather than by incrementing a field.
 *
 * Adding a day's worth of milliseconds to a UTC instant is exact — UTC has no
 * daylight saving — and it carries month and year boundaries for free. The
 * obvious `day + 1` on the day number produces `29-Feb-2026`, a date that does
 * not exist, on the single commonest range a caller asks for.
 */
function dayAfter(day: Date): Date {
  return new Date(day.getTime() + MILLISECONDS_PER_DAY);
}

/**
 * A command whose arguments include synchronizing literals.
 *
 * `fragments` always holds exactly one more entry than `literals`: the text
 * before the first literal, between each pair, and after the last. A command
 * with no literals is one fragment and nothing else, which is why the ordinary
 * path and the literal path are one code path rather than two.
 */
interface LiteralCommand {
  fragments: string[];
  literals: Uint8Array[];
}

const ENCODER = new TextEncoder();

/**
 * Whether a term can travel as an IMAP quoted string.
 *
 * Printable US-ASCII, minus the double quote and the backslash. `QUOTED-CHAR`
 * does permit those two escaped, but this client does not construct escapes:
 * the literal path is already built, already length-prefixes the bytes, and
 * therefore already makes the term unable to be reinterpreted as command syntax
 * (T-02-11). Adding an escaping rule would be a second, weaker mechanism for a
 * problem the first one has already solved.
 *
 * CR, LF and NUL all fall outside this range and so take the literal path. CR
 * and LF are legal inside a literal — that is what literals are for — and NUL
 * is not, which is why it is refused at the boundary instead (see
 * `assertSearchable`).
 */
const QUOTABLE_TERM = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;

/** A tagged NO carrying the response code that names an unsupported charset. */
const BADCHARSET = /\[BADCHARSET\b/i;

/**
 * Build the `UID SEARCH` command for one page of one query.
 *
 * ## The date rule, stated once and in full
 *
 * - **Day-granular, disregarding time and timezone.** RFC 3501 §6.4.4 says so
 *   of both keys. There is no way to express "after 3pm", and a message
 *   received at 23:00 UTC may carry an internal date of either adjacent day
 *   depending on the server's own reckoning. The tool description says this
 *   rather than implying a precision that does not exist.
 * - **The start bound is inclusive; the end bound is sent one day later.**
 *   `SINCE` matches an internal date "within or later than the specified date"
 *   and `BEFORE` matches one "earlier than the specified date" — so a caller's
 *   inclusive 28 February becomes `BEFORE 1-Mar-2026`. Sending the caller's own
 *   end date would silently drop every message from the last day of the range,
 *   which is a plausible-looking wrong answer rather than a visible failure.
 * - **Matched on the server's own received date**, never the sender's `Date`
 *   header. That is what a person means by "mail from last week"; it is also
 *   the field a listing row already reports, so a search row and a listing row
 *   for the same message cannot disagree. The header is stranger-authored and
 *   is frequently wrong or absent.
 * - **Formatted from a fixed English table**, never through a locale-aware
 *   formatter — see `IMAP_MONTHS`.
 *
 * ## Two things considered and declined, recorded so they are not rediscovered
 *
 * **The extended search return option** (`ESEARCH`) is advertised by this
 * account's server and is declined: its result is a compressed sequence-set
 * rather than a flat list, which is more parsing rather than less in a phase
 * whose central risk is parser correctness. Opting in is also all-or-nothing
 * per command, so there is no way to ask for a count and still receive the
 * classic response — and a total count was already declined (D-24).
 *
 * **Server-side sorting** is likewise available and likewise declined: sorting
 * integers descending in the client is free, and the server-side form mandates
 * a charset argument, which drags in another rejection path for nothing.
 *
 * ## Key order
 *
 * Fixed, so an ordered command assertion can be written against it at all. The
 * cursor's range key comes first, which keeps a plain listing's command
 * byte-identical to what it was before search existed.
 */
function searchKeys(
  tag: string,
  criteria: SearchCriteria,
  cursor: PageCursor | null,
): LiteralCommand {
  const keys: { key: string; term?: string }[] = [];

  if (cursor !== null) keys.push({ key: `UID 1:${cursor.lastUid - 1}` });
  if (criteria.unreadOnly === true) keys.push({ key: "UNSEEN" });
  if (criteria.startDate !== undefined) {
    keys.push({ key: `SINCE ${imapDate(parseIsoDay(criteria.startDate))}` });
  }
  if (criteria.endDate !== undefined) {
    // The whole of the inclusive-end rule, in one call. See the docstring.
    keys.push({ key: `BEFORE ${imapDate(dayAfter(parseIsoDay(criteria.endDate)))}` });
  }
  if (criteria.sender !== undefined) {
    keys.push({ key: "FROM", term: criteria.sender });
  }
  if (criteria.keyword !== undefined) {
    keys.push({ key: "TEXT", term: criteria.keyword });
  }
  // `search = "SEARCH" [SP "CHARSET" SP astring] 1*(SP search-key)` — at least
  // one key is required, so a search with nothing to say still says something.
  if (keys.length === 0) keys.push({ key: "ALL" });

  // Decided before the head is written, because the clause sits BEFORE the
  // first key and there is no going back once the line has started.
  const needsCharset = keys.some(
    (one) => one.term !== undefined && !QUOTABLE_TERM.test(one.term),
  );

  const fragments: string[] = [];
  const literals: Uint8Array[] = [];
  let current = `${tag} UID SEARCH${needsCharset ? " CHARSET UTF-8" : ""}`;

  for (const one of keys) {
    if (one.term === undefined) {
      current += ` ${one.key}`;
      continue;
    }
    if (QUOTABLE_TERM.test(one.term)) {
      current += ` ${one.key} "${one.term}"`;
      continue;
    }
    // THE count. It comes from the ENCODED value's byte length and never from
    // the string's `.length`, and the two diverge on every non-ASCII input.
    // Too small and the server parses the tail of the term as a new command,
    // against text a stranger may have chosen; too large and it waits for
    // octets that will never arrive, holding the socket to the read bound. This
    // is the one place in this phase where an off-by-one is silently
    // catastrophic rather than merely wrong.
    const bytes = ENCODER.encode(one.term);
    current += ` ${one.key} {${bytes.byteLength}}`;
    fragments.push(current);
    literals.push(bytes);
    current = "";
  }

  fragments.push(current);
  return { fragments, literals };
}

/**
 * Send a command whose arguments may include synchronizing literals.
 *
 * The handshake, per literal: write the fragment ending in the declared byte
 * count, wait for the server's continuation, write exactly that many raw bytes,
 * then carry on with the next fragment. The last fragment ends the command
 * line. A command with no literals writes one line and never waits, which is
 * the ASCII path — no charset clause, no handshake, no extra round trip.
 *
 * **A rejection arriving instead of a continuation is RETURNED, not raised**,
 * and it is returned as an ordinary `CommandResult` so the caller cannot tell
 * where in the exchange it arrived. That matters because an unsupported charset
 * is a tagged `NO` that may land on either side of the continuation, and it is
 * a successful answer either way. See `ContinuationOutcome` for why an
 * exception here would be the wrong shape.
 *
 * Untagged data volunteered during each handshake is merged into the finished
 * command's untagged list. An `* EXPUNGE` that arrived while the server was
 * getting ready is as real as one that arrives afterwards.
 */
async function sendWithLiterals(
  channel: ImapChannel,
  tag: string,
  command: LiteralCommand,
): Promise<CommandResult> {
  const collected: ResponseLine[] = [];

  for (let index = 0; index < command.literals.length; index += 1) {
    await channel.write(command.fragments[index]!);

    const outcome = await awaitContinuation(channel, tag);
    if (outcome.kind === "rejected") {
      return {
        ...outcome.result,
        untagged: [...collected, ...outcome.result.untagged],
      };
    }
    collected.push(...outcome.untagged);

    // The raw payload, with no terminator: the declared count covers the term
    // alone, so a CRLF appended here would be read as two octets of it.
    await channel.writeBytes(command.literals[index]!);
  }

  await channel.write(command.fragments[command.fragments.length - 1]!);
  const result = await readUntilTag(channel, tag);
  return { ...result, untagged: [...collected, ...result.untagged] };
}

/** What round trip one of a page established. */
interface SearchOutcome {
  identifiers: number[];
  /** The server declined the charset — a successful call with nothing to show. */
  unsupportedCharset: boolean;
}

/**
 * Round trip ONE of a page: which identifiers are in play.
 *
 * Each page re-runs the search rather than caching a result list (D-25). That
 * keeps the listing stateless, so nothing goes stale between pages, and it is
 * what lets a cursor carry a single identifier rather than thousands.
 *
 * `ALL` on page one; a range strictly BELOW the cursor's last identifier on
 * every page after it, composed by intersection with whatever the caller asked
 * for. **Strictly below is the whole boundary property**: an inclusive range
 * would return the cursor's own message again at the top of the next page, and
 * a range starting one lower still would skip the message immediately after it.
 * Both failures look entirely plausible in a response.
 *
 * The intersection is also what makes unread paging correct for free: a message
 * that becomes read between two pages simply stops matching, so it drops out
 * with no duplicate and no skip.
 *
 * Descending-UID ordering is applied by the caller and is what makes paging
 * safe: new mail always receives a higher identifier, so it lands ahead of page
 * one and can never shift a later page out from under a live cursor.
 * Identifiers are unique within a mailbox, so there is no tie to break and the
 * order is total.
 *
 * A charset rejection is reported rather than raised. The search RAN; the
 * server declined the encoding; none of the four categories in the closed
 * vocabulary describes that. `not_found` would tell the model the mailbox does
 * not exist and `connection_failed` would tell it to retry something that will
 * fail identically (T-02-37).
 */
async function searchPage(
  session: MailSession,
  cursor: PageCursor | null,
  criteria: SearchCriteria,
): Promise<SearchOutcome> {
  const tag = session.channel.nextTag();
  const result = await sendWithLiterals(
    session.channel,
    tag,
    searchKeys(tag, criteria, cursor),
  );

  // A NO carrying the response code, and only that. RFC 3501 §6.4.4 is explicit
  // that an unsupported charset "MUST return a tagged NO response (not a BAD)",
  // so a BAD here is a genuinely malformed command and still refuses.
  if (result.status === "NO" && BADCHARSET.test(result.tagged.text)) {
    return { identifiers: [], unsupportedCharset: true };
  }
  if (result.status !== "OK") throw new ImapNotFoundError();

  // Every search reply on the response, concatenated. A server may legitimately
  // split a long result across more than one untagged line, and taking only the
  // first would silently shorten the folder.
  const found: number[] = [];
  for (const line of result.untagged) {
    const identifiers = parseSearchLine(line);
    if (identifiers !== null) found.push(...identifiers);
  }
  return { identifiers: found, unsupportedCharset: false };
}

/** What round trip two established about one row, before its snippet arrives. */
interface RowStructure {
  uid: number;
  items: Map<string, SExpr>;
  /**
   * Every part this message declares, kept rather than discarded.
   *
   * Carried so the blank-window fallback can name the resolved part's HTML
   * sibling without walking the structure a second time. Re-walking would parse
   * the same `BODYSTRUCTURE` twice per page and give the two walks a chance to
   * disagree — the list is already in hand at the one place it is built.
   */
  parts: BodyPart[];
  /** The part that IS this message's readable body, or `null`. */
  textPart: BodyPart | null;
  hasAttachments: boolean;
}

/**
 * The empty answer, spelled once so every early return agrees on it.
 *
 * This one object is handed to every caller by reference. Inside one isolate
 * that makes it shared between users (audit row N2), so it is frozen: a caller
 * that tries to write to it gets a `TypeError`, and the next caller still gets
 * an empty page.
 *
 * The inner array is frozen too. The unsupported-charset return spreads this
 * object, and a spread copy is a new outer object that still shares the same
 * inner array. The inner freeze is the one that protects that path.
 *
 * Frozen by the two statements below and not inside the declaring expression,
 * because the expression form does not type-check here: `messages` is declared
 * as a mutable array, and a frozen literal is a read-only one. The statement
 * form changes no type.
 */
const EMPTY_PAGE: SearchPage = {
  messages: [],
  hasMore: false,
  nextCursor: null,
  unsupportedCharset: false,
};
Object.freeze(EMPTY_PAGE.messages);
Object.freeze(EMPTY_PAGE);

/**
 * Fetch one page inside an open session.
 *
 * The mailbox is already open read-only and the validity gate has already run
 * — `withMailSessionOver` does both before this is called, which is what makes
 * "a validity change refuses before any fetch is written" a property of the
 * orchestrator rather than of every caller (D-23, T-02-12).
 *
 * **ONE page implementation, shared by the listing, the search and the unread
 * listing.** The criteria are the only thing that varies: a listing passes
 * none, a search passes the caller's, and the unread listing passes exactly one
 * added key. D-17 gave the unread tool its own NAME for the model's benefit and
 * said in the same breath that it "shares the list implementation internally
 * rather than duplicating it" — a second paging implementation is how the two
 * drift, and the drift would be in the ordering and the cursor arithmetic,
 * which are the parts nobody re-reads.
 */
async function fetchPage(
  session: MailSession,
  mailbox: string,
  cursor: PageCursor | null,
  pageSize: number,
  criteria: SearchCriteria,
): Promise<SearchPage> {
  const uidValidity = session.uidValidity;
  // Unreachable while this runs under an opened mailbox, and asserted rather
  // than assumed: a page whose rows carried no validity would mint identifiers
  // that no later call could gate.
  if (uidValidity === null) throw new ImapNotFoundError();

  // Nothing sits below UID 1, so a cursor resting there IS the end of the
  // folder. The guard is also what keeps `1:0` — a range no server has to
  // accept — off the wire entirely.
  if (cursor !== null && cursor.lastUid <= 1) return EMPTY_PAGE;

  const found = await searchPage(session, cursor, criteria);
  // A successful call that found nothing, with the reason attached. No metadata
  // fetch follows, because there is nothing to fetch.
  if (found.unsupportedCharset) return { ...EMPTY_PAGE, unsupportedCharset: true };

  // Newest first, and de-duplicated first: identifiers are unique within a
  // mailbox, so a repeat is a malformed reply rather than a real second
  // message, and letting one through would fetch the same row twice.
  const ordered = [...new Set(found.identifiers)].sort((a, b) => b - a);
  const page = ordered.slice(0, pageSize);
  if (page.length === 0) return EMPTY_PAGE;

  const hasMore = ordered.length > page.length;
  // Minted from the page's LAST identifier as the search reported it, not from
  // the last row actually returned. A message that vanished between the search
  // and the metadata fetch drops out of this page; anchoring the cursor to the
  // rows would then hand the next page a starting point above the gap, and the
  // vanished identifier would be re-requested forever.
  const lastUid = page[page.length - 1]!;

  const messages = await summaryRows(session, mailbox, uidValidity, page);

  return {
    messages,
    hasMore,
    nextCursor: hasMore
      ? encodeCursor({ mailbox, uidValidity, lastUid })
      : null,
    unsupportedCharset: false,
  };
}

/**
 * The listing's rows for `page`, a list of UIDs already chosen and ordered by
 * the caller, inside an open session.
 *
 * THE ONE ROW BUILDER. One batched metadata fetch of `PAGE_ITEMS`, then the
 * preview fetches, then the assembly, all in the peeking form. The listing, the
 * search, the unread listing and the recall new-mail read all build their rows
 * here, so the fields and the fetch items cannot drift between them. Rows come
 * back in `page`'s order; a UID the fetch did not answer for is left out.
 */
async function summaryRows(
  session: MailSession,
  mailbox: string,
  uidValidity: number,
  page: readonly number[],
): Promise<MessageSummary[]> {
  const metadata = await sendCommand(
    session.channel,
    session.channel.nextTag(),
    `UID FETCH ${page.join(",")} ${PAGE_ITEMS}`,
  );
  if (metadata.status !== "OK") throw new ImapNotFoundError();
  const replies = fetchReplies(metadata.untagged);

  const rows: RowStructure[] = [];
  for (const uid of page) {
    const items = replies.get(uid);
    // A UID the search reported and the fetch did not answer for is a message
    // expunged between the two commands. An ordinary race on a live mailbox,
    // and the row is simply absent rather than reported as an error.
    if (items === undefined) continue;

    const declared = items.get("BODYSTRUCTURE");
    const parts = Array.isArray(declared) ? walkBodystructure(declared) : [];
    rows.push({
      uid,
      items,
      parts,
      textPart: selectTextPart(parts),
      hasAttachments: attachmentsFrom(parts).length > 0,
    });
  }

  const previews = await pagePreviews(session, rows);

  const messages: MessageSummary[] = [];
  for (const row of rows) {
    const header = headerBlockOf(row.items);
    // The same parser the full fetch uses, so subject and sender decoding
    // cannot drift between the two responses. A row whose header block never
    // arrived keeps its place with null fields rather than being dropped.
    const parsed = header === null ? null : await extractMessage(header);

    const internalDate = row.items.get("INTERNALDATE");
    const size = row.items.get("RFC822.SIZE");

    // Already built, above, from the windows the snippet passes returned. A row
    // with no window, no resolved part, or nothing readable in either keeps its
    // place with an empty preview rather than being dropped.
    const preview = previews.get(row.uid) ?? "";

    messages.push({
      id: encodeMessageId({ mailbox, uidValidity, uid: row.uid }),
      uid: row.uid,
      unread: !isSeen(row.items.get("FLAGS") ?? null),
      internalDate: typeof internalDate === "string" ? internalDate : null,
      wireSizeBytes: typeof size === "string" ? Number(size) : 0,
      subject: parsed?.subject ?? null,
      fromName: parsed?.fromName ?? null,
      fromAddress: parsed?.fromAddress ?? null,
      snippet: preview,
      hasAttachments: row.hasAttachments,
    });
  }
  return messages;
}

/**
 * One snippet command per DISTINCT resolved part path AND window, and no more.
 *
 * This is the whole of D-20's cost claim. The natural implementation walks each
 * message's structure and fetches that message's snippet, which reads as "two
 * extra round trips" and is in fact two PER MESSAGE. Grouping collapses it back
 * to a small constant per PAGE, because almost every message resolves to `1` or
 * `1.1`.
 *
 * **The window is part of the key, and the cost claim has to say so.** A window
 * follows the resolved part's SUBTYPE (`windowOctetsFor`), and a single-part
 * `text/plain` message and a single-part `text/html` message both resolve to
 * path `1` — the commonest mixed page there is, and exactly what UAT check 2
 * measured at 20 HTML rows among 100. Those rows shared one command before
 * G-02-9a and take two after it. So the honest claim is: AT MOST ONE ADDITIONAL
 * COMMAND PER RESOLVED PATH THAT CARRIES BOTH SUBTYPES — bounded by the number
 * of distinct paths on a page, which is one or two in practice, and never one
 * per message. A stated, bounded, tested increment is what D-20 survives; an
 * unstated one is what it does not.
 *
 * A `Map`, so the command order is the order the groups first appeared —
 * deterministic, which is what lets an ordered command assertion be written
 * against it at all.
 *
 * A snippet command that fails is skipped rather than raised, in
 * `fetchWindowsByPath` below. The rows it would have filled keep their place
 * with an empty preview: losing a preview costs a reader a convenience, and
 * losing the page costs them their mail.
 */
async function fetchSnippetWindows(
  session: MailSession,
  rows: RowStructure[],
): Promise<Map<number, Uint8Array>> {
  const groups = new Map<string, WindowGroup>();
  for (const row of rows) {
    if (row.textPart === null) continue;
    groupBy(groups, row.textPart, row.uid);
  }
  return fetchWindowsByPath(session, groups);
}

/**
 * One grouped fetch's worth of rows: where to read, how far, and for whom.
 *
 * The path and the window travel TOGETHER rather than as two parallel maps,
 * because they are two halves of one command and a call site holding them
 * separately is one that can pair a path with the wrong window.
 */
interface WindowGroup {
  path: string;
  octets: number;
  uids: number[];
}

/**
 * Add one identifier to its group, creating the group on first sight.
 *
 * Takes the resolved PART rather than its path, and derives both halves of the
 * key here through `windowOctetsFor`. Neither call site gets the chance to
 * choose a window, so neither can choose the wrong one — the same structural
 * move `snippetFromPart` made in 02-16, for the same reason.
 */
function groupBy(
  groups: Map<string, WindowGroup>,
  part: BodyPart,
  uid: number,
): void {
  const path = part.path;
  const octets = windowOctetsFor(part);
  const key = `${octets}:${path}`;
  const group = groups.get(key);
  if (group === undefined) groups.set(key, { path, octets, uids: [uid] });
  else group.uids.push(uid);
}

/**
 * One partial fetch per grouped path-and-window, and the windows it returned.
 *
 * The command construction lives HERE and nowhere else, so both snippet passes
 * write literally the same command shape: the same item builder, therefore the
 * same peeking form (D-47, CLAUDE.md §5). A second pass composing its own fetch
 * item is how one of them quietly acquires a non-peeking spelling and marks a
 * page read.
 *
 * The window size now travels WITH the path in the group rather than being a
 * constant this function reaches for. That is what lets 02-17's recovery fetch
 * its HTML sibling at the escalated window without this function knowing which
 * pass called it: the window is a property of the TARGET part, not of the pass.
 */
async function fetchWindowsByPath(
  session: MailSession,
  groups: Map<string, WindowGroup>,
): Promise<Map<number, Uint8Array>> {
  const windows = new Map<number, Uint8Array>();
  for (const { path, octets, uids } of groups.values()) {
    const result = await sendCommand(
      session.channel,
      session.channel.nextTag(),
      `UID FETCH ${uids.join(",")} ${snippetItems(path, octets)}`,
    );
    if (result.status !== "OK") continue;

    for (const [uid, items] of fetchReplies(result.untagged)) {
      // The reply key is spelled without the peek, and its partial-fetch origin
      // marker has already been stripped at the parse site — see ORIGIN_MARKER.
      // The WINDOW SIZE never appears in the reply key either: a server echoes
      // the section and the origin, never the requested length, so escalating
      // the window changes what is looked up not at all.
      const window = items.get(`BODY[${path}]`);
      if (window instanceof Uint8Array) windows.set(uid, window);
    }
  }

  return windows;
}

/**
 * Every row's finished preview: the grouped snippet fetch, then AT MOST one
 * bounded recovery pass for the rows that came back with nothing readable.
 *
 * **Why a second pass exists at all.** `selectTextPart` resolves the readable
 * part from `BODYSTRUCTURE`, where no body bytes have been fetched and content
 * is invisible, so a blank `text/plain` placeholder wins on presence over the
 * populated HTML part beside it. Two real messages on this account do exactly
 * that, and their previews came back empty (G-02-3b, UAT check 2 — uid 184545
 * and uid 184504, which the UAT read as "image-only marketing mail with no
 * extractable text part"; that reading is wrong, and this is the real cause).
 * Neither the content gate in `extractMessage` nor the conversion in
 * `snippetFromPart` can reach it: both run on whichever part was ALREADY
 * chosen. Only a caller holding the decoded window knows the choice was empty.
 *
 * **The recovery is evidence-based, and that is the whole of its cost claim.**
 * It fires on an observed empty preview, never on a guessed size threshold, so
 * a page whose every window carries text issues ZERO additional commands and
 * costs byte for byte what it costs today. When it does fire, the affected rows
 * are grouped by their sibling's path exactly as the first pass groups, so the
 * realistic worst case is ONE additional command for the page rather than one
 * per message — which is D-20's cost model preserved rather than traded away
 * (T-02-49). Every session is a socket and every command is serialised on it.
 *
 * **It runs once and never re-enters.** No retry, no loop, no second recovery
 * of a recovered window: after this pass the preview is whatever it is. A
 * bounded cost that can re-enter is an unbounded cost with extra steps.
 */
async function pagePreviews(
  session: MailSession,
  rows: RowStructure[],
): Promise<Map<number, string>> {
  const windows = await fetchSnippetWindows(session, rows);

  const previews = new Map<number, string>();
  /** The rows to recover, and the part each one's second window will hold. */
  const fallbacks = new Map<number, BodyPart>();
  const groups = new Map<string, WindowGroup>();

  for (const row of rows) {
    const part = row.textPart;
    if (part === null) continue;

    const window = windows.get(row.uid);
    const preview =
      window === undefined ? "" : await snippetFromPart(window, part);
    if (hasReadableText(preview)) {
      previews.set(row.uid, preview);
      continue;
    }

    // Nothing readable came back. The sibling lookup goes through the MIME
    // module rather than through path arithmetic here — a call site deriving
    // `1.2` from `1.1` by string surgery is exactly the fragility `parentPath`
    // and `childrenOf` exist to prevent.
    const sibling = htmlAlternativeOf(row.parts, part);
    // No alternative to try: the empty preview stands, which is the correct
    // outcome for a message with nothing previewable in it.
    if (sibling === null) continue;

    fallbacks.set(row.uid, sibling);
    // The SIBLING is grouped, not the part that came back blank — so the
    // recovery inherits the sibling's window, which for an HTML alternative is
    // the escalated one. That is not a detail: uid 184545 still previewed empty
    // after 02-17 shipped this recovery, because the second fetch reached only
    // 1024 octets into an HTML part whose prose begins past its style block
    // (G-02-9a, UAT check 9 — its full fetch returns prose, its listing row did
    // not). The window is a property of the TARGET part, never of the pass.
    groupBy(groups, sibling, row.uid);
  }

  if (groups.size === 0) return previews;

  const recovered = await fetchWindowsByPath(session, groups);
  // Only the rows that fell back are overwritten, and only with what the second
  // window actually decoded to. A row whose recovery also came back blank keeps
  // its empty preview.
  for (const [uid, part] of fallbacks) {
    const window = recovered.get(uid);
    if (window === undefined) continue;
    previews.set(uid, await snippetFromPart(window, part));
  }

  return previews;
}

/**
 * Resolve the caller's cursor, or refuse it, before any socket is opened.
 *
 * The mailbox check lives here rather than inside the session for the reason
 * the fetch tool decodes its identifier before connecting: a cursor minted for
 * another folder is refusable without spending a connection, and a refusal that
 * costs nothing is the one worth having. It also refuses a token of the wrong
 * KIND — a message id handed where a position belongs names one message rather
 * than a place in a list — because `decodeCursor` checks the discriminator
 * before it reads a field.
 *
 * The VALIDITY check is deliberately NOT here, and cannot be: the mailbox's
 * current validity is something only the server can state. That comparison runs
 * in `withMailSessionOver`, after the mailbox is opened and before any fetch is
 * written, which is what makes "no fetch precedes the refusal" a property of
 * the orchestrator rather than of each caller.
 */
function resolveCursor(
  mailbox: string,
  token: string | undefined,
): PageCursor | null {
  if (token === undefined) return null;
  const cursor = decodeCursor(token);
  // Refuse rather than repair, and say nothing about why. Answering a
  // foreign-folder cursor against the requested mailbox would return the wrong
  // messages under right-looking identifiers, which is worse than any error.
  if (cursor.mailbox !== mailbox) throw new ImapNotFoundError();
  return cursor;
}

/** No filters at all — what a plain listing asks for. */
const NO_CRITERIA: SearchCriteria = {};

/** The one added key that turns the shared page implementation into MAIL-05. */
const UNREAD_ONLY: SearchCriteria = { unreadOnly: true };

/**
 * The mailbox both search and the unread listing fall back to.
 *
 * `INBOX` is the one mailbox name RFC 3501 mandates: "The special name INBOX is
 * included in the output from LIST" and it is case-insensitive. So this is not
 * the model constructing a wire name — the thing D-18's opaque folder tokens
 * exist to prevent — it is the one name the protocol itself guarantees.
 */
export const DEFAULT_MAILBOX = "INBOX";

/**
 * Refuse a term that cannot be sent, before a byte reaches the wire.
 *
 * A NUL is the only character with no representation on either path: `CHAR8 =
 * %x01-ff` excludes it from a literal, and it is outside the quotable range
 * too. Refusing it here — at the boundary, before any socket is opened — gives
 * the caller a real answer rather than a protocol error, and costs nothing.
 *
 * CR and LF deliberately need no handling. They are legal inside a literal,
 * which is precisely what literals are for, so unlike on the credential path
 * there is nothing to refuse.
 *
 * The dates are parsed here for their side effect: a malformed one refuses at
 * the same boundary rather than several round trips later.
 */
function assertSearchable(criteria: SearchCriteria): void {
  for (const term of [criteria.keyword, criteria.sender]) {
    if (term !== undefined && term.includes("\u0000")) {
      throw new ImapNotFoundError();
    }
  }
  if (criteria.startDate !== undefined) parseIsoDay(criteria.startDate);
  if (criteria.endDate !== undefined) parseIsoDay(criteria.endDate);
}

/** List one page of a folder over an already-open stream pair. */
export async function listMessagesOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  options: ListMessagesOptions = {},
): Promise<MessagePage> {
  const cursor = resolveCursor(mailbox, options.cursor);
  const pageSize = clampPageSize(options.pageSize);

  return withMailSessionOver(
    duplex,
    principal,
    gate,
    mailbox,
    cursor?.uidValidity ?? null,
    (session) => fetchPage(session, mailbox, cursor, pageSize, NO_CRITERIA),
    options,
  );
}

/**
 * List one page of a folder in iCloud.
 *
 * The cursor's own UIDVALIDITY is what the session gate compares against, so a
 * page continued across a mailbox renumbering is REFUSED rather than silently
 * restarted from page one (D-23). Refusing is the only shape that literally
 * satisfies "forces a re-list rather than trusting stale identifiers": a silent
 * restart answers a question the caller did not ask, and a model that missed
 * the change would believe it was still paging.
 */
export async function listMessages(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  options: ListMessagesOptions = {},
): Promise<MessagePage> {
  const cursor = resolveCursor(mailbox, options.cursor);
  const pageSize = clampPageSize(options.pageSize);

  return withMailSession(
    principal,
    gate,
    mailbox,
    cursor?.uidValidity ?? null,
    (session) => fetchPage(session, mailbox, cursor, pageSize, NO_CRITERIA),
    options,
  );
}

/** Search one page of a folder over an already-open stream pair. */
export async function searchMessagesOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  criteria: SearchCriteria,
  options: ListMessagesOptions = {},
): Promise<SearchPage> {
  assertSearchable(criteria);
  const cursor = resolveCursor(mailbox, options.cursor);
  const pageSize = clampPageSize(options.pageSize);

  return withMailSessionOver(
    duplex,
    principal,
    gate,
    mailbox,
    cursor?.uidValidity ?? null,
    (session) => fetchPage(session, mailbox, cursor, pageSize, criteria),
    options,
  );
}

/**
 * Search one folder in iCloud (MAIL-04).
 *
 * **One folder, and the folder is a parameter rather than a sweep.** IMAP's
 * search is per-mailbox and needs the mailbox open, so an account-wide search
 * would be one mailbox open plus one search PER FOLDER, serialised on the one
 * connection this project permits, against a twenty-second call deadline
 * (D-27, T-02-07). One folder is predictable in cost and matches how mail
 * actually lives; the caller names another folder when it wants one.
 *
 * The term validation and the cursor decode both run BEFORE the socket is
 * opened, so a NUL in a term, a malformed date, or a cursor minted for another
 * folder all refuse without spending any of the connection budget.
 *
 * Everything else — the page implementation, the ordering, the cursor contract,
 * the validity gate — is the listing's, unchanged. A search result is a listing
 * with filters, and the two must not be able to drift apart.
 */
export async function searchMessages(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  criteria: SearchCriteria,
  options: ListMessagesOptions = {},
): Promise<SearchPage> {
  assertSearchable(criteria);
  const cursor = resolveCursor(mailbox, options.cursor);
  const pageSize = clampPageSize(options.pageSize);

  return withMailSession(
    principal,
    gate,
    mailbox,
    cursor?.uidValidity ?? null,
    (session) => fetchPage(session, mailbox, cursor, pageSize, criteria),
    options,
  );
}

/** One mailbox's validity, and every UID in it since a day. */
export interface WindowUids {
  readonly uidValidity: number;
  readonly uids: number[];
}

/**
 * The window's UID snapshot, inside an open session (Phase 26, D-17b, D-19).
 *
 * The search is the listing's own private search with no cursor and a start
 * day only, so the command is built by the one builder the listing uses and no
 * second search spelling exists. A charset refusal cannot happen on a date-only
 * search, because no term is sent; if one ever arrives it is reported as
 * not-found rather than as an empty mailbox, since an empty snapshot would tell
 * the reconcile to remove everything.
 */
async function windowUidsIn(session: MailSession, sinceDay: string): Promise<WindowUids> {
  const uidValidity = session.uidValidity;
  if (uidValidity === null) throw new ImapNotFoundError();
  const found = await searchPage(session, null, { startDate: sinceDay });
  if (found.unsupportedCharset) throw new ImapNotFoundError();
  return { uidValidity, uids: [...new Set(found.identifiers)] };
}

/** The window's UID snapshot over an already-open stream pair. */
export async function windowUidsOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  sinceDay: string,
  options: MailSessionOptions = {},
): Promise<WindowUids> {
  parseIsoDay(sinceDay);
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    mailbox,
    null,
    (session) => windowUidsIn(session, sinceDay),
    options,
  );
}

/**
 * Every UID in `mailbox` received on or after `sinceDay` (`YYYY-MM-DD`), and
 * the mailbox's UIDVALIDITY (Phase 26, D-17b).
 *
 * This is the snapshot the recall reconcile compares the person's ledger
 * against. It is bounded to the retention window, because a vector outside the
 * window is expiring anyway, and removing one early is the privacy-safe
 * direction. One read-only open and one search, in one session, and no fetch at
 * all, so nothing is read and nothing can be marked read.
 *
 * A malformed day is refused before any socket is opened.
 */
export async function windowUids(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  sinceDay: string,
  options: MailSessionOptions = {},
): Promise<WindowUids> {
  parseIsoDay(sinceDay);
  return withMailSession(
    principal,
    gate,
    mailbox,
    null,
    (session) => windowUidsIn(session, sinceDay),
    options,
  );
}

/** One page of new mail in a UID range, and where the next page starts. */
export interface RangePage {
  /** The listing's own rows, oldest first. */
  readonly rows: MessageSummary[];
  /**
   * The first UID not yet read. The last UID this page chose plus one when
   * more remained in the range; otherwise the range's exclusive upper end.
   */
  readonly nextFrom: number;
}

/** Whether `uid` can be a message UID: a safe integer of at least 1. */
function isUidValue(uid: number): boolean {
  return Number.isSafeInteger(uid) && uid >= 1;
}

/**
 * The oldest page of `[fromUid, toUidExclusive)`, inside an open session.
 *
 * The search is the one bounded range search; the rows are the listing's own
 * row builder. Chosen oldest first and at most `PAGE_SIZE_DEFAULT`, so a caller
 * that stores `nextFrom` moves past exactly the UIDs this page chose.
 */
async function summariesInRangeIn(
  session: MailSession,
  mailbox: string,
  fromUid: number,
  toUidExclusive: number,
): Promise<RangePage> {
  const uidValidity = session.uidValidity;
  if (uidValidity === null) throw new ImapNotFoundError();

  const found = await uidsInRange(session, fromUid, toUidExclusive);
  const ordered = [...found].sort((a, b) => a - b);
  const page = ordered.slice(0, PAGE_SIZE_DEFAULT);
  if (page.length === 0) return { rows: [], nextFrom: toUidExclusive };

  const nextFrom = ordered.length > page.length ? page[page.length - 1]! + 1 : toUidExclusive;
  const rows = await summaryRows(session, mailbox, uidValidity, page);
  return { rows, nextFrom };
}

/**
 * Refuse a range whose ends are not UIDs, before any socket. Answers true when
 * the range is empty, so the caller can answer at once with no session.
 */
function emptyRange(fromUid: number, toUidExclusive: number): boolean {
  if (!isUidValue(fromUid) || !isUidValue(toUidExclusive)) throw new ImapNotFoundError();
  return toUidExclusive <= fromUid;
}

/** New mail in a UID range, oldest first, over an already-open stream pair. */
export async function summariesInRangeOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  uidValidity: number,
  fromUid: number,
  toUidExclusive: number,
  options: MailSessionOptions = {},
): Promise<RangePage> {
  if (emptyRange(fromUid, toUidExclusive)) return { rows: [], nextFrom: fromUid };
  return withMailSessionOver(
    duplex,
    principal,
    gate,
    mailbox,
    uidValidity,
    (session) => summariesInRangeIn(session, mailbox, fromUid, toUidExclusive),
    options,
  );
}

/**
 * New mail in `[fromUid, toUidExclusive)`, oldest first, as the listing's own
 * rows (Phase 26, D-16).
 *
 * OLDEST FIRST, so a caller that stores `nextFrom` moves forward past exactly
 * what it read, and a burst larger than one page is read over several calls
 * with nothing skipped.
 *
 * BOUNDED AT BOTH ENDS, for the reason Phase 23 D-18 gives: the open-ended form
 * always takes in the newest message and anything that arrived after the
 * status reply. The upper end is the status reply's next UID minus one.
 *
 * THE LISTING'S OWN ITEMS. The rows are built by the listing's row builder, so
 * every fetch item is the peeking one and no fetch item is added. The folder is
 * opened read-only through the orchestrator with `uidValidity` as the expected
 * validity, so a folder whose validity moved is refused before any search.
 *
 * An empty range opens no socket. A range whose ends are not UIDs is refused
 * before any socket.
 */
export async function summariesInRange(
  principal: Principal,
  gate: SessionGate,
  mailbox: string,
  uidValidity: number,
  fromUid: number,
  toUidExclusive: number,
  options: MailSessionOptions = {},
): Promise<RangePage> {
  if (emptyRange(fromUid, toUidExclusive)) return { rows: [], nextFrom: fromUid };
  return withMailSession(
    principal,
    gate,
    mailbox,
    uidValidity,
    (session) => summariesInRangeIn(session, mailbox, fromUid, toUidExclusive),
    options,
  );
}

/** List one page of a folder's unread mail over an already-open stream pair. */
export async function listUnreadOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string = DEFAULT_MAILBOX,
  options: ListMessagesOptions = {},
): Promise<MessagePage> {
  return searchMessagesOver(duplex, principal, gate, mailbox, UNREAD_ONLY, options);
}

/**
 * List one page of a folder's unread mail (MAIL-05).
 *
 * **One added search key, and nothing else.** D-17 gave this its own tool name
 * because a search buried as a parameter is a search the model reaches for
 * less — but that decision was about the tool SURFACE, and it says in the same
 * breath that this "shares the list implementation internally rather than
 * duplicating it". A second paging implementation is how the two drift, and it
 * would drift in the ordering and the cursor arithmetic, which are the parts
 * nobody re-reads. There is exactly one of each, one function down.
 *
 * The intersection is also what makes paging correct with no extra machinery: a
 * message that becomes read between two pages simply stops matching the unread
 * key, so it drops out with no duplicate and no skip.
 *
 * **This does NOT sweep the account, and the omission is deliberate.** An
 * account-wide unread list is the more useful reading of MAIL-05 on its face,
 * and it was still not built: IMAP's search is per-mailbox and needs the
 * mailbox open, so a sweep is one mailbox open plus one search PER FOLDER,
 * serialised on the single connection this project permits, against a
 * twenty-second call deadline — the same cost shape D-27 declined for search
 * (T-02-07). The concurrent version is not an escape either: the request-scoped
 * gate refuses a second session at runtime and `scripts/forbidden-tokens.mjs`
 * refuses a fan-out at commit time, both by design.
 *
 * If a sweep is ever wanted, the shape to add is an explicit flag kept SERIAL,
 * with the folder count bounded — not a fan-out, and not a silent default.
 */
export async function listUnread(
  principal: Principal,
  gate: SessionGate,
  mailbox: string = DEFAULT_MAILBOX,
  options: ListMessagesOptions = {},
): Promise<MessagePage> {
  return searchMessages(principal, gate, mailbox, UNREAD_ONLY, options);
}

// ---------------------------------------------------------------------------
// The draft write (DRAFT-02, DRAFT-04, criterion 2)
//
// The first non-read command this project has ever issued, and the only one it
// will ever issue: PROJECT.md's boundary is that a draft reaches the Drafts
// folder this way and that this is the entire write path. There is no send
// path, now or later, and `./.claude/CLAUDE.md` § 2 records why that human step
// is a safety property rather than a scope decision.
//
// The command's own construction lives in `appendCommand` below, whose shape is
// copied from `searchKeys` one section up: fragments and literals, with the
// trailing empty fragment carrying the terminating CRLF. `sendWithLiterals`
// needs no change of any kind to serve it, and remains module-private — its
// contract includes "a rejection is RETURNED, not raised", and widening that
// subtle interface for one call site would be the larger change.
//
// **What makes this section's failures different from every other section's:**
// a read that goes wrong returns nothing, or the wrong thing, and is visible.
// A write that goes wrong here returns a tagged OK. PITFALLS #8 is the entry,
// and its whole point is that a missing flag, a blank message id, a bare
// newline or an undercounted literal all succeed. That is why the assertions in
// `test/append.test.ts` are on the recorded bytes and their order.
// ---------------------------------------------------------------------------

/**
 * The flag list every draft is written with.
 *
 * **The backslashes are load-bearing and are the first thing to check when a
 * draft does not appear as a draft.** A template literal that lost one produces
 * a syntactically valid flag list naming a KEYWORD flag rather than a system
 * flag, and the server accepts it without complaint — PITFALLS #8 names exactly
 * this as its first failure mode, and it returns success.
 *
 * **The seen flag is included deliberately, and it does NOT violate Convention
 * 5.** That convention is about reading someone's mail without marking it read;
 * nothing here reads anything. This is a message this server is creating, and
 * the client marks its own locally-composed drafts seen, so a draft appearing
 * bold-unread in the user's own list is cosmetically wrong for no reason. A
 * later reader will otherwise read this as a violation, which is why it is
 * written down rather than left to be inferred.
 *
 * The claim about the client's own unread treatment is ASSUMED rather than
 * measured, and it is a check on this phase's UAT record.
 */
export const DRAFT_APPEND_FLAGS = "(\\Draft \\Seen)";

/** The response code carrying the destination's two identifiers. */
const APPEND_IDENTIFIERS = /\[APPENDUID (\d+) (\d+)\]/i;

/**
 * Read the two identifiers out of a tagged completion, if it carried them.
 *
 * **Absent is handled as absent, never as an error**, and that is the whole
 * subtlety of this function. RFC 4315 does not use MUST: it permits omission
 * for a mailbox whose identifiers are not sticky, and says a server SHOULD NOT
 * send the code when the client cannot select the target. The write succeeded
 * either way, so `null` is an ordinary outcome and the caller must not fail on
 * it — it simply means the draft cannot be named in the response.
 *
 * Nothing else in this repository parses a response code off a tagged line;
 * `parseTaggedResponse` yields tag, status and text and stops there. So this is
 * a new, pure, trivially-testable function rather than a use of existing
 * machinery.
 *
 * Both numbers go through the identifier layer's own bound rather than a
 * restatement of it. A value above the unsigned 32-bit ceiling cannot name
 * anything, and minting a token from one would fail inside that token's own
 * decoder — arbitrarily far from here, against a value that by then looks like
 * the model's fault.
 */
export function parseAppendUid(
  taggedText: string,
): { uidValidity: number; uid: number } | null {
  const match = APPEND_IDENTIFIERS.exec(taggedText);
  if (match === null) return null;

  const uidValidity = Number(match[1]);
  const uid = Number(match[2]);
  if (!isWireNumber(uidValidity) || !isWireNumber(uid)) return null;

  return { uidValidity, uid };
}

/**
 * Build the write command: one fragment, one literal, one empty fragment.
 *
 * A sibling of `searchKeys` in shape, and the trailing empty fragment is the
 * same device — it is what writes the terminating CRLF after the literal's
 * octets, so the whole handshake falls out of `sendWithLiterals` unchanged.
 *
 * THE count. It comes from the ENCODED array's `byteLength` and never from a
 * string's `.length`, and the two diverge on every non-ASCII input. Too small
 * and the server parses the tail of the message as new commands, against text a
 * stranger may have chosen; too large and it waits for octets that will never
 * arrive, holding the socket to the read bound. `searchKeys` calls this the one
 * place an off-by-one is silently catastrophic rather than merely wrong, and it
 * is more so here: the payload is longer and it carries a stranger's bytes.
 *
 * **No internal date is sent, and that is a decision.** The argument is
 * optional; the server's own clock is the honest answer for when a draft was
 * created; and the date-time production it would need is a DIFFERENT one from
 * the `date-text` `imapDate()` already emits for the search keys — so sending
 * one would mean a second date formatter for no gain and one more place to be
 * silently wrong.
 */
function appendCommand(
  tag: string,
  quotedMailbox: string,
  flags: string,
  message: Uint8Array,
): LiteralCommand {
  return {
    fragments: [
      `${tag} APPEND ${quotedMailbox} ${flags} {${message.byteLength}}`,
      "",
    ],
    literals: [message],
  };
}

/** Where a draft is going, and how that folder was decided. */
export interface AppendTarget {
  /** The wire mailbox name. Never display-decoded. */
  mailbox: string;
  /** The role this server resolved for it, or `null`. */
  role: FolderRole;
  /**
   * Which path resolved that role, or `null`.
   *
   * **This is the field D-30 was built for and this is the first write that
   * depends on it.** iCloud emits no special-use attribute for the drafts
   * folder — measured in phase 2 and re-confirmed since — so the target rests
   * on this client's own name ladder rather than on a statement by the server.
   * A caller cannot tell a heuristic match from a server-stated one without
   * being told, and on a write that difference is worth naming.
   */
  roleSource: RoleSource;
}

/**
 * What a write attempt established.
 *
 * The refusal arm is the shipped `unsupportedCharset` shape, applied to a size
 * rather than to a charset: the call SUCCEEDED and reports a stated reason, and
 * no fifth error category is invented for it. `not_found` would tell the model
 * the folder does not exist and `connection_failed` would tell it to retry
 * something that will fail identically — both are worse than false.
 *
 * The two identifiers are nullable on the success arm for the reason
 * `parseAppendUid` gives: a server may legitimately omit them, and the draft
 * was still written.
 */
export type AppendOutcome =
  | {
      appended: true;
      /** The destination's UIDVALIDITY, or `null` when it was not reported. */
      uidValidity: number | null;
      /** The identifier assigned to the draft, or `null`. */
      uid: number | null;
      /** The wire mailbox the draft landed in. */
      mailbox: string;
      /** The resolved role of that mailbox. */
      role: FolderRole;
      /** How that role was resolved. See `AppendTarget.roleSource`. */
      roleSource: RoleSource;
    }
  | {
      appended: false;
      refusal: "message-too-large";
      sizeBytes: number;
      limitBytes: number;
    };

/**
 * Refuse an oversized message before anything is opened.
 *
 * **Checked before the socket, which is the cheapest possible refusal and the
 * one that spends none of the connection budget.** The ceiling itself, and the
 * arithmetic under it, live beside the builder that produces the bytes — see
 * `MAX_APPEND_LITERAL_BYTES` in `./compose.ts`.
 */
function refuseOversize(message: Uint8Array): AppendOutcome | null {
  if (message.byteLength <= MAX_APPEND_LITERAL_BYTES) return null;

  return {
    appended: false,
    refusal: "message-too-large",
    sizeBytes: message.byteLength,
    limitBytes: MAX_APPEND_LITERAL_BYTES,
  };
}

/**
 * Refuse a caller-supplied folder name that cannot travel on a command line.
 *
 * **This check is not redundant with the session orchestrator's, and that is
 * the point.** `withMailSessionOver` quotes and refuses inside its
 * `mailbox !== null` branch — the branch this path deliberately skips, because
 * the write runs from the authenticated state with no mailbox open. So the
 * refusal has to be made here or it is not made at all, and a name carrying CR
 * or LF would terminate the command line early and inject a second command
 * built from the name's own bytes.
 *
 * Refuse rather than repair, on `./credentials.ts`'s argument transferred
 * whole: escaping around it would send a value the server rejects and would
 * point the investigation at the wrong thing.
 */
function assertQuotableMailbox(mailbox: string | null): void {
  if (mailbox !== null && quoteMailbox(mailbox) === null) {
    throw new ImapNotFoundError();
  }
}

/**
 * Decide which folder the draft goes to, from the listing the session just did.
 *
 * Two shapes, and neither lets the caller name a raw mailbox. With no folder
 * given, the target is whichever folder the shipped role ladder resolved as
 * drafts; with one given, it is that folder — but only if the server itself
 * listed it, so the value came from a `LIST` reply rather than from anything
 * constructed. D-18's rule, unbent: a name the model can read is a name the
 * model can construct, and a constructed wire name is invented one character
 * off.
 *
 * Neither resolving is `not_found` rather than a guess. Criterion 1 requires
 * the drafts folder be discovered rather than guessed, and a guess that happens
 * to be right is still a guess.
 */
function resolveAppendTarget(
  listing: FolderListing,
  mailbox: string | null,
): AppendTarget {
  const found =
    mailbox === null
      ? listing.folders.find((one) => one.role === "drafts")
      : listing.folders.find((one) => one.wireName === mailbox);

  if (found === undefined) throw new ImapNotFoundError();

  return {
    mailbox: found.wireName,
    role: found.role,
    roleSource: found.roleSource,
  };
}

/**
 * Write one draft inside an already-open session.
 *
 * The listing runs on the SAME conversation, immediately before the write. Both
 * commands are authenticated-state commands, so neither opens a mailbox and
 * neither needs a second session — which matters, because every session is a
 * socket and D-46's gate refuses a second one at runtime.
 *
 * **A refusal suggesting the folder be created is declined rather than acted
 * on, and it is not given a branch of its own because there is nothing
 * different to do.** RFC 3501 permits the server to answer a failed write with
 * a `NO` carrying a create-suggestion response code. Creating a mailbox is a
 * write this project has not authorised, and adding it would be a SECOND write
 * path arriving by accident, so the suggestion is ignored and the refusal is
 * reported as `not_found` like any other. A branch that tested for the code and
 * then did exactly what the general case does would be a rule that silently
 * matches nothing, which this codebase treats as worse than no rule.
 */
async function writeDraft(
  session: MailSession,
  mailbox: string | null,
  message: Uint8Array,
): Promise<AppendOutcome> {
  const target = resolveAppendTarget(await listAllFolders(session), mailbox);

  // On the RESOLVED name, which is the one that reaches the command line. The
  // caller-supplied name was already refused above; this is the server's own.
  const quoted = quoteMailbox(target.mailbox);
  if (quoted === null) throw new ImapNotFoundError();

  const tag = session.channel.nextTag();
  const result = await sendWithLiterals(
    session.channel,
    tag,
    appendCommand(tag, quoted, DRAFT_APPEND_FLAGS, message),
  );

  if (result.status !== "OK") throw new ImapNotFoundError();

  const identifiers = parseAppendUid(result.tagged.text);
  return {
    appended: true,
    uidValidity: identifiers?.uidValidity ?? null,
    uid: identifiers?.uid ?? null,
    mailbox: target.mailbox,
    role: target.role,
    roleSource: target.roleSource,
  };
}

/** Write one draft over an already-open stream pair. */
export async function appendDraftOver(
  duplex: DuplexLike,
  principal: Principal,
  gate: SessionGate,
  mailbox: string | null,
  message: Uint8Array,
  options: MailSessionOptions = {},
): Promise<AppendOutcome> {
  const refusal = refuseOversize(message);
  if (refusal !== null) return refusal;
  assertQuotableMailbox(mailbox);

  return withMailSessionOver(
    duplex,
    principal,
    gate,
    // No mailbox: both the listing and the write run from the authenticated
    // state, so nothing is opened and no validity gate runs. This is already
    // the shape the orchestrator takes and it needs no signature change — D-43
    // warns that changing that signature touches every mail call site.
    null,
    null,
    (session) => writeDraft(session, mailbox, message),
    options,
  );
}

/**
 * Write one draft to iCloud.
 *
 * **The bytes arrive finished.** They come from `buildDraft` in `./compose.ts`,
 * and nothing in this file assembles a message — the split is what keeps the
 * whole of RFC 5322 unit-testable against literal values with no socket, which
 * is where the coverage for a write path with silent failure modes belongs.
 *
 * The size is checked before the connection is spent, the folder name is
 * refused before a byte is written, and the target is resolved from the
 * server's own listing rather than from a name anyone constructed.
 */
export async function appendDraft(
  principal: Principal,
  gate: SessionGate,
  mailbox: string | null,
  message: Uint8Array,
  options: MailSessionOptions = {},
): Promise<AppendOutcome> {
  const refusal = refuseOversize(message);
  if (refusal !== null) return refusal;
  assertQuotableMailbox(mailbox);

  return withMailSession(
    principal,
    gate,
    null,
    null,
    (session) => writeDraft(session, mailbox, message),
    options,
  );
}

