// The IMAP conversation, driven end to end with no socket.
//
// Every case here attaches to the duck-typed stream pair the session operates
// on. Nothing opens a network connection and nothing authenticates against the
// real Apple ID — the live proof is a human-invoked step in a later plan, and
// the test environment offers no interception facility that would make an
// automated "integration test" anything other than a real login.

import { beforeAll, describe, expect, it } from "vitest";
import {
  ImapAuthError,
  ImapConnectError,
  ImapThrottleError,
  toErrorCategory,
} from "../src/errors";
import { runDiagnosticOver } from "../src/mail/diagnose";
import { diagnosticResult } from "../src/mcp/tools/diagnose";
import {
  CLOSE_TIMEOUT_MS,
  DRAIN_TIMEOUT_MS,
  ImapChannel,
  READ_TIMEOUT_MS,
  readGreeting,
  sendCommand,
  teardown,
} from "../src/mail/imap-session";
import {
  AUTH_REJECTED_LEGACY_TEXT,
  AUTH_REJECTED_TEXT,
  CONNECTION_LIMIT_TEXT,
  GREETING,
  GREETING_AT_CONNECTION_LIMIT,
  INBOX_EXISTS,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  taggedNo,
  taggedOk,
  untaggedFloodThenTagged,
  wire,
} from "./fixtures/icloud-bytes";
import {
  createFailingDuplex,
  createFakeDuplex,
  createNeverClosingDuplex,
  createRejectingCloseDuplex,
  createSilentPeerDuplex,
} from "./fixtures/fake-duplex";
import {
  FAKE_APP_PASSWORD,
  FAKE_APPLE_ID,
  ownerPrincipal,
} from "./fixtures/bound-secrets";
import type { Principal } from "../src/principal";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

/**
 * The injected bounds (D-51, WINDOWS.md ledger entry 9).
 *
 * Before these existed the four cases below spent roughly 20 s of wall time
 * genuinely waiting out real production bounds, and D-45's call deadline would
 * have made it a third such wait. Every one of them still fails the same way
 * under the same mutation — revert the bound and the case hangs to the runner
 * timeout — at roughly 1% of the cost.
 *
 * The production constants are NOT replaced. They stay the defaults, they keep
 * their calibration docstrings against the live proof, and the case below
 * asserts their values directly so a silent edit to one is still caught.
 */
const FAST_READ_MS = 40;
const FAST_DRAIN_MS = 40;
const FAST_CLOSE_MS = 40;
const FAST_TEARDOWN = {
  drainTimeoutMs: FAST_DRAIN_MS,
  closeTimeoutMs: FAST_CLOSE_MS,
};

/** The IMAP verb of each outbound line — the second token, after the tag. */
function commandWords(lines: string[]): string[] {
  return lines.map((line) => line.split(" ")[1] ?? "");
}

/** The tag of each outbound line — the first token. */
function commandTags(lines: string[]): string[] {
  return lines.map((line) => line.split(" ")[0]);
}

describe("the production bounds themselves", () => {
  it("are the calibrated values, not whatever a caller last injected", () => {
    // The cases below inject small bounds so the suite does not spend twenty
    // seconds re-measuring three constants. That trade is only safe while the
    // constants are still asserted somewhere, because an injectable bound is a
    // bound a future caller — or a future default — can set wrong, and the
    // calibration in each docstring is against the live proof rather than
    // against taste.
    expect(READ_TIMEOUT_MS).toBe(10000);
    expect(DRAIN_TIMEOUT_MS).toBe(2000);
    expect(CLOSE_TIMEOUT_MS).toBe(3000);
    // The stated two-step worst case for a whole teardown.
    expect(DRAIN_TIMEOUT_MS + CLOSE_TIMEOUT_MS).toBe(5000);
  });

  it("are what a channel and a teardown use when nothing is injected", async () => {
    // Proves the seam ADDED a parameter rather than replacing the constant: an
    // options bag whose defaults had drifted would leave every case above
    // passing while production ran on the wrong numbers.
    const duplex = createFakeDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
    );

    expect(result.closeOutcome).toBe("closed");
    expect(result.closeMs).toBeLessThan(DRAIN_TIMEOUT_MS);
  });
});

describe("readGreeting", () => {
  it("returns the first untagged line", async () => {
    const duplex = createFakeDuplex([GREETING]);
    const channel = new ImapChannel(duplex);

    await expect(readGreeting(channel)).resolves.toContain("* OK");
  });

  it("classifies a greeting that refuses on connection count", async () => {
    const duplex = createFakeDuplex([GREETING_AT_CONNECTION_LIMIT]);
    const channel = new ImapChannel(duplex);

    await expect(readGreeting(channel)).rejects.toBeInstanceOf(
      ImapThrottleError,
    );
  });

  it("gives up on a peer that establishes and then stalls without a greeting", async () => {
    // The connection-limit shape this project explicitly designs against: a
    // server at its ceiling completes the TCP and TLS handshake, then says
    // nothing and closes nothing. Before readLine had a deadline this blocked
    // forever, so the caller's `finally` never ran — no LOGOUT, no close() —
    // and the socket kept counting against the very ceiling that caused the
    // stall until the request was torn down externally.
    //
    // The bound is INJECTED (D-51, ledger entry 9). What this case proves is
    // that the deadline exists and fires; proving it fires at exactly ten
    // seconds would cost ten seconds of wall time on every run to re-measure a
    // constant, and the constant is asserted separately below. The assertion
    // stays discriminating in the way that matters: remove the bound and this
    // hangs to the runner timeout, exactly as it did at the production value.
    const duplex = createSilentPeerDuplex();
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });

    const startedAt = Date.now();
    await expect(readGreeting(channel)).rejects.toBeInstanceOf(ImapConnectError);
    expect(Date.now() - startedAt).toBeLessThan(FAST_READ_MS + 4000);
  });

  it("surfaces a duplex that rejects on open as a connection failure", async () => {
    // The injected-failure half of criterion 3's proof: an unreachable peer is
    // modelled at the transport seam, so nothing that deliberately misconnects
    // has to ship in the deployed Worker.
    const duplex = createFailingDuplex();
    const channel = new ImapChannel(duplex);

    await expect(readGreeting(channel)).rejects.toBeInstanceOf(
      ImapConnectError,
    );
  });
});

describe("sendCommand", () => {
  it("writes the tag and the command line, terminated", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    ]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    const result = await sendCommand(channel, "a1", "CAPABILITY");

    expect(duplex.writtenLines()).toEqual(["a1 CAPABILITY"]);
    expect(result.status).toBe("OK");
    // `.text` since Phase 2: a command result carries logical responses, not
    // raw lines, so a literal-bearing reply survives as one entry rather than
    // being shredded across several.
    expect(result.untagged.map((line) => line.text)).toEqual([
      `* CAPABILITY ${PRE_AUTH_CAPABILITY}`,
    ]);
  });

  it("reads through any number of untagged lines to reach its own tag", async () => {
    const duplex = createFakeDuplex([GREETING, untaggedFloodThenTagged("a1")]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    const result = await sendCommand(channel, "a1", "NOOP");

    expect(result.status).toBe("OK");
    expect(result.untagged).toHaveLength(4);
    expect(result.tagged.text).toBe("a1 OK completed");
    expect(result.tagged.literals).toEqual([]);
  });

  it("keeps distinct, incrementing tags across a multi-command exchange", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      untaggedFloodThenTagged("a2"),
      logoutExchange("a3"),
    ]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    await sendCommand(channel, "a1", "CAPABILITY");
    await sendCommand(channel, "a2", "NOOP");
    await sendCommand(channel, "a3", "LOGOUT");

    const tags = duplex.writtenLines().map((line) => line.split(" ")[0]);
    expect(tags).toEqual(["a1", "a2", "a3"]);
    expect(new Set(tags).size).toBe(tags.length);
  });
});

describe("teardown", () => {
  it("drains the readable to completion BEFORE calling close()", async () => {
    // Ordering, not co-occurrence. The runtime's `closed` promise resolves
    // only after the readable has been read to completion; that behaviour is
    // specified and intentional, so an implementation that closed first would
    // hang on every single call rather than intermittently.
    const duplex = createFakeDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
    );

    const drainedAt = duplex.firstIndexOf("readable-done");
    const closedAt = duplex.firstIndexOf("close");

    expect(drainedAt).toBeGreaterThanOrEqual(0);
    expect(closedAt).toBeGreaterThanOrEqual(0);
    expect(closedAt).toBeGreaterThan(drainedAt);

    expect(result.logoutOk).toBe(true);
    expect(result.closeOutcome).toBe("closed");
  });

  it("sends LOGOUT before draining", async () => {
    const duplex = createFakeDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex);
    await readGreeting(channel);

    await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
    );

    expect(duplex.writtenLines()).toEqual(["a1 LOGOUT"]);
    const logoutAt = duplex.events.findIndex(
      (event) => event.kind === "write" && event.line === "a1 LOGOUT",
    );
    expect(logoutAt).toBeLessThan(duplex.firstIndexOf("readable-done"));
  });

  it("resolves within the timeout when the closed promise never settles", async () => {
    // ONE of the two hang shapes: the readable ends normally and only
    // `closed` never settles. It reproduces on every call rather than
    // intermittently, so step 4's race is a genuine backstop rather than
    // defensive decoration.
    //
    // It is NOT the shape that made step 4 unreachable. Because this
    // fixture's readable *does* end, the drain always completes and the code
    // after it always runs — which is why this case asserts `readable-done`
    // fired, and why it could never have caught CR-02. The case below, on a
    // readable that never ends, is the one that covers that.
    const duplex = createNeverClosingDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const startedAt = Date.now();
    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
      FAST_TEARDOWN,
    );
    const elapsed = Date.now() - startedAt;

    expect(result.closeOutcome).toBe("timed-out");
    expect(result.logoutOk).toBe(true);
    // Under the injected bound this settles in tens of milliseconds. The
    // assertion is stated in absolute terms rather than as the bound plus a
    // slack figure, because the property worth pinning is that the whole case
    // costs well under a second — against the production 3000 ms constant it
    // could not, and reverting the injection is exactly the mutation that has
    // to fail here.
    expect(elapsed).toBeLessThan(1000);
    expect(elapsed).toBeLessThan(FAST_CLOSE_MS + 4000);
    // It still drained and still called close() — the timeout is the last
    // step, not a replacement for the first three.
    expect(duplex.firstIndexOf("readable-done")).toBeGreaterThanOrEqual(0);
    expect(duplex.firstIndexOf("close")).toBeGreaterThan(
      duplex.firstIndexOf("readable-done"),
    );
  });

  it("returns against a readable that never ends, reaching close() and the race", async () => {
    // The OTHER hang shape, and the one that actually mattered: a peer that
    // completed its handshake and then sent nothing and closed nothing. The
    // drain's `read()` never settles, so before this bound existed the loop
    // never exited, `teardown` never returned, and step 4's race was never
    // even constructed — the backstop was unreachable in the exact failure
    // its own docstring names.
    //
    // Deliberately no `readable-done` assertion: that event firing would mean
    // the readable ended, i.e. that this case is not reproducing the hang.
    const duplex = createSilentPeerDuplex();
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });

    // Step 1 is stubbed to fail immediately rather than driven through the
    // channel. Against a silent peer a real LOGOUT would sit out the whole read
    // bound first, and this case is about steps 2 through 4; that is also what
    // keeps the elapsed bound below meaningful.
    const startedAt = Date.now();
    const result = await teardown(
      duplex,
      channel.reader,
      async () => {
        throw new Error("the peer is silent; LOGOUT cannot complete");
      },
      FAST_TEARDOWN,
    );
    const elapsed = Date.now() - startedAt;

    expect(result.logoutOk).toBe(false);
    expect(elapsed).toBeLessThan(FAST_DRAIN_MS + FAST_CLOSE_MS + 4000);

    // Step 3 still ran. Giving up on the drain must fall through to close(),
    // not skip it.
    expect(duplex.firstIndexOf("close")).toBeGreaterThanOrEqual(0);
  });

  it("reports a fired backstop as a closeMs at or above the drain deadline", async () => {
    // `closeMs` is the independent cross-check on `closeOutcome`, and it is
    // retained for that reason rather than out of habit. Before ledger entry 5
    // was closed it was the ONLY thing separating a benign teardown from a
    // dangerous one, because the boolean it replaced mapped both to `false`;
    // the live proof recorded `closeMs: 0` (01-IMAP-PROOF.md section 5), which is
    // `sock.closed` rejecting immediately — no hang, no leak.
    //
    // Now that the outcome names itself, this case and the clean one below keep
    // asserting the timing separation anyway. Two fields agreeing is what makes
    // either trustworthy: an outcome value that had drifted away from its own
    // race arm would still have to lie about the clock to pass both.
    //
    // Under injected bounds the two states stay just as far apart — the
    // separation is between "at or above the drain deadline" and "well below
    // it", and scaling both ends of it changes neither side of the comparison.
    const duplex = createSilentPeerDuplex();
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });

    const result = await teardown(
      duplex,
      channel.reader,
      async () => {
        throw new Error("the peer is silent; LOGOUT cannot complete");
      },
      FAST_TEARDOWN,
    );

    expect(result.closeOutcome).toBe("timed-out");
    expect(result.closeMs).toBeGreaterThanOrEqual(FAST_DRAIN_MS);
  });

  it("reports a clean teardown as a closeMs well below the drain deadline", async () => {
    // The other direction of the same disambiguation: a well-behaved peer must
    // not produce a closeMs anywhere near the deadline, or the two states would
    // be indistinguishable again and the assertion above would prove nothing.
    const duplex = createFakeDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
      FAST_TEARDOWN,
    );

    expect(result.closeOutcome).toBe("closed");
    expect(result.closeMs).toBeLessThan(FAST_DRAIN_MS);
  });

  it("reports a rejecting closed promise as its own outcome, not as the hang", async () => {
    // The case the real server actually produced, and the entire point of
    // WINDOWS.md ledger entry 5. Under the old boolean this fixture and the
    // silent-peer one above both reported `false`, so the benign observed
    // teardown was indistinguishable from the runtime hang by anything except
    // a duration a reader had to know to consult.
    const duplex = createRejectingCloseDuplex([GREETING, logoutExchange("a1")]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
      FAST_TEARDOWN,
    );

    expect(result.closeOutcome).toBe("rejected");
    // It matches the live proof in every other respect: LOGOUT completed, the
    // close was immediate, and the backstop never engaged.
    expect(result.logoutOk).toBe(true);
    expect(result.closeMs).toBeLessThan(FAST_DRAIN_MS);
  });

  it("gives the rejecting close and the fired backstop DIFFERENT values", async () => {
    // The assertion a boolean could not make, stated directly rather than left
    // to be inferred from two cases that each pass in isolation. If a later
    // edit collapsed either arm of step 4's race back into the other — the
    // tempting one-line "widen the race to treat a rejection as clean" — every
    // other case in this file would still pass and this one would not.
    const rejecting = createRejectingCloseDuplex([GREETING, logoutExchange("a1")]);
    const rejectingChannel = new ImapChannel(rejecting, {
      readTimeoutMs: FAST_READ_MS,
    });
    await readGreeting(rejectingChannel);
    const rejected = await teardown(
      rejecting,
      rejectingChannel.reader,
      async (line) => (await sendCommand(rejectingChannel, "a1", line)).tagged.text,
      FAST_TEARDOWN,
    );

    const silent = createSilentPeerDuplex();
    const silentChannel = new ImapChannel(silent, {
      readTimeoutMs: FAST_READ_MS,
    });
    const timedOut = await teardown(
      silent,
      silentChannel.reader,
      async () => {
        throw new Error("the peer is silent; LOGOUT cannot complete");
      },
      FAST_TEARDOWN,
    );

    expect(rejected.closeOutcome).not.toBe(timedOut.closeOutcome);

    // And neither is the clean value, so the three are genuinely three rather
    // than a boolean wearing a third name.
    const clean = createFakeDuplex([GREETING, logoutExchange("a1")]);
    const cleanChannel = new ImapChannel(clean, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(cleanChannel);
    const closed = await teardown(
      clean,
      cleanChannel.reader,
      async (line) => (await sendCommand(cleanChannel, "a1", line)).tagged.text,
      FAST_TEARDOWN,
    );

    expect(
      new Set([
        closed.closeOutcome,
        rejected.closeOutcome,
        timedOut.closeOutcome,
      ]).size,
    ).toBe(3);
  });

  it("runs every step even when LOGOUT itself fails", async () => {
    // Each step is individually wrapped: a connection that cannot be closed
    // tidily is a fact to report, not a reason to abandon the remaining steps.
    const duplex = createFailingDuplex();
    const channel = new ImapChannel(duplex);

    const result = await teardown(
      duplex,
      channel.reader,
      async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
    );

    expect(result.logoutOk).toBe(false);
    expect(duplex.firstIndexOf("close")).toBeGreaterThanOrEqual(0);
    expect(typeof result.logoutMs).toBe("number");
    expect(typeof result.closeMs).toBe("number");
  });

  it("does not throw, whatever the transport does", async () => {
    const duplex = createFailingDuplex();
    const channel = new ImapChannel(duplex);

    await expect(
      teardown(
        duplex,
        channel.reader,
        async (line) => (await sendCommand(channel, "a1", line)).tagged.text,
      ),
    ).resolves.toBeTypeOf("object");
  });
});

describe("ImapChannel.withWriter", () => {
  it("converts a failure to acquire the writer, not just one raised while emitting", async () => {
    // getWriter() throws on an already-locked stream, and that is reachable
    // here because a releaseLock() failure is swallowed. Acquiring outside the
    // conversion boundary let the raw TypeError escape on the credential path.
    const duplex = createFakeDuplex([]);
    const channel = new ImapChannel(duplex);
    duplex.writable.getWriter(); // lock it out from under the channel

    await expect(
      channel.withWriter(async () => {
        throw new Error("emit must never run; acquisition already failed");
      }),
    ).rejects.toBeInstanceOf(ImapConnectError);
  });

  it("re-raises ImapAuthError unchanged rather than converting it", async () => {
    // The one exemption. A credential that is absent or malformed is permanent;
    // reporting it as connection_failed would tell the caller a retry is worth
    // trying. The error carries a fixed internal label and no constructor
    // argument, so re-raising it adds no credential-adjacent text.
    const channel = new ImapChannel(createFakeDuplex([]));

    await expect(
      channel.withWriter(async () => {
        throw new ImapAuthError();
      }),
    ).rejects.toBeInstanceOf(ImapAuthError);
  });

  it("still converts every other failure raised while emitting", async () => {
    const channel = new ImapChannel(createFakeDuplex([]));

    await expect(
      channel.withWriter(async () => {
        throw new TypeError("something the stream layer raised");
      }),
    ).rejects.toBeInstanceOf(ImapConnectError);
  });
});

describe("ImapChannel.nextTag", () => {
  it("hands out distinct, incrementing tags", () => {
    const channel = new ImapChannel(createFakeDuplex([]));

    const tags = [
      channel.nextTag(),
      channel.nextTag(),
      channel.nextTag(),
      channel.nextTag(),
    ];

    expect(tags).toEqual(["a1", "a2", "a3", "a4"]);
    expect(new Set(tags).size).toBe(tags.length);
  });

  it("gives each channel its own counter, so requests cannot share state", () => {
    const first = new ImapChannel(createFakeDuplex([]));
    const second = new ImapChannel(createFakeDuplex([]));

    first.nextTag();
    first.nextTag();

    expect(second.nextTag()).toBe("a1");
  });
});

describe("the authenticated conversation", () => {
  // Driven through the real diagnostic over an in-memory duplex. The Apple ID
  // and password below are the fakes bound for tests; the real Secrets exist
  // only in Cloudflare, and no automated command in this repository logs into
  // the real account.

  it("emits CAPABILITY, LOGIN, CAPABILITY, EXAMINE, LOGOUT in that order with distinct tags", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report, failed } = await runDiagnosticOver(duplex, principal, 1);

    const lines = duplex.writtenLines();
    expect(commandWords(lines)).toEqual([
      "CAPABILITY",
      "LOGIN",
      "CAPABILITY",
      "EXAMINE",
      "LOGOUT",
    ]);
    expect(commandTags(lines)).toEqual(["a1", "a2", "a3", "a4", "a5"]);
    // The read-only form, spelled out. SELECT would open the mailbox
    // read-write and let a diagnostic mutate the state it is meant to observe.
    expect(lines[3]).toBe('a4 EXAMINE "INBOX"');
    expect(failed).toBe(false);
    expect(report.authenticated).toBe(true);
    expect(report.authMechanism).toBe("LOGIN");
    expect(report.logoutOk).toBe(true);
    expect(report.closeOutcome).toBe("closed");
  });

  it("returns BOTH capability strings verbatim", async () => {
    // Capability lists changing after authentication is normal, specified
    // behaviour. Reading the list once, before authenticating, is a false
    // negative that a later phase's APPEND design would be built on.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.greetingCapability).toBe(PRE_AUTH_CAPABILITY);
    expect(report.postLoginCapability).toBe(POST_AUTH_CAPABILITY);
    expect(report.greetingCapability).not.toBe(report.postLoginCapability);
  });

  it("derives literalPlus from the post-authentication list, not the greeting", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.literalPlus).toBe(true);
  });

  it("reports literalPlus false when the greeting advertises it but the post-login list does not", async () => {
    // The reverse of the reported iCloud shape, asserted so the derivation is
    // pinned to the post-login string rather than merely agreeing with it.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", `${PRE_AUTH_CAPABILITY} LITERAL+`),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", PRE_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.greetingCapability).toContain("LITERAL+");
    expect(report.postLoginCapability).not.toContain("LITERAL+");
    expect(report.literalPlus).toBe(false);
  });

  it("carries six separately measured timings", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 42);

    expect(Object.keys(report.timings).sort()).toEqual([
      "closeMs",
      "connectMs",
      "examineMs",
      "loginMs",
      "logoutMs",
      "tlsHandshakeMs",
    ]);
    for (const value of Object.values(report.timings)) {
      expect(typeof value).toBe("number");
    }
    // Each stage is bracketed by its own clock reading rather than derived
    // from the others; the connect measurement is taken outside this function
    // and threaded in, which is why it survives verbatim.
    expect(report.timings.connectMs).toBe(42);
  });
});

describe("the read-only inbox stage (D-52)", () => {
  // 01-IMAP-PROOF.md § 4 records its 424 ms connect-through-close figure as a
  // LOWER BOUND precisely because Phase 1 never opened a mailbox. This stage is
  // the missing round trip, and these cases are what make the number real.

  it("opens the inbox with the read-only command, never the mutating one", async () => {
    // The property, not the spelling: a diagnostic exists to observe, and
    // SELECT would open the mailbox read-write — letting the tool whose whole
    // purpose is answering "is it iCloud, my credentials, or our code?" change
    // the state it was asked about.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    await runDiagnosticOver(duplex, principal, 1);

    const lines = duplex.writtenLines();
    expect(lines).toContain('a4 EXAMINE "INBOX"');
    expect(commandWords(lines)).not.toContain("SELECT");
    expect(lines.join("\n")).not.toContain("SELECT");
  });

  it("reports the validity and the message count the server actually sent", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report, failed } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(false);
    expect(report.inboxUidValidity).toBe(INBOX_UIDVALIDITY);
    expect(report.inboxMessageCount).toBe(INBOX_EXISTS);
    expect(typeof report.timings.examineMs).toBe("number");
  });

  it("does not corrupt a UIDVALIDITY above 2^31", async () => {
    // The value is unsigned 32-bit and the fixture's is RFC 3501's own worked
    // example, which exceeds 2^31. A signed-int assumption anywhere on this
    // path turns it negative silently.
    expect(INBOX_UIDVALIDITY).toBeGreaterThan(2 ** 31);

    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.inboxUidValidity).toBeGreaterThan(2 ** 31);
    expect(report.inboxUidValidity).toBe(INBOX_UIDVALIDITY);
  });

  it("keeps every earlier measurement when the inbox open is refused", async () => {
    // The point of the whole outcome shape: a diagnostic that discards its
    // measurements at the first problem is useless for the one job it has. A
    // refused open is also exactly the run where the earlier stages matter
    // most — they are what say the failure is the mailbox, not the login.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      taggedNo("a4", "[NONEXISTENT] Mailbox does not exist"),
      logoutExchange("a5"),
    ]);

    const { report, failed, error } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(true);
    expect(toErrorCategory(error).category).toBe("not_found");

    // Everything measured before the refusal survived it.
    expect(report.tlsEstablished).toBe(true);
    expect(report.authenticated).toBe(true);
    expect(report.authMechanism).toBe("LOGIN");
    expect(report.greetingCapability).toBe(PRE_AUTH_CAPABILITY);
    expect(report.postLoginCapability).toBe(POST_AUTH_CAPABILITY);
    expect(report.literalPlus).toBe(true);
    expect(typeof report.timings.loginMs).toBe("number");
    // Including the failed stage's own cost — recorded before the status was
    // even examined, because what it cost is a fact regardless of the answer.
    expect(typeof report.timings.examineMs).toBe("number");
    // And teardown still ran.
    expect(report.logoutOk).toBe(true);
    expect(report.closeOutcome).toBe("closed");
  });

  it("leaves the inbox fields null when the conversation never got that far", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.inboxUidValidity).toBeNull();
    expect(report.inboxMessageCount).toBeNull();
    expect(report.timings.examineMs).toBeNull();
  });

  it("reports a null validity rather than zero when the server omits the code", async () => {
    // The RFC is explicit: a missing UIDVALIDITY means the server does not
    // support unique identifiers. That is a fact worth seeing in a diagnostic,
    // and defaulting it to zero would report a working server.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      wire("* 7 EXISTS", "a4 OK [READ-ONLY] EXAMINE completed"),
      logoutExchange("a5"),
    ]);

    const { report, failed } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(false);
    expect(report.inboxUidValidity).toBeNull();
    expect(report.inboxMessageCount).toBe(7);
  });
});

describe("the authentication fallback", () => {
  it("retries exactly once with the SASL mechanism after a rejected LOGIN", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_LEGACY_TEXT),
      taggedOk("a3", "AUTHENTICATE completed"),
      capabilityResponse("a4", POST_AUTH_CAPABILITY),
      examineResponse("a5"),
      logoutExchange("a6"),
    ]);

    const { report, failed } = await runDiagnosticOver(duplex, principal, 1);

    const words = commandWords(duplex.writtenLines());
    expect(words.filter((word) => word === "LOGIN")).toHaveLength(1);
    expect(words.filter((word) => word === "AUTHENTICATE")).toHaveLength(1);
    expect(failed).toBe(false);
    expect(report.authenticated).toBe(true);
    expect(report.authMechanism).toBe("AUTHENTICATE PLAIN");
  });

  it("makes no third attempt when both mechanisms are rejected", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_LEGACY_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const { error } = await runDiagnosticOver(duplex, principal, 1);

    const words = commandWords(duplex.writtenLines());
    expect(words).toEqual(["CAPABILITY", "LOGIN", "AUTHENTICATE", "LOGOUT"]);
    expect(error).toBeInstanceOf(ImapAuthError);
  });

  it("maps a double rejection to the auth_failed category", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_LEGACY_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const { report, failed, error } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(true);
    expect(toErrorCategory(error).category).toBe("auth_failed");
    expect(report.authenticated).toBe(false);
    expect(report.authMechanism).toBeNull();
    expect(report.postLoginCapability).toBeNull();
    expect(report.literalPlus).toBeNull();
  });

  it("carries the server's own reply text, and nothing of the credential", async () => {
    // The distinction between a wrong password and a wrong username format is
    // otherwise invisible, and a log dive is not available under a credential
    // policy that forbids logging on this path. The text is Apple's — the
    // credential is in the command we sent, never in the reply.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_LEGACY_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.authFailureDetail).toBeTypeOf("string");
    expect(report.authFailureDetail).toContain(AUTH_REJECTED_LEGACY_TEXT);
    expect(report.authFailureDetail).toContain(AUTH_REJECTED_TEXT);

    // The non-vacuity guard. It used to be the presence assertion the fixture
    // ran over the two bindings; with the credentials now being the fixture's
    // own constants it is stated the same way every other containment case in
    // this file states it. `not.toContain("")` is true of every string.
    expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
    expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);

    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain(FAKE_APP_PASSWORD);
    expect(serialized).not.toContain(FAKE_APPLE_ID);
  });

  it("bounds the assembled detail, not merely each part of it", async () => {
    // Mirrors the module-private MAX_FAILURE_DETAIL. Kept private there because
    // nothing outside the module has any business reading it; duplicated here
    // rather than exported so that changing the bound stays a deliberate
    // two-place edit rather than something a test silently ratifies.
    const MAX_FAILURE_DETAIL = 200;

    const longRejection = `[AUTHENTICATIONFAILED] ${"verbose ".repeat(40)}`;
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", longRejection),
      taggedNo("a3", longRejection),
      logoutExchange("a4"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    // Truncating per part left the real ceiling at roughly twice the constant
    // plus label text, so a per-part bound would sail past this.
    expect(report.authFailureDetail?.length).toBeLessThanOrEqual(
      MAX_FAILURE_DETAIL,
    );
    // And it truncated rather than simply being handed something short.
    expect(longRejection.length * 2).toBeGreaterThan(MAX_FAILURE_DETAIL);
  });

  it("leaves authFailureDetail null on a successful authentication", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.authFailureDetail).toBeNull();
  });
});

describe("failure categories, proven by injection", () => {
  it("maps a connection-count refusal to rate_limited, without retrying", async () => {
    // Retrying against a server that is already refusing on connection count
    // is the behaviour most likely to turn a temporary refusal into a lockout
    // of the user's own mail on their own devices.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", CONNECTION_LIMIT_TEXT),
      logoutExchange("a3"),
    ]);

    const { failed, error } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(true);
    expect(error).toBeInstanceOf(ImapThrottleError);
    expect(toErrorCategory(error).category).toBe("rate_limited");
    expect(commandWords(duplex.writtenLines())).not.toContain("AUTHENTICATE");
  });

  it("carries the server's own refusal text through to the tool response", async () => {
    // WINDOWS.md ledger entry 6. The refusal used to reach the caller as a
    // fixed message with the evidence discarded — which mattered precisely
    // because this server has never returned a throttle response in any
    // observed run, so the first real one is the only sample there will be.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", CONNECTION_LIMIT_TEXT),
      logoutExchange("a3"),
    ]);

    const outcome = await runDiagnosticOver(duplex, principal, 1);

    // It reached the report from the parsed reply...
    expect(outcome.report.throttleFailureDetail).toBe(CONNECTION_LIMIT_TEXT);
    // ...and it crossed the tool boundary in a field of its own, distinct from
    // the authentication one, so the response is unambiguous about which
    // refusal it is reporting.
    const body = JSON.parse(
      diagnosticResult(outcome).content[0]!.text,
    ) as Record<string, unknown>;

    expect(body.category).toBe("rate_limited");
    expect(body.throttleFailureDetail).toBe(CONNECTION_LIMIT_TEXT);
    expect("authFailureDetail" in body).toBe(false);
  });

  it("carries a refusal that arrives in the greeting, before any command", async () => {
    // The third raise site, and the asymmetric one: a greeting refusal is an
    // untagged farewell, so its text comes from the line itself rather than
    // from a parsed tagged reply — there is no tagged completion in existence
    // yet to parse.
    const duplex = createFakeDuplex([GREETING_AT_CONNECTION_LIMIT]);

    const outcome = await runDiagnosticOver(duplex, principal, 1);

    expect(outcome.error).toBeInstanceOf(ImapThrottleError);
    expect(outcome.report.throttleFailureDetail).toContain("Too many");
    expect(outcome.report.throttleFailureDetail).toContain("* BYE");
    expect(outcome.report.authFailureDetail).toBeNull();
  });

  it("bounds the refusal text with the same cap the auth path uses", async () => {
    // Mirrors the module-private MAX_FAILURE_DETAIL, duplicated here for the
    // same reason the auth-path case duplicates it: changing the bound stays a
    // deliberate two-place edit rather than something a test silently ratifies.
    const MAX_FAILURE_DETAIL = 200;

    const verbose = `[UNAVAILABLE] Too many ${"simultaneous ".repeat(40)}`;
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", verbose),
      logoutExchange("a3"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.throttleFailureDetail?.length).toBe(MAX_FAILURE_DETAIL);
    // And it truncated rather than being handed something already short.
    expect(verbose.length).toBeGreaterThan(MAX_FAILURE_DETAIL);
    // Verbatim up to the cut, with nothing normalised on the way through.
    expect(report.throttleFailureDetail).toBe(
      verbose.slice(0, MAX_FAILURE_DETAIL),
    );
  });

  it("leaves the refusal text null when nothing was throttled", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      examineResponse("a4"),
      logoutExchange("a5"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(report.throttleFailureDetail).toBeNull();
  });

  it("never leaks a credential fragment through the refusal text", async () => {
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", CONNECTION_LIMIT_TEXT),
      logoutExchange("a3"),
    ]);

    const outcome = await runDiagnosticOver(duplex, principal, 1);

    expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
    expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);

    for (const serialized of [
      JSON.stringify(diagnosticResult(outcome)),
      JSON.stringify(outcome.report),
    ]) {
      expect(serialized).not.toContain(FAKE_APP_PASSWORD);
      expect(serialized).not.toContain(FAKE_APPLE_ID);
    }
  });

  it("maps a duplex that rejects on open to connection_failed", async () => {
    const duplex = createFailingDuplex();

    const { report, failed, error } = await runDiagnosticOver(duplex, principal, 1);

    expect(failed).toBe(true);
    expect(error).toBeInstanceOf(ImapConnectError);
    expect(toErrorCategory(error).category).toBe("connection_failed");
    expect(report.tlsEstablished).toBe(false);
    expect(report.authenticated).toBe(false);
  });

  it("closes the connection even when the conversation fails part-way", async () => {
    // A leaked connection counts against a low, undocumented ceiling. Teardown
    // runs in a finally for exactly this reason.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const { report } = await runDiagnosticOver(duplex, principal, 1);

    expect(duplex.firstIndexOf("close")).toBeGreaterThan(
      duplex.firstIndexOf("readable-done"),
    );
    expect(report.logoutOk).toBe(true);
    expect(report.closeOutcome).toBe("closed");
  });

  it("never leaks a credential fragment into anything that crosses the boundary", async () => {
    // 01-IMAP-PROOF.md cites this case as criterion-3 evidence, which is
    // exactly why it has to be capable of failing. It previously asserted over
    // `JSON.stringify(toErrorCategory(error))`, whose two values both come from
    // a frozen literal map in src/errors.ts — structurally incapable of
    // containing a credential regardless of what `error` held, and so proof of
    // nothing about the path it named.
    //
    // The two values below are what actually reach a caller: the tool result on
    // the failure path, and the report, which is serialized wholesale on the
    // success path.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedNo("a2", AUTH_REJECTED_TEXT),
      taggedNo("a3", AUTH_REJECTED_TEXT),
      logoutExchange("a4"),
    ]);

    const outcome = await runDiagnosticOver(duplex, principal, 1);

    // A case that would pass just as happily against an empty credential is
    // not a proof of containment; `not.toContain("")` is true of every string.
    // The two length assertions are that guard, and they are why the fixture's
    // constants are never coalesced onto an empty string.
    expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
    expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);

    for (const serialized of [
      JSON.stringify(diagnosticResult(outcome)),
      JSON.stringify(outcome.report),
    ]) {
      expect(serialized).not.toContain(FAKE_APP_PASSWORD);
      expect(serialized).not.toContain(FAKE_APPLE_ID);
    }
  });
});
