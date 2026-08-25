// The byte-counted reader, against deliberately hostile bytes.
//
// A fixture built only from well-behaved short messages passes against BOTH the
// correct implementation and the broken one. That is the trap, and this file
// exists to avoid it: every case here was chosen because a line-splitting
// reader fails it.
//
// The discriminating-power check was performed rather than assumed —
// `readUntilTag` was reverted to read lines instead of logical responses, this
// file was run, and the failure was observed and recorded in 02-04-SUMMARY.md.
// A test that stays green under that revert is testing nothing.

import { describe, expect, it } from "vitest";
import { ImapConnectError } from "../src/errors";
import { parseSExpr } from "../src/mail/imap-parser";
import {
  ImapChannel,
  MAX_LITERAL_OCTETS,
  awaitContinuation,
  readGreeting,
  readUntilTag,
  sendCommand,
} from "../src/mail/imap-session";
import {
  BINARY_FETCH,
  BINARY_PAYLOAD,
  FORGED_COMPLETION,
  HOSTILE_BODY,
  HOSTILE_FETCH,
  MULTIPART_BODY,
  MULTIPART_FETCH,
  OVERSIZE_OCTETS,
  OVERSIZE_TAIL,
  TRUNCATED_LITERAL_HEAD,
  hostileThenNextCommand,
  oversizeThenNextCommand,
} from "./fixtures/hostile-bytes";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import {
  createFakeDuplex,
  createStallingDuplex,
} from "./fixtures/fake-duplex";

const DECODER = new TextDecoder();

/** A read bound of a few milliseconds, so no case here costs wall time. */
const FAST_READ_MS = 40;

/** The literal payload of the first untagged response carrying one. */
function firstLiteral(untagged: { literals: Uint8Array[] }[]): Uint8Array {
  for (const line of untagged) {
    if (line.literals.length > 0) return line.literals[0]!;
  }
  throw new Error("no untagged response carried a literal");
}

describe("a literal payload spelling this command's own completion", () => {
  it("does NOT terminate the read (T-02-01)", async () => {
    // The headline threat. Anyone who can send mail to this account can put
    // `a5 OK UID FETCH completed` in a body. A reader that splits lines returns
    // there, reports a status it did not receive, and feeds the rest of the
    // body to the NEXT command's reader — desynchronising the session against
    // attacker-chosen text.
    const duplex = createFakeDuplex([GREETING, HOSTILE_FETCH]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");

    // The completion that came back is the REAL one — the one that followed the
    // literal, not the one inside it.
    expect(result.status).toBe("OK");
    expect(result.tagged.text).toBe("a5 OK UID FETCH completed");
    expect(result.tagged.literals).toEqual([]);

    // And the whole payload was consumed, forgery included, as data.
    const payload = DECODER.decode(firstLiteral(result.untagged));
    expect(payload).toBe(HOSTILE_BODY);
    expect(payload).toContain(FORGED_COMPLETION);
    expect(payload.endsWith("desynchronised from that point onwards.\r\n")).toBe(
      true,
    );
  });

  it("leaves the forged line inside the payload, never in the protocol text", async () => {
    // The separation that makes the rest of the session safe: content lands in
    // `literals`, protocol text lands in `text`, and nothing crosses.
    const duplex = createFakeDuplex([GREETING, HOSTILE_FETCH]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");

    expect(result.untagged).toHaveLength(1);
    expect(result.untagged[0]!.text).not.toContain(FORGED_COMPLETION);
    expect(result.untagged[0]!.text).not.toContain("desynchronised");
  });

  it("leaves the stream synchronised, so the NEXT command gets its own answer", async () => {
    // THE discriminating assertion, and it is deliberately not about the first
    // reply. The forged completion is byte-identical to the real one — that is
    // what makes it a forgery — so comparing the returned tagged text cannot
    // tell a correct reader from a broken one. What can is where the stream is
    // left standing: a reader that returned at the forgery leaves the rest of
    // the body unread, and this second command then consumes prose as protocol.
    const duplex = createFakeDuplex([
      GREETING,
      hostileThenNextCommand("a5", "a6"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");
    const next = await sendCommand(channel, "a6", "CAPABILITY");

    expect(next.status).toBe("OK");
    expect(next.tagged.text).toBe("a6 OK CAPABILITY completed");
    expect(next.untagged.map((line) => line.text)).toEqual([
      "* CAPABILITY IMAP4rev1 UIDPLUS",
    ]);
    // Not one byte of the message body reached the second command's reader.
    for (const line of next.untagged) {
      expect(line.text).not.toContain("desynchronised");
      expect(line.text).not.toContain("transcript");
    }
  });
});

describe("reassembly across physical lines", () => {
  it("returns a literal-bearing reply as ONE logical response", async () => {
    // Asserted on the assembled protocol text rather than on a count of lines
    // read, because a count would pass against an implementation that happened
    // to read the right number of lines for the wrong reason.
    const duplex = createFakeDuplex([GREETING, MULTIPART_FETCH]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");

    // One untagged response, not twenty-odd fragments.
    expect(result.untagged).toHaveLength(1);
    const line = result.untagged[0]!;

    // The bytes that FOLLOWED the last literal octet belong to this same
    // logical line: the `)` closing the item list is part of it, and there was
    // no CRLF between the payload and it.
    expect(line.text.startsWith("* 1 FETCH (UID 4827 ")).toBe(true);
    expect(line.text.endsWith(")")).toBe(true);

    // And the structure parses, which it cannot if the line was shredded.
    const parsed = parseSExpr(line);
    expect(parsed[2]).toBe("FETCH");
    expect(Array.isArray(parsed[3])).toBe(true);

    expect(DECODER.decode(line.literals[0]!)).toBe(MULTIPART_BODY);
  });
});

describe("literal payloads are bytes, never decoded strings", () => {
  it("round-trips a payload containing invalid UTF-8 byte-identically", async () => {
    // Compared as BYTES. A string comparison is precisely the assertion that
    // would pass while the payload was being corrupted, because both sides
    // would carry the same U+FFFD substitutions.
    const duplex = createFakeDuplex([GREETING, BINARY_FETCH]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const result = await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");
    const payload = firstLiteral(result.untagged);

    expect(payload).toBeInstanceOf(Uint8Array);
    expect(payload.byteLength).toBe(BINARY_PAYLOAD.byteLength);
    expect(Array.from(payload)).toEqual(Array.from(BINARY_PAYLOAD));

    // And the bytes really were unrepresentable, so the case is not vacuous.
    expect(DECODER.decode(payload)).toContain("�");
  });
});

describe("a literal larger than the cap", () => {
  it("is consumed and discarded past the cap, and the NEXT response still parses", async () => {
    // The second half is the important half. Consuming past the cap is what
    // keeps the stream synchronised; an implementation that abandoned the read
    // would leave the remainder to be misparsed as commands, and the only way
    // to see the difference is to ask the next command whether it still got its
    // own answer.
    const duplex = createFakeDuplex([
      GREETING,
      oversizeThenNextCommand("a5", "a6"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const first = await sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])");
    const payload = firstLiteral(first.untagged);

    expect(OVERSIZE_OCTETS).toBeGreaterThan(MAX_LITERAL_OCTETS);
    expect(payload.byteLength).toBe(MAX_LITERAL_OCTETS);
    // The recognisable tail sat past the cap, so it must be gone.
    expect(DECODER.decode(payload.subarray(-64))).not.toContain(OVERSIZE_TAIL);

    // The stream stayed synchronised: the next command gets its own answer,
    // parsed as protocol rather than as the tail of a discarded payload.
    const second = await sendCommand(channel, "a6", "CAPABILITY");
    expect(second.status).toBe("OK");
    expect(second.tagged.text).toBe("a6 OK CAPABILITY completed");
    expect(second.untagged[0]!.text).toBe("* CAPABILITY IMAP4rev1 UIDPLUS");
  });
});

describe("a literal whose octets never arrive", () => {
  it("raises inside the read bound rather than hanging", async () => {
    // The peer announces 5000 octets and then stops — no bytes, no EOF. Without
    // a bound inside readOctets this holds the socket for the whole request
    // budget against a low, undocumented ceiling, and the caller's teardown
    // never runs.
    const duplex = createStallingDuplex([GREETING, TRUNCATED_LITERAL_HEAD]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const startedAt = Date.now();
    await expect(
      sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])"),
    ).rejects.toBeInstanceOf(ImapConnectError);

    // Under one second of wall time, which is what proves an injected bound is
    // in use rather than the production ten seconds.
    expect(Date.now() - startedAt).toBeLessThan(1000);
  });

  it("raises when the peer closes mid-literal instead of stalling", async () => {
    // The other direction: EOF rather than silence. A short literal is not a
    // recoverable condition — everything after it would be read at the wrong
    // offset — so it refuses rather than returning what did arrive.
    const channel = new ImapChannel(
      createFakeDuplex([GREETING, TRUNCATED_LITERAL_HEAD]),
      { readTimeoutMs: FAST_READ_MS },
    );
    await readGreeting(channel);

    await expect(
      sendCommand(channel, "a5", "UID FETCH 4827 (BODY.PEEK[])"),
    ).rejects.toBeInstanceOf(ImapConnectError);
  });
});

describe("Phase 1's conversation after the reader switched", () => {
  it("produces the same tagged completions and the same untagged content", async () => {
    // The blast-radius check. `readLine()` did not change, and a literal-free
    // response comes back through `readResponse()` as the same line with an
    // empty literal list — so every Phase 1 path behaves identically. Driven
    // from the existing byte fixtures rather than new ones, so this really is
    // the old conversation.
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", POST_AUTH_CAPABILITY),
      logoutExchange("a4"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });

    expect(await readGreeting(channel)).toContain("* OK");

    const pre = await sendCommand(channel, "a1", "CAPABILITY");
    expect(pre.tagged.text).toBe("a1 OK CAPABILITY completed");
    expect(pre.untagged.map((line) => line.text)).toEqual([
      `* CAPABILITY ${PRE_AUTH_CAPABILITY}`,
    ]);
    expect(pre.untagged.every((line) => line.literals.length === 0)).toBe(true);

    const login = await sendCommand(channel, "a2", "LOGIN redacted redacted");
    expect(login.tagged.text).toBe("a2 OK LOGIN completed");

    const post = await sendCommand(channel, "a3", "CAPABILITY");
    expect(post.untagged.map((line) => line.text)).toEqual([
      `* CAPABILITY ${POST_AUTH_CAPABILITY}`,
    ]);

    const logout = await sendCommand(channel, "a4", "LOGOUT");
    expect(logout.tagged.text).toBe("a4 OK LOGOUT completed");
    expect(logout.untagged.map((line) => line.text)).toEqual(["* BYE Logging out"]);
  });
});

// ---------------------------------------------------------------------------
// The SEND side: synchronizing literals and the continuation wait (D-28)
//
// Everything above reads literals the server sent. Everything below writes one,
// which is a different problem with a different failure mode: the read side
// gets desynchronised, the write side HANGS. PITFALLS #7 names it, and
// `01-IMAP-PROOF.md` § 2 is why it is reachable — this account's measured
// capability list does not carry the optimistic form, so the handshake is
// mandatory rather than optional.
// ---------------------------------------------------------------------------

/** The continuation with the free-form text the grammar permits after the sign. */
const CONTINUATION = wire("+ Ready for additional command text");

/** The bare form: a plus sign, and nothing else on the line. */
const BARE_CONTINUATION = wire("+");

/**
 * A term that is five JavaScript characters and eight UTF-8 bytes.
 *
 * `c`, `a`, `f` are one byte each, `é` (U+00E9) is two, and `☕` (U+2615) is
 * three. The gap between the two counts is the whole subject of the last case
 * in this section, and it is the failure that is silently catastrophic: a count
 * that is too small leaves the tail of the term parsed as a new command, and one
 * that is too large leaves the server waiting for octets that never come.
 */
const ACCENTED_TERM = "café☕";
const ACCENTED_BYTES = new TextEncoder().encode(ACCENTED_TERM);

/** An untagged reply whose literal payload begins a line with a plus sign. */
function fetchWithPlusInPayload(payload: string): Uint8Array {
  const bytes = new TextEncoder().encode(payload);
  const head = new TextEncoder().encode(
    `* 1 FETCH (UID 4827 BODY[1] {${bytes.byteLength}}\r\n`,
  );
  const tail = new TextEncoder().encode(")\r\n");
  const joined = new Uint8Array(head.byteLength + bytes.byteLength + tail.byteLength);
  joined.set(head, 0);
  joined.set(bytes, head.byteLength);
  joined.set(tail, head.byteLength + bytes.byteLength);
  return joined;
}

describe("the continuation wait", () => {
  it("returns on a continuation carrying free-form text", async () => {
    const duplex = createFakeDuplex([GREETING, CONTINUATION]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("continuation");
    if (outcome.kind !== "continuation") throw new Error("unreachable");
    expect(outcome.untagged).toEqual([]);
  });

  it("returns on a BARE plus sign too", async () => {
    // `continue-req = "+" SP (resp-text / base64)` in the grammar, but servers
    // do send the bare sign, and matching on a whole line would miss both this
    // and the free-form case above. The match is on the sign or its
    // space-suffixed prefix, never on the line.
    const duplex = createFakeDuplex([GREETING, BARE_CONTINUATION]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    expect((await awaitContinuation(channel, "a5")).kind).toBe("continuation");
  });

  it("does not treat a line merely CONTAINING a plus sign as a continuation", async () => {
    // Added after mutation M3: relaxing the match to `text.includes("+")` left
    // every case green, because no fixture happened to carry a plus sign
    // anywhere but in a continuation. The gap is real and this server hits it —
    // a capability list is exactly the untagged line a server may volunteer
    // mid-command, and this account's own advertises `LITERAL+`. Under the
    // relaxed match the client would take that line as the go-ahead and write
    // the literal payload into the middle of a reply the server was still
    // sending.
    const duplex = createFakeDuplex([
      GREETING,
      wire("* CAPABILITY IMAP4rev1 LITERAL+ AUTH=PLAIN ID"),
      CONTINUATION,
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("continuation");
    if (outcome.kind !== "continuation") throw new Error("unreachable");
    // Collected as data, not consumed as the go-ahead.
    expect(outcome.untagged.map((line) => line.text)).toEqual([
      "* CAPABILITY IMAP4rev1 LITERAL+ AUTH=PLAIN ID",
    ]);
  });

  it("collects untagged data that arrives while the continuation is pending", async () => {
    // RFC 3501 §2.2.1: the server may send untagged data while the continuation
    // is still outstanding, "in which case the client takes the appropriate
    // action for the response, and reads another response from the server". A
    // reader that returned on the first line it did not recognise would drop it.
    const duplex = createFakeDuplex([
      GREETING,
      wire("* 4 EXPUNGE", "* 171 EXISTS"),
      CONTINUATION,
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("continuation");
    if (outcome.kind !== "continuation") throw new Error("unreachable");
    expect(outcome.untagged.map((line) => line.text)).toEqual([
      "* 4 EXPUNGE",
      "* 171 EXISTS",
    ]);
  });

  it("does not end on a completion belonging to a DIFFERENT tag", async () => {
    // The same clause of §2.2.1, and the half most easily collapsed into "any
    // tagged line means stop". A completion for another command says nothing
    // about ours, and the continuation is still pending.
    const duplex = createFakeDuplex([
      GREETING,
      wire("a4 OK NOOP completed"),
      CONTINUATION,
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("continuation");
    if (outcome.kind !== "continuation") throw new Error("unreachable");
    expect(outcome.untagged.map((line) => line.text)).toEqual([
      "a4 OK NOOP completed",
    ]);
  });

  it("stops at a rejection for OUR tag even when a continuation follows it", async () => {
    // THE discriminating case, and it is deliberately not the timing one. With
    // an injected read bound a stall costs milliseconds, so wall time cannot
    // tell a correct implementation from one missing the branch. What can is a
    // continuation sitting immediately behind the rejection: an implementation
    // that only ever looks for a plus sign swallows the rejection into its
    // untagged list and reports a continuation that was never ours.
    const duplex = createFakeDuplex([
      GREETING,
      wire("a5 BAD Invalid search criteria"),
      CONTINUATION,
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("rejected");
    if (outcome.kind !== "rejected") throw new Error("unreachable");
    expect(outcome.result.status).toBe("BAD");
    expect(outcome.result.tagged.text).toBe("a5 BAD Invalid search criteria");
  });

  it("aborts on a rejection rather than stalling to the read bound (T-02-36)", async () => {
    // A peer that rejects the command and then says nothing at all — no
    // continuation, ever. Without the rejection branch this read runs to the
    // bound and reports a transient transport fault, which in production is
    // half the call deadline spent on a question the server already answered
    // and then described to the caller as worth retrying.
    const duplex = createStallingDuplex([
      GREETING,
      wire("a5 NO [BADCHARSET (US-ASCII)] Unsupported charset"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const startedAt = Date.now();
    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("rejected");
    if (outcome.kind !== "rejected") throw new Error("unreachable");
    // A NO rather than a BAD, and the difference is load-bearing one layer up:
    // an unsupported charset is a well-specified answer the caller reports as
    // an empty result, not a failure. The wait hands the reply back rather than
    // raising, so that distinction survives to the place that can act on it.
    expect(outcome.result.status).toBe("NO");
    expect(outcome.result.tagged.text).toContain("BADCHARSET");
    expect(Date.now() - startedAt).toBeLessThan(1000);
  });

  it("does not mistake a plus sign INSIDE a literal payload for a continuation", async () => {
    // The read side's byte counting, proven from the write side's point of
    // view. Anyone who can send mail to this account can put a line beginning
    // with a plus sign in a body, and a line-splitting reader would take it as
    // the server's go-ahead — writing the literal payload into the middle of an
    // untagged reply the server is still sending.
    const payload = "First line.\r\n+ Ready for additional command text\r\nLast.\r\n";
    const duplex = createFakeDuplex([
      GREETING,
      fetchWithPlusInPayload(payload),
      CONTINUATION,
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    const outcome = await awaitContinuation(channel, "a5");

    expect(outcome.kind).toBe("continuation");
    if (outcome.kind !== "continuation") throw new Error("unreachable");
    // ONE collected response, carrying the forged sign as payload rather than
    // as protocol. A line-splitting reader collects the FETCH head line only
    // and returns at the sign inside the body.
    expect(outcome.untagged).toHaveLength(1);
    expect(DECODER.decode(outcome.untagged[0]!.literals[0]!)).toBe(payload);
    expect(outcome.untagged[0]!.text).not.toContain("Ready for additional");
  });
});

describe("writing a synchronizing literal", () => {
  it("declares the UTF-8 BYTE count, never the JavaScript string length", async () => {
    // The single worst failure available on this path, and the one the channel's
    // own docstring has warned about since Phase 1. Asserted on BOTH numbers so
    // the case cannot pass by coincidence on a term where they agree.
    expect(ACCENTED_TERM.length).toBe(5);
    expect(ACCENTED_BYTES.byteLength).toBe(8);

    const duplex = createFakeDuplex([
      GREETING,
      CONTINUATION,
      wire("* SEARCH 4102 3871", "a5 OK SEARCH completed"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    await channel.write(
      `a5 UID SEARCH CHARSET UTF-8 TEXT {${ACCENTED_BYTES.byteLength}}`,
    );
    const outcome = await awaitContinuation(channel, "a5");
    expect(outcome.kind).toBe("continuation");

    await channel.writeBytes(ACCENTED_BYTES);
    await channel.write("");
    const result = await readUntilTag(channel, "a5");

    expect(result.status).toBe("OK");
    expect(duplex.writtenLines()[0]).toBe(
      "a5 UID SEARCH CHARSET UTF-8 TEXT {8}",
    );
    expect(duplex.writtenLines()[0]).not.toContain("{5}");
  });

  it("writes the payload as raw bytes with NO terminator appended", async () => {
    // `write` appends CRLF and `writeBytes` must not: the declared count covers
    // the payload alone, so two extra octets here would leave the server reading
    // the command terminator as payload and the payload's own terminator as the
    // start of a new command.
    const duplex = createFakeDuplex([
      GREETING,
      CONTINUATION,
      wire("* SEARCH", "a5 OK SEARCH completed"),
    ]);
    const channel = new ImapChannel(duplex, { readTimeoutMs: FAST_READ_MS });
    await readGreeting(channel);

    await channel.write(
      `a5 UID SEARCH CHARSET UTF-8 TEXT {${ACCENTED_BYTES.byteLength}}`,
    );
    await awaitContinuation(channel, "a5");
    await channel.writeBytes(ACCENTED_BYTES);
    await channel.write("");

    // The payload chunk, byte for byte, and nothing else in it.
    expect(Array.from(duplex.writes[1]!)).toEqual(Array.from(ACCENTED_BYTES));
    expect(duplex.writes[1]!.byteLength).toBe(8);
    // And the command terminator arrives as its own write, after the payload.
    expect(DECODER.decode(duplex.writes[2]!)).toBe("\r\n");
  });
});
