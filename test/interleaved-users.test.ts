// Interleaved users: two users' requests overlap in one isolate, and each one
// still sends its OWN login bytes (CRED-06, Phase 9 D-18).
//
// **What this file proves.** Nothing under `src/` keeps a "current user" that
// one request could overwrite while another is waiting. A principal is a
// parameter all the way down, so a request that is parked at an await wakes up
// holding the same user it went to sleep with.
//
// The shape of every case is the same. Start user A and do not wait for it. A
// parks at a point the test controls, BEFORE it has sent any login bytes. Run
// all of user B to the end. Let A go. Then read both wires. If anything shared
// had been set by B in the gap, A would wake up and log in as B, and the byte
// assertion on A's wire would say so.
//
// **Why the zero-writes control matters.** Every case asserts that the parked
// user had sent NOTHING at the moment the other user finished. Without that, a
// test could pass with the two sessions simply running one after the other,
// and it would prove nothing about overlap. The control is what makes "these
// two were interleaved" a checked fact and not a hope.
//
// **No concurrent combinator is used anywhere here, on purpose.** Production
// allows a handful of simultaneous connections per invocation, and a scan rule
// refuses a combinator wrapped around a session or a DAV entry point. The
// overlap is built by hand: start one, run the other, release, then await.
//
// Each mail session has its OWN gate. One shared gate would refuse the second
// session with the throttle error. That is correct behaviour for one request
// and the wrong test for two.
//
// **This file holds no real value.** Users A and B are fakes under
// `example.invalid` with plainly fake passwords, read only from `USER_A` and
// `USER_B`. Both principals come from `testPrincipal`, which wraps the real
// props constructor (D-17). Nothing here reads, prints or asserts on the
// pool's ambient identity. The DAV half records a LABEL for each request,
// never a header value. Nothing opens a network connection and nothing
// authenticates against a real Apple ID.

import { afterEach, describe, expect, it, vi } from "vitest";
import { DavAuthError } from "../src/dav/errors";
import { createDavFetch } from "../src/dav/transport";
import { createSessionGate, withMailSessionOver } from "../src/mail/service";
import { principalFromProps } from "../src/principal";
import {
  createFakeDuplex,
  createHeldFirstReadDuplex,
} from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
} from "./fixtures/icloud-bytes";
import {
  CALDAV_ENTRY,
  HOME_A,
  HOME_B,
  twoUserDavStub,
  userOfBasicHeader,
} from "./fixtures/two-user-dav";
import { USER_A, USER_B, testPrincipal } from "./fixtures/two-users";
import type { Principal } from "../src/principal";
import type { TestUser } from "./fixtures/two-users";

/** Bounds for the session that runs straight through. A few milliseconds. */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/**
 * Bounds for the session that is parked on purpose.
 *
 * The parked session is waiting on its greeting read for as long as the other
 * user takes. The other user runs over an in-memory stream, so almost no real
 * time passes, but a 40 ms read bound would still turn a slow machine into a
 * false failure. The teardown bounds stay short.
 */
const PARKED_BOUNDS = {
  ...FAST_BOUNDS,
  readTimeoutMs: 10_000,
  callDeadlineMs: 10_000,
};

/**
 * One whole session with no mailbox opened: greeting, capability, the login
 * answer, capability again, and the goodbye.
 */
function sessionScript(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    logoutExchange("a4"),
  ];
}

/** The login line `user` must send, byte for byte, CRLF stripped. */
function loginLineOf(user: TestUser): string {
  return `a2 LOGIN "${user.appleId}" "${user.appPassword}"`;
}

/** Every line a whole null-mailbox session for `user` puts on the wire. */
function wireOf(user: TestUser): string[] {
  return ["a1 CAPABILITY", loginLineOf(user), "a3 CAPABILITY", "a4 LOGOUT"];
}

/** What one interleaved run left behind. */
interface InterleavedWires {
  /** What the parked session had written when the other one finished. */
  readonly parkedLinesWhileParked: string[];
  /** Whether the parked session held its gate at that moment. */
  readonly parkedGateHeldWhileParked: boolean;
  /** What the straight-through session had written when it finished. */
  readonly runnerLines: string[];
  /** What the parked session had written once released and finished. */
  readonly parkedLines: string[];
  readonly parkedResult: string;
  readonly runnerResult: string;
}

/**
 * Park one session at its greeting read, run the other to its end, release the
 * parked one, and hand back both wires.
 *
 * Each session gets its own principal object, its own gate and its own duplex.
 * The two session calls are never handed to a combinator: the parked one is
 * started and kept, the runner is awaited, and only then is the parked one
 * released and awaited.
 */
async function interleave(
  parkedPrincipal: Principal,
  runnerPrincipal: Principal,
): Promise<InterleavedWires> {
  const parked = createHeldFirstReadDuplex(sessionScript());
  const parkedGate = createSessionGate();
  const runnerDuplex = createFakeDuplex(sessionScript());

  // Started, and deliberately not awaited. It takes its gate at once, asks for
  // the greeting, and waits there.
  const parkedSession = withMailSessionOver(
    parked.duplex,
    parkedPrincipal,
    parkedGate,
    null,
    null,
    async () => "parked",
    PARKED_BOUNDS,
  );
  // If the case fails before the await below, nobody is listening to this.
  parkedSession.catch(() => {});

  const runnerResult = await withMailSessionOver(
    runnerDuplex,
    runnerPrincipal,
    createSessionGate(),
    null,
    null,
    async () => "runner",
    FAST_BOUNDS,
  );

  // Copies, taken NOW, before the release. These are the control.
  const parkedLinesWhileParked = [...parked.duplex.writtenLines()];
  const parkedGateHeldWhileParked = parkedGate.held;
  const runnerLines = [...runnerDuplex.writtenLines()];

  parked.release();
  const parkedResult = await parkedSession;

  return {
    parkedLinesWhileParked,
    parkedGateHeldWhileParked,
    runnerLines,
    parkedLines: [...parked.duplex.writtenLines()],
    parkedResult,
    runnerResult,
  };
}

describe("mail: interleaved users each send their own login bytes", () => {
  it("A parks before its login, all of B runs, then A wakes and logs in as A", async () => {
    const a = await testPrincipal(USER_A);
    const b = await testPrincipal(USER_B);

    const run = await interleave(a, b);

    // The positive control. A had started (it held its gate) and had written
    // nothing at all when B finished.
    expect(
      run.parkedGateHeldWhileParked,
      "A never started: its gate was not held while B ran, so nothing was interleaved",
    ).toBe(true);
    expect(
      run.parkedLinesWhileParked,
      "A had already written to its wire before B finished, so A was not parked ahead of its login",
    ).toEqual([]);

    // B ran a whole session in the gap: its own login line, through to the
    // goodbye.
    expect(run.runnerResult).toBe("runner");
    expect(
      run.runnerLines,
      "B's wire does not hold B's login line followed by B's goodbye",
    ).toEqual(wireOf(USER_B));

    // A woke up as A.
    expect(run.parkedResult).toBe("parked");
    expect(
      run.parkedLines,
      "A's wire does not hold A's login line: A woke up as somebody else",
    ).toEqual(wireOf(USER_A));

    // Neither wire holds the other user's password anywhere.
    expect(
      run.parkedLines.some((line) => line.includes(USER_B.appPassword)),
      "B's password is on A's wire",
    ).toBe(false);
    expect(
      run.runnerLines.some((line) => line.includes(USER_A.appPassword)),
      "A's password is on B's wire",
    ).toBe(false);
  });

  it("gives the same bytes per user with the roles swapped", async () => {
    const forward = await interleave(
      await testPrincipal(USER_A),
      await testPrincipal(USER_B),
    );
    const swapped = await interleave(
      await testPrincipal(USER_B),
      await testPrincipal(USER_A),
    );

    expect(
      swapped.parkedGateHeldWhileParked,
      "B never started: its gate was not held while A ran",
    ).toBe(true);
    expect(
      swapped.parkedLinesWhileParked,
      "B had already written to its wire before A finished",
    ).toEqual([]);

    // Swapped: B is the parked one and A runs straight through.
    expect(
      swapped.parkedLines,
      "B's wire does not hold B's login line when B is the parked one",
    ).toEqual(wireOf(USER_B));
    expect(
      swapped.runnerLines,
      "A's wire does not hold A's login line when A runs straight through",
    ).toEqual(wireOf(USER_A));

    // Who goes first changes nothing about what each user sends.
    expect(
      swapped.runnerLines,
      "A's bytes differ depending on who went first",
    ).toEqual(forward.parkedLines);
    expect(
      swapped.parkedLines,
      "B's bytes differ depending on who went first",
    ).toEqual(forward.runnerLines);

    expect(
      swapped.parkedLines.some((line) => line.includes(USER_A.appPassword)),
      "A's password is on B's wire",
    ).toBe(false);
    expect(
      swapped.runnerLines.some((line) => line.includes(USER_B.appPassword)),
      "B's password is on A's wire",
    ).toBe(false);
  });

  it("two interleaved sessions for the SAME user each log in as that user", async () => {
    // Two requests from one person. Two principal OBJECTS, built apart, so the
    // password reader has to answer each one on its own.
    const first = await testPrincipal(USER_A);
    const second = await testPrincipal(USER_A);
    expect(
      first === second,
      "the constructor handed back one shared object, so this case tests nothing",
    ).toBe(false);

    const run = await interleave(first, second);

    expect(run.parkedGateHeldWhileParked).toBe(true);
    expect(
      run.parkedLinesWhileParked,
      "the parked session had already written before the other one finished",
    ).toEqual([]);
    expect(
      run.runnerLines,
      "the straight-through session did not log in as A",
    ).toEqual(wireOf(USER_A));
    expect(
      run.parkedLines,
      "the parked session did not log in as A once released",
    ).toEqual(wireOf(USER_A));
  });
});

// ---------------------------------------------------------------------------
// The DAV twin.
// ---------------------------------------------------------------------------

/** A header the TEST adds, so the stub can tell which instance sent a request. */
const SENDER_HEADER = "x-test-sent-by";

/** One request as the wrapped stub saw it. Two labels and a URL. No header value. */
interface SentRequest {
  /** Which instance sent it, from the header the test added. */
  readonly sender: string | null;
  /** Whose login it carried, worked out by the fixture. A label only. */
  readonly user: "A" | "B" | "unknown";
  readonly url: string;
}

interface HoldingStub {
  readonly fetch: typeof globalThis.fetch;
  readonly sent: SentRequest[];
  /** Let the held response go. */
  release(): void;
}

/**
 * The two-home stub, wrapped so the FIRST response to a request sent by
 * `heldSender` waits until the test releases it.
 *
 * The hold keys on who SENT the request, not on whose login it carried. If a
 * leak made A's request carry B's login, a hold keyed on the login would not
 * hold it, and the case would stop being an interleave at the very moment it
 * mattered.
 *
 * The login header is read, compared and dropped by `userOfBasicHeader`. Only
 * its label is kept.
 */
function holdingStub(heldSender: "A" | "B"): HoldingStub {
  const stub = twoUserDavStub();
  const sent: SentRequest[] = [];
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let holdNext = true;

  const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const sender = headers.get(SENDER_HEADER);
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    sent.push({
      sender,
      user: userOfBasicHeader(headers.get("authorization")),
      url,
    });

    const response = await stub.fetch(input, init);
    if (sender === heldSender && holdNext) {
      holdNext = false;
      await held;
    }
    return response;
  }) as typeof globalThis.fetch;

  return { fetch, sent, release: () => release() };
}

/** A PROPFIND from one instance, marked with who sent it. */
function propfind(
  davFetch: typeof globalThis.fetch,
  sender: "A" | "B",
  url: string,
): Promise<Response> {
  return davFetch(url, {
    method: "PROPFIND",
    headers: { [SENDER_HEADER]: sender },
  });
}

describe("DAV: interleaved users each send their own login header", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  for (const [heldSender, otherSender] of [
    ["A", "B"],
    ["B", "A"],
  ] as const) {
    it(`${heldSender}'s first response is held while all of ${otherSender} runs, and every request carries its sender's login`, async () => {
      const stub = holdingStub(heldSender);
      vi.stubGlobal("fetch", stub.fetch);

      const homeOf = { A: HOME_A, B: HOME_B } as const;
      const userOf = { A: USER_A, B: USER_B } as const;
      const heldFetch = createDavFetch(testPrincipal(userOf[heldSender]));
      const otherFetch = createDavFetch(testPrincipal(userOf[otherSender]));

      // Started, and deliberately not awaited. Its response is held.
      const heldFirst = propfind(heldFetch, heldSender, CALDAV_ENTRY);
      heldFirst.catch(() => {});

      // All of the other user's requests, one after the other, to the end.
      const otherStatuses = [
        (await propfind(otherFetch, otherSender, CALDAV_ENTRY)).status,
        (await propfind(otherFetch, otherSender, homeOf[otherSender])).status,
      ];
      expect(otherStatuses, `${otherSender}'s own requests were not served`).toEqual([
        207, 207,
      ]);

      // The control. The held user's one request is out and unanswered, and it
      // has sent nothing else.
      expect(
        stub.sent.filter((one) => one.sender === heldSender).length,
        `${heldSender} was not parked on exactly one request while ${otherSender} ran`,
      ).toBe(1);

      stub.release();
      expect((await heldFirst).status).toBe(207);

      // The held user's NEXT request, built after the other user has been and
      // gone. A shared "current user" would show up here.
      expect(
        (await propfind(heldFetch, heldSender, homeOf[heldSender])).status,
        `${heldSender} was refused under ${heldSender}'s own home after the interleave`,
      ).toBe(207);

      // Labels only. Every request carried the login of the instance that sent
      // it, and none carried a login the fixture does not know.
      expect(stub.sent).toHaveLength(4);
      expect(
        stub.sent.filter((one) => one.user === "unknown").length,
        "a request carried a login that is neither A's nor B's",
      ).toBe(0);
      expect(
        stub.sent.filter((one) => one.user !== one.sender),
        "a request carried the OTHER user's login",
      ).toEqual([]);
    });
  }

  it("A parked BEFORE its header is built still sends A's login after all of B", async () => {
    // The closest DAV twin of the mail case. A's promise of a principal does
    // not resolve until the test says so, so A is parked ahead of the point
    // where its header is built, having sent nothing.
    const stub = holdingStub("B");
    stub.release();
    vi.stubGlobal("fetch", stub.fetch);

    let releaseA: () => void = () => {};
    const heldA = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    const aFetch = createDavFetch(heldA.then(() => testPrincipal(USER_A)));
    const bFetch = createDavFetch(testPrincipal(USER_B));

    const aFirst = propfind(aFetch, "A", CALDAV_ENTRY);
    aFirst.catch(() => {});

    expect((await propfind(bFetch, "B", CALDAV_ENTRY)).status).toBe(207);
    expect((await propfind(bFetch, "B", HOME_B)).status).toBe(207);

    expect(
      stub.sent.filter((one) => one.sender === "A").length,
      "A had already sent a request before B finished, so A was not parked ahead of its header",
    ).toBe(0);

    releaseA();
    expect((await aFirst).status).toBe(207);

    expect(
      stub.sent.filter((one) => one.user !== one.sender),
      "a request carried the OTHER user's login",
    ).toEqual([]);
    expect(stub.sent.filter((one) => one.sender === "A")).toHaveLength(1);
  });

  it("A's refused principal sends nothing, and B is untouched", async () => {
    const stub = holdingStub("B");
    stub.release();
    vi.stubGlobal("fetch", stub.fetch);

    // A real refusal from the real constructor: props with no password in
    // them. The no-op handler goes on straight away, so the rejection is never
    // unheard.
    const refused = principalFromProps({ v: 1, appleId: USER_A.appleId });
    refused.catch(() => {});

    const aFetch = createDavFetch(refused);
    const bFetch = createDavFetch(testPrincipal(USER_B));

    // `rejects.toBeInstanceOf` reports a class name on failure, never a value.
    await expect(propfind(aFetch, "A", CALDAV_ENTRY)).rejects.toBeInstanceOf(
      DavAuthError,
    );
    expect((await propfind(bFetch, "B", CALDAV_ENTRY)).status).toBe(207);
    await expect(propfind(aFetch, "A", HOME_A)).rejects.toBeInstanceOf(
      DavAuthError,
    );
    expect((await propfind(bFetch, "B", HOME_B)).status).toBe(207);

    expect(
      stub.sent.filter((one) => one.sender === "A").length,
      "a request went out for a user whose principal was refused",
    ).toBe(0);
    expect(stub.sent).toHaveLength(2);
    expect(
      stub.sent.filter((one) => one.user !== "B"),
      "one of B's requests did not carry B's login",
    ).toEqual([]);
  });
});
