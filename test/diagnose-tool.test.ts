// The tool boundary's response shaping.
//
// The interesting case is the failing one. `authFailureDetail` was populated
// and tested in plan 01-03 and then discarded one frame later, so on the single
// most likely failure in this phase — iCloud refusing LOGIN — the caller was
// told "credentials rejected" and nothing else. That is precisely the run where
// the extra text decides whether the failure is diagnostic or useless: a wrong
// app-specific password and a username format iCloud will not accept produce
// the same category and different rejection texts.
//
// These cases pin the two properties that make echoing it safe: the detail
// appears only for an authentication refusal, decided by the error's TYPE, and
// neither bound credential appears in any response.

import { describe, expect, it } from "vitest";
import {
  ImapAuthError,
  ImapConnectError,
  ImapThrottleError,
  SAFE_MESSAGES,
} from "../src/errors";
import type { DiagnosticOutcome, DiagnosticReport } from "../src/mail/diagnose";
import { diagnosticResult } from "../src/mcp/tools/diagnose";
import {
  FAKE_APP_PASSWORD,
  FAKE_APPLE_ID,
} from "./fixtures/bound-secrets";

/** Apple's own wording on a refusal, in the shape the session layer records. */
const SERVER_REJECTION =
  'LOGIN: NO [AUTHENTICATIONFAILED] Authentication failed. | AUTHENTICATE PLAIN: NO [AUTHENTICATIONFAILED] Authentication failed.';

function report(overrides: Partial<DiagnosticReport> = {}): DiagnosticReport {
  return {
    host: "imap.mail.me.com",
    port: 993,
    secureTransport: "on",
    tlsEstablished: true,
    greetingCapability: "CAPABILITY IMAP4rev1 ID AUTH=PLAIN",
    postLoginCapability: null,
    literalPlus: null,
    authMechanism: null,
    authenticated: false,
    authFailureDetail: null,
    throttleFailureDetail: null,
    logoutOk: true,
    closeOutcome: "closed",
    inboxUidValidity: 3857529045,
    inboxMessageCount: 172,
    timings: {
      connectMs: 12,
      tlsHandshakeMs: 34,
      loginMs: 56,
      examineMs: 78,
      logoutMs: 7,
      closeMs: 8,
    },
    ...overrides,
  };
}

/** The single text payload every result carries. */
function payload(outcome: DiagnosticOutcome): string {
  const result = diagnosticResult(outcome);
  expect(result.content).toHaveLength(1);
  return result.content[0]!.text;
}

describe("a successful run", () => {
  it("returns the report and is not an error", () => {
    const succeeded = report({
      authenticated: true,
      authMechanism: "LOGIN",
      postLoginCapability: "CAPABILITY IMAP4rev1 LITERAL+ UIDPLUS",
      literalPlus: true,
    });
    const result = diagnosticResult({
      report: succeeded,
      failed: false,
      error: null,
    });

    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0]!.text)).toEqual(succeeded);
  });
});

describe("the close outcome reaches the caller as three distinguishable values", () => {
  // WINDOWS.md ledger entry 5. The report is serialized wholesale on the
  // success path, so what teardown observed is what the caller reads — and the
  // whole defect was that two of these three arrived as the same word.
  const outcomes = ["closed", "rejected", "timed-out"] as const;

  for (const outcome of outcomes) {
    it(`carries ${outcome} through verbatim`, () => {
      const body = JSON.parse(
        payload({
          report: report({ authenticated: true, closeOutcome: outcome }),
          failed: false,
          error: null,
        }),
      ) as Record<string, unknown>;

      expect(body.closeOutcome).toBe(outcome);
      // The independent cross-check survives alongside it. Ledger entry 5's
      // fix is a second field, not a replacement for the timing that made the
      // live proof interpretable in the first place.
      expect((body.timings as Record<string, unknown>).closeMs).toBe(8);
    });
  }

  it("keeps the three values distinct once serialized", () => {
    const serialized = outcomes.map(
      (outcome) =>
        JSON.parse(
          payload({
            report: report({ authenticated: true, closeOutcome: outcome }),
            failed: false,
            error: null,
          }),
        ).closeOutcome as string,
    );

    expect(new Set(serialized).size).toBe(3);
  });

  it("reports null when teardown never ran at all", () => {
    // The empty state, distinct from all three: a connect that never opened a
    // socket has no teardown to report, and `false` used to claim it did.
    const body = JSON.parse(
      payload({
        report: report({ closeOutcome: null }),
        failed: false,
        error: null,
      }),
    ) as Record<string, unknown>;

    expect(body.closeOutcome).toBeNull();
  });
});

describe("an authentication refusal", () => {
  const outcome: DiagnosticOutcome = {
    report: report({ authFailureDetail: SERVER_REJECTION }),
    failed: true,
    error: new ImapAuthError(),
  };

  it("carries the server's rejection text through to the caller", () => {
    const body = JSON.parse(payload(outcome)) as Record<string, unknown>;

    expect(body.category).toBe("auth_failed");
    expect(body.message).toBe(SAFE_MESSAGES.auth_failed);
    // The whole reason this test exists.
    expect(body.authFailureDetail).toBe(SERVER_REJECTION);
    expect(diagnosticResult(outcome).isError).toBe(true);
  });

  it("omits the field entirely when the server said nothing to record", () => {
    const body = JSON.parse(
      payload({ ...outcome, report: report({ authFailureDetail: null }) }),
    ) as Record<string, unknown>;

    expect(body).toEqual({
      category: "auth_failed",
      message: SAFE_MESSAGES.auth_failed,
    });
    expect("authFailureDetail" in body).toBe(false);
  });
});

describe("the detail is gated on the error's type, not on the field being set", () => {
  // A report that carries a detail from an earlier stage, paired with a
  // non-auth failure. If the condition were `detail !== null` rather than a
  // type check, every one of these would leak a field that does not belong to
  // the failure being reported.
  const withDetail = report({ authFailureDetail: SERVER_REJECTION });

  const cases: [string, unknown, string][] = [
    ["a transport failure", new ImapConnectError(), "connection_failed"],
    ["a throttle refusal", new ImapThrottleError(), "rate_limited"],
    ["an unrecognised value", { message: SERVER_REJECTION }, "connection_failed"],
    ["null", null, "connection_failed"],
  ];

  for (const [label, error, category] of cases) {
    it(`omits it for ${label}`, () => {
      const body = JSON.parse(
        payload({ report: withDetail, failed: true, error }),
      ) as Record<string, unknown>;

      expect(body.category).toBe(category);
      expect("authFailureDetail" in body).toBe(false);
    });
  }
});

describe("a connection-limit refusal (WINDOWS.md ledger entry 6)", () => {
  const REFUSAL = "[UNAVAILABLE] Too many simultaneous connections; try later";

  it("carries the server's own refusal text under its own field name", () => {
    const body = JSON.parse(
      payload({
        report: report({ throttleFailureDetail: REFUSAL }),
        failed: true,
        error: new ImapThrottleError(),
      }),
    ) as Record<string, unknown>;

    expect(body.category).toBe("rate_limited");
    expect(body.message).toBe(SAFE_MESSAGES.rate_limited);
    expect(body.throttleFailureDetail).toBe(REFUSAL);
    // Its own field, not the authentication one. The two refusals are
    // different facts and a shared field would make the response ambiguous.
    expect("authFailureDetail" in body).toBe(false);
  });

  it("omits the field entirely when the server said nothing to record", () => {
    // The realistic shape for the gate in `src/mail/service.ts`, which raises
    // this class with no server involved at all.
    const body = JSON.parse(
      payload({
        report: report({ throttleFailureDetail: null }),
        failed: true,
        error: new ImapThrottleError(),
      }),
    ) as Record<string, unknown>;

    expect(body).toEqual({
      category: "rate_limited",
      message: SAFE_MESSAGES.rate_limited,
    });
  });

  it("is gated on the error's type, exactly as the authentication one is", () => {
    // A report carrying BOTH details, paired with each failure in turn. Only
    // the field belonging to the reported failure may appear — a gate that had
    // degraded to `detail !== null` would emit both every time.
    const both = report({
      authFailureDetail: SERVER_REJECTION,
      throttleFailureDetail: REFUSAL,
    });

    const asAuth = JSON.parse(
      payload({ report: both, failed: true, error: new ImapAuthError() }),
    ) as Record<string, unknown>;
    expect(asAuth.authFailureDetail).toBe(SERVER_REJECTION);
    expect("throttleFailureDetail" in asAuth).toBe(false);

    const asThrottle = JSON.parse(
      payload({ report: both, failed: true, error: new ImapThrottleError() }),
    ) as Record<string, unknown>;
    expect(asThrottle.throttleFailureDetail).toBe(REFUSAL);
    expect("authFailureDetail" in asThrottle).toBe(false);

    const asTransport = JSON.parse(
      payload({ report: both, failed: true, error: new ImapConnectError() }),
    ) as Record<string, unknown>;
    expect("throttleFailureDetail" in asTransport).toBe(false);
    expect("authFailureDetail" in asTransport).toBe(false);
  });

  it("does not widen the vocabulary", () => {
    const body = JSON.parse(
      payload({
        report: report({ throttleFailureDetail: REFUSAL }),
        failed: true,
        error: new ImapThrottleError(REFUSAL),
      }),
    ) as Record<string, unknown>;

    // The claim this case makes is that a refusal which now CARRIES TEXT is
    // still one of the shipped categories rather than a new one invented to
    // hold the text. It said so by asserting the vocabulary's SIZE, which made
    // this file a second place the size is written down — and Phase 5's
    // deliberate four-to-six growth then failed here, in a file about the
    // connection-limit detail, for a reason that has nothing to do with it.
    //
    // The size belongs in `test/errors.test.ts`, where a
    // `Record<ErrorCategory, true>` puts the compiler behind it. What belongs
    // here is that THIS path lands inside the vocabulary and on the category it
    // always did.
    expect(Object.keys(SAFE_MESSAGES)).toContain(body.category as string);
    expect(body.category).toBe("rate_limited");
    expect(body.message).toBe(SAFE_MESSAGES.rate_limited);
  });
});

describe("no response carries a credential", () => {
  // The two fake credentials come from the fixture, never off an environment
  // object, and never through a coalesce onto an empty string — that would
  // typecheck and keep every case below green while making `not.toContain("")`
  // trivially true, which is exactly what the non-zero-length guards prevent.

  const outcomes: [string, DiagnosticOutcome][] = [
    [
      "success",
      { report: report({ authenticated: true }), failed: false, error: null },
    ],
    [
      "auth refusal with detail",
      {
        report: report({ authFailureDetail: SERVER_REJECTION }),
        failed: true,
        error: new ImapAuthError(),
      },
    ],
    [
      "connection-limit refusal with detail",
      {
        report: report({
          throttleFailureDetail:
            "[UNAVAILABLE] Too many simultaneous connections",
        }),
        failed: true,
        error: new ImapThrottleError(),
      },
    ],
    [
      "an error whose own message embeds both credentials",
      {
        report: report(),
        failed: true,
        error: new Error(
          `a1 LOGIN "${FAKE_APPLE_ID}" "${FAKE_APP_PASSWORD}"`,
        ),
      },
    ],
  ];

  for (const [label, outcome] of outcomes) {
    it(`contains neither bound value: ${label}`, () => {
      const serialized = JSON.stringify(diagnosticResult(outcome));

      expect(FAKE_APPLE_ID.length).toBeGreaterThan(0);
      expect(FAKE_APP_PASSWORD.length).toBeGreaterThan(0);
      expect(serialized).not.toContain(FAKE_APPLE_ID);
      expect(serialized).not.toContain(FAKE_APP_PASSWORD);
    });
  }
});
