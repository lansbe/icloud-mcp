// The FND-05 error boundary: a closed vocabulary of exactly seven categories,
// and a translation function that dispatches on type rather than on text.
//
// Four through Phases 1-4. Two more arrived in Phase 5 (CALW-05 and CALW-04),
// in one edit, because a category that exists before anything can raise it is
// the hazard `src/errors.ts`'s own header names. A seventh,
// `subscription_unreadable`, arrived with quick task 260822-h1c, from the DAV
// side only, on the same footing.

import { describe, expect, it } from "vitest";
import {
  DavAuthError,
  DavConfirmationError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavSubscriptionError,
  DavThrottleError,
  davToErrorCategory,
} from "../src/dav/errors";
import type { ErrorCategory } from "../src/errors";
import {
  ImapAuthError,
  ImapConnectError,
  ImapNotFoundError,
  ImapThrottleError,
  SAFE_MESSAGES,
  toErrorCategory,
} from "../src/errors";
import { assertMailSecretsBound, entryEnv } from "./fixtures/bound-secrets";

/**
 * The seven values the vocabulary now holds, listed exhaustively.
 *
 * The record below is the type-level half of the exhaustiveness claim: adding
 * an eighth member to `ErrorCategory` makes it a compile error, and removing
 * one makes the excess key a compile error. `npx tsc --noEmit` is therefore
 * part of this assertion, not merely adjacent to it.
 */
const EVERY_CATEGORY: Record<ErrorCategory, true> = {
  auth_failed: true,
  connection_failed: true,
  rate_limited: true,
  not_found: true,
  stale_resource: true,
  confirmation_invalid: true,
  subscription_unreadable: true,
};

const CATEGORIES = Object.keys(EVERY_CATEGORY) as ErrorCategory[];

/** The seven, sorted, so every set assertion below reads from one place. */
const SORTED_CATEGORIES = [
  "auth_failed",
  "confirmation_invalid",
  "connection_failed",
  "not_found",
  "rate_limited",
  "stale_resource",
  "subscription_unreadable",
];

/**
 * Every value the translation boundary could ever be handed.
 *
 * The four error classes are the designed inputs. Everything after them is
 * the undesigned half — a `catch` block receives whatever was thrown, and in
 * this runtime that can be any value at all.
 */
const EVERY_INPUT: unknown[] = [
  new ImapAuthError(),
  new ImapConnectError(),
  new ImapThrottleError(),
  // The one class that takes a constructor argument. Included so every
  // exhaustive assertion below covers the carrying form as well as the bare
  // one — a detail that changed the produced category would be caught here.
  new ImapThrottleError("[UNAVAILABLE] Too many simultaneous connections"),
  new ImapNotFoundError(),
  null,
  undefined,
  "",
  "a string that was thrown",
  {},
  { category: "not_found" },
  [],
  0,
  Number.NaN,
  false,
  new Error("a plain error"),
  new TypeError("a subclass we did not define"),
  Symbol("thrown symbol"),
  () => "a thrown function",
];

describe("the category vocabulary", () => {
  it("is exactly the seven values the vocabulary now holds, with no eighth", () => {
    expect(CATEGORIES).toHaveLength(7);
    expect([...CATEGORIES].sort()).toEqual(SORTED_CATEGORIES);
  });

  it("has one fixed safe message per category and no others", () => {
    expect(Object.keys(SAFE_MESSAGES)).toHaveLength(7);
    expect([...Object.keys(SAFE_MESSAGES)].sort()).toEqual(
      [...CATEGORIES].sort(),
    );
    for (const category of CATEGORIES) {
      expect(typeof SAFE_MESSAGES[category]).toBe("string");
      expect(SAFE_MESSAGES[category].length).toBeGreaterThan(0);
    }
  });

  it("gives every category a message of its own, with no two alike", () => {
    // A copy-paste that duplicated a message would leave two categories
    // operationally indistinguishable to the model reading the response, which
    // is the whole of what the closed vocabulary is for. The set comparison is
    // what catches it; a per-value non-emptiness check would not.
    const values = CATEGORIES.map((category) => SAFE_MESSAGES[category]);
    expect(new Set(values).size).toBe(values.length);
  });

  it("tells the caller what to do about a rate limit, not merely that it hit one", () => {
    // The retry guidance is the point: an unguided model faced with a
    // throttling server retries in a loop, which is the behaviour most likely
    // to escalate a temporary refusal into a lockout of the user's own mail.
    expect(SAFE_MESSAGES.rate_limited).toContain("not retry in a loop");
    expect(SAFE_MESSAGES.auth_failed).toContain("retrying will not help");
  });

  it("warns that an attendee reply is one of the things that moves an event", () => {
    // 05-RESEARCH.md Pitfall 5. RFC 6638 §3.2.10 records that the SERVER
    // rewrites a scheduling object resource when an attendee changes their
    // participation status, so `If-Match` refuses a commit nobody raced. This
    // project keeps `If-Match` anyway — the alternative instructs the server to
    // MERGE, on a write path whose entire purpose is that nothing happens
    // silently — and what it owes in exchange is saying so here. Without this
    // sentence the first real occurrence reads as a bug and gets "fixed" by
    // dropping the conditional header, which is the failure this phase is
    // being careful about.
    //
    // Asserted against a substring of the shipped constant rather than a
    // paraphrase: a reworded message that dropped the disclosure would pass a
    // paraphrase check built out of the same words.
    expect(SAFE_MESSAGES.stale_resource).toContain(
      "An attendee replying to an invitation also changes the event",
    );
    expect(SAFE_MESSAGES.stale_resource).toContain("nothing was overwritten");
    expect(SAFE_MESSAGES.stale_resource).toContain("Preview the change again");
  });

  it.each(["signature", "expiry", "hash", "version", "base64", "token"])(
    "refuses a confirmation without ever naming %s",
    (forbidden) => {
      // Six conditions raise `confirmation_invalid` and they are deliberately
      // indistinguishable. A refusal that named the check that failed would
      // turn the commit endpoint into an oracle for the confirmation's internal
      // structure — `decodeDavPayload`'s discipline, one module over.
      expect(SAFE_MESSAGES.confirmation_invalid.toLowerCase()).not.toContain(
        forbidden,
      );
    },
  );

  it("still tells the caller what to do about a rejected confirmation", () => {
    // Naming no cause is not the same as saying nothing. The model needs to
    // know that the answer is a fresh preview rather than a retry of the same
    // commit, or it will loop on a refusal that can never change.
    expect(SAFE_MESSAGES.confirmation_invalid).toContain("was not accepted");
    expect(SAFE_MESSAGES.confirmation_invalid).toContain(
      "Preview the change again",
    );
  });
});

describe("toErrorCategory", () => {
  it("maps each error class to its category", () => {
    expect(toErrorCategory(new ImapAuthError()).category).toBe("auth_failed");
    expect(toErrorCategory(new ImapThrottleError()).category).toBe(
      "rate_limited",
    );
    expect(toErrorCategory(new ImapConnectError()).category).toBe(
      "connection_failed",
    );
    expect(toErrorCategory(new ImapNotFoundError()).category).toBe("not_found");
  });

  it("reaches not_found without the vocabulary growing a member for it", () => {
    // `not_found` was reserved and unreachable through Phase 1. Phase 2 adds
    // the class that arrives at it — a category becoming REACHABLE, not a new
    // category being invented. Phase 5 does the same thing twice more, from the
    // DAV tree. The count assertion is the guard: a member added alongside a
    // class rather than in a deliberate vocabulary edit would fail here and in
    // the `EVERY_CATEGORY` record above, which `npx tsc --noEmit` checks.
    expect(toErrorCategory(new ImapNotFoundError()).category).toBe("not_found");
    expect(CATEGORIES).toHaveLength(7);

    const produced = new Set(
      EVERY_INPUT.map((input) => toErrorCategory(input).category),
    );
    // The IMAP tree reaches four of the seven. The three categories that
    // arrived after Phase 1 (the two from Phase 5, plus
    // `subscription_unreadable`) are raised from the DAV tree only, which is
    // why this is a subset assertion and not an equality one — the equality
    // lives in the reachability case at the bottom of this file, over BOTH
    // translation functions.
    expect(produced.size).toBeLessThanOrEqual(4);
    for (const category of produced) {
      expect(CATEGORIES).toContain(category);
    }
  });

  it("returns connection_failed with its fixed message for null, undefined, '' and {}", () => {
    // The four the edge probe named, asserted individually so a failure names
    // which input broke rather than which loop iteration did.
    for (const input of [null, undefined, "", {}]) {
      const result = toErrorCategory(input);
      expect(result.category).toBe("connection_failed");
      expect(result.message).toBe(SAFE_MESSAGES.connection_failed);
    }
  });

  it("never throws, whatever it is handed", () => {
    for (const input of EVERY_INPUT) {
      expect(() => toErrorCategory(input)).not.toThrow();
    }
  });

  it("can only ever produce a member of the closed vocabulary", () => {
    // Exhaustive over the input space rather than a spot check: every value
    // the boundary could receive lands inside the closed vocabulary.
    for (const input of EVERY_INPUT) {
      const result = toErrorCategory(input);
      expect(CATEGORIES).toContain(result.category);
      expect(result.message).toBe(SAFE_MESSAGES[result.category]);
    }
  });

  it("returns only the category and its message — no other field escapes", () => {
    expect(Object.keys(toErrorCategory(new ImapAuthError())).sort()).toEqual([
      "category",
      "message",
    ]);
  });
});

describe("the connection-limit detail (WINDOWS.md ledger entry 6)", () => {
  const REFUSAL = "[UNAVAILABLE] Too many simultaneous connections";

  it("keeps the vocabulary at its declared size", () => {
    // The gate on this whole change. A refusal that now carries text is still
    // a `rate_limited`, not a category invented to hold the text.
    expect(toErrorCategory(new ImapThrottleError(REFUSAL)).category).toBe(
      "rate_limited",
    );
    expect(CATEGORIES).toHaveLength(7);
    expect([...CATEGORIES].sort()).toEqual(SORTED_CATEGORIES);
  });

  it("translates to the same category and the same fixed message with or without a detail", () => {
    // The detail rides in a dedicated field that only the tool boundary reads,
    // never in the message. If it ever leaked into the message the translation
    // would stop being a constant lookup, which is the property the whole
    // FND-05 boundary rests on.
    const bare = toErrorCategory(new ImapThrottleError());
    const detailed = toErrorCategory(new ImapThrottleError(REFUSAL));

    expect(detailed).toEqual(bare);
    expect(detailed.message).toBe(SAFE_MESSAGES.rate_limited);
    expect(detailed.message).not.toContain(REFUSAL);
    expect(JSON.stringify(detailed)).not.toContain(REFUSAL);
  });

  it("still returns only the category and its message", () => {
    // The added constructor argument must not add a returned field. This is
    // the assertion that catches a well-meaning "pass the detail through too".
    expect(
      Object.keys(toErrorCategory(new ImapThrottleError(REFUSAL))).sort(),
    ).toEqual(["category", "message"]);
  });

  it("carries the detail on the error itself, unmodified apart from length", () => {
    expect(new ImapThrottleError(REFUSAL).detail).toBe(REFUSAL);
    expect(new ImapThrottleError().detail).toBeNull();
    // The message is the fixed internal label regardless, so no caller reading
    // `.message` can reach the server's text even by accident.
    expect(new ImapThrottleError(REFUSAL).message).toBe(
      new ImapThrottleError().message,
    );
  });
});

describe("credential containment at the error boundary", () => {
  // The values bound for tests. They are fakes, and the real Secrets are never
  // present locally — but the assertion is about the mechanism, and the
  // mechanism cannot tell a fake password from a real one.
  //
  // Narrowed by assertion, never by a coalesce: `?? ""` would typecheck and
  // keep every case below green while making `not.toContain("")` trivially
  // true, which is exactly what the non-zero-length case guards against.
  const entry = entryEnv();
  assertMailSecretsBound(entry);
  const fakeAppleId = entry.APPLE_ID;
  const fakePassword = entry.APPLE_APP_PASSWORD;

  it("has fake credentials to test against", () => {
    expect(fakeAppleId.length).toBeGreaterThan(0);
    expect(fakePassword.length).toBeGreaterThan(0);
  });

  it("does not surface a credential embedded in a caught error's message", () => {
    // This is the concrete proof that the function dispatches on TYPE rather
    // than reading `.message`. IMAP puts the app-specific password inline in
    // the LOGIN command, so a transport error raised while those bytes are in
    // flight can carry the whole credential in its text.
    const leaky = new Error(
      `a7 LOGIN "${fakeAppleId}" "${fakePassword}" failed`,
    );

    const serialized = JSON.stringify(toErrorCategory(leaky));

    expect(serialized).not.toContain(fakePassword);
    expect(serialized).not.toContain(fakeAppleId);
  });

  it("does not surface a credential embedded in a caught error's stack", () => {
    const leaky = new Error("transport failed");
    leaky.stack = `Error: transport failed\n  at write("a7 LOGIN ${fakeAppleId} ${fakePassword}")`;

    const serialized = JSON.stringify(toErrorCategory(leaky));

    expect(serialized).not.toContain(fakePassword);
    expect(serialized).not.toContain(fakeAppleId);
  });

  it("does not surface a credential embedded in a not_found refusal", () => {
    // The new class is on the same footing as the other three. It is the one
    // most likely to be raised while caller-supplied text is in hand — a token
    // that failed to decode — so the containment claim is asserted for it
    // directly rather than inherited from the classes above.
    const leaky = new ImapNotFoundError();
    leaky.message = `token for ${fakeAppleId} rejected: ${fakePassword}`;

    const serialized = JSON.stringify(toErrorCategory(leaky));

    expect(serialized).not.toContain(fakePassword);
    expect(serialized).not.toContain(fakeAppleId);
    expect(JSON.parse(serialized).category).toBe("not_found");
    expect(JSON.parse(serialized).message).toBe(SAFE_MESSAGES.not_found);
  });

  it("does not surface a credential carried in the connection-limit detail", () => {
    // The new field is on the same footing as the classes above rather than
    // exempt from them. In production its value comes from a parsed server
    // reply and structurally cannot hold the credential — but the containment
    // claim is about the mechanism, and the mechanism must hold even when the
    // field is handed something it could never really receive.
    const leaky = new ImapThrottleError(
      `a3 NO too many connections for "${fakeAppleId}" "${fakePassword}"`,
    );

    const serialized = JSON.stringify(toErrorCategory(leaky));

    expect(serialized).not.toContain(fakePassword);
    expect(serialized).not.toContain(fakeAppleId);
    expect(JSON.parse(serialized).category).toBe("rate_limited");
    expect(JSON.parse(serialized).message).toBe(SAFE_MESSAGES.rate_limited);
  });

  it("does not surface a credential carried by a recognised error class", () => {
    // Belt and braces: even if one of our own classes were somehow given
    // context, the translation must not pass it through.
    const recognised = new ImapAuthError();
    recognised.message = `rejected ${fakePassword}`;

    const serialized = JSON.stringify(toErrorCategory(recognised));

    expect(serialized).not.toContain(fakePassword);
    expect(JSON.parse(serialized).category).toBe("auth_failed");
  });
});

describe("every category is reachable, and every reachable answer is a category", () => {
  /**
   * Every shipped error class, across BOTH protocol trees.
   *
   * The two trees share a vocabulary and nothing else at runtime, so neither
   * translation function can prove this on its own: the IMAP tree reaches four
   * of the seven, and the three categories that arrived after Phase 1 are
   * raised only from the DAV side. The union is the only thing the claim can
   * be made over.
   */
  const REACHABLE_CATEGORIES = new Set<ErrorCategory>([
    ...[
      new ImapAuthError(),
      new ImapConnectError(),
      new ImapThrottleError(),
      new ImapNotFoundError(),
    ].map((err) => toErrorCategory(err).category),
    ...[
      new DavAuthError(),
      new DavConnectError(),
      new DavThrottleError(),
      new DavNotFoundError(true),
      new DavNotFoundError(false),
      new DavStaleResourceError(),
      new DavConfirmationError(),
      new DavSubscriptionError(),
    ].map((err) => davToErrorCategory(err).category),
  ]);

  it("matches SAFE_MESSAGES exactly, in both directions", () => {
    // Both directions, and they catch different failures.
    //
    // A category in `SAFE_MESSAGES` that nothing above produces is the hazard
    // `src/errors.ts`'s own header names: a value in the model's vocabulary
    // that no code path can reach. That was the state of `stale_resource` and
    // `confirmation_invalid` for four phases, deliberately — this assertion is
    // what says the deliberate window has closed.
    //
    // A category produced above that `SAFE_MESSAGES` lacks is the same hazard
    // wearing the other hat: a class whose branch was never added to its
    // translation chain, which is exactly what a six-branch chain edited by
    // hand invites. It cannot happen while both functions return
    // `SAFE_MESSAGES[category]`, and asserting it anyway is what keeps that
    // from being a property nobody is checking.
    expect([...REACHABLE_CATEGORIES].sort()).toEqual(
      [...Object.keys(SAFE_MESSAGES)].sort(),
    );
  });

  it("counts connection_failed once, and not because of the default arm", () => {
    // `connection_failed` is reachable twice over: from the explicit
    // `DavConnectError` / `ImapConnectError` branches, and from the
    // fall-through default that catches `null`, a string, or a tsdav bare
    // Error. The set above collapses the two, which is correct — but it means
    // a future edit deleting the explicit branch would leave the equality case
    // green for the wrong reason. This is the case that would go red instead.
    expect(toErrorCategory(new ImapConnectError()).category).toBe(
      "connection_failed",
    );
    expect(davToErrorCategory(new DavConnectError()).category).toBe(
      "connection_failed",
    );
    expect(toErrorCategory(null).category).toBe("connection_failed");
    expect(davToErrorCategory(null).category).toBe("connection_failed");
  });

  it("gives every reachable category its own fixed message", () => {
    // The pairing, not merely the naming: a class that reached the right
    // category while returning some other category's message would satisfy the
    // equality above.
    for (const category of REACHABLE_CATEGORIES) {
      expect(SAFE_MESSAGES[category].length).toBeGreaterThan(0);
    }
    expect(davToErrorCategory(new DavStaleResourceError()).message).toBe(
      SAFE_MESSAGES.stale_resource,
    );
    expect(davToErrorCategory(new DavConfirmationError()).message).toBe(
      SAFE_MESSAGES.confirmation_invalid,
    );
  });
});

describe("the DAV categoriser and the principal module's refusal (Phase 9 D-10)", () => {
  it("answers the principal module's auth error exactly as it answers the DAV auth error", () => {
    // A DAV tool callback awaits the promise of the principal. With an unset
    // or bad secret that promise rejects with the MAIL tree's auth error class,
    // because that is the one error the principal module raises. Read as a
    // connection fault it would invite a retry, and retries against a bad
    // credential are how an account gets locked.
    //
    // The whole result object is compared with the DAV auth error's, so the
    // category and the fixed text are both pinned without the text being typed
    // a second time here (D-05: the text does not change).
    const forDav = davToErrorCategory(new DavAuthError());
    expect(forDav.category, "the control itself is wrong").toBe("auth_failed");
    expect(forDav.message.length).toBeGreaterThan(0);

    expect(
      davToErrorCategory(new ImapAuthError()),
      "the principal module's refusal does not read auth_failed on the DAV side",
    ).toEqual(forDav);
  });

  it("still answers a plain Error with connection_failed", () => {
    // The widened first branch must not have become a catch-all. A bare Error
    // is what the DAV library throws, and it stays on the floor.
    expect(davToErrorCategory(new Error("anything")).category).toBe(
      "connection_failed",
    );
    // Nor may any other mail-tree class ride in on the widened branch.
    expect(davToErrorCategory(new ImapConnectError()).category).toBe(
      "connection_failed",
    );
    expect(davToErrorCategory(new ImapThrottleError()).category).toBe(
      "connection_failed",
    );
  });
});

describe("DavSubscriptionError and subscription_unreadable", () => {
  it("maps to subscription_unreadable, never to not_found", () => {
    // The class this project trades one confident falsehood for another by
    // NOT raising: the calendar exists and calendar_list_calendars already
    // listed it, so not_found would tell the model something false a second
    // way.
    const { category } = davToErrorCategory(new DavSubscriptionError());
    expect(category).toBe("subscription_unreadable");
    expect(category).not.toBe("not_found");
  });

  it("carries no constructor argument and no field a URL could ride in", () => {
    // The CS:source href is a URL on a third-party host, and the error
    // boundary is the last place it should ride out. Asserted structurally
    // rather than by convention: the class's own shape makes a URL
    // unspeakable here, on the same footing DavConfirmationError and
    // DavStaleResourceError already sit on.
    const err = new DavSubscriptionError();
    expect(Object.keys(err).sort()).toEqual(["kind", "name"].sort());
    expect(err.message).toBe("dav-subscription-not-readable");
  });

  it("tells the model the calendar is not empty, and forbids reporting it as such", () => {
    // The one sentence that has to be here rather than in a comment: without
    // it, the first genuine occurrence reads as a bug and gets fixed by
    // reporting eventCount: 0 again -- exactly the false-empty answer this
    // category exists to prevent.
    expect(SAFE_MESSAGES.subscription_unreadable).toContain(
      "NOT the same as the calendar being empty",
    );
    expect(SAFE_MESSAGES.subscription_unreadable).toContain(
      "do not report it as having no events",
    );
    expect(SAFE_MESSAGES.subscription_unreadable).toContain(
      "Retrying will not help",
    );
  });
});
