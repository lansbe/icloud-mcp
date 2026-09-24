// The FND-05 error boundary: a closed vocabulary of exactly eight categories,
// and a translation function that dispatches on type rather than on text.
//
// Four through Phases 1-4. Two more arrived in Phase 5 (CALW-05 and CALW-04),
// in one edit, because a category that exists before anything can raise it is
// the hazard `src/errors.ts`'s own header names. A seventh,
// `subscription_unreadable`, arrived with quick task 260822-h1c, from the DAV
// side only, on the same footing. An eighth, `request_unsendable`, arrived in
// Phase 14 on that same footing and for a reason the others did not have: it
// was added AFTER a wrong answer had already been produced and read. workerd
// refuses to build a request carrying `MKCALENDAR`, the throw landed in the
// DAV transport's catch, and the probe reported `connection_failed` against a
// server it had never contacted -- a failure that says nothing about iCloud,
// dressed as a transient fault the model is told to retry.

import { describe, expect, it } from "vitest";
// Namespace imports, used by the reachability set-equality at the foot of this
// file and by nothing else. Reading the modules' own exports is what makes
// that assertion capable of failing: a hand-written list of error classes
// would agree with itself by construction, and a class added without a
// dispatcher branch would appear on neither side.
import * as davErrorsModule from "../src/dav/errors";
import * as imapErrorsModule from "../src/errors";
import {
  DavAuthError,
  DavConfirmationError,
  DavConnectError,
  DavNotFoundError,
  DavStaleResourceError,
  DavSubscriptionError,
  DavThrottleError,
  DavUnsendableError,
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
import { FAKE_APP_PASSWORD, FAKE_APPLE_ID } from "./fixtures/bound-secrets";

/**
 * The eight values the vocabulary now holds, listed exhaustively.
 *
 * The record below is the type-level half of the exhaustiveness claim: adding
 * a ninth member to `ErrorCategory` makes it a compile error, and removing
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
  request_unsendable: true,
};

const CATEGORIES = Object.keys(EVERY_CATEGORY) as ErrorCategory[];

/** The eight, sorted, so every set assertion below reads from one place. */
const SORTED_CATEGORIES = [
  "auth_failed",
  "confirmation_invalid",
  "connection_failed",
  "not_found",
  "rate_limited",
  "request_unsendable",
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
  it("is exactly the eight values the vocabulary now holds, with no ninth", () => {
    expect(CATEGORIES).toHaveLength(8);
    expect([...CATEGORIES].sort()).toEqual(SORTED_CATEGORIES);
  });

  it("has one fixed safe message per category and no others", () => {
    expect(Object.keys(SAFE_MESSAGES)).toHaveLength(8);
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

  it("tells the signed-in person the recovery that actually exists", () => {
    // Asserted by VALUE rather than by substring. This text is a contract —
    // 11-UI-SPEC.md carries it verbatim — and the two things it must not lose
    // are the action and the clause that stops a client looping. A paraphrase
    // check built out of the same words would survive losing either.
    //
    // The old wording told a human to check the app-specific password. That
    // stopped being true at the Phase 11 switch, in two ways at once: the
    // person who must act is the signed-in user rather than the owner, and the
    // fix is a fresh sign-in rather than an owner editing a Worker secret.
    expect(SAFE_MESSAGES.auth_failed).toBe(
      "iCloud rejected the password saved for this connection. Reconnect " +
        "this server in your Claude app and sign in again; retrying will not " +
        "help.",
    );
  });

  it.each(["mail", "mailbox", "imap", "calendar", "contact"])(
    "recovers from a dead credential without ever naming %s",
    (forbidden) => {
      // The same string is served on a calendar call and on a contacts call,
      // so a sentence naming mail would be wrong two thirds of the time — and
      // wrong in the direction that sends the reader to look at the wrong
      // thing. The three strings that arrived after Phase 1 are neutral for
      // the same reason; this one joined them when it was reworded.
      expect(SAFE_MESSAGES.auth_failed.toLowerCase()).not.toContain(forbidden);
    },
  );

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
    expect(CATEGORIES).toHaveLength(8);

    const produced = new Set(
      EVERY_INPUT.map((input) => toErrorCategory(input).category),
    );
    // The IMAP tree reaches four of the eight. The four categories that
    // arrived after Phase 1 (the two from Phase 5, plus
    // `subscription_unreadable` and `request_unsendable`) are raised from the
    // DAV tree only, which is why this is a subset assertion and not an
    // equality one — the equality lives in the reachability case at the bottom
    // of this file, over BOTH translation functions.
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
    expect(CATEGORIES).toHaveLength(8);
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
  // The two fake credentials the fixture owns. They are fakes, and the real
  // Secrets are never present locally — but the assertion is about the
  // mechanism, and the mechanism cannot tell a fake password from a real one.
  //
  // They are read from the fixture, never off an environment object, and never
  // through a coalesce onto an empty string, which would typecheck and keep
  // every case below green while making `not.toContain("")` trivially true —
  // exactly what the non-zero-length case guards against. The fixture's own
  // header says why, and says it without spelling the operator.
  const fakeAppleId = FAKE_APPLE_ID;
  const fakePassword = FAKE_APP_PASSWORD;

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
   * of the eight, and the four categories that arrived after Phase 1 are
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
      new DavUnsendableError(),
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

describe("the wait outcome is one answer, not two that happen to agree (CONF-06)", () => {
  // The IMAP half of the end-to-end proof whose DAV half lives in
  // `test/dav-transport.test.ts`, asserted here beside it deliberately.
  //
  // The two trees share a vocabulary and nothing else at runtime, and each has
  // its own class for a server asking the caller to wait. Two correct answers
  // that were never compared are two answers, and one of them can drift. What
  // makes this a single answer is that both dispatchers return the same entry
  // of the same table, and that is asserted rather than assumed.

  it("reads the IMAP throttle class as the wait category, exactly as a 429 does", () => {
    expect(toErrorCategory(new ImapThrottleError()).category).toBe("rate_limited");
    expect(davToErrorCategory(new DavThrottleError()).category).toBe(
      "rate_limited",
    );
  });

  it("hands both sides the identical fixed sentence, read from the shipped table", () => {
    const imap = toErrorCategory(new ImapThrottleError());
    const dav = davToErrorCategory(new DavThrottleError());

    expect(imap.message).toBe(SAFE_MESSAGES.rate_limited);
    expect(dav.message).toBe(SAFE_MESSAGES.rate_limited);

    // Not implied by the two above: a table whose entry was read twice still
    // proves nothing if a dispatcher were ever changed to compose its own
    // string. This is the assertion that the two callers are one answer.
    expect(imap.message).toBe(dav.message);
  });

  it("keeps the server's own refusal text out of the sentence the caller reads", () => {
    // `ImapThrottleError` is the one class in `src/errors.ts` that takes a
    // constructor argument, and the argument is the server's own reply text.
    // It rides in a dedicated field the tool boundary surfaces after a type
    // check; it must never reach `message`, or the fixed-string guarantee the
    // whole table rests on would hold only for the bare form.
    const carrying = toErrorCategory(
      new ImapThrottleError("[UNAVAILABLE] Too many simultaneous connections"),
    );

    expect(carrying.category).toBe("rate_limited");
    expect(carrying.message).toBe(SAFE_MESSAGES.rate_limited);
    expect(carrying.message).not.toContain("simultaneous");
  });

  it("gives the wait sentence to the wait category and to nothing else", () => {
    // The distinctness claim, stated about THIS string rather than about the
    // table as a whole. The table-wide "no two alike" case above would stay
    // green if the wait sentence and the floor's sentence were merged into one
    // new string used by both — the count of distinct values would not move.
    for (const category of CATEGORIES) {
      if (category === "rate_limited") continue;
      expect(SAFE_MESSAGES[category]).not.toBe(SAFE_MESSAGES.rate_limited);
    }
  });
});

describe("the floor, and what it is allowed to promise (CONF-06)", () => {
  it("still holds exactly eight categories, with no ninth added beside the wait outcome", () => {
    // Stated here as well as in the vocabulary block above, because THIS is
    // the plan that had the obvious reason to add one. A server asking the
    // caller to wait already has its own entry; inventing a second beside it
    // would have put a category in the model's vocabulary that duplicates a
    // shipped one, which is the hazard `src/errors.ts`'s own header names from
    // the other direction.
    expect(CATEGORIES).toHaveLength(8);
    expect(Object.keys(SAFE_MESSAGES)).toHaveLength(8);
    expect(CATEGORIES).not.toContain("throttled");
    expect(CATEGORIES).not.toContain("service_unavailable");
  });

  it("no longer tells the caller an unclassified failure is safe to retry once", () => {
    // The sentence Phase 14's collection write probe produced for a failure
    // that was neither transient nor retryable. `request_unsendable` closed
    // that particular hole by adding a CLASS; this closes what remains, which
    // is every OTHER unclassified value that still lands here.
    //
    // Asserted by VALUE, not by substring. The claim is about what the string
    // promises, and a promise can be restored in different words — a substring
    // check for the old phrasing would pass against a paraphrase of it.
    expect(SAFE_MESSAGES.connection_failed).not.toContain("safe to retry once");
    expect(SAFE_MESSAGES.connection_failed).toBe(
      "Could not establish a secure connection to iCloud Mail. This is what " +
        "this server reports when it cannot tell what went wrong, so it may " +
        "or may not be transient. Retry once at most — if it happens again, " +
        "the cause is not transient and retrying will not help.",
    );
  });

  it("still names iCloud Mail in its first clause, which is a separate decision", () => {
    // The small inaccuracy on a calendar call, accepted deliberately and
    // recorded in `src/dav/errors.ts`. Pinned so a reword of the retry clause
    // cannot quietly take the naming with it: that would touch shipped Phase 1
    // and 2 responses, and it is not this plan's decision to take.
    expect(SAFE_MESSAGES.connection_failed).toContain(
      "Could not establish a secure connection to iCloud Mail.",
    );
  });

  it("still gives the caller a recovery, and one distinct from every other entry", () => {
    // Closing the promise must not close the guidance. A floor that said only
    // "something failed" would leave the model to invent its own policy, and
    // the policy it invents is a loop.
    expect(SAFE_MESSAGES.connection_failed).toContain("Retry once at most");
    expect(SAFE_MESSAGES.connection_failed).toContain("will not help");
    for (const category of CATEGORIES) {
      if (category === "connection_failed") continue;
      expect(SAFE_MESSAGES[category]).not.toBe(SAFE_MESSAGES.connection_failed);
    }
  });

  it("still catches every undesigned value without throwing", () => {
    // The floor's actual job, unchanged by the reword. A `catch` in this
    // runtime receives whatever was thrown, and the translation boundary must
    // answer for all of it.
    for (const thrown of [new Error("plain"), null, undefined, "", {}]) {
      expect(toErrorCategory(thrown).category).toBe("connection_failed");
      expect(davToErrorCategory(thrown).category).toBe("connection_failed");
    }
  });
});

describe("every error class this repository exports is named in a dispatcher branch", () => {
  // The other direction of the reachability claim above, and the one that
  // claim cannot make.
  //
  // `REACHABLE_CATEGORIES` proves every CATEGORY is raisable and that every
  // raisable answer is a category. It says nothing about a CLASS. A new error
  // class added to either module without a matching branch falls silently to
  // the default and becomes indistinguishable from an unclassified third-party
  // error — which is precisely the failure `DavUnsendableError` was added in
  // Phase 14 to repair, after it had already happened once and the wrong
  // answer had been read as a measurement of iCloud's behaviour.
  //
  // So the equality below is between the classes the two modules EXPORT and
  // the classes the two dispatchers NAME. The export side is read off the
  // modules rather than restated, so a class added later lands on one side
  // only.

  /** Every error class a module exports, read from the module itself. */
  function exportedErrorClasses(
    module: unknown,
  ): Map<string, new () => Error> {
    const found = new Map<string, new () => Error>();
    for (const [name, value] of Object.entries(
      module as Record<string, unknown>,
    )) {
      if (typeof value === "function" && value.prototype instanceof Error) {
        found.set(name, value as new () => Error);
      }
    }
    return found;
  }

  const EXPORTED_ERROR_CLASSES = new Map<string, new () => Error>([
    ...exportedErrorClasses(imapErrorsModule),
    ...exportedErrorClasses(davErrorsModule),
  ]);

  /**
   * The category every unrecognised value falls to, read from the code rather
   * than written down, so this stays true if the default is ever moved.
   */
  const DEFAULT_CATEGORY = toErrorCategory(new Error("unclassified")).category;

  /**
   * The classes whose branch legitimately produces the default category.
   *
   * Recorded as an EXACT LIST with a reason each rather than tolerated, on the
   * precedent of the prefix-shadow exception in
   * `test/forbidden-tokens.test.ts`. Without the list this equality could not
   * be written at all: these two ARE branched, and their branch answers with
   * the default, so "produces something other than the default" would call
   * them unbranched and the assertion would be red on shipped, correct code.
   *
   * With the list, adding an entry is how somebody would silence a genuinely
   * unbranched class — which is why the case below refuses an entry whose
   * class a dispatcher gives a category of its own, and pins the list's
   * contents exactly.
   */
  const RESTATES_THE_DEFAULT: Record<string, string> = {
    ImapConnectError:
      "the explicit IMAP floor — the transport genuinely failed, which is the same thing the default already says",
    DavConnectError:
      "the last branch of the DAV chain by constraint, because it restates the default; nothing is ever appended below it",
  };

  /** True when either dispatcher gives this value an answer of its own. */
  function namedByADispatcher(thrown: Error): boolean {
    return (
      toErrorCategory(thrown).category !== DEFAULT_CATEGORY ||
      davToErrorCategory(thrown).category !== DEFAULT_CATEGORY
    );
  }

  it("reads both modules' exports, rather than a list that agrees with itself", () => {
    // The vacuity guard. Set equality between two empty sets passes, so a
    // namespace read that came back with nothing — a bundler change, a barrel
    // file, a rename — would turn the case below green for the worst possible
    // reason.
    //
    // The number is pinned rather than bounded, and it is meant to be edited:
    // adding an error class to either module should be a deliberate act that
    // fails a test until somebody says so. A number in a test goes stale
    // LOUDLY, which is the opposite of one written in prose.
    expect(
      EXPORTED_ERROR_CLASSES.size,
      "four Imap* classes and eight Dav* classes ship today",
    ).toBe(12);
    expect([...EXPORTED_ERROR_CLASSES.keys()]).toContain("ImapThrottleError");
    expect([...EXPORTED_ERROR_CLASSES.keys()]).toContain("DavUnsendableError");
  });

  it("matches the exported classes against the branched ones, in both directions", () => {
    const branched = [...EXPORTED_ERROR_CLASSES.entries()]
      .filter(
        ([name, klass]) =>
          namedByADispatcher(new klass()) || name in RESTATES_THE_DEFAULT,
      )
      .map(([name]) => name);

    // A class on the export side and not the branched side is a class that
    // falls silently to the floor. A name on the branched side and not the
    // export side cannot happen while the branched side is filtered from the
    // export side — asserted anyway, because that filtering is an
    // implementation detail of this case and not a property of the code.
    expect(branched.sort()).toEqual([...EXPORTED_ERROR_CLASSES.keys()].sort());
  });

  it("refuses an exception entry for a class a dispatcher actually answers for", () => {
    // Guards the guard. The exception list is the one way to make the equality
    // above pass without adding a branch, so every entry has to earn its place
    // twice: it must name a class the modules really export, and a dispatcher
    // must really hand it the default.
    expect(Object.keys(RESTATES_THE_DEFAULT).sort()).toEqual([
      "DavConnectError",
      "ImapConnectError",
    ]);

    for (const [name, reason] of Object.entries(RESTATES_THE_DEFAULT)) {
      const klass = EXPORTED_ERROR_CLASSES.get(name);
      expect(
        klass,
        `${name} is on the exception list but is not an exported error class`,
      ).toBeDefined();

      expect(
        reason.length,
        `${name} is on the exception list with no reason worth reading`,
      ).toBeGreaterThan(30);

      const instance = new klass!();
      expect(
        namedByADispatcher(instance),
        `${name} is on the exception list but a dispatcher gives it a category of its own — take it off`,
      ).toBe(false);
    }
  });

  it("keeps DavConnectError last, so nothing is appended below the floor", () => {
    // The ORDER constraint `davToErrorCategory`'s docstring states, asserted
    // from the outside. A branch appended after the connect branch would sit
    // below the floor while looking like a peer of the others: it could never
    // be reached, and every case above would stay green, because its class
    // would still be exported and the equality only asks whether SOME
    // dispatcher answers for it.
    //
    // This is the assertion that would catch it — the appended class would
    // reach the default instead of its own category, and so would fail the
    // equality by not being in the exception list. Stated here explicitly so
    // the constraint is visible at the place it is checked.
    expect(davToErrorCategory(new DavConnectError()).category).toBe(
      DEFAULT_CATEGORY,
    );
    expect(davToErrorCategory(new DavUnsendableError()).category).not.toBe(
      DEFAULT_CATEGORY,
    );
  });
});
