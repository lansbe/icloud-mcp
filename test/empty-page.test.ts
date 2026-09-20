// The shared empty page cannot be changed by a caller (audit row N2).
//
// WHAT THIS FILE PROVES. The mail service keeps one empty page at module scope
// and hands it to every caller by reference. Inside one isolate that object is
// shared between users. So a caller that could write to it would change what
// the next caller reads. These tests show that a write to the returned page
// throws, and that the next caller still gets an empty page.
//
// WHAT IT CANNOT PROVE. It drives ONE of the two return sites that hand the
// constant out by reference: the listing call whose cursor rests on the lowest
// identifier. The second site (a search that found nothing) returns the very
// same constant, so the same freeze covers it, but no test here reaches it. The
// third site (the server declined the charset) builds a fresh outer object by
// spreading the constant. That copy still shares the constant's inner array,
// which is why the inner array is frozen too. No test here reaches that site
// either.
//
// WHAT WOULD MAKE IT PASS FOR THE WRONG REASON. A scripted conversation that
// broke before the page came back would make every test here fail, and a
// failure says nothing about a freeze. So the first test is a control. It only
// checks that the call gives an empty page. It was green before the freeze and
// after it, while the write tests were red before the freeze. Without the
// control, that red run would have shown nothing.
//
// WHY ITS OWN FILE. Phase 8 edits no existing test file beyond the ones its
// decisions name (D-17). The few local helpers below are copies from the
// service test, and each says so.
//
// Every call here runs over the in-memory duplex. Nothing opens a connection
// and nothing reads a real credential. The mailbox is opened in its read-only
// form, as every mailbox in this project is. The ambient environment object is
// only read, never written.
//
// This file contains no logging calls of any kind and must never acquire any.

import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { encodeCursor } from "../src/mail/ids";
import { createSessionGate, listMessagesOver } from "../src/mail/service";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  examineResponse,
  logoutExchange,
  taggedOk,
} from "./fixtures/icloud-bytes";
import type { Principal } from "../src/principal";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// The owner's principal, from the real env constructor over the pool's
// ambient environment. Resolved once, and the very same object is handed to
// every call: the password reader answers only the object a constructor
// built, so it is never spread and never cloned.
let principal: Principal;
beforeAll(async () => {
  principal = await ownerPrincipal();
});

/** The mailbox every call here opens. A copy of the service test's constant. */
const MAILBOX = "INBOX";

/**
 * Bounds a few milliseconds wide, so no case here waits out a real timeout.
 *
 * A copy of the four values in the service test. Copied, not imported, because
 * that file exports nothing and must not be edited to start.
 */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/**
 * The four turns every mail session opens with, then the read-only mailbox open.
 *
 * A rebuild of the service test's local helper of the same name. The fifth turn
 * uses the fixture's own export, which carries the validity line and the
 * read-only completion. That is all this path needs.
 */
function listingPrefix(): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    examineResponse("a4"),
  ];
}

/**
 * A cursor resting on the lowest identifier.
 *
 * Nothing sits below it, so the service answers with its shared empty page and
 * sends no search at all. That makes this the cheapest path to the constant.
 * The validity is the one the scripted mailbox reports, so the validity gate
 * lets the call through.
 */
function lowestCursor(): string {
  return encodeCursor({
    mailbox: MAILBOX,
    uidValidity: INBOX_UIDVALIDITY,
    lastUid: 1,
  });
}

/**
 * One whole call, as one caller would make it.
 *
 * Every call builds its OWN duplex and its OWN session gate. Two callers share
 * nothing here except what the service module itself shares between them, and
 * that is the thing under test.
 */
async function emptyPageCall() {
  const duplex = createFakeDuplex([...listingPrefix(), logoutExchange("a5")]);
  const page = await listMessagesOver(duplex, principal, createSessionGate(), MAILBOX, {
    ...FAST_BOUNDS,
    cursor: lowestCursor(),
  });
  return { page, duplex };
}

/** A made-up row. It stands for one user's message showing up for another. */
const SOMEONE_ELSES_ROW = { uid: 1, subject: "a row that belongs to someone else" };

describe("the shared empty page", () => {
  it("control: a cursor resting on the lowest identifier gives an empty page", async () => {
    const { page, duplex } = await emptyPageCall();

    expect(page.messages).toEqual([]);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    // No search reached the wire. So this call took the early return, which is
    // the site that hands the constant out by reference.
    expect(duplex.writtenLines().some((line) => line.includes("SEARCH"))).toBe(
      false,
    );
  });

  it("throws when a caller writes to the page it was given", async () => {
    const { page } = await emptyPageCall();

    expect(() => {
      (page.messages as unknown[]).push(SOMEONE_ELSES_ROW);
    }).toThrow(TypeError);
    expect(() => {
      (page as { hasMore: boolean }).hasMore = true;
    }).toThrow(TypeError);
  });

  it("gives the next caller an empty page after an earlier caller tried to write", async () => {
    const first = await emptyPageCall();
    // Caught, so this test reaches the second call whether or not the writes
    // throw. Before the freeze they did not throw, and the row below is what
    // the second caller then saw.
    try {
      (first.page.messages as unknown[]).push(SOMEONE_ELSES_ROW);
    } catch {
      // A frozen array refuses the push. That is the wanted outcome.
    }
    try {
      (first.page as { hasMore: boolean }).hasMore = true;
    } catch {
      // A frozen object refuses the write. That is the wanted outcome.
    }

    const second = await emptyPageCall();

    expect(second.page.messages).toEqual([]);
    expect(second.page.hasMore).toBe(false);
    expect(second.page.nextCursor).toBeNull();
  });

  it("hands out a page that is frozen, and so is its list of rows", async () => {
    const { page } = await emptyPageCall();

    expect(Object.isFrozen(page)).toBe(true);
    expect(Object.isFrozen(page.messages)).toBe(true);
  });
});
