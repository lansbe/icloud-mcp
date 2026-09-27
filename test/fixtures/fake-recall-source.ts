// A scripted mailbox for the recall build tests (Phase 25, plan 25-02).
//
// Stands in for the IMAP page source Phase 26 will write. It serves pages of up
// to 25 messages, newest first, below the cursor's last UID, and records every
// call with the cursor it was given. A test can tell it to throw on the next
// page, to wait on a promise the test controls, to change its UIDVALIDITY, or
// to report a UID list other than its messages.
//
// It never reads the gate it is handed: the engine is what is under test, and
// the gate is only threaded through.

import type { PageCursor } from "../../src/mail/ids";
import type { Principal } from "../../src/principal";
import type { RecallPage, RecallSource } from "../../src/recall/build";

/** One message in the scripted mailbox. */
export interface FakeMessage {
  readonly uid: number;
  /** ms since the epoch. */
  readonly date: number;
  readonly text: string;
  readonly snippet: string;
}

/** One recorded call. */
export interface FakeSourceCall {
  readonly kind: "page" | "uids";
  readonly mailbox: string;
  readonly cursor: PageCursor | null;
}

/** The fake source, plus the controls a test drives it with. */
export interface FakeRecallSource extends RecallSource {
  readonly calls: FakeSourceCall[];
  /** Change the mailbox's UIDVALIDITY from now on. */
  setValidity(value: number): void;
  /** Report this UID list from `uids` instead of the messages' own. */
  setUids(uids: number[] | null): void;
  /** Make the next page call throw. */
  failNextPage(): void;
  /** Make the next page call wait until the returned function is called. */
  holdNextPage(): () => void;
  /** Called at the start of every page call, before anything else. */
  onPage: (() => Promise<void> | void) | null;
}

const PAGE = 25;

/** A fresh scripted mailbox. */
export function createFakeRecallSource(options: {
  mailbox: string;
  uidValidity: number;
  messages: FakeMessage[];
}): FakeRecallSource {
  let validity = options.uidValidity;
  let uidsOverride: number[] | null = null;
  let failNext = false;
  let hold: Promise<void> | null = null;
  const calls: FakeSourceCall[] = [];
  const newestFirst = [...options.messages].sort((x, y) => y.uid - x.uid);

  const source: FakeRecallSource = {
    calls,
    onPage: null,
    setValidity(value) {
      validity = value;
    },
    setUids(uids) {
      uidsOverride = uids;
    },
    failNextPage() {
      failNext = true;
    },
    holdNextPage() {
      let release!: () => void;
      hold = new Promise<void>((resolve) => {
        release = resolve;
      });
      return release;
    },
    async page(_gate, _principal: Principal, mailbox, cursor): Promise<RecallPage> {
      calls.push({ kind: "page", mailbox, cursor });
      if (source.onPage !== null) await source.onPage();
      if (hold !== null) {
        const waiting = hold;
        hold = null;
        await waiting;
      }
      if (failNext) {
        failNext = false;
        throw new Error("fake-recall-source: page set to fail");
      }
      const below = cursor === null ? newestFirst : newestFirst.filter((m) => m.uid < cursor.lastUid);
      const chosen = below.slice(0, PAGE);
      const items = chosen.map((m) => ({
        ref: { mailbox, uidValidity: validity, uid: m.uid },
        text: m.text,
        snippet: m.snippet,
        messageDate: m.date,
      }));
      const last = chosen[chosen.length - 1];
      const next =
        below.length > PAGE && last !== undefined
          ? { mailbox, uidValidity: validity, lastUid: last.uid }
          : null;
      return { uidValidity: validity, items, next };
    },
    async uids(_gate, _principal: Principal, mailbox) {
      calls.push({ kind: "uids", mailbox, cursor: null });
      return {
        uidValidity: validity,
        uids: uidsOverride ?? newestFirst.map((m) => m.uid),
      };
    },
  };
  return source;
}

/** `count` messages with UIDs 1..count, dated `daysAgo` days back, with distinct text. */
export function scriptedMessages(count: number, daysAgo = 1): FakeMessage[] {
  const out: FakeMessage[] = [];
  for (let uid = 1; uid <= count; uid += 1) {
    out.push({
      uid,
      date: Date.now() - daysAgo * 24 * 60 * 60 * 1000,
      text: `message number ${uid} about topic${uid}`,
      snippet: `Subject ${uid}`,
    });
  }
  return out;
}
