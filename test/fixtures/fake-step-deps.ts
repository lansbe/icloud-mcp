// One builder of `StepDeps` for every recall step test (Phase 26, plans 26-03
// and 26-04).
//
// The lease is the REAL one (`createLeasedMail(createSessionGate())`), so a
// held lease really refuses. Everything else is a fake that records what it
// was asked: the store and the embedder over the pool's fake bindings, one
// scripted mailbox per folder for the page source, the folder listing and the
// status check. Every read waits a turn of the event loop before it logs its
// end, so a step that did not await a read would return before the end is
// logged, and the tests can see it.
//
// A change to `StepDeps` is made here, once, for every step test.

import { createLeasedMail } from "../../src/agent/lease";
import type { FolderSnapshotOutcome } from "../../src/mail/service";
import { createSessionGate } from "../../src/mail/service";
import type { RecallSource } from "../../src/recall/build";
import { createEmbedder } from "../../src/recall/embed";
import { createRecallStore } from "../../src/recall/index";
import type { StepDeps } from "../../src/recall/sync";
import { createFakeAi, type FakeAi } from "./fake-embedder";
import {
  createFakeRecallSource,
  type FakeMessage,
  type FakeRecallSource,
} from "./fake-recall-source";
import { createFakeVectorize, type FakeVectorize } from "./fake-vectorize";

/** One scripted folder. */
export interface FakeFolder {
  readonly uidValidity: number;
  readonly messages: FakeMessage[];
}

/** The harness a step test drives. */
export interface StepHarness {
  readonly deps: StepDeps;
  /**
   * Everything in call order: `lease` when the lease runner is called, `enter`
   * and `exit` around the leased work, and `<read>:start` / `<read>:end` for
   * `folders`, `snapshot:<mailbox>`, `page:<mailbox>` and `uids:<mailbox>`.
   */
  readonly log: string[];
  readonly sources: Record<string, FakeRecallSource>;
  readonly index: FakeVectorize;
  readonly ai: FakeAi;
  /** What the folder listing answers from now on. */
  setFolders(folders: string[]): void;
  /** What the status check answers for `mailbox` from now on; null for the default. */
  setSnapshot(mailbox: string, outcome: FolderSnapshotOutcome | null): void;
  /** The clock `deps.now()` reads. */
  setNow(now: number): void;
}

/** One turn of the event loop. */
function tick(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** A status check that answered, from a scripted folder. */
function answered(mailbox: string, folder: FakeFolder): FolderSnapshotOutcome {
  const top = folder.messages.reduce((max, m) => Math.max(max, m.uid), 0);
  return {
    mailbox,
    answered: true,
    snapshot: {
      name: mailbox,
      uidValidity: folder.uidValidity,
      uidNext: top + 1,
      messages: folder.messages.length,
      highestModseq: "7",
    },
  };
}

/** Build a harness over these scripted folders. */
export function fakeStepDeps(options: {
  folders?: string[];
  mailboxes: Record<string, FakeFolder>;
}): StepHarness {
  const log: string[] = [];
  let listed = options.folders ?? Object.keys(options.mailboxes);
  const overrides = new Map<string, FolderSnapshotOutcome>();
  let clock: number | null = null;

  const sources: Record<string, FakeRecallSource> = {};
  for (const [mailbox, folder] of Object.entries(options.mailboxes)) {
    sources[mailbox] = createFakeRecallSource({
      mailbox,
      uidValidity: folder.uidValidity,
      messages: folder.messages,
    });
  }
  function sourceFor(mailbox: string): FakeRecallSource {
    const source = sources[mailbox];
    if (source === undefined) throw new Error(`fake-step-deps: no scripted mailbox ${mailbox}`);
    return source;
  }

  const source: RecallSource = {
    async page(gate, principal, mailbox, cursor) {
      log.push(`page:${mailbox}:start`);
      const page = await sourceFor(mailbox).page(gate, principal, mailbox, cursor);
      await tick();
      log.push(`page:${mailbox}:end`);
      return page;
    },
    async uids(gate, principal, mailbox) {
      log.push(`uids:${mailbox}:start`);
      const answer = await sourceFor(mailbox).uids(gate, principal, mailbox);
      await tick();
      log.push(`uids:${mailbox}:end`);
      return answer;
    },
  };

  const real = createLeasedMail(createSessionGate());
  const index = createFakeVectorize();
  const ai = createFakeAi();

  const deps: StepDeps = {
    store: createRecallStore(index),
    embedder: createEmbedder(ai),
    leased: {
      withConnectionLease(principal, fn) {
        log.push("lease");
        return real.withConnectionLease(principal, async (gate) => {
          log.push("enter");
          try {
            return await fn(gate);
          } finally {
            log.push("exit");
          }
        });
      },
    },
    source,
    reads: {
      async folders() {
        log.push("folders:start");
        await tick();
        log.push("folders:end");
        return [...listed];
      },
      async snapshot(_gate, _principal, mailbox) {
        log.push(`snapshot:${mailbox}:start`);
        await tick();
        log.push(`snapshot:${mailbox}:end`);
        const override = overrides.get(mailbox);
        if (override !== undefined) return override;
        const folder = options.mailboxes[mailbox];
        return folder === undefined ? { mailbox, answered: false } : answered(mailbox, folder);
      },
    },
    now: () => clock ?? Date.now(),
  };

  return {
    deps,
    log,
    sources,
    index,
    ai,
    setFolders(folders) {
      listed = folders;
    },
    setSnapshot(mailbox, outcome) {
      if (outcome === null) overrides.delete(mailbox);
      else overrides.set(mailbox, outcome);
    },
    setNow(now) {
      clock = now;
    },
  };
}
