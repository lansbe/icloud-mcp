// Index a batch of messages for one person, and recall from their own vectors
// (Phase 25, RCLL-01, RCLL-03, D-08).
//
// Indexing runs in one fixed order, and the order is the point:
//
//   1. drop messages already older than the retention window;
//   2. cap the embedded text and the snippet;
//   3. encode each ref and compute its vector id;
//   4. record the ids in the person's ledger, in their own object, FIRST;
//   5. embed every text in one call;
//   6. write the vectors to the store.
//
// Ledger first, store second, so the ledger is always a superset of what the
// store holds for this person (src/agent/recall-ledger.ts says why). If the
// object refuses the record, nothing is embedded and nothing is written, and
// the refusal comes back as `RecallRefusedError` carrying the object's reason
// and nothing else.
//
// Recall is inherent (owner, 2026-09-27): nothing has to be turned on first.
//
// This is the one module in src/recall/ that imports the message-token module,
// apart from the build engine. It never touches IMAP. No logging, and no caught
// value is ever read (./.claude/CLAUDE.md §4).

import { agentFor } from "../agent/lease";
import type { RecordRefusal } from "../agent/recall-ledger";
import { encodeMessageId, type MessageRef } from "../mail/ids";
import type { Principal } from "../principal";
import { type Embedder, embedder } from "./embed";
import { vectorIdOf } from "./ids";
import { type RecallMatch, type RecallStore, recallStore } from "./index";
import { EMBED_TEXT_MAX_CHARS, RECALL_TTL_MS, SNIPPET_MAX_CHARS } from "./retention";

/** One message to index. */
export interface RecallItem {
  readonly ref: MessageRef;
  /** The text to embed. Capped here, embedded, and never stored. */
  readonly text: string;
  /** The one piece of text stored: meant to be the subject line. Capped here. */
  readonly snippet: string;
  /** The message's own date, in ms since the epoch. */
  readonly messageDate: number;
}

/** The store and the embedder, passed in so tests can pass fakes. */
export interface RecallDeps {
  readonly store: RecallStore;
  readonly embedder: Embedder;
}

/** The production pair, over the real bindings. */
export function recallDeps(): RecallDeps {
  return { store: recallStore(), embedder: embedder() };
}

/** Thrown when the person's object refuses to record. Carries its reason only. */
export class RecallRefusedError extends Error {
  readonly kind = "recall-refused" as const;
  readonly reason: RecordRefusal;

  constructor(reason: RecordRefusal) {
    super("recall-record-refused");
    this.name = "RecallRefusedError";
    this.reason = reason;
  }
}

/** Thrown when the person's object cannot be reached. */
export class RecallLedgerError extends Error {
  readonly kind = "recall-ledger" as const;

  constructor() {
    super("recall-ledger-unreachable");
    this.name = "RecallLedgerError";
  }
}

/** `text` cut to at most `max` code points, so no surrogate pair is split. */
function capCodePoints(text: string, max: number): string {
  const points = Array.from(text);
  return points.length <= max ? text : points.slice(0, max).join("");
}

/**
 * Index `items` as `principal`'s. Returns how many were indexed.
 *
 * With nothing left after the window filter, calls nothing and returns 0.
 */
export async function indexItems(
  principal: Principal,
  items: readonly RecallItem[],
  deps: RecallDeps,
): Promise<number> {
  const now = Date.now();
  const kept = items.filter((item) => item.messageDate + RECALL_TTL_MS > now);
  if (kept.length === 0) return 0;

  const refs: string[] = [];
  const texts: string[] = [];
  const snippets: string[] = [];
  const rows: {
    vectorId: string;
    mailbox: string;
    uidValidity: number;
    messageDate: number;
  }[] = [];
  for (const item of kept) {
    const ref = encodeMessageId(item.ref);
    refs.push(ref);
    texts.push(capCodePoints(item.text, EMBED_TEXT_MAX_CHARS));
    snippets.push(capCodePoints(item.snippet, SNIPPET_MAX_CHARS));
    rows.push({
      vectorId: await vectorIdOf(principal, ref),
      mailbox: item.ref.mailbox,
      uidValidity: item.ref.uidValidity,
      messageDate: item.messageDate,
    });
  }

  let answer: Awaited<ReturnType<ReturnType<typeof agentFor>["recallRecord"]>>;
  try {
    answer = await agentFor(principal).recallRecord(rows);
  } catch {
    throw new RecallLedgerError();
  }
  if (!answer.ok) throw new RecallRefusedError(answer.reason);

  const vectors = await deps.embedder.embed(texts);
  const indexedAt = Date.now();
  await deps.store.upsert(
    principal,
    refs.map((ref, i) => ({
      ref,
      values: vectors[i]!,
      snippet: snippets[i]!,
      indexedAt,
    })),
  );
  return kept.length;
}

/** The nearest of `principal`'s own messages to `queryText`, in rank order. No score. */
export async function recallFor(
  principal: Principal,
  queryText: string,
  deps: RecallDeps,
  topK?: number,
): Promise<RecallMatch[]> {
  const [vector] = await deps.embedder.embed([capCodePoints(queryText, EMBED_TEXT_MAX_CHARS)]);
  return deps.store.query(principal, vector!, { topK });
}
