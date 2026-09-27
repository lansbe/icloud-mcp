// The recall store (Phase 25, RCLL-01, D-02, D-03).
//
// The ONLY module under `src/` that may name the vector index binding. A scan
// count in plan 25-04 holds that, and zero is a violation too: a store whose
// one reader was moved or emptied guards nothing, and that loss is quieter than
// a duplicate.
//
// WHY THE STORE IS WRAPPED AT ALL. It fails open. A query that names no
// partition is read as searching every person's vectors (SPIKE-09 (4) is
// unstated, so this designs to the cautious reading). Nothing refuses such a
// query; it simply answers with other people's mail. So the partition and the
// filter are set here, from the signed-in principal, and nowhere else. Every
// read and write method takes a `Principal`. None takes a partition name, a
// user id string, or the environment.
//
// THREE LAYERS, each with its own test that goes red when it is removed
// (test/recall-isolation.test.ts):
//
//   1. The partition. Every query and every write names the principal's user id
//      as its partition, set LAST in the options so no caller field can
//      replace it.
//   2. The metadata filter. Every query filters on `u` equal to the user id,
//      and every write stores `u`. The store needs a string metadata index on
//      `u` for this. Without that index the filter matches nothing, so this
//      layer fails closed.
//   3. The returned-match check. Every match whose stored `u` is not the
//      caller's user id is dropped before anything leaves this module.
//
// Three of the binding's verbs are never used here, and plan 25-04 bans them.
// They are described by role, because the scan reads comments too:
//
//   - the by-id read verb and the by-id query verb both skip the partition, so
//     either one could reach another person's vector by id;
//   - the keep-first write verb keeps whatever is already stored under an id,
//     so a re-index would silently change nothing, forever.
//
// Every write goes through the upsert verb, which replaces what an id held.
//
// Deletes take ledger ids only. The ids come from the person's own ledger in
// their own object (src/agent/recall-ledger.ts), which only ever holds ids
// this module computed for that person.
//
// A rejection from the binding becomes `RecallStoreError`, and the caught value
// is never read. This module logs nothing (./.claude/CLAUDE.md §4).

import { env } from "cloudflare:workers";
import type { Principal } from "../principal";
import { vectorIdOf } from "./ids";

/** The most vectors, or ids, sent to the binding in one call. */
const BATCH = 1000;

/** The most matches one query may ask for, with metadata returned. */
const TOP_K_MAX = 50;

/** A 64-character lower-case hex id, the only shape a ledger id has. */
const VECTOR_ID = /^[0-9a-f]{64}$/;

/** One recalled message: its opaque ref, its snippet, when it was indexed. No score. */
export interface RecallMatch {
  readonly ref: string;
  readonly snippet: string;
  readonly indexedAt: number;
}

/** One message to write: the encoded message token, its vector, its snippet. */
export interface RecallEntry {
  readonly ref: string;
  readonly values: number[];
  readonly snippet: string;
  readonly indexedAt: number;
}

/** What a caller may say about a query. Only the number of matches. */
export interface RecallQueryOptions {
  readonly topK?: number;
}

/** Thrown when the store cannot be reached, or a delete names a bad id. */
export class RecallStoreError extends Error {
  readonly kind = "recall-store" as const;

  constructor() {
    super("recall-store-failed");
    this.name = "RecallStoreError";
  }
}

/** The recall store, scoped to one principal on every read and write. */
export interface RecallStore {
  /** Write these entries as `principal`'s vectors. Ids are computed here. */
  upsert(principal: Principal, entries: readonly RecallEntry[]): Promise<void>;
  /** The nearest of `principal`'s own vectors to `values`, in rank order. */
  query(
    principal: Principal,
    values: number[],
    options?: RecallQueryOptions,
  ): Promise<RecallMatch[]>;
  /** Delete these ledger ids. Each must be 64 lower-case hex characters. */
  deleteIds(ids: readonly string[]): Promise<void>;
}

/** Clamp a requested match count to 1..TOP_K_MAX. */
function clampTopK(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 5;
  return Math.min(TOP_K_MAX, Math.max(1, Math.floor(value)));
}

/** A match's metadata as this module stores it, or null if it is not ours. */
function ownMatch(metadata: unknown, userId: string): RecallMatch | null {
  if (typeof metadata !== "object" || metadata === null) return null;
  const m = metadata as { u?: unknown; r?: unknown; s?: unknown; a?: unknown };
  if (m.u !== userId) return null;
  if (typeof m.r !== "string" || typeof m.s !== "string") return null;
  if (typeof m.a !== "number" || !Number.isFinite(m.a)) return null;
  return { ref: m.r, snippet: m.s, indexedAt: m.a };
}

/** A store over the given index binding. */
export function createRecallStore(index: Vectorize): RecallStore {
  return {
    async upsert(principal, entries) {
      const vectors: VectorizeVector[] = [];
      for (const entry of entries) {
        vectors.push({
          id: await vectorIdOf(principal, entry.ref),
          values: entry.values,
          namespace: principal.userId,
          metadata: {
            u: principal.userId,
            r: entry.ref,
            a: entry.indexedAt,
            s: entry.snippet,
          },
        });
      }
      for (let i = 0; i < vectors.length; i += BATCH) {
        try {
          await index.upsert(vectors.slice(i, i + BATCH));
        } catch {
          throw new RecallStoreError();
        }
      }
    },

    async query(principal, values, options) {
      const sent: VectorizeQueryOptions = {
        ...options,
        topK: clampTopK(options?.topK),
        returnValues: false,
        namespace: principal.userId,
        filter: { u: principal.userId },
        returnMetadata: "all",
      };
      let answer: VectorizeMatches;
      try {
        answer = await index.query(values, sent);
      } catch {
        throw new RecallStoreError();
      }
      const matches: RecallMatch[] = [];
      for (const match of answer.matches ?? []) {
        const own = ownMatch(match.metadata, principal.userId);
        if (own !== null) matches.push(own);
      }
      return matches;
    },

    async deleteIds(ids) {
      for (const id of ids) {
        if (typeof id !== "string" || !VECTOR_ID.test(id)) throw new RecallStoreError();
      }
      for (let i = 0; i < ids.length; i += BATCH) {
        try {
          await index.deleteByIds(ids.slice(i, i + BATCH));
        } catch {
          throw new RecallStoreError();
        }
      }
    },
  };
}

/** The production store, over the real binding. */
export function recallStore(): RecallStore {
  return createRecallStore(env.RECALL_INDEX);
}
