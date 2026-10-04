// The embedder for semantic recall (Phase 25, D-02, D-05).
//
// Turns text into the vectors the recall index holds. This is the ONLY module
// under `src/` that reads the AI binding off the environment, and it holds the
// one model id. A scan count in plan 25-04 holds the one reader, and zero
// readers is a violation too.
//
// Two ways in. `createEmbedder(ai)` takes the binding as a parameter, so tests
// pass a fake. `embedder()` reads the real binding, for production. Nothing
// assigns onto the environment.
//
// One call per batch, with the texts as an array. The answer is refused, and
// nothing downstream runs, unless it holds exactly one vector per text, each of
// exactly RECALL_DIMENSIONS finite numbers. The index's dimension is fixed when
// it is created, so a vector of any other length would be refused by the store
// anyway; refusing it here means nothing is written first.
//
// A failed call becomes `RecallEmbedError`. The caught value is never read: its
// text is the platform's, and nothing about it belongs in an answer. This
// module logs nothing (./.claude/CLAUDE.md §4).

import { env } from "cloudflare:workers";
import { takeBudget } from "../free/budget";

/** The one embedding model recall uses. */
export const RECALL_MODEL = "@cf/baai/bge-m3";

/**
 * The length of every vector the model returns, and the index's dimension.
 *
 * 1024 is what SPIKE-10 measured for this model on the real account (Phase 14).
 * The model's page does not state it. A test pins this number, and the owner
 * creates the index from it, so the two cannot drift apart silently.
 */
export const RECALL_DIMENSIONS = 1024;

/** Thrown when the model cannot be reached or answers in the wrong shape. */
export class RecallEmbedError extends Error {
  readonly kind = "recall-embed" as const;

  constructor() {
    super("recall-embedding-failed");
    this.name = "RecallEmbedError";
  }
}

/** Turns texts into vectors, one per text, in the same order. */
export interface Embedder {
  embed(texts: readonly string[]): Promise<number[][]>;
}

/** Whether `value` is one vector of the right length and only finite numbers. */
function isVector(value: unknown): value is number[] {
  if (!Array.isArray(value) || value.length !== RECALL_DIMENSIONS) return false;
  for (const x of value) {
    if (typeof x !== "number" || !Number.isFinite(x)) return false;
  }
  return true;
}

/** An embedder over the given AI binding. */
export function createEmbedder(ai: Ai): Embedder {
  return {
    async embed(texts: readonly string[]): Promise<number[][]> {
      let answer: unknown;
      try {
        answer = await ai.run(RECALL_MODEL, { text: [...texts] });
      } catch {
        throw new RecallEmbedError();
      }
      const data =
        typeof answer === "object" && answer !== null
          ? (answer as { data?: unknown }).data
          : undefined;
      if (!Array.isArray(data) || data.length !== texts.length) throw new RecallEmbedError();
      const vectors: number[][] = [];
      for (const vector of data) {
        if (!isVector(vector)) throw new RecallEmbedError();
        vectors.push(vector);
      }
      return vectors;
    },
  };
}

/** The production embedder, over the real binding. */
export function embedder(): Embedder {
  const engine = createEmbedder(env.AI);
  return { async embed(texts) {
    await takeBudget(env, "embeddingBytes", texts.reduce((sum, text) => sum + new TextEncoder().encode(text).byteLength, 0));
    return engine.embed(texts);
  } };
}
