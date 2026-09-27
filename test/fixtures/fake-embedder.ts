// A fake Workers AI binding for the recall tests (Phase 25).
//
// The test pool turns remote bindings off, so the real AI binding fails every
// call (D-16). Tests pass this fake to `createEmbedder` instead.
//
// `run(model, input)` answers `{ shape: [n, 1024], data }`, one vector per text.
// Each vector is deterministic: the lower-cased words of the text are hashed
// into 1024 buckets and the result is scaled to unit length. So two texts that
// share words score higher against each other than two that share none, which
// is all a ranking test needs.
//
// Options make it answer wrongly on purpose: vectors of another length, the
// wrong number of vectors, or a rejection. Every call is recorded in `calls`.

/** Options for the fake. */
export interface FakeAiOptions {
  /** The length of every vector. Default 1024. */
  readonly dimensions?: number;
  /** Added to the number of vectors returned. Default 0. */
  readonly extraVectors?: number;
  /** Reject every call. */
  readonly reject?: boolean;
}

/** One recorded call. */
export interface FakeAiCall {
  readonly model: string;
  readonly input: unknown;
}

/** The fake, typed as the binding, plus its call log. */
export type FakeAi = Ai & { readonly calls: FakeAiCall[] };

function hashWord(word: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < word.length; i += 1) {
    h ^= word.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** The fake's vector for `text`, at `dimensions` long. */
export function fakeVectorOf(text: string, dimensions = 1024): number[] {
  const v = new Array<number>(dimensions).fill(0);
  const words = text.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 0);
  if (words.length === 0) v[0] = 1;
  for (const word of words) v[hashWord(word) % dimensions]! += 1;
  const norm = Math.sqrt(v.reduce((sum, x) => sum + x * x, 0));
  return v.map((x) => x / norm);
}

/** A fresh fake AI binding. */
export function createFakeAi(options: FakeAiOptions = {}): FakeAi {
  const dimensions = options.dimensions ?? 1024;
  const calls: FakeAiCall[] = [];
  const fake = {
    calls,
    async run(model: string, input: unknown) {
      calls.push({ model, input });
      if (options.reject) throw new Error("fake-ai: set to reject");
      const raw = (input as { text?: unknown }).text;
      const texts = Array.isArray(raw) ? (raw as string[]) : [String(raw)];
      const data = texts.map((t) => fakeVectorOf(t, dimensions));
      for (let i = 0; i < (options.extraVectors ?? 0); i += 1) data.push(fakeVectorOf("extra", dimensions));
      return { shape: [data.length, dimensions], data };
    },
  };
  return fake as unknown as FakeAi;
}
