// A fake Vectorize index for the recall tests (Phase 25).
//
// The test pool cannot simulate Vectorize at all: every call goes to a remote
// proxy, and vitest.config.ts turns remote bindings off so the suite never
// reaches the account (SPIKE-09 (2), D-16). So recall is tested against this
// fake, passed to `createRecallStore`, never assigned onto the environment.
//
// THE FAKE MODELS THE CONSERVATIVE READING. Where Cloudflare's documentation
// does not say what the store does, the fake does the thing that would hurt
// most, because that is what the design has to survive:
//
// - A query with no partition searches EVERY vector (SPIKE-09 (4), unstated).
// - With a partition, a query searches only that partition.
// - Ids are index-wide, not per partition (SPIKE-09 (3), unstated). An upsert
//   of an existing id overwrites it, its partition included.
// - The keep-first write keeps the vector already stored under an id.
// - A filter on a property with no metadata index matches NOTHING. Only the
//   properties in `options.metadataIndexes` are indexed (default `["u"]`).
// - With the property indexed, only vectors whose metadata equals the value
//   match.
// - Matches are ranked by cosine similarity, and carry `id`, `score`,
//   `namespace` and, when asked, `metadata` and `values`.
//
// `ignoreScopes: true` makes every query ignore both the partition and the
// filter. It stands for a store that fails open, so the returned-match check
// can be tested on its own.
//
// Every call is recorded in `calls`, with its arguments exactly as received.
// A method named in `failing` rejects instead of running.

/** One recorded call to the fake. */
export interface FakeVectorizeCall {
  readonly method: string;
  readonly args: readonly unknown[];
}

/** Options for the fake. */
export interface FakeVectorizeOptions {
  /** Metadata properties with an index. Default `["u"]`. */
  readonly metadataIndexes?: readonly string[];
  /** Queries ignore both the partition and the filter. */
  readonly ignoreScopes?: boolean;
}

/** One stored vector. */
export interface StoredVector {
  readonly id: string;
  readonly values: number[];
  readonly namespace?: string;
  readonly metadata?: Record<string, unknown>;
}

/** The fake, typed as the binding, plus what a test inspects. */
export type FakeVectorize = Vectorize & {
  readonly calls: FakeVectorizeCall[];
  readonly vectors: Map<string, StoredVector>;
  readonly failing: Set<string>;
  ignoreScopes: boolean;
};

function cosine(a: readonly number[], b: readonly number[]): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / Math.sqrt(na * nb);
}

function filterMatches(
  metadata: Record<string, unknown> | undefined,
  filter: Record<string, unknown>,
  indexed: readonly string[],
): boolean {
  for (const [key, wanted] of Object.entries(filter)) {
    if (!indexed.includes(key)) return false;
    const value =
      typeof wanted === "object" && wanted !== null && "$eq" in wanted
        ? (wanted as { $eq: unknown }).$eq
        : wanted;
    if (metadata?.[key] !== value) return false;
  }
  return true;
}

/** A fresh fake index. */
export function createFakeVectorize(options: FakeVectorizeOptions = {}): FakeVectorize {
  const indexed = options.metadataIndexes ?? ["u"];
  const calls: FakeVectorizeCall[] = [];
  const vectors = new Map<string, StoredVector>();
  const failing = new Set<string>();

  const state = { ignoreScopes: options.ignoreScopes ?? false };

  function record(method: string, args: unknown[]): void {
    calls.push({ method, args });
    if (failing.has(method)) throw new Error(`fake-vectorize: ${method} set to fail`);
  }

  function store(list: VectorizeVector[], keepFirst: boolean): void {
    for (const v of list) {
      if (keepFirst && vectors.has(v.id)) continue;
      vectors.set(v.id, {
        id: v.id,
        values: Array.from(v.values),
        ...(v.namespace === undefined ? {} : { namespace: v.namespace }),
        ...(v.metadata === undefined ? {} : { metadata: { ...v.metadata } }),
      });
    }
  }

  function search(values: readonly number[], opts: VectorizeQueryOptions = {}): VectorizeMatches {
    let pool = [...vectors.values()];
    if (!state.ignoreScopes) {
      if (opts.namespace !== undefined) pool = pool.filter((v) => v.namespace === opts.namespace);
      if (opts.filter !== undefined) {
        const filter = opts.filter as Record<string, unknown>;
        pool = pool.filter((v) => filterMatches(v.metadata, filter, indexed));
      }
    }
    const topK = opts.topK ?? 5;
    const wantMetadata = opts.returnMetadata !== undefined && opts.returnMetadata !== false && opts.returnMetadata !== "none";
    const matches = pool
      .map((v) => ({ v, score: cosine(values, v.values) }))
      .sort((x, y) => y.score - x.score)
      .slice(0, topK)
      .map(({ v, score }) => {
        const match: Record<string, unknown> = { id: v.id, score };
        if (v.namespace !== undefined) match.namespace = v.namespace;
        if (wantMetadata && v.metadata !== undefined) match.metadata = { ...v.metadata };
        if (opts.returnValues) match.values = [...v.values];
        return match as unknown as VectorizeMatch;
      });
    return { matches, count: matches.length };
  }

  const fake = {
    calls,
    vectors,
    failing,
    get ignoreScopes() {
      return state.ignoreScopes;
    },
    set ignoreScopes(value: boolean) {
      state.ignoreScopes = value;
    },
    async describe() {
      record("describe", []);
      return {
        vectorCount: vectors.size,
        dimensions: 1024,
        processedUpToDatetime: 0,
        processedUpToMutation: 0,
      };
    },
    async query(values: VectorFloatArray | number[], opts?: VectorizeQueryOptions) {
      record("query", [values, opts]);
      return search(Array.from(values), opts);
    },
    async queryById(id: string, opts?: VectorizeQueryOptions) {
      record("queryById", [id, opts]);
      const v = vectors.get(id);
      if (v === undefined) return { matches: [], count: 0 };
      return search(v.values, opts);
    },
    async insert(list: VectorizeVector[]) {
      record("insert", [list]);
      store(list, true);
      return { mutationId: `m-${calls.length}` };
    },
    async upsert(list: VectorizeVector[]) {
      record("upsert", [list]);
      store(list, false);
      return { mutationId: `m-${calls.length}` };
    },
    async deleteByIds(ids: string[]) {
      record("deleteByIds", [ids]);
      for (const id of ids) vectors.delete(id);
      return { mutationId: `m-${calls.length}` };
    },
    async getByIds(ids: string[]) {
      record("getByIds", [ids]);
      return ids.flatMap((id) => {
        const v = vectors.get(id);
        return v === undefined ? [] : [{ ...v } as VectorizeVector];
      });
    },
  };
  return fake as unknown as FakeVectorize;
}
