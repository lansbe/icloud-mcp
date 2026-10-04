import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

// Full bge-m3 vectors, not a keyword fallback or dimension reduction. Stream
// SQLite rows through a bounded top-K list; never materialize the whole index.
export const SEMANTIC_DIMENSIONS = 1024;
export const SEMANTIC_MAX_VECTORS = 40000;
export const SEMANTIC_USER_MAX_VECTORS = 10000;
const USER = /^[0-9a-f]{64}$/;
type VectorRow = { id: string; owner: string; values: ArrayBuffer; metadata: string; norm: number };

function vectorNorm(values: readonly number[]): number {
  if (values.length !== SEMANTIC_DIMENSIONS || values.some(x => !Number.isFinite(x))) {
    throw new Error("semantic-vector-invalid");
  }
  const norm = Math.sqrt(values.reduce((sum, x) => sum + x * x, 0));
  if (!Number.isFinite(norm) || norm <= 0) throw new Error("semantic-vector-invalid");
  return norm;
}

export class SemanticStore extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS semantic_vectors (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, vals BLOB NOT NULL,
      metadata TEXT NOT NULL, norm REAL NOT NULL)`);
    ctx.storage.sql.exec(`CREATE INDEX IF NOT EXISTS semantic_owner ON semantic_vectors(owner)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS semantic_counts (owner TEXT PRIMARY KEY, n INTEGER NOT NULL)`);
  }

  async store(vectors: VectorizeVector[]): Promise<boolean> {
    try {
    if (vectors.length > 1000) throw new Error("semantic-batch-too-large");
    const rows = vectors.map(v => {
      if (!USER.test(v.id) || !v.namespace || !USER.test(v.namespace) ||
          v.metadata?.u !== v.namespace) throw new Error("semantic-owner-invalid");
      const source = Array.from(v.values);
      vectorNorm(source);
      const values = new Float32Array(source);
      const norm = vectorNorm(Array.from(values));
      const metadata = JSON.stringify(v.metadata);
      if (new TextEncoder().encode(metadata).byteLength > 8192) throw new Error("semantic-metadata-too-large");
      return { id: v.id, owner: v.namespace, values, norm, metadata };
    });
    this.ctx.storage.transactionSync(() => {
      const counts = new Map<string, number>();
      const count = (owner: string) => {
        if (!counts.has(owner)) counts.set(owner, this.ctx.storage.sql.exec<{n: number}>(
          `select n FROM semantic_counts WHERE owner = ?`, owner).toArray()[0]?.n ?? 0);
        return counts.get(owner)!;
      };
      for (const row of rows) {
        const before = this.ctx.storage.sql.exec<{owner: string}>(
          `select owner FROM semantic_vectors WHERE id = ?`, row.id,
        ).toArray()[0];
        if (before && before.owner !== row.owner) throw new Error("semantic-owner-invalid");
        if (!before) {
          if (count("*") >= SEMANTIC_MAX_VECTORS || count(row.owner) >= SEMANTIC_USER_MAX_VECTORS) {
            throw new Error("semantic-capacity-reached");
          }
          counts.set("*", count("*") + 1);
          counts.set(row.owner, count(row.owner) + 1);
        }
        this.ctx.storage.sql.exec(`INSERT INTO semantic_vectors VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET vals = excluded.vals, metadata = excluded.metadata, norm = excluded.norm`,
          row.id, row.owner, row.values, row.metadata, row.norm);
      }
      for (const [owner, n] of counts) this.ctx.storage.sql.exec(
        `INSERT INTO semantic_counts VALUES (?, ?) ON CONFLICT(owner) DO UPDATE SET n = excluded.n`, owner, n);
    });
    return true;
    } catch { return false; }
  }

  async search(owner: string, values: number[], topK: number): Promise<VectorizeMatches> {
    if (!USER.test(owner) || !Number.isSafeInteger(topK) || topK < 1 || topK > 50) {
      throw new Error("semantic-query-invalid");
    }
    const norm = vectorNorm(values);
    const best: VectorizeMatch[] = [];
    const cursor = this.ctx.storage.sql.exec<VectorRow>(
      `select id, owner, vals AS "values", metadata, norm FROM semantic_vectors WHERE owner = ?`, owner,
    );
    for (const row of cursor) {
      const stored = new Float32Array(row.values);
      let dot = 0;
      for (let i = 0; i < SEMANTIC_DIMENSIONS; i++) dot += values[i]! * stored[i]!;
      const score = Math.min(1, Math.max(-1, dot / (norm * row.norm)));
      const hit: VectorizeMatch = { id: row.id, score, metadata: JSON.parse(row.metadata) };
      // Stable lexical order for exact ties; at most 51 small rows retained.
      let position = best.findIndex(x => score > x.score || (score === x.score && row.id < x.id));
      if (position < 0) position = best.length;
      if (position < topK) { best.splice(position, 0, hit); if (best.length > topK) best.pop(); }
    }
    return { count: best.length, matches: best };
  }

  async remove(ids: string[]): Promise<void> {
    if (ids.length > 1000 || ids.some(id => !USER.test(id))) throw new Error("semantic-delete-invalid");
    this.ctx.storage.transactionSync(() => {
      for (const id of ids) {
        const owner = this.ctx.storage.sql.exec<{owner: string}>(
          `select owner FROM semantic_vectors WHERE id = ?`, id).toArray()[0]?.owner;
        if (!owner) continue;
        this.ctx.storage.sql.exec(`DELETE FROM semantic_vectors WHERE id = ?`, id);
        this.ctx.storage.sql.exec(`UPDATE semantic_counts SET n = n - 1 WHERE owner = ? OR owner = '*'`, owner);
      }
    });
  }
}

export function semanticIndex(env: Env): Pick<Vectorize, "upsert" | "query" | "deleteByIds"> {
  if (!env.FREE_RECALL) throw new Error("semantic-not-configured");
  const stub = env.FREE_RECALL.getByName("recall-v1");
  return {
    async upsert(vectors) {
      if (!(await stub.store(vectors))) throw new Error("semantic-storage-unavailable-or-full");
      return { mutationId: "sqlite-synchronous" };
    },
    async query(vector, options) {
      const owner = options?.namespace;
      if (!owner || options?.filter?.u !== owner || options.returnValues) throw new Error("semantic-owner-invalid");
      return stub.search(owner, Array.from(vector), options.topK ?? 5);
    },
    async deleteByIds(ids) {
      await stub.remove(ids);
      return { mutationId: "sqlite-synchronous" };
    },
  };
}
