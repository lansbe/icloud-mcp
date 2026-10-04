import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

// A single, bounded SQLite vault for this deployment. No public route reaches
// these methods; callers have already checked the signed-in user's key prefix.
export const BLOB_CHUNK_BYTES = 512 * 1024;
export const BLOB_MAX_BYTES = 20 * 1024 * 1024;
export const VAULT_MAX_BYTES = 256 * 1024 * 1024;
export const VAULT_MAX_OBJECTS = 512;
export const BLOB_TTL_MS = 24 * 60 * 60 * 1000;
export const UPLOAD_PENDING_TTL_MS = 15 * 60 * 1000;
const KEY = /^staging\/[0-9a-f]{64}\/[A-Za-z0-9._-]{1,256}$/;

export interface BlobMetadata {
  contentType?: string;
  customMetadata?: Record<string, string>;
}
type BlobRow = {
  key: string;
  size: number;
  written: number;
  ready: number;
  expires: number;
  metadata: string;
}
export interface BlobHead {
  key: string;
  size: number;
  httpMetadata: { contentType?: string };
  customMetadata: Record<string, string>;
}

export class BlobVault extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS blobs (
      key TEXT PRIMARY KEY, size INTEGER NOT NULL, written INTEGER NOT NULL,
      ready INTEGER NOT NULL, expires INTEGER NOT NULL, metadata TEXT NOT NULL)`);
    ctx.storage.sql.exec(`CREATE INDEX IF NOT EXISTS blobs_expiry ON blobs(expires)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS chunks (
      key TEXT NOT NULL, part INTEGER NOT NULL, bytes BLOB NOT NULL,
      PRIMARY KEY(key, part))`);
  }

  private row(key: string): BlobRow | null {
    return this.ctx.storage.sql.exec<BlobRow>(
      `select * FROM blobs WHERE key = ?`, key,
    ).toArray()[0] ?? null;
  }

  private erase(key: string): void {
    this.ctx.storage.sql.exec(`DELETE FROM chunks WHERE key = ?`, key);
    this.ctx.storage.sql.exec(`DELETE FROM blobs WHERE key = ?`, key);
  }

  private sweep(): void {
    for (const row of this.ctx.storage.sql.exec<{key: string}>(
      `select key FROM blobs WHERE expires <= ?`, Date.now(),
    ).toArray()) this.erase(row.key);
  }

  private async schedule(): Promise<void> {
    const next = this.ctx.storage.sql.exec<{at: number | null}>(
      `select min(expires) AS at FROM blobs`,
    ).one().at;
    if (next === null) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, next));
  }

  async begin(key: string, size: number, metadata: BlobMetadata): Promise<boolean> {
    if (!KEY.test(key) || key.includes("..") || !Number.isSafeInteger(size) ||
        size < 0 || size > BLOB_MAX_BYTES) return false;
    const encoded = JSON.stringify(metadata);
    if (new TextEncoder().encode(encoded).byteLength > 8192) return false;
    const accepted = this.ctx.storage.transactionSync(() => {
      this.sweep();
      if (this.row(key)) return false; // an upload URL cannot replace a file
      const held = this.ctx.storage.sql.exec<{n: number; bytes: number}>(
        `select count(*) AS n, coalesce(sum(size), 0) AS bytes FROM blobs`,
      ).one();
      if (held.n >= VAULT_MAX_OBJECTS || held.bytes + size > VAULT_MAX_BYTES) return false;
      this.ctx.storage.sql.exec(`INSERT INTO blobs VALUES (?, ?, 0, 0, ?, ?)`,
        key, size, Date.now() + UPLOAD_PENDING_TTL_MS, encoded);
      return true;
    });
    await this.schedule();
    return accepted;
  }

  async writeChunk(key: string, part: number, bytes: Uint8Array): Promise<boolean> {
    return this.ctx.storage.transactionSync(() => {
      const row = this.row(key);
      if (!row || row.ready || row.expires <= Date.now() || !Number.isSafeInteger(part) ||
          part < 0 || bytes.byteLength < 1 || bytes.byteLength > BLOB_CHUNK_BYTES ||
          row.written !== part * BLOB_CHUNK_BYTES || row.written + bytes.byteLength > row.size) return false;
      // Every non-final part must be full. This makes missing/out-of-order chunks unrepresentable.
      if (bytes.byteLength < BLOB_CHUNK_BYTES && row.written + bytes.byteLength !== row.size) return false;
      this.ctx.storage.sql.exec(`INSERT INTO chunks VALUES (?, ?, ?)`, key, part, bytes);
      this.ctx.storage.sql.exec(`UPDATE blobs SET written = written + ? WHERE key = ?`, bytes.byteLength, key);
      return true;
    });
  }

  async finish(key: string): Promise<boolean> {
    const ok = this.ctx.storage.transactionSync(() => {
      const row = this.row(key);
      if (!row || row.ready || row.expires <= Date.now() || row.written !== row.size) return false;
      this.ctx.storage.sql.exec(`UPDATE blobs SET ready = 1, expires = ? WHERE key = ?`,
        Date.now() + BLOB_TTL_MS, key);
      return true;
    });
    await this.schedule();
    return ok;
  }

  async head(key: string): Promise<BlobHead | null> {
    const row = this.row(key);
    if (!row || !row.ready || row.expires <= Date.now()) return null;
    const meta = JSON.parse(row.metadata) as BlobMetadata;
    return { key, size: row.size, httpMetadata: { contentType: meta.contentType },
      customMetadata: meta.customMetadata ?? {} };
  }

  async readChunk(key: string, part: number): Promise<ArrayBuffer | null> {
    if (!(await this.head(key))) return null;
    return this.ctx.storage.sql.exec<{bytes: ArrayBuffer}>(
      `select bytes FROM chunks WHERE key = ? AND part = ?`, key, part,
    ).toArray()[0]?.bytes ?? null;
  }

  async remove(keys: string[]): Promise<void> {
    if (keys.length > VAULT_MAX_OBJECTS) throw new Error("storage-request-refused");
    this.ctx.storage.transactionSync(() => { for (const key of keys) this.erase(key); });
    await this.schedule();
  }

  async list(prefix: string): Promise<{key: string; size: number}[]> {
    return this.ctx.storage.sql.exec<{key: string; size: number}>(
      `select key, size FROM blobs WHERE ready = 1 AND expires > ?
       AND substr(key, 1, ?) = ? ORDER BY key LIMIT ?`,
      Date.now(), prefix.length, prefix, VAULT_MAX_OBJECTS,
    ).toArray();
  }

  async alarm(): Promise<void> {
    this.ctx.storage.transactionSync(() => this.sweep());
    await this.schedule();
  }
}
