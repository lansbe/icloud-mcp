import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

export const FREE_BUDGETS = {
  requests: { limit: 2000, period: "day" },
  oauthWrites: { limit: 128, period: "day" },
  oauthCleanup: { limit: 256, period: "day" },
  embeddingBytes: { limit: 2_000_000, period: "day" },
  semanticScans: { limit: 200, period: "day" },
} as const;
export type FreeBudgetKind = keyof typeof FREE_BUDGETS;

export class FreeQuotaError extends Error {
  constructor() { super("free-capacity-reached-retry-after-reset"); }
}

export class FreeBudget extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS budget (
      kind TEXT PRIMARY KEY, period TEXT NOT NULL, used INTEGER NOT NULL)`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS claims (
      key TEXT PRIMARY KEY, expires INTEGER NOT NULL)`);
    ctx.storage.sql.exec(`CREATE INDEX IF NOT EXISTS claims_expiry ON claims(expires)`);
  }

  // Synchronous SQLite transactions make reservations linearizable across
  // concurrent requests. Failed external calls do not refund their reservation.
  async take(kind: FreeBudgetKind, amount = 1): Promise<boolean> {
    if (!Object.hasOwn(FREE_BUDGETS, kind) || !Number.isSafeInteger(amount) || amount < 0) return false;
    const rule = FREE_BUDGETS[kind];
    const period = new Date().toISOString().slice(0, 10);
    return this.ctx.storage.transactionSync(() => {
      const row = this.ctx.storage.sql.exec<{period: string; used: number}>(
        `select period, used FROM budget WHERE kind = ?`, kind,
      ).toArray()[0];
      const used = row?.period === period ? row.used : 0;
      if (used + amount > rule.limit) return false;
      this.ctx.storage.sql.exec(`INSERT INTO budget VALUES (?, ?, ?)
        ON CONFLICT(kind) DO UPDATE SET period = excluded.period, used = excluded.used`,
        kind, period, used + amount);
      return true;
    });
  }

  async claim(key: string, expires: number): Promise<boolean> {
    const now = Date.now();
    if (key.length > 256 || !Number.isSafeInteger(expires) || expires <= now || expires > now + 86400000) return false;
    const won = this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(`DELETE FROM claims WHERE expires <= ?`, now);
      if (this.ctx.storage.sql.exec(`select key FROM claims WHERE key = ?`, key).toArray().length) return false;
      if (this.ctx.storage.sql.exec<{n: number}>(`select count(*) AS n FROM claims`).one().n >= 10000) return false;
      this.ctx.storage.sql.exec(`INSERT INTO claims VALUES (?, ?)`, key, expires);
      return true;
    });
    await this.ctx.storage.setAlarm(now + 60 * 60 * 1000);
    return won;
  }

  async alarm(): Promise<void> {
    this.ctx.storage.sql.exec(`DELETE FROM claims WHERE expires <= ?`, Date.now());
    const next = this.ctx.storage.sql.exec<{at: number | null}>(`select min(expires) AS at FROM claims`).one().at;
    if (next !== null) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, next));
  }
}

export function budgetOf(env: Env) {
  if (!env.FREE_BUDGET) throw new FreeQuotaError();
  return env.FREE_BUDGET.getByName("deployment-v1");
}

export async function takeBudget(env: Env, kind: FreeBudgetKind, amount = 1): Promise<void> {
  if (env.FREE_BUDGET && !(await budgetOf(env).take(kind, amount))) throw new FreeQuotaError();
}
