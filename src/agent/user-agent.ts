// The per-person Durable Object (Phase 24, D-01, D-03, D-05).
//
// One object per signed-in person. It holds ONE thing: a connection lease
// record, at storage key `lease`, of the shape `{ token, expiresAt }`. It holds
// no user id, no address and no credential. An object whose lease was released
// holds nothing at all.
//
// It is a lease holder and never a session holder. It never opens a socket, and
// it never imports mail, DAV or tool code. The reason is cost and time, not
// tidiness. An open socket keeps a Durable Object resident and billed for up to
// 15 minutes per connection. And a socket held here would escape the 20-second
// call deadline that bounds every mail conversation in the Worker request
// (ARCHITECTURE §3.2). So the socket stays in the Worker request, and this
// object only records "this person has one conversation open until time T".
//
// Only one place builds a stub for it: `agentFor` in `./lease.ts`, from the
// signed-in principal's user id, through the namespace's by-name accessor. The
// namespace offers three other id helpers — the name-to-id helper, the
// string-to-id helper and the random-id helper. None of them is used under
// `src/`, and they are described here by role only because the scan reads
// comments too.
//
// This module logs nothing (./.claude/CLAUDE.md §4).

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

/**
 * How long a lease lasts, in milliseconds, from the moment it is granted.
 *
 * 30 000 = the call deadline (20 000) + the drain bound (2 000) + the close
 * bound (3 000) + a 5 000 margin. That is the longest a leased mail call can
 * keep its socket open once the work has started, plus room to spare. A test
 * pins this number to that sum, so raising the deadline forces a decision here.
 *
 * It is a literal, not an import of the three constants, because this module
 * must not import mail code. The test does the import instead.
 *
 * The object sets the expiry. The caller never chooses it, so a stale caller
 * cannot extend a lease.
 */
export const LEASE_TTL_MS = 30000;

/** The storage key of the one record this object holds. */
const LEASE_KEY = "lease";

/** What is stored while a lease is held. */
interface LeaseRecord {
  /** Minted per grant. A release must present it. */
  readonly token: string;
  /** Absolute time, in ms since the epoch, after which the lease is free. */
  readonly expiresAt: number;
}

/** The answer to an acquire that was granted. */
export interface LeaseGrant {
  readonly held: true;
  readonly token: string;
}

/** The answer to an acquire that found the lease already held. */
export interface LeaseRefusal {
  readonly held: false;
}

/** Either answer to an acquire. */
export type LeaseAnswer = LeaseGrant | LeaseRefusal;

/** Whether a stored value is a lease that has not yet expired. */
function isLive(record: unknown, now: number): boolean {
  if (typeof record !== "object" || record === null) return false;
  const expiresAt = (record as { expiresAt?: unknown }).expiresAt;
  return typeof expiresAt === "number" && expiresAt > now;
}

/**
 * One person's connection lease.
 *
 * Two RPC methods and nothing else: no `fetch`, no alarm, no constructor logic,
 * no location hint. Both methods are synchronous on purpose. With no `await`
 * between the read and the write, the read-check-write is atomic under the
 * object's input gate, and the RPC reply is held back until the write is
 * durable.
 */
export class UserAgent extends DurableObject<Env> {
  /**
   * Take the lease, or say it is held.
   *
   * A record that is missing, malformed or past its expiry is free, and is
   * replaced by a new grant with a new token. A live record is left exactly as
   * it was.
   */
  acquire(): LeaseAnswer {
    const now = Date.now();
    const current = this.ctx.storage.kv.get<unknown>(LEASE_KEY);
    if (isLive(current, now)) return { held: false };

    const token = crypto.randomUUID();
    const record: LeaseRecord = { token, expiresAt: now + LEASE_TTL_MS };
    this.ctx.storage.kv.put(LEASE_KEY, record);
    return { held: true, token };
  }

  /**
   * Give the lease back.
   *
   * Deletes the record only when `token` is the current holder's token. Any
   * other value, of any type, changes nothing and does not throw. So a late or
   * duplicate release, or one from a request whose lease already expired and
   * was granted to someone else, cannot free the newer holder's lease.
   */
  release(token: unknown): void {
    if (typeof token !== "string") return;
    const current = this.ctx.storage.kv.get<unknown>(LEASE_KEY);
    if (typeof current !== "object" || current === null) return;
    if ((current as { token?: unknown }).token !== token) return;
    this.ctx.storage.kv.delete(LEASE_KEY);
  }
}
