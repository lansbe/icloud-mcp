// What the rules job did, kept in the person's own object (Phase 28, D-18).
//
// A ring of the last 100 entries under one key in the object's key-value
// storage. Each entry is a time, the run it belongs to, what kind of entry it
// is, the rule's id, the message's opaque id, and an outcome from a closed
// list. No subject, no address and no draft text is ever written here: the
// person reads this back through a tool, and the ring must not become a second
// copy of their mail.
//
// This module logs nothing.

/** The storage key of the ring. */
export const ACTIVITY_KEY = "activity";

/** The most entries the ring keeps. The oldest goes first. */
export const ACTIVITY_MAX = 100;

/** What an entry is about: a whole run, a flag, or a draft. */
export type ActivityKind = "run" | "flag" | "draft";

/** One entry. Ids and closed words only. */
export interface ActivityEntry {
  /** When, in milliseconds since the epoch. */
  readonly at: number;
  /** The run it belongs to. */
  readonly runId: string;
  readonly kind: ActivityKind;
  /** The rule's id, for an action; null for a run entry. */
  readonly ruleId: string | null;
  /** The message's opaque id, for an action; null for a run entry. */
  readonly messageId: string | null;
  /** A run outcome or an action outcome, from their closed lists. */
  readonly outcome: string;
}

/** The part of the object's storage the ring uses. */
export interface ActivityStorage {
  get<T = unknown>(key: string): T | undefined;
  put<T>(key: string, value: T): void;
}

/** Whether `value` is an entry this module wrote. */
function isEntry(value: unknown): value is ActivityEntry {
  if (typeof value !== "object" || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.at === "number" &&
    typeof e.runId === "string" &&
    (e.kind === "run" || e.kind === "flag" || e.kind === "draft") &&
    (e.ruleId === null || typeof e.ruleId === "string") &&
    (e.messageId === null || typeof e.messageId === "string") &&
    typeof e.outcome === "string"
  );
}

/** Every stored entry that parses, oldest first. */
function stored(storage: ActivityStorage): ActivityEntry[] {
  const value = storage.get<unknown>(ACTIVITY_KEY);
  return Array.isArray(value) ? value.filter(isEntry) : [];
}

/** Append one entry, dropping the oldest past `ACTIVITY_MAX`. Synchronous. */
export function appendActivity(storage: ActivityStorage, entry: ActivityEntry): void {
  const next = [...stored(storage), entry];
  storage.put(ACTIVITY_KEY, next.slice(Math.max(0, next.length - ACTIVITY_MAX)));
}

/** The newest `n` entries, newest first. */
export function readActivity(storage: ActivityStorage, n: number): ActivityEntry[] {
  const count = Math.max(0, Math.min(ACTIVITY_MAX, Math.floor(n)));
  return stored(storage).reverse().slice(0, count);
}
