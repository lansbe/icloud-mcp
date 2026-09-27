// SPIKE-11's local floor: what one lease acquire plus release costs in the pool
// (Phase 24, D-11).
//
// THIS IS A FLOOR, NOT THE VERDICT. Local workerd has no global name check and
// no placement, so the first-ever use of a name here skips the step that can
// cost "up to a few hundred milliseconds" on the real network. The verdict is
// plan 24-04's real-network probe, against its pre-registered rule: strict if
// the slowest first-ever-name acquire+release is under 1 000 ms.
//
// Three kinds of sample, for each of five fresh names shaped like a real user
// id (64 lowercase hex characters):
//   first    the first acquire+release on a never-used name
//   warm     five more pairs on the same name
//   evicted  one pair after the object is evicted from memory
//
// Each sample is printed as one `[lease-cost]` line. The assertions are sanity
// only — every pair completes, every release frees the record, and no sample
// takes 5 seconds — so this file cannot flake on a slow machine.

import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

/** A fresh name shaped like a real user id: 64 lowercase hex characters. */
function freshName(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The sanity ceiling on one sample. Far above any plausible local cost. */
const SAMPLE_CEILING_MS = 5000;

/** One timed acquire+release on this name. Returns the elapsed milliseconds. */
async function timedPair(name: string): Promise<number> {
  const stub = env.USER_AGENT.getByName(name);
  const started = performance.now();
  const answer = await stub.acquire();
  expect(answer.held).toBe(true);
  await stub.release((answer as { token: string }).token);
  const elapsed = performance.now() - started;

  const left = await runInDurableObject(stub, (_instance, state) =>
    state.storage.kv.get("lease"),
  );
  expect(left).toBeUndefined();
  return elapsed;
}

/** Print one sample. Only the kind and the number, never a binding. */
function report(kind: string, elapsed: number): void {
  console.info(`[lease-cost] ${kind} ${elapsed.toFixed(2)} ms`);
}

describe("SPIKE-11 local floor (not the verdict)", () => {
  it("times first-ever, warm and after-eviction acquire+release pairs", async () => {
    for (let n = 0; n < 5; n += 1) {
      const name = freshName();
      expect(name).toMatch(/^[0-9a-f]{64}$/);

      const first = await timedPair(name);
      report("first", first);
      expect(first).toBeLessThan(SAMPLE_CEILING_MS);

      for (let w = 0; w < 5; w += 1) {
        const warm = await timedPair(name);
        report("warm", warm);
        expect(warm).toBeLessThan(SAMPLE_CEILING_MS);
      }

      await evictDurableObject(env.USER_AGENT.getByName(name));
      const evicted = await timedPair(name);
      report("evicted", evicted);
      expect(evicted).toBeLessThan(SAMPLE_CEILING_MS);
    }
  });
});
