import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { semanticIndex, SEMANTIC_DIMENSIONS } from "../../src/free/semantic-store";
import { createRecallStore } from "../../src/recall/index";
import { USER_A, USER_B, testPrincipal } from "../fixtures/two-users";

const stub = () => env.FREE_RECALL!.getByName("recall-v1");
const id = (n: number) => n.toString(16).padStart(64, "0");
const vector = (a: number, b = 0) => [a, b, ...new Array(SEMANTIC_DIMENSIONS - 2).fill(0)];
beforeEach(async () => {
  await runInDurableObject(stub(), (_instance, state) => { state.storage.sql.exec("delete from semantic_vectors"); state.storage.sql.exec("delete from semantic_counts"); });
});
describe("exact cosine with unchanged embeddings", () => {
  it("ranks against a double-precision reference, resolves ties deterministically and isolates users", async () => {
    const data = [vector(1), vector(1, 1), vector(0, 1), vector(-1), vector(1)];
    await stub().store(data.map((values, i) => ({ id: id(i + 1), namespace: USER_A.userId,
      values, metadata: { u: USER_A.userId, r: `ref-${i}`, s: `fixture-${i}`, a: Date.now() } })));
    await stub().store([{id: id(99), namespace: USER_B.userId, values: vector(1), metadata: {u: USER_B.userId}}]);
    const found = await stub().search(USER_A.userId, vector(1), 5);
    expect(found.matches.map(x => x.id)).toEqual([id(1), id(5), id(2), id(3), id(4)]);
    expect(found.matches.map(x => x.score)).toEqual([1, 1, 1 / Math.sqrt(2), 0, -1]);
    const store = createRecallStore(semanticIndex(env));
    const a = await testPrincipal(USER_A);
    const matches = await store.query(a, vector(1), {topK: 5});
    expect(matches.map(x => x.ref)).toEqual(["ref-0", "ref-4", "ref-1"]);
    await expect(semanticIndex(env).query(vector(1), {namespace: USER_A.userId, filter: {u: USER_B.userId}})).rejects.toThrow();
    await expect(stub().store([{id: id(1), namespace: USER_B.userId, values: vector(1), metadata: {u: USER_B.userId}}])).resolves.toBe(false);
  });

  it("keeps 10,000 vectors per person, scans through a cursor and refuses the next vector", async () => {
    const values = vector(1, 0.1);
    for (let page = 0; page < 100; page++) {
      await stub().store(Array.from({length: 100}, (_, j) => ({ id: id(page * 100 + j + 1),
        namespace: USER_A.userId, values, metadata: {u: USER_A.userId, r: `r-${page}-${j}`, s: "synthetic", a: 1} })));
    }
    const before = Date.now();
    const found = await stub().search(USER_A.userId, vector(1), 5);
    const elapsed = Date.now() - before;
    expect(found.matches).toHaveLength(5);
    expect(found.matches.map(x => x.id)).toEqual([1, 2, 3, 4, 5].map(id));
    expect(elapsed).toBeLessThan(30000); // local elapsed only, never a production CPU claim
    await expect(stub().store([{id: id(10001), namespace: USER_A.userId, values, metadata:{u: USER_A.userId}}])).resolves.toBe(false);
    await stub().remove([id(1)]);
    await stub().store([{id: id(10001), namespace: USER_A.userId, values, metadata:{u: USER_A.userId}}]);
  });

  it("rejects malformed vectors before writing anything", async () => {
    for (const values of [[], vector(0), vector(Infinity), vector(NaN)]) {
      await expect(stub().store([{id: id(1), namespace: USER_A.userId, values, metadata:{u: USER_A.userId}}])).resolves.toBe(false);
    }
    expect((await stub().search(USER_A.userId, vector(1), 1)).matches).toEqual([]);
  });
});
