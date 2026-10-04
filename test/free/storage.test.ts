import { env } from "cloudflare:workers";
import { runInDurableObject, runDurableObjectAlarm } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { vaultOf, attachmentStore, writeBlob } from "../../src/free/blob-store";
import { BLOB_CHUNK_BYTES, VAULT_MAX_BYTES } from "../../src/free/blob-vault";
import { budgetOf, FREE_BUDGETS } from "../../src/free/budget";
import { mintFreeUpload, handleUpload } from "../../src/free/upload";
import { mintSaveLink, claimSaveLink } from "../../src/save/link";
import { putSaved, getStaged, putStaged } from "../../src/staging/r2";
import { confirmStagedUpload } from "../../src/staging/presign";
import { reserveConfirmation } from "../../src/confirm";
import { USER_A, USER_B } from "../fixtures/two-users";
import { DEPLOYED_HOSTNAME } from "../../src/deployed-hostname.generated";

const key = () => `staging/${USER_A.userId}/upload-0123456789abcdef-${Date.now()}`;
beforeEach(async () => {
  await runInDurableObject(vaultOf(env), (_instance, state) => {
    state.storage.sql.exec("delete from chunks"); state.storage.sql.exec("delete from blobs");
  });
  await runInDurableObject(budgetOf(env), (_instance, state) => {
    state.storage.sql.exec("delete from budget"); state.storage.sql.exec("delete from claims");
  });
});

describe("SQLite attachment storage through the production port", () => {
  it("round trips a complete 4 MiB staged file in bounded chunks and isolates users", async () => {
    const bytes = new Uint8Array(4 * 1024 * 1024);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
    const staged = await putStaged(env, USER_A.userId, {
      bytes, filename: "synthetic.pdf", mimeType: "application/pdf", limitBytes: bytes.length, nowMs: Date.now(),
    });
    expect(staged.staged).toBe(true);
    const held = (await vaultOf(env).list(`staging/${USER_A.userId}/`))[0]!;
    expect((await getStaged(env, USER_A.userId, held.key))?.bytes).toEqual(bytes);
    expect(await getStaged(env, USER_B.userId, held.key)).toBeNull();
    const sizes = await runInDurableObject(vaultOf(env), (_instance, state) =>
      state.storage.sql.exec<{n: number; max: number}>("select count(*) as n, max(length(bytes)) as max from chunks").one());
    expect(sizes).toEqual({ n: bytes.length / BLOB_CHUNK_BYTES, max: BLOB_CHUNK_BYTES });
  });

  it("streams the full existing 20 MiB save ceiling, then deletes it", async () => {
    const bytes = new Uint8Array(20 * 1024 * 1024).fill(42);
    const saved = await putSaved(env, USER_A.userId, bytes, Date.now());
    expect(saved).not.toBeNull();
    const stored = await attachmentStore(env).get(saved!);
    const downloaded = new Uint8Array(await new Response(stored!.body).arrayBuffer());
    expect(downloaded.length).toBe(bytes.length);
    expect(downloaded.every(x => x === 42)).toBe(true);
    await attachmentStore(env).delete(saved!);
    expect(await attachmentStore(env).head(saved!)).toBeNull();
  });

  it("never publishes incomplete files; pending bytes are removed by the alarm", async () => {
    const k = key();
    expect(await vaultOf(env).begin(k, 10, {})).toBe(true);
    expect(await vaultOf(env).writeChunk(k, 1, new Uint8Array(10))).toBe(false);
    expect(await vaultOf(env).finish(k)).toBe(false);
    expect(await vaultOf(env).head(k)).toBeNull();
    await runInDurableObject(vaultOf(env), (_instance, state) =>
      state.storage.sql.exec("update blobs set expires = 0"));
    await runDurableObjectAlarm(vaultOf(env));
    expect(await vaultOf(env).begin(k, 10, {})).toBe(true);
  });

  it("reserves global capacity atomically before any bytes and refuses overwrites", async () => {
    const k = key();
    const answers = await Promise.all([vaultOf(env).begin(k, 1, {}), vaultOf(env).begin(k, 1, {})]);
    expect(answers.sort()).toEqual([false, true]);
    await runInDurableObject(vaultOf(env), (_instance, state) =>
      state.storage.sql.exec("update blobs set size = ?", VAULT_MAX_BYTES));
    expect(await vaultOf(env).begin(k + "1", 1, {})).toBe(false);
  });
});

describe("signed uploads, exact length and single use", () => {
  it("uploads then confirms a complete file, and refuses altered headers and replay", async () => {
    const input = { key: key(), contentLength: 6, contentType: "text/plain", filename: "fixture.txt" };
    const url = await mintFreeUpload(env, USER_A.userId, input);
    expect(new URL(url).hostname).toBe(DEPLOYED_HOSTNAME);
    const make = (text: string, filename = "fixture.txt") => new Request(url, { method: "PUT",
      headers: { "content-length": "6", "content-type": "text/plain", "x-amz-meta-filename": filename }, body: text });
    expect((await handleUpload(make("abcdef", "wrong"), env)).status).toBe(400);
    expect((await handleUpload(make("abcdef"), env)).status).toBe(201);
    expect((await handleUpload(make("ABCDEF"), env)).status).toBe(410);
    expect((await confirmStagedUpload(env, USER_A.userId, input.key, 6, Date.now(), Date.now() + 60000)).staged).toBe(true);
    expect((await confirmStagedUpload(env, USER_B.userId, input.key, 6, Date.now(), Date.now() + 60000)).staged).toBe(false);
    expect(new TextDecoder().decode((await getStaged(env, USER_A.userId, input.key))!.bytes)).toBe("abcdef");
  });

  it("refuses forged claims and under/over length bodies without publishing bytes", async () => {
    for (const body of ["abc", "abcdefgh"]) {
      const k = key() + (body.length === 3 ? "1" : "2");
      const url = await mintFreeUpload(env, USER_A.userId, { key: k, contentLength: 6, contentType: "text/plain", filename: "f" });
      const response = await handleUpload(new Request(url, { method: "PUT", body,
        headers: { "content-length": "6", "content-type": "text/plain", "x-amz-meta-filename": "f" } }), env);
      expect([400, 413]).toContain(response.status);
      expect(await vaultOf(env).head(k)).toBeNull();
      expect((await handleUpload(new Request(url + "x", { method: "PUT" }), env)).status).toBe(410);
    }
  });
});

describe("Free atomic claims and budgets", () => {
  it("allows exactly one racing save download and confirmation", async () => {
    const k = await putSaved(env, USER_A.userId, new Uint8Array([1]), Date.now());
    const link = await mintSaveLink(env, USER_A.userId, k!, 1, Date.now());
    const token = new URL(link!.url).pathname.slice("/save/".length);
    const claims = await Promise.all(Array.from({length: 8}, () => claimSaveLink(env, token, Date.now())));
    expect(claims.filter(Boolean)).toHaveLength(1);
    const confirmations = await Promise.allSettled(Array.from({length: 8}, () =>
      reserveConfirmation(env.CONFIRM_KV, USER_A.userId, "synthetic-confirmation", Math.floor(Date.now() / 1000) + 60)));
    expect(confirmations.filter(x => x.status === "fulfilled")).toHaveLength(1);
  });

  it("refuses the request beyond the budget and resets at the next UTC period", async () => {
    const stub = budgetOf(env);
    expect(await stub.take("semanticScans", FREE_BUDGETS.semanticScans.limit - 1)).toBe(true);
    const result = await Promise.all([stub.take("semanticScans"), stub.take("semanticScans")]);
    expect(result.sort()).toEqual([false, true]);
    await runInDurableObject(stub, (_instance, state) => state.storage.sql.exec("update budget set period = '2000-01-01'"));
    expect(await stub.take("semanticScans")).toBe(true);
  });
});
