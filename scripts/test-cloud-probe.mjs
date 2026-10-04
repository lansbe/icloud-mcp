import assert from "node:assert/strict";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from "miniflare";
import { mkdirSync } from "node:fs";

mkdirSync("dist/cloud-probe", {recursive: true});
const buildOptions = {bundle: true,
  format: "esm", platform: "browser", target: "es2022", external: ["cloudflare:*", "node:*"],
  conditions: ["workerd", "worker", "browser"], minify: true, sourcemap: false, legalComments: "eof"};
await build({...buildOptions, entryPoints: ["scripts/cloud-probe/worker.ts"], outfile: "dist/cloud-probe/worker.mjs"});
// This instrumentation is local only, never included in the deployable bundle.
await build({...buildOptions, outfile: "dist/cloud-probe/test-worker.mjs", stdin: {resolveDir: process.cwd(), contents: `
import worker, {CloudProbe} from './scripts/cloud-probe/worker.ts';
export default worker;
export class TestCloudProbe extends CloudProbe {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/__test/running' || path === '/__test/failed') {
      this.ctx.storage.sql.exec('UPDATE probe_state SET phase = ? WHERE id = 1', path.split('/').pop());
      return new Response('ok');
    }
    return super.fetch(request);
  }
}`}});
const mf = new Miniflare(convertV4MiniflareOptions({log: new Log(LogLevel.ERROR), workers: [{name: "bounded-probe",
  scriptPath: "dist/cloud-probe/test-worker.mjs", modules: true, compatibilityDate: "2026-08-01", compatibilityFlags: ["nodejs_compat"],
  durableObjects: {PROBE: {className: "TestCloudProbe", useSQLite: true}},
  outboundService() { throw new Error("No external network allowed"); },
}]}));
try {
  await mf.ready;
  const worker = await mf.getWorker();
  const origin = (await mf.ready).origin;
  const call = (path, init) => worker.fetch(origin + path, init);
  const step = () => call("/step", {method: "POST", headers: {origin, "x-probe-step": "fixed-v1", "content-length": "0"}});
  assert.equal((await call("/?count=999999")).status, 400);
  assert.equal((await call("/step", {method: "POST", body: "payload"})).status, 400);
  assert.equal((await call("/step", {method: "POST", headers: {"x-probe-step": "fixed-v1", "content-length": "0"}})).status, 403);
  assert.equal((await call("/reset", {method: "POST", headers: {"content-length": "0"}})).status, 404);
  assert.equal((await call("/")).status, 200);
  // Overlapping calls may finish successive stages, but may never repeat one.
  const concurrent = await Promise.all(Array.from({length: 8}, step));
  const accepted = concurrent.filter(r => r.status === 200);
  assert.ok(accepted.length > 0);
  assert.equal(concurrent.filter(r => r.status === 409).length, 8 - accepted.length);
  const indices = (await Promise.all(accepted.map(r => r.json()))).map(x => x.step).sort((a, b) => a - b);
  assert.deepEqual(indices, Array.from({length: accepted.length}, (_, i) => i));
  for (let i = accepted.length; i < 107; i++) {
    const response = await step();
    assert.equal(response.status, 200, `stage ${i}: ${await response.clone().text()}`);
    const data = await response.json(); assert.equal(data.step, i);
  }
  for (let i = 0; i < 5; i++) assert.equal((await step()).status, 409);
  const status = await (await call("/status")).json();
  assert.equal(status.phase, "complete"); assert.equal(status.next, 107); assert.equal(status.results.length, 107);
  assert.equal(JSON.parse(status.results[106].result).vectors, 10000);
  const namespace = await mf.getDurableObjectNamespace("PROBE");
  const stub = namespace.getByName("synthetic-once-v1");
  // Durable state is the guard, not an in-memory counter. A persisted running
  // attempt (including after a crash) must never restart or skip ahead.
  await stub.fetch("https://synthetic.invalid/__test/running");
  assert.equal((await step()).status, 409);
  await stub.fetch("https://synthetic.invalid/__test/failed");
  assert.equal((await step()).status, 409);
  console.log(JSON.stringify({passed: true, steps: status.results.length, vectors: 10000,
    checks: ["fixed input", "same origin", "concurrent reservation", "full sequence", "persistent stop", "no reset"],
    scope: "local workerd; no Cloudflare CPU measurement"}));
} finally { await mf.dispose(); }
