import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions, kCurrentWorker, Log, LogLevel } from "miniflare";
import { performance } from "node:perf_hooks";
import { mkdirSync, writeFileSync } from "node:fs";
import { prepareFree, validateFreeConfig } from "./free-config.mjs";

const cfg = prepareFree();
const host = validateFreeConfig(cfg).hostname;
mkdirSync("dist/bench", {recursive: true});
await build({entryPoints: ["scripts/bench/worker.ts"], outfile: "dist/bench/worker.mjs", bundle: true,
  format: "esm", platform: "browser", target: "es2022", external: ["cloudflare:*", "node:*"],
  conditions: ["workerd", "worker", "browser"], sourcemap: false});
const started = performance.now();
const mf = new Miniflare(convertV4MiniflareOptions({inspectorPort: 0, log: new Log(LogLevel.ERROR), workers: [{name: "local-benchmark", scriptPath: "dist/bench/worker.mjs", modules: true,
  compatibilityDate: "2026-08-01", compatibilityFlags: ["nodejs_compat"],
  durableObjects: Object.fromEntries(cfg.durable_objects.bindings.map(x => [x.name, {
    className: x.name === "FREE_APPLICATION" ? "BenchApplication" : x.class_name, useSQLite: true}])),
  kvNamespaces: ["OAUTH_KV", "DAV_CACHE", "ALLOW_LIST_KV"],
  bindings: {ALLOWED_APPLE_IDS_SEED: '["synthetic@example.invalid"]', CONFIRM_SECRET: "synthetic-benchmark-secret"},
  serviceBindings: {SELF: kCurrentWorker},
  // No network, AI or real account is reachable through this harness.
  outboundService() { throw new Error("Benchmark external network disabled"); },
}]}));
let socket;
const output = {scope: "local workerd V8 sampling; not Cloudflare metered CPU", date: new Date().toISOString(),
  node: process.version, platform: `${process.platform}/${process.arch}`, runtimeReadyMs: 0, measurements: []};
try {
  await mf.ready;
  output.runtimeReadyMs = performance.now() - started;
  const inspector = await mf.getInspectorURL();
  const listing = new URL("/json", inspector);
  listing.protocol = "http:";
  const targets = await (await fetch(listing)).json();
  const target = targets.find(x => x.title?.includes("local-benchmark")) ?? targets[0];
  if (!target?.webSocketDebuggerUrl) throw new Error("No local profiler target");
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let id = 0;
  const pending = new Map();
  socket.onmessage = event => { const msg = JSON.parse(event.data); const p = pending.get(msg.id);
    if (p) { pending.delete(msg.id); msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result); } };
  const send = (method, params = {}) => new Promise((resolve, reject) => { const n = ++id; pending.set(n, {resolve, reject}); socket.send(JSON.stringify({id:n, method, params})); });
  await send("Profiler.enable");
  await send("Profiler.setSamplingInterval", {interval: 100});
  async function measure(name, call) {
    await send("Profiler.start");
    const start = performance.now();
    const response = await call();
    const text = await response.text();
    const elapsedMs = performance.now() - start;
    const {profile} = await send("Profiler.stop");
    const nodes = new Map(profile.nodes.map(n => [n.id, n]));
    let sampledActiveUs = 0;
    for (let i = 0; i < (profile.samples?.length ?? 0); i++) {
      const label = nodes.get(profile.samples[i])?.callFrame.functionName;
      if (label !== "(idle)" && label !== "(root)") sampledActiveUs += profile.timeDeltas[i] ?? 0;
    }
    if (!response.ok) throw new Error(`${name}: HTTP ${response.status} ${text.slice(0, 200)}`);
    if (name.includes("whoami") && (!text.includes("synthetic@example.invalid") || text.includes('"isError":true'))) {
      throw new Error("Synthetic identity assertion failed");
    }
    const row = {name, elapsedMs, sampledActiveMs: sampledActiveUs / 1000, responseBytes: new TextEncoder().encode(text).byteLength};
    output.measurements.push(row); process.stdout.write(JSON.stringify(row) + "\n");
    return text;
  }
  const transport = await mf.getWorker();
  const fetchLocal = (path, init) => transport.fetch(`https://${host}${path}`, init);
  await measure("discovery-first-request", () => fetchLocal("/.well-known/oauth-authorization-server"));
  await measure("discovery-warm", () => fetchLocal("/.well-known/oauth-authorization-server"));
  const setup = await fetchLocal("/__local_bench/setup");
  if (!setup.ok) throw new Error("Synthetic auth setup failed");
  const token = (await setup.json()).access_token;
  const rpc = (method, params = {}) => fetchLocal("/mcp", {method: "POST", headers: {
    authorization: `Bearer ${token}`, host, "content-type": "application/json", accept: "application/json, text/event-stream"},
    body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})});
  await measure("oauth-bearer-and-whoami-first", () => rpc("tools/call", {name: "account_whoami", arguments: {}}));
  await measure("oauth-bearer-and-whoami-warm", () => rpc("tools/call", {name: "account_whoami", arguments: {}}));
  await measure("47-tool-schemas-first", () => rpc("tools/list"));
  await measure("47-tool-schemas-warm", () => rpc("tools/list"));
  for (const kind of ["mime", "pdf-small", "pdf-large"]) {
    await measure(`${kind}-first`, () => fetchLocal(`/__local_bench/${kind}`));
    await measure(`${kind}-warm`, () => fetchLocal(`/__local_bench/${kind}`));
  }
  const seeded = await fetchLocal("/__local_bench/vector-seed");
  if (!seeded.ok || (await seeded.json()).count !== 10000) throw new Error("Synthetic vector seeding failed");
  await measure("cosine-10000-first", () => fetchLocal("/__local_bench/vector-query"));
  await measure("cosine-10000-warm", () => fetchLocal("/__local_bench/vector-query"));
  mkdirSync("docs/free", {recursive: true});
  writeFileSync("docs/free/benchmark.local.json", JSON.stringify(output, null, 2) + "\n");
} finally { socket?.close(); await mf.dispose(); }
