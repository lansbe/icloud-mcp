// Deployable synthetic probe; intentionally separate from the local auth harness.
// One fixed sequence for the lifetime of this namespace. No reset or user input.
import { SemanticStore } from "../../src/free/semantic-store";
import type { Env } from "../../src/env";
import { extractText } from "unpdf";
import { extractMessage } from "../../src/mail/mime";
import { textPdf } from "../bench/pdf-fixture";

const TOTAL_STEPS = 107;
const OWNER = "a".repeat(64);
const OBJECT_NAME = "synthetic-once-v1";
type State = { next: number; phase: string; result: string };
type ProbeEnv = { PROBE: DurableObjectNamespace<CloudProbe> };

function label(step: number): string {
  if (step < 2) return `pdf-small-${step === 0 ? "first" : "warm"}`;
  if (step < 4) return `pdf-large-${step === 2 ? "first" : "warm"}`;
  if (step === 4) return "mime";
  if (step < 105) return `seed-${step - 5}`;
  return `cosine-10000-${step === 105 ? "first" : "warm"}`;
}

export class CloudProbe extends SemanticStore {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS probe_state (
      id INTEGER PRIMARY KEY CHECK(id = 1), next INTEGER NOT NULL,
      phase TEXT NOT NULL, result TEXT NOT NULL)`);
    ctx.storage.sql.exec(`INSERT OR IGNORE INTO probe_state VALUES (1, 0, 'ready', '{}')`);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS probe_results (
      step INTEGER PRIMARY KEY, label TEXT NOT NULL, result TEXT NOT NULL)`);
  }

  private state(): State {
    return this.ctx.storage.sql.exec<State>(`SELECT next, phase, result FROM probe_state WHERE id = 1`).one();
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/status" && request.method === "GET") {
      return Response.json({ ...this.state(), total: TOTAL_STEPS,
        results: this.ctx.storage.sql.exec(`SELECT step, label, result FROM probe_results ORDER BY step`).toArray() });
    }
    if (path !== "/step" || request.method !== "POST" || request.headers.get("content-length") !== "0") {
      return new Response("Unsupported probe request", {status: 400});
    }
    // No await before this atomic reservation. Concurrent calls and a restarted
    // isolate see running; a crash consumes its attempt permanently.
    const state = this.ctx.storage.transactionSync(() => {
      const state = this.state();
      if (state.phase === "ready" && state.next < TOTAL_STEPS) {
        this.ctx.storage.sql.exec(`UPDATE probe_state SET phase = 'running', next = next + 1 WHERE id = 1`);
        return state;
      }
      return null;
    });
    if (!state) return Response.json({...this.state(), total: TOTAL_STEPS}, {status: 409});
    // Persist the attempt before any heavy computation, even across a crash.
    await this.ctx.storage.sync();
    const name = label(state.next);
    try {
      const result = await this.work(state.next);
      this.ctx.storage.transactionSync(() => {
        const encoded = JSON.stringify(result);
        this.ctx.storage.sql.exec(`INSERT INTO probe_results VALUES (?, ?, ?)`, state.next, name, encoded);
        this.ctx.storage.sql.exec(`UPDATE probe_state SET phase = ?, result = ? WHERE id = 1`,
          state.next + 1 === TOTAL_STEPS ? "complete" : "ready", encoded);
      });
      return Response.json({step: state.next, label: name, result, next: state.next + 1, total: TOTAL_STEPS,
        phase: state.next + 1 === TOTAL_STEPS ? "complete" : "ready"});
    } catch {
      this.ctx.storage.sql.exec(`UPDATE probe_state SET phase = 'failed', result = ? WHERE id = 1`,
        JSON.stringify({step: state.next, label: name}));
      return Response.json({phase: "failed", step: state.next, label: name}, {status: 500});
    }
  }

  private async work(step: number): Promise<Record<string, unknown>> {
    if (step < 4) {
      const large = step >= 2;
      const line = "Synthetic benchmark text with no personal information. ".repeat(2);
      const pdf = textPdf(large ? Array.from({length: 360}, () => Array.from({length: 45}, () => line))
        : [["Synthetic document."]]);
      const bytes = pdf.byteLength;
      const result = await extractText(pdf, {mergePages: true});
      if (result.totalPages !== (large ? 360 : 1) || !result.text.includes("Synthetic")) throw new Error("pdf-fixture");
      return {bytes, pages: result.totalPages, characters: result.text.length};
    }
    if (step === 4) {
      const mime = new TextEncoder().encode("From: synthetic@example.invalid\r\nTo: fixture@example.invalid\r\nSubject: Synthetic\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
        + "<p>Synthetic &amp; safe</p>".repeat(16000));
      const parsed = await extractMessage(mime);
      if (parsed.subject !== "Synthetic") throw new Error("mime-fixture");
      return {bytes: mime.byteLength, subject: parsed.subject};
    }
    const values = [1, ...new Array(1023).fill(0)];
    if (step < 105) {
      const batch = step - 5;
      const ok = await super.store(Array.from({length: 100}, (_, i) => ({
        id: (batch * 100 + i + 1).toString(16).padStart(64, "0"), namespace: OWNER, values,
        metadata: {u: OWNER, r: "synthetic", s: "synthetic", a: 1},
      })));
      if (!ok) throw new Error("seed-failed");
      return {vectors: (batch + 1) * 100};
    }
    const result = await super.search(OWNER, values, 5);
    if (result.count !== 5 || result.matches.some(x => x.score !== 1)) throw new Error("cosine-fixture");
    return {count: result.count, score: result.matches[0]!.score, vectors: 10000, dimensions: 1024};
  }
}

const html = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>icloud-mcp — sonde Free</title>
<style>body{font:16px system-ui;max-width:850px;margin:48px auto;padding:20px}button{padding:12px}pre{white-space:pre-wrap}</style>
<h1>icloud-mcp — test synthétique borné</h1>
<p>Une seule séquence : quatre extractions PDF, un MIME, 10 000 vecteurs fictifs et deux recherches cosinus.
Aucun accès iCloud, aucun fichier reçu, aucun secret. Un échec arrête définitivement cette sonde.</p>
<p>Les durées ci-dessous sont des temps aller-retour navigateur, pas le CPU facturé par Cloudflare.</p>
<button id="run">Exécuter la séquence unique</button> <a href="/status">Résultats persistés</a><pre id="output"></pre>
<script>document.querySelector('#run').onclick=async function(){this.disabled=true;const out=document.querySelector('#output');
try{for(let n=0;n<107;n++){const start=performance.now();const response=await fetch('/step',{method:'POST',headers:{'x-probe-step':'fixed-v1'}});
const result=await response.json();out.textContent+=JSON.stringify({...result,browserRoundTripMs:Math.round(performance.now()-start)})+'\\n';
if(!response.ok||result.phase==='complete')break;}}catch{out.textContent+='Sonde interrompue. Consulter les résultats persistés.';}};</script></html>`;

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.search || (request.headers.get("content-length") ?? "0") !== "0" || request.headers.has("transfer-encoding") ||
        (request.method === "POST" && request.headers.get("content-length") !== "0")) {
      return new Response("No probe parameters or body accepted", {status: 400});
    }
    if (url.pathname === "/" && request.method === "GET") return new Response(html, {headers: {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
      "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
    }});
    const read = url.pathname === "/status" && request.method === "GET";
    const step = url.pathname === "/step" && request.method === "POST" && request.headers.get("x-probe-step") === "fixed-v1";
    if (!read && !step) return new Response("Not found", {status: 404});
    if (step && request.headers.get("origin") !== url.origin) return new Response("Same origin required", {status: 403});
    if (!env.PROBE) return new Response("Probe storage not configured", {status: 503});
    try { return await env.PROBE.getByName(OBJECT_NAME).fetch(request); }
    catch { return new Response("Probe stopped or unavailable", {status: 503}); }
  },
} satisfies ExportedHandler<ProbeEnv>;
