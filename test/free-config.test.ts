import { describe, expect, it } from "vitest";
// @ts-expect-error -- Node-only tooling modules do not ship runtime declarations.
import { validateFreeConfig } from "../scripts/free-config.mjs";
// @ts-expect-error -- Node tooling is covered by runtime assertions.
import { stripJsonComments, stripTrailingCommas } from "../scripts/hostname.mjs";
import { matchRule, FORBIDDEN } from "../scripts/forbidden-tokens.mjs";

// @ts-expect-error -- Vite build-time raw glob has no ambient declaration.
const templates = import.meta.glob("../wrangler.free.jsonc.example", { eager: true, query: "?raw", import: "default" });
const config = () => JSON.parse(stripTrailingCommas(stripJsonComments(Object.values(templates)[0] as string)));
describe("Free deployment gates", () => {
  it("accepts the isolated Free template and refuses live placeholders", () => {
    expect(validateFreeConfig(config()).problems).toEqual([]);
    expect(validateFreeConfig(config(), true).problems.length).toBeGreaterThan(0);
  });
  it("refuses paid dependencies, missing services and extra public hosts", () => {
    for (const property of ["r2_buckets", "limits", "vectorize", "unsafe", "queues", "containers", "tail_consumers", "streaming_tail_consumers", "logpush"]) {
      const c = config(); c[property] = {};
      expect(validateFreeConfig(c).problems.length).toBeGreaterThan(0);
    }
    for (const kind of ["logs", "traces"]) {
      const e = config(); e.observability[kind] = {enabled: true};
      expect(validateFreeConfig(e).problems.length).toBeGreaterThan(0);
    }
    const c = config(); c.durable_objects.bindings.pop();
    expect(validateFreeConfig(c).problems.length).toBeGreaterThan(0);
    const d = config(); d.preview_urls = true;
    expect(validateFreeConfig(d).problems.length).toBeGreaterThan(0);
  });
  it("supports one free workers.dev origin without buying a domain", () => {
    const c = config(); c.routes = []; c.workers_dev = true;
    c.vars.PUBLIC_HOSTNAME = `${c.name}.synthetic.workers.dev`;
    expect(validateFreeConfig(c).problems).toEqual([]);
    c.routes = [{pattern: "second.example.com", custom_domain: true}];
    expect(validateFreeConfig(c).problems.length).toBeGreaterThan(0);
  });
  it("keeps the per-person namespace check and limits service exceptions to exact names and modules", () => {
    const rule = FORBIDDEN.find(x => x.id === "agent-name-not-from-principal")!;
    const call = 'env.FREE_BLOBS.getByName("attachments-v1")';
    expect(matchRule(rule, 0, "src/free/blob-store.ts", call)).toEqual([]);
    for (const source of [call.replace("FREE_BLOBS", "USER_AGENT"), call.replace('"attachments-v1"', 'request.name'), call.replace('"attachments-v1"', '"other"')]) {
      expect(matchRule(rule, 0, "src/free/blob-store.ts", source)).toHaveLength(1);
    }
    expect(matchRule(rule, 0, "src/other.ts", call)).toHaveLength(1);
    for (const [file, binding, name] of [["src/index.ts", "FREE_APPLICATION", "application-v1"],
      ["src/free/blob-store.ts", "FREE_BLOBS", "attachments-v1"],
      ["src/free/budget.ts", "FREE_BUDGET", "deployment-v1"],
      ["src/free/semantic-store.ts", "FREE_RECALL", "recall-v1"]]) {
      const fixed = `env.${binding}.getByName("${name}")`;
      expect(matchRule(rule, 0, file, fixed)).toHaveLength(0);
      for (const prefix of ["request.", "other", "$", "owner."]) {
        expect(matchRule(rule, 0, file, prefix + fixed)).toHaveLength(1);
      }
    }
  });
});
