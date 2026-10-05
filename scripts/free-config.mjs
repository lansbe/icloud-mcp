import { readFileSync, existsSync, copyFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { stripJsonComments, stripTrailingCommas } from "./hostname.mjs";
import { validOpenAiRedirect } from "../src/auth/openai-redirect.ts";

export function readFreeConfig(path = "wrangler.free.jsonc") {
  return JSON.parse(stripTrailingCommas(stripJsonComments(readFileSync(path, "utf8"))));
}

export function validateFreeConfig(config, live = false) {
  const problems = [];
  const required = { USER_AGENT: "UserAgent", FREE_APPLICATION: "FreeApplication", FREE_BLOBS: "BlobVault",
    FREE_BUDGET: "FreeBudget", FREE_RECALL: "SemanticStore" };
  for (const [binding, klass] of Object.entries(required)) {
    const entries = config.durable_objects?.bindings?.filter(x => x.name === binding) ?? [];
    if (entries.length !== 1 || entries[0].class_name !== klass || entries[0].script_name ||
        config.exports?.[klass]?.storage !== "sqlite") problems.push(`Missing local SQLite service: ${binding}`);
  }
  if (config.main !== "src/index.ts") problems.push("Use the guarded entrypoint.");
  for (const property of ["r2_buckets", "vectorize", "queues", "containers", "unsafe", "migrations", "limits", "tail_consumers", "streaming_tail_consumers", "logpush"]) {
    if (property in config) problems.push(`Not part of the Free profile: ${property}`);
  }
  if (config.preview_urls !== false) problems.push("Preview URLs must remain disabled.");
  if (config.services?.length !== 1 || config.services[0].binding !== "SELF" || config.services[0].service !== config.name) {
    problems.push("SELF must name this Worker only.");
  }
  if (config.ai?.binding !== "AI" || config.ai.remote === true) problems.push("Use the AI binding without remote local access.");
  if (config.observability?.enabled !== false || config.observability?.logs?.enabled === true || config.observability?.traces?.enabled === true) problems.push("Disable invocation logging: URLs can carry capabilities.");
  if (Object.keys(config.vars ?? {}).some(x => !["ALLOWED_APPLE_IDS_SEED", "PUBLIC_HOSTNAME", "ACCESS_MODE", "OPENAI_REDIRECT_URI"].includes(x))) {
    problems.push("Unexpected variable; credentials do not belong in configuration.");
  }
  if (!["mail-read-only", "read-only", "full"].includes(config.vars?.ACCESS_MODE)) problems.push("Set ACCESS_MODE explicitly to mail-read-only, read-only or full.");
  if (config.vars?.OPENAI_REDIRECT_URI !== undefined && !validOpenAiRedirect(config.vars.OPENAI_REDIRECT_URI)) {
    problems.push("Copy one exact OpenAI redirect URI from its connection management page.");
  }
  const namespaces = config.kv_namespaces ?? [];
  if ([...namespaces.map(x => x.binding)].sort().join(",") !== "ALLOW_LIST_KV,DAV_CACHE,OAUTH_KV") {
    problems.push("Use exactly three separate KV namespaces.");
  }
  if (new Set(namespaces.map(x => x.id)).size !== namespaces.length) problems.push("KV namespaces must not share an id.");
  if (live && namespaces.some(x => !/^[0-9a-f]{32}$/.test(x.id ?? ""))) problems.push("Configure real KV namespace ids.");
  const routes = config.routes ?? [];
  const hostname = config.workers_dev === true ? config.vars?.PUBLIC_HOSTNAME : routes[0]?.pattern;
  if (config.workers_dev === true) {
    if (routes.length !== 0 || !hostname?.endsWith(".workers.dev") || !hostname?.startsWith(`${config.name}.`)) {
      problems.push("Use one canonical workers.dev hostname and no additional route.");
    }
  } else if (config.workers_dev !== false || routes.length !== 1 || routes[0].custom_domain !== true) {
    problems.push("Use one canonical custom domain or one workers.dev hostname.");
  }
  if (typeof hostname !== "string" || !/^[a-zA-Z0-9.-]+$/.test(hostname)) problems.push("Invalid public hostname.");
  let allowed;
  try { allowed = JSON.parse(config.vars?.ALLOWED_APPLE_IDS_SEED); } catch {}
  if (!Array.isArray(allowed) || allowed.length < 1 || allowed.includes("*")) problems.push("Set an explicit, closed allow list.");
  if (live && JSON.stringify(config).includes("YOUR_")) problems.push("Replace all placeholders before deployment.");
  if (live && hostname?.endsWith(".example.com")) problems.push("Replace the example hostname.");
  return { problems, hostname };
}

export function prepareFree() {
  if (!existsSync("wrangler.free.jsonc")) copyFileSync("wrangler.free.jsonc.example", "wrangler.free.jsonc");
  const config = readFreeConfig();
  const { problems, hostname } = validateFreeConfig(config);
  if (problems.length) throw new Error(problems.join("\n"));
  writeFileSync("src/deployed-hostname.generated.ts",
    `// GENERATED from the Free profile. Do not commit.\nexport const DEPLOYED_HOSTNAME = ${JSON.stringify(hostname)};\n`);
  return config;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  prepareFree();
  process.stdout.write("Free configuration checked; hostname generated. No resources created.\n");
}
