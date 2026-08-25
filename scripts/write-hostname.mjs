// Bootstraps the local Worker config and bakes the deployed hostname into a
// generated TypeScript module.
//
// Two jobs, run on prepare/pretest/pretypecheck/predeploy:
//
//   1. If `wrangler.jsonc` does not exist, copy it from the tracked template
//      `wrangler.jsonc.example`. A fresh clone has only the template (the real
//      config is git-ignored, since it holds account-specific ids), so this is
//      what makes `npm install && npm test` work with zero manual setup. An
//      existing wrangler.jsonc is never touched — your real values are safe.
//
//   2. Write the hostname from `routes[0].pattern` into
//      `src/deployed-hostname.generated.ts` so module-init code can import it.
//      That code runs inside a deployed Worker, which has no filesystem and
//      cannot read the config off disk, so the value has to be baked in.
//
// Runnable:  node scripts/write-hostname.mjs

import { copyFileSync, existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { getHostname } from "./hostname.mjs";

const CONFIG_URL = new URL("../wrangler.jsonc", import.meta.url);
const TEMPLATE_URL = new URL("../wrangler.jsonc.example", import.meta.url);
const OUT_URL = new URL("../src/deployed-hostname.generated.ts", import.meta.url);

// 1. Bootstrap the local config from the template if it is missing.
if (!existsSync(CONFIG_URL)) {
  copyFileSync(TEMPLATE_URL, CONFIG_URL);
  process.stdout.write(
    `wrangler.jsonc not found — copied from wrangler.jsonc.example. ` +
      `Edit it and fill in your Cloudflare account id, KV namespace ids, and domain.\n`,
  );
}

// 2. Bake the hostname into the generated module.
const hostname = getHostname();
const body = `// GENERATED FILE — DO NOT EDIT, and do not commit it (it is git-ignored).
//
// Written by scripts/write-hostname.mjs from routes[0].pattern in
// wrangler.jsonc, which is the single source of truth for the deployed
// hostname. This module exists so module-init code (src/mcp/api-handler.ts,
// and src/auth/oauth.ts through it) can import the value: that code runs inside
// a deployed Worker, which has no filesystem and cannot read the config off
// disk. Regenerated on prepare/pretest/pretypecheck/predeploy.
//
// To change the hostname, edit wrangler.jsonc — never this file.
export const DEPLOYED_HOSTNAME = ${JSON.stringify(hostname)};
`;

writeFileSync(OUT_URL, body);
process.stdout.write(`wrote ${fileURLToPath(OUT_URL)} (DEPLOYED_HOSTNAME = ${hostname})\n`);
