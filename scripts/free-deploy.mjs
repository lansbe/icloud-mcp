import { spawnSync } from "node:child_process";
import { prepareFree, validateFreeConfig } from "./free-config.mjs";

const dry = process.argv.includes("--dry-run");
const config = prepareFree();
const { problems } = validateFreeConfig(config, !dry);
if (!dry && !process.argv.includes("--confirm-free-plan")) {
  problems.push("Deployment requires --confirm-free-plan after verifying Workers Free in the dashboard. This script cannot verify account billing.");
}
if (problems.length) {
  process.stderr.write(problems.join("\n") + "\n");
  process.exitCode = 1;
} else {
  const args = ["wrangler", "deploy", "--config", "wrangler.free.jsonc"];
  if (dry) args.push("--dry-run", "--outdir", "dist/free");
  const result = spawnSync("npx", args, { stdio: "inherit", env: { ...process.env, WRANGLER_SEND_METRICS: "false" } });
  process.exitCode = result.status ?? 1;
}
