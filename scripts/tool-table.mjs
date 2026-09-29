// README's tool block, written or checked from the code.
//
//   node scripts/tool-table.mjs --write   rewrite the block between the markers
//   node scripts/tool-table.mjs --check   exit 1 if the block has drifted
//
// The work is in scripts/tool-table-core.mjs. This file only reads and writes
// files, and prints through process.stdout.write and process.stderr.write, as
// scripts/grants.mjs does.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  TOOL_GROUPS,
  checkReadme,
  registeredNames,
  withBlock,
} from "./tool-table-core.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TOOLS_DIR = `${ROOT}src/mcp/tools/`;
const README = `${ROOT}README.md`;

const USAGE = "usage: node scripts/tool-table.mjs --write | --check\n";

function toolSources() {
  const sources = {};
  for (const file of readdirSync(TOOLS_DIR)) {
    if (file.endsWith(".ts")) {
      sources[`src/mcp/tools/${file}`] = readFileSync(TOOLS_DIR + file, "utf8");
    }
  }
  return sources;
}

function main(argv) {
  const mode = argv[0];
  if (argv.length !== 1 || (mode !== "--write" && mode !== "--check")) {
    process.stderr.write(USAGE);
    return 2;
  }
  const names = registeredNames(toolSources());
  let readme = readFileSync(README, "utf8");

  if (mode === "--write") {
    const next = withBlock(readme, TOOL_GROUPS);
    if (next !== readme) writeFileSync(README, next);
    process.stdout.write(next === readme ? "README.md is already up to date.\n" : "README.md written.\n");
    readme = next;
  }

  const findings = checkReadme(readme, TOOL_GROUPS, names);
  for (const finding of findings) process.stderr.write(`${finding.kind}: ${finding.detail}\n`);
  if (findings.length > 0) return 1;
  if (mode === "--check") process.stdout.write(`README.md's tool block matches the ${names.length} registered tools.\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
