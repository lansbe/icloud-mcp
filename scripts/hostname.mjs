// The single place the deployed hostname is ever derived.
//
// Plan 01-02's verify commands, plan 01-05's smoke script, and
// scripts/write-hostname.mjs (which bakes the value into a generated module for
// the Worker bundle) all need the production hostname. Without this module each
// would carry its own copy of the same fragile text search against
// wrangler.jsonc, and each would be an undeclared dependency on how
// `node --eval` resolves module syntax against a "type": "module" package. One
// derivation, read by all.
//
// The hostname has ONE source of truth — routes[0].pattern in wrangler.jsonc.
// This module is its only reader; everything else derives from here.
//
// Importable:  import { getHostname } from "./scripts/hostname.mjs";
// Runnable:    HOST=$(node scripts/hostname.mjs)

import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const CONFIG_URL = new URL("../wrangler.jsonc", import.meta.url);
// Fallback for a fresh clone that has not yet copied the template into place:
// the real wrangler.jsonc is git-ignored, so before `npm install` runs only the
// tracked template exists. Reading it still yields the placeholder hostname,
// which is enough for a typecheck/test run.
const TEMPLATE_URL = new URL("../wrangler.jsonc.example", import.meta.url);

/**
 * Remove `//` line comments and block comments from a JSONC document without
 * touching text inside string literals. Runs as a character scanner rather
 * than a regex because a regex cannot tell a comment from a `//` that happens
 * to sit inside a string value (for example a URL or a path).
 *
 * Newlines inside removed regions are preserved so that any JSON.parse error
 * still reports a line number matching the original file.
 *
 * Exported so a second script can read a DIFFERENT value out of the same
 * git-ignored JSONC config without re-typing the scanner. The hostname itself
 * still has exactly one reader -- `getHostname()` below -- so exporting the
 * text helpers does not give the hostname a second home.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      } else if (ch === "\n") {
        out += ch;
      }
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === "\\") {
        // Consume the escaped character verbatim so an escaped quote does not
        // look like the end of the string.
        out += text[i + 1] ?? "";
        i++;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }

    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }

    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    out += ch;
  }

  return out;
}

/**
 * Remove trailing commas before `}` or `]`. JSONC permits them; JSON.parse
 * does not. String-aware for the same reason as the comment stripper.
 *
 * Exported for the same reason as `stripJsonComments`.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripTrailingCommas(text) {
  let out = "";
  let inString = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += text[i + 1] ?? "";
        i++;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }

    if (ch === ",") {
      // Look ahead past whitespace for a closing brace or bracket.
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j++;
      if (text[j] === "}" || text[j] === "]") continue; // drop the comma
    }

    out += ch;
  }

  return out;
}

/**
 * Read the production hostname out of wrangler.jsonc.
 *
 * The route is read STRUCTURALLY — the file is comment-stripped, JSON.parse'd,
 * and the parsed object is walked to `routes[0].pattern`. It is deliberately
 * not pulled out of the raw file text with a pattern match: D-04 chose jsonc
 * precisely so the config could be filled with rationale comments, and a
 * text-level search for the first `pattern` key returns whichever one appears
 * earliest in the file regardless of which block it belongs to.
 *
 * Throws rather than returning undefined, so a later `curl` cannot build a URL
 * out of a missing value.
 *
 * @returns {string} e.g. "icloud-mcp.example.com"
 */
export function getHostname() {
  const configPath = fileURLToPath(CONFIG_URL);

  let raw;
  try {
    raw = readFileSync(CONFIG_URL, "utf8");
  } catch {
    // No real config yet — fall back to the tracked template.
    try {
      raw = readFileSync(TEMPLATE_URL, "utf8");
    } catch (cause) {
      throw new Error(
        `Cannot read Worker config at ${configPath} or its template ${fileURLToPath(TEMPLATE_URL)}`,
        { cause },
      );
    }
  }

  let config;
  try {
    config = JSON.parse(stripTrailingCommas(stripJsonComments(raw)));
  } catch (cause) {
    throw new Error(
      `${configPath} is not valid JSONC — could not parse it after stripping comments`,
      { cause },
    );
  }

  const routes = config?.routes;
  if (!Array.isArray(routes) || routes.length === 0) {
    throw new Error(
      `${configPath} declares no "routes" entry. With workers_dev: false (D-02) ` +
        `the Worker has no reachable URL at all without a custom-domain route.`,
    );
  }

  const pattern = routes[0]?.pattern;
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new Error(
      `${configPath} routes[0] has no "pattern" string — cannot derive the deployed hostname.`,
    );
  }

  return pattern;
}

// Runnable as well as importable: print the hostname and nothing else, so a
// shell can write `HOST=$(node scripts/hostname.mjs)`.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(`${getHostname()}\n`);
}
