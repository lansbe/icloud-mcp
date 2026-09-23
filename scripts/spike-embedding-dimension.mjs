// SPIKE-10: measure the embedding model's output dimension by RUNNING it.
//
// The number is absent from Cloudflare's model catalogue page and from the
// published model schema, so it cannot be asserted -- only measured. And it has
// to be measured BEFORE an index exists, because a Vectorize index's dimension
// is fixed at creation and cannot be changed afterwards. Getting it wrong costs
// re-embedding the whole retained corpus into a new index.
//
// This script therefore creates nothing. It adds no binding to the Worker
// config, no index, and no npm dependency. It runs the model once over the
// account-scoped HTTP endpoint with the owner's own token, reads the shape off
// the answer, and exits.
//
// RUN IT WITH:
//
//   CLOUDFLARE_API_TOKEN=... node scripts/spike-embedding-dimension.mjs
//
// The token wants the narrowest scope that can run a model: Account ->
// Workers AI -> Read on this one account, and nothing else. It is created by
// the owner, is never stored in this repository, and should live only in the
// shell that runs this once.
//
// THE TOKEN IS NEVER WRITTEN OUT, and neither is the environment object it came
// from. CLAUDE.md section 4's ban reaches scripts/ as well as src/, and it is
// blunt on purpose: a diagnostic line naming the bare environment object leaks
// every secret in it at once, with no secret-named variable anywhere in sight.
// Output here goes through the process's standard-output writer, the same
// mechanism scripts/grants.mjs uses, and every value it writes is either a
// constant in this file or an integer read off a response.

import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { stripJsonComments, stripTrailingCommas } from "./hostname.mjs";

/** The model under measurement. Named once, written into the output, so the
 *  verdict cannot end up recording a dimension without its model. */
const MODEL = "@cf/baai/bge-m3";

/** The environment variable the token is read from. */
const TOKEN_VAR = "CLOUDFLARE_API_TOKEN";

/** One short string of input. The content is irrelevant -- only the SHAPE of
 *  the answer is read -- so it is a fixed, uninteresting sentence rather than
 *  anything from the account. Nothing personal reaches Workers AI here. */
const PROBE_TEXT = "a short sentence, measured only for the shape of its answer";

/** The real Worker config. Deliberately NOT falling back to
 *  wrangler.jsonc.example the way scripts/hostname.mjs does: the template
 *  carries a placeholder account id, and a request built from a placeholder
 *  fails as a 404 that reads like a broken endpoint rather than as unconfigured
 *  local state. */
const CONFIG_URL = new URL("../wrangler.jsonc", import.meta.url);

/** A Cloudflare account id is 32 lowercase hex characters. Checked so the
 *  template's placeholder cannot be sent to the API. */
const ACCOUNT_ID = /^[0-9a-f]{32}$/;

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_CANNOT_TRY = 2;

const NO_TOKEN = `No ${TOKEN_VAR} in the environment, so nothing was measured and nothing was sent.

  Create an account-scoped API token with Account -> Workers AI -> Read on this
  one account, then:

    ${TOKEN_VAR}=... node scripts/spike-embedding-dimension.mjs

  The token is not stored anywhere in this repository. Keep it in the shell that
  runs this once.`;

/**
 * The Cloudflare account id, read out of the Worker config rather than typed
 * here. One declared place: `vars.R2_ACCOUNT_ID` in wrangler.jsonc, which is
 * the account handle the R2 binding already uses and is an opaque identifier
 * rather than a credential.
 *
 * Read STRUCTURALLY -- comment-stripped, JSON.parse'd, then walked -- for the
 * same reason scripts/hostname.mjs reads the route that way: the config is full
 * of rationale comments, and a text search would happily return a value out of
 * one of them.
 *
 * @returns {{ accountId: string } | { problem: string }}
 */
function readAccountId() {
  const configPath = fileURLToPath(CONFIG_URL);

  let raw;
  try {
    raw = readFileSync(CONFIG_URL, "utf8");
  } catch {
    return {
      problem: `Cannot read the Worker config at ${configPath}. It is git-ignored; copy wrangler.jsonc.example to wrangler.jsonc and fill in the account id.`,
    };
  }

  let config;
  try {
    config = JSON.parse(stripTrailingCommas(stripJsonComments(raw)));
  } catch {
    return {
      problem: `${configPath} is not valid JSONC -- it could not be parsed after stripping comments.`,
    };
  }

  const accountId = config?.vars?.R2_ACCOUNT_ID;
  if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) {
    return {
      problem: `${configPath} has no usable vars.R2_ACCOUNT_ID. It must be the 32-character account id, not the template's placeholder.`,
    };
  }

  return { accountId };
}

/**
 * Cloudflare's own top-level error codes from a failed response, and NOTHING
 * else from the body. A code is a number Cloudflare publishes; a message can
 * echo back what was sent.
 *
 * @param {unknown} body
 * @returns {string}
 */
function errorCodesOf(body) {
  const errors = /** @type {{ errors?: unknown }} */ (body)?.errors;
  if (!Array.isArray(errors)) return "none reported";
  const codes = errors
    .map((entry) => /** @type {{ code?: unknown }} */ (entry)?.code)
    .filter((code) => typeof code === "number");
  return codes.length > 0 ? codes.join(", ") : "none reported";
}

/**
 * Run the model once and report the shape of what comes back.
 *
 * @param {(text: string) => void} write
 * @param {(text: string) => void} writeError
 * @returns {Promise<number>} the process exit code
 */
export async function measureDimension(write, writeError, token) {
  // Checked FIRST, before the config is even opened, so the no-credential path
  // provably touches nothing: no file, no socket, no request.
  if (typeof token !== "string" || token.length === 0) {
    writeError(`${NO_TOKEN}\n`);
    return EXIT_CANNOT_TRY;
  }

  const account = readAccountId();
  if ("problem" in account) {
    writeError(`${account.problem}\n`);
    return EXIT_CANNOT_TRY;
  }

  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${account.accountId}/ai/run/${MODEL}`;

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ text: [PROBE_TEXT] }),
    });
  } catch {
    // The caught value is never printed: a fetch failure can carry the request
    // it failed on, and that request carries the token in a header.
    writeError(`The request to Workers AI did not complete.\n`);
    return EXIT_FAILED;
  }

  let body;
  try {
    body = await response.json();
  } catch {
    writeError(
      `HTTP ${response.status} from Workers AI, and the body was not JSON.\n`,
    );
    return EXIT_FAILED;
  }

  if (!response.ok) {
    writeError(
      `HTTP ${response.status} from Workers AI. Cloudflare error codes: ${errorCodesOf(body)}.\n`,
    );
    return EXIT_FAILED;
  }

  const shape = /** @type {{ result?: { shape?: unknown } }} */ (body)?.result
    ?.shape;
  if (
    !Array.isArray(shape) ||
    shape.length === 0 ||
    !shape.every((n) => typeof n === "number")
  ) {
    // Key NAMES only, never values. The shape of an answer is what this script
    // is for; the content of one is not.
    const keys = Object.keys(
      /** @type {Record<string, unknown>} */ (body?.result) ?? {},
    );
    writeError(
      `HTTP ${response.status}, but result.shape was not an array of numbers. ` +
        `Keys present on \`result\` (names only): ${keys.join(", ") || "none"}. ` +
        `Read the dimension off whichever of those carries it, and record which one.\n`,
    );
    return EXIT_FAILED;
  }

  const dimension = shape[shape.length - 1];
  const measuredAt = new Date().toISOString().slice(0, 10);

  write(
    [
      `model:      ${MODEL}`,
      `shape:      [${shape.join(", ")}]`,
      `dimension:  ${dimension}`,
      `measured:   ${measuredAt}`,
      ``,
      `That dimension is what the Vectorize index must be created with. It is`,
      `fixed at creation; changing it later means a new index and re-embedding`,
      `everything retained.`,
      ``,
    ].join("\n"),
  );
  return EXIT_OK;
}

// Runnable as well as importable.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await measureDimension(
    (text) => process.stdout.write(text),
    (text) => process.stderr.write(text),
    process.env[TOKEN_VAR],
  );
}
