// The owner's command: see every connection to this server, and cut any of them off.
//
//   node scripts/grants.mjs
//   node scripts/grants.mjs list [--address <a>]...
//   node scripts/grants.mjs revoke <grantId>... [--yes]
//   node scripts/grants.mjs revoke --address <a> [--yes]
//   node scripts/grants.mjs revoke --legacy-owner [--yes]
//   node scripts/grants.mjs prune-clients [--yes]
//   node scripts/grants.mjs --help
//
// **It runs as YOU, through wrangler's own login, and there is no web endpoint
// for this.** That was a decision, not an omission: a revoke endpoint would be
// new attack surface on a server that reaches real personal mail, for a job one
// person does a few times a year. Nothing here is reachable from the internet.
//
// **It always reads the REMOTE store.** Every command this runs carries the
// remote flag, fixed inside the store adapter in `grants-core.mjs` rather than
// passed in from here. Without it wrangler talks to the local simulator on this
// machine: the listing comes back empty, which looks exactly like "no
// connections", and a delete succeeds against nothing. The Phase 11 runbook
// records that trap against a hand-typed command.
//
// **It prints masked addresses only.** `u***@example.com` with bullets, from the
// one masking function in `src/principal.ts`. An address given after --address
// is used to work out which group to label and is never printed back.
//
// **It needs the local `wrangler.jsonc`.** That file is git-ignored and holds the
// namespace ids, so the binding names used here resolve through it. On a fresh
// clone, copy the example config and fill it in first.
//
// **What it can delete.** Two things, and only after printing them and being
// told --yes. A grant and the tokens under it. And a client registration that NO
// grant names — which is a different job with a different reason: registration is
// unauthenticated by the OAuth spec, a client record never expires, and nothing
// else in this repository ever removes one, so they accumulate forever in the
// same namespace as the grants. A record a grant still names is never touched:
// deleting one makes that grant's next refresh answer `invalid_client` and signs
// that person out even though their grant is perfect.
//
// It never touches the allow list, which is step 1 of removing somebody and is a
// separate decision.
//
// **IT NEEDS NODE 22.18 OR LATER**, and the requirement is not cosmetic. Two
// things below exist only from that version. `module.registerHooks` — the
// synchronous resolve hook in step 1 — landed in 22.15, and unflagged TypeScript
// type stripping, which is what lets step 2 import `../src/principal` at all,
// landed in 22.18. Both are load-bearing rather than convenient: without the
// hook the Worker's extensionless imports do not resolve, and without type
// stripping the one masking rule and the one user-id rule cannot be reached, so
// this script would have to keep second copies of both — which is the exact
// drift its rule 1 exists to prevent.
//
// `package.json` declares the floor in `engines` and step 0 below checks it
// before anything version-dependent is touched, so an older runtime gets one
// sentence rather than a stack trace. That matters here more than anywhere: this
// is the command that ends a session after a lost laptop.
//
// Layout below, and the ORDER is load-bearing:
//
//   0. the runtime check, before any version-dependent import;
//   1. the resolve hook, registered before anything else is imported;
//   2. the imports, which only work once the hook is in place;
//   3. the wrangler runner, whose stdout is always captured;
//   4. the known addresses, read only once the arguments have been accepted;
//   5. the call, and the exit status.

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// 0. The runtime check.
//
// It comes first, and `node:module` is imported DYNAMICALLY below rather than at
// the top of this file, because that is the whole point: a named static import of
// a member the runtime does not have fails at LINK time, before any line of this
// file runs. On Node 20 that is a raw `SyntaxError` naming the member, with no
// hint that the version is the problem and nothing this file can say about it.
// So the check has to sit above the import that would fail.
//
// The same reasoning covers the three dynamic imports in step 2: they are all
// above the top-level try in step 5, so a failure there is also a raw stack
// trace. This check is what they are protected by.
//
// It fails OPEN on a version string it cannot read. A false refusal here would
// deny the owner their only revoke command over a formatting surprise, and an
// ugly stack trace is the lesser harm.
// ---------------------------------------------------------------------------

/** The floor, as major/minor. Matches `engines.node` in package.json. */
const MIN_NODE = [22, 18];

/** One fixed sentence. It names the version it found, which is not sensitive. */
const NODE_TOO_OLD =
  `This needs Node ${MIN_NODE[0]}.${MIN_NODE[1]} or later and this is ` +
  `Node ${process.versions.node}. It uses two things no earlier version has: ` +
  "the synchronous module resolve hook, and built-in TypeScript type stripping " +
  "so it can call the Worker's own masking and user-id functions rather than " +
  "keeping second copies of them. Install a newer Node and run this again. " +
  "Nothing was read and nothing was revoked.";

const parts = String(process.versions.node)
  .split(".")
  .slice(0, 2)
  .map((part) => Number.parseInt(part, 10));

if (
  parts.length === 2 &&
  Number.isInteger(parts[0]) &&
  Number.isInteger(parts[1]) &&
  (parts[0] < MIN_NODE[0] ||
    (parts[0] === MIN_NODE[0] && parts[1] < MIN_NODE[1]))
) {
  process.stderr.write(`${NODE_TOO_OLD}\n`);
  process.exit(1);
}

const { registerHooks } = await import("node:module");

// ---------------------------------------------------------------------------
// 1. The resolve hook.
//
// Two problems, one hook, and both of them exist because this script imports the
// Worker's OWN code rather than a copy of it. That is the whole point: the user
// id and the masked label have to come out of `src/principal.ts`, because a
// second copy of either rule here is how two rules drift until one address
// becomes two users, or until one of the two forms stops masking.
//
//   a. The Worker's modules import each other without a file extension, which
//      Node refuses. A relative specifier that fails for that reason is retried
//      once with the TypeScript extension. Node strips the types itself.
//   b. The OAuth library imports a class from the Workers runtime namespace,
//      which does not exist under Node. It is only used for an `instanceof`
//      check against a handler shape this script does not use, so an empty class
//      from a data URL satisfies it.
//
// Anything else is rethrown. A hook that swallowed a real resolution failure
// would turn a missing module into a confusing error much further along.
// ---------------------------------------------------------------------------

const RUNTIME_STUB = `data:text/javascript,${encodeURIComponent(
  "export class WorkerEntrypoint {}",
)}`;

registerHooks({
  resolve(specifier, context, next) {
    if (specifier === "cloudflare:workers") {
      return { url: RUNTIME_STUB, shortCircuit: true };
    }
    try {
      return next(specifier, context);
    } catch (error) {
      if (error?.code === "ERR_MODULE_NOT_FOUND" && specifier.startsWith(".")) {
        return next(`${specifier}.ts`, context);
      }
      throw error;
    }
  },
});

// ---------------------------------------------------------------------------
// 2. The imports. Dynamic, because a static import is hoisted above the hook
//    registration and would fail before the hook existed.
//
//    The library prints its own one-line notice about a compatibility flag when
//    it loads. It is left alone rather than filtered: it carries no data, and it
//    goes to the error stream, so it never mixes into anything captured here.
// ---------------------------------------------------------------------------

const { USAGE, createWranglerKv, runGrants } = await import("./grants-core.mjs");
const { ALLOW_LIST_KEY, parseAllowList } = await import(
  "../src/auth/allow-list"
);
const { unstable_readConfig } = await import("wrangler");

/** The repository root, so a run from any directory behaves the same. */
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** The Worker config, by absolute path rather than relative to the caller's directory. */
const CONFIG_PATH = fileURLToPath(new URL("../wrangler.jsonc", import.meta.url));

/**
 * This repository's OWN wrangler, never a global one.
 *
 * The version is pinned in `package.json`, and the flags and output shapes this
 * script depends on are that version's. A globally installed wrangler of some
 * other version is the shape that prints a listing this script then misreads.
 */
const WRANGLER = fileURLToPath(
  new URL("../node_modules/.bin/wrangler", import.meta.url),
);

// Every refusal is one fixed sentence, and none of them carries a caught value:
// wrangler's own output can echo a stored record back.
//
// THE COST OF THAT, SAID PLAINLY, BECAUSE IT IS REAL. A refusal that shows
// nothing cannot tell you a transient failure from a permanent one, and the
// first run of this script against the live store failed exactly that way and
// then worked on a retry with nothing changed. So both sentences tell you to run
// it again first. Reading the caught value out would be the obvious fix and is
// the one thing not on offer.
const WRANGLER_FAILED =
  "A wrangler command did not complete. Run this again: the first call of a " +
  "session sometimes fails and then works. If it fails twice, check that you " +
  "are logged in (npx wrangler whoami) and that the local wrangler.jsonc names " +
  "the bindings.";
const SEED_UNREADABLE =
  "Could not read the seed address out of the local Worker config, so a group " +
  "may show as unknown. Pass --address <a> to label it.";
const STORED_LIST_UNREADABLE =
  "Could not read the stored allow list, so a group may show as unknown. The " +
  "listing below is still complete; only the labels are affected. Pass " +
  "--address <a> to label a group, or run this again.";
const SOMETHING_WENT_WRONG =
  "This could not finish, so nothing above should be trusted as complete. " +
  "Nothing was revoked unless a line above says it was. Run it again before " +
  "concluding anything: a first call that fails and then works has been seen.";

// ---------------------------------------------------------------------------
// 3. The runner.
// ---------------------------------------------------------------------------

/**
 * Run one wrangler command and hand back its standard output.
 *
 * **Output is always CAPTURED, never inherited.** A raw grant record holds
 * ciphertext and a wrapped key, and a raw token record holds a hash; inheriting
 * the stream would put whichever one this happened to read straight into the
 * terminal and from there into the scrollback. Everything printed by this
 * program goes through the core's renderer, which prints only parsed summary
 * fields.
 *
 * **A failure throws one fixed sentence.** It carries neither wrangler's error
 * output nor its standard output, because either can echo a stored value back.
 *
 * @param {readonly string[]} args
 * @returns {string}
 */
function run(args) {
  try {
    return execFileSync(WRANGLER, [...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // A listing of a busy namespace is bigger than the default ceiling, and
      // hitting it would look like a failed command rather than a truncated one.
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    throw new Error(WRANGLER_FAILED);
  }
}

// ---------------------------------------------------------------------------
// 4. The known addresses.
// ---------------------------------------------------------------------------

/**
 * Add the named addresses from one parsed allow list.
 *
 * A list that admits nobody, and a list that admits everybody, both add no
 * names — neither one knows who is actually connected. Groups this cannot label
 * are shown by the first few characters of their id instead, which is the honest
 * answer rather than a guess.
 *
 * @param {{ kind: string, addresses?: ReadonlySet<string> }} list
 * @param {string[]} into
 */
function addNamed(list, into) {
  if (list.kind !== "some" || list.addresses === undefined) return;
  for (const address of list.addresses) into.push(address);
}

/**
 * Who this server knows about, so a group can be labelled by a masked address.
 *
 * Read from the same two places the login page reads: the seed in the Worker
 * config, and the one stored document. Both go through the real
 * `parseAllowList`, so this script cannot disagree with the door about what a
 * list means.
 *
 * It is a FUNCTION handed to the core rather than a list computed up front, and
 * that is the point: nothing below runs for `--help` or for a usage mistake, so
 * a mistyped command costs no wrangler call at all.
 *
 * Any `--address` values on the command line are added by the core, from the
 * parse it has already done, so the arguments are read exactly once.
 *
 * @returns {Promise<string[]>}
 */
async function knownAddresses() {
  const addresses = [];

  // The seed. `unstable_readConfig` is marked unstable by its own package, so a
  // failure here is survivable by design: say so once and carry on with what is
  // left, rather than refusing to list anything.
  try {
    const config = unstable_readConfig({ config: CONFIG_PATH });
    addNamed(parseAllowList(config?.vars?.ALLOWED_APPLE_IDS_SEED), addresses);
  } catch {
    process.stderr.write(`${SEED_UNREADABLE}\n`);
  }

  // The stored list. LISTED first and read only if the listing returns it: the
  // key may legitimately not exist, and a read of a key that is not there is a
  // failed command rather than an empty answer.
  //
  // WRAPPED, in the same shape the seed above uses, and for a sharper reason
  // (WR-07). `run` throws on any non-zero exit, and nothing between here and the
  // top-level catch handled it — so a wrangler hiccup while looking for the
  // allow-list document aborted the WHOLE command, a plain `list` included, with
  // the "nothing above should be trusted" sentence and exit 1. This read exists
  // only to put a nicer label on a group; a listing showing `unknown (id ...)`
  // is perfectly useful, and refusing to show anything is not.
  //
  // Not hypothetical: WRANGLER_FAILED itself records that the first wrangler
  // call of a session sometimes fails and then works, and this listing IS the
  // first wrangler call the program makes.
  const listStore = createWranglerKv(run, "ALLOW_LIST_KV");
  let unreadable = false;
  try {
    const listed = await listStore.list({ prefix: ALLOW_LIST_KEY });
    if (listed.keys.some((key) => key.name === ALLOW_LIST_KEY)) {
      addNamed(parseAllowList(await listStore.get(ALLOW_LIST_KEY)), addresses);
    }
  } catch {
    // Never read the caught value: it carries wrangler's own output, which can
    // echo a stored record back.
    unreadable = true;
  }

  // THE OTHER HALF OF THE SAME FAILURE (IN-06). The adapter COUNTS a read it
  // could not complete rather than throwing, so a failed `get` never reaches the
  // catch above — it just returns null and the list quietly holds nobody. The
  // core's own `READS_INCOMPLETE` note cannot see it either: that reads the
  // OAUTH_KV adapter's counter, and this is a second adapter with a counter of
  // its own that nothing was reading. The result was a group printing as
  // `unknown (id ...)` with no note at all, which is exactly the "a row dropped
  // in silence" outcome that message exists to prevent for the other store.
  //
  // One note either way, never two: a run that both threw and counted is still
  // one thing the owner needs to know.
  if (unreadable || (listStore.readFailures?.() ?? 0) > 0) {
    process.stderr.write(`${STORED_LIST_UNREADABLE}\n`);
  }

  return addresses;
}

// ---------------------------------------------------------------------------
// 5. The call, and the exit status.
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);

try {
  if (argv.includes("--help") || argv.includes("-h")) {
    // Answered AFTER the imports above, deliberately. Reaching this line means
    // the whole chain loaded under Node — the hook, the Worker's own modules,
    // and the OAuth library — with no network touched and no store read. That
    // makes --help the cheapest check that this script still works at all.
    process.stdout.write(`${USAGE}\n`);
    process.exitCode = 0;
  } else {
    process.exitCode = await runGrants(argv, {
      kv: createWranglerKv(run, "OAUTH_KV"),
      knownAddresses,
      write: (text) => process.stdout.write(text),
      writeError: (text) => process.stderr.write(text),
    });
  }
} catch {
  // The caught value is never printed. A thrown error here would carry
  // wrangler's own output, which can echo a stored value.
  process.stderr.write(`${SOMETHING_WENT_WRONG}\n`);
  process.exitCode = 1;
}
