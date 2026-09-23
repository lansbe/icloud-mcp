// The owner's grants tool, minus the terminal (LIFE-05).
//
// **What this file is.** Since Phase 11, removing somebody is two steps: take
// them off the list so they cannot sign in again, then end the session they
// already have. This is the second step. Now that a login never expires, a lost
// laptop or a rotated app-specific password leaves a grant alive until somebody
// revokes it, so the owner needs to SEE every connection under a name he
// recognises and cut off any of them.
//
// **It is importable from two runtimes, and that is why it is not TypeScript.**
// `test/grants-script.test.ts` imports it inside the Workers pool, where the
// real provider, the real store and the real `userIdOf` live, and
// `scripts/grants.mjs` imports it under Node behind a resolve hook. So it
// imports NOTHING from Node's own module namespace: one such import and the
// pool can no longer load it, and the tests would have to be replaced by a
// mock of the very library this file exists to call. `scripts/grants-core.d.mts`
// carries the types so the test compiles under `strict` without `allowJs`.
//
// **It prints nothing.** Every function here returns text or a value, and the
// caller decides where it goes. That is what lets the test read the output
// rather than capture a stream, and it is why there is no logging call anywhere
// below — the scan refuses one in this directory too, and the reason is the same
// as it is under src/: output from here would carry stored values.
//
// Three rules, and each one is a thing this script must never do:
//
//   1. IT HASHES, FOLDS AND MASKS NOTHING ITSELF. The user id comes from
//      `userIdOf` and the masked label from `maskAppleId`, both in
//      `src/principal.ts`, which is the one place either rule is written down. A
//      second copy here is how two forms drift until one of them stops masking —
//      or until one address becomes two users. The listing and the revoke come
//      from the library's own `listUserGrants` and `revokeGrant`, reached through
//      `getOAuthApi`, because the revoke has to delete the tokens BEFORE the
//      grant and the library already does that in the right order.
//
//   2. NO RAW STORED VALUE REACHES THE CALLER. A grant record holds ciphertext
//      and a wrapped key. Only the library's summary fields are read, and every
//      string that came from the store goes through `printable` before it is
//      rendered: a client name is chosen by whoever registered, and an escape
//      sequence printed raw would drive the owner's terminal.
//
//   3. NOTHING IS DELETED THAT WAS NOT PRINTED FIRST, and nothing is deleted at
//      all without `--yes`. An unknown or ambiguous id refuses the whole
//      request rather than guessing, because the guess would cut off the wrong
//      person's connection.
//
// **There is a second thing it can delete, and it is a different job.**
// `prune-clients` removes `client:` records that NO grant names. Registration is
// unauthenticated by the OAuth spec, a client record never expires, the library's
// own sweeper has a grant sweep and a token sweep and no client sweep, and
// calling that sweeper would perform the forced logout LIFE-01 exists to remove.
// So without this the records accumulate forever in the very namespace holding
// the grants and the tokens, on a write any stranger can make. The safe set is
// computed FROM the grants and never from the records, because a record a grant
// still claims is load-bearing: deleting one makes that grant's next refresh
// answer `invalid_client` even though the grant is perfect, which signs the
// person out (spike S2). The records are LISTED and never READ — a `client_name`
// is chosen by whoever registered and the endpoint accepts a body up to 1 MiB.
//
// The full grant id IS printed. It is needed to revoke, and it is not a
// credential on its own — an access token is `userId:grantId:secret` and the
// secret is the part that is never stored in the clear anywhere.

import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { maskAppleId, userIdOf } from "../src/principal";

/** The store's user segment for a grant made before this milestone. */
const LEGACY_USER_KEY = "owner";

/** What a group of legacy grants is called. The door has refused them since Phase 11. */
const LEGACY_LABEL = "legacy v1.0 owner grants";

/**
 * How many characters of an unlabelled user segment are shown.
 *
 * Eight is enough to tell two groups apart and to type as a target. The whole
 * 64 would be a stable handle on a person this server cannot name, printed into
 * a terminal whose scrollback ends up in a paste.
 */
const UNKNOWN_ID_CHARACTERS = 8;

/** U+2026 HORIZONTAL ELLIPSIS, as an escape so no editor can turn it into three dots. */
const ELLIPSIS = "\u2026";

/** The longest client name rendered. Chosen by whoever registered, so bounded. */
const CLIENT_NAME_MAX = 60;

/** A page cap, so a store that keeps handing back the same cursor cannot spin. */
const MAX_PAGES = 1000;

/** Exit codes. Zero is success; a usage refusal and a failed revoke differ. */
const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;

/**
 * The first sentence printed when `--yes` was not given, word for word.
 *
 * Plan 12-05 greps the recorded output for it, and `test/grants-script.test.ts`
 * compares against this export rather than against a second copy of the words,
 * so the sentence and its checks cannot drift apart.
 */
export const NOTHING_REVOKED =
  "Nothing was revoked. Re-run with --yes to revoke the grants listed above.";

/** The same sentence for the prune, so neither command can be misread as the other. */
export const NOTHING_PRUNED =
  "Nothing was deleted. Re-run with --yes to delete the client records above.";

/** What the owner sees when there is nothing to prune. */
const NO_ORPHAN_CLIENTS =
  "No orphan client registrations. Every client record still has a grant naming it.";

/**
 * Printed if a record turned out to be claimed after all.
 *
 * It names nothing. The point is that the record was KEPT, and the owner's next
 * action is the same either way: run the command again.
 */
const KEPT_CLAIMED_CLIENT =
  "A client record gained a grant while this ran, so it was kept. Run the command again.";

/** What the owner sees for an empty listing. It says which store it read. */
const NOTHING_FOUND =
  "No grants found. This read the REMOTE store, not the local simulator.";

/** Every usage form, in one place, so the entry's --help is not a second copy. */
export const USAGE = [
  "List and revoke the grants that let a Claude app reach this server.",
  "",
  "  node scripts/grants.mjs",
  "  node scripts/grants.mjs list [--address <a>]...",
  "  node scripts/grants.mjs revoke <grantId>... [--yes]",
  "  node scripts/grants.mjs revoke --address <a> [--yes]",
  "  node scripts/grants.mjs revoke --legacy-owner [--yes]",
  "  node scripts/grants.mjs prune-clients [--yes]",
  "  node scripts/grants.mjs --help",
  "",
  "prune-clients deletes client registrations that NO grant names. Registration",
  "is unauthenticated and a client record never expires, so they accumulate. A",
  "record a grant still names is never touched: deleting one signs that person",
  "out even though their grant is fine.",
  "",
  "Nothing is deleted without --yes. A revoke always prints its targets first.",
  "An --address value is used only to label a group; it is never printed back.",
].join("\n");

/** Fixed refusals. None of them carries anything from the input. */
const UNKNOWN_COMMAND = "Unknown command.";
const UNKNOWN_FLAG = "Unknown flag.";
const ADDRESS_NEEDS_VALUE = "--address needs an address after it.";
const LIST_TAKES_NO_IDS = "list takes no grant ids.";
const LIST_TAKES_NO_YES = "list deletes nothing, so --yes means nothing here.";
const PRUNE_TAKES_NO_TARGET =
  "prune-clients takes no grant id, no --address and no --legacy-owner. " +
  "It acts on every client record no grant names.";
const REVOKE_NEEDS_TARGET =
  "revoke needs a grant id, --address <a>, or --legacy-owner.";
const PREFIX_TOO_SHORT =
  "An id prefix must be at least 8 characters. Nothing was revoked.";
const NO_SUCH_GRANT = "No grant matches that id. Nothing was revoked.";
const AMBIGUOUS_GRANT =
  "That id prefix matches more than one grant. Nothing was revoked.";
const ADDRESS_REFUSED =
  "That is not an address this server would accept. Nothing was revoked.";
const NO_TARGETS = "No grants match that target. Nothing was revoked.";
const READS_INCOMPLETE =
  "Some records could not be read, so the listing above may be incomplete.";

/**
 * A string safe to put in a terminal: control characters replaced, length cut.
 *
 * Every character below 0x20, plus 0x7F and the 0x80-0x9F block, becomes a
 * question mark. Those are the ones that do something rather than show
 * something: an escape can clear the screen or move the cursor, a line break can
 * forge a whole extra row of output, and the upper block carries the eight-bit
 * forms of the same sequences.
 *
 * **The bidirectional and invisible controls go the same way, and for the same
 * reason (WR-02).** U+202A-U+202E are the embedding and override codes,
 * U+2066-U+2069 the isolates, and U+200B-U+200F and U+2060 are zero-width marks
 * and joiners; U+2028 and U+2029 are line and paragraph separators, which is the
 * forged-row problem again in a different block, and U+FEFF is the byte-order
 * mark. A trailing override REVERSES the display order of everything after it on
 * the row — and this string is printed one column to the left of the grant id the
 * owner is about to type into a `revoke`, with `created`, `expires` and the
 * client marker after it. A client name is chosen by whoever registered, so it
 * is exactly as untrusted as an escape sequence and deserves no more trust.
 *
 * The cut is applied as characters are kept, so a name made entirely of escapes
 * cannot push past the limit on its way through.
 *
 * **It iterates CODE POINTS, not UTF-16 code units (IN-02).** A cut landing
 * between a high and a low surrogate used to emit a lone surrogate, which renders
 * as a replacement character — and it meant the rendered length was in code units
 * rather than in characters, so `max` did not mean what it says. A surrogate pair
 * now counts as one and is kept or dropped whole.
 *
 * @param {unknown} value
 * @param {number} max
 * @returns {string}
 */
function printable(value, max) {
  if (typeof value !== "string") return "";
  let out = "";
  let kept = 0;
  for (const character of value) {
    if (kept >= max) break;
    const code = character.codePointAt(0);
    const dangerous =
      code < 0x20 ||
      code === 0x7f ||
      (code >= 0x80 && code <= 0x9f) ||
      (code >= 0x200b && code <= 0x200f) ||
      (code >= 0x2028 && code <= 0x202e) ||
      (code >= 0x2060 && code <= 0x2069) ||
      code === 0xfeff;
    out += dangerous ? "?" : character;
    kept += 1;
  }
  return out;
}

/**
 * A seconds-since-epoch stamp as an ISO day, or the unknown marker.
 *
 * The day rather than the instant: what the owner is answering is "was this made
 * before or after I changed my password", and a day answers it. A value that is
 * not a usable number comes back as a word rather than as `Invalid Date`.
 *
 * @param {unknown} value
 * @returns {string}
 */
function isoDay(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "unknown";
  const when = new Date(value * 1000);
  if (Number.isNaN(when.getTime())) return "unknown";
  return when.toISOString().slice(0, 10);
}

/**
 * Every key name under a prefix, following the store's cursor.
 *
 * Serial, one page at a time. The wrangler adapter paginates internally and
 * reports the listing complete, so there it is one call.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @param {string} prefix
 * @returns {Promise<string[]>}
 */
async function allKeysUnder(kv, prefix) {
  const names = [];
  let cursor;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const listed = await kv.list(
      cursor === undefined ? { prefix } : { prefix, cursor },
    );
    for (const key of listed?.keys ?? []) {
      if (typeof key?.name === "string") names.push(key.name);
    }
    if (listed?.list_complete !== false) break;
    if (typeof listed?.cursor !== "string" || listed.cursor.length === 0) break;
    cursor = listed.cursor;
  }
  return names;
}

/**
 * The distinct user segments that have at least one grant.
 *
 * Read from the key names rather than from the records, because the records can
 * only be fetched once you know which prefix to ask the library for.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @returns {Promise<string[]>}
 */
async function distinctUserKeys(kv) {
  const found = new Set();
  for (const name of await allKeysUnder(kv, "grant:")) {
    const segments = name.split(":");
    if (segments.length >= 3 && segments[1].length > 0) found.add(segments[1]);
  }
  return [...found];
}

/**
 * The client ids that still have a record.
 *
 * A grant naming a client that is gone is already dead: its next refresh answers
 * `invalid_client` even though the grant itself is fine (spike S2). Saying so is
 * what stops the owner revoking something that has already stopped working.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @returns {Promise<Set<string>>}
 */
export async function presentClientIds(kv) {
  const present = new Set();
  for (const name of await allKeysUnder(kv, "client:")) {
    present.add(name.slice("client:".length));
  }
  return present;
}

/**
 * Map each known address's user segment to its masked label.
 *
 * Serial on purpose: a fan-out over a store is the shape two scan rules exist to
 * refuse elsewhere in this project, and nothing here needs to be fast.
 *
 * An address the id function turns away is skipped rather than reported. A list
 * assembled from a config seed and a stored document can hold anything, and one
 * bad entry must not cost the owner the whole listing.
 *
 * @param {readonly string[]} addresses
 * @returns {Promise<Map<string, string>>}
 */
async function labelsFor(addresses) {
  const labels = new Map();
  for (const address of addresses) {
    const userKey = await userIdOf(address);
    if (userKey === null) continue;
    labels.set(userKey, maskAppleId(address));
  }
  return labels;
}

/**
 * The smallest options object the provider's constructor accepts.
 *
 * It is here rather than imported from `src/auth/oauth.ts` deliberately. That
 * module reaches the Worker's real handler, which reaches the socket module,
 * which Node cannot load at all. None of these values is used by the two
 * helpers this file calls — the constructor merely refuses to exist without
 * them.
 *
 * @returns {Record<string, unknown>}
 */
function minimalOptions() {
  const handler = {
    fetch() {
      return new Response(null, { status: 404 });
    },
  };
  return {
    apiRoute: "/mcp",
    apiHandler: handler,
    defaultHandler: handler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
  };
}

/**
 * The library's helpers over one store.
 *
 * The argument is an object literal built here and handed straight in. Nothing
 * is ever assigned onto one: the `env-assignment` scan rule reads this directory
 * too, and the reason it exists is that such an object is shared.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @returns {{ listUserGrants: Function, revokeGrant: Function }}
 */
function helpersOver(kv) {
  return getOAuthApi(minimalOptions(), { OAUTH_KV: kv });
}

/**
 * Wrap a wrangler runner as a store the library's helpers can use.
 *
 * `run(args)` runs the repository's own pinned wrangler and returns its stdout
 * as a string. It is injected rather than built here so this file stays free of
 * Node's process machinery and keeps running in the Workers pool.
 *
 * **The binding name and the remote flag are fixed at these call sites and are
 * never taken from a caller.** Without `--remote`, wrangler talks to the local
 * simulator on the owner's own machine: the listing comes back empty, which
 * looks exactly like "no grants", and a delete succeeds against nothing. That
 * trap has misled this project before — `11-RUNBOOK.md` records it against a
 * hand-typed command. A namespace id is refused for the other half of the same
 * reason: the binding reads the id out of the local `wrangler.jsonc`, so there
 * is one place it is written down and it is the place the deploy reads, while a
 * pasted id silently points at the wrong namespace after a re-provision and
 * fails as "the key is not there".
 *
 * @param {(args: readonly string[]) => string} run
 * @param {string} binding
 * @returns {import("./grants-core.d.mts").GrantStore}
 */
export function createWranglerKv(run, binding) {
  let failures = 0;

  return {
    async list(options) {
      const prefix = typeof options?.prefix === "string" ? options.prefix : "";
      const output = run([
        "kv",
        "key",
        "list",
        "--binding",
        binding,
        "--remote",
        "--prefix",
        prefix,
      ]);
      const parsed = JSON.parse(output.trim().length === 0 ? "[]" : output);
      const keys = Array.isArray(parsed)
        ? parsed.filter((entry) => typeof entry?.name === "string")
        : [];
      // wrangler pages internally and prints the whole prefix, so the listing is
      // always complete. Reporting otherwise would send the library's cursor
      // loop after a page that does not exist.
      return { keys, list_complete: true };
    },

    async get(name, options) {
      let output;
      try {
        output = run([
          "kv",
          "key",
          "get",
          "--binding",
          binding,
          "--remote",
          "--text",
          name,
        ]);
      } catch {
        // A key can vanish between the listing and this read: legacy grants
        // still carry a TTL. The caught value is never read — it would carry
        // wrangler's own stderr, which can echo a stored value. The count is
        // what the caller reports, because a row dropped in silence reads as
        // "that grant is already gone", and that is the one answer this tool
        // must not invent.
        failures += 1;
        return null;
      }
      if (options?.type !== "json") return output;
      try {
        return JSON.parse(output);
      } catch {
        failures += 1;
        return null;
      }
    },

    async delete(name) {
      run(["kv", "key", "delete", "--binding", binding, "--remote", name]);
    },

    readFailures() {
      return failures;
    },
  };
}

/**
 * Every grant in the store, grouped by user segment and labelled.
 *
 * Five steps, in this order:
 *
 *   1. build the library's helpers over the store;
 *   2. list the grant prefix once, to find each distinct user segment;
 *   3. hash each known address to build a segment-to-address map;
 *   4. list the client prefix once, to see which client records still exist;
 *   5. ask the library for each segment's grants and reduce them to rows.
 *
 * No whole stored value ever reaches a row. The library's summary carries no
 * props and no key material, and only its named fields are copied.
 *
 * `presentClients` is optional and exists so ONE run of the program pays for the
 * client listing once. `runGrants` reads that set itself — it needs it for the
 * orphan count too — and hands it down. A caller that passes nothing gets the
 * old behaviour and the listing happens here.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @param {readonly string[]} knownAddresses
 * @param {ReadonlySet<string>} [presentClients]
 * @returns {Promise<import("./grants-core.d.mts").GrantGroup[]>}
 */
export async function listGrants(kv, knownAddresses, presentClients) {
  const helpers = helpersOver(kv);
  const userKeys = await distinctUserKeys(kv);
  const labels = await labelsFor(knownAddresses);
  const clients =
    presentClients === undefined ? await presentClientIds(kv) : presentClients;

  const groups = [];
  for (const userKey of userKeys) {
    const grants = [];
    let cursor;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const result = await helpers.listUserGrants(
        userKey,
        cursor === undefined ? undefined : { cursor },
      );
      for (const item of result?.items ?? []) {
        const clientId = typeof item?.clientId === "string" ? item.clientId : "";
        grants.push({
          id: typeof item?.id === "string" ? item.id : "",
          userKey,
          // Carried rather than only consulted. `clientPresent` below answers
          // "is the record still there"; the prune answers the reverse question
          // — "is there still a grant naming this record" — and it cannot be
          // answered without knowing which record each grant claims.
          clientId,
          // The raw name. It is neutralised at render time, so a caller reading
          // a row still sees what was stored.
          clientName:
            typeof item?.metadata?.clientName === "string"
              ? item.metadata.clientName
              : "",
          created: isoDay(item?.createdAt),
          expires:
            item?.expiresAt === undefined || item?.expiresAt === null
              ? "never"
              : isoDay(item.expiresAt),
          clientPresent: clients.has(clientId),
        });
      }
      if (typeof result?.cursor !== "string" || result.cursor.length === 0) break;
      cursor = result.cursor;
    }

    grants.sort((left, right) =>
      left.created === right.created
        ? left.id.localeCompare(right.id)
        : left.created.localeCompare(right.created),
    );

    const masked = labels.get(userKey);
    if (masked !== undefined) {
      groups.push({ userKey, label: masked, kind: "address", grants });
    } else if (userKey === LEGACY_USER_KEY) {
      groups.push({
        userKey,
        label: LEGACY_LABEL,
        kind: "legacy",
        grants,
      });
    } else {
      groups.push({
        userKey,
        label: `unknown (id ${printable(userKey, UNKNOWN_ID_CHARACTERS)}${ELLIPSIS})`,
        kind: "unknown",
        grants,
      });
    }
  }

  // Named people first, then the legacy pile, then the segments nothing could
  // label. Stable, so two runs read the same and a diff of two captures means
  // something changed in the store.
  const rank = { address: 0, legacy: 1, unknown: 2 };
  groups.sort((left, right) =>
    rank[left.kind] === rank[right.kind]
      ? left.label.localeCompare(right.label)
      : rank[left.kind] - rank[right.kind],
  );
  return groups;
}

/**
 * The client records that no grant names any more. PURE — it reads no store.
 *
 * **Why this exists.** Client registration is unauthenticated by the OAuth spec,
 * it never expires (a TTL would eventually kill a live client — spike S2 — so
 * restoring one is not the answer), and until now nothing in this repository
 * ever deleted a `client:` record. The library's own sweeper has a grant sweep
 * and a token sweep and no client sweep, and calling it would perform the forced
 * logout LIFE-01 exists to remove. So without this the namespace holding the
 * grants and the tokens grew forever, on a write any stranger could make.
 *
 * **The safe set is defined by the grants, not by the records.** A record is
 * only a candidate when NO grant claims it. That is the whole of spike S2's
 * lesson: a client whose record is gone answers `invalid_client` on its next
 * refresh even though the grant itself is perfect, so deleting a claimed record
 * silently signs that person out.
 *
 * A grant whose row carries an empty client id claims nothing and is ignored —
 * it cannot make a record safe and it cannot make one unsafe.
 *
 * @param {ReadonlySet<string>} presentClients
 * @param {readonly import("./grants-core.d.mts").GrantGroup[]} groups
 * @returns {string[]}
 */
export function orphanClientIds(presentClients, groups) {
  const claimed = new Set();
  for (const group of groups) {
    for (const grant of group.grants) {
      if (grant.clientId.length > 0) claimed.add(grant.clientId);
    }
  }
  const orphans = [];
  for (const id of presentClients) {
    if (!claimed.has(id)) orphans.push(id);
  }
  // Stable, so two runs read the same and a diff of two captures means the store
  // changed rather than the iteration order.
  orphans.sort((left, right) => left.localeCompare(right));
  return orphans;
}

/**
 * The orphan records as text, each id cut to the same eight characters an
 * unlabelled user segment is cut to.
 *
 * **The record is never READ, only listed.** A `client_name` is chosen by
 * whoever registered and the registration endpoint accepts a body up to 1 MiB,
 * so fetching these to print a nicer label is the one thing this command must
 * not do — it would pull an attacker's chosen megabyte through the owner's
 * terminal. Eight characters is enough to count them and to diff two runs.
 *
 * @param {readonly string[]} orphans
 * @returns {string}
 */
function renderOrphans(orphans) {
  if (orphans.length === 0) return `${NO_ORPHAN_CLIENTS}\n`;

  const lines = [
    "Client registrations in the REMOTE store that NO grant names.",
    "",
  ];
  for (const id of orphans) {
    lines.push(`  ${printable(id, UNKNOWN_ID_CHARACTERS)}${ELLIPSIS}`);
  }
  lines.push("");
  lines.push(
    `${orphans.length} ${orphans.length === 1 ? "record" : "records"}, ` +
      "none of them holding a live connection.",
  );
  return `${lines.join("\n")}\n`;
}

/**
 * Delete the orphan records, then check the store agrees.
 *
 * `kv.delete` on the key directly, and NEVER the library's `deleteClient`: that
 * helper revokes every grant under the client as well, which is the forced
 * logout this whole phase exists to remove, arriving by another road.
 *
 * `claimed` is passed in and checked HERE rather than trusted from the caller.
 * The caller has already excluded these, so this branch should be unreachable —
 * which is exactly why it is worth having at the one line that does the damage.
 * A future edit that widens the candidate set still cannot delete a record
 * somebody's grant depends on.
 *
 * Serial, one delete at a time, and each one independent: a key that vanished
 * between the listing and the delete must not abort the rest.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @param {readonly string[]} orphans
 * @param {ReadonlySet<string>} claimed
 * @param {(text: string) => void} writeError
 * @returns {Promise<number>}
 */
async function pruneClients(kv, orphans, claimed, writeError) {
  for (const id of orphans) {
    if (claimed.has(id)) {
      writeError(`${KEPT_CLAIMED_CLIENT}\n`);
      continue;
    }
    try {
      await kv.delete(`client:${id}`);
    } catch {
      // Never read the caught value: under the wrangler adapter it carries that
      // command's own output.
      writeError(
        `Client record ${printable(id, UNKNOWN_ID_CHARACTERS)}${ELLIPSIS} ` +
          "could not be deleted. Run the command again.\n",
      );
    }
  }

  // The check, in the same shape the revoke's verification takes: a delete that
  // reported success and left the key behind is what this exists to catch.
  const still = await presentClientIds(kv);
  let left = 0;
  for (const id of orphans) {
    if (claimed.has(id)) continue;
    if (still.has(id)) {
      left += 1;
      writeError(
        `Client record ${printable(id, UNKNOWN_ID_CHARACTERS)}${ELLIPSIS} ` +
          "is still in the store after the delete. Run the command again.\n",
      );
    }
  }
  return left;
}

/**
 * The groups as text. It returns lines and prints nothing.
 *
 * One header per person, then one line per grant carrying the full grant id, the
 * client name, the day it was made, the day it expires (`never` when it does
 * not), and whether its client record still exists.
 *
 * Every field that came from the store goes through `printable` here, which is
 * the one place that happens.
 *
 * @param {readonly import("./grants-core.d.mts").GrantGroup[]} groups
 * @returns {string}
 */
export function renderGrants(groups) {
  if (groups.length === 0) return `${NOTHING_FOUND}\n`;

  const lines = ["Grants in the REMOTE store, by person.", ""];
  let total = 0;

  for (const group of groups) {
    const count = group.grants.length;
    lines.push(`${group.label}  (${count} ${count === 1 ? "grant" : "grants"})`);
    for (const grant of group.grants) {
      total += 1;
      lines.push(
        `  ${printable(grant.id, 64)}` +
          `  client "${printable(grant.clientName, CLIENT_NAME_MAX)}"` +
          `  created ${printable(grant.created, 10)}` +
          `  expires ${printable(grant.expires, 10)}` +
          `  ${grant.clientPresent ? "client present" : "client gone"}`,
      );
    }
    lines.push("");
  }

  lines.push(
    `${total} ${total === 1 ? "grant" : "grants"} under ` +
      `${groups.length} ${groups.length === 1 ? "group" : "groups"}, ` +
      "read from the REMOTE store.",
  );
  return `${lines.join("\n")}\n`;
}

/**
 * Read the arguments. Nothing is touched until this has accepted them.
 *
 * It returns either `{ error }` or a plain description of what was asked for.
 * That split is what lets a usage mistake cost no store call at all, which in
 * the owner's terminal means no wrangler call — and a `revoke` that reached the
 * store with no target is the one mistake this tool must never make quietly.
 *
 * @param {readonly string[]} argv
 * @returns {Record<string, unknown>}
 */
function readArguments(argv) {
  const rest = [...argv];
  let command = "list";
  if (rest.length > 0 && !String(rest[0]).startsWith("-")) {
    command = String(rest.shift());
  }
  if (command !== "list" && command !== "revoke" && command !== "prune-clients") {
    return { error: UNKNOWN_COMMAND };
  }

  const ids = [];
  const addresses = [];
  let legacyOwner = false;
  let yes = false;

  while (rest.length > 0) {
    const token = String(rest.shift());
    if (token === "--yes") {
      yes = true;
      continue;
    }
    if (token === "--legacy-owner") {
      legacyOwner = true;
      continue;
    }
    if (token === "--address") {
      const value = rest.shift();
      if (typeof value !== "string" || value.length === 0 || value.startsWith("-")) {
        return { error: ADDRESS_NEEDS_VALUE };
      }
      addresses.push(value);
      continue;
    }
    if (token.startsWith("-")) return { error: UNKNOWN_FLAG };
    ids.push(token);
  }

  if (command === "list") {
    if (ids.length > 0) return { error: LIST_TAKES_NO_IDS };
    if (yes) return { error: LIST_TAKES_NO_YES };
    if (legacyOwner) return { error: UNKNOWN_FLAG };
  }

  if (command === "prune-clients") {
    // It takes NO target, and that is the point rather than an omission: the
    // safe set is computed from the grants, so letting the owner name a record
    // would be letting them name the one thing the computation exists to refuse.
    if (ids.length > 0 || addresses.length > 0 || legacyOwner) {
      return { error: PRUNE_TAKES_NO_TARGET };
    }
  }

  if (
    command === "revoke" &&
    ids.length === 0 &&
    addresses.length === 0 &&
    !legacyOwner
  ) {
    return { error: REVOKE_NEEDS_TARGET };
  }

  return { command, ids, addresses, legacyOwner, yes };
}

/**
 * Find one grant by an exact id, or by a prefix of at least eight characters.
 *
 * An exact id wins. Otherwise the prefix must match exactly one grant: an
 * ambiguous prefix refuses the whole request rather than taking the first hit,
 * because the first hit would be somebody else's connection.
 *
 * @param {readonly import("./grants-core.d.mts").GrantRow[]} all
 * @param {string} wanted
 * @returns {Record<string, unknown>}
 */
function findGrant(all, wanted) {
  const exact = all.filter((grant) => grant.id === wanted);
  if (exact.length === 1) return { grant: exact[0] };
  if (exact.length > 1) return { error: AMBIGUOUS_GRANT };
  if (wanted.length < UNKNOWN_ID_CHARACTERS) return { error: PREFIX_TOO_SHORT };
  const prefixed = all.filter((grant) => grant.id.startsWith(wanted));
  if (prefixed.length === 0) return { error: NO_SUCH_GRANT };
  if (prefixed.length > 1) return { error: AMBIGUOUS_GRANT };
  return { grant: prefixed[0] };
}

/**
 * Work out which grants a revoke is aimed at, without deleting anything.
 *
 * The result is a list of groups holding only the targeted grants, so the same
 * renderer prints the targets that printed the listing. Whatever is shown is
 * exactly what would go.
 *
 * @param {readonly import("./grants-core.d.mts").GrantGroup[]} groups
 * @param {Record<string, unknown>} asked
 * @returns {Promise<Record<string, unknown>>}
 */
async function targetsFor(groups, asked) {
  const all = groups.flatMap((group) => group.grants);
  const chosen = new Set();

  for (const wanted of asked.ids) {
    const found = findGrant(all, wanted);
    if (found.error !== undefined) return { error: found.error };
    chosen.add(`${found.grant.userKey}:${found.grant.id}`);
  }

  for (const address of asked.addresses) {
    const userKey = await userIdOf(address);
    if (userKey === null) return { error: ADDRESS_REFUSED };
    for (const grant of all) {
      if (grant.userKey === userKey) chosen.add(`${userKey}:${grant.id}`);
    }
  }

  if (asked.legacyOwner) {
    for (const grant of all) {
      if (grant.userKey === LEGACY_USER_KEY) {
        chosen.add(`${LEGACY_USER_KEY}:${grant.id}`);
      }
    }
  }

  const targets = [];
  for (const group of groups) {
    const grants = group.grants.filter((grant) =>
      chosen.has(`${grant.userKey}:${grant.id}`),
    );
    if (grants.length > 0) targets.push({ ...group, grants });
  }
  return { targets };
}

/**
 * Delete each target, then check the store agrees.
 *
 * `revokeGrant` is the library's own, which deletes every token under the grant
 * BEFORE the grant itself. That order is the whole point: the door checks an
 * access token against its own token record, which carries its own copy of the
 * grant and never reads the grant key, so deleting only the grant leaves the
 * token working for up to an hour.
 *
 * Serial, one grant at a time. Then both prefixes are re-listed, because a
 * delete that reported success and left a key behind is the failure this step
 * exists to catch.
 *
 * @param {import("./grants-core.d.mts").GrantStore} kv
 * @param {readonly import("./grants-core.d.mts").GrantGroup[]} targets
 * @param {(text: string) => void} writeError
 * @returns {Promise<number>}
 */
async function revokeTargets(kv, targets, writeError) {
  const helpers = helpersOver(kv);
  for (const group of targets) {
    for (const grant of group.grants) {
      await helpers.revokeGrant(grant.id, group.userKey);
    }
  }

  let left = 0;
  for (const group of targets) {
    for (const grant of group.grants) {
      const remaining = [
        ...(await allKeysUnder(kv, `grant:${group.userKey}:${grant.id}`)),
        ...(await allKeysUnder(kv, `token:${group.userKey}:${grant.id}:`)),
      ];
      if (remaining.length > 0) {
        left += 1;
        writeError(
          `Grant ${printable(grant.id, 64)} still has records in the store ` +
            "after the revoke. Run the list again.\n",
        );
      }
    }
  }
  return left;
}

/**
 * Parse, then act. Returns the exit code the caller should use.
 *
 * `deps.knownAddresses` is a FUNCTION rather than a list, so nothing is read
 * for a usage error. In the owner's terminal that function is what reads the
 * config seed and the stored allow list, and both cost a wrangler call.
 *
 * Any `--address` values on the command line are added to the labels here, from
 * the parse that has already happened, so the whole program reads the arguments
 * exactly once.
 *
 * @param {readonly string[]} argv
 * @param {import("./grants-core.d.mts").GrantDeps} deps
 * @returns {Promise<number>}
 */
export async function runGrants(argv, deps) {
  const write = deps.write;
  const writeError = deps.writeError ?? deps.write;

  const asked = readArguments(argv);
  if (asked.error !== undefined) {
    writeError(`${asked.error}\n\n${USAGE}\n`);
    return EXIT_USAGE;
  }

  const addresses = [
    ...new Set([...(await deps.knownAddresses()), ...asked.addresses]),
  ];
  // The client prefix is listed HERE, once, and handed down. Both the listing's
  // `client present` column and the orphan count need it, and a second listing
  // would double the slowest part of the owner's wait for nothing.
  const clients = await presentClientIds(deps.kv);
  const groups = await listGrants(deps.kv, addresses, clients);
  const orphans = orphanClientIds(clients, groups);

  /** Say so when a record could not be read, rather than showing a short list. */
  const noteIncompleteReads = () => {
    const failed =
      typeof deps.kv.readFailures === "function" ? deps.kv.readFailures() : 0;
    if (failed > 0) writeError(`${READS_INCOMPLETE}\n`);
  };

  if (asked.command === "list") {
    write(renderGrants(groups));
    // The growth is stated rather than left silent. Nothing in this repository
    // deleted a client record before this command existed, so an owner who never
    // sees the count has no way to know the namespace is filling up.
    if (orphans.length > 0) {
      write(
        `${orphans.length} client ` +
          `${orphans.length === 1 ? "registration" : "registrations"} ` +
          "no grant names. Run prune-clients to see them.\n",
      );
    }
    noteIncompleteReads();
    return EXIT_OK;
  }

  if (asked.command === "prune-clients") {
    write(renderOrphans(orphans));
    noteIncompleteReads();
    if (orphans.length === 0) return EXIT_OK;
    if (!asked.yes) {
      write(`${NOTHING_PRUNED}\n`);
      return EXIT_OK;
    }

    // A SECOND read of both prefixes, on the --yes path only. Somebody can
    // register a client and complete a sign-in in the seconds between the owner
    // reading the list and re-running with --yes, and deleting that record would
    // sign them straight back out. Only ids orphaned in BOTH views are deleted;
    // the fresh view's claimed set is then checked again at the delete itself.
    const freshClients = await presentClientIds(deps.kv);
    const freshGroups = await listGrants(deps.kv, addresses, freshClients);
    const stillOrphan = new Set(orphanClientIds(freshClients, freshGroups));
    const claimed = new Set();
    for (const group of freshGroups) {
      for (const grant of group.grants) {
        if (grant.clientId.length > 0) claimed.add(grant.clientId);
      }
    }
    const going = orphans.filter((id) => stillOrphan.has(id));

    const left = await pruneClients(deps.kv, going, claimed, writeError);
    if (left > 0) return EXIT_FAILED;
    write(
      `Deleted ${going.length} client ` +
        `${going.length === 1 ? "record" : "records"}. No grant named any of ` +
        "them, so no connection was cut. Allow about a minute for the deletes " +
        "to be seen everywhere.\n",
    );
    return EXIT_OK;
  }

  const aimed = await targetsFor(groups, asked);
  if (aimed.error !== undefined) {
    writeError(`${aimed.error}\n`);
    return EXIT_USAGE;
  }
  if (aimed.targets.length === 0) {
    write(`${NO_TARGETS}\n`);
    noteIncompleteReads();
    return EXIT_OK;
  }

  // ALWAYS the targets first, in the same format as the listing. Whatever is
  // printed here is exactly what would go.
  write(renderGrants(aimed.targets));
  noteIncompleteReads();

  if (!asked.yes) {
    write(`${NOTHING_REVOKED}\n`);
    return EXIT_OK;
  }

  const left = await revokeTargets(deps.kv, aimed.targets, writeError);
  const count = aimed.targets.reduce(
    (running, group) => running + group.grants.length,
    0,
  );
  if (left > 0) return EXIT_FAILED;
  write(
    `Revoked ${count} ${count === 1 ? "grant" : "grants"} and every token ` +
      "under them. Allow about a minute for the deletes to be seen everywhere.\n",
  );
  return EXIT_OK;
}
