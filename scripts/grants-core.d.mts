// Types for scripts/grants-core.mjs.
//
// The core is plain ESM rather than TypeScript for one reason: it has to run in
// TWO runtimes. `test/grants-script.test.ts` imports it inside the Workers pool,
// where the real provider and the real store live, and `scripts/grants.mjs`
// imports it under Node with a resolve hook in front of it. A `.ts` file would
// need a build step for the second of those, and a build step between the owner
// and a revoke command is a step that can be stale.
//
// This declaration exists so the test can import the core under `strict` without
// the project enabling `allowJs`, which would pull every script in scripts/ into
// the typecheck program. It follows `scripts/forbidden-tokens.d.mts`, which
// exists for the same reason.
//
// The shape here is not load-bearing on its own: the test asserts on runtime
// values, so a drift between this file and the implementation surfaces as a
// failing test rather than as a silent lie.

/**
 * The slice of a KV namespace the library's helpers and this core actually use.
 *
 * Three methods, not the whole binding. The wrangler-backed adapter implements
 * exactly these, so a call the adapter cannot serve is a type error rather than
 * a surprise in the owner's terminal.
 */
export interface GrantStore {
  list(options?: {
    prefix?: string;
    cursor?: string;
    limit?: number;
  }): Promise<{
    keys: Array<{ name: string; expiration?: number }>;
    list_complete: boolean;
    cursor?: string;
  }>;
  get(name: string, options?: { type?: string }): Promise<unknown>;
  delete(name: string): Promise<void>;
  /**
   * How many reads the adapter could not complete, when it counts them.
   *
   * Optional because a real KV binding has no such method. The wrangler adapter
   * does: a key can vanish between the listing and the read (legacy grants still
   * carry a TTL), and a listing that silently dropped a row would be read as
   * "that grant is already gone".
   */
  readFailures?(): number;
}

/** One grant, reduced to the fields that are safe to print. */
export interface GrantRow {
  /** The full grant id. Needed to revoke, and not a credential on its own. */
  readonly id: string;
  /** The store's user segment this grant sits under. */
  readonly userKey: string;
  /**
   * Which `client:` record this grant claims. Empty when the summary had none.
   *
   * Carried, not just consulted: the prune's safe set is "every record no grant
   * names", and that question cannot be answered from `clientPresent`, which
   * answers the reverse one.
   */
  readonly clientId: string;
  /** `metadata.clientName`, neutralised and cut at render time. */
  readonly clientName: string;
  /** ISO day the grant was made, or the unknown marker. */
  readonly created: string;
  /** ISO day it expires, or `never`. */
  readonly expires: string;
  /** Whether the `client:` record behind it still exists. */
  readonly clientPresent: boolean;
}

/** One person (or one unlabelled user segment), with their grants. */
export interface GrantGroup {
  /** The store's user segment. */
  readonly userKey: string;
  /** The masked address, the unknown marker, or the legacy marker. */
  readonly label: string;
  /** `address` when a known address hashed to this segment. */
  readonly kind: "address" | "unknown" | "legacy";
  readonly grants: readonly GrantRow[];
}

/** What `runGrants` needs from the world around it. */
export interface GrantDeps {
  readonly kv: GrantStore;
  /** Called only once the arguments have been accepted. */
  knownAddresses(): Promise<readonly string[]>;
  /** Where normal output goes. */
  write(text: string): void;
  /** Where refusals go. Defaults to `write`. */
  writeError?(text: string): void;
}

/** The first sentence printed when `--yes` was not given. Plan 12-05 greps it. */
export declare const NOTHING_REVOKED: string;

/** The same sentence for `prune-clients`, so neither can be misread as the other. */
export declare const NOTHING_PRUNED: string;

/**
 * Every usage form, in one place.
 *
 * Exported so `scripts/grants.mjs` can answer `--help` with the same text a
 * usage refusal prints, rather than keeping a second copy that goes stale the
 * first time a flag is added.
 */
export declare const USAGE: string;

/**
 * Wrap a wrangler runner as a store.
 *
 * `run(args)` must return the command's stdout as a string and throw on
 * failure. The binding name and the remote flag are fixed here, never taken
 * from a caller.
 */
export declare function createWranglerKv(
  run: (args: readonly string[]) => string,
  binding: string,
): GrantStore;

/**
 * Every grant in the store, grouped by user segment and labelled.
 *
 * `presentClients` is optional so one run of the program can pay for the client
 * listing once and hand the set down. Omitting it lists the prefix here.
 */
export declare function listGrants(
  kv: GrantStore,
  knownAddresses: readonly string[],
  presentClients?: ReadonlySet<string>,
): Promise<GrantGroup[]>;

/** Every client id that still has a record in the store. */
export declare function presentClientIds(
  kv: GrantStore,
): Promise<Set<string>>;

/**
 * The client records no grant names any more. Pure — it reads no store.
 *
 * A record a grant still claims is never in the result: deleting one makes that
 * grant's next refresh answer `invalid_client` even though the grant is fine,
 * which signs the person out (spike S2).
 */
export declare function orphanClientIds(
  presentClients: ReadonlySet<string>,
  groups: readonly GrantGroup[],
): string[];

/** The groups as text. Returns lines; prints nothing. */
export declare function renderGrants(groups: readonly GrantGroup[]): string;

/** Parse, then act. Returns the process exit code. */
export declare function runGrants(
  argv: readonly string[],
  deps: GrantDeps,
): Promise<number>;
