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
   * Write one value. Optional because only the autonomy setup writes, and the
   * listing and revoke doubles never need it.
   *
   * The wrangler adapter's version carries only client records, which hold a
   * hash and no secret, and refuses any write that would expire.
   */
  put?(
    name: string,
    value: string,
    options?: { expiration?: number; expirationTtl?: number },
  ): Promise<void>;
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
  /**
   * Whether this is an autonomy grant: its client id is `AUTONOMY_CLIENT_ID`.
   *
   * Set from the client id ONLY, never from the client name, which any
   * registrant chooses. `listGrants` always sets it. It is optional so a row
   * built by hand, as a test builds one, reads as not autonomy without it.
   */
  readonly autonomy?: boolean;
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

/** Somewhere to set a Worker secret. The value never reaches a command line. */
export interface SecretStore {
  put(name: string, value: string): Promise<void>;
}

/** What `autonomy-setup` needs beyond the store. Absent: the command refuses. */
export interface AutonomySetupDeps {
  /** The deployed hostname. Called only by `autonomy-setup`. */
  hostname(): string;
  /** Cryptographically random bytes. */
  randomBytes(length: number): Uint8Array;
  readonly secrets: SecretStore;
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
  /** Only `autonomy-setup` reads this. */
  readonly autonomy?: AutonomySetupDeps;
  /** The clock `list` reads the rules job's next wake against. Defaults to `Date.now`. */
  now?(): number;
}

/** The library helpers `installAutonomyClientRecord` calls. */
export interface ClientHelpers {
  createClient(info: Record<string, unknown>): Promise<{ clientId: string }>;
  updateClient(
    clientId: string,
    updates: { clientSecret: string },
  ): Promise<unknown | null>;
}

export interface InstallAutonomyClientOptions {
  /** The library's helpers over the SAME store as `kv`. */
  readonly helpers: ClientHelpers;
  readonly kv: GrantStore;
  /** Exactly one (D-29). */
  readonly redirectUris: readonly string[];
  /** The value the library hashes onto the record. Never stored in the clear. */
  readonly clientSecret: string;
  /** Replace an existing autonomy client. Ends everyone's key. */
  readonly replace?: boolean;
}

/**
 * Create the autonomy client through the library and re-key it under the fixed
 * id, leaving no random-id copy. The one place this project writes a client
 * record; the test pool's autonomy fixture calls it too.
 */
export declare function installAutonomyClientRecord(
  options: InstallAutonomyClientOptions,
): Promise<{ kind: "installed"; replaced: boolean } | { kind: "exists" }>;

/**
 * Wrap a runner that feeds standard input as a secret store. The secret's name
 * is the only thing on the command line; the value goes to standard input.
 */
export declare function createWranglerSecrets(
  runWithInput: (args: readonly string[], input: string) => string,
): SecretStore;

/** The two Worker secrets `autonomy-setup` sets, by name. */
export declare const AUTONOMY_SECRET_NAMES: readonly string[];

/** What `--replace` costs, word for word. */
export declare const REPLACE_ENDS_KEYS: string;

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
 * failure.
 *
 * The REMOTE FLAG is fixed inside the adapter and cannot be reached by a caller:
 * there is no value anybody can pass that produces a command without it, which
 * is what makes the local-simulator trap unspeakable rather than merely
 * discouraged. Without it wrangler reads the simulator on this machine, the
 * listing comes back empty, and "no connections" is indistinguishable from a
 * clean account.
 *
 * The BINDING NAME is this parameter, chosen at each call site — `"OAUTH_KV"`
 * and `"ALLOW_LIST_KV"`. It is fixed at those sites rather than fixed here, and
 * the distinction is worth keeping straight: this copy used to claim both were
 * beyond a caller's reach, which the `.mjs` docstring never did.
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
 *
 * The autonomy client is never in the result either, claimed or not: right
 * after setup no grant names it, and deleting it would end every key.
 */
export declare function orphanClientIds(
  presentClients: ReadonlySet<string>,
  groups: readonly GrantGroup[],
): string[];

/** The groups as text. Returns lines; prints nothing. */
export declare function renderGrants(
  groups: readonly GrantGroup[],
  statuses?: ReadonlyMap<string, string>,
): string;
/** What the rules job line says for a person with no status record. */
export declare const NO_RUN_RECORDED: string;
/** What it says for a record that is there but cannot be read. */
export declare const STATUS_UNREADABLE: string;
/** One status record as the words printed after "rules job". Pure. */
export declare function autonomyStatusText(value: unknown, now: number): string;
/** The status line's words for each person holding an autonomy grant. */
export declare function readAutonomyStatuses(
  kv: GrantStore,
  groups: readonly GrantGroup[],
  now: number,
): Promise<Map<string, string>>;

/**
 * The whole closing report of a `prune-clients --yes` run.
 *
 * `gained` is how many candidates a grant claimed between the command's two
 * reads — the case the second read exists for, and the one that must never be
 * reported as a bare `Deleted 0 client records.` `vanished` is how many were
 * already gone. Both sentences are omitted when their count is zero.
 */
export declare function prunedSummary(
  deleted: number,
  gained: number,
  vanished: number,
): string;

/** Parse, then act. Returns the process exit code. */
export declare function runGrants(
  argv: readonly string[],
  deps: GrantDeps,
): Promise<number>;
