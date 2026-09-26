// Types for scripts/forbidden-tokens.mjs.
//
// The scanner is plain Node ESM on purpose — .husky/pre-commit runs it before
// anything guarantees node_modules exists, so it cannot be TypeScript and cannot
// be compiled. This declaration exists so test/forbidden-tokens.test.ts can
// import it under `strict` without the project enabling `allowJs`, which would
// pull every script in scripts/ into the typecheck program.
//
// The shape here is not load-bearing on its own: the test asserts on runtime
// values, so a drift between this file and the implementation surfaces as a
// failing test rather than as a silent lie.

/** One rule in the ban list. */
export interface ForbiddenRule {
  /** Stable identifier, reported as a violation's `pattern`. */
  readonly id: string;
  /** The pattern itself. Never restated outside the scanner. */
  readonly pattern: RegExp;
  /** Why the rule exists. Printed by the hook when it rejects a commit. */
  readonly why: string;
  /** Optional repo-relative directory prefix restricting the rule's reach. */
  readonly scope?: string;
}

/** One violation. */
export interface Violation {
  /** Repo-relative, forward-slashed. */
  readonly file: string;
  /** 1-based; 0 when the violation is about the file's absence. */
  readonly line: number;
  readonly column: number;
  /** The `id` of the rule that fired. */
  readonly pattern: string;
  /** Sort key, so results are stable across runs. */
  readonly patternIndex: number;
  readonly why: string;
}

export interface ScanOptions {
  /** Paths to skip. Defaults to `EXCLUDED`. */
  readonly excluded?: ReadonlySet<string>;
}

export declare const REPO_ROOT: string;
export declare const FORBIDDEN: readonly ForbiddenRule[];
export declare const SOCKET_IMPORT: RegExp;
export declare const SOCKET_OWNER: string;
export declare const EXCLUDED: ReadonlySet<string>;

export declare function scan(root?: string, options?: ScanOptions): Violation[];
export declare function checkSocketOwnership(
  importers: ReadonlyArray<{ file: string; line: number; column: number }>,
): Violation[];
export declare function checkCommitHook(hookPath?: string): Violation[];
export declare function scanWranglerConfig(
  configPath?: string,
  hostnameSourcePath?: string,
): Violation[];
export declare function formatViolation(violation: Violation): string;

/**
 * Exported so a scope test can drive the real prefix mechanism. A test that
 * asserted `rule.scope` equalled a string would keep passing if the scanner
 * stopped honouring scope at all.
 */
export declare function matchRule(
  rule: ForbiddenRule,
  ruleIndex: number,
  relativePath: string,
  contents: string,
): Violation[];

/** One file matching a count constraint, and where it matched. */
export interface OwnershipMatch {
  readonly file: string;
  readonly line: number;
  readonly column: number;
}

export declare const DAV_HOST_LITERAL: RegExp;
export declare const DAV_HOST_OWNER: string;
export declare const DAV_HOST_SCOPE: string;
export declare const DAV_FETCH_CALL: RegExp;
export declare const DAV_FETCH_OWNER: string;
export declare const DAV_FETCH_SCOPE: string;
export declare const APPEND_COMMAND: RegExp;
export declare const APPEND_OWNER: string;
export declare const APPEND_SCOPE: string;
export declare const SUBSCRIPTION_FEED_FETCH_CALL: RegExp;
export declare const SUBSCRIPTION_FEED_FETCH_OWNER: string;
export declare const SUBSCRIPTION_FEED_FETCH_SCOPE: string;
export declare const PROPS_READER: RegExp;
export declare const PROPS_READER_OWNER: string;
export declare const PROPS_READER_SCOPE: string;
export declare const PASSWORD_READER_IMPORT: RegExp;
export declare const PASSWORD_READER_OWNERS: readonly string[];
export declare const PASSWORD_READER_SCOPE: string;
export declare const MAIL_SECRET_READ: RegExp;
export declare const MAIL_SECRET_READ_OWNER: string;
export declare const MAIL_SECRET_READ_SCOPE: string;
export declare const ADDRESS_HASH: RegExp;
export declare const ADDRESS_HASH_OWNER: string;
export declare const ADDRESS_HASH_SCOPE: string;
export declare const PRINCIPAL_CONSTRUCTOR: RegExp;
export declare const PRINCIPAL_CONSTRUCTOR_OWNERS: readonly string[];
export declare const PRINCIPAL_CONSTRUCTOR_SCOPE: string;
export declare const CONFIRM_LINE_COMPOSER: RegExp;
export declare const CONFIRM_LINE_OWNER: string;
export declare const CONFIRM_LINE_SCOPE: string;
export declare const MUTATING_OPEN_COMMAND: RegExp;
export declare const MUTATING_OPEN_OWNER: string;
export declare const MUTATING_OPEN_SCOPE: string;
export declare const MUTATING_SESSION_IMPORT: RegExp;
export declare const MUTATING_SESSION_OWNER: string;
export declare const MUTATING_SESSION_SCOPE: string;
export declare const OWNERSHIP_VIOLATION_IDS: readonly string[];

/** One declared DAV write module: why it is declared, and a disposition for
 *  every name it exports — the exact string `"guarded"` when the name must
 *  appear in the `dav-concurrent-request` alternation, or a prose reason when it
 *  must not. */
export interface DavWriteModule {
  readonly why: string;
  readonly exports: Readonly<Record<string, string>>;
}

export declare const DAV_WRITE_MODULES: Readonly<Record<string, DavWriteModule>>;

export declare function checkDavHostOwnership(
  resolvers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkDavFetchOwnership(
  callers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkAppendOwnership(
  appenders: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkSubscriptionFeedFetchOwnership(
  callers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkPropsReaderOwnership(
  readers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkPasswordReaderOwnership(
  importers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkMailSecretReaderOwnership(
  readers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkAddressHashOwnership(
  hashers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkPrincipalConstructorOwnership(
  callers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkConfirmLineOwnership(
  composers: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkMutatingOpenOwnership(
  sites: ReadonlyArray<OwnershipMatch>,
): Violation[];
export declare function checkMutatingSessionImportOwnership(
  importers: ReadonlyArray<OwnershipMatch>,
): Violation[];

/** Every name `contents` exports as a `function` declaration, in source order. */
export declare function exportedFunctionNames(contents: string): string[];

/**
 * The names in the trailing alternation group of the shipped
 * `dav-concurrent-request` rule.
 *
 * The optional parameter exists so a test can prove the extraction THROWS on a
 * pattern with no trailing group. `checkDavWriteCoverage` calls this with no
 * argument, so its third arm always measures the rule that actually ships.
 */
export declare function davAlternationNames(rule?: ForbiddenRule): string[];

/**
 * The three-armed write-module coverage check.
 *
 * `collected` maps a repo-relative module path to the exported names `scan()`
 * read out of that file during the walk. The optional `manifest` exists so a
 * test can drive the third arm, which no value of `collected` can produce
 * against the shipped manifest; the alternation is deliberately NOT a
 * parameter.
 */
export declare function checkDavWriteCoverage(
  collected: Readonly<Record<string, readonly string[]>>,
  manifest?: Readonly<Record<string, DavWriteModule>>,
): Violation[];
