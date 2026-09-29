// Types for scripts/tool-table-core.mjs.
//
// The core is plain ESM so it can run both in the Workers pool (the test) and
// under Node (the CLI). This file lets the test import it under `strict`
// without the project enabling `allowJs`, as scripts/grants-core.d.mts does.
// The test asserts on runtime values, so a drift between this file and the
// implementation shows up as a failing test.

/** One README row: a tool and its line. */
export interface ToolRow {
  readonly name: string;
  readonly line: string;
}

/** One README group: its heading, an optional intro paragraph, and its rows. */
export interface ToolGroup {
  readonly heading: string;
  readonly intro: string | null;
  readonly rows: readonly ToolRow[];
}

export type FindingKind =
  | "markers-missing"
  | "block-differs"
  | "missing-row"
  | "unregistered-row"
  | "duplicate-row";

/** One thing wrong with README's tool block. */
export interface Finding {
  readonly kind: FindingKind;
  readonly detail: string;
}

/** The comment that opens the generated block in README. */
export declare const START_MARKER: string;

/** The comment that closes it. */
export declare const END_MARKER: string;

/** Every kind of finding `checkReadme` can report. */
export declare const FINDING_KINDS: readonly FindingKind[];

/** README's tool groups, in README's order. */
export declare const TOOL_GROUPS: readonly ToolGroup[];

/** Every tool name registered in the given sources, sorted. Throws on a name it cannot resolve. */
export declare function registeredNames(
  sources: Readonly<Record<string, string>>,
): string[];

/** Every row's tool name, in table order. Duplicates are kept. */
export declare function rowNames(groups: readonly ToolGroup[]): string[];

/** README's whole tool block: the count line, then each group's table. */
export declare function renderBlock(groups: readonly ToolGroup[]): string;

/** What is wrong with README's tool block. Empty means nothing is. */
export declare function checkReadme(
  readmeText: string,
  groups: readonly ToolGroup[],
  names: readonly string[],
): Finding[];

/** README with the text between the markers replaced by the rendered block. Throws without markers. */
export declare function withBlock(
  readmeText: string,
  groups: readonly ToolGroup[],
): string;
