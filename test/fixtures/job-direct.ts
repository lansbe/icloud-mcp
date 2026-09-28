// The rules job driven directly (Phase 28, plan 28-03).
//
// `runAutonomyJob` with deps that record everything: each tool call, each
// storage write, each wake asked for, each disarm and each status write, in one
// ordered event list. The tool answers come from the REAL tool-side builders
// (the change answer, the sign-in answer, the flag answer, the compose answer,
// the tool error answer), so the job reads them exactly as it reads a real
// answer through Phase 27's `call`.
//
// The shapes are copied from test/autonomy-draft.test.ts (28-02), which keeps
// its own copies. Nothing here opens a connection.

import { AUTONOMY_KEY } from "../../src/agent/autonomy";
import { JOB_MARKER_KEY, JOB_NEXT_AT_KEY, type JobDeps, RULES_KEY, runAutonomyJob } from "../../src/agent/job";
import type { Rule } from "../../src/agent/rules";
import type { CallAnswer } from "../../src/agent/tool-call";
import type { NewMailRow } from "../../src/mail/service";
import { signedInAsResult } from "../../src/mcp/tools/account";
import { type ChangesAnswer, changesResult } from "../../src/mcp/tools/changes";
import { composeToolResult, flagStateToolResult, mailErrorResult } from "../../src/mcp/tools/mail";
import type { Principal } from "../../src/principal";

export const MIN = 60_000;
export const HOUR = 60 * MIN;
export const DAY = 24 * HOUR;

/** The account's own address in the direct cases. */
export const SELF = "me@icloud.com";

/** The time of the first direct run: 10:00 UTC on a fixed day. */
export const T0 = Date.UTC(2026, 8, 28, 10, 0, 0);

/** A user id for the direct cases. */
export const NAME = "b".repeat(64);

/** The words every draft rule here carries. */
export const RULE_TEXT = "Thank you for your note. I will reply properly soon.";

/** A stored rule matching every row whose subject holds "role". */
export function rule(id: string, then: Rule["then"], when: Rule["when"] = { subjectContains: ["role"] }): Rule {
  return { v: 1, id, createdAt: 0, when, then };
}

export const DRAFT: Rule["then"] = { draft: { text: RULE_TEXT } };
export const FLAG: Rule["then"] = { flag: true };

/** A new-mail row as the change check builds it. */
export function newRow(i: number, over: Partial<NewMailRow> = {}): NewMailRow {
  return {
    id: `INBOX-msg-${i}`,
    uid: 5000 + i,
    unread: true,
    receivedAt: "13-Aug-2026 09:14:02 -0700",
    fromName: "A Sender",
    fromAddress: `sender${i}@example.com`,
    subject: "About the role",
    mailingList: false,
    ...over,
  };
}

/** A key-value store in memory, in the shape the job uses. */
export function memoryStorage(seed: Record<string, unknown> = {}) {
  const map = new Map<string, unknown>(Object.entries(seed));
  return {
    map,
    get<T = unknown>(key: string): T | undefined {
      return map.get(key) as T | undefined;
    },
    put<T>(key: string, value: T): void {
      map.set(key, value);
    },
    delete(key: string): boolean {
      return map.delete(key);
    },
    *list<T = unknown>(options: { prefix?: string } = {}): Iterable<[string, T]> {
      for (const [key, value] of [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
        if (options.prefix === undefined || key.startsWith(options.prefix)) yield [key, value as T];
      }
    },
  };
}
export type Memory = ReturnType<typeof memoryStorage>;

/** Storage for an armed person with these rules and a fresh stored marker. */
export function armedStorage(rules: Rule[], markerAt = T0 - HOUR): Memory {
  return memoryStorage({
    [AUTONOMY_KEY]: { v: 1, grantId: "grant-1", generation: 1 },
    [RULES_KEY]: rules,
    [JOB_MARKER_KEY]: { marker: "marker-0", at: markerAt },
  });
}

/** The change answer for the inbox alone, as the real tool builds it. */
export function changesAnswerFor(
  rows: NewMailRow[],
  sentMarker: boolean,
  marker: string,
  count?: number,
): CallAnswer {
  const answer = {
    mail: [
      {
        folder: "INBOX",
        state: sentMarker ? "changes" : "started",
        newMessages: sentMarker ? (count ?? rows.length) : null,
        otherActivity: null,
        mechanism: "status-uidnext",
        rows: sentMarker ? rows : [],
      },
    ],
    calendar: { calendars: [], notCovered: [], gone: 0, unchecked: null },
    carried: [],
    since: null,
    marker,
  } as unknown as ChangesAnswer;
  return { kind: "ok", result: changesResult(answer) };
}

/** A successful compose answer, as the real tool builds it. */
export function placedAnswer(args: Record<string, unknown>): CallAnswer {
  return {
    kind: "ok",
    result: composeToolResult({
      appended: true,
      id: "Drafts-id",
      role: "drafts",
      roleSource: "name",
      sizeBytes: 900,
      refusal: null,
      limitBytes: null,
      parentMessageId: "<p@example.com>",
      referencesCount: 1,
      attachedCount: 0,
      attachedBytes: 0,
      consumedStagedIds: [],
      subject: "Re: About the role",
      to: (args.to as string[]) ?? [],
      cc: [],
    } as never),
  };
}

/** A confirmed flag answer, as the real tool builds it. */
export function flaggedAnswer(args: Record<string, unknown>): CallAnswer {
  return {
    kind: "ok",
    result: flagStateToolResult(args.id as string, true, { applied: true, flagged: true, source: "store-echo" }),
  };
}

/** The sign-in check's answer, as the real tool builds it. */
export function whoamiAnswer(): CallAnswer {
  return { kind: "ok", result: signedInAsResult({ appleId: SELF } as unknown as Principal) };
}

/** A tool error answer for `err`, as the real tool builds it, handed back intact. */
export function toolError(err: unknown): CallAnswer {
  return { kind: "ok", result: mailErrorResult(err) };
}

/** One recorded call. */
export interface Recorded {
  readonly tool: string;
  readonly args: Record<string, unknown>;
}

/** Everything one direct run did. */
export interface DirectRun {
  readonly outcome: string;
  readonly calls: Recorded[];
  /** Every wake asked for, in order. */
  readonly wakes: number[];
  /** `call <tool>`, `put <key>`, `delete <key>`, `wake`, `disarm`, `session`, `status`, in order. */
  readonly events: string[];
  readonly disarms: number;
}

/** How one direct run behaves. Every field is optional. */
export interface DirectOptions {
  readonly now?: number;
  /** The rows a change answer lists when a marker was sent. */
  readonly rows?: NewMailRow[];
  /** The count the change answer gives; the row count when absent. */
  readonly count?: number;
  /** Answer a call instead of the default; undefined falls through to it. */
  readonly answer?: (tool: string, args: Record<string, unknown>) => CallAnswer | undefined;
  /** The session's answer instead of running `use`. */
  readonly session?: "not_allowed" | "off" | "revoked" | "failed";
  readonly isRetry?: boolean;
  /** Keep the stored next wake, instead of forgetting it so the run is due. */
  readonly keepNextAt?: boolean;
  /** Extra deps, laid over the recording ones. */
  readonly over?: Partial<JobDeps>;
}

let runCounter = 0;

/** The fresh marker the latest direct run's change answer carried. */
export function lastFreshMarker(): string {
  return `fresh-${runCounter}`;
}

/**
 * Run the job once over `storage`, with recording deps. The stored next wake
 * is forgotten first, so the run is due, unless `keepNextAt` is set.
 */
export async function directRun(storage: Memory, options: DirectOptions = {}): Promise<DirectRun> {
  if (options.keepNextAt !== true) storage.delete(JOB_NEXT_AT_KEY);
  runCounter += 1;
  const fresh = `fresh-${runCounter}`;
  const now = options.now ?? T0;
  const calls: Recorded[] = [];
  const wakes: number[] = [];
  const events: string[] = [];
  let disarms = 0;

  const fallback = (tool: string, args: Record<string, unknown>): CallAnswer => {
    if (tool === "changes_since") {
      return changesAnswerFor(options.rows ?? [], typeof args.marker === "string", fresh, options.count);
    }
    if (tool === "account_whoami") return whoamiAnswer();
    if (tool === "mail_flag") return flaggedAnswer(args);
    if (tool === "mail_compose_reply") return placedAnswer(args);
    return { kind: "failed" };
  };

  const logged: JobDeps["storage"] = {
    get: (key) => storage.get(key),
    put: (key, value) => {
      events.push(`put ${key}`);
      storage.put(key, value);
    },
    delete: (key) => {
      events.push(`delete ${key}`);
      return storage.delete(key);
    },
    list: (opts) => storage.list(opts),
  };

  const deps: JobDeps = {
    storage: logged,
    name: NAME,
    now: () => now,
    isRetry: options.isRetry === true,
    requestWake: async (wantedAt) => {
      events.push("wake");
      wakes.push(wantedAt);
    },
    disarm: async () => {
      events.push("disarm");
      disarms += 1;
      storage.delete(AUTONOMY_KEY);
      return { kind: "off" };
    },
    withSession: async (use) => {
      events.push("session");
      if (options.session !== undefined) return { kind: options.session };
      return {
        kind: "ok",
        value: await use(async (tool, args) => {
          events.push(`call ${tool}`);
          calls.push({ tool, args });
          return options.answer?.(tool, args) ?? fallback(tool, args);
        }),
      };
    },
    ...options.over,
  } as JobDeps;
  const outcome = await runAutonomyJob(deps);
  return { outcome, calls, wakes, events, disarms };
}

/** The action calls only. */
export function actions(calls: Recorded[]): Recorded[] {
  return calls.filter((call) => call.tool === "mail_flag" || call.tool === "mail_compose_reply");
}
