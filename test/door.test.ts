// The door (CRED-04, D-07, D-08, D-09, D-27).
//
// **What this file proves.** The OAuth provider checks the bearer token, and
// then hands the API handler whatever props were stored with the grant. It does
// not check their shape. Spike S1 showed that, with no check of our own, a
// grant holding ANY props reaches the tool layer with a 200. So the API handler
// is a door: only a grant this server will still serve goes through, and every
// other grant gets a real HTTP 401 with a challenge header, before any MCP code
// runs.
//
// **Phase 11 inverted what "will still serve" means, and the inversion is the
// point.** It used to mean the one fixed owner grant, minted by a login gate
// that compared a shared secret. It now means a grant carrying a person's own
// Apple ID, checked against the allow list ON EVERY REQUEST. Two consequences,
// both deliberate:
//
//   GATE-05. The OLD owner grant is refused. Everyone holding one must sign in
//   again, and a real 401 with a challenge is what tells their client to.
//
//   GATE-03. Removing an address from the list refuses that person's very next
//   request. There is no cache and no token expiry to wait out.
//
// Three things are shown, each on both serving lanes:
//
// 1. A listed grant reaches a tool. Status 200, and the recording tool ran.
// 2. Every other shape of props is refused. Status 401, a challenge that names
//    the protected-resource metadata document, a fixed JSON body, and the
//    recording tool did NOT run. Nothing from the props is echoed back.
// 3. An unusable stored credential is NOT a 401. The grant still gets a 200 and
//    the mail diagnostic answers `auth_failed`. Signing in again is exactly
//    what fixes that one, but the client is told by the TOOL rather than by a
//    challenge, because the door cannot see a password Apple has revoked and
//    must not pretend to.
//
// **Why the positive control matters.** A recording tool that can never fire
// reports "never ran" whatever the door does. Every refusal below sends the
// SAME well-formed request that the served case proves does reach the tool. The
// only thing that differs is the props on the context. That is what makes
// "still false" mean "the door stopped it".
//
// **How the props get onto the context.** The OAuth provider sets them at run
// time. Here the test sets them, on the pool's own execution context, and
// drives the door's three-argument fetch directly. No OAuth grant is completed,
// so nothing here revokes anything.
//
// **This file holds no real value.** The Apple ID and the app password in the
// table are user A's fakes from the two-user fixture, and user A's address is
// on the allow list the pool binds (see vitest.config.ts) for exactly that
// reason. No test here reads, prints or asserts on the pool's ambient identity,
// and nothing here reaches the network: a grant that is refused never builds a
// principal at all, and a grant whose password is unusable is refused by the
// constructor before any socket opens.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import type { EntryEnv } from "../src/env";
import { assertMailSecretsBound, entryEnv } from "./fixtures/bound-secrets";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import { USER_A } from "./fixtures/two-users";
import worker, {
  CANARY_TOOL_NAME,
  registerCanary,
} from "./fixtures/worker-with-canary";

const HOSTNAME = DEPLOYED_HOSTNAME;
const ORIGIN = `https://${HOSTNAME}`;

// @ts-expect-error — Vite's `import.meta.glob` has no ambient declaration here;
// `test/dav-home-containment.test.ts` carries the full argument for it. `?raw`
// inlines the file's text at build time, which is how a Workers isolate with no
// filesystem reads source.
const DOOR_SOURCE_GLOB: Record<string, string> = import.meta.glob(
  "../src/mcp/api-handler.ts",
  { query: "?raw", import: "default", eager: true },
);

const DOOR_SOURCE: string = Object.values(DOOR_SOURCE_GLOB)[0] ?? "";

/** The mail diagnostic. The one tool that awaits the principal in this plan. */
const MAIL_DIAGNOSTIC = "mail_imap_diagnose";

/** The exact challenge the door must send for a request to the MCP path. */
const EXPECTED_CHALLENGE = `Bearer realm="OAuth", resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp", error="invalid_token", scope="mcp"`;

/** The door under test, with the recording tool registered beside the real ones. */
const door = createMcpApiHandler([registerCanary]);

/** Props for one case. `absent` means the context carries no props at all. */
type CaseProps = { absent: true } | { absent: false; props: unknown };

/**
 * The grant the login page mints, for a person who is on the allow list.
 *
 * User A's address is bound into `ALLOWED_APPLE_IDS` in `vitest.config.ts`
 * precisely so this positive control can exist. Without a grant the door
 * actually serves, every refusal below is vacuous.
 */
const LISTED: CaseProps = {
  absent: false,
  props: {
    v: 1,
    appleId: USER_A.appleId,
    appPassword: USER_A.appPassword,
  },
};

/**
 * Drive the door with a context that carries the props under test.
 *
 * The pool's execution context is a plain object with no props field of its
 * own, and the installed type marks the field read-only. So the value is
 * defined onto the real context, which needs no cast and no wrapper, and the
 * MCP handler downstream sees the very same context the door saw.
 */
async function callDoor(
  request: Request,
  caseProps: CaseProps,
  withEnv: EntryEnv = entryEnv(),
): Promise<Response> {
  const ctx = createExecutionContext();
  if (!caseProps.absent) {
    Object.defineProperty(ctx, "props", {
      value: caseProps.props,
      enumerable: true,
    });
  }
  const response = await door.fetch(request, withEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Drive the fixture Worker, for the recording tool's reset and read routes. */
async function callWorker(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/**
 * A fully well-formed 2026-07-28 `tools/call`.
 *
 * Every header and envelope field the revision requires is present, so nothing
 * downstream of the door has an excuse to reject it.
 */
function toolCall(path: string, name: string = CANARY_TOOL_NAME): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
      "Mcp-Method": "tools/call",
      "Mcp-Name": name,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: {},
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/**
 * The shape Claude Desktop sends: a claim-less `tools/call`.
 *
 * No protocol-version envelope, no protocol-version header, and none of the
 * routing headers the 2026-07-28 revision adds. A second helper rather than an
 * option on `toolCall`, because what sets the two apart is the ABSENCE of
 * fields, and an absence written as a flag is one spread away from coming back.
 */
function claimlessToolCall(path: string, name: string = CANARY_TOOL_NAME): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: {} },
    }),
  });
}

/** A well-formed 2026-07-28 `tools/list`. It calls no tool at all. */
function toolsList(path: string): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      host: HOSTNAME,
      "Mcp-Method": "tools/list",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
}

/** The two lanes, so every case runs on both. */
const LANES: ReadonlyArray<
  readonly [string, (path: string, name?: string) => Request]
> = [
  ["modern lane", toolCall],
  ["claim-less lane", claimlessToolCall],
];

async function canaryWasInvoked(): Promise<boolean> {
  const response = await callWorker(new Request(`${ORIGIN}/__canary`));
  const body = (await response.json()) as { invoked: boolean };
  return body.invoked;
}

/**
 * The JSON-RPC message in a response body, on either lane.
 *
 * The modern lane answers with a JSON body. The claim-less lane answers over
 * an event stream, where the message is the text after `data:`. Null when the
 * body holds neither.
 */
function rpcMessageIn(bodyText: string): Record<string, unknown> | null {
  const trimmed = bodyText.trim();
  const candidates = trimmed.startsWith("{")
    ? [trimmed]
    : trimmed
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim());
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Not this line. Try the next one.
    }
  }
  return null;
}

/**
 * Every props shape the door must refuse (D-07).
 *
 * `marks` lists the strings that case's props hold and that must not come back
 * in the 401. Each mark is long enough that it cannot match by accident.
 */
const REFUSED_PROPS: ReadonlyArray<{
  readonly label: string;
  readonly caseProps: CaseProps;
  readonly marks: readonly string[];
}> = [
  {
    // GATE-05. THE row this phase exists to add. Every grant minted before the
    // switch has exactly this shape, and each one holds no credential at all —
    // it named the owner and the credentials came from the Worker secrets. A
    // server that honoured these would be serving the owner's mail to whoever
    // still holds one of those tokens, out of secrets Phase 13 is about to
    // delete. The 401 and its challenge are what send those clients to sign in
    // again, which is the only thing that can fix it.
    label: "the OLD single-key owner grant, which this phase stops honouring",
    caseProps: { absent: false, props: { userId: "owner" } },
    marks: [],
  },
  {
    label: "a user id that is not the owner's",
    caseProps: { absent: false, props: { userId: "someone-else-entirely" } },
    marks: ["someone-else-entirely"],
  },
  {
    label: "the owner's id plus one extra key",
    caseProps: {
      absent: false,
      props: { userId: "owner", extra: "extra-key-value-marker" },
    },
    marks: ["extra-key-value-marker"],
  },
  {
    label: "the owner's id in a different letter case",
    caseProps: { absent: false, props: { userId: "Owner" } },
    marks: [],
  },
  {
    label: "no props at all",
    caseProps: { absent: true },
    marks: [],
  },
  {
    label: "null",
    caseProps: { absent: false, props: null },
    marks: [],
  },
  {
    label: "an array holding the owner's id",
    caseProps: { absent: false, props: ["owner"] },
    marks: [],
  },
];

beforeEach(async () => {
  // Reset between cases, so a passing first case cannot mask a failing second.
  await callWorker(new Request(`${ORIGIN}/__canary/reset`, { method: "POST" }));
  expect(await canaryWasInvoked()).toBe(false);
});

describe.each(LANES)("a listed grant goes through the door, %s", (_lane, build) => {
  it("reaches the tool layer with a 200", async () => {
    // The positive control. Without this passing, every refusal below is
    // vacuous: the same request, with a listed person's props, must reach the
    // tool.
    const response = await callDoor(build("/mcp"), LISTED);

    expect(response.status, "a listed grant was not served").toBe(200);
    expect(
      response.headers.get("WWW-Authenticate"),
      "a listed grant was sent a challenge",
    ).toBeNull();

    // The claim-less lane answers over a stream and the tool runs as the
    // stream is pulled. Drain before reading the flag, on both lanes.
    await response.text();

    expect(
      await canaryWasInvoked(),
      "a listed grant did not reach the tool layer",
    ).toBe(true);
  });
});

describe.each(LANES)("every other grant is refused at the door, %s", (_lane, build) => {
  it("runs a table that is not empty and whose marks are real", () => {
    expect(REFUSED_PROPS.length).toBe(7);
    for (const one of REFUSED_PROPS) {
      for (const mark of one.marks) {
        expect(mark.length, `a mark in "${one.label}" is too short to mean anything`).toBeGreaterThan(10);
      }
    }
  });

  it.each(REFUSED_PROPS)("refuses $label", async ({ caseProps, marks }) => {
    const response = await callDoor(build("/mcp"), caseProps);

    expect(response.status, "props this server must not serve were served").toBe(401);

    const challenge = response.headers.get("WWW-Authenticate");
    expect(challenge, "the 401 carries no challenge").not.toBeNull();
    expect(challenge).toMatch(/^Bearer/);
    expect(challenge).toContain("/.well-known/oauth-protected-resource/mcp");
    expect(challenge, "the challenge is not built from the library's parts").toBe(
      EXPECTED_CHALLENGE,
    );

    expect(response.headers.get("Content-Type")).toBe("application/json");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Pragma")).toBe("no-cache");

    const bodyText = await response.text();
    const body = JSON.parse(bodyText) as Record<string, unknown>;
    expect(body.error).toBe("invalid_token");
    expect(body.error_description).toBe(
      "Stored login is out of date. Sign in again.",
    );
    expect(Object.keys(body).sort(), "the 401 body grew a key").toEqual([
      "error",
      "error_description",
    ]);

    // Nothing from the props comes back, in the body or in any header.
    const everyHeader = [...response.headers.entries()]
      .map(([name, value]) => `${name}: ${value}`)
      .join("\n");
    for (const mark of marks) {
      expect(bodyText, "the 401 body echoes the props").not.toContain(mark);
      expect(everyHeader, "a 401 header echoes the props").not.toContain(mark);
    }

    // The assertion this table exists for.
    expect(
      await canaryWasInvoked(),
      "the tool layer was reached by a grant the door must refuse",
    ).toBe(false);
  });
});

describe.each(LANES)(
  "a grant the door cannot inspect is refused, not a 500, %s",
  (_lane, build) => {
    // Code review WR-01. The guard reads several things off the props, and each
    // read can run code the props brought with them. A throw out of the guard
    // is a 500 with no challenge, which tells the client nothing about signing
    // in again. So the guard fails closed and these get the ordinary 401.
    //
    // Neither shape is reachable today: props reach the context only through a
    // parse of the decrypted grant, which builds plain objects with data
    // properties. They are pinned anyway, because the guarantee is meant to be
    // a property of the guard rather than of what currently feeds it.
    //
    // **Both shapes had to move with the switch, and the accessor one is the
    // reason why.** The guard now reads `appleId` rather than `userId`, so an
    // accessor on the OLD key would never be reached — the case would still
    // answer 401, for the entirely different reason that the key is absent, and
    // would look green while proving nothing about the catch. The shape below
    // carries THREE own keys so the count passes, with `appleId` the one that
    // throws when it is read.
    const UNINSPECTABLE: ReadonlyArray<readonly [string, () => unknown]> = [
      [
        "props whose Apple ID is an accessor that throws",
        () => {
          const props = { v: 1, appPassword: "irrelevant-to-this-case" };
          Object.defineProperty(props, "appleId", {
            enumerable: true,
            get(): string {
              throw new Error("the accessor ran");
            },
          });
          return props;
        },
      ],
      [
        "props that are a proxy whose membership trap throws",
        () =>
          new Proxy(
            { v: 1, appleId: USER_A.appleId, appPassword: USER_A.appPassword },
            {
              has(): boolean {
                throw new Error("the trap ran");
              },
            },
          ),
      ],
    ];

    it.each(UNINSPECTABLE)("refuses %s", async (_shape, makeProps) => {
      const response = await callDoor(build("/mcp"), {
        absent: false,
        props: makeProps(),
      });

      expect(
        response.status,
        "a grant the guard could not inspect was not refused with a 401",
      ).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toBe(EXPECTED_CHALLENGE);

      const body = JSON.parse(await response.text()) as Record<string, unknown>;
      expect(body.error).toBe("invalid_token");
      expect(
        Object.keys(body).sort(),
        "the 401 body grew a key, or carries the caught value",
      ).toEqual(["error", "error_description"]);

      expect(
        await canaryWasInvoked(),
        "a grant the guard could not inspect reached the tool layer",
      ).toBe(false);
    });
  },
);

describe.each(LANES)(
  "removal from the allow list takes effect on the next request, %s",
  (_lane, build) => {
    // GATE-03, and the pair is the whole assertion — neither half means
    // anything alone. One grant, two environments, two answers. If only the
    // refusal existed it would be satisfied by a door that refuses everything;
    // if only the service existed it would be satisfied by a door that checks
    // nothing at all.
    //
    // **The removal is expressed by varying the ENVIRONMENT, not by editing a
    // binding.** `callDoor` already takes an environment override for exactly
    // this. Assigning onto the ambient environment would leak the change into
    // every later case in the run, and a scan rule rejects it outright.
    //
    // **There is no cache to wait out and no token to expire.** The list is
    // parsed and compared inside `fetch` on every single request, which is why
    // "deploy without them and their access ends" is a true sentence for the
    // owner to read in the README.

    /** The pool's environment with user A taken off the allow list. */
    function envWithoutUserA(): EntryEnv {
      return {
        ...entryEnv(),
        ALLOWED_APPLE_IDS: JSON.stringify(["somebody-else@example.invalid"]),
      };
    }

    it("serves the grant while the address is listed", async () => {
      // The positive control for the pair. The SAME grant, one environment
      // over, is what makes the refusal below mean "the list stopped it".
      const response = await callDoor(build("/mcp"), LISTED);

      expect(response.status, "a listed grant was not served").toBe(200);
      expect(response.headers.get("WWW-Authenticate")).toBeNull();

      await response.text();
      expect(
        await canaryWasInvoked(),
        "a listed grant did not reach the tool layer",
      ).toBe(true);
    });

    it("refuses that identical grant once the address is gone", async () => {
      const response = await callDoor(build("/mcp"), LISTED, envWithoutUserA());

      expect(
        response.status,
        "a grant whose address was removed from the list was still served",
      ).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toBe(EXPECTED_CHALLENGE);

      const bodyText = await response.text();
      const body = JSON.parse(bodyText) as Record<string, unknown>;
      expect(body.error).toBe("invalid_token");
      expect(Object.keys(body).sort(), "the 401 body grew a key").toEqual([
        "error",
        "error_description",
      ]);

      // The marks. This grant holds a real-shaped address and password, and
      // neither may come back in the refusal — not in the body and not in a
      // header. A removed person's own credentials echoed at them would be the
      // one place this server leaks what it is holding.
      const everyHeader = [...response.headers.entries()]
        .map(([name, value]) => `${name}: ${value}`)
        .join("\n");
      for (const mark of [USER_A.appleId, USER_A.appPassword]) {
        expect(bodyText, "the 401 body echoes the props").not.toContain(mark);
        expect(everyHeader, "a 401 header echoes the props").not.toContain(mark);
      }

      expect(
        await canaryWasInvoked(),
        "a removed person's grant reached the tool layer",
      ).toBe(false);
    });

    it("refuses that grant against an allow list that cannot be read", async () => {
      // Fail-closed, at the door as well as at the login page. A deployment
      // whose list is missing or malformed serves nobody — including people
      // whose grants were minted while it was fine.
      for (const broken of [undefined, "", "not json", "[]", '{"a":1}']) {
        const response = await callDoor(build("/mcp"), LISTED, {
          ...entryEnv(),
          ALLOWED_APPLE_IDS: broken,
        });

        expect(
          response.status,
          `an unreadable allow list (${String(broken)}) still served a grant`,
        ).toBe(401);
        expect(response.headers.get("WWW-Authenticate")).toBe(EXPECTED_CHALLENGE);
        await response.text();
      }

      expect(await canaryWasInvoked()).toBe(false);
    });
  },
);

describe("an unusable stored credential is not a 401 (D-09)", () => {
  // **The claim is unchanged; what carries it moved with identity itself.**
  //
  // This block used to unset the two Worker secrets, because that was where a
  // credential came from. Since the switch the credential lives in the grant,
  // so the equivalent shape is a grant whose PASSWORD is unusable. Everything
  // the block asserts is the same, and so is the reason it matters: the door
  // must not answer 401 for this. A 401 tells the client to drop its token and
  // sign in again, and that advice is wrong here — the address is still listed
  // and the grant is still well-formed. The tool's `auth_failed` is the honest
  // answer, and it is the one a model can act on.
  //
  // The door lets this through ON PURPOSE. It checks the address and never the
  // password, because it cannot see whether Apple would accept one without
  // asking Apple, and asking Apple on every request is exactly what this
  // server must not do.

  /**
   * A grant on the list whose password can never be used.
   *
   * An empty string, which `principalFromProps` refuses (D-19) before any
   * socket exists — so this case reaches no network either.
   */
  const UNUSABLE_PASSWORD: CaseProps = {
    absent: false,
    props: { v: 1, appleId: USER_A.appleId, appPassword: "" },
  };

  it.each(LANES)(
    "answers 200 and the mail diagnostic says auth_failed, %s",
    async (_lane, build) => {
      const response = await callDoor(
        build("/mcp", MAIL_DIAGNOSTIC),
        UNUSABLE_PASSWORD,
      );

      expect(
        response.status,
        "an unusable credential was answered with something other than a served request",
      ).toBe(200);
      expect(
        response.headers.get("WWW-Authenticate"),
        "an unusable credential was answered with a sign-in challenge",
      ).toBeNull();

      const message = rpcMessageIn(await response.text());
      expect(message, "the response holds no JSON-RPC message").not.toBeNull();
      const result = message?.result as
        | { isError?: boolean; content?: { text?: string }[] }
        | undefined;
      expect(result, "the tool call has no result").toBeDefined();
      expect(result?.isError, "the tool did not report a failure").toBe(true);

      const answer = JSON.parse(result?.content?.[0]?.text ?? "null") as {
        category?: string;
        authRefusedBy?: string;
        authFailureDetail?: string;
      } | null;
      expect(answer?.category).toBe("auth_failed");

      // Code review WR-04. The answer says WHICH SIDE refused. This server did,
      // before any socket opened, so Apple said nothing and there is no
      // rejection text to carry. An answer with no such field means iCloud was
      // asked. The category and its message are untouched (D-05).
      expect(
        answer?.authRefusedBy,
        "the answer does not say the refusal happened before iCloud was asked",
      ).toBe("this server");
      expect(
        answer?.authFailureDetail,
        "a refusal that never reached Apple carries Apple's rejection text",
      ).toBeUndefined();
    },
  );

  it("answers a tools/list with 200, though no tool ever awaits the principal", async () => {
    // The door makes the promise of the principal for every request. A request
    // that calls no tool never awaits it. With an unusable stored credential
    // that promise rejects, and the door's no-op handler is what keeps it from
    // being an unhandled rejection.
    const response = await callDoor(toolsList("/mcp"), UNUSABLE_PASSWORD);

    expect(response.status).toBe(200);
    const message = rpcMessageIn(await response.text());
    const result = message?.result as { tools?: { name: string }[] } | undefined;
    expect(
      result?.tools?.some((tool) => tool.name === MAIL_DIAGNOSTIC),
      "the tools/list answer does not list the mail diagnostic",
    ).toBe(true);
  });
});

describe("identity comes from the grant and from nowhere else (the promotion)", () => {
  // **What this block is for.** Phase 11 did not ADD a per-user identity beside
  // the environment one. It PROMOTED it: the per-user principal is now the only
  // live identity path, and the environment-backed constructor is a retiring
  // variant that the next milestone's cutover requirement deletes along with
  // the three secrets. Adding alongside is the shape that silently contradicts
  // a promotion — a second person could be stored and never served, because the
  // environment identity would still win somewhere — so the invariant is worth
  // its own proof rather than being inferred from the switch having been made.
  //
  // **Two cases, and they are not the same claim.**
  //
  // The FIRST is the claim. It is behavioural: a grant carrying a listed
  // address and a usable password is SERVED, and the request reaches the tool
  // layer, while the two mail secrets are absent from the environment the door
  // was called with. Before the switch that request failed on the way to the
  // tool, because identity came from those secrets. It succeeds now because
  // identity comes from the props. Nothing about a file's text is asserted.
  //
  // The SECOND is a tripwire, and it exists because the first has a blind spot
  // that is worth stating rather than glossing. **The recording tool never
  // AWAITS the principal** — it flips a flag and returns, exactly as its own
  // fixture says. So "the request reached the tool layer" proves the door
  // served the grant; it does not prove which object the promise it handed down
  // was built from. Two shapes would pass the behavioural case and should not:
  //
  //   1. A door that keeps a DEAD reference to the retiring constructor — an
  //      import it no longer calls, a branch nothing reaches. That is how a
  //      later phase reintroduces the singular assumption by accident: the name
  //      comes back first, the call site comes back second, and the gap between
  //      them is where nothing is watching.
  //   2. The add-ALONGSIDE shape the context file names as the thing a promote
  //      must not become: the address checked against the props, the credential
  //      still taken from the environment. With the recording tool, a rejected
  //      environment principal is indistinguishable from a resolved props one.
  //
  // The source-text case closes both, and it closes them the same way: the door
  // cannot build a principal from the environment without naming the one
  // constructor that does it, and it names it nowhere. That is why the pair is
  // the proof and neither half is.
  //
  // **Why there is no third case awaiting a real principal.** Only a tool that
  // awaits it can observe what it resolved to, and every such tool opens a
  // socket to Apple the moment the principal is usable. D-09 forbids that from
  // any test in this repository, and the props here are fakes, so the socket
  // would be a real connection attempt against a real Apple host with a made-up
  // address. The existing block above takes the other branch — a props password
  // the constructor REFUSES, which reaches no network — and that branch cannot
  // tell the two sources apart, because an absent environment secret is refused
  // by the same constructor with the same answer.
  //
  // **The constructor itself is NOT deleted here, and that is deliberate.** Its
  // definition stays in the principal module, `test/fixtures/bound-secrets.ts`
  // still calls it, and a dozen suites still drive it. The next milestone's
  // cutover requirement deletes it together with the three secrets. What this
  // phase owns is making the per-user principal the only LIVE path, which is
  // what these two cases hold.

  /**
   * The pool's environment with the two mail secrets taken away.
   *
   * A fresh spread COPY, never a write onto the object `entryEnv()` hands back.
   * That object is shared by every test in the isolate, so an in-place override
   * would leak into every later case in the run — and the environment-assignment
   * scan rule refuses that form outright, in every scanned directory.
   */
  function envWithoutMailSecrets(): EntryEnv {
    return {
      ...entryEnv(),
      APPLE_ID: undefined,
      APPLE_APP_PASSWORD: undefined,
    };
  }

  it.each(LANES)(
    "serves a listed grant with the environment's mail secrets absent, %s",
    async (_lane, build) => {
      // Non-vacuity first, and it is the same positive control every refusal in
      // this file leans on: the identical request with the identical props IS
      // served under the ordinary environment. Without that, "served with the
      // secrets absent" could be satisfied by a door that serves anything.
      const control = await callDoor(build("/mcp"), LISTED);
      expect(control.status, "the control was not served").toBe(200);
      await control.text();
      expect(
        await canaryWasInvoked(),
        "the control did not reach the tool layer",
      ).toBe(true);

      await callWorker(new Request(`${ORIGIN}/__canary/reset`, { method: "POST" }));
      expect(await canaryWasInvoked()).toBe(false);

      // The second non-vacuity guard, and the one specific to this case: the
      // pool really does bind both secrets, and the copy below really has
      // neither. Without this pair, a `?? ""` slipped into the fixture or a
      // pool that stopped binding them would leave the case asserting that a
      // request is served with two things absent that were never there.
      const ambient = entryEnv();
      assertMailSecretsBound(ambient);
      const withoutSecrets = envWithoutMailSecrets();
      expect(
        withoutSecrets.APPLE_ID,
        "the override did not remove the Apple ID binding",
      ).toBeUndefined();
      expect(
        withoutSecrets.APPLE_APP_PASSWORD,
        "the override did not remove the app-password binding",
      ).toBeUndefined();

      const response = await callDoor(build("/mcp"), LISTED, withoutSecrets);

      expect(
        response.status,
        "a grant carrying its own credentials was refused because the environment had none",
      ).toBe(200);
      expect(
        response.headers.get("WWW-Authenticate"),
        "a grant carrying its own credentials was sent a sign-in challenge",
      ).toBeNull();

      // The claim-less lane answers over a stream and the tool runs as the
      // stream is pulled. Drain before reading the flag, on both lanes.
      await response.text();

      expect(
        await canaryWasInvoked(),
        "a request whose identity is in its grant did not reach the tool layer with the environment's mail secrets absent",
      ).toBe(true);
    },
  );

  it("the door's source names the retiring environment constructor nowhere", () => {
    // Non-vacuity first. A `?raw` import that resolved to nothing would make
    // the assertion below pass while reading an empty string, which is the
    // failure this whole mechanism is most prone to.
    expect(
      DOOR_SOURCE.length,
      "the ?raw import of src/mcp/api-handler.ts loaded nothing",
    ).toBeGreaterThan(1000);
    expect(
      DOOR_SOURCE,
      "the ?raw import did not load the door's source",
    ).toContain("createMcpApiHandler");

    // Comments count, and on purpose. The door DOES discuss the retiring
    // constructor — it has to, because the switch is the interesting thing
    // about that line — and it does so by ROLE. A file that starts spelling
    // the name again is a file where somebody is thinking about it as code.
    expect(
      DOOR_SOURCE,
      "the door names the environment-backed principal constructor; identity must come from the grant, and even a dead reference is how the singular assumption comes back",
    ).not.toContain("principalFromEnv");
  });
});
