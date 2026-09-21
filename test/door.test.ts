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
import { entryEnv } from "./fixtures/bound-secrets";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import { USER_A } from "./fixtures/two-users";
import worker, {
  CANARY_TOOL_NAME,
  registerCanary,
} from "./fixtures/worker-with-canary";

const HOSTNAME = DEPLOYED_HOSTNAME;
const ORIGIN = `https://${HOSTNAME}`;

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
