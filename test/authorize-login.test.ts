// The switch, proved on one path: a listed person signs in with their own
// Apple ID, one login happens, and the grant that comes out is one the door
// serves.
//
// **What this file proves that its neighbours do not.**
// `test/allow-list.test.ts` drives the allow-list rule straight at the
// predicate — it proves the RULE. `test/door.test.ts` proves a stored grant is
// checked against that rule on every request — it proves the rule is WIRED to
// the serving path. This file proves the third thing, which neither of those
// can see: that the login page consults the rule BEFORE it spends anything, and
// that what it stores is exactly what the door will later accept. A rule that
// were correct, and wired at the door, and consulted one step too late at the
// login page, would pass both of those files and still send an unlisted
// stranger's credentials to Apple.
//
// Three test shapes, the taxonomy `test/authorize-redirect-allowlist.test.ts`
// lays out in its own header:
//
//   The handler with a STUBBED PROVIDER. Anything about ORDERING — that an
//   unlisted address never reaches the proof, that the 503 gate beats the
//   method dispatch, that `completeAuthorization` received exactly these
//   arguments — cannot be observed from outside a real provider. Those drive
//   `createLoginHandler(proof).fetch` directly with a recording stub.
//
//   An INJECTED PROOF. D-09 forbids any automated login to a real Apple ID:
//   no test, CI job, pre-commit hook or post-deploy check ever authenticates
//   against one. So the proof is a counter. That is not only how this file
//   stays inside D-09 — it is the only way "zero sockets were opened for that
//   request" becomes an assertion rather than an inference. A refusal that
//   happened AFTER a failed login and one that happened before the socket
//   existed produce the identical status code.
//
//   The REAL DOOR. The round trip at the end takes the props this file just
//   recorded, puts them on a pool execution context, and drives the production
//   door. Without it the two halves could each be self-consistent and still
//   disagree with one another — a login page storing a shape the door refuses
//   would leave every person who signed in locked out on their very next call,
//   and nothing above this line would notice.
//
// **The `completeAuthorization` stub RECORDS rather than being omitted**, the
// habit the redirect-allowlist file's own recorder states: "the refusal beat
// the ceremony" is only really proved by the ceremony not being completed, and
// a stub that simply lacked the method would fail by throwing, which is a
// different assertion wearing the same green.
//
// **This file holds no real value.** Both addresses sit under `.invalid`, a
// name reserved so it can never resolve, and the password is plainly fake.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { LoginProof } from "../src/auth/login-handler";
import { UNCONFIGURED_BODY, createLoginHandler } from "../src/auth/login-handler";
import type { Env, LoginGateSecret } from "../src/env";
import { entryEnv } from "./fixtures/bound-secrets";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  UNLISTED_APPLE_ID,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/**
 * The allow list this file's stubbed env binds.
 *
 * Named once here and built from the shared constant, following the habit the
 * three older authorize suites use for the bound secret: a value a test asserts
 * against is spelled in one place, with a comment saying where the real one
 * lives. The pool's own binding is in `vitest.config.ts` under
 * `ALLOWED_APPLE_IDS`, and it holds this same address.
 */
const STUB_ALLOW_LIST = JSON.stringify([LISTED_APPLE_ID]);

/** A query the stub provider is happy to parse. */
const STUB_QUERY = "response_type=code&client_id=stub-client";

/** Where the stub provider says the code would go. On an allowed origin. */
const STUB_REDIRECT = "https://claude.ai/cb";

/** What `completeAuthorization` was handed, recorded rather than inferred. */
interface CompleteArgs {
  userId?: unknown;
  metadata?: unknown;
  props?: unknown;
  scope?: unknown;
}

/** Everything the handler reached, and with what. */
interface Recorder {
  readonly calls: string[];
  readonly completed: CompleteArgs[];
  readonly proof: LoginProof;
  /** How many times the login proof ran. Zero is the assertion that matters. */
  proofCalls(): number;
}

/**
 * A recorder whose proof counts, and optionally refuses.
 *
 * Refusing by THROWING is what production does — a login iCloud turns down
 * rejects out of `withMailSession`, and the handler branches on the error's
 * type and never on a returned flag. A stub answering `false` instead would be
 * exercising control flow this server does not have.
 */
function recorder(options: { refuse?: boolean } = {}): Recorder {
  const calls: string[] = [];
  const completed: CompleteArgs[] = [];
  let proofCalls = 0;
  return {
    calls,
    completed,
    proof: async () => {
      proofCalls += 1;
      if (options.refuse) throw new Error("the injected proof refused");
    },
    proofCalls: () => proofCalls,
  };
}

/** A KV stub: no real namespace, nothing over the cap. */
function quietKv() {
  return {
    async get() {
      return null;
    },
    async put() {
      /* nothing here asserts on the counter. */
    },
  };
}

/**
 * An env whose provider records what the handler reached, and with what.
 *
 * `allowList` is a parameter rather than a constant because the 503 cases need
 * it absent, and because an absent binding is exactly the shape a deployment
 * that forgot to provision the Secret has.
 */
function stubEnv(
  record: Recorder,
  options: { allowList?: string | undefined } = {},
): Env & LoginGateSecret {
  return {
    OAUTH_KV: quietKv(),
    ALLOWED_APPLE_IDS:
      "allowList" in options ? options.allowList : STUB_ALLOW_LIST,
    OAUTH_PROVIDER: {
      parseAuthRequest: async () => {
        record.calls.push("parseAuthRequest");
        return {
          responseType: "code",
          clientId: "stub-client",
          redirectUri: STUB_REDIRECT,
          scope: ["mcp"],
          state: "",
        };
      },
      lookupClient: async () => {
        record.calls.push("lookupClient");
        return { clientId: "stub-client", clientName: "Stub Client" };
      },
      completeAuthorization: async (args: CompleteArgs) => {
        record.calls.push("completeAuthorization");
        record.completed.push(args);
        return { redirectTo: `${STUB_REDIRECT}?code=stub-code` };
      },
    },
  } as unknown as Env & LoginGateSecret;
}

function get(query = STUB_QUERY): Request {
  return new Request(`${ORIGIN}/authorize?${query}`);
}

function post(
  appleId: string,
  appPassword: string = FAKE_APP_PASSWORD,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: appPassword,
      oauth_request: STUB_QUERY,
    }).toString(),
  });
}

function verb(name: string): Request {
  return new Request(`${ORIGIN}/authorize?${STUB_QUERY}`, { method: name });
}

describe("the method dispatch", () => {
  // Titled so `-t "method"` matches. 11-VALIDATION.md ships that exact command
  // for LOGIN-01, and a name filter that matches nothing passes SILENTLY —
  // which would leave the row looking covered while measuring nothing.

  it("renders the form on a GET, asking for an Apple ID and a password", async () => {
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      get(),
      stubEnv(record),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(body).toContain(`name="apple_id"`);
    expect(body).toContain(`name="app_password"`);
    // The field the switch removed. Its absence is the whole change, visible.
    expect(body).not.toContain(`name="secret"`);
    // LOGIN-07, the half this plan already owes: neither credential field
    // carries a value attribute, so nothing typed comes back to the reader.
    expect(body).not.toMatch(/name="apple_id"[^>]*value=/);
    expect(body).not.toMatch(/name="app_password"[^>]*value=/);
    // A render is not a sign-in.
    expect(record.proofCalls()).toBe(0);
  });

  it("refuses a method that is neither GET nor POST", async () => {
    const record = recorder();
    const handler = createLoginHandler(record.proof);

    for (const name of ["PUT", "DELETE", "PATCH"]) {
      const response = await handler.fetch(verb(name), stubEnv(record));
      expect(response.status, `${name} was not refused`).toBe(405);
      expect(response.headers.get("allow")).toBe("GET, POST");
    }

    expect(record.calls).not.toContain("completeAuthorization");
    expect(record.proofCalls()).toBe(0);
  });
});

describe("one login, and only one, for a sign-in that works", () => {
  // Titled so `-t "one login"` matches — 11-VALIDATION.md's LOGIN-01 command.

  it("ends in a 302 and calls the proof exactly once", async () => {
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location") ?? "").toContain("code=");
    // Exactly one. Not "at least one": a retry loop, a fallback mechanism or a
    // second session would each cost this person another attempt at Apple,
    // whose own lockout threshold is unpublished and assumed small.
    expect(record.proofCalls()).toBe(1);
    expect(record.calls).toContain("completeAuthorization");
  });

  it("does not complete the ceremony when the proof refuses", async () => {
    // The proof still ran — the address was listed, so asking Apple was the
    // right thing to do — but nothing was stored and nothing was redirected.
    const record = recorder({ refuse: true });
    const response = await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(record.proofCalls()).toBe(1);
    expect(response.status).toBe(401);
    expect(response.headers.get("location")).toBeNull();
    expect(record.calls).not.toContain("completeAuthorization");
  });
});

describe("the props the ceremony is completed with", () => {
  // Titled so `-t "props"` matches — 11-VALIDATION.md's LOGIN-06 command.

  it("holds exactly the version, the address and the password", async () => {
    const record = recorder();
    await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(record.completed).toHaveLength(1);
    const args = record.completed[0];
    const props = args.props as Record<string, unknown>;

    // EXACTLY three own keys, symbol keys included. `principalFromProps` at the
    // other end refuses a fourth of any kind, so a props object that grew one
    // here would be stored successfully and then refused on every later
    // request — a person locked out by their own sign-in.
    expect(Reflect.ownKeys(props)).toHaveLength(3);
    expect(Object.keys(props).sort()).toEqual(["appPassword", "appleId", "v"]);
    expect(props.v).toBe(1);
    expect(props.appleId).toBe(LISTED_APPLE_ID);
    expect(props.appPassword).toBe(FAKE_APP_PASSWORD);
  });

  it("names the user by a derived id, not by the address and not by owner", async () => {
    const record = recorder();
    await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    const userId = record.completed[0]?.userId;

    // 64 lowercase hex characters: the full digest, never shortened, and never
    // upper case. It names every per-user object this person will ever have.
    expect(typeof userId).toBe("string");
    expect(userId).toMatch(/^[0-9a-f]{64}$/);
    // The two values it must never be. The address itself would put personal
    // data in every key name the provider writes; the old fixed literal would
    // make two people one user.
    expect(userId).not.toBe(LISTED_APPLE_ID);
    expect(userId).not.toBe("owner");
  });

  it("puts nothing but the client name in the metadata", async () => {
    // Metadata is not encrypted the way props are. Nothing about the person
    // goes in it — not the address, not the id derived from it.
    const record = recorder();
    await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    const metadata = record.completed[0]?.metadata as Record<string, unknown>;

    expect(Object.keys(metadata)).toEqual(["clientName"]);
    expect(metadata.clientName).toBe("Stub Client");
  });
});

describe("an address that is not on the list", () => {
  it("never reaches the proof, so no socket is opened to Apple", async () => {
    // GATE-02, and the reason the proof is injected at all. A status code
    // cannot tell "refused before the socket" from "refused after the login
    // failed" — both are a 401. Only the counter can.
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post(UNLISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(record.proofCalls(), "an unlisted address reached Apple").toBe(0);
    expect(response.status).toBe(401);
    expect(record.calls).not.toContain("completeAuthorization");
  });

  it("is answered the same way a refused password is", async () => {
    // LOGIN-05's shape, as far as this plan takes it: the status and the body
    // are identical, so a reader cannot sort listed addresses from unlisted
    // ones by trying one. The single failure string and the time floor land in
    // plans 11-02 and 11-04; what is already true here is that these two
    // answers are the same object built by the same code path.
    const unlisted = recorder();
    const refused = recorder({ refuse: true });

    const a = await createLoginHandler(unlisted.proof).fetch(
      post(UNLISTED_APPLE_ID),
      stubEnv(unlisted),
    );
    const b = await createLoginHandler(refused.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(refused),
    );

    expect(a.status).toBe(b.status);
    expect(await a.text()).toBe(await b.text());
  });

  it("refuses an address this server cannot read at all", async () => {
    // The fail-closed edge. An address the folding turns away is not compared
    // against the list, it is refused — and it is refused here rather than by
    // the principal constructor, so nothing is built for it either.
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post("no-at-sign-at-all"),
      stubEnv(record),
    );

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
  });

  it("refuses a password the principal constructor will not store", async () => {
    // LOGIN-03's floor, which this plan already has for free: an empty password
    // is refused by `principalFromProps` (D-19) before any socket exists. The
    // looser shape check — what an app-specific password may look like — is
    // plan 11-04's, deliberately, because a strict rule that is wrong refuses a
    // legitimate person with a silent failure.
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID, ""),
      stubEnv(record),
    );

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
  });
});

describe("a deployment with no usable allow list refuses to authorize", () => {
  // Carried over from the retired `test/authorize-secret.test.ts`. Its subject
  // — the shared-secret comparison — left with the switch, but two of its
  // claims are about the GATE rather than about the secret, and those are still
  // exactly as load-bearing: the gate fires above the method dispatch, and the
  // refusal is rendered locally rather than redirected anywhere.

  const UNUSABLE: ReadonlyArray<readonly [string, string | undefined]> = [
    ["absent", undefined],
    ["an empty string", ""],
    ["not JSON at all", "someone@icloud.com"],
    ["an empty array", "[]"],
    ["an object rather than an array", '{"allow":["someone@icloud.com"]}'],
  ];

  it.each(UNUSABLE)("answers 503 to a GET when the list is %s", async (_label, list) => {
    // Above the method dispatch, so a GET never reaches the form. A form served
    // by a deployment that cannot say who may sign in invites a submission
    // nobody can act on.
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      get(),
      stubEnv(record, { allowList: list }),
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    // Rendered locally, never redirected. A refusal that sent the browser
    // somewhere would be the CVE-class bug this file's neighbour exists to
    // prevent, arriving through the one door nobody was watching.
    expect(response.headers.get("location")).toBeNull();
    // The gate is above everything: the provider was never consulted.
    expect(record.calls).toHaveLength(0);
  });

  it.each(UNUSABLE)("answers 503 to a POST when the list is %s", async (_label, list) => {
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record, { allowList: list }),
    );

    expect(response.status).toBe(503);
    expect(await response.text()).toBe(UNCONFIGURED_BODY);
    expect(record.proofCalls(), "a POST past an unusable list reached Apple").toBe(0);
    expect(record.calls).toHaveLength(0);
  });

  it("names no binding in the refusal", async () => {
    // The body is a fixed constant that interpolates nothing, which is what
    // lets it stay true for an allow list after being written for a secret.
    const record = recorder();
    const body = await createLoginHandler(record.proof)
      .fetch(get(), stubEnv(record, { allowList: undefined }))
      .then((response) => response.text());

    expect(body).not.toContain("ALLOWED_APPLE_IDS");
    expect(body).not.toContain("AUTH_SECRET");
  });

  it("still 404s every path other than /authorize", async () => {
    // The gate belongs inside the /authorize branch only. Placed above the
    // pathname check it would answer 503 here too, and `defaultHandler` would
    // become a second reachable surface.
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      new Request(`${ORIGIN}/anything-else`),
      stubEnv(record, { allowList: undefined }),
    );

    expect(response.status).toBe(404);
  });
});

describe("the round trip: what the page stores is what the door serves", () => {
  // The case the whole plan exists for. Both halves could be internally
  // consistent and still disagree: a login page storing a shape the door
  // refuses would lock every person out on their very next call, and every
  // assertion above this line would stay green.

  /** The production door, built exactly as `src/index.ts` builds it. */
  const door = createMcpApiHandler();

  /** A `tools/list`. It calls no tool, so it awaits no principal and opens
   *  no socket — the response says only whether the door let it through. */
  function toolsList(props: unknown): Promise<Response> {
    const request = new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        host: DEPLOYED_HOSTNAME,
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
    return (async () => {
      const ctx = createExecutionContext();
      Object.defineProperty(ctx, "props", { value: props, enumerable: true });
      const response = await door.fetch(request, entryEnv(), ctx);
      await waitOnExecutionContext(ctx);
      return response;
    })();
  }

  it("serves the very props the login page recorded", async () => {
    const record = recorder();
    const response = await createLoginHandler(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );
    expect(response.status).toBe(302);

    // Not a hand-built look-alike. The exact object the handler handed the
    // provider, carried across to the door untouched.
    const stored = record.completed[0]?.props;
    const served = await toolsList(stored);

    expect(served.status, "the door refused a grant this server just minted").toBe(200);
    expect(served.headers.get("WWW-Authenticate")).toBeNull();
  });

  it("refuses the old single-key owner grant the same request would have carried", async () => {
    // GATE-05, from this side. The positive control above is what makes this
    // mean "the door stopped it" rather than "the request was malformed": the
    // two calls differ in nothing but the props.
    const served = await toolsList({ userId: "owner" });

    expect(served.status).toBe(401);
    expect(served.headers.get("WWW-Authenticate")).toMatch(/^Bearer/);
  });
});
