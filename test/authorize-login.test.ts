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
//   `createLoginHandler(proof).fetch` directly with a recording stub, through
//   the `handlerOver` helper below.
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
//
// ---------------------------------------------------------------------------
// **What the counter counts, and why that is the same thing as a socket
// count.** This matters enough to write down, because it is TRANSITIVE and a
// later reader who mistakes it for a direct measurement will trust it in a
// situation where one of its three links has moved.
//
// The counter counts calls to the INJECTED PROOF. It does not count calls to
// the socket opener, and this repository has no harness that does. The two are
// equivalent here only because three separate things hold at once:
//
//   1. The proof is the single call site in this flow that reaches the session
//      runner. Every other branch of the handler returns a response without
//      touching it.
//   2. No second session helper may exist under `src/auth/`. Convention 3
//      permits exactly one orchestrator, and the scan enforces that as a COUNT
//      in both directions — zero owners is as much a violation as two.
//   3. The socket specifier may be imported by exactly one file,
//      `src/mail/socket.ts`, whose opener takes no parameters. That too is a
//      count enforced in both directions.
//
// Break any one of those and a zero here stops meaning "no socket was opened"
// while still looking exactly as green. If one of them changes, this file's
// claim has to be re-derived rather than assumed.
// ---------------------------------------------------------------------------

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { LoginProof } from "../src/auth/login-handler";
import {
  FAILURE_FLOOR_MS,
  UNCONFIGURED_BODY,
  createLoginHandler,
  loginHandler,
} from "../src/auth/login-handler";
import {
  APPLE_THROTTLE_BODY,
  CREDENTIAL_FAILURE_BODY,
  SOURCE_REFUSAL_BODY,
} from "../src/auth/login-page";
import type { Env, LoginGateSecret } from "../src/env";
import {
  ImapAuthError,
  ImapConnectError,
  ImapThrottleError,
} from "../src/errors";
import { withMailSessionOver } from "../src/mail/service";
import { entryEnv } from "./fixtures/bound-secrets";
import { createFakeDuplex } from "./fixtures/fake-duplex";
import {
  GREETING,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  logoutExchange,
  taggedOk,
} from "./fixtures/icloud-bytes";
import { DEPLOYED_HOSTNAME, createMcpApiHandler } from "../src/mcp/api-handler";
import { USER_A_VECTOR } from "./fixtures/user-id-vectors";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  UNLISTED_APPLE_ID,
  loginProofCalls,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/**
 * The allow list this file's stubbed env binds.
 *
 * Named once here and built from the shared constant, following the habit the
 * three older authorize suites use for the bound secret: a value a test asserts
 * against is spelled in one place, with a comment saying where the real one
 * lives. The pool's own binding is in `vitest.config.ts` under
 * `ALLOWED_APPLE_IDS_SEED`, and it holds this same address.
 */
const STUB_ALLOW_LIST = JSON.stringify([LISTED_APPLE_ID]);

/**
 * An address the SEED does not hold and the STORE can be made to.
 *
 * The store half of the allow list was added on 2026-09-20 and this is the only
 * address in this file that exercises it. It is deliberately not
 * `UNLISTED_APPLE_ID`: that one must stay in neither source, because it is what
 * every refusal case in this file posts, and an address that became listed in
 * one of them would turn a whole block of refusals green for the wrong reason.
 */
const STORE_ONLY_APPLE_ID = "store-listed@example.invalid";

/**
 * The floor almost every case in this file injects, in milliseconds.
 *
 * Small on purpose. The production figure is three seconds, and every failing
 * path sleeps whatever is left of it — so a suite that took the default would
 * pay three seconds for each of roughly twenty refusals, for a property each
 * case demonstrates just as well in a tenth of that. The injectable floor
 * exists for exactly this and defaults to the exported constant, so production
 * behaviour is unchanged.
 *
 * Exactly ONE case declines this helper and builds the handler the way
 * production does, and that case is what stops the injection from hiding a
 * default that had quietly become a tenth of a second.
 */
const TEST_FLOOR_MS = 120;

/** The handler under test, with the floor injected small. */
function handlerOver(proof: LoginProof, floorMs: number = TEST_FLOOR_MS) {
  return createLoginHandler(proof, floorMs);
}

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
  // Optional here on purpose: the case that reads it asserts the value is
  // explicitly `false` rather than merely absent, and absent IS the library's
  // revoking default. Typing it as required would make "we forgot to pass it"
  // a compile error instead of the test failure it should be.
  revokeExistingGrants?: unknown;
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
 *
 * `rejectWith` builds the error to throw, so a case can pick the TYPE the
 * handler's mapping branches on. It is a factory rather than an instance
 * because a shared error object reused across cases would carry one stack into
 * all of them.
 */
function recorder(
  options: { refuse?: boolean; rejectWith?: () => Error } = {},
): Recorder {
  const calls: string[] = [];
  const completed: CompleteArgs[] = [];
  let proofCalls = 0;
  return {
    calls,
    completed,
    proof: async () => {
      proofCalls += 1;
      if (options.rejectWith) throw options.rejectWith();
      if (options.refuse) throw new Error("the injected proof refused");
    },
    proofCalls: () => proofCalls,
  };
}

/**
 * A KV stub: no real namespace, and nothing over the cap unless asked.
 *
 * `failures` is what the per-target hourly counter reads back, so one case can
 * drive the third layer without making five real attempts first.
 */
function quietKv(failures?: number) {
  return {
    async get() {
      return failures === undefined ? null : String(failures);
    },
    async put() {
      /* nothing here asserts on the counter. */
    },
  };
}

/**
 * A rate-limit binding stub that always answers the same way.
 *
 * Every case in this file that is not specifically about a limiter takes one of
 * these, and that is the point rather than a shortcut. The real bindings are
 * SQLite-backed counters the pool persists to disk with wall-clock-aligned
 * windows, and nothing resets them between tests or between runs — so a case
 * that touched a real one would spend a window that the next case, or the next
 * run of this suite, then has to live with. A stub touches nothing.
 *
 * `keys` records what the binding was asked about, for the cases that care
 * which key a layer is counting by.
 *
 * It takes `{ key }` and ignores nothing else, because `{ key }` is all the
 * shipped options type accepts.
 */
function limiter(success: boolean, keys?: string[]) {
  return {
    async limit({ key }: { key: string }) {
      keys?.push(key);
      return { success };
    },
  };
}

/**
 * An env whose provider records what the handler reached, and with what.
 *
 * `allowList` is the SEED, and it is a parameter rather than a constant because
 * the 503 cases need it absent, and because an absent binding is exactly the
 * shape a live config that never carried the key has.
 *
 * `stored` is the STORE, and it defaults to an empty one — the state the
 * namespace is in on the day this ships, and the state that makes a case about
 * something else say nothing about the store. `storeThrows` makes the read fail
 * instead, which is the one thing a real namespace cannot be asked to do.
 *
 * Both limiters default to letting the request through, so a case that says
 * nothing about them is a case about something else.
 */
function stubEnv(
  record: Recorder,
  options: {
    allowList?: string | undefined;
    stored?: string | null;
    storeThrows?: boolean;
    failures?: number;
    kv?: unknown;
    floodRefused?: boolean;
    burstRefused?: boolean;
    limiterKeys?: string[];
  } = {},
): Env & LoginGateSecret {
  return {
    OAUTH_KV: options.kv ?? quietKv(options.failures),
    LOGIN_IP_LIMITER: limiter(options.floodRefused !== true),
    LOGIN_ID_LIMITER: limiter(
      options.burstRefused !== true,
      options.limiterKeys,
    ),
    ALLOWED_APPLE_IDS_SEED:
      "allowList" in options ? options.allowList : STUB_ALLOW_LIST,
    ALLOW_LIST_KV: {
      async get(): Promise<string | null> {
        record.calls.push("readStoredAllowList");
        if (options.storeThrows === true) {
          throw new Error("the store is unreachable");
        }
        return options.stored ?? null;
      },
    },
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

// ---------------------------------------------------------------------------
// The pool-backed half of this file: the REAL provider, the REAL bindings the
// runner supplies from `wrangler.jsonc`, and the injected proof. Everything
// above drives the handler over stubs, which is what lets those cases observe
// ordering. These three helpers are what the cases that need a real binding or
// a real store use instead, and they are shared rather than repeated because
// two separate blocks below need the same registered client.
// ---------------------------------------------------------------------------

/** Drive the real provider over the injected proof, through its real fetch. */
async function callWorker(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Register a real client through the real registration endpoint. */
async function register(clientName: string, redirectUri: string): Promise<string> {
  const response = await callWorker(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: clientName,
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
  );

  expect(response.status).toBeLessThan(300);
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

/** An authorization query the real provider parses and re-validates. */
function authorizeQuery(
  clientId: string,
  redirectUri: string,
  state: string,
): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    state,
  }).toString();
}

/** A POST at the real Worker, from a named source connection. */
function postFrom(source: string, appleId: string, query: string): Request {
  return new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": source,
    },
    body: new URLSearchParams({
      apple_id: appleId,
      app_password: FAKE_APP_PASSWORD,
      oauth_request: query,
    }).toString(),
  });
}

/**
 * A limiter key this invocation owns and nothing else in the repository uses.
 *
 * Not an address shape, and it does not need to be: the binding keys on the
 * string it is handed and never parses it. Minting a fresh one per case is what
 * keeps two cases in this file, and this file and its neighbours, from spending
 * one another's windows — see the block comment on the GATE-04 cases below for
 * why that is done this way rather than by resetting the counters.
 */
function freshSource(): string {
  return `test-source-${crypto.randomUUID()}`;
}

describe("the method dispatch", () => {
  // Titled so `-t "method"` matches. 11-VALIDATION.md ships that exact command
  // for LOGIN-01, and a name filter that matches nothing passes SILENTLY —
  // which would leave the row looking covered while measuring nothing.

  it("renders the form on a GET, asking for an Apple ID and a password", async () => {
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
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
    const handler = handlerOver(record.proof);

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
    const response = await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(record.proofCalls()).toBe(1);
    expect(response.status).toBe(401);
    expect(response.headers.get("location")).toBeNull();
    expect(record.calls).not.toContain("completeAuthorization");
  });
});

describe("two allow-list sources, asked in order", () => {
  // GATE-01 and GATE-03, at the login page. The allow list split on 2026-09-20
  // into a synchronous `vars` SEED holding the owner and a KV STORE holding
  // everybody else. This block is the whole behavioural claim about that split.
  //
  // **Every case reads the socket counter and not only the status**, because a
  // status cannot tell "refused before the socket" from "refused after the
  // login failed at Apple". Criterion 2 is an assertion about socket count.
  //
  // **The store read is recorded as a call**, which is what lets the ordering
  // cases below assert a short-circuit rather than infer one.

  it("signs in an address the seed names, without reading the store", async () => {
    // The owner's own sign-in. The seed is asked first and short-circuits, so
    // this costs no store round trip — the cost argument written at the check
    // in source, asserted here so it cannot quietly stop being true.
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );

    expect(response.status).toBe(302);
    expect(record.proofCalls()).toBe(1);
    expect(
      record.calls,
      "the seed already said yes and the store was read anyway",
    ).not.toContain("readStoredAllowList");
  });

  it("signs in an address only the store names, and reaches Apple once", async () => {
    // The case the store exists for: a family member the seed does not and
    // will not name. Without it the whole namespace is unreachable code.
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
      post(STORE_ONLY_APPLE_ID),
      stubEnv(record, { stored: JSON.stringify([STORE_ONLY_APPLE_ID]) }),
    );

    expect(response.status).toBe(302);
    expect(record.proofCalls(), "a store-listed address did not reach Apple")
      .toBe(1);
    expect(record.calls).toContain("readStoredAllowList");
    expect(record.calls).toContain("completeAuthorization");
  });

  it("opens nothing for an address in neither source", async () => {
    // One store read is spent — the seed said no, so the store had to be asked
    // — and then nothing. No socket, no ceremony. What bounds that round trip
    // is layer 1, the source limiter, far above this point.
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
      post(STORE_ONLY_APPLE_ID),
      stubEnv(record, { stored: JSON.stringify(["somebody@example.invalid"]) }),
    );

    expect(response.status).toBe(401);
    expect(record.proofCalls(), "an unlisted address reached Apple").toBe(0);
    expect(record.calls).toContain("readStoredAllowList");
    expect(record.calls).not.toContain("completeAuthorization");
  });

  it("refuses the store-listed address when the store throws, and still signs the seed-listed one in", async () => {
    // **THE FAIL-CLOSED PAIR, AND BOTH HALVES BELONG IN ONE CASE.** The refusal
    // alone is satisfied by a server that refuses everybody, which is exactly
    // what a store outage must NOT cause — the owner has to stay able to reach
    // his own server. The sign-in alone says nothing about the store at all.
    const refusedRecord = recorder();
    const refused = await handlerOver(refusedRecord.proof).fetch(
      post(STORE_ONLY_APPLE_ID),
      stubEnv(refusedRecord, { storeThrows: true }),
    );

    expect(refused.status).toBe(401);
    expect(
      refusedRecord.proofCalls(),
      "a store that threw admitted somebody anyway",
    ).toBe(0);

    const servedRecord = recorder();
    const served = await handlerOver(servedRecord.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(servedRecord, { storeThrows: true }),
    );

    expect(
      served.status,
      "a store outage locked out an address the seed names",
    ).toBe(302);
    expect(servedRecord.proofCalls()).toBe(1);
  });

  it("means nobody for a stored value that cannot be read", async () => {
    // The same parse rule the seed goes through, reached through the store. A
    // value with two readings resolves closed here exactly as it does there.
    for (const bad of ["not json", '"*"', "[]", '["*", "someone@x.invalid"]']) {
      const record = recorder();
      const response = await handlerOver(record.proof).fetch(
        post(STORE_ONLY_APPLE_ID),
        stubEnv(record, { stored: bad }),
      );

      expect(
        response.status,
        `a stored value of ${JSON.stringify(bad)} admitted somebody`,
      ).toBe(401);
      expect(record.proofCalls()).toBe(0);
    }
  });

  it("answers 503 on both verbs when the seed is unusable, whatever the store holds", async () => {
    // The gate above the method dispatch reads the SEED ONLY. A deployment
    // whose seed is unusable cannot serve its own owner, so it is unconfigured
    // however full the store is — and a store read on every GET would spend a
    // round trip rendering a page.
    for (const request of [get(), post(STORE_ONLY_APPLE_ID)]) {
      const record = recorder();
      const response = await handlerOver(record.proof).fetch(
        request,
        stubEnv(record, {
          allowList: undefined,
          stored: JSON.stringify([STORE_ONLY_APPLE_ID, LISTED_APPLE_ID, "*"]),
        }),
      );

      expect(response.status, `${request.method} did not answer 503`).toBe(503);
      expect(record.proofCalls()).toBe(0);
      // Above everything: the provider was never consulted, and neither was
      // the store.
      expect(record.calls).toHaveLength(0);
    }
  });
});

describe("the props the ceremony is completed with", () => {
  // Titled so `-t "props"` matches — 11-VALIDATION.md's LOGIN-06 command.

  it("holds exactly the version, the address and the password", async () => {
    const record = recorder();
    await handlerOver(record.proof).fetch(
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
    // The form that was TYPED, unchanged. This line used to assert the
    // opposite — the separators stripped — and the reversal is LOGIN-04's
    // amendment: spike S5 was declined on 2026-09-20 and the handler stopped
    // transforming the submitted value rather than guessing at a format Apple
    // has never published.
    //
    // The claim underneath is unchanged and is the one that matters: the stored
    // value is the value that went to Apple, so the grant and the wire cannot
    // disagree from the moment it is written. The block titled "the dashes a
    // person may or may not type" is where that is the subject; this line is
    // here so this case cannot go stale against it.
    expect(props.appPassword).toBe(FAKE_APP_PASSWORD);
  });

  it("names the user by a derived id, not by the address and not by owner", async () => {
    const record = recorder();
    await handlerOver(record.proof).fetch(
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
    await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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

    const a = await handlerOver(unlisted.proof).fetch(
      post(UNLISTED_APPLE_ID),
      stubEnv(unlisted),
    );
    const b = await handlerOver(refused.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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
    const body = await handlerOver(record.proof)
      .fetch(get(), stubEnv(record, { allowList: undefined }))
      .then((response) => response.text());

    expect(body).not.toContain("ALLOWED_APPLE_IDS_SEED");
    expect(body).not.toContain("ALLOW_LIST_KV");
    expect(body).not.toContain("AUTH_SECRET");
  });

  it("still 404s every path other than /authorize", async () => {
    // The gate belongs inside the /authorize branch only. Placed above the
    // pathname check it would answer 503 here too, and `defaultHandler` would
    // become a second reachable surface.
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
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
    const response = await handlerOver(record.proof).fetch(
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

  it("does not revoke an earlier grant when a second sign-in arrives", async () => {
    // Measured, 2026-09-21, hours after the phase shipped. The client submits
    // this form TWICE about 1.4s apart, and both submissions succeed — each
    // completed in ~1s, under the three-second floor every failure is held to.
    // Under the library's default the second grant's creation revoked the
    // first, the client held a token for the one that lost, and the eventually
    // consistent store served it for about sixty seconds before the delete
    // caught up: 401, re-discovery, re-registration, and round again.
    //
    // The library's note on that default says it prevents "infinite re-auth
    // loops". Here it caused one. LIFE-03 promises one Apple ID may be signed
    // in from several Claude apps at once, so concurrent grants are the shape
    // this project wants; this asserts we ask for them rather than inherit the
    // opposite. Restoring the default reinstates the lockout.
    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(record),
    );
    expect(response.status).toBe(302);

    // Explicitly false, not merely absent — absent IS the revoking default.
    expect(record.completed[0]?.revokeExistingGrants).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// LOGIN-03 and LOGIN-04. The refusal that opens nothing, and the one
// canonicalisation — proved on the wire rather than in a return value.
// ---------------------------------------------------------------------------

/**
 * Bounds that keep a scripted conversation from waiting on a real timeout.
 *
 * The same four values `test/service.test.ts` uses, for the same reason: a fake
 * duplex answers instantly, so the production read timeout would be nothing but
 * dead wall-clock in the suite.
 */
const FAST_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 200,
};

/** The observed shape, as a person is most likely to paste it. */
const DASHED_PASSWORD = "dddd-eeee-ffff-gggg";

/**
 * The same characters, typed without the separators Apple showed.
 *
 * Deliberately NOT described as "the same password" any more. Whether iCloud
 * treats these two as one credential is unmeasured — spike S5 was declined —
 * and this server no longer takes a position on it. They are two different byte
 * strings and they reach Apple as two different byte strings.
 */
const DASHLESS_PASSWORD = "ddddeeeeffffgggg";

/**
 * One sign-in driven through the REAL session runner over a scripted duplex.
 *
 * The proof handed to the handler is the production one in every respect but
 * the socket: it calls `withMailSessionOver`, so the command line this reads
 * back is built by the code that builds the real one. Asserting a helper's
 * return value instead would prove what some function answered, not what Apple
 * is actually told — and "what Apple is actually told" is the entire claim now
 * that the handler transforms nothing on the way there.
 *
 * Both passwords driven through here are declared in this file and are plainly
 * fake, so a failed assertion that prints the line discloses nothing. That is
 * the one thing that makes a line assertion safe here and unsafe in
 * `test/service.test.ts`, whose conversations carry the pool's ambient
 * credential and are therefore asserted by COUNT.
 */
async function loginLineFor(typed: string): Promise<string | undefined> {
  const duplex = createFakeDuplex([
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", POST_AUTH_CAPABILITY),
    logoutExchange("a4"),
  ]);
  const record = recorder();
  const overTheWire: LoginProof = (principal, gate) =>
    withMailSessionOver(
      duplex,
      principal,
      gate,
      null,
      null,
      async () => {},
      FAST_BOUNDS,
    );

  const response = await handlerOver(overTheWire).fetch(
    post(LISTED_APPLE_ID, typed),
    stubEnv(record),
  );
  expect(response.status).toBe(302);

  return duplex.writtenLines().find((line) => line.includes(" LOGIN "));
}

describe("the app-password shape check, and what it deliberately does not check", () => {
  // Titled so `-t "shape"` matches. 11-VALIDATION.md ships that exact command
  // for LOGIN-03, and a name filter that matches nothing passes SILENTLY —
  // which would leave the row looking covered while measuring nothing.
  //
  // The check refuses only what cannot be an app-specific password under ANY
  // grammar. Apple documents no format; the four-dashed-groups shape is one
  // observed sample, the owner's own. So the refused table below holds three
  // classes and no fourth, and the accepted table is what stops a later session
  // tightening this into the grammar it happens to remember.

  const REFUSED: ReadonlyArray<readonly [string, string]> = [
    ["empty", ""],
    ["nothing but white space", "   "],
    ["carrying a space in the middle", "abcd efgh ijkl mnop"],
    ["carrying a tab in the middle", "abcd-efgh\tijkl-mnop"],
    ["far too short to be any credential", "abcd"],
    ["far longer than any credential", "z".repeat(96)],
  ];

  it.each(REFUSED)(
    "refuses a password that is %s, with nothing opened to Apple",
    async (_label, password) => {
      const record = recorder();
      const response = await handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID, password),
        stubEnv(record),
      );

      // The assertion that carries the requirement. A row asserting only the
      // status would pass against a handler that refused AFTER opening a
      // socket — both answers are the identical 401.
      expect(
        record.proofCalls(),
        "a clearly-wrong password reached Apple",
      ).toBe(0);
      expect(response.status).toBe(401);
      expect(record.calls).not.toContain("completeAuthorization");
    },
  );

  const ACCEPTED: ReadonlyArray<readonly [string, string]> = [
    ["the observed shape, with dashes", "abcd-efgh-ijkl-mnop"],
    ["the observed shape, without them", "abcdefghijklmnop"],
    ["a grammar nobody here has ever observed", "Xy7Q-9mK2-Ws4R-pL8Z"],
    ["a longer value still inside the band", "abcdefghijklmnopqrstuvwx"],
  ];

  it.each(ACCEPTED)(
    "accepts %s rather than guessing at Apple's grammar",
    async (_label, password) => {
      // The third row is the one this table exists for. It carries digits and
      // upper case, which the single observed sample does not, and a strict
      // rule would refuse it behind a message that deliberately will not say
      // why — locking out a legitimate person with no way to learn the reason.
      const record = recorder();
      const response = await handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID, password),
        stubEnv(record),
      );

      expect(record.proofCalls()).toBe(1);
      expect(response.status).toBe(302);
    },
  );
});

describe("the dashes a person may or may not type", () => {
  // Titled so `-t "dashes"` matches — 11-VALIDATION.md's LOGIN-04 command.
  //
  // This block used to assert the opposite of what it asserts now, and the
  // reversal is the whole of LOGIN-04's amendment. It used to hold that both
  // forms reach Apple as the SAME bytes, because the handler stripped the
  // separators on the way out. That behaviour was gated on spike S5 — a manual
  // check of whether iCloud accepts the dashless form — and S5 was NOT RUN. The
  // owner declined it on 2026-09-20 after finding the planned procedure could
  // not work: it said to re-enter the password in Mail.app, which signs in
  // through the Mac's system iCloud account and never sees an app-specific
  // password at all.
  //
  // With no measurement, the transformation was removed rather than guessed at.
  // Apple publishes no format for these values, so a server that edits one is
  // inventing a grammar on the person's behalf. What ships is pass-through, and
  // what these two cases pin is that pass-through is real in BOTH directions:
  // nothing is stripped, and nothing is inserted.

  it("reach Apple as the bytes the person typed, on the wire", async () => {
    // Titled so `-t "wire"` matches as well, and the word is literal: these are
    // the recorded outbound command lines, not values a helper handed back.
    const dashed = await loginLineFor(DASHED_PASSWORD);
    const dashless = await loginLineFor(DASHLESS_PASSWORD);

    // Each form arrives as itself. Asserting the full command line rather than
    // a substring is what makes this a byte claim.
    expect(dashed).toBe(`a2 LOGIN "${LISTED_APPLE_ID}" "${DASHED_PASSWORD}"`);
    expect(dashless).toBe(
      `a2 LOGIN "${LISTED_APPLE_ID}" "${DASHLESS_PASSWORD}"`,
    );

    // And they DIFFER. Without this row the pair above would still pass against
    // a handler that stripped separators, on the day someone made the two
    // constants equal — which is exactly how a pass-through claim rots back
    // into a transformation nobody noticed.
    expect(dashed).not.toBe(dashless);
  });

  it("are written into the grant unchanged, so the grant and the wire agree", async () => {
    // The other half of LOGIN-04. The wire value and the props value are now
    // the same EXPRESSION in the handler rather than two derivations, so this
    // case is pinning that nothing re-derives one of them on the way past.
    //
    // A grant holding a different form from the one Apple was told would work
    // on the day it was written and fail on every request afterwards, because
    // every later request replays the stored bytes and never the typed ones.
    for (const password of [DASHED_PASSWORD, DASHLESS_PASSWORD]) {
      const record = recorder();
      await handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID, password),
        stubEnv(record),
      );

      const props = record.completed[0]?.props as Record<string, unknown>;
      expect(props.appPassword).toBe(password);
    }
  });
});

// ---------------------------------------------------------------------------
// LOGIN-05. Every credential-path failure takes the same wall-clock and says
// the same thing, apart from the one message that can only be built after Apple
// has already answered.
// ---------------------------------------------------------------------------

/** How long one call to the handler took, wall-clock, from outside it. */
async function timed(call: () => Promise<Response>): Promise<{
  response: Response;
  elapsed: number;
}> {
  const started = Date.now();
  const response = await call();
  return { response, elapsed: Date.now() - started };
}

describe("every failed sign-in answers with the same body", () => {
  // Titled so `-t "same body"` matches — 11-VALIDATION.md's LOGIN-05 command.

  it("gives an unlisted address and a wrong password the same body and the same status", async () => {
    // The case criterion 3 lives or dies on. One of these two answers happened
    // without Apple ever being contacted and the other happened after Apple
    // turned the password down, and a reader must not be able to tell which.
    const unlisted = recorder();
    const wrong = recorder({ refuse: true });

    const a = await handlerOver(unlisted.proof).fetch(
      post(UNLISTED_APPLE_ID),
      stubEnv(unlisted),
    );
    const b = await handlerOver(wrong.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(wrong),
    );

    expect(unlisted.proofCalls()).toBe(0);
    expect(wrong.proofCalls()).toBe(1);
    expect(a.status).toBe(401);
    expect(b.status).toBe(a.status);

    const bodyA = await a.text();
    expect(bodyA).toBe(await b.text());

    // Against the exported constant, never a retyped sentence: a copy of the
    // wording in this file could drift from the page's and leave the equality
    // above passing while both answers said something nobody approved.
    for (const line of CREDENTIAL_FAILURE_BODY) {
      expect(bodyA).toContain(line);
    }
  });

  it("gives a badly-shaped password the same body as a wrong one", async () => {
    // The member the owner most recently declined to split out. The UI
    // researcher argued a shape failure is a pure function of what the reader
    // typed and therefore leaks nothing; the owner declined, to remove the last
    // place a credential-path message varies at all.
    const shape = recorder();
    const wrong = recorder({ refuse: true });

    const a = await handlerOver(shape.proof).fetch(
      post(LISTED_APPLE_ID, "abcd"),
      stubEnv(shape),
    );
    const b = await handlerOver(wrong.proof).fetch(
      post(LISTED_APPLE_ID),
      stubEnv(wrong),
    );

    expect(shape.proofCalls()).toBe(0);
    expect(a.status).toBe(b.status);
    expect(await a.text()).toBe(await b.text());
  });
});

describe("the time floor, on every failing path", () => {
  // Titled so `-t "floor"` matches — 11-VALIDATION.md's second LOGIN-05
  // command. A floor applied only after the allow-list check would let a
  // stopwatch sort listed addresses from unlisted ones, which is the exact leak
  // it exists to close — so every path gets its own row rather than one row
  // standing in for the rest.

  it("holds a shape refusal, which opened nothing at all", async () => {
    // The path with no I/O between the handler's entry and the refusal. In this
    // runtime the clock does not advance during code execution, so the elapsed
    // time reads as zero here and the whole floor is slept. That is the correct
    // answer for a path that did no work.
    const record = recorder();
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID, "abcd"),
        stubEnv(record),
      ),
    );

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it("holds an address that is not on the list", async () => {
    const record = recorder();
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post(UNLISTED_APPLE_ID),
        stubEnv(record),
      ),
    );

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it("holds an address this server cannot read at all", async () => {
    const record = recorder();
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post("no-at-sign-at-all"),
        stubEnv(record),
      ),
    );

    expect(response.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it("holds a password Apple turned down", async () => {
    const record = recorder({ rejectWith: () => new ImapAuthError() });
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID),
        stubEnv(record),
      ),
    );

    expect(record.proofCalls()).toBe(1);
    expect(response.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it("holds an Apple that is refusing on availability grounds", async () => {
    const record = recorder({ rejectWith: () => new ImapThrottleError() });
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID),
        stubEnv(record),
      ),
    );

    expect(response.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it("holds the source-connection refusal too, which costs wall-clock knowingly", async () => {
    // The row most easily left out, because it is the one refusal with a status
    // of its own. Skipping it would be the leak: a 429 that returned instantly
    // while every other answer took the floor is a signal in itself.
    const record = recorder();
    const { response, elapsed } = await timed(() =>
      handlerOver(record.proof).fetch(
        post(LISTED_APPLE_ID),
        stubEnv(record, { floodRefused: true }),
      ),
    );

    expect(response.status).toBe(429);
    expect(record.proofCalls()).toBe(0);
    expect(elapsed).toBeGreaterThanOrEqual(TEST_FLOOR_MS);
  });

  it(
    "defaults to the production floor when nothing injects one",
    async () => {
      // The case that proves the default is the real figure rather than the
      // injected one. Without it every row above would hold against a handler
      // whose production default had quietly become a tenth of a second.
      expect(FAILURE_FLOOR_MS).toBe(3000);

      // The one call in this file that does NOT go through `handlerOver`. It
      // builds the handler the way `src/auth/oauth.ts` builds it — with no
      // second argument at all — which is the only way the default can be the
      // thing under test rather than the thing being bypassed.
      const record = recorder();
      const { response, elapsed } = await timed(() =>
        createLoginHandler(record.proof).fetch(
          post(UNLISTED_APPLE_ID),
          stubEnv(record),
        ),
      );

      expect(response.status).toBe(401);
      expect(elapsed).toBeGreaterThanOrEqual(FAILURE_FLOOR_MS);
    },
    10_000,
  );
});

describe("what the page says depends on the error's type and on nothing else", () => {
  it("renders the throttle message when Apple refused on availability grounds", async () => {
    const record = recorder({ rejectWith: () => new ImapThrottleError() });
    const response = await handlerOver(record.proof).fetch(post(LISTED_APPLE_ID), stubEnv(record));
    const body = await response.text();

    expect(response.status).toBe(401);
    for (const line of APPLE_THROTTLE_BODY) {
      expect(body).toContain(line);
    }
    // And not the other one. A page carrying both would be a page that told a
    // reader to check a password AND to wait, which is two instructions for one
    // event.
    expect(body).not.toContain(CREDENTIAL_FAILURE_BODY[0]);
  });

  it("renders the throttle message for a connect or read failure as well", async () => {
    // The row research left open and this plan decided. The throttle wording is
    // literally true of a connect failure; the single failure string is false
    // of it, and would send a family member hunting for a typo that is not
    // there. It can only fire after the allow-list check passed, so it leaks
    // nothing the throttle message did not already leak.
    const record = recorder({ rejectWith: () => new ImapConnectError() });
    const body = await handlerOver(record.proof)
      .fetch(post(LISTED_APPLE_ID), stubEnv(record))
      .then((response) => response.text());

    for (const line of APPLE_THROTTLE_BODY) {
      expect(body).toContain(line);
    }
  });

  it("renders the single failure string when Apple turned the password down", async () => {
    const record = recorder({ rejectWith: () => new ImapAuthError() });
    const body = await handlerOver(record.proof)
      .fetch(post(LISTED_APPLE_ID), stubEnv(record))
      .then((response) => response.text());

    for (const line of CREDENTIAL_FAILURE_BODY) {
      expect(body).toContain(line);
    }
    expect(body).not.toContain(APPLE_THROTTLE_BODY[0]);
  });

  it("renders the single failure string for an error it has never seen", async () => {
    // Failing toward the SILENT answer, deliberately. No live refusal has ever
    // been observed from iCloud, so every code the classifier matches comes
    // from the specification rather than from evidence; an unfamiliar error
    // must not be promoted into the one message that discloses list membership.
    const record = recorder({ rejectWith: () => new Error("something else") });
    const body = await handlerOver(record.proof)
      .fetch(post(LISTED_APPLE_ID), stubEnv(record))
      .then((response) => response.text());

    for (const line of CREDENTIAL_FAILURE_BODY) {
      expect(body).toContain(line);
    }
    expect(body).not.toContain(APPLE_THROTTLE_BODY[0]);
  });
});

// ---------------------------------------------------------------------------
// Criterion 2. The socket count, the counter that proves it, the control that
// proves the counter can move, and the sweep that measures the "only" in
// "stored only in the grant's encrypted props".
// ---------------------------------------------------------------------------

describe("zero sockets to Apple, and a counter that has been shown to move", () => {
  // Titled so `-t "zero sockets"` matches — 11-VALIDATION.md's GATE-02 command.

  /**
   * Drive one request through a freshly-zeroed counter.
   *
   * The two assertions before the call are the non-vacuity guard, in the shape
   * the source-text block in `test/service.test.ts` uses on itself: prove the
   * instrument is the one under test and prove it is at rest, so a zero
   * afterwards is a READING rather than a default. A new recorder per call is
   * also the reset — the reason `test/door.test.ts` gives for its own is that a
   * passing first case must not mask a failing second.
   */
  async function countFor(
    request: Request,
    options: { allowList?: string | undefined } = {},
  ): Promise<{ record: Recorder; response: Response }> {
    const record = recorder();
    const handler = handlerOver(record.proof);

    // Not the production export. That one carries `proveWithApple`, which opens
    // a real socket to iCloud — so a case that reached it would both violate
    // D-09 and count nothing.
    expect(handler).not.toBe(loginHandler);
    expect(record.proofCalls()).toBe(0);

    const response = await handler.fetch(request, stubEnv(record, options));
    return { record, response };
  }

  it("opens nothing for a password that cannot be an app-specific one", async () => {
    const { record, response } = await countFor(post(LISTED_APPLE_ID, "abcd"));

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
    expect(record.calls).not.toContain("completeAuthorization");
  });

  it("opens nothing for an address that is not on the list", async () => {
    const { record, response } = await countFor(post(UNLISTED_APPLE_ID));

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
  });

  it("opens nothing for an address this server cannot read", async () => {
    const { record, response } = await countFor(post("no-at-sign-at-all"));

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(401);
  });

  it("opens nothing for a deployment whose allow list is not configured", async () => {
    const { record, response } = await countFor(post(LISTED_APPLE_ID), {
      allowList: undefined,
    });

    expect(record.proofCalls()).toBe(0);
    expect(response.status).toBe(503);
    // The gate is above everything: the provider was never consulted either.
    expect(record.calls).toHaveLength(0);
  });

  it("records exactly one for a good sign-in (the control)", async () => {
    // WITHOUT THIS CASE EVERY ZERO ABOVE IS UNFALSIFIABLE. A counter that can
    // never increment looks exactly like a counter that stayed at zero, and
    // four green rows would say nothing at all about where the refusals happen.
    // Do not delete this as redundant with the sign-in cases higher up: those
    // prove the ceremony completes, this one proves the INSTRUMENT the four
    // rows above are read from is capable of moving.
    const { record, response } = await countFor(post(LISTED_APPLE_ID));

    expect(response.status).toBe(302);
    expect(record.proofCalls()).toBe(1);
  });
});

describe("a credential arriving in a query string authenticates nothing", () => {
  // Titled so `-t "query string"` matches — 11-VALIDATION.md's D3 command.

  it("is answered with the form, and the ceremony is not completed", async () => {
    // D3 is the reason invocation logs are allowed to stay on: they record no
    // bodies, and a credential in a URL is the one shape that would reach a
    // retained log. The form is POST-only, so this is what a GET carrying the
    // two field names in its query does.
    //
    // What this case asserts is that nothing was AUTHENTICATED, not that
    // nothing was echoed. The raw query is round-tripped into the hidden
    // `oauth_request` field on purpose, so the POST re-runs the provider's own
    // client, redirect-URI, response-type and PKCE validation against it — a
    // value a requester put in their own URL therefore comes back on their own
    // page, which is the same posture the 404 body already takes with the
    // caller's own Host header. The credential-reflection rule LOGIN-07 states
    // is about values the FORM submitted, and both of those fields still carry
    // no value attribute below.
    const query = new URLSearchParams({
      response_type: "code",
      client_id: "stub-client",
      apple_id: LISTED_APPLE_ID,
      app_password: FAKE_APP_PASSWORD,
    }).toString();

    const record = recorder();
    const response = await handlerOver(record.proof).fetch(
      new Request(`${ORIGIN}/authorize?${query}`),
      stubEnv(record),
    );
    const body = await response.text();

    expect(record.proofCalls(), "a query string reached Apple").toBe(0);
    expect(record.calls).not.toContain("completeAuthorization");
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();

    // The rendered form, with both boxes empty.
    expect(body).toContain(`name="apple_id"`);
    expect(body).toContain(`name="app_password"`);
    expect(body).not.toMatch(/name="apple_id"[^>]*value=/);
    expect(body).not.toMatch(/name="app_password"[^>]*value=/);
  });
});

describe("after a sign-in the password is in the grant and nowhere else", () => {
  // Titled so `-t "nowhere else"` matches — 11-VALIDATION.md's LOGIN-06 row,
  // and the one case here whose whole job is to find something that should not
  // be there.
  //
  // Criterion 1 says the credentials are stored ONLY in the grant's encrypted
  // props. The props SHAPE is asserted higher up in this file; "only" is the
  // security half of that claim and nothing measured it until now. An audit
  // cell in a planning document cannot go red.

  /** A password no other test, fixture or binding in this repository holds. */
  const SWEEP_TYPED = "zqxjk7-vbnm42-plok98";

  /** What the canonicaliser makes of it, which is what actually gets stored. */
  const SWEEP_CANONICAL = "zqxjk7vbnm42plok98";

  it("holds it in no key of any store this Worker binds", async () => {
    // The non-empty guard, first and for the reason `test/fixtures/bound-secrets.ts`
    // already gives about its own: `not.toContain("")` is true of every string,
    // so a containment sweep run against an empty needle passes while proving
    // nothing at all.
    expect(SWEEP_TYPED.length).toBeGreaterThan(0);
    expect(SWEEP_CANONICAL.length).toBeGreaterThan(0);

    const redirectUri = "https://claude.ai/sweep-callback";
    const clientId = await register("Sweep Client", redirectUri);
    const query = authorizeQuery(clientId, redirectUri, "sweep");

    const signedIn = await callWorker(
      new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          apple_id: LISTED_APPLE_ID,
          app_password: SWEEP_TYPED,
          oauth_request: query,
        }).toString(),
      }),
    );

    // The sweep means nothing unless a sign-in really happened: a grant that
    // was never written cannot have leaked into anything.
    expect(signedIn.status).toBe(302);

    const env = entryEnv();
    const stores: ReadonlyArray<readonly [string, KVNamespace]> = [
      ["OAUTH_KV", env.OAUTH_KV],
      ["CONFIRM_KV", env.CONFIRM_KV],
      ["DAV_CACHE", env.DAV_CACHE],
    ];

    let swept = 0;
    for (const [name, store] of stores) {
      const listed = await store.list();
      // A partial page would make this a sweep of the first thousand keys
      // wearing the name of a sweep of all of them.
      expect(listed.list_complete, `${name} listing was truncated`).toBe(true);

      for (const key of listed.keys) {
        swept += 1;
        // KEYS are enumerated rather than a key SHAPE being asserted. A shape
        // assertion pins today's format; the claim is that the value is absent
        // from all of them, whatever they are called.
        const value = await store.get(key.name);
        expect(
          value ?? "",
          `${name}/${key.name} holds the submitted password`,
        ).not.toContain(SWEEP_CANONICAL);
        expect(value ?? "").not.toContain(SWEEP_TYPED);
      }
    }

    // A sweep over nothing is a sweep that proves nothing. The grant this case
    // just minted is itself at least one key.
    expect(swept, "the sweep enumerated no keys at all").toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// GATE-04. The three layers that stand between a stranger and Apple.
//
// The first two drive the REAL rate-limit bindings the runner supplies from
// `wrangler.jsonc`. The third drives a counting store, because the hourly cap
// and the per-target binding cannot both be exercised by the same six
// requests: the binding refuses the fourth attempt in a minute, and six real
// attempts inside an hour would never get past it.
//
// ---------------------------------------------------------------------------
// HOW THE COUNTERS ARE KEPT FROM BLEEDING, AND WHY IT IS NOT `reset()`.
//
// The hazard is real and it is the reason this paragraph exists. The runner's
// limiter is a counter with wall-clock-aligned windows, and nothing clears it
// between tests — so two cases sharing a key spend one another's window, and a
// suite that passes in isolation fails in file order. If that ever appears
// here, the cause is a shared key and not the handler.
//
// Every case below therefore owns its key outright. The two that drive a real
// binding mint a fresh connecting-address value per invocation, which is the
// habit `test/authorize-redirect-allowlist.test.ts` already follows for the
// same reason, and the second one also uses the OTHER address the pool's allow
// list holds, so its per-target key is one nothing else in this repository
// touches. The third case drives a store stub, so it has no shared counter at
// all.
//
// `reset()` was the obvious alternative and it was MEASURED and declined, on
// two findings. First, it is not needed: a fixed limiter key was driven seven
// times in a throwaway case and answered with exactly five successes, and the
// same case one second later answered with exactly five again — so the
// counters do not survive a run, and there is nothing between runs to clear.
// Second, it would be actively unsafe here: `reset()` deletes all data from
// ALL bindings, and this runner persists the KV namespaces to disk while the
// limiter counters live only in memory. The one thing it would really have
// cleared is the store that the sweep case above, and whatever sibling file is
// running beside this one, are using at that moment.
// ---------------------------------------------------------------------------

/**
 * The OTHER address the pool's allow list holds. See `vitest.config.ts`.
 *
 * Taken from the user-id vectors rather than retyped, because that file is
 * where the address and its derived id are held to each other, and a second
 * spelling here is a second thing to keep in step. The per-target case below
 * uses it so the key it spends belongs to no other case in this file.
 */
const SECOND_LISTED_APPLE_ID = USER_A_VECTOR.input;

describe("the ip limiter, the first layer and the only one with its own status", () => {
  // Titled so `-t "ip limiter"` matches — 11-VALIDATION.md's first GATE-04 row.

  it(
    "refuses a sixth attempt from one source, above everything it protects",
    async () => {
      const redirectUri = "https://claude.ai/flood-callback";
      const clientId = await register("Flood Client", redirectUri);
      const query = authorizeQuery(clientId, redirectUri, "flood");

      // The control, and it comes FIRST because it has to come from a source
      // that has spent nothing. Without it the refusal below would be
      // satisfied by a request that was going to fail anyway — a bad client, a
      // wrong address, a page that never works. This proves the very same
      // POST, from a source with budget left, signs in.
      const control = await callWorker(
        postFrom(freshSource(), LISTED_APPLE_ID, query),
      );
      expect(control.status, "the control sign-in did not work").toBe(302);

      const source = freshSource();

      // Five priming requests whose authorization query cannot be parsed. Each
      // is answered 400 by the provider — and each still spends a tick of this
      // key, which is itself the ordering claim: the limiter sits ABOVE the
      // parse, so a flood carrying nothing valid at all is still braked.
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        const primed = await callWorker(
          postFrom(source, LISTED_APPLE_ID, "not-a-valid-authorization-request"),
        );
        expect(primed.status, `priming attempt ${attempt} was not a 400`).toBe(
          400,
        );
      }

      // The sixth carries the SAME valid query the control just signed in
      // with, from the same registered client, for an address that is on the
      // list. The only thing different about it is the source's spent budget.
      const before = loginProofCalls();
      const refused = await callWorker(
        postFrom(source, LISTED_APPLE_ID, query),
      );

      expect(refused.status).toBe(429);
      expect(await refused.text()).toBe(SOURCE_REFUSAL_BODY);
      expect(refused.headers.get("retry-after")).toBe("60");
      // Never reached the allow-list check, which is what "above everything it
      // protects" means: the proof is the instrument, and it did not move.
      expect(loginProofCalls(), "the sixth attempt reached Apple").toBe(before);
    },
    20_000,
  );
});

describe("the per-id layer, which answers as a wrong password and never as a 429", () => {
  // Titled so `-t "per-id"` matches — 11-VALIDATION.md's second GATE-04 row.

  it(
    "refuses a fourth attempt against one address with the single failure string",
    async () => {
      const redirectUri = "https://claude.ai/per-id-callback";
      const clientId = await register("Per Id Client", redirectUri);
      const query = authorizeQuery(clientId, redirectUri, "per-id");

      // One source for the whole case, with budget for all four attempts: the
      // source limiter allows five a minute and this makes four, so whatever
      // refuses the last one, it is not that layer.
      const source = freshSource();

      for (let attempt = 1; attempt <= 3; attempt += 1) {
        const signedIn = await callWorker(
          postFrom(source, SECOND_LISTED_APPLE_ID, query),
        );
        expect(signedIn.status, `attempt ${attempt} did not sign in`).toBe(302);
      }

      const before = loginProofCalls();
      const refused = await callWorker(
        postFrom(source, SECOND_LISTED_APPLE_ID, query),
      );
      const body = await refused.text();

      // THE STATUS IS HALF THE CLAIM, and it is asserted on its own rather
      // than left implied by the body. Success criterion 3 forbids a refusal
      // that only ever appears for a listed address, and a 429 here would be
      // exactly that: nobody who is not on the list can ever reach this layer,
      // so its answer has to be indistinguishable from a wrong password.
      expect(refused.status).toBe(401);
      expect(refused.status).not.toBe(429);
      expect(refused.headers.get("retry-after")).toBeNull();

      // The body compared against the exported constant, not a retyped
      // sentence that could drift from it.
      for (const line of CREDENTIAL_FAILURE_BODY) {
        expect(body).toContain(line);
      }
      expect(body).not.toContain(SOURCE_REFUSAL_BODY);

      // And it cost Apple nothing, which is the point of refusing here.
      expect(loginProofCalls(), "the fourth attempt reached Apple").toBe(before);
    },
    20_000,
  );
});

describe("the hourly counter, the layer no platform window can reach", () => {
  // Titled so `-t "hourly"` matches — 11-VALIDATION.md's third GATE-04 row.

  /** A store that really counts, and remembers every key it was handed. */
  function countingKv() {
    const values = new Map<string, string>();
    const gets: string[] = [];
    const puts: string[] = [];
    return {
      gets,
      puts,
      binding: {
        async get(key: string) {
          gets.push(key);
          return values.get(key) ?? null;
        },
        async put(key: string, value: string) {
          puts.push(key);
          values.set(key, value);
        },
      },
    };
  }

  it("refuses the sixth failed guess in the window, under a key that names nobody", async () => {
    // Both limiters stubbed open, deliberately. The per-target binding refuses
    // a fourth attempt in a minute, so six real attempts could never reach
    // this layer — which is exactly why the hour needs a counter of its own
    // and cannot be a fourth binding.
    const counter = countingKv();
    const record = recorder({ rejectWith: () => new ImapAuthError() });
    const handler = handlerOver(record.proof);
    const env = stubEnv(record, { kv: counter.binding });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const turned = await handler.fetch(post(LISTED_APPLE_ID), env);
      expect(turned.status, `guess ${attempt} was not refused`).toBe(401);
    }
    expect(record.proofCalls(), "five guesses did not each cost one").toBe(5);

    const refused = await handler.fetch(post(LISTED_APPLE_ID), env);
    const body = await refused.text();

    expect(refused.status).toBe(401);
    for (const line of CREDENTIAL_FAILURE_BODY) {
      expect(body).toContain(line);
    }
    // The sixth did not reach Apple. That is the whole of what an hourly cap
    // buys: the five before it each spent a real attempt at a real account.
    expect(record.proofCalls(), "the sixth guess reached Apple").toBe(5);

    // Six reads and five writes. The sixth read the counter and did not bump
    // it — a trip that counted itself would refill its own cap, and an address
    // that tripped once could never come back inside the window.
    expect(counter.gets).toHaveLength(6);
    expect(counter.puts).toHaveLength(5);
    // One key, because one address in one hour is one counter.
    expect(new Set([...counter.gets, ...counter.puts]).size).toBe(1);

    // THE PROPERTY, NOT THE SHAPE. The keys are read back out of the store and
    // checked for the address rather than matched against today's format: the
    // claim is that no key names a person, and a format assertion would move
    // with the format instead of holding it to anything.
    for (const key of [...counter.gets, ...counter.puts]) {
      expect(key, "a counter key carries the address").not.toContain(
        LISTED_APPLE_ID,
      );
      // And not the local part either, which is the half a reader would
      // recognise on its own.
      expect(key).not.toContain(LISTED_APPLE_ID.split("@")[0]!);
    }
  });
});
