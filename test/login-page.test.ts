// What the person at the keyboard is actually shown, and what rides back with
// it on every other answer this surface can give.
//
// **This file and `test/authorize-login.test.ts` prove different things and the
// difference is worth stating.** That file is about FLOW: who is refused, in
// what order, how many times the login proof was called, and what the ceremony
// was completed with. It can watch the whole path and still not notice that the
// page forgot to explain what an app-specific password is, or that a submitted
// password came back in the markup, or that the method-not-allowed answer can
// be framed. This file is about the RESPONSE SURFACE — the bytes, the headers
// and the attributes — and it asserts them against the constants the handler
// actually serves rather than against retyped copies that could drift.
//
// Three tables, and each one is named so the phase's validation map can find
// it. Those commands filter on `explainer`, `never echoed` and `headers`, and a
// name filter that matches nothing passes SILENTLY — which would leave three
// requirement rows looking covered while measuring nothing. If a table is
// renamed, the filter in `11-VALIDATION.md` has to be renamed with it.
//
// Two shapes, the same two the consent suite uses. A recording stub provider
// for everything that is about what a single response looks like, because that
// needs no registered client and no real namespace. The real entry — over the
// injected login proof, because D-09 forbids any automated login to a real
// Apple ID — for the one case that has to complete the whole ceremony, which is
// the only way to see the redirect that carries the authorization code.
//
// ---------------------------------------------------------------------------
// The one claim in this contract that a HUMAN confirms, not this file.
//
// No copy line may force horizontal scrolling at 320px width.
//
// The longest unbreakable token USED to be the example app-specific password
// in the password field's help text, `abcd-efgh-ijkl-mnop`. That example is
// gone: spike S5 was declined on 2026-09-20, the handler stopped transforming
// the submitted value, and the copy now tells the reader to paste it exactly as
// Apple showed it rather than naming a shape the project cannot stand behind.
//
// So the risk this backstop covers went DOWN rather than away. The longest
// remaining token on the page is a rendered destination origin, which already
// has its own `overflow-wrap` treatment and its own row in the UI spec. The
// note is kept rather than deleted because the claim is still the claim — no
// copy line may force horizontal scrolling — and because a backstop that
// silently loses its worst case looks exactly like one that was never needed.
//
// Nothing here can check that. This project has no browser in its test
// environment — the suite runs inside the workers runtime, which lays nothing
// out and measures nothing — so a test asserting it would be asserting the
// presence of a CSS declaration, not the behaviour the claim is about. It is
// recorded as a backstop in `11-VALIDATION.md` and confirmed by eye at 320px.
// ---------------------------------------------------------------------------

import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { loginHandler } from "../src/auth/login-handler";
import {
  APPLE_THROTTLE_BODY,
  CREDENTIAL_FAILURE_BODY,
  EXPLAINER_SECTIONS,
  RESPONSE_HEADERS,
  renderForm,
} from "../src/auth/login-page";
import type { Env, LoginGateSecret } from "../src/env";
import { DEPLOYED_HOSTNAME } from "../src/mcp/api-handler";
import { entryEnv } from "./fixtures/bound-secrets";
import worker, {
  FAKE_APP_PASSWORD,
  LISTED_APPLE_ID,
  resetLoginProof,
} from "./fixtures/worker-with-login-proof";

const ORIGIN = `https://${DEPLOYED_HOSTNAME}`;

/** An origin the redirect allowlist admits, so cases reach the page. */
const ALLOWED_REDIRECT = "https://claude.ai/cb";

/**
 * The two values a case pretends the person typed.
 *
 * Deliberately unlike anything else on the page, so `not.toContain` is a real
 * assertion rather than one satisfied by the string being improbable. The
 * address is not on the pool's allow list, which is what makes the POST come
 * back as the 401 form rather than completing a ceremony.
 */
const TYPED_APPLE_ID = "typed-into-the-form@example.invalid";
const TYPED_PASSWORD = "zzzz-typed-into-the-box-zzzz";

/**
 * The rendered text, with tags removed and this page's own escaping undone.
 *
 * The contract's copy is asserted against this rather than against the raw
 * body, for two reasons that both come from the page being honest markup.
 * Apostrophes are escaped, so `Apple's` reaches the browser as `Apple&#39;s`
 * and a raw-body assertion on the contract string would fail against a
 * correctly-escaped page. And both mentions of Apple's account site are links,
 * so the contract sentence is interrupted by an anchor tag in the middle.
 * Stripping tags and decoding gives back exactly what the reader sees.
 *
 * `&amp;` is decoded LAST, so a literal `&amp;lt;` in the source cannot be
 * turned into a `<` by two passes.
 */
function textOf(html: string): string {
  return html
    .replace(/<[^>]*>/g, "")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&amp;", "&");
}

/**
 * One input element, read out by id rather than searched for in the body.
 *
 * Reading the element is what makes the never-echoed assertions mean anything.
 * The form carries a hidden field that legitimately has a value attribute — the
 * round-tripped authorization query — so a body-wide search for `value=` would
 * be satisfied by that one and would never see a credential field that had
 * grown one.
 */
function inputTag(body: string, id: string): string | null {
  return new RegExp(`<input[^>]*id="${id}"[^>]*>`).exec(body)?.[0] ?? null;
}

/** The two credential inputs, asserted present so a rename cannot pass. */
function credentialInputs(body: string): string[] {
  return ["apple-id", "app-password"].map((id) => {
    const tag = inputTag(body, id);
    expect(tag).not.toBeNull();
    return tag as string;
  });
}

/** The rendered client name, read out of the marked element. */
function clientFrom(body: string): string | null {
  return /<strong class="client">([^<]*)<\/strong>/.exec(body)?.[1] ?? null;
}

/**
 * The whole policy string, written out THREE TIMES rather than derived.
 *
 * Everywhere else this file asserts against the constant the handler serves,
 * because a retyped copy can drift from the source. Here the retyped copy IS
 * the assertion, and the drift is the thing being caught: `form-action` now
 * varies per destination, so a test that built its expectation by substituting
 * into whatever the source currently says would go green for `form-action *` and
 * for a directive that had quietly lost its origin again.
 *
 * So these are literals, complete, in order, including the three directives that
 * do not vary. Asserted with `toBe` on the whole header value — never `toContain`
 * — because a substring match on `form-action 'self'` is satisfied by
 * `form-action 'self' *` and by the bare directive this work exists to replace.
 */
const POLICY_SELF =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/** The claude.ai form of it: the shape a real Claude sign-in is served. */
const POLICY_CLAUDE =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://claude.ai; frame-ancestors 'none'; base-uri 'none'";

/** The loopback form of it, for a locally-bound client on its own port. */
const POLICY_LOOPBACK =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:27890; frame-ancestors 'none'; base-uri 'none'";

/**
 * A loopback callback of the shape this account really registers.
 *
 * `test/authorize-redirect-allowlist.test.ts` owns whether the allowlist admits
 * the class; this is about what the admitted origin does to the directive.
 */
const LOOPBACK_REDIRECT = "http://127.0.0.1:27890/callback";

/**
 * Every value in the exported header constant, on the response as served.
 *
 * The loop still iterates `RESPONSE_HEADERS`, which is what keeps every case
 * below non-vacuous — an emptied constant asserts nothing. The policy is the one
 * value taken from the caller instead, because it varies with the destination,
 * and it defaults to the bare form so a case that forgets to say is asserting
 * the narrow directive rather than accepting whatever it finds.
 */
function expectSecurityHeaders(
  response: Response,
  policy: string = POLICY_SELF,
): void {
  for (const [name, value] of Object.entries(RESPONSE_HEADERS)) {
    expect(response.headers.get(name)).toBe(
      name === "content-security-policy" ? policy : value,
    );
  }
}

/** A KV stub. `value` is what the per-target hourly counter reads back. */
function quietKv(value: string | null = null) {
  return {
    async get() {
      return value;
    },
    async put() {
      // Nothing in this file asserts on the counter.
    },
  };
}

/**
 * A rate-limit binding stub with a fixed answer. Takes only a key.
 *
 * Stubbed rather than real for every case here, including the one that wants a
 * refusal. The real bindings are counters the pool persists to disk with
 * wall-clock windows and no reset between tests or between runs, so a case that
 * spent one would leave the next run of this file to live with it — and these
 * cases are about the HEADERS on a response, not about counting.
 */
function limiter(success: boolean) {
  return {
    async limit() {
      return { success };
    },
  };
}

/**
 * An env whose provider answers from the options, and records nothing.
 *
 * These cases are about what ONE response looks like, so a fixed client and a
 * fixed parsed request are enough; the consent suite already owns whether and
 * when the provider is consulted.
 */
function stubEnv(
  options: {
    parseAuthRequest?: () => Promise<unknown>;
    client?: { clientId: string; clientName?: string } | null;
    redirectUri?: string;
    kv?: unknown;
    floodRefused?: boolean;
  } = {},
): Env & LoginGateSecret {
  return {
    OAUTH_KV: options.kv ?? quietKv(),
    LOGIN_IP_LIMITER: limiter(options.floodRefused !== true),
    LOGIN_ID_LIMITER: limiter(true),
    // Without this the allow-list gate answers 503 above the method dispatch
    // and no case here reaches the response it was written for.
    ALLOWED_APPLE_IDS_SEED: JSON.stringify([LISTED_APPLE_ID]),
    // The store half, answering "nobody is in here". A case in this file is
    // never about the store, so it says nothing about it — and a binding that
    // said something would make every case in the file quietly depend on it.
    ALLOW_LIST_KV: { get: async () => null },
    OAUTH_PROVIDER: {
      parseAuthRequest:
        options.parseAuthRequest ??
        (async () => ({
          responseType: "code",
          clientId: "stub-client",
          redirectUri: options.redirectUri ?? ALLOWED_REDIRECT,
          scope: ["mcp"],
          state: "",
        })),
      lookupClient: async () =>
        options.client === undefined
          ? { clientId: "stub-client", clientName: "Stub Client" }
          : options.client,
    },
  } as unknown as Env & LoginGateSecret;
}

/** An env carrying nothing, for the answers that read no binding. */
function emptyEnv(): Env & LoginGateSecret {
  return {} as unknown as Env & LoginGateSecret;
}

const STUB_QUERY = "response_type=code&client_id=stub-client";

/** A GET of the form, through the stubbed provider. */
function getForm(
  options: Parameters<typeof stubEnv>[0] = {},
): Promise<Response> {
  return loginHandler.fetch(
    new Request(`${ORIGIN}/authorize?${STUB_QUERY}`),
    stubEnv(options),
  );
}

/** A POST carrying the two distinctive typed values. */
function postForm(
  options: Parameters<typeof stubEnv>[0] = {},
  source = "203.0.113.200",
): Promise<Response> {
  return loginHandler.fetch(
    new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": source,
      },
      body: new URLSearchParams({
        apple_id: TYPED_APPLE_ID,
        app_password: TYPED_PASSWORD,
        oauth_request: STUB_QUERY,
      }).toString(),
    }),
    stubEnv(options),
  );
}

/** Drive the real provider, over the injected proof, through its real fetch. */
async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, entryEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** The identity the page is handed when a case drives the renderer directly. */
const STUB_IDENTITY = { name: "Stub Client", redirectUri: ALLOWED_REDIRECT };

describe("the explainer is on the page, always", () => {
  /** Every string the contract requires, headings and bodies alike. */
  const CONTRACT_STRINGS = EXPLAINER_SECTIONS.flatMap((section) => [
    section.heading,
    ...section.steps,
    ...section.paragraphs,
  ]);

  it("loaded four sections, which is what makes the cases below non-vacuous", () => {
    // Without this a deleted section list would make every assertion below an
    // iteration over nothing, and the table would go green by measuring air.
    expect(EXPLAINER_SECTIONS).toHaveLength(4);
    expect(CONTRACT_STRINGS.length).toBeGreaterThanOrEqual(8);
  });

  it("renders every heading and every body on a first load", async () => {
    const text = textOf(await (await getForm()).text());

    // Asserted as strings, never as a count. A count passes when two sections
    // merge into one, which is exactly the regression that loses a section.
    for (const string of CONTRACT_STRINGS) {
      expect(text).toContain(string);
    }
  });

  it("renders every heading and every body on a failed render too", async () => {
    // The render a person most needs the explainer on. A page that drops the
    // explanation after a refusal explains an app-specific password only to
    // people who already got it right.
    const response = await postForm();
    const text = textOf(await response.text());

    expect(response.status).toBe(401);
    for (const string of CONTRACT_STRINGS) {
      expect(text).toContain(string);
    }
  });

  it("puts no explainer section inside a collapsible disclosure", async () => {
    // The requirement is that the page EXPLAINS this. An explanation nobody
    // opened is an explanation nobody read, so a disclosure element anywhere on
    // this page is a failure of the requirement rather than a styling choice.
    const body = await (await getForm()).text();

    expect(body).not.toContain("<details");
    expect(body).not.toContain("<summary");
  });

  it("links Apple's account site in a new tab, with no opener and no referrer", async () => {
    // The reader is being sent away mid-form. A same-tab navigation throws away
    // whatever they had already typed, and this page never keeps it.
    const body = await (await getForm()).text();

    expect(body).toContain(
      `<a href="https://account.apple.com" target="_blank" rel="noopener noreferrer">account.apple.com</a>`,
    );
  });

  it("ships no script, no image and no web font", async () => {
    // This is what lets the policy header stay as narrow as it is on the one
    // page in this project that handles a credential.
    const body = await (await getForm()).text();

    expect(body).not.toMatch(/<\s*script/i);
    expect(body).not.toMatch(/<\s*img/i);
    expect(body).not.toMatch(/<\s*link/i);
    expect(body).not.toContain("@font-face");
  });
});

describe("the browser is not given a format rule nobody here wrote", () => {
  // Hardening, 2026-09-21 — NOT a regression test, and the difference matters.
  // These cases were written while chasing a reported "Sign in does nothing".
  // That report turned out to have nothing to do with this field: the Worker
  // logs showed the whole OAuth flow succeeding twice over with no 4xx, and the
  // real cause was a client holding a stale connection. No failing behaviour was
  // ever observed here, so nothing below was seen red against a real symptom.
  //
  // What they DO foreclose is real. A browser refuses to submit a form whose
  // email field it dislikes, and does it silently as far as the reader is
  // concerned: nothing reaches the server, so there is no failure body, no
  // status and no log line to find afterwards.
  //
  // It is also the same mistake this phase declined to make about the password.
  // Apple publishes no app-specific password format, so the shape check refuses
  // only what cannot be one under any grammar. An Apple ID is a format this
  // project controls just as little, and letting the browser enforce a rule
  // nobody here wrote is that rule arriving by the back door.

  it("does not let the browser validate the Apple ID's format", async () => {
    const [appleId] = credentialInputs(await (await getForm()).text());

    expect(appleId).toContain(`type="text"`);
    expect(appleId).not.toContain(`type="email"`);
  });

  it("keeps the phone keyboard hint and the empty-box refusal", async () => {
    // Neither of these claims to know the format. `inputmode` only picks a
    // keyboard, and `required` only refuses an empty box — which is refusable
    // without asserting anything about what a valid value looks like.
    const [appleId] = credentialInputs(await (await getForm()).text());

    expect(appleId).toContain(`inputmode="email"`);
    expect(appleId).toMatch(/\srequired\b/);
  });

  it("puts no pattern or maxlength on either credential field", async () => {
    // The two other ways a browser-side format rule gets reintroduced. The real
    // gate is the server, which refuses before opening any socket to Apple.
    for (const tag of credentialInputs(await (await getForm()).text())) {
      expect(tag).not.toMatch(/\spattern=/);
      expect(tag).not.toMatch(/\smaxlength=/);
    }
  });
});

describe("what was typed is never echoed", () => {
  /** The page must not carry a value attribute on either credential field. */
  function expectNoPrefilledValues(body: string): void {
    for (const tag of credentialInputs(body)) {
      expect(tag).not.toMatch(/\svalue=/);
    }
    // Non-vacuity: the matcher above CAN see a value attribute, and the hidden
    // field is the one that legitimately has one.
    expect(body).toMatch(/<input type="hidden" name="oauth_request" value="/);
  }

  it("carries no pre-filled value on a first load", async () => {
    const body = await (await getForm()).text();

    expectNoPrefilledValues(body);
    expect(body).not.toContain(TYPED_APPLE_ID);
    expect(body).not.toContain(TYPED_PASSWORD);
  });

  it("carries neither submitted value back after a failed sign-in", async () => {
    // THE case. Re-typing is the recovery, which is why the failure copy says
    // the boxes are empty on purpose rather than letting it read as a bug.
    const response = await postForm();
    const body = await response.text();

    expect(response.status).toBe(401);
    expect(body).not.toContain(TYPED_APPLE_ID);
    expect(body).not.toContain(TYPED_PASSWORD);
    expectNoPrefilledValues(body);
  });

  it("carries neither submitted value back when the destination is refused", async () => {
    // A different response shape entirely — plain text, no form — and the rule
    // is the same. The refusal names the destination it turned down and nothing
    // the sender typed into the two boxes.
    const response = await postForm({
      redirectUri: "https://attacker.example/cb",
    });
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(body).not.toContain(TYPED_APPLE_ID);
    expect(body).not.toContain(TYPED_PASSWORD);
  });

  it("leaves no slot in either failure body for a value to be put in", () => {
    // The constants themselves. Every other case here proves a value did not
    // come back on some particular path; this one proves there is nowhere for
    // one to go, which is the property that holds on paths nobody has written
    // yet. A body with a placeholder in it is a body someone will fill.
    const lines = [...CREDENTIAL_FAILURE_BODY, ...APPLE_THROTTLE_BODY];

    expect(lines).toHaveLength(3);
    for (const line of lines) {
      expect(line).not.toContain("${");
      expect(line).not.toContain("{{");
      expect(line).not.toContain("%s");
    }
  });
});

describe("the security headers are on every response", () => {
  /**
   * Every response `/authorize` can produce, enumerated.
   *
   * The enumeration is the form the requirement's word "every" takes. A check
   * that only looked at the form would have missed the two answers that carried
   * no caching header at all before this plan — the method-not-allowed one and
   * the per-source refusal.
   */
  const RESPONSES: readonly {
    label: string;
    status: number;
    serve: () => Promise<Response>;
    /**
     * The whole policy this case must carry. Omitted means the bare directive,
     * which is the right answer for every response with no destination.
     */
    policy?: string;
  }[] = [
    {
      label: "the unknown-path 404",
      status: 404,
      serve: () => loginHandler.fetch(new Request(`${ORIGIN}/`), emptyEnv()),
    },
    {
      label: "the unconfigured 503",
      status: 503,
      serve: () =>
        loginHandler.fetch(new Request(`${ORIGIN}/authorize?${STUB_QUERY}`), {
          ALLOWED_APPLE_IDS_SEED: undefined,
        } as unknown as Env & LoginGateSecret),
    },
    {
      label: "the refused-destination 403",
      status: 403,
      serve: () => getForm({ redirectUri: "https://attacker.example/cb" }),
    },
    {
      label: "the unknown-client 400",
      status: 400,
      serve: () => getForm({ client: null }),
    },
    {
      label: "the locally-rendered authorization-error 400",
      status: 400,
      serve: () =>
        getForm({
          parseAuthRequest: async () => {
            throw new AuthorizationError("invalid_request", {
              description: "Missing response_type",
            });
          },
        }),
    },
    {
      label: "the authorization-error redirect",
      status: 302,
      // On the POST path this is itself a form-submission redirect, so a
      // directive forbidding its own destination refuses it in WebKit exactly as
      // it refused the success redirect. The destination here is on the
      // allowlist, so it is named.
      policy: POLICY_CLAUDE,
      serve: () =>
        getForm({
          parseAuthRequest: async () => {
            throw new AuthorizationError("invalid_request", {
              description: "Missing response_type",
              redirectUri: ALLOWED_REDIRECT,
            });
          },
        }),
    },
    {
      label: "the method-not-allowed 405",
      status: 405,
      serve: () =>
        loginHandler.fetch(
          new Request(`${ORIGIN}/authorize`, { method: "PUT" }),
          stubEnv(),
        ),
    },
    {
      label: "the source-connection 429",
      status: 429,
      serve: () => postForm({ floodRefused: true }, "203.0.113.201"),
    },
    {
      label: "the form at 200",
      status: 200,
      // The document that submits the form, so this is the one the browser
      // actually enforces `form-action` from.
      policy: POLICY_CLAUDE,
      serve: () => getForm(),
    },
    {
      label: "the form at 401",
      status: 401,
      // The re-render has to permit the destination too. A directive that
      // widened only on a first load would break every sign-in that took two
      // attempts, which is the attempt a person is most likely to make.
      policy: POLICY_CLAUDE,
      serve: () => postForm({}, "203.0.113.202"),
    },
  ];

  it("names four headers and no fewer", () => {
    // Non-vacuity for every case below: the loop inside `expectSecurityHeaders`
    // iterates this constant, so an emptied constant would make all of them
    // pass while asserting nothing at all.
    expect(Object.keys(RESPONSE_HEADERS)).toHaveLength(4);
    // The whole string, so the constant and the literal this file asserts with
    // are pinned to each other in one place. Every case below then compares a
    // served header against one of the three complete literals.
    expect(RESPONSE_HEADERS["content-security-policy"]).toBe(POLICY_SELF);
  });

  for (const enumerated of RESPONSES) {
    it(`carries all four on ${enumerated.label}`, async () => {
      const response = await enumerated.serve();

      expect(response.status).toBe(enumerated.status);
      expectSecurityHeaders(response, enumerated.policy);
    });
  }

  it("carries all four on the redirect that hands over the authorization code", async () => {
    // The site where the caching header matters most: this location header
    // carries the code, so a cached copy of this redirect is a cached copy of a
    // credential-equivalent. It is also the only response in the enumeration
    // that needs the whole ceremony, which is why it drives the real entry over
    // the injected proof rather than a stub.
    resetLoginProof();
    const redirectUri = "https://claude.ai/api/mcp/auth_callback";
    const registration = await call(
      new Request(`${ORIGIN}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Header Case Client",
          redirect_uris: [redirectUri],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        }),
      }),
    );
    const { client_id: clientId } = (await registration.json()) as {
      client_id: string;
    };

    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      state: "xyz",
    }).toString();

    const response = await call(
      new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": "203.0.113.203",
        },
        body: new URLSearchParams({
          apple_id: LISTED_APPLE_ID,
          app_password: FAKE_APP_PASSWORD,
          oauth_request: query,
        }).toString(),
      }),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location") ?? "").toContain(
      `${redirectUri}?code=`,
    );
    // The redirect at the centre of the 2026-09-23 defect. It carries the same
    // widened directive the page that submitted the form carries, so this whole
    // surface answers with one policy value per destination rather than two that
    // have to be kept in step.
    expectSecurityHeaders(response, POLICY_CLAUDE);
  });

  it("keeps each site's own headers alongside the four", async () => {
    // The spread goes first and the site's own headers follow. If that order
    // were reversed, or the spread replaced the object, these would be the
    // three values quietly lost.
    const notFound = await loginHandler.fetch(
      new Request(`${ORIGIN}/`),
      emptyEnv(),
    );
    expect(notFound.headers.get("content-type")).toBe(
      "text/plain; charset=utf-8",
    );

    const notAllowed = await loginHandler.fetch(
      new Request(`${ORIGIN}/authorize`, { method: "PUT" }),
      stubEnv(),
    );
    expect(notAllowed.headers.get("allow")).toBe("GET, POST");

    // Sixty rather than the three hundred this asserted before. The source
    // limiter is now a platform binding whose window is sixty seconds, and the
    // header carries the real figure even though the body rounds up to "a few
    // minutes" — see the body constant for why the pair is deliberate.
    const refused = await postForm({ floodRefused: true }, "203.0.113.204");
    expect(refused.headers.get("retry-after")).toBe("60");
  });
});

describe("form-action names the destination the flow is about to redirect to", () => {
  /**
   * The table the 2026-09-23 defect earns.
   *
   * `form-action 'self'` alone blocked this flow's OWN success redirect in
   * Safari: WebKit still checks a form submission's redirect against the
   * submitting document's directive, Chromium stopped, and the code was issued
   * and never exchanged with no error anywhere. Phase 11's review predicted it as
   * WR-05 and it was skipped on evidence from the one browser that cannot
   * reproduce it.
   *
   * So every case here asserts the WHOLE header value with `toBe`. A
   * `toContain("form-action 'self'")` would be satisfied by the bare directive
   * this replaces AND by `form-action 'self' *`, which is to say by both of the
   * two failures worth catching.
   */
  const policyOf = (response: Response): string =>
    response.headers.get("content-security-policy") ?? "";

  it("the three literals differ only in the directive under test", () => {
    // Non-vacuity. If these three strings were ever edited into agreement, every
    // case below would pass while distinguishing nothing.
    expect(POLICY_CLAUDE).not.toBe(POLICY_SELF);
    expect(POLICY_LOOPBACK).not.toBe(POLICY_SELF);
    expect(POLICY_LOOPBACK).not.toBe(POLICY_CLAUDE);
    expect(POLICY_CLAUDE.replace(" https://claude.ai", "")).toBe(POLICY_SELF);
    expect(POLICY_LOOPBACK.replace(" http://127.0.0.1:27890", "")).toBe(
      POLICY_SELF,
    );
  });

  it("permits exactly claude.ai on the page a Claude sign-in is served", async () => {
    const response = await getForm({ redirectUri: ALLOWED_REDIRECT });

    expect(response.status).toBe(200);
    expect(policyOf(response)).toBe(POLICY_CLAUDE);

    // Named separately so a regression that reached for a wildcard instead of
    // the origin fails on its own assertion rather than inside a diff of two
    // long strings.
    expect(policyOf(response)).not.toContain("*");
    expect(policyOf(response)).toContain(
      "form-action 'self' https://claude.ai;",
    );
  });

  it("permits the same origin the consent block names, not a second derivation", async () => {
    // The tie that stops the page saying one thing and the browser being told
    // another. Both come from `originOf`, and this is what proves it: the origin
    // inside the directive is byte-identical to the one in the marked element
    // the reader is asked to check.
    const response = await getForm({ redirectUri: ALLOWED_REDIRECT });
    const shown = /<code class="dest">([^<]*)<\/code>/.exec(
      await response.text(),
    )?.[1];

    expect(shown).toBe("https://claude.ai");
    expect(policyOf(response)).toBe(
      POLICY_SELF.replace("form-action 'self'", `form-action 'self' ${shown}`),
    );
  });

  it("permits a loopback client's own origin, port and all", async () => {
    // A real registered shape in this account: a locally-bound client on an
    // ephemeral port. The allowlist admits the class with any port, so the
    // directive has to carry whichever port this request actually holds.
    const response = await getForm({ redirectUri: LOOPBACK_REDIRECT });

    expect(response.status).toBe(200);
    expect(policyOf(response)).toBe(POLICY_LOOPBACK);
    expect(await response.text()).toContain(
      '<code class="dest">http://127.0.0.1:27890</code>',
    );
  });

  it("widens the re-render after a failed attempt too", async () => {
    const response = await postForm(
      { redirectUri: LOOPBACK_REDIRECT },
      "203.0.113.205",
    );

    expect(response.status).toBe(401);
    expect(policyOf(response)).toBe(POLICY_LOOPBACK);
  });

  it("never lets an off-list origin reach the directive, because no page is rendered", async () => {
    // The refusal happens above the render, so there is no path on which an
    // unvalidated origin could be interpolated into a policy. Asserted three
    // ways: the status, the absence of a form, and the bare directive.
    const response = await getForm({
      redirectUri: "https://attacker.example/cb",
    });
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(body).not.toContain("<form");
    expect(policyOf(response)).toBe(POLICY_SELF);
    expect(policyOf(response)).not.toContain("attacker.example");
  });

  it("keeps the bare directive for a destination it cannot reduce to an allowed origin", async () => {
    // The fail-closed edge, driven straight at the renderer because the handler
    // refuses these above it. A custom-scheme callback and an unparseable string
    // both answer the narrow directive rather than interpolating whatever came
    // in.
    for (const redirectUri of ["myapp:/cb", "not a url at all"]) {
      const response = renderForm(STUB_QUERY, null, {
        name: "Native Client",
        redirectUri,
      });

      expect(response.status).toBe(200);
      expect(policyOf(response)).toBe(POLICY_SELF);
    }
  });
});

describe("there are two failure states on the credential path, and no more", () => {
  it("renders the one credential-path body, both of its lines, at 401", async () => {
    const response = await postForm({}, "203.0.113.210");
    const text = textOf(await response.text());

    expect(response.status).toBe(401);
    // An equality against the exported constant, line by line. A retyped
    // sentence here could drift from the one the page serves, and the whole
    // point of this body is that it never varies.
    expect(CREDENTIAL_FAILURE_BODY).toHaveLength(2);
    for (const line of CREDENTIAL_FAILURE_BODY) {
      expect(text).toContain(line);
    }
  });

  it("marks BOTH inputs invalid after a credential failure, never one", async () => {
    // Narrowing this to the password would rebuild the shape-specific signal
    // the owner removed — in the accessibility tree, where it is harder to see
    // and just as readable to anyone listening for it.
    const body = await (await postForm({}, "203.0.113.211")).text();

    for (const tag of credentialInputs(body)) {
      expect(tag).toContain(`aria-invalid="true"`);
      expect(tag).toContain(`aria-describedby="login-error `);
    }
  });

  it("marks NEITHER input invalid when Apple is the one not answering", async () => {
    // Nothing the reader typed was rejected, so nothing they typed is invalid.
    // The handler does not build this state yet — branching on the throttle
    // error's type is plan 11-04's — so the case drives the renderer, which is
    // the surface that has to be right when that branch lands.
    const response = renderForm("", "throttled", STUB_IDENTITY);
    const body = await response.text();

    expect(response.status).toBe(401);
    for (const tag of credentialInputs(body)) {
      expect(tag).not.toContain("aria-invalid");
      expect(tag).toContain(`aria-describedby="login-error `);
    }
    expect(textOf(body)).toContain(APPLE_THROTTLE_BODY[0]);
  });

  it("puts the alert region immediately above the form, on both", async () => {
    for (const body of [
      await (await postForm({}, "203.0.113.212")).text(),
      await renderForm("", "throttled", STUB_IDENTITY).text(),
    ]) {
      const regionAt = body.indexOf(`id="login-error"`);
      expect(regionAt).toBeGreaterThan(-1);
      expect(body).toContain(`role="alert"`);

      const closedAt = body.indexOf("</div>", regionAt) + "</div>".length;
      const formAt = body.indexOf("<form");
      expect(formAt).toBeGreaterThan(closedAt);
      expect(body.slice(closedAt, formAt).trim()).toBe("");
    }
  });

  it("changes the title on a failed render, and on no other", async () => {
    // The only signal a screen-reader user gets that the page came back
    // different. No script means there is no second one to fall back on.
    expect(await (await getForm()).text()).toContain(
      "<title>Sign in — iCloud MCP</title>",
    );
    expect(await (await postForm({}, "203.0.113.213")).text()).toContain(
      "<title>Could not sign in — iCloud MCP</title>",
    );
  });

  it("names the client and the destination on a failed render too", async () => {
    // The consent block is the control that lets a person tell an attacker's
    // client from their own, and a second attempt must be no less informed than
    // the first.
    const body = await (await postForm({}, "203.0.113.214")).text();

    expect(clientFrom(body)).toBe("Stub Client");
    expect(body).toContain(`<code class="dest">https://claude.ai</code>`);
  });
});

describe("a client name is cut before it is escaped", () => {
  /** A name long enough to bury the consent block, ending in an escapable character. */
  function longName(): string {
    return `${"n".repeat(79)}&tail that must never be shown`;
  }

  it("cuts a name far longer than the limit, with an ellipsis", async () => {
    const body = await (
      await getForm({ client: { clientId: "stub-client", clientName: longName() } })
    ).text();
    const rendered = clientFrom(body);

    expect(rendered).not.toBeNull();
    expect(rendered).toContain("…");
    expect(body).not.toContain("tail that must never be shown");
  });

  it("cuts first and escapes second, so no entity is sliced in half", async () => {
    // THE case. Escaping first and then cutting at 80 would leave `&am` where
    // the name's 80th character is an ampersand — not an injection, but a
    // visible mangling of a name the reader is being asked to recognise.
    // Cutting first also makes the 80 a count of characters the reader sees
    // rather than a count of markup.
    const body = await (
      await getForm({ client: { clientId: "stub-client", clientName: longName() } })
    ).text();

    expect(clientFrom(body)).toBe(`${"n".repeat(79)}&amp;…`);
    expect(body).not.toContain("&am…");
  });

  it("leaves a name within the limit exactly as registered", async () => {
    // Non-vacuity for the two cases above: truncation is not simply always on.
    const name = "a".repeat(80);
    const body = await (
      await getForm({ client: { clientId: "stub-client", clientName: name } })
    ).text();

    expect(clientFrom(body)).toBe(name);
    expect(clientFrom(body)).not.toContain("…");
  });
});
