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
// No copy line may force horizontal scrolling at 320px width. The longest
// unbreakable token on the page is the example app-specific password in the
// password field's help text, `abcd-efgh-ijkl-mnop`, and it must wrap rather
// than overflow.
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

/** Every value in the exported header constant, on the response as served. */
function expectSecurityHeaders(response: Response): void {
  for (const [name, value] of Object.entries(RESPONSE_HEADERS)) {
    expect(response.headers.get(name)).toBe(value);
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
    ALLOWED_APPLE_IDS: JSON.stringify([LISTED_APPLE_ID]),
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
          ALLOWED_APPLE_IDS: undefined,
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
      serve: () => getForm(),
    },
    {
      label: "the form at 401",
      status: 401,
      serve: () => postForm({}, "203.0.113.202"),
    },
  ];

  it("names four headers and no fewer", () => {
    // Non-vacuity for every case below: the loop inside `expectSecurityHeaders`
    // iterates this constant, so an emptied constant would make all of them
    // pass while asserting nothing at all.
    expect(Object.keys(RESPONSE_HEADERS)).toHaveLength(4);
    expect(RESPONSE_HEADERS["content-security-policy"]).toContain(
      "frame-ancestors 'none'",
    );
    expect(RESPONSE_HEADERS["content-security-policy"]).toContain(
      "form-action 'self'",
    );
  });

  for (const enumerated of RESPONSES) {
    it(`carries all four on ${enumerated.label}`, async () => {
      const response = await enumerated.serve();

      expect(response.status).toBe(enumerated.status);
      expectSecurityHeaders(response);
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
    expectSecurityHeaders(response);
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
