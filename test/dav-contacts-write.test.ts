// The contact write path, driven end to end through the REAL registrar.
//
// This is the phase's tracer, asserted at the boundary a caller actually reaches:
// the registrations `registerContactsTools` performs, invoked with a recording
// `fetch` in place of a network. Nothing here calls a preview builder or a commit
// directly, because the properties that matter are properties of the whole
// path — that a preview spends no request, that a commit spends exactly one, that
// a token spent twice creates one card — and each of those is a claim about the
// wiring rather than about a function.
//
// Every byte below is invented. No fixture from `test/fixtures/dav-bytes.ts` is
// added or edited here: plan 16-02 owns that file this wave, so the byte
// expectations are built inline.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { beforeAll, afterEach, describe, expect, it, vi } from "vitest";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  composeConfirmationLine,
  contactChangeHashOf,
  mintConfirmation,
  verifyConfirmation,
} from "../src/confirm";
import type { NormalizedContactChange } from "../src/confirm";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { encodeAddressBookId, encodeContactId } from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import {
  buildContactCard,
  displayNameFor,
  parseVCard,
  patchContactCard,
} from "../src/dav/vcard";
import { SAFE_MESSAGES } from "../src/errors";
import { registerContactsTools } from "../src/mcp/tools/contacts";
import { UNTRUSTED_PREAMBLE } from "../src/mcp/untrusted";
import { ownerPrincipal } from "./fixtures/bound-secrets";
import {
  EMPTY_FORMATTED_NAME_VCF,
  ROUND_TRIP_HAZARDS_VCF,
} from "./fixtures/dav-bytes";
import type { Principal } from "../src/principal";

// The owner's principal, as the PROMISE the real env constructor returns over the
// pool's ambient environment. The no-op handler means a file that builds it and
// awaits it nowhere leaves no rejection unheard.
const owner = ownerPrincipal();
owner.catch(() => {});

let principal: Principal;
beforeAll(async () => {
  principal = await owner;
});

// ---------------------------------------------------------------------------
// The account this stub describes
// ---------------------------------------------------------------------------

const CARDDAV_SERVER = "https://contacts.icloud.com";
const PRINCIPAL_PATH = "/1234567890/principal/";
const CARDDAV_HOME = "https://p42-contacts.icloud.com/1234567890/carddavhome/";
const BOOK_PATH = "/1234567890/carddavhome/card/";
const BOOK_URL = `https://p42-contacts.icloud.com${BOOK_PATH}`;

const BOOK_ID = encodeAddressBookId({ collectionUrl: BOOK_URL });

const XML_HEADERS = { "content-type": "text/xml; charset=utf-8" };

function multistatus(body: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">${body}</multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

interface Observed {
  url: string;
  method: string;
  body: string | null;
  /**
   * The conditional header, byte-exact, or null when the request carried none.
   *
   * ONE named header and never the whole set, for the reason
   * `test/dav-contacts.test.ts` gives about its own copy: recording every header
   * would put the account's credential in a test's observation record, and
   * `./transport.ts` is the only place a credential may be touched at all.
   */
  ifMatch: string | null;
}

interface WriteStub {
  observed: Observed[];
  fetch: typeof globalThis.fetch;
  /** The highest number of requests in flight at once. See the overlap note. */
  maxInFlight: number;
  /**
   * The entity tag every read answers with, quotes included, and MUTABLE.
   *
   * Mutable because the whole of CONW-06 is a claim about the card changing
   * BETWEEN two reads: a test that cannot move this value cannot drive the case
   * at all. Set it between the preview and the commit to be somebody editing the
   * card on their phone in the gap.
   */
  etag: string;
}

/**
 * The smallest CardDAV conversation that reaches BOTH legs: the duplicate scan's
 * reads, and the write's PUT.
 *
 * **It answered no read at all until CONW-05, and the reason it answered none is
 * worth keeping in view: a create reads nothing, so a stub that could answer a
 * read would let a leg that performed one pass unnoticed.** The duplicate scan is
 * a read, on the PREVIEW leg, deliberately and by design — so the read branches
 * exist now and the property that argument protected is held a different way: the
 * commit-leg assertions count from a clean slate through `afterPreview`, which
 * also asserts the preview wrote nothing.
 *
 * The book advertises only the reports the real account advertises, so the scan
 * takes the live route rather than the one this account does not have. `cards`
 * defaults to EMPTY, which is the cheapest shape that still issues every request
 * the route costs: with no object to read, the bulk read is skipped by the route
 * itself rather than by this stub.
 *
 * Anything this stub does not recognise answers 500, which surfaces as a refusal
 * rather than as a silent success.
 *
 * The overlap counter wraps the WHOLE conversation rather than one branch, so a
 * fan-out anywhere in a leg is seen — including one pairing a read with a write,
 * which is the shape a two-request commit would most plausibly grow into. §3 of
 * `.claude/CLAUDE.md` is what makes that worth counting rather than assuming.
 */
function writeStub(
  options: { onPut?: () => Response; cards?: Record<string, string> } = {},
): WriteStub {
  const cards = options.cards ?? {};
  const state: WriteStub = {
    observed: [],
    fetch: async () => new Response(null, { status: 500 }),
    maxInFlight: 0,
    etag: '"etag-1"',
  };

  let inFlight = 0;

  const answer = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const method = String(init?.method ?? "GET");
    state.observed.push({
      url,
      method,
      body:
        init?.body === undefined || init?.body === null
          ? null
          : String(init.body),
      ifMatch: new Headers(init?.headers ?? {}).get("if-match"),
    });

    if (url.includes("/.well-known/")) return new Response(null, { status: 404 });

    const path = new URL(url).pathname;

    if (url.startsWith(CARDDAV_SERVER)) {
      if (path === PRINCIPAL_PATH) {
        return multistatus(
          `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><C:addressbook-home-set><href>${CARDDAV_HOME}</href></C:addressbook-home-set></prop></propstat></response>`,
        );
      }
      if (path === "/") {
        return multistatus(
          `<response><href>${PRINCIPAL_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><current-user-principal><href>${PRINCIPAL_PATH}</href></current-user-principal></prop></propstat></response>`,
        );
      }
    }

    if (method === "PUT") {
      return options.onPut?.() ?? new Response(null, { status: 201 });
    }

    // --- the duplicate scan's reads (CONW-05) ------------------------------
    //
    // One address book, advertising what the real account advertises, so the scan
    // takes the route production takes.
    const body = String(init?.body ?? "");

    if (method === "PROPFIND") {
      if (body.includes("supported-report-set")) {
        return path === BOOK_PATH
          ? multistatus(
              `<response><href>${BOOK_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><supported-report-set><supported-report><report><sync-collection/></report></supported-report><supported-report><report><addressbook-multiget/></report></supported-report></supported-report-set></prop></propstat></response>`,
            )
          : new Response(null, { status: 404 });
      }
      // The home set.
      if (path !== BOOK_PATH) {
        return multistatus(
          `<response><href>${BOOK_PATH}</href><propstat><status>HTTP/1.1 200 OK</status><prop><displayname>Contacts</displayname><resourcetype><collection/><C:addressbook/></resourcetype></prop></propstat></response>`,
        );
      }
      // One address book's objects, plus the collection itself — which a real
      // server includes and a caller must therefore filter out.
      return multistatus(
        [BOOK_PATH, ...Object.keys(cards)]
          .map(
            (href) =>
              `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><getetag>${state.etag}</getetag></prop></propstat></response>`,
          )
          .join(""),
      );
    }

    if (method === "REPORT" && body.includes("addressbook-multiget")) {
      const asked = [
        ...body.matchAll(/<[a-z]*:?href>([^<]+)<\/[a-z]*:?href>/g),
      ].map((one) => one[1]);
      return multistatus(
        asked
          .filter((href) => cards[href] !== undefined)
          .map(
            (href) =>
              `<response><href>${href}</href><propstat><status>HTTP/1.1 200 OK</status><prop><getetag>${state.etag}</getetag><C:address-data><![CDATA[${cards[href]}]]></C:address-data></prop></propstat></response>`,
          )
          .join(""),
      );
    }

    return new Response(null, { status: 500 });
  };

  state.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    inFlight += 1;
    state.maxInFlight = Math.max(state.maxInFlight, inFlight);
    try {
      return await answer(input, init);
    } finally {
      inFlight -= 1;
    }
  }) as typeof globalThis.fetch;

  return state;
}

/**
 * Resolve CardDAV into the real KV binding so later calls are cache hits.
 *
 * Every request-count assertion below is about what a WARM call costs. Leaving
 * discovery in the count would measure the discovery chain instead of the write.
 */
async function warm(stub: WriteStub): Promise<void> {
  vi.stubGlobal("fetch", stub.fetch);
  await clearDavCache(env, principal, "carddav");
  const resolved = await resolveDavAccount(
    env,
    principal,
    createDavFetch(owner),
    "carddav",
  );
  expect(resolved.cacheHit).toBe(false);
  stub.observed.length = 0;
}

/**
 * Assert the preview leg WROTE nothing, then forget its reads.
 *
 * Every commit-leg count below used to be able to say "the whole conversation was
 * one request", because the preview leg spent nothing at all. CONW-05 put a read
 * on the preview leg on purpose, so the claim is split into the two halves it was
 * always really making: the preview writes nothing (asserted here, on the method,
 * which is the half that matters), and the commit costs exactly one request
 * (asserted there, from a clean slate).
 *
 * Clearing rather than counting a delta, because a delta hides WHICH requests were
 * the preview's — and a preview that grew a PUT would show up as a bigger delta
 * rather than as the write it is.
 */
function afterPreview(stub: WriteStub): void {
  expect(
    stub.observed.filter((one) => one.method === "PUT"),
    "the preview leg wrote something",
  ).toHaveLength(0);
  stub.observed.length = 0;
}

interface Registration {
  name: string;
  options: Record<string, unknown>;
  callback: (args: Record<string, unknown>) => Promise<{
    isError?: boolean;
    content: { text: string }[];
  }>;
}

/** Every registration `registerContactsTools` performs, without an MCP server. */
function registeredContacts(): Registration[] {
  const recorded: Registration[] = [];
  const server = {
    registerTool(
      name: string,
      options: Record<string, unknown>,
      callback: Registration["callback"],
    ) {
      recorded.push({ name, options, callback });
    },
  };
  registerContactsTools(
    server as unknown as McpServer,
    createDavFetch(owner),
    owner,
  );
  return recorded;
}

/** Invoke one REGISTERED callback. The stub must already be installed. */
async function invoke(
  name: string,
  args: Record<string, unknown>,
): Promise<{ isError?: boolean; content: { text: string }[] }> {
  const tool = registeredContacts().find((one) => one.name === name);
  expect(tool, `${name} is not registered`).toBeDefined();
  return tool!.callback(args);
}

/** The two content blocks of a result, as raw text. */
function blocks(result: { content: { text: string }[] }): {
  trusted: string;
  untrusted: string;
} {
  expect(result.content.length).toBe(2);
  return { trusted: result.content[0].text, untrusted: result.content[1].text };
}

/** The JSON object inside a fenced block. */
function fencedObject(text: string): Record<string, unknown> {
  return JSON.parse(
    text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1),
  ) as Record<string, unknown>;
}

/** A preview's two halves, already parsed, with the two-block shape asserted. */
async function preview(args: Record<string, unknown>): Promise<{
  trusted: Record<string, unknown>;
  untrusted: Record<string, unknown>;
  raw: { trusted: string; untrusted: string };
}> {
  const result = await invoke("contacts_create", args);
  expect(
    result.isError,
    `the preview refused: ${result.content[0]?.text}`,
  ).not.toBe(true);
  const raw = blocks(result);
  return {
    trusted: JSON.parse(raw.trusted) as Record<string, unknown>,
    untrusted: fencedObject(raw.untrusted),
    raw,
  };
}

/** The change one create supplies, on the wire. */
function supplied(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    kind: "create",
    formattedName: "Adaeze Okonkwo",
    name: { family: "Okonkwo", given: "Adaeze" },
    organisation: ["Reliability"],
    note: "Met at the reliability conference.",
    emails: [{ value: "adaeze@example.invalid", types: ["INTERNET", "HOME"] }],
    tels: [{ value: "+1-555-0142", types: ["CELL"] }],
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ===========================================================================
// The preview
// ===========================================================================

describe("the contacts_create preview", () => {
  it("writes NOTHING and returns a confirmation", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted } = await preview({ addressBookId: BOOK_ID, change: supplied() });

    // NOTHING WRITTEN. A create has nothing to read on its own account — the
    // target is computed from an opaque id and the confirmation is signed locally
    // — so every request this leg makes is the duplicate scan's, and the scan
    // writes nothing. The method is what the claim is about, not the count.
    expect(stub.observed.filter((one) => one.method === "PUT")).toHaveLength(0);
    expect(typeof trusted.confirmToken).toBe("string");
    expect(String(trusted.confirmToken).length).toBeGreaterThan(0);
    expect(trusted.willCreate).toBe(true);
    expect(trusted.expiresInSeconds).toBe(CONFIRM_TTL_SECONDS);
    // Field NAMES from the module's own closed vocabulary, never values.
    expect(trusted.changedFields).toEqual([
      "formattedName",
      "name",
      "organisation",
      "note",
      "emails",
      "tels",
    ]);
    expect(trusted.fieldCount).toBe(6);
    expect(JSON.stringify(trusted)).not.toContain("Adaeze");
  });

  it("keeps the confirmation line OUTSIDE the trusted half", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted, untrusted, raw } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    // Phase 15's decision, inherited rather than reopened: the line quotes a
    // card-supplied name, so it rides in the untrusted half on both legs.
    expect("confirmationLine" in trusted).toBe(false);
    expect("confirmationLine" in untrusted).toBe(true);
    expect(raw.untrusted).toContain(UNTRUSTED_PREAMBLE);
    // One fence for the whole response, not one per field.
    expect(raw.untrusted.match(/---BEGIN UNTRUSTED /g)?.length).toBe(1);
    // The id is on BOTH sides, so the model joins them by identity.
    expect(untrusted.id).toBe(trusted.id);
  });

  it("composes the line through the SHIPPED composer, not a second sentence", async () => {
    const stub = writeStub();
    await warm(stub);

    const { untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    // Byte-compared against the composer's own output for the same summary, so a
    // hand-written sentence anywhere on this path fails here rather than reading
    // plausibly in a response nobody diffed.
    expect(untrusted.confirmationLine).toBe(
      composeConfirmationLine(
        {
          kind: "create",
          noun: "contact",
          name: "Adaeze Okonkwo",
          alsoRemoved: null,
          fieldCount: null,
          recipientCount: null,
        },
        "would",
      ),
    );
    expect(untrusted.confirmationLine).toBe(
      "Creating contact 'Adaeze Okonkwo'. Undoing it is a separate, explicit request.",
    );
  });

  it("names the contact from N when FN is present and EMPTY", async () => {
    // iCloud returns cards with an empty `FN` while `N` is populated — Apple's
    // own forums document it and `displayNameFor`'s docstring carries the
    // evidence. A caller mirroring such a card supplies exactly this pair, and a
    // line reading `the contact` would report a named contact as nameless.
    const stub = writeStub();
    await warm(stub);

    const { untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied({
        formattedName: "",
        name: { family: "Okonkwo", given: "Adaeze" },
      }),
    });

    expect(untrusted.confirmationLine).toContain("'Adaeze Okonkwo'");
    expect(untrusted.confirmationLine).not.toContain("the contact");
  });

  it("refuses a forged address book id without opening anything", async () => {
    const stub = writeStub();
    await warm(stub);

    const result = await invoke("contacts_create", {
      addressBookId: "not-a-token",
      change: supplied(),
    });

    expect(result.isError).toBe(true);
    expect(stub.observed).toHaveLength(0);
    expect(JSON.parse(result.content[0].text).category).toBe("not_found");
  });
});

// ===========================================================================
// The duplicate candidates on the preview (CONW-05)
// ===========================================================================

describe("the preview's duplicate candidates", () => {
  /**
   * A card already holding the address and the number `supplied()` carries.
   *
   * **Named DIFFERENTLY from the card being created, on purpose.** The fence
   * assertions below check that this name does not reach the trusted half, and a
   * twin sharing the created card's name would make those assertions pass on
   * either string — so they would no longer be about the candidate at all.
   */
  const TWIN_HREF = `${BOOK_PATH}twin.vcf`;
  const TWIN_NAME = "Marisol Solano";
  const TWIN_EMAIL = "adaeze@example.invalid";
  const TWIN_VCF = [
    "BEGIN:VCARD",
    "VERSION:3.0",
    "UID:twin-0001",
    `FN:${TWIN_NAME}`,
    "N:Solano;Marisol;;;",
    `EMAIL;TYPE=INTERNET:${TWIN_EMAIL}`,
    "TEL;TYPE=CELL:+1-555-0142",
    "END:VCARD",
    "",
  ].join("\r\n");

  it("names a card already holding a supplied value, and merges nothing", async () => {
    const stub = writeStub({ cards: { [TWIN_HREF]: TWIN_VCF } });
    await warm(stub);

    const { trusted, untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    expect(trusted.duplicateCandidateCount).toBe(1);
    // The signal is a CLOSED three-value vocabulary this server chose from, so it
    // rides OUTSIDE the fence beside the count.
    expect(trusted.duplicateCandidates).toEqual([
      {
        id: encodeContactId({
          addressBookUrl: BOOK_URL,
          objectUrl: `${BOOK_URL}twin.vcf`,
        }),
        addressBookId: BOOK_ID,
        signal: "email",
      },
    ]);
    // And the write is unaffected by what it found: this is still a create of a
    // NEW card, at the id the preview planned, which is not the candidate's.
    expect(trusted.willCreate).toBe(true);
    expect(trusted.id).not.toBe(
      encodeContactId({
        addressBookUrl: BOOK_URL,
        objectUrl: `${BOOK_URL}twin.vcf`,
      }),
    );
    // Nothing was copied off the candidate into the change either.
    expect(untrusted.change).toEqual(
      (await preview({ addressBookId: BOOK_ID, change: supplied() })).untrusted
        .change,
    );
  });

  it("keeps every candidate's NAME and ADDRESS inside the fence", async () => {
    const stub = writeStub({ cards: { [TWIN_HREF]: TWIN_VCF } });
    await warm(stub);

    const { raw, untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    // Both came off a card somebody ELSE wrote. The address is the sharper of the
    // two: it looks like a protocol value, so a reader assumes it is safe.
    expect(raw.trusted).not.toContain(TWIN_NAME);
    expect(raw.trusted).not.toContain(TWIN_EMAIL);

    const candidates = untrusted.duplicateCandidates as Record<
      string,
      unknown
    >[];
    expect(candidates).toHaveLength(1);
    expect(candidates[0].displayName).toBe(TWIN_NAME);
    expect(
      (candidates[0].emails as { value: string }[]).map((one) => one.value),
    ).toEqual([TWIN_EMAIL]);
    // The id is on BOTH sides, so the fenced name joins the trusted signal by
    // identity rather than by position.
    expect(candidates[0].id).toBe(
      (trustedCandidates(raw.trusted)[0] as Record<string, unknown>).id,
    );
  });

  it("reports ZERO on a preview that found nothing, rather than omitting the key", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    // A field that appears only when it is interesting teaches a reader to treat
    // its absence as the absence of the question rather than as an answer to it.
    expect("duplicateCandidateCount" in trusted).toBe(true);
    expect(trusted.duplicateCandidateCount).toBe(0);
    expect(trusted.duplicateCandidates).toEqual([]);
  });

  it("spends NOTHING scanning when the change carries no address and no number", async () => {
    const stub = writeStub();
    await warm(stub);

    const withoutValues = supplied();
    delete withoutValues.emails;
    delete withoutValues.tels;

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: withoutValues,
    });

    // The whole preview is a decode, a uuid, a hash and an HMAC again — which is
    // the locked "a create carrying neither spends nothing" decision, and it has
    // to be true of the discovery read as well as of the queries.
    expect(stub.observed).toHaveLength(0);
    expect(trusted.duplicateCandidateCount).toBe(0);
  });

  it("probes the FIRST supplied address and number, not all of them", async () => {
    const stub = writeStub();
    await warm(stub);

    await preview({
      addressBookId: BOOK_ID,
      change: supplied({
        emails: [
          { value: "first@example.invalid" },
          { value: "second@example.invalid" },
          { value: "third@example.invalid" },
        ],
      }),
    });

    // A create carrying five addresses must not cost five queries. On the live
    // route the probe values are not on the wire at all, so what this counts is
    // the route's cost: one enumeration over one book, and no more.
    const enumerations = stub.observed.filter(
      (one) =>
        one.method === "PROPFIND" &&
        new URL(one.url).pathname === BOOK_PATH &&
        !String(one.body).includes("supported-report-set"),
    );
    expect(enumerations).toHaveLength(1);
    expect(stub.maxInFlight).toBe(1);
  });

  it("writes exactly ONE card, carrying nothing off the candidate", async () => {
    const stub = writeStub({ cards: { [TWIN_HREF]: TWIN_VCF } });
    await warm(stub);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    expect(trusted.duplicateCandidateCount).toBe(1);
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });
    expect(
      result.isError,
      `the commit refused: ${result.content[0]?.text}`,
    ).not.toBe(true);

    // ONE write. Not a merge into the candidate, not a second card, and not a
    // refusal: refusing would make a legitimate second card for the same person
    // impossible to create, which is why CONW-05 asks for surfacing.
    const writes = stub.observed.filter((one) => one.method === "PUT");
    expect(writes).toHaveLength(1);
    expect(new URL(writes[0].url).pathname).not.toBe(TWIN_HREF);

    // And no field of the candidate reached the written body. The candidate's uid
    // is the sharpest witness: a merge would have written it.
    const body = String(writes[0].body);
    expect(body).not.toContain("twin-0001");
    expect(body).not.toContain(TWIN_NAME);
    expect(body).toContain("\r\nUID:");
    expect(parseVCard(body).uid).not.toBe("twin-0001");
  });

  it("does NOT bind the candidates into the signed change", async () => {
    // They are an observation this server made at preview time, like an ETag.
    // Binding them would make the commit refuse a write because somebody else
    // added a card in between, which is not what CONW-06 is for.
    const withTwin = writeStub({ cards: { [TWIN_HREF]: TWIN_VCF } });
    await warm(withTwin);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    expect(trusted.duplicateCandidateCount).toBe(1);

    // The book changes underneath: the candidate is gone by commit time.
    const emptied = writeStub();
    vi.stubGlobal("fetch", emptied.fetch);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });

    expect(
      result.isError,
      `the commit refused: ${result.content[0]?.text}`,
    ).not.toBe(true);
    expect(emptied.observed.filter((one) => one.method === "PUT")).toHaveLength(
      1,
    );
  });
});

/** The candidate rows of a trusted block, already parsed. */
function trustedCandidates(trusted: string): unknown[] {
  const parsed = JSON.parse(trusted) as Record<string, unknown>;
  return parsed.duplicateCandidates as unknown[];
}

// ===========================================================================
// The commit
// ===========================================================================

describe("the contacts_commit write", () => {
  it("costs exactly ONE request, and its body is the card the builder emitted", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted, untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });
    expect(
      result.isError,
      `the commit refused: ${result.content[0]?.text}`,
    ).not.toBe(true);

    // ONE request, and it is the write. Never two: a retried write is a second
    // write, which is why `createContact` passes `false` for rediscovery.
    expect(stub.observed).toHaveLength(1);
    expect(stub.observed[0].method).toBe("PUT");
    expect(stub.maxInFlight).toBe(1);

    // The card that went out is byte-identical to the one the builder emits for
    // the change the preview echoed back. The uid is read off the SIGNED object
    // url, so the builder is handed the same one the write is addressed with.
    const change = untrusted.change as NormalizedContactChange;
    const uid = decodeURIComponent(
      new URL(stub.observed[0].url).pathname.split("/").pop()!.slice(0, -".vcf".length),
    );
    expect(stub.observed[0].body).toBe(buildContactCard(uid, change));

    // And what went out is a real card: structured `N` under semicolons, not the
    // comma form `setValues` would have produced.
    const body = String(stub.observed[0].body);
    expect(body).toContain("\r\nN:Okonkwo;Adaeze;;;\r\n");
    expect(body).toContain("\r\nEMAIL;TYPE=INTERNET,HOME:adaeze@example.invalid\r\n");
    expect(body.endsWith("END:VCARD\r\n")).toBe(true);
    // Nothing this server invented on the way through. A `REV` would make two
    // serialisations of one change differ, which is the hazard the fidelity proof
    // in 16-03 depends on not existing.
    expect(body).not.toContain("REV:");
    expect(body).not.toContain("PRODID");

    const parsed = parseVCard(body);
    expect(parsed.uid).toBe(uid);
    expect(parsed.formattedName).toBe("Adaeze Okonkwo");
    expect(parsed.name?.family).toBe("Okonkwo");
    expect(parsed.emails.map((one) => one.value)).toEqual([
      "adaeze@example.invalid",
    ]);

    // The card is addressable the moment it exists, under the id the preview
    // already published.
    const committed = JSON.parse(blocks(result).trusted) as Record<
      string,
      unknown
    >;
    expect(committed.applied).toBe(true);
    expect(committed.id).toBe(trusted.id);
    expect(committed.id).toBe(
      encodeContactId({
        addressBookUrl: BOOK_URL,
        objectUrl: stub.observed[0].url,
      }),
    );
  });

  it("answers with the SAME sentence in the past tense", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted, untrusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    afterPreview(stub);
    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });
    const after = fencedObject(blocks(result).untrusted);

    expect(after.confirmationLine).toBe(
      "Created contact 'Adaeze Okonkwo'. Undoing it is a separate, explicit request.",
    );
    // The whole tense lives in the verb, which is what makes the two lines
    // comparable: strip the leading word and the remainders are byte-identical.
    const drop = (line: unknown) => String(line).split(" ").slice(1).join(" ");
    expect(drop(after.confirmationLine)).toBe(
      drop(untrusted.confirmationLine),
    );
    // And the line is still fenced on this leg too.
    expect("confirmationLine" in JSON.parse(blocks(result).trusted)).toBe(false);
  });

  it("creates exactly ONE card when one token is committed twice", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    afterPreview(stub);

    const first = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });
    expect(first.isError).not.toBe(true);
    expect(stub.observed).toHaveLength(1);

    const spentAfterFirst = stub.observed.length;
    const second = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied(),
    });

    expect(second.isError).toBe(true);
    const parsed = JSON.parse(second.content[0].text);
    expect(parsed.category).toBe("confirmation_invalid");
    expect(parsed.message).toBe(SAFE_MESSAGES.confirmation_invalid);
    // ZERO additional outbound requests. The KV reservation precedes every DAV
    // request, which is the property `If-Match` structurally cannot deliver
    // because `If-Match` IS the request.
    expect(stub.observed.length).toBe(spentAfterFirst);
  });

  it("refuses a create confirmation carrying an ETag, before anything is sent", async () => {
    const stub = writeStub();
    await warm(stub);

    const change: NormalizedContactChange = {
      kind: "create",
      formattedName: { value: "Adaeze Okonkwo" },
      name: null,
      organisation: null,
      address: null,
      note: null,
      emails: null,
      tels: null,
    };
    const forged = await mintConfirmation(
      {
        v: CONFIRM_VERSION,
        t: "dav",
        k: "create",
        j: crypto.randomUUID(),
        c: BOOK_URL,
        o: `${BOOK_URL}forged.vcf`,
        r: null,
        // The whole point. `If-Match` asserts the resource is unchanged and
        // `If-None-Match: *` asserts it does not exist; a payload holding both
        // intentions is one whose author disagreed with itself about which
        // operation this is.
        e: '"an-etag"',
        s: null,
        h: await contactChangeHashOf(change),
        x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
        u: principal.userId,
      },
      env.CONFIRM_SECRET,
    );

    const result = await invoke("contacts_commit", {
      confirmToken: forged,
      change: { kind: "create", formattedName: "Adaeze Okonkwo" },
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("refuses a change altered between the preview and the commit", async () => {
    const stub = writeStub();
    await warm(stub);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied({ formattedName: "Somebody Else" }),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("refuses a commit that swaps 'leave it alone' for 'clear it'", async () => {
    // The swap `canonicalContactChange` exists to make impossible, driven through
    // the real gate rather than only against the canonical. `JSON.stringify`
    // collapses `[undefined]` and `[null]` to the same bytes, so a positional
    // canonical built the obvious way would hash these two identically — and this
    // commit would be ACCEPTED after the user approved a preview that promised to
    // leave the note alone.
    const stub = writeStub();
    await warm(stub);

    const withoutNote = supplied();
    delete withoutNote.note;

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: withoutNote,
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: supplied({ note: null }),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("refuses a malformed token without opening anything", async () => {
    const stub = writeStub();
    await warm(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: "not-a-token",
      change: supplied(),
    });

    expect(result.isError).toBe(true);
    expect(stub.observed).toHaveLength(0);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
  });
});

// ===========================================================================
// The update (CONW-02, CONW-03, CONW-05 on the update side, CONW-06)
//
// The requirement the whole phase exists for, and the one PITFALLS #39 warns is
// discovered too late. CardDAV has no partial update: changing a phone number
// means writing a complete replacement card, so an update built from what the
// model remembers deletes everything it does not remember, on every device the
// user owns, silently.
//
// Every assertion below is therefore about what SURVIVES rather than about what
// changed. The card driven through is `ROUND_TRIP_HAZARDS_VCF` — the only fixture
// carrying all three of the properties a rebuilt card would lose.
// ===========================================================================

/** Where the card being updated lives, and the opaque id that names it. */
const CARD_HREF = `${BOOK_PATH}noor.vcf`;
const CARD_URL = `${BOOK_URL}noor.vcf`;
const CARD_ID = encodeContactId({
  addressBookUrl: BOOK_URL,
  objectUrl: CARD_URL,
});

/**
 * What the XML layer actually delivers for a card placed inside CDATA.
 *
 * **One CRLF short of the fixture, and that is MEASURED rather than assumed** —
 * plan 16-06 measured `xml-js` dropping a card's trailing terminator out of a
 * CDATA section, and recorded it as a behaviour rather than trimming both sides
 * into agreement. It closes from the other end because `patchContactCard` APPENDS
 * the terminator rather than preserving one, which is why 16-03 could assert that
 * normalisation as an identity.
 *
 * The fixture's own ending is asserted rather than trusted, so the day the
 * fixture stops ending in CRLF this helper fails instead of silently removing two
 * bytes of content.
 */
function asDelivered(vcf: string): string {
  expect(
    vcf.endsWith("\r\n"),
    "the fixture no longer ends in CRLF, so this helper is removing content",
  ).toBe(true);
  return vcf.slice(0, -2);
}

/** A card's content lines, unfolded, so a re-fold at new boundaries is absorbed. */
function unfold(vcf: string): string {
  return vcf.replace(/\r\n /g, "");
}

/**
 * One card's content lines, unfolded, with a trailing terminator absorbed.
 *
 * The two sides of every comparison below disagree about the terminator by
 * construction and for reasons already measured: the FETCHED bytes arrive one
 * CRLF short of the fixture because `xml-js` drops it out of CDATA (16-06), and
 * the WRITTEN bytes carry one because `patchContactCard` appends it (16-03). A
 * split that kept it would put an empty final element on one side only and report
 * a length mismatch instead of the content difference the caller is asking about.
 */
function contentLines(vcf: string): string[] {
  return unfold(vcf).replace(/\r\n$/, "").split("\r\n");
}

/**
 * The two `ical.js` re-serialisation transformations plan 16-03 MEASURED, absorbed
 * on both sides of a comparison.
 *
 * Applied to the fetched card as well as the written one, and that is the whole
 * point: neither is a change to the card's CONTENT, so a comparison that could not
 * see past them would report four differences on a change that named one field —
 * and a reader given four would stop reading the number.
 *
 *   2. The group AND the property name come back upper-cased. Both halves:
 *      `item1.X-ABLabel` becomes `ITEM1.X-ABLABEL`.
 *   3. Repeated type parameters merge: `TYPE=INTERNET;TYPE=HOME` becomes
 *      `TYPE=INTERNET,HOME`.
 *
 * Deliberately narrow, on 16-03's own terms. Only the text before the first `;` or
 * `:` is re-cased, so a parameter VALUE whose case changed is NOT absorbed; the
 * merge is case-sensitive on the parameter name and runs in one direction only, so
 * a reordered or re-cased parameter name is NOT absorbed either. 16-03's own
 * numbers 1 and 4 — the re-fold and the terminator — are absorbed by `unfold` and
 * `contentLines` above, each for its own measured reason.
 */
function absorbReserialisation(line: string): string {
  const boundary = line.search(/[;:]/);
  if (boundary < 0) return line.toUpperCase();
  return (
    line.slice(0, boundary).toUpperCase() +
    line.slice(boundary).replace(/;TYPE=([^;:]+);TYPE=/g, ";TYPE=$1,")
  );
}

/** The change one update supplies, on the wire. A DIFF and never a whole card. */
function suppliedUpdate(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    kind: "update",
    note: "Prefers a fortnight of notice.",
    ...overrides,
  };
}

/** An update preview's two halves, already parsed. */
async function updatePreview(args: Record<string, unknown>): Promise<{
  trusted: Record<string, unknown>;
  untrusted: Record<string, unknown>;
  raw: { trusted: string; untrusted: string };
}> {
  const result = await invoke("contacts_update", args);
  expect(
    result.isError,
    `the preview refused: ${result.content[0]?.text}`,
  ).not.toBe(true);
  const raw = blocks(result);
  return {
    trusted: JSON.parse(raw.trusted) as Record<string, unknown>,
    untrusted: fencedObject(raw.untrusted),
    raw,
  };
}

/** A stub holding the three-hazard card at the url `CARD_ID` names. */
function hazardStub(options: { onPut?: () => Response } = {}): WriteStub {
  return writeStub({
    onPut: options.onPut,
    cards: { [CARD_HREF]: ROUND_TRIP_HAZARDS_VCF },
  });
}

describe("the contacts_update preview", () => {
  it("writes NOTHING, and reports how much of the card it is NOT touching", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });

    expect(stub.observed.filter((one) => one.method === "PUT")).toHaveLength(0);
    // FALSE, and this is the field discriminating now rather than being
    // constantly true.
    expect(trusted.willCreate).toBe(false);
    expect(trusted.id).toBe(CARD_ID);
    expect(trusted.changedFields).toEqual(["note"]);
    expect(trusted.fieldCount).toBe(1);
    expect(typeof trusted.confirmToken).toBe("string");

    // **The field this preview exists for.** The hazard card carries thirteen
    // properties and the change names one, so twelve are preserved — including
    // the photo, the grouped label, the unmodelled phonetic name and the card's
    // own REV, none of which any read path in this project can see.
    expect("preservedPropertyCount" in trusted).toBe(true);
    expect(trusted.preservedPropertyCount).toBe(12);
    expect(trusted.preservedPropertyCount as number).toBeGreaterThan(0);

    // Nothing off the card reached the trusted half.
    expect(JSON.stringify(trusted)).not.toContain("Noor");
    expect(JSON.stringify(trusted)).not.toContain("Vaskez");
  });

  it("reports ZERO preserved properties on a CREATE, rather than omitting the key", async () => {
    // The key set must not vary between the two previews: a field appearing only
    // on the update teaches a reader to read its absence on a create as the
    // absence of the question rather than as an answer to it.
    const stub = writeStub();
    await warm(stub);

    const { trusted } = await preview({
      addressBookId: BOOK_ID,
      change: supplied(),
    });

    expect("preservedPropertyCount" in trusted).toBe(true);
    expect(trusted.preservedPropertyCount).toBe(0);
    expect(trusted.willCreate).toBe(true);
  });

  it("composes the overwrite line through the SHIPPED composer", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { untrusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });

    expect(untrusted.confirmationLine).toBe(
      composeConfirmationLine(
        {
          kind: "update",
          noun: "contact",
          name: "Noor Vasquez",
          alsoRemoved: null,
          fieldCount: 1,
          recipientCount: null,
        },
        "would",
      ),
    );
    // Byte-pinned as well, because the composer's output is what a person reads.
    // The consequence clause is the one the update arm of the shipped table
    // carries: the previous values are gone, and no invitation leaves the
    // building on this path.
    expect(untrusted.confirmationLine).toBe(
      "Overwriting contact 'Noor Vasquez', changing 1 field. The values it held before cannot be recovered.",
    );
    // And the line stays OUTSIDE the trusted half: it quotes a card-supplied name.
    expect("confirmationLine" in untrusted).toBe(true);
  });

  it("names the contact from N when the FETCHED card's FN is present and EMPTY", async () => {
    // iCloud returns cards with an empty `FN` while `N` is populated,
    // inconsistently across resyncs, on contacts that display correctly
    // everywhere else. A write path reading `FN` directly reports a named contact
    // as nameless on a real subset of the owner's address book — and this is the
    // sentence somebody reads before agreeing to an overwrite.
    const stub = writeStub({
      cards: { [CARD_HREF]: EMPTY_FORMATTED_NAME_VCF },
    });
    await warm(stub);

    const { untrusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });

    const named = parseVCard(asDelivered(EMPTY_FORMATTED_NAME_VCF));
    expect(named.formattedName).toBe("");
    expect(named.name).not.toBe(null);
    expect(untrusted.confirmationLine).toContain(
      `'${displayNameFor(named)}'`,
    );
    expect(untrusted.confirmationLine).not.toContain("the contact");
  });

  it("refuses a forged contact id without opening anything", async () => {
    const stub = hazardStub();
    await warm(stub);

    const result = await invoke("contacts_update", {
      id: "not-a-token",
      change: suppliedUpdate(),
    });

    expect(result.isError).toBe(true);
    // The decode is lexically ahead of the read, so a forged id costs nothing.
    expect(stub.observed).toHaveLength(0);
    expect(JSON.parse(result.content[0].text).category).toBe("not_found");
  });

  it("refuses a change that names NOTHING, before reading anything", async () => {
    // There is no write to confirm, and a confirmation for a no-op is a
    // capability nobody should be holding.
    const stub = hazardStub();
    await warm(stub);

    const result = await invoke("contacts_update", {
      id: CARD_ID,
      change: { kind: "update" },
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("never offers the card being updated as its own duplicate (CONW-05)", async () => {
    // The card carries the address the change supplies, so without
    // `excludeObjectUrl` it would match its own probe and be presented as a
    // second person with the same details — the one candidate that is certainly
    // not one. This is the reason that parameter exists at all.
    const stub = hazardStub();
    await warm(stub);

    const { trusted, raw } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate({
        emails: [{ value: "noor@example.invalid", types: ["INTERNET"] }],
      }),
    });

    const rows = trusted.duplicateCandidates as { id: string }[];
    expect(rows.map((one) => one.id)).not.toContain(CARD_ID);
    expect(trusted.duplicateCandidateCount).toBe(0);
    expect(rows).toEqual([]);
    // The object URL itself, in either half of the response, in any spelling. The
    // id above is the encoded form; this is the value `excludeObjectUrl` compares.
    expect(raw.trusted).not.toContain("noor.vcf");
    expect(raw.untrusted).not.toContain("noor.vcf");
  });
});

describe("the contacts_update commit", () => {
  it("spends TWO serial requests: the re-read, then the conditional write", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });
    expect(
      result.isError,
      `the commit refused: ${result.content[0]?.text}`,
    ).not.toBe(true);

    // TWO, and the count is the property. The fan-out rule bans CONCURRENCY and
    // not request count, and its own text permits this shape by name: "a patch
    // needs the whole resource, and rebuilding drops every component it did not
    // rebuild."
    expect(stub.observed).toHaveLength(2);
    expect(stub.observed[0].method).toBe("REPORT");
    expect(stub.observed[1].method).toBe("PUT");
    // SERIAL. One awaited before the next begins, never a pair.
    expect(stub.maxInFlight).toBe(1);

    const committed = JSON.parse(blocks(result).trusted) as Record<
      string,
      unknown
    >;
    expect(committed.applied).toBe(true);
    // An update moves nothing, so the id is the one the caller supplied.
    expect(committed.id).toBe(CARD_ID);
  });

  it("writes the PATCH of the bytes it just read, byte for byte", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted, untrusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    const writes = stub.observed.filter((one) => one.method === "PUT");
    expect(writes).toHaveLength(1);

    // **The whole of CONW-03, in one equality.** The expected bytes are COMPUTED
    // here by applying the shipped patcher to the exact card the stubbed
    // transport served, rather than copied from a constant that could have been
    // written to match whatever the code happens to emit.
    const change = untrusted.change as NormalizedContactChange;
    expect(writes[0].body).toBe(
      patchContactCard(asDelivered(ROUND_TRIP_HAZARDS_VCF), change),
    );

    // And nothing this server invented on the way through. A REV of its own would
    // make two serialisations of one change differ, which is the hazard the
    // fidelity proof in 16-03 depends on not existing — the card's OWN REV is a
    // different matter and is asserted to survive below.
    expect(writes[0].body).not.toContain("PRODID");
  });

  it("carries every unmentioned property through, including three no read path sees", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);
    await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    const written = String(
      stub.observed.filter((one) => one.method === "PUT")[0].body,
    );
    const delivered = asDelivered(ROUND_TRIP_HAZARDS_VCF);

    // **Hazard one: the photo.** Compared UNFOLDED, because the library re-folds
    // long values at its own column boundaries — 16-03 measured that and
    // normalised it by name. The payload is what must be identical, and it is.
    const photoOf = (card: string) =>
      unfold(card)
        .split("\r\n")
        .find((line) => line.startsWith("PHOTO;"));
    expect(photoOf(written)).toBe(photoOf(delivered));
    // And it still DECODES, which is the claim a byte comparison against another
    // byte string cannot quite make on its own: a payload corrupted identically on
    // both sides would pass the equality above and fail here.
    expect(atob(String(photoOf(written)).split(":")[1])).toContain(
      "Decode it and you get this sentence.",
    );

    // **Hazard two: the grouped label pair**, both halves still sharing one
    // prefix. Upper-cased by the library on re-serialisation — 16-03's
    // normalisation 2, which upper-cases the group AND the property name — so the
    // bytes that actually go to iCloud are pinned here rather than the fixture's
    // spelling.
    expect(written).toContain(
      "\r\nITEM1.EMAIL;TYPE=INTERNET:noor@example.invalid\r\n",
    );
    expect(written).toContain("\r\nITEM1.X-ABLABEL:Studio\r\n");

    // **Hazard three: a property `parseVCard` cannot see at all.** It survives
    // because it is never READ — only copied. This is the property PITFALLS #39
    // is about, and a card rebuilt from a parse would have deleted it.
    expect(written).toContain("\r\nX-PHONETIC-LAST-NAME:Vaskez\r\n");

    // The card's OWN revision stamp, which this server neither reads nor writes.
    expect(written).toContain("\r\nREV:20260106T000000Z\r\n");

    // And the one thing that DID change, in place, with the old value gone.
    expect(written).toContain("\r\nNOTE:Prefers a fortnight of notice.\r\n");
    expect(written).not.toContain("Restores ledgers");
  });

  it("leaves an unmentioned TEXT field alone, proven by the bytes and not by a field diff", async () => {
    const stub = hazardStub();
    await warm(stub);

    // Only the note is named. `FN`, `N`, `ORG` and every address and number go
    // unmentioned.
    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);
    await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    const written = String(
      stub.observed.filter((one) => one.method === "PUT")[0].body,
    );
    const delivered = asDelivered(ROUND_TRIP_HAZARDS_VCF);

    // EXACTLY ONE line differs, and it is the one the change named. A field-by-
    // field comparison could not make this claim: it would only compare the
    // fields it knew to ask about. `setOrRemoveText` updates in place, which is
    // why the line does not move — 16-03 recorded that a mentioned STRUCTURED
    // property relocates to the end instead.
    const before = contentLines(delivered).map(absorbReserialisation);
    const after = contentLines(written).map(absorbReserialisation);
    expect(after).toHaveLength(before.length);
    const differing = after.filter((line, index) => line !== before[index]);
    expect(
      differing,
      "more than the named line changed",
    ).toEqual(["NOTE:Prefers a fortnight of notice."]);
  });

  it("clears a field on a null and replaces the whole address list on a list", async () => {
    const stub = hazardStub();
    await warm(stub);

    // `note: null` CLEARS it; `emails` supplied REPLACES every one on the card,
    // the grouped one included. `formattedName` is unmentioned and survives.
    const change = suppliedUpdate({
      note: null,
      emails: [{ value: "noor@studio.invalid", types: ["INTERNET"] }],
    });

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change,
    });
    expect(trusted.changedFields).toEqual(["note", "emails"]);
    afterPreview(stub);

    await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change,
    });

    const written = String(
      stub.observed.filter((one) => one.method === "PUT")[0].body,
    );

    // Cleared.
    expect(written).not.toContain("NOTE:");
    // Replaced, both of them, and the new value carries NO parameter and no group
    // prefix off the entries it replaced — `setEntries` removes every property of
    // that name and adds one per supplied entry, which is the grouped-label
    // corruption CONW-03 exists to stop.
    expect(written).not.toContain("noor.vasquez@example.invalid");
    expect(written).toContain(
      "\r\nEMAIL;TYPE=INTERNET:noor@studio.invalid\r\n",
    );
    expect(written).not.toContain("ITEM1.EMAIL");
    // The orphaned label stands, and that is the patch rule being OBEYED rather
    // than a gap in it: the label is a property the change did not name, and this
    // server deleting an unnamed property is the failure the whole path avoids.
    // 16-03 recorded it; it is asserted here so it cannot change unnoticed.
    expect(written).toContain("\r\nITEM1.X-ABLABEL:Studio\r\n");
    // Untouched.
    expect(written).toContain("\r\nFN:Noor Vasquez\r\n");
    expect(written).toContain("\r\nX-PHONETIC-LAST-NAME:Vaskez\r\n");
  });

  it("sends the conditional header the PREVIEW observed, byte for byte", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);
    await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    const write = stub.observed.filter((one) => one.method === "PUT")[0];

    // Read out of the CONFIRMATION rather than hardcoded, so the claim is "the
    // header carries the version the user approved against" and not "the header
    // carries some string this test also knows". Verifying spends nothing and
    // reserves nothing — the reservation is `reserveConfirmation`'s job and it
    // already ran on the commit above.
    const signed = await verifyConfirmation(
      String(trusted.confirmToken),
      env.CONFIRM_SECRET,
      principal.userId,
      "dav",
    );
    expect(signed.e).toBe('"etag-1"');
    // Byte-exact, quotes included. `assertEtag` refuses a falsy one before
    // anything reaches the wire, because a falsy value reaching the library DROPS
    // the header and turns this write unconditional with no error, no warning and
    // a 200 from the server.
    expect(write.ifMatch).toBe(signed.e);
  });

  it("refuses a card edited between the preview and the commit, spending no write", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    // Somebody edits the card on their phone. iCloud's version stamp moves.
    stub.etag = '"etag-2"';

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe("stale_resource");
    expect(JSON.parse(result.content[0].text).message).toBe(
      SAFE_MESSAGES.stale_resource,
    );

    // ZERO writes, counted. The local comparison is the cheap refusal: a raced
    // update costs ONE read rather than a write the server was always going to
    // refuse.
    expect(stub.observed.filter((one) => one.method === "PUT")).toHaveLength(0);
    expect(stub.observed).toHaveLength(1);
    expect(stub.observed[0].method).toBe("REPORT");
  });

  it("surfaces a 412 on the write as stale_resource too", async () => {
    // The OTHER race, and the one the local comparison structurally cannot see:
    // the card changing between THIS SERVER'S own read and its own write. The
    // conditional header is what catches it, and the whole 412 to stale_resource
    // chain already shipped — this drives it rather than re-deciding it.
    const stub = hazardStub({
      onPut: () => new Response(null, { status: 412 }),
    });
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe("stale_resource");
    // ONE write attempt and no retry. A retried write is a second write, which is
    // why `updateContact` pins re-discovery off — and re-resolving the account's
    // home urls cannot make a superseded version current.
    expect(stub.observed.filter((one) => one.method === "PUT")).toHaveLength(1);
  });

  it("writes exactly ONCE when one update token is committed twice", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    const first = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });
    expect(first.isError).not.toBe(true);
    expect(stub.observed.filter((one) => one.method === "PUT")).toHaveLength(1);

    const spentAfterFirst = stub.observed.length;
    const second = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });

    expect(second.isError).toBe(true);
    expect(JSON.parse(second.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    // ZERO additional requests — not even the re-read. The KV reservation
    // precedes every DAV request, which is the property `If-Match` structurally
    // cannot deliver because `If-Match` IS the request.
    expect(stub.observed.length).toBe(spentAfterFirst);
  });

  it("refuses an update token presented with a CREATE-shaped change", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    // The SIGNED kind says update; the supplied change says create. A
    // disagreement the caller authored must resolve in favour of neither, and it
    // is refused before the hash and before any request.
    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate({ kind: "create" }),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("refuses a change altered between the preview and the commit", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);

    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate({ note: "Something else entirely." }),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    // Refused BEFORE the reservation and therefore before the re-read.
    expect(stub.observed).toHaveLength(0);
  });

  it("refuses an update confirmation carrying NO ETag, before anything is sent", async () => {
    // The create arm's refusal is the mirror image of this one, and the pair is
    // what makes `ConfirmPayload.e`'s "null ONLY for a create" invariant real —
    // the type cannot express it, because the field is `string | null` for every
    // kind. An update with no version to bind is an unconditional overwrite, which
    // is the raced write nobody can detect.
    const stub = hazardStub();
    await warm(stub);

    const change: NormalizedContactChange = {
      kind: "update",
      formattedName: null,
      name: null,
      organisation: null,
      address: null,
      note: { value: "Prefers a fortnight of notice." },
      emails: null,
      tels: null,
    };
    const forged = await mintConfirmation(
      {
        v: CONFIRM_VERSION,
        t: "dav",
        k: "update",
        j: crypto.randomUUID(),
        c: BOOK_URL,
        o: CARD_URL,
        r: null,
        e: null,
        s: null,
        h: await contactChangeHashOf(change),
        x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
        u: principal.userId,
      },
      env.CONFIRM_SECRET,
    );

    const result = await invoke("contacts_commit", {
      confirmToken: forged,
      change: suppliedUpdate(),
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).category).toBe(
      "confirmation_invalid",
    );
    expect(stub.observed).toHaveLength(0);
  });

  it("answers with the SAME sentence in the past tense", async () => {
    const stub = hazardStub();
    await warm(stub);

    const { trusted, untrusted } = await updatePreview({
      id: CARD_ID,
      change: suppliedUpdate(),
    });
    afterPreview(stub);
    const result = await invoke("contacts_commit", {
      confirmToken: trusted.confirmToken,
      change: suppliedUpdate(),
    });
    const after = fencedObject(blocks(result).untrusted);

    expect(after.confirmationLine).toBe(
      "Overwrote contact 'Noor Vasquez', changing 1 field. The values it held before cannot be recovered.",
    );
    const drop = (line: unknown) => String(line).split(" ").slice(1).join(" ");
    expect(drop(after.confirmationLine)).toBe(drop(untrusted.confirmationLine));
    // Fenced on this leg too: it quotes the card's own name.
    expect("confirmationLine" in JSON.parse(blocks(result).trusted)).toBe(false);
  });
});
