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
} from "../src/confirm";
import type { NormalizedContactChange } from "../src/confirm";
import { clearDavCache, resolveDavAccount } from "../src/dav/discovery";
import { encodeAddressBookId, encodeContactId } from "../src/dav/ids";
import { createDavFetch } from "../src/dav/transport";
import { buildContactCard, parseVCard } from "../src/dav/vcard";
import { SAFE_MESSAGES } from "../src/errors";
import { registerContactsTools } from "../src/mcp/tools/contacts";
import { UNTRUSTED_PREAMBLE } from "../src/mcp/untrusted";
import { ownerPrincipal } from "./fixtures/bound-secrets";
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
}

interface WriteStub {
  observed: Observed[];
  fetch: typeof globalThis.fetch;
  /** The highest number of requests in flight at once. See the overlap note. */
  maxInFlight: number;
}

/**
 * The smallest CardDAV conversation that reaches the write: discovery and a PUT.
 *
 * No enumeration branch and no multi-get, deliberately — a create reads nothing,
 * so a stub that could answer a read would let a leg that performed one pass
 * unnoticed. Anything this stub does not recognise answers 500, which surfaces as
 * a refusal rather than as a silent success.
 *
 * The overlap counter wraps the WHOLE conversation rather than one branch, so a
 * fan-out anywhere in a leg is seen — including one pairing a read with a write,
 * which is the shape a two-request commit would most plausibly grow into. §3 of
 * `.claude/CLAUDE.md` is what makes that worth counting rather than assuming.
 */
function writeStub(options: { onPut?: () => Response } = {}): WriteStub {
  const state: WriteStub = {
    observed: [],
    fetch: async () => new Response(null, { status: 500 }),
    maxInFlight: 0,
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

    // ZERO requests. A create has nothing to read and this leg writes nothing,
    // so the whole preview is a decode, a uuid, a hash and an HMAC.
    expect(stub.observed).toHaveLength(0);
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
    expect(stub.observed).toHaveLength(0);

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
