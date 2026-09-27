// The DAV library behaviour Phase 23's change check stands on, pinned against
// the build this repository actually has installed.
//
// The change check reads a sync answer through tsdav's raw sync helper and
// decides from it whether anything changed. Three things about that helper
// decide whether the answer is right, and none of them is visible in the
// library's type declarations:
//
//   1. An answer with no member responses ("nothing changed") still carries
//      the NEW sync token. On 2.3.1 the element came back with no raw body, so
//      the token was lost and the next check could not continue from it.
//   2. A member status line with no reason phrase ("HTTP/1.1 404") parses to
//      its own code. On 2.3.1 the parse failed and the status fell back to the
//      whole answer's 207, so a removal read as a change.
//   3. A non-2xx answer RESOLVES to one failed element rather than throwing.
//      That is why every later plan checks every element's status itself: a
//      caller that trusted "it did not throw" would read a refused sync as
//      "nothing changed".
//
// These are read off the installed build rather than remembered. A future
// bump, or a downgrade, that changes any of them turns this file red instead
// of quietly changing an answer the user relies on.
//
// Nothing here opens a network connection. Every request goes to a local stub
// passed as the helper's own fetch parameter, and the project's transport is
// deliberately not in the path: this file pins the library, not the transport.

import { describe, expect, it } from "vitest";
import { syncCollection } from "tsdav";
import tsdavPackage from "tsdav/package.json";

/** The exact version this phase was built and verified against. */
const PINNED_TSDAV_VERSION = "2.3.4";

const COLLECTION_URL = "https://dav.invalid/123456/calendars/home/";
const OLD_TOKEN = "https://dav.invalid/ns/sync/1233";
const NEW_TOKEN = "https://dav.invalid/ns/sync/1234";

const XML_HEADERS = { "content-type": "application/xml; charset=utf-8" };

interface RecordedRequest {
  url: string;
  method: string | undefined;
  body: string;
}

/** A stub fetch that records what the helper sent and answers with one fixed
 *  response. One request per call, so the recorder holds at most one entry. */
function stubFetch(answer: () => Response): {
  fetch: typeof fetch;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const stub = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    requests.push({
      url: String(input),
      method: init?.method,
      body: typeof init?.body === "string" ? init.body : "",
    });
    return answer();
  };
  return { fetch: stub as typeof fetch, requests };
}

/** A 207 multistatus in the DAV namespace, modelled on RFC 6578 section 3.2. */
function multistatus(inner: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">${inner}</D:multistatus>`,
    { status: 207, headers: XML_HEADERS },
  );
}

function removedMember(statusLine: string): string {
  return (
    `<D:response><D:href>/123456/calendars/home/gone.ics</D:href>` +
    `<D:status>${statusLine}</D:status></D:response>` +
    `<D:sync-token>${NEW_TOKEN}</D:sync-token>`
  );
}

function sync(fetchStub: typeof fetch) {
  return syncCollection({
    url: COLLECTION_URL,
    props: { "d:getetag": {} },
    syncLevel: 1,
    syncToken: OLD_TOKEN,
    fetch: fetchStub,
  });
}

describe("tsdav contract for the change check", () => {
  it("is the exact version this phase was verified against", () => {
    expect(tsdavPackage.version).toBe(PINNED_TSDAV_VERSION);
  });

  it("keeps the new sync token when the answer has no member responses", async () => {
    const { fetch } = stubFetch(() =>
      multistatus(`<D:sync-token>${NEW_TOKEN}</D:sync-token>`),
    );
    const responses = await sync(fetch);
    expect(responses).toHaveLength(1);
    // Read exactly the way the later plans will read it.
    expect(responses[0]?.raw?.multistatus?.syncToken).toBe(NEW_TOKEN);
  });

  it("parses a member status line with no reason phrase to its own code", async () => {
    const { fetch } = stubFetch(() => multistatus(removedMember("HTTP/1.1 404")));
    const responses = await sync(fetch);
    expect(responses).toHaveLength(1);
    expect(responses[0]?.status).toBe(404);
    expect(responses[0]?.ok).toBe(false);
  });

  it("still parses the ordinary status line that carries a reason phrase", async () => {
    const { fetch } = stubFetch(() =>
      multistatus(removedMember("HTTP/1.1 404 Not Found")),
    );
    const responses = await sync(fetch);
    expect(responses).toHaveLength(1);
    expect(responses[0]?.status).toBe(404);
    expect(responses[0]?.ok).toBe(false);
  });

  it("resolves to one failed element on a refused sync rather than throwing", async () => {
    const { fetch } = stubFetch(
      () =>
        new Response(
          `<?xml version="1.0" encoding="utf-8"?>\n<D:error xmlns:D="DAV:"><D:valid-sync-token/></D:error>`,
          { status: 403, headers: XML_HEADERS },
        ),
    );
    const pending = sync(fetch);
    await expect(pending).resolves.toBeDefined();
    const responses = await pending;
    expect(responses).toHaveLength(1);
    expect(responses[0]?.ok).toBe(false);
    expect(responses[0]?.status).toBe(403);
  });

  it("sends a REPORT carrying sync-collection, sync-level 1 and the token passed in", async () => {
    const { fetch, requests } = stubFetch(() =>
      multistatus(`<D:sync-token>${NEW_TOKEN}</D:sync-token>`),
    );
    await sync(fetch);
    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request?.url).toBe(COLLECTION_URL);
    expect(request?.method).toBe("REPORT");
    expect(request?.body).toContain("sync-collection");
    expect(request?.body).toMatch(/<d:sync-level>1<\/d:sync-level>/);
    expect(request?.body).toContain(`<d:sync-token>${OLD_TOKEN}</d:sync-token>`);
  });
});
