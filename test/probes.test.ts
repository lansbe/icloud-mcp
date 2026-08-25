// Wave-0 runtime probes. Two research assumptions, settled by execution rather
// than by prose.
//
// This file exists because `02-RESEARCH.md` rates A4 and A7 LOW confidence and
// says, of both, "plan the probe rather than the assumption". Everything below
// runs inside real `workerd` (the `workers` vitest project), against the real
// `postal-mime` build that ships in the bundle. Nothing here is mocked, and
// nothing here imports from `src/` — the probes must stay runnable before the
// modules that will depend on them exist.
//
// **The assertions ARE the evidence.** If one of them starts failing, the
// runtime's behaviour changed and that is a finding to report — not an
// assertion to adjust until it passes. Changing an assertion here to make the
// suite green destroys the only record of what was measured.
//
// ---------------------------------------------------------------------------
// The measurements, verbatim
// ---------------------------------------------------------------------------
// Recorded in the style `01-IMAP-PROOF.md` § 2 established for the capability
// string (D-07): the measurement itself, not a summary of it. Measured
// 2026-08-13, `workerd` via `@cloudflare/vitest-pool-workers@0.21.2`,
// `postal-mime@3.0.0`.
//
//   A4  extracted text of `<p>amp &amp; nbsp[&nbsp;] num &#8217; hex &#x2014;</p>`
//       "\namp &amp; nbsp[&nbsp;] num &#8217; hex &#x2014;"
//
//   A4  `t.removed` observed on each text chunk, in arrival order, for a
//       document whose `head`, `title`, `script` and `style` were all removed
//       by a prior element handler
//       [{"text":"TITLECONTENT","removed":false},
//        {"text":"var leak = 'SCRIPTCONTENT';","removed":false},
//        {"text":".x{content:'STYLECONTENT'}","removed":false},
//        {"text":"visible text","removed":false}]
//
//   A7  PostalMime.parse of a CRLF header block with no body
//       {"subject":"Café ☕ prüfung",
//        "from":{"address":"jane.doe@example.invalid","name":"Doe, Jane"},
//        "date":"2026-08-13T13:15:00.000Z",
//        "messageId":"<abc123.def456@example.invalid>",
//        "attachments":0,"headerCount":4}
//
// Measured 2026-08-14, same runtime and pool version, for the link-emission and
// inline-hidden work (G-02-3d / G-02-3e). Five behaviours, none of which
// Cloudflare's HTMLRewriter reference documents at all.
//
//   P1  element.getAttribute("href") for
//       <a href="https://e.invalid/p?a=1&amp;b=2&#38;c=3&x=4">label</a>
//       "https://e.invalid/p?a=1&amp;b=2&#38;c=3&x=4"
//
//   P2  opens, closes and any raise, per element, under a handler that calls
//       element.onEndTag() on every element it matches
//       {"img":           "opens=1 closes=0 thrown=TypeError: Parser error: No end tag.",
//        "img-selfclose": "opens=1 closes=0 thrown=TypeError: Parser error: No end tag.",
//        "br":            "opens=1 closes=0 thrown=TypeError: Parser error: No end tag.",
//        "a-selfclose":   "opens=1 closes=1 thrown=none",
//        "a-unclosed":    "opens=1 closes=1 thrown=none",
//        "div-unclosed":  "opens=1 closes=0 thrown=none"}
//
//   P3  <div style="x">text</div>, the non-void control for P2
//       {"opens":1,"closes":1}
//
//   P4  <style style="display:none">x</style>, with onEndTag registered by BOTH
//       a .on("style") handler (A, registered first) and a .on("*") handler
//       (B, registered second)
//       {"opensA":1,"closesA":0,"opensB":1,"closesB":1}
//
//   P5  element.tagName for <DIV>a</DIV><div>b</div><IMG>
//       ["div","div","img"]
//       element.getAttribute("style") on an element carrying no style attribute
//       null
//
// ---------------------------------------------------------------------------
// What each measurement settles
// ---------------------------------------------------------------------------
// **A4 — CONFIRMED, as assumed.** `HTMLRewriter` delivers entity references
// undecoded. Named (`&amp;`), non-breaking-space (`&nbsp;`), decimal numeric
// (`&#8217;`) and hexadecimal numeric (`&#x2014;`) all arrive verbatim.
// `src/mail/mime.ts` therefore owes an entity decoder; the ~15 lines the
// research budgeted are real work, not dead code.
//
// **A4, second half — REFUTED. This is the finding.** Research Pattern 9
// caveat 2 states that checking `t.removed` is what keeps `<script>` source out
// of extracted text. It does not. `removed` is `false` on **every** chunk
// above, including the text inside elements a prior handler had already
// removed, so the check never fires and never could. `element.remove()` drops
// the element from the rewriter's *output*; it does not suppress the `text`
// handler for content inside it, and `Text.removed` reports only whether that
// text chunk itself was removed by an earlier *text* handler.
//
// The consequence is a security one, not a cosmetic one: the loop exactly as
// written in the research puts attacker-authored JavaScript source, CSS, and
// `<title>` text into the string handed to the model (T-02-13). The shape that
// does work is asserted below — a skip counter opened in the `element` handler
// and closed from `element.onEndTag()`. `onEndTag` was measured firing 4 times
// against 4 opens, so the counter returns to zero and cannot latch.
//
// **P1 — attributes arrive RAW, entity references intact.** `getAttribute`
// returns exactly the bytes the sender wrote, `&amp;` and `&#38;` included. This
// is the same byte-preserving behaviour A4 measured for text, now confirmed to
// extend to attribute values — but it was worth measuring rather than inferring,
// because a parser that decodes attributes while preserving text would be an
// entirely reasonable design and the docs settle neither. `src/mail/mime.ts`
// therefore owes an emitted link target ONE `decodeEntities` pass at the point
// it reads the attribute, and must then re-escape every ampersand so the single
// wholesale pass at the end of `htmlToText` restores it rather than decoding it
// a second time. A tracking URL carries `&amp;` almost universally, so the
// wrong branch here corrupts the common case, not an exotic one.
//
// **P2 — THIS IS THE FINDING, and it is worse than the hazard it was written to
// check.** The question was whether `onEndTag` silently never fires for a void
// element, which would latch a skip counter open and blank the rest of the
// document. It does not silently do anything: `element.onEndTag()` **raises**
// `TypeError: Parser error: No end tag.` synchronously, inside the element
// handler, for `img` and `br` alike and for both the bare and the self-closing
// spelling. Uncaught, that exception propagates out of the `.text()` await —
// out of `htmlToText`, and out of `extractMessage`, which has no catch — so a
// counter opened on a tracking pixel does not merely lose the body, it fails the
// whole message fetch. `<img style="display:none">` is the single most common
// element in marketing mail, which is what makes this the live case rather than
// a corner one.
//
// The mitigation is unchanged by the severity: never call `onEndTag` on a member
// of the void set. It is correct against both failure modes at once, and it does
// not depend on which of them this runtime happens to exhibit.
//
// Two neighbouring cases are recorded with it, because both were candidates for
// the same raise and neither is one. An `<a>` closes cleanly even when written
// self-closing or left unclosed (`opens=1 closes=1`), so the link handler needs
// no guard of its own. An unclosed `<div>` registers without raising and then
// never closes (`opens=1 closes=0`) — a genuine latch, and the accepted failure
// direction this module already documents for an unclosed `<script>`.
//
// **P3 — the control holds.** A properly closed non-void element opens once and
// closes once, so P2's zero-close results are a property of void elements rather
// than of a broken probe.
//
// **P4 — a second `onEndTag` registration REPLACES the first.** With two
// handlers both matching one element, only the LATER registration's callback
// runs: `closesA` is 0 while `closesB` is 1. A shared counter incremented by
// both handlers is therefore decremented once and finishes latched at +1 — the
// P2 catastrophe reached by a completely different route. This is why
// `htmlToText`'s inline-hidden handler returns early for any element the
// non-content handler already claims: the guard does not make the double
// registration safe, it makes it unreachable.
//
// **P5 — `tagName` is lowercase regardless of source case**, and `getAttribute`
// answers `null` for an absent attribute. Both are convenient rather than
// load-bearing: the guard lowercases at the comparison site anyway, because a
// guard whose correctness rests on an undocumented case convention is a guard
// one runtime update from being wrong.
//
// **A7 — CONFIRMED, cleanly.** `PostalMime.parse` accepts a bare RFC822 header
// block with no body, which is exactly the shape
// `BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]` returns. The RFC
// 2047 encoded word is decoded, `from` carries display name and address
// separately, and `date` and `messageId` are populated. List metadata can come
// from `HEADER.FIELDS` through this library, so the ~60-line hand-rolled RFC
// 2047 decoder that § Don't Hand-Roll warns against is not needed.

import { describe, expect, it } from "vitest";
import PostalMime from "postal-mime";

/** The block-level selector from research Pattern 9, verbatim. */
const BLOCK = "p,div,br,li,tr,h1,h2,h3,h4,h5,h6,blockquote,table";

/** The elements whose text must never reach the reader. */
const DROPPED = "script,style,head,noscript,title";

/**
 * The extraction loop exactly as `02-RESEARCH.md` Pattern 9 publishes it,
 * minus the entity decode and whitespace collapse (which are what A4 is
 * deciding). Reproduced here unchanged so the probe measures the *proposed*
 * code rather than a corrected variant of it.
 */
async function extractAsResearched(html: string): Promise<string> {
  const out: string[] = [];
  const res = new HTMLRewriter()
    .on(DROPPED, {
      element(e) {
        e.remove();
      },
    })
    .on(BLOCK, {
      element() {
        out.push("\n");
      },
    })
    .on("*", {
      text(t) {
        if (!t.removed && t.text) out.push(t.text);
      },
    })
    .transform(new Response(html));
  await res.text(); // consuming the body is what drives the parse
  return out.join("");
}

/**
 * The corrected loop: a depth counter opened when a dropped element starts and
 * closed from its end tag. This is the shape `src/mail/mime.ts` should adopt.
 */
async function extractWithSkipCounter(html: string): Promise<string> {
  const out: string[] = [];
  let skipDepth = 0;
  const res = new HTMLRewriter()
    .on(DROPPED, {
      element(e) {
        e.remove();
        skipDepth += 1;
        e.onEndTag(() => {
          skipDepth -= 1;
        });
      },
    })
    .on(BLOCK, {
      element() {
        out.push("\n");
      },
    })
    .on("*", {
      text(t) {
        if (skipDepth === 0 && t.text) out.push(t.text);
      },
    })
    .transform(new Response(html));
  await res.text();
  return out.join("");
}

/** One of each entity form a real HTML mail body carries. */
const ENTITY_FIXTURE =
  "<p>amp &amp; nbsp[&nbsp;] num &#8217; hex &#x2014;</p>";

/** A document whose every droppable element carries identifiable text. */
const DROPPABLE_FIXTURE =
  "<html><head><title>TITLECONTENT</title></head><body>" +
  "<script>var leak = 'SCRIPTCONTENT';</script>" +
  "<style>.x{content:'STYLECONTENT'}</style>" +
  "<p>visible text</p>" +
  "</body></html>";

describe("Probe A4: HTMLRewriter entity handling", () => {
  it("delivers every entity form undecoded, verbatim", async () => {
    // The measurement. Asserted as one exact string rather than as four
    // `toContain` calls, because the joined result is the artefact that
    // `src/mail/mime.ts` will actually receive.
    expect(await extractAsResearched(ENTITY_FIXTURE)).toBe(
      "\namp &amp; nbsp[&nbsp;] num &#8217; hex &#x2014;",
    );
  });

  it("does not decode a named entity into its character", async () => {
    const text = await extractAsResearched(ENTITY_FIXTURE);
    expect(text).toContain("&amp;");
    // The decoded form is absent: the only "&" present are the ones that open
    // an entity reference, so stripping every reference leaves none behind.
    expect(text.replace(/&(?:amp|nbsp);|&#(?:\d+|x[0-9a-fA-F]+);/g, "")).not.toContain(
      "&",
    );
  });

  it("does not decode a non-breaking space into U+00A0", async () => {
    const text = await extractAsResearched(ENTITY_FIXTURE);
    expect(text).toContain("nbsp[&nbsp;]");
    expect(text).not.toContain(" ");
  });

  it("does not decode decimal or hexadecimal numeric references", async () => {
    const text = await extractAsResearched(ENTITY_FIXTURE);
    expect(text).toContain("&#8217;");
    expect(text).toContain("&#x2014;");
    expect(text).not.toContain("’"); // &#8217; right single quote
    expect(text).not.toContain("—"); // &#x2014; em dash
  });
});

describe("Probe A4 (second half): whether `removed` keeps script text out", () => {
  // Research Pattern 9 caveat 2 claims it does. It does not. These assertions
  // record the real behaviour; see the header for why this is a finding rather
  // than a bug in the probe.

  it("reports removed === false on every chunk, including dropped elements'", async () => {
    const seen: Array<{ text: string; removed: boolean }> = [];
    const res = new HTMLRewriter()
      .on(DROPPED, {
        element(e) {
          e.remove();
        },
      })
      .on("*", {
        text(t) {
          if (t.text) seen.push({ text: t.text, removed: t.removed });
        },
      })
      .transform(new Response(DROPPABLE_FIXTURE));
    await res.text();

    expect(seen.map((c) => c.text)).toEqual([
      "TITLECONTENT",
      "var leak = 'SCRIPTCONTENT';",
      ".x{content:'STYLECONTENT'}",
      "visible text",
    ]);
    // Not one chunk is flagged. The guard in the researched loop is unreachable.
    expect(seen.every((c) => c.removed === false)).toBe(true);
  });

  it("leaks script, style and title text through the researched loop", async () => {
    const text = await extractAsResearched(DROPPABLE_FIXTURE);
    expect(text).toContain("SCRIPTCONTENT");
    expect(text).toContain("STYLECONTENT");
    expect(text).toContain("TITLECONTENT");
  });

  it("excludes all three once a skip counter guards the text handler", async () => {
    const text = await extractWithSkipCounter(DROPPABLE_FIXTURE);
    expect(text).not.toContain("SCRIPTCONTENT");
    expect(text).not.toContain("STYLECONTENT");
    expect(text).not.toContain("TITLECONTENT");
    expect(text).toBe("\nvisible text");
  });

  it("closes the skip counter once per open, so it cannot latch", async () => {
    let opens = 0;
    let closes = 0;
    const res = new HTMLRewriter()
      .on(DROPPED, {
        element(e) {
          opens += 1;
          e.onEndTag(() => {
            closes += 1;
          });
        },
      })
      .transform(new Response(DROPPABLE_FIXTURE));
    await res.text();

    expect(opens).toBe(4); // head, title, script, style
    expect(closes).toBe(opens);
  });
});

/**
 * Drive a rewriter to completion over one document.
 *
 * Consuming the transformed body is what runs the handlers; `.transform()` is
 * lazy and without this nothing fires.
 */
async function drive(
  html: string,
  build: (rewriter: HTMLRewriter) => HTMLRewriter,
): Promise<void> {
  await build(new HTMLRewriter()).transform(new Response(html)).text();
}

describe("Probe P1: whether an attribute value arrives entity-decoded", () => {
  // The one measurement `src/mail/mime.ts`'s link emission branches on. All
  // three entity spellings a real query string carries are present: the named
  // form, the decimal numeric form, and a bare ampersand that is not a
  // reference at all.
  const HREF_FIXTURE =
    '<a href="https://e.invalid/p?a=1&amp;b=2&#38;c=3&x=4">label</a>';

  it("returns the attribute exactly as the sender wrote it, references intact", async () => {
    let href: string | null = null;
    await drive(HREF_FIXTURE, (rewriter) =>
      rewriter.on("a", {
        element(element) {
          href = element.getAttribute("href");
        },
      }),
    );

    // Asserted as one exact string rather than as three `toContain` calls, for
    // A4's reason: the whole value is what the module actually receives, and a
    // parser that decoded ONE of these forms and not the others would satisfy
    // every containment check while still corrupting a real URL.
    expect(href).toBe("https://e.invalid/p?a=1&amp;b=2&#38;c=3&x=4");
  });
});

describe("Probe P2-P5: onEndTag registration and tagName semantics", () => {
  /**
   * Open a counter on every element the selector matches and try to register a
   * close. Reports the raise rather than propagating it, because whether the
   * registration raises at all is the measurement.
   */
  async function countEndTags(
    html: string,
    selector: string,
  ): Promise<{ opens: number; closes: number; thrown: string }> {
    let opens = 0;
    let closes = 0;
    let thrown = "none";
    await drive(html, (rewriter) =>
      rewriter.on(selector, {
        element(element) {
          opens += 1;
          try {
            element.onEndTag(() => {
              closes += 1;
            });
          } catch (error) {
            thrown = `${(error as Error).name}: ${(error as Error).message}`;
          }
        },
      }),
    );
    return { opens, closes, thrown };
  }

  const NO_END_TAG = "TypeError: Parser error: No end tag.";

  it("P2: RAISES on a void element rather than silently never firing", async () => {
    // The finding. See the header for why the severity matters: this exception
    // escapes `htmlToText` and `extractMessage` alike, so a counter opened on a
    // tracking pixel costs the whole message rather than the rest of the body.
    expect(await countEndTags('<div>a<img style="x">b</div>', "img")).toEqual({
      opens: 1,
      closes: 0,
      thrown: NO_END_TAG,
    });
    expect(await countEndTags('<div>a<br style="x">b</div>', "br")).toEqual({
      opens: 1,
      closes: 0,
      thrown: NO_END_TAG,
    });
  });

  it("P2: raises for the self-closing spelling too, so the spelling is no escape", async () => {
    // A sender writing XHTML-style markup gets the same raise. Recorded because
    // "it only happens on the bare form" would be a plausible reading of the
    // case above on its own, and would make the void set look avoidable.
    expect(await countEndTags('<div>a<img style="x" />b</div>', "img")).toEqual({
      opens: 1,
      closes: 0,
      thrown: NO_END_TAG,
    });
  });

  it("P2: an anchor closes cleanly even self-closed or left unclosed", async () => {
    // Why the link handler needs no void guard of its own. `<a>` is not a void
    // element and the parser treats it as closeable in both malformed spellings.
    expect(await countEndTags('<div>a<a href="x" />b</div>', "a")).toEqual({
      opens: 1,
      closes: 1,
      thrown: "none",
    });
    expect(await countEndTags('<div>a<a href="x">b</div>', "a")).toEqual({
      opens: 1,
      closes: 1,
      thrown: "none",
    });
  });

  it("P2: an unclosed non-void element latches without raising", async () => {
    // The accepted failure direction, measured rather than assumed. No raise,
    // no close — the same shape `htmlToText` already documents for an unclosed
    // `<script>`, where losing text beats leaking source.
    expect(await countEndTags('<div style="x">a', "div")).toEqual({
      opens: 1,
      closes: 0,
      thrown: "none",
    });
  });

  it("P3: CONTROL - a properly closed non-void element opens once and closes once", async () => {
    // Without this, P2's zero-close results cannot be told apart from a probe
    // that never registered anything in the first place.
    expect(await countEndTags('<div style="x">text</div>', "div")).toEqual({
      opens: 1,
      closes: 1,
      thrown: "none",
    });
  });

  it("P4: a second onEndTag registration REPLACES the first", async () => {
    // Handler A registers first and never fires; handler B registers second and
    // does. A counter shared by both is incremented twice and decremented once,
    // so it finishes latched — the P2 catastrophe by another route. This is the
    // measured necessity behind `htmlToText`'s disjointness guard.
    const counts = { opensA: 0, closesA: 0, opensB: 0, closesB: 0 };
    await drive('<style style="display:none">x</style>', (rewriter) =>
      rewriter
        .on("style", {
          element(element) {
            counts.opensA += 1;
            element.onEndTag(() => {
              counts.closesA += 1;
            });
          },
        })
        .on("*", {
          element(element) {
            counts.opensB += 1;
            element.onEndTag(() => {
              counts.closesB += 1;
            });
          },
        }),
    );

    expect(counts).toEqual({ opensA: 1, closesA: 0, opensB: 1, closesB: 1 });
    // Spelled out as the property that matters, so a future reader does not have
    // to derive it from four numbers: both handlers saw the element, only one
    // close ran.
    expect(counts.opensA + counts.opensB).toBe(2);
    expect(counts.closesA + counts.closesB).toBe(1);
  });

  it("P5: tagName is lowercase whatever the source case, and a missing attribute is null", async () => {
    const seen: string[] = [];
    let missing: string | null | "unset" = "unset";
    await drive("<DIV>a</DIV><div>b</div><IMG>", (rewriter) =>
      rewriter.on("*", {
        element(element) {
          seen.push(element.tagName);
          if (element.tagName === "div" && missing === "unset") {
            missing = element.getAttribute("style");
          }
        },
      }),
    );

    expect(seen).toEqual(["div", "div", "img"]);
    expect(missing).toBeNull();
  });
});

describe("Probe A7: PostalMime.parse on a headers-only block", () => {
  // Exactly the bytes `BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE MESSAGE-ID)]`
  // returns: CRLF line endings, a terminating blank line, and no body at all.
  // The Subject carries an RFC 2047 base64 encoded word with non-ASCII content.
  const HEADERS_ONLY =
    "Subject: =?utf-8?B?Q2Fmw6kg4piVIHByw7xmdW5n?=\r\n" +
    'From: "Doe, Jane" <jane.doe@example.invalid>\r\n' +
    "Date: Wed, 13 Aug 2026 09:15:00 -0400\r\n" +
    "Message-ID: <abc123.def456@example.invalid>\r\n" +
    "\r\n";

  it("resolves rather than throwing, and finds no body or attachments", async () => {
    const email = await PostalMime.parse(HEADERS_ONLY);
    expect(email.attachments).toEqual([]);
    expect(email.text).toBeUndefined();
    expect(email.html).toBeUndefined();
    expect(email.headers).toHaveLength(4);
  });

  it("decodes the RFC 2047 encoded word in Subject", async () => {
    const email = await PostalMime.parse(HEADERS_ONLY);
    expect(email.subject).toBe("Café ☕ prüfung");
  });

  it("returns From as a display name and an address, separately", async () => {
    const email = await PostalMime.parse(HEADERS_ONLY);
    // The comma inside the quoted display name is the case a naive split breaks.
    expect(email.from?.name).toBe("Doe, Jane");
    expect(email.from?.address).toBe("jane.doe@example.invalid");
  });

  it("populates date as an ISO instant and messageId with its angle brackets", async () => {
    const email = await PostalMime.parse(HEADERS_ONLY);
    expect(email.date).toBe("2026-08-13T13:15:00.000Z"); // -0400 normalised to UTC
    expect(email.messageId).toBe("<abc123.def456@example.invalid>");
  });

  it("parses even when the terminating blank line is absent", async () => {
    // Not every reader appends the blank line the RFC calls for; this asserts
    // the parse does not depend on it.
    const email = await PostalMime.parse(
      "Subject: Plain subject\r\n" +
        "From: Jane <jane@example.invalid>\r\n" +
        "Message-ID: <x@example.invalid>\r\n",
    );
    expect(email.subject).toBe("Plain subject");
    expect(email.messageId).toBe("<x@example.invalid>");
  });
});

// ---------------------------------------------------------------------------
// Probe U1-U5: `unpdf` inside real workerd (plan 04-07 Task 1)
//
// The ROADMAP research flag Phase 4 owes. `unpdf`'s own claim is that it is
// "tested against Cloudflare Workers"; nothing anywhere establishes CPU or heap
// for `extractText()` on a multi-megabyte PDF inside a 128 MB isolate, and
// `04-RESEARCH.md` § 4.2 marks the scanned image-only case **assumed** rather
// than measured. That case is the one a recruiter's document actually produces,
// and it is the most valuable of the three.
//
// **The abort criterion was decided BEFORE the probe ran and is not
// renegotiated after seeing the numbers:** if the 2 MB PDF exceeds ~5 s of CPU
// or fails to complete inside the isolate, `unpdf` does not ship in this phase.
// `ABORT_THRESHOLD_MS` below is that number, and the U2 case is that decision.
//
// The fixtures are GENERATED here rather than committed. A PDF is binary, a
// committed one would need its provenance vouched for, and a hand-built
// structure is the only kind whose contents are known exactly — U1 asserts an
// equality against a string this file wrote, not a fuzzy match against a file
// somebody downloaded.
//
// ---------------------------------------------------------------------------
// The measurements, verbatim
// ---------------------------------------------------------------------------
// Measured 2026-08-20, `workerd` via `@cloudflare/vitest-pool-workers@0.21.2`,
// `unpdf@1.8.0` (exact pin; 1.8.1 was refused at 04-01's blocking checkpoint).
// Each line is the `Measured` record `measure()` returned, verbatim.
//
//   U1  a 1-page hand-built PDF carrying two lines of text
//       {"sourceBytes":638,"totalPages":1,"shape":"string","chars":44,
//        "elapsedMs":814,
//        "head":"Hello from a probe PDF.\nSecond line of t"}
//
//   U2  a 600-page text-heavy PDF, 2.33 MiB of source
//       {"sourceBytes":2443588,"totalPages":600,"shape":"string",
//        "chars":2068049,"elapsedMs":640,
//        "head":"p0 l0 Senior engineer, remote, contract "}
//
//   U3  a scanned, image-only PDF: one raw RGB image, no text operator
//       {"sourceBytes":115864,"totalPages":1,"shape":"string","chars":0,
//        "elapsedMs":0,"head":""}
//
//   U4  pdf.length and pdf.byteLength AFTER one extractText call on that array
//       {"byteLengthAfter":0,"sourceBytes":0}
//
//   U5  Date.now() advance across ~40 ms of pure synchronous arithmetic in this
//       pool, with no I/O between the two reads
//       recorded by the assertion below rather than as a fixed number, because
//       it is a property (does the clock move at all) rather than a quantity
//
//   Cross-check, Node 24 with `process.hrtime.bigint()` — a TRUE wall clock, on
//   the same `unpdf@1.8.0` build and the byte-identical 2 443 588-byte fixture:
//       2 068 049 chars, 600 pages, 546 ms
//   The small document, with pdf.js already loaded: 1 ms.
//
// ---------------------------------------------------------------------------
// What each measurement settles
// ---------------------------------------------------------------------------
// **U2 — THE ABORT CRITERION DID NOT FIRE, by a factor of about eight.** 640 ms
// against a 5 000 ms threshold, for a document larger than the one the criterion
// named (2.33 MiB, not 2 MiB) and 600 pages deep. `unpdf` ships, ATT-02 covers
// PDFs, and ROADMAP criterion 3 is not degraded. The Node cross-check at 546 ms
// on a true clock lands within 15% of the workerd figure, which is what makes
// the workerd number trustworthy rather than merely available — see U5.
//
// Against `CALL_DEADLINE_MS` (20 000 ms), 640 ms is 3.2% of the budget, and the
// extraction does not run inside that window at all: the session closes before
// any decoding or extraction begins. The margin is stated rather than left to be
// inferred because `MAX_PDF_SOURCE_BYTES` in `src/mail/extract.ts` is calibrated
// from exactly this ratio.
//
// **U1 — the 814 ms is pdf.js MODULE LOAD, not extraction.** A 638-byte
// document cannot cost more than a 2.4 MB one; the ordering is what settles it.
// U1 runs first in this file and pays the one-time cost of resolving and
// evaluating the serverless pdf.js build, and U2 — running after it, on a
// document 3 800 times larger — comes in FASTER. Node confirms the split from
// the other side: 1 ms for the same small document once the module is loaded.
// The consequence for the tool is that the FIRST attachment extraction in a
// fresh isolate pays roughly 0.8 s that no later one does.
//
// **U3 — the image-only case returns an EMPTY STRING. This is the finding the
// research marked assumed, and it is now measured.** Not `null`, not an empty
// array, not a throw, and not a rejected promise: `{ totalPages: 1, text: "" }`,
// resolved. Two consequences, and they are why this case was worth the probe.
// A `no-text-layer` branch built on a `catch` would never fire — the second U3
// case asserts the promise resolves, so that mistake fails here rather than in
// front of a user. And an empty string returned as a SUCCESS is exactly the
// shape a model reads as "this document is blank"; `extract.ts` therefore maps
// it to a stated refusal rather than passing it through.
//
// **U4 — extractText DETACHES the array it is handed.** After the call the
// caller's own `Uint8Array` has `byteLength === 0`, and a second call on it
// rejects. Nothing in `unpdf`'s documentation says so. The caller still holds a
// reference that is now silently empty, so any code that extracts and then
// measures, hashes, or re-reads those bytes gets zero — which is why
// `extract.ts` hands `extractText` a COPY and keeps the original. The second
// case asserts the copy leaves the caller's array intact, so the mitigation is
// pinned rather than merely described.
//
// **U5 — the pool's `Date.now()` DOES advance across pure computation**, so the
// elapsed figures above are real rather than spectre-clamped zeroes. This is not
// a given: workerd freezes the clock between I/O operations in production, and
// under that behaviour every measurement in this file would read 0 and the abort
// criterion would be untestable. U3's 0 ms is genuine sub-millisecond work on a
// page with no text, not a clamp — U1, U2 and U5 all move, and the Node
// cross-check agrees with U2 independently.
// ---------------------------------------------------------------------------

import { extractText } from "unpdf";

/** Assemble a PDF from 1-indexed objects, with a real xref table. */
function buildPdf(
  objects: (string | { head: string; stream: Uint8Array })[],
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: string | Uint8Array) => {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    parts.push(bytes);
    offset += bytes.length;
  };

  push("%PDF-1.4\n");
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(offset);
    push(`${index + 1} 0 obj\n`);
    if (typeof object === "string") {
      push(`${object}\n`);
    } else {
      push(`<< ${object.head} /Length ${object.stream.length} >>\nstream\n`);
      push(object.stream);
      push("\nendstream\n");
    }
    push("endobj\n");
  });

  const xrefAt = offset;
  let table = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const at of offsets) table += `${String(at).padStart(10, "0")} 00000 n \n`;
  push(table);
  push(
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
      `startxref\n${xrefAt}\n%%EOF\n`,
  );

  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A PDF whose every page carries a real text layer. */
function textPdf(pages: string[][]): Uint8Array {
  const encoder = new TextEncoder();
  const objects: (string | { head: string; stream: Uint8Array })[] = [
    "", // 1: catalog, filled in below once the page tree is known
    "", // 2: page tree, likewise
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", // 3
  ];
  const kids: string[] = [];

  for (const lines of pages) {
    let content = "BT /F1 12 Tf 72 720 Td 14 TL\n";
    for (const line of lines) {
      content += `(${line.replace(/([()\\])/g, "\\$1")}) Tj T*\n`;
    }
    content += "ET\n";
    objects.push({ head: "", stream: encoder.encode(content) });
    const contentNumber = objects.length;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
        `/Contents ${contentNumber} 0 R ` +
        `/Resources << /Font << /F1 3 0 R >> >> >>`,
    );
    kids.push(`${objects.length} 0 R`);
  }

  objects[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${pages.length} >>`;
  return buildPdf(objects);
}

/**
 * A scanned page: one raw RGB image drawn to the page, and NO text operator.
 *
 * The structural definition of "no text layer" — the content stream contains no
 * `BT`, no `Tj` and no font resource at all, which is what a scanner produces.
 */
function imageOnlyPdf(width: number, height: number): Uint8Array {
  const encoder = new TextEncoder();
  const pixels = new Uint8Array(width * height * 3);
  for (let index = 0; index < pixels.length; index += 1) {
    pixels[index] = (index * 37) & 0xff;
  }
  return buildPdf([
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [5 0 R] /Count 1 >>",
    {
      head:
        `/Type /XObject /Subtype /Image /Width ${width} /Height ${height} ` +
        `/ColorSpace /DeviceRGB /BitsPerComponent 8`,
      stream: pixels,
    },
    {
      head: "",
      stream: encoder.encode(`q ${width} 0 0 ${height} 0 0 cm /Im0 Do Q\n`),
    },
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] ` +
      `/Contents 4 0 R /Resources << /XObject << /Im0 3 0 R >> >> >>`,
  ]);
}

/** The line each page of the bulk document carries. */
const BULK_LINE =
  "Senior engineer, remote, contract to hire. Compensation on request.";

/**
 * A text-heavy document that clears two megabytes of SOURCE PDF.
 *
 * Deliberately built from many small pages rather than a few enormous ones:
 * page count is what drives pdf.js's per-page setup cost, so this is the
 * harsher of the two shapes at the same byte size.
 */
function bulkPdf(): Uint8Array {
  const pages: string[][] = [];
  for (let page = 0; page < 600; page += 1) {
    const lines: string[] = [];
    for (let line = 0; line < 45; line += 1) {
      lines.push(`p${page} l${line} ${BULK_LINE}`);
    }
    pages.push(lines);
  }
  return textPdf(pages);
}

/** What one `extractText` call produced, and what it cost. */
interface Measured {
  sourceBytes: number;
  totalPages: number;
  shape: string;
  chars: number;
  elapsedMs: number;
  head: string;
}

async function measure(pdf: Uint8Array): Promise<Measured> {
  const sourceBytes = pdf.length;
  const started = Date.now();
  const result = await extractText(pdf, { mergePages: true });
  const elapsedMs = Date.now() - started;
  const text = result.text;
  return {
    sourceBytes,
    totalPages: result.totalPages,
    shape: `${typeof text}${Array.isArray(text) ? "[]" : ""}`,
    chars: typeof text === "string" ? text.length : -1,
    elapsedMs,
    head: typeof text === "string" ? text.slice(0, 40) : "",
  };
}

/**
 * The threshold the abort decision was stated against, before the probe ran.
 *
 * Not a tuning knob. Raising it after seeing a bad number is precisely the move
 * stating the criterion in advance exists to prevent.
 */
const ABORT_THRESHOLD_MS = 5000;

/** `CALL_DEADLINE_MS` in `src/mail/service.ts`, restated so the margin is visible. */
const CALL_DEADLINE_MS = 20000;

describe("Probe U1: a small text-bearing PDF", () => {
  it("returns the document's own text, exactly", async () => {
    const measured = await measure(
      textPdf([["Hello from a probe PDF.", "Second line of text."]]),
    );

    expect(measured.sourceBytes).toBe(638);
    expect(measured.totalPages).toBe(1);
    expect(measured.shape).toBe("string");
    expect(measured.chars).toBe(44);
    expect(measured.head).toBe("Hello from a probe PDF.\nSecond line of t");
    // 814 ms measured, and it is module load rather than extraction — see the
    // header. Bounded rather than pinned, because a load time is the one figure
    // here that legitimately varies with the machine.
    expect(measured.elapsedMs).toBeLessThan(ABORT_THRESHOLD_MS);
  });

  it("merges to one string rather than a per-page array under mergePages", async () => {
    // Which overload ships is load-bearing: the array arm hands `extract.ts` a
    // value whose `.length` is a PAGE COUNT, so a byte ceiling applied to it
    // would silently bound the wrong quantity.
    const merged = await extractText(textPdf([["one"], ["two"]]), {
      mergePages: true,
    });
    expect(typeof merged.text).toBe("string");
    expect(merged.text).toContain("one");
    expect(merged.text).toContain("two");

    const perPage = await extractText(textPdf([["one"], ["two"]]));
    expect(Array.isArray(perPage.text)).toBe(true);
    expect(perPage.text).toHaveLength(2);
  });
});

describe("Probe U2: a text-heavy PDF past two megabytes", () => {
  it("completes inside the isolate, under the pre-stated abort threshold", async () => {
    const pdf = bulkPdf();
    expect(pdf.length).toBeGreaterThan(2 * 1024 * 1024);

    const measured = await measure(pdf);

    expect(measured.sourceBytes).toBe(2443588);
    expect(measured.totalPages).toBe(600);
    expect(measured.shape).toBe("string");
    expect(measured.chars).toBe(2068049);
    expect(measured.head).toBe("p0 l0 Senior engineer, remote, contract ");

    // **THE ABORT CRITERION.** Measured at 640 ms. If this starts failing, the
    // runtime's behaviour changed and that is a finding to report — not an
    // assertion to raise until it passes. Raising it would silently reverse a
    // decision a human was told had been taken on a number.
    expect(measured.elapsedMs).toBeLessThan(ABORT_THRESHOLD_MS);

    // The margin against the call deadline, stated rather than inferred:
    // `MAX_PDF_SOURCE_BYTES` is calibrated from this ratio.
    expect(measured.elapsedMs).toBeLessThan(CALL_DEADLINE_MS / 10);
  });
});

describe("Probe U3: a scanned, image-only PDF with no text layer", () => {
  it("resolves with an EMPTY STRING rather than null, an array or a throw", async () => {
    const measured = await measure(imageOnlyPdf(240, 160));

    expect(measured.sourceBytes).toBe(115864);
    expect(measured.totalPages).toBe(1);
    // The finding `04-RESEARCH.md` § 4.2 marked assumed. It is a string, and it
    // is empty. `src/mail/extract.ts`'s `no-text-layer` branch is built against
    // this and nothing else.
    expect(measured.shape).toBe("string");
    expect(measured.chars).toBe(0);
  });

  it("does NOT reject, so a no-text-layer branch cannot be built on a catch", async () => {
    // The mistake this case exists to fail: a `try`/`catch` mapping to
    // `no-text-layer` would never fire, and the empty string would reach the
    // model as a successful answer meaning "this document is blank".
    await expect(
      extractText(imageOnlyPdf(120, 80), { mergePages: true }),
    ).resolves.toEqual({ totalPages: 1, text: "" });
  });
});

describe("Probe U4: what extractText does to the array it is handed", () => {
  it("DETACHES the input buffer, so a second call on the same array rejects", async () => {
    const pdf = textPdf([["Hello from a probe PDF."]]);
    expect(pdf.byteLength).toBeGreaterThan(0);

    await extractText(pdf, { mergePages: true });

    // Undocumented, and silent: the caller still holds a reference that is now
    // zero-length. Anything that extracts and then measures, hashes or re-reads
    // those bytes gets nothing, with no error to say why.
    expect(pdf.byteLength).toBe(0);
    expect(pdf.length).toBe(0);
    await expect(extractText(pdf, { mergePages: true })).rejects.toThrow();
  });

  it("leaves a COPY of the caller's array untouched, which is the mitigation", async () => {
    const pdf = textPdf([["Hello from a probe PDF."]]);
    const before = pdf.byteLength;

    const result = await extractText(pdf.slice(), { mergePages: true });

    expect(result.text).toContain("Hello from a probe PDF.");
    expect(pdf.byteLength).toBe(before);
  });
});

describe("Probe U5: whether this pool's clock advances at all", () => {
  it("moves Date.now() across pure computation, so U1-U3 are not clamped zeroes", () => {
    // The control that makes every elapsed figure above meaningful. Production
    // workerd freezes the clock between I/O operations; under that behaviour
    // every measurement in this file would read 0 and the abort criterion would
    // be untestable rather than merely unmet.
    const started = Date.now();
    let sink = 0;
    while (Date.now() - started < 40) {
      for (let index = 0; index < 100000; index += 1) sink += index % 7;
    }
    const elapsed = Date.now() - started;

    expect(sink).toBeGreaterThan(0);
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });
});
